package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// Upstream SOCKS5 for every platform and provider dial. Empty means dial
// directly. Loopback is never sent through the proxy, so a local SOCKS
// listener cannot loop into itself. Read at dial time, so a process can set
// it before the network space is built and every later socket follows it.
var upstreamSocks atomic.Value // string

func SetUpstreamSocks(addr string) {
	upstreamSocks.Store(addr)
	upstreamDnsCache.clear()
}

func UpstreamSocks() string {
	v, _ := upstreamSocks.Load().(string)
	return v
}

// Names are resolved with DoH to IP literals, never with the proxy's own
// resolver and never with the OS stub. usque resolves names with 1.1.1.1
// inside the Warp tunnel, which returns NXDOMAIN or times out for URnetwork
// platform names. The Android process has no resolv.conf, so the Go stub
// dials [::1]:53. DoH is sent both through the proxy and directly and the
// first answer wins: where Shield is needed, direct TLS to public DoH IPs
// is usually blocked, and where the Warp exit is slow, direct is faster.
// A DNS error is returned as *net.DNSError so an unprovisioned family name
// still falls back.
var upstreamDohServers = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://1.0.0.1/dns-query",
	"https://9.9.9.9/dns-query",
}

const (
	upstreamDnsTtl         = 5 * time.Minute
	upstreamDnsNegativeTtl = 30 * time.Second
)

var upstreamDirectDohClient = newUpstreamDohClient((&net.Dialer{Timeout: 4 * time.Second}).DialContext)

var upstreamProxyDoh struct {
	mu     sync.Mutex
	socks  string
	client *http.Client
}

func newUpstreamDohClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext:           dial,
			TLSHandshakeTimeout:   6 * time.Second,
			ResponseHeaderTimeout: 6 * time.Second,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       60 * time.Second,
		},
	}
}

// DoH client whose connections go through the SOCKS proxy. The servers are
// IP literals, so the proxy never resolves a name for these requests.
func upstreamProxyDohClient(socks string) (*http.Client, error) {
	upstreamProxyDoh.mu.Lock()
	defer upstreamProxyDoh.mu.Unlock()
	if upstreamProxyDoh.client != nil && upstreamProxyDoh.socks == socks {
		return upstreamProxyDoh.client, nil
	}
	dialer, err := proxy.SOCKS5("tcp", socks, nil, &net.Dialer{Timeout: 4 * time.Second})
	if err != nil {
		return nil, err
	}
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks dialer has no DialContext")
	}
	if old := upstreamProxyDoh.client; old != nil {
		old.CloseIdleConnections()
	}
	upstreamProxyDoh.socks = socks
	upstreamProxyDoh.client = newUpstreamDohClient(ctxDialer.DialContext)
	return upstreamProxyDoh.client, nil
}

// dialViaUpstream dials addr through the process SOCKS proxy. used is false
// when no proxy is set or the address is loopback. Hostnames are resolved
// here and the proxy is given the IP, so the proxy does not look them up.
func dialViaUpstream(ctx context.Context, network, addr string) (net.Conn, bool, error) {
	socks := UpstreamSocks()
	if socks == "" {
		return nil, false, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, true, err
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil, false, nil
	}
	dialAddr := addr
	if net.ParseIP(host) == nil {
		ip, err := resolveUpstreamHost(ctx, socks, network, host)
		if err != nil {
			return nil, true, err
		}
		dialAddr = net.JoinHostPort(ip.String(), port)
	}
	dialer, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		return nil, true, err
	}
	if ctxDialer, ok := dialer.(proxy.ContextDialer); ok {
		conn, err := ctxDialer.DialContext(ctx, network, dialAddr)
		return conn, true, err
	}
	conn, err := dialer.Dial(network, dialAddr)
	return conn, true, err
}

func resolveUpstreamHost(ctx context.Context, socks, network, host string) (net.IP, error) {
	switch network {
	case "tcp6", "udp6":
		return dohLookup(ctx, socks, host, "AAAA")
	case "tcp4", "udp4":
		return dohLookup(ctx, socks, host, "A")
	default:
		ip, err := dohLookup(ctx, socks, host, "A")
		if err == nil {
			return ip, nil
		}
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			return nil, err
		}
		return dohLookup(ctx, socks, host, "AAAA")
	}
}

type upstreamDnsEntry struct {
	ip       net.IP
	notFound bool
	expires  time.Time
}

type upstreamDnsCacheMap struct {
	mu      sync.Mutex
	entries map[string]upstreamDnsEntry
}

var upstreamDnsCache = &upstreamDnsCacheMap{}

func (self *upstreamDnsCacheMap) get(key string) (upstreamDnsEntry, bool) {
	self.mu.Lock()
	defer self.mu.Unlock()
	entry, ok := self.entries[key]
	if !ok || time.Now().After(entry.expires) {
		return upstreamDnsEntry{}, false
	}
	return entry, true
}

func (self *upstreamDnsCacheMap) put(key string, entry upstreamDnsEntry) {
	self.mu.Lock()
	defer self.mu.Unlock()
	if self.entries == nil {
		self.entries = map[string]upstreamDnsEntry{}
	}
	self.entries[key] = entry
}

func (self *upstreamDnsCacheMap) clear() {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.entries = nil
}

type upstreamDohResult struct {
	ip  net.IP
	err error
}

// dohLookup races every server over both paths. The first address wins.
// NXDOMAIN is only final once every query has finished without an address.
func dohLookup(ctx context.Context, socks, host, qtype string) (net.IP, error) {
	key := qtype + " " + host
	if entry, ok := upstreamDnsCache.get(key); ok {
		if entry.notFound {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return entry.ip, nil
	}

	clients := []*http.Client{}
	if proxied, err := upstreamProxyDohClient(socks); err == nil {
		clients = append(clients, proxied)
	}
	clients = append(clients, upstreamDirectDohClient)

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan upstreamDohResult, len(clients)*len(upstreamDohServers))
	for _, client := range clients {
		for _, server := range upstreamDohServers {
			go func(client *http.Client, server string) {
				ip, err := dohQuery(raceCtx, client, server, host, qtype)
				results <- upstreamDohResult{ip: ip, err: err}
			}(client, server)
		}
	}

	var last error
	notFound := 0
	for range cap(results) {
		result := <-results
		if result.err == nil {
			upstreamDnsCache.put(key, upstreamDnsEntry{ip: result.ip, expires: time.Now().Add(upstreamDnsTtl)})
			return result.ip, nil
		}
		var dnsErr *net.DNSError
		if errors.As(result.err, &dnsErr) && dnsErr.IsNotFound {
			notFound++
		} else {
			last = result.err
		}
	}
	if notFound > 0 {
		upstreamDnsCache.put(key, upstreamDnsEntry{notFound: true, expires: time.Now().Add(upstreamDnsNegativeTtl)})
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if last == nil {
		last = &net.DNSError{Err: "DoH resolution failed", Name: host, IsTemporary: true}
	}
	return nil, last
}

type dohJSON struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func dohQuery(ctx context.Context, client *http.Client, server, host, qtype string) (net.IP, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("name", host)
	q.Set("type", qtype)
	u.RawQuery = q.Encode()
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: host, IsTemporary: true}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: host, IsTemporary: true}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &net.DNSError{Err: fmt.Sprintf("DoH HTTP %d", resp.StatusCode), Name: host, IsTemporary: true}
	}
	var parsed dohJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: host, IsTemporary: true}
	}
	if parsed.Status == 3 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	want := 1
	if qtype == "AAAA" {
		want = 28
	}
	for _, ans := range parsed.Answer {
		if ans.Type != want {
			continue
		}
		if ip := net.ParseIP(ans.Data); ip != nil {
			return ip, nil
		}
	}
	if parsed.Status == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return nil, &net.DNSError{Err: "DoH resolution failed", Name: host, IsTemporary: true}
}
