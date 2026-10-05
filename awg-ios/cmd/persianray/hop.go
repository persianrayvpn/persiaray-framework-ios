package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

type hopEgress struct {
	IP      string
	Country string
}

func filterSame24(hosts []string, outerEP string) []string {
	oh, _, err := net.SplitHostPort(normalizeEndpoint(outerEP))
	if err != nil {
		oh = strings.TrimSpace(strings.TrimSuffix(outerEP, ":2408"))
		if i := strings.LastIndexByte(outerEP, ':'); i > 0 && net.ParseIP(outerEP[:i]) != nil {
			oh = outerEP[:i]
		}
	}
	oaddr, err := netip.ParseAddr(oh)
	if err != nil || !oaddr.Is4() {
		return hosts
	}
	p24 := netip.PrefixFrom(oaddr, 24)
	var out []string
	for _, h := range hosts {
		host, _, err := net.SplitHostPort(h)
		if err != nil {
			out = append(out, h)
			continue
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is4() || !p24.Contains(a) {
			out = append(out, h)
		}
	}
	return out
}

func (t *awgTunnel) startHop(cfg *socksConfig) error {
	if cfg.travel() {
		return t.startTravelHop(cfg)
	}
	// Same gate as Masque Hop: do not attach the inner WireGuard until the
	// outer session can carry traffic.
	if !waitStackReady(t.outerNet, 12*time.Second) {
		return fmt.Errorf("outer hop not ready")
	}
	hosts := filterSame24(cfg.hopInnerHosts(), cfg.Endpoint)
	if len(hosts) == 0 {
		hosts = []string{"188.114.97.170:2408"}
	}
	if !cfg.HopShield {
		hosts = hosts[:1]
	} else if len(hosts) > 4 {
		hosts = hosts[:4]
	}
	var first hopEgress
	if cfg.HopShield {
		eg, err := lookupHopEgress(t.outerNet, 8*time.Second)
		if err == nil {
			first = eg
		}
	}
	var lastErr error
	for i, ep := range hosts {
		if err := t.replaceInner(cfg, ep); err != nil {
			lastErr = err
			continue
		}
		if !cfg.HopShield {
			return nil
		}
		second, err := lookupHopEgress(t.innerNet, 8*time.Second)
		if err != nil {
			lastErr = err
			if i == len(hosts)-1 {
				return nil
			}
			continue
		}
		if hopExitsDiffer(first, second) {
			return nil
		}
		if i == len(hosts)-1 {
			return nil
		}
	}
	if t.innerDev == nil {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("hop inner failed")
	}
	return nil
}

func (t *awgTunnel) replaceInner(cfg *socksConfig, endpoint string) error {
	if t.innerDev != nil {
		t.innerDev.Close()
		t.innerDev = nil
		t.innerNet = nil
	}
	innerLocal, err := parseAddr(cfg.InnerAddress)
	if err != nil {
		return err
	}
	dns, err := netip.ParseAddr(cfg.DNS)
	if err != nil {
		dns = netip.MustParseAddr("1.1.1.1")
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{innerLocal}, []netip.Addr{dns}, 1200)
	if err != nil {
		return err
	}
	outerLocal := t.outerLocal
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		if a, err := netip.ParseAddr(host); err == nil && a.Is6() && t.outerLocal6.IsValid() {
			outerLocal = t.outerLocal6
		}
	}
	bind := &hopBind{tnet: t.outerNet, local: outerLocal}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelError, "awg-hop "))
	uapi, err := cfg.innerUAPI(endpoint)
	if err != nil {
		dev.Close()
		return err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("inner ipc: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("inner up: %w", err)
	}
	t.innerDev = dev
	t.innerNet = tnet
	t.innerLocal = innerLocal
	return nil
}

// startTravelHop tries NAT64 targets for cfg.TravelCountries and keeps the
// first whose exit is in one of them; otherwise the first regular inner host.
func (t *awgTunnel) startTravelHop(cfg *socksConfig) error {
	countries := cfg.TravelCountries
	travelLog("Travel Mode is enabled! countries=%v", countries)
	var targets []travelHost
	switch {
	case !waitStackReady(t.outerNet, 12*time.Second):
		travelLog("Travel Mode: outer tunnel not connected; skipping NAT64 gateways")
	case !t.outerLocal6.IsValid():
		travelLog("Travel Mode: outer tunnel has no IPv6 address; skipping NAT64 gateways")
	default:
		targets = travelPickTargets(travelNetstackDial(t.outerNet), countries)
	}
	for i, target := range targets {
		ep := net.JoinHostPort(target.Host, "2408")
		travelLog("Travel Mode trying %s [%d/%d] inner %s", target.Label, i+1, len(targets), ep)
		if err := t.replaceInner(cfg, ep); err != nil {
			travelLog("Travel Mode: %s inner failed: %v", target.Label, err)
			continue
		}
		eg, err := lookupHopEgress(t.innerNet, 8*time.Second)
		if err != nil {
			travelLog("Travel Mode: no answer through %s: %v", target.Label, err)
			continue
		}
		if travelExitIn(countries, eg.Country) {
			travelLog("Travel Mode: exit %s ip=%s via %s", eg.Country, eg.IP, target.Label)
			return nil
		}
		travelLog("Travel Mode: %s exits in %s, not a selected country", target.Label, eg.Country)
	}
	hosts := filterSame24(cfg.hopInnerHosts(), cfg.Endpoint)
	fallback := "188.114.97.170:2408"
	if len(hosts) > 0 {
		fallback = hosts[0]
	}
	travelLog("Travel Mode: no selected country reached; regular hop inner %s", fallback)
	return t.replaceInner(cfg, fallback)
}

func waitStackReady(tnet *netstack.Net, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := lookupHopEgress(tnet, 3*time.Second); err == nil {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func hopExitsDiffer(a, b hopEgress) bool {
	ac := strings.ToUpper(strings.TrimSpace(a.Country))
	bc := strings.ToUpper(strings.TrimSpace(b.Country))
	if ac != "" && bc != "" {
		return ac != bc
	}
	return a.IP != "" && b.IP != "" && a.IP != b.IP
}

func lookupHopEgress(tnet *netstack.Net, timeout time.Duration) (hopEgress, error) {
	if tnet == nil {
		return hopEgress{}, fmt.Errorf("no netstack")
	}
	deadline := time.Now().Add(timeout)
	eg, err := lookupIPAPI(tnet, deadline)
	if err == nil {
		return eg, nil
	}
	return lookupTrace(tnet, deadline)
}

func lookupIPAPI(tnet *netstack.Net, deadline time.Time) (hopEgress, error) {
	addrs, err := tnet.LookupHost("ip-api.com")
	if err != nil || len(addrs) == 0 {
		return hopEgress{}, fmt.Errorf("ip-api resolve")
	}
	c, err := tnet.DialTCP(&net.TCPAddr{IP: net.ParseIP(addrs[0]), Port: 80})
	if err != nil {
		return hopEgress{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(deadline)
	req := "GET /json?fields=status,query,countryCode HTTP/1.1\r\nHost: ip-api.com\r\nUser-Agent: persianray-ios-awg/1.0\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return hopEgress{}, err
	}
	body, err := readHTTPBody(c)
	if err != nil {
		return hopEgress{}, err
	}
	var obj struct {
		Status      string `json:"status"`
		Query       string `json:"query"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return hopEgress{}, err
	}
	if obj.Status != "success" {
		return hopEgress{}, fmt.Errorf("ip-api %s", obj.Status)
	}
	return hopEgress{IP: obj.Query, Country: obj.CountryCode}, nil
}

func lookupTrace(tnet *netstack.Net, deadline time.Time) (hopEgress, error) {
	c, err := tnet.DialTCP(&net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 80})
	if err != nil {
		return hopEgress{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(deadline)
	req := "GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nUser-Agent: persianray-ios-awg/1.0\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return hopEgress{}, err
	}
	body, err := readHTTPBody(c)
	if err != nil {
		return hopEgress{}, err
	}
	ip := ""
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
			break
		}
	}
	if ip == "" {
		return hopEgress{}, fmt.Errorf("no ip in trace")
	}
	return hopEgress{IP: ip}, nil
}

func readHTTPBody(c net.Conn) ([]byte, error) {
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return io.ReadAll(br)
}
