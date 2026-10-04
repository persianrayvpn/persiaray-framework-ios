package main

// Travel Mode: the hop's inner WireGuard dials Warp through a public NAT64
// gateway, so the exit follows the gateway's country instead of the local
// Cloudflare colo. Mirrors Android `TravelProbe` and desktop `travel.rs`.
//
// Every check runs through the outer tunnel, which must carry IPv6:
//   - travelReach: any HTTP answer from an IPv6 literal (tunnel IPv6 control),
//   - travelGateway: ip-api through a NAT64 address, giving the gateway's
//     public IPv4 and country (TCP only; it does not prove UDP),
//   - travelDiscover: RFC 7050 `ipv4only.arpa` over DNS/TCP to a public DNS64,
//     so prefixes are learned live instead of trusting stale lists.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// travelWarpTarget is the Warp WireGuard IPv4 packed into each NAT64 prefix.
// The gateway, not the outer colo, reaches it, so the local hairpin that rules
// it out as a plain inner host does not apply.
const travelWarpTarget = "162.159.192.1"

// travelKeepaliveSec: public NAT64 UDP mappings often expire around 30s.
const travelKeepaliveSec = 15

// ip-api.com's IPv4; its NAT64 form reports the gateway's egress IP and country.
const travelGatewayProbeIPv4 = "208.95.112.1"

// Native IPv6 of 1.1.1.1: tells "tunnel has no IPv6" apart from "gateway dead".
const travelControlIPv6 = "2606:4700:4700::1111"

const (
	travelConnectTimeout = 4 * time.Second
	travelReadTimeout    = 6 * time.Second
	// Live DNS64 servers answered in under 1s; dead ones would otherwise hold the whole batch.
	travelDiscoveryRead = 2 * time.Second
	// Slowest working gateway seen took ~3.7s (ZTVI Fremont).
	travelGatewayRead = 4500 * time.Millisecond
	// Working gateways answered within ~300ms of each other; dead ones only time out.
	travelWinnerGrace = 500 * time.Millisecond
	travelMaxBody     = 8 * 1024
)

type travelPrefix struct {
	prefix  string
	country string
	label   string
}

// Known public NAT64 /96 prefixes. The country is where the gateway sits,
// which is what picks the Warp exit; ip-api only knows the IPv4 registrant
// (nat64.net Amsterdam reports GB yet exits NL).
var travelPrefixes = []travelPrefix{
	{"2a02:898:146:64::", "NL", "Netherlands"},
	{"2a00:1098:2b:0:0:1::", "NL", "Amsterdam (nat64.net)"},
	{"2a03:7900:6446::", "NL", "Ede (Tuxis)"},
	{"2602:fc59:b0:64::", "US", "Fremont"},
	{"2602:fc59:11:64::", "US", "Chicago"},
	{"2001:67c:2960:6464::", "DE", "Germany"},
	{"2a01:4f8:c2c:123f:64:5::", "DE", "Nuremberg (nat64.net)"},
	{"2001:67c:2b0:db32:0:1::", "FI", "Tampere"},
	{"2a01:4f9:c010:3f02:64::", "FI", "Helsinki (nat64.net)"},
	{"2a00:1098:2c:0:0:5::", "GB", "London (nat64.net)"},
}

// travelCountries Travel Mode can pick, in UI order.
var travelCountries = []string{"NL", "US", "DE", "FI", "GB"}

// Public DNS64 resolvers asked for their live NAT64 prefixes.
var travelDNS64 = []struct{ address, provider string }{
	{"2a00:1098:2b::1", "nat64.net Amsterdam"},
	{"2a00:1098:2c::1", "nat64.net London"},
	{"2a01:4f8:c2c:123f::1", "nat64.net Nuremberg"},
	{"2a01:4f9:c010:3f02::1", "nat64.net Helsinki"},
	{"2a01:4ff:f0:9876::1", "nat64.net Ashburn"},
	{"2001:67c:2b0::4", "Trex"},
	{"2001:67c:2b0::6", "Trex"},
	{"2001:67c:2960::64", "level66"},
	{"2001:67c:2960::6464", "level66"},
	{"2a03:7900:2:0:31:3:104:161", "Tuxis"},
	{"2602:fc23:18::7", "August Internet"},
	{"2602:fc59:11:1::64", "ZTVI"},
	{"2602:fc59:b0:9e::64", "ZTVI"},
}

// travelHost is one Travel Mode inner target: a NAT64-synthesized IPv6 for Warp :2408.
type travelHost struct {
	Host string `json:"host"`
	// Country is the expected gateway country; empty for discovered prefixes.
	Country string `json:"country"`
	Label   string `json:"label"`
	// probeHost is the same prefix around travelGatewayProbeIPv4.
	probeHost string
}

// travelDial opens TCP to an IPv6 literal through the outer tunnel. Errors
// name the stage that failed, for the logs.
type travelDial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

type travelProbeResult struct {
	ok      bool
	detail  string
	ms      int64
	country string
}

// --- log buffer drained by Swift (PRTravelLogTake) ---

var (
	travelLogMu    sync.Mutex
	travelLogLines []string
)

func travelLog(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	travelLogMu.Lock()
	travelLogLines = append(travelLogLines, line)
	if len(travelLogLines) > 400 {
		travelLogLines = travelLogLines[len(travelLogLines)-400:]
	}
	travelLogMu.Unlock()
}

func travelLogTake() string {
	travelLogMu.Lock()
	defer travelLogMu.Unlock()
	out := strings.Join(travelLogLines, "\n")
	travelLogLines = nil
	return out
}

// --- address helpers ---

// travelNat64 is the RFC 6052 /96 embedding: ipv4 fills the last 32 bits of prefix.
func travelNat64(prefix, ipv4 string) (string, bool) {
	v4, err := netip.ParseAddr(strings.TrimSpace(ipv4))
	if err != nil || !v4.Is4() {
		return "", false
	}
	p, err := netip.ParseAddr(strings.TrimSpace(prefix))
	if err != nil || !p.Is6() {
		return "", false
	}
	b := p.As16()
	v := v4.As4()
	copy(b[12:], v[:])
	return netip.AddrFrom16(b).String(), true
}

// travelPrefixKey is the same /96 regardless of how the prefix is written.
func travelPrefixKey(prefix string) ([12]byte, bool) {
	var key [12]byte
	p, err := netip.ParseAddr(strings.TrimSpace(prefix))
	if err != nil || !p.Is6() {
		return key, false
	}
	b := p.As16()
	copy(key[:], b[:12])
	return key, true
}

func travelTarget(p travelPrefix) (travelHost, bool) {
	host, ok := travelNat64(p.prefix, travelWarpTarget)
	if !ok {
		return travelHost{}, false
	}
	probe, ok := travelNat64(p.prefix, travelGatewayProbeIPv4)
	if !ok {
		return travelHost{}, false
	}
	return travelHost{Host: host, Country: p.country, Label: p.label, probeHost: probe}, true
}

func travelCountryCode(raw string) string {
	t := strings.ToUpper(strings.TrimSpace(raw))
	if len(t) != 2 || t[0] < 'A' || t[0] > 'Z' || t[1] < 'A' || t[1] > 'Z' {
		return ""
	}
	return t
}

// travelExitIn reports whether an egress country is one of countries.
func travelExitIn(countries []string, raw string) bool {
	c := travelCountryCode(raw)
	if c == "" {
		return false
	}
	for _, s := range countries {
		if s == c {
			return true
		}
	}
	return false
}

// travelNormalizeCountries keeps known codes, in UI order.
func travelNormalizeCountries(raw []string) []string {
	want := map[string]bool{}
	for _, c := range raw {
		if code := travelCountryCode(c); code != "" {
			want[code] = true
		}
	}
	var out []string
	for _, c := range travelCountries {
		if want[c] {
			out = append(out, c)
		}
	}
	return out
}

// --- pick ---

// travelPickTargets returns live NAT64 targets for countries through dial:
// IPv6 control, then the known prefixes for those countries. Only if none
// answers are DNS64 servers asked for unknown prefixes. Fastest first; empty
// when none answer.
func travelPickTargets(dial travelDial, countries []string) []travelHost {
	control := travelReach(dial, travelControlIPv6)
	travelLog("Travel Mode IPv6 control probe [%s]:80 %s", travelControlIPv6, control.detail)
	if !control.ok {
		travelLog("Travel Mode: outer tunnel has no working IPv6; skipping NAT64 gateways")
		return nil
	}
	var known []travelPrefix
	for _, p := range travelPrefixes {
		for _, c := range countries {
			if p.country == c {
				known = append(known, p)
				break
			}
		}
	}
	if targets := travelProbeGateways(dial, known, countries); len(targets) > 0 {
		return targets
	}

	travelLog("Travel Mode: no known gateway answered for %v; asking DNS64 servers", countries)
	knownKeys := map[[12]byte]bool{}
	for _, p := range travelPrefixes {
		if k, ok := travelPrefixKey(p.prefix); ok {
			knownKeys[k] = true
		}
	}
	type discovery struct {
		prefixes []string
		detail   string
	}
	found := make([]discovery, len(travelDNS64))
	var wg sync.WaitGroup
	for i, d := range travelDNS64 {
		wg.Add(1)
		go func(i int, address string) {
			defer wg.Done()
			prefixes, detail := travelDiscover(dial, address)
			found[i] = discovery{prefixes, detail}
		}(i, d.address)
	}
	wg.Wait()
	var unknown []travelPrefix
	seen := map[[12]byte]bool{}
	for i, d := range travelDNS64 {
		travelLog("Travel Mode DNS64 %s [%s]: %s", d.provider, d.address, found[i].detail)
		for _, raw := range found[i].prefixes {
			k, ok := travelPrefixKey(raw)
			if !ok || knownKeys[k] || seen[k] {
				continue
			}
			seen[k] = true
			unknown = append(unknown, travelPrefix{prefix: raw, label: d.provider + " (discovered)"})
		}
	}
	fallback := travelProbeGateways(dial, unknown, countries)
	if len(fallback) == 0 {
		travelLog("Travel Mode: no NAT64 gateway answered for %v", countries)
	}
	return fallback
}

type travelProbeOutcome struct {
	host   travelHost
	result travelProbeResult
}

func travelProbeGateways(dial travelDial, prefixes []travelPrefix, countries []string) []travelHost {
	var candidates []travelHost
	for _, p := range prefixes {
		if t, ok := travelTarget(p); ok {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	// Probes are not waited on past the grace window, so the pick does not
	// sit through dead gateways' read timeouts; each still logs its own result.
	results := make(chan travelProbeOutcome, len(candidates))
	var picked atomic.Bool
	for _, t := range candidates {
		go func(t travelHost) {
			r := travelGateway(dial, t.probeHost)
			late := ""
			if picked.Load() {
				late = " (late, after pick)"
			}
			hint := t.Country
			if hint == "" {
				hint = "—"
			}
			travelLog("Travel Mode %s hint=%s gateway probe [%s]:80 %s%s", t.Label, hint, t.probeHost, r.detail, late)
			results <- travelProbeOutcome{t, r}
		}(t)
	}

	type winner struct {
		host travelHost
		ms   int64
	}
	var winners []winner
	received := 0
	var grace <-chan time.Time
loop:
	for received < len(candidates) {
		select {
		case o := <-results:
			received++
			country := o.host.Country
			if country == "" {
				country = o.result.country
			}
			if o.result.ok && travelExitIn(countries, country) {
				if grace == nil {
					grace = time.After(travelWinnerGrace)
				}
				winners = append(winners, winner{o.host, o.result.ms})
			}
		case <-grace:
			break loop
		}
	}
	picked.Store(true)
	if received < len(candidates) {
		travelLog("Travel Mode: picked %dms after the first answer; %d slower gateway(s) still finishing",
			travelWinnerGrace.Milliseconds(), len(candidates)-received)
	}
	sort.SliceStable(winners, func(i, j int) bool { return winners[i].ms < winners[j].ms })
	out := make([]travelHost, len(winners))
	for i, w := range winners {
		out[i] = w.host
	}
	return out
}

// --- probes ---

type travelStageError struct {
	stage string
	err   error
}

func (e *travelStageError) Error() string { return e.err.Error() + " at " + e.stage }

func travelFail(err error, started time.Time) travelProbeResult {
	ms := time.Since(started).Milliseconds()
	return travelProbeResult{detail: fmt.Sprintf("%v after %dms", err, ms), ms: ms}
}

func travelReach(dial travelDial, ipv6 string) travelProbeResult {
	started := time.Now()
	resp, err := travelHTTPGet(dial, ipv6, "1.1.1.1", "/", travelReadTimeout)
	if err != nil {
		return travelFail(err, started)
	}
	ms := time.Since(started).Milliseconds()
	status := travelStatusLine(resp)
	if status == "" {
		return travelProbeResult{detail: fmt.Sprintf("no HTTP status after %dms", ms), ms: ms}
	}
	return travelProbeResult{ok: true, detail: fmt.Sprintf("ok %dms %q", ms, status), ms: ms}
}

func travelGateway(dial travelDial, nat64Host string) travelProbeResult {
	started := time.Now()
	resp, err := travelHTTPGet(dial, nat64Host, "ip-api.com", "/json/?fields=status,countryCode,query", travelGatewayRead)
	if err != nil {
		return travelFail(err, started)
	}
	ms := time.Since(started).Milliseconds()
	status := travelStatusLine(resp)
	if status == "" {
		return travelProbeResult{detail: fmt.Sprintf("no HTTP status after %dms", ms), ms: ms}
	}
	var obj struct {
		Query       string `json:"query"`
		CountryCode string `json:"countryCode"`
	}
	if _, body, ok := strings.Cut(resp, "\r\n\r\n"); ok {
		a, b := strings.Index(body, "{"), strings.LastIndex(body, "}")
		if a >= 0 && b > a {
			_ = json.Unmarshal([]byte(body[a:b+1]), &obj)
		}
	}
	country := travelCountryCode(obj.CountryCode)
	ip := strings.TrimSpace(obj.Query)
	if ip == "" {
		ip = "—"
	}
	shown := country
	if shown == "" {
		shown = "—"
	}
	return travelProbeResult{
		ok:      true,
		detail:  fmt.Sprintf("ok %dms %q gateway ip=%s country=%s", ms, status, ip, shown),
		ms:      ms,
		country: country,
	}
}

// travelDiscover asks dns64Server which NAT64 /96 prefixes it synthesizes for ipv4only.arpa.
func travelDiscover(dial travelDial, dns64Server string) ([]string, string) {
	started := time.Now()
	prefixes, err := func() ([]string, error) {
		c, err := travelOpen(dial, dns64Server, 53)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(travelDiscoveryRead))
		q := travelDNSQuery()
		framed := make([]byte, 2, 2+len(q))
		binary.BigEndian.PutUint16(framed, uint16(len(q)))
		framed = append(framed, q...)
		if _, err := c.Write(framed); err != nil {
			return nil, &travelStageError{"DNS query", err}
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, &travelStageError{"DNS answer", travelTimeoutText(err)}
		}
		msg := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return nil, &travelStageError{"DNS answer", travelTimeoutText(err)}
		}
		return travelParsePrefixes(msg)
	}()
	ms := time.Since(started).Milliseconds()
	if err != nil {
		return nil, fmt.Sprintf("%v after %dms", err, ms)
	}
	return prefixes, fmt.Sprintf("%d prefix(es) in %dms %s", len(prefixes), ms, strings.Join(prefixes, ", "))
}

func travelOpen(dial travelDial, ipv6 string, port uint16) (net.Conn, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipv6))
	if err != nil || !addr.Is6() {
		return nil, fmt.Errorf("not an IPv6 literal: %s", ipv6)
	}
	ctx, cancel := context.WithTimeout(context.Background(), travelConnectTimeout+travelReadTimeout)
	defer cancel()
	return dial(ctx, netip.AddrPortFrom(addr, port))
}

func travelHTTPGet(dial travelDial, ipv6, host, path string, read time.Duration) (string, error) {
	c, err := travelOpen(dial, ipv6, 80)
	if err != nil {
		return "", err
	}
	defer c.Close()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: persianray-ios/1.0\r\nConnection: close\r\n\r\n", path, host)
	_ = c.SetDeadline(time.Now().Add(read))
	if _, err := io.WriteString(c, req); err != nil {
		return "", &travelStageError{"HTTP response", err}
	}
	var buf []byte
	chunk := make([]byte, 2048)
	for len(buf) < travelMaxBody {
		_ = c.SetReadDeadline(time.Now().Add(read))
		n, err := c.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			if len(buf) == 0 {
				return "", &travelStageError{"HTTP response", travelTimeoutText(err)}
			}
			break
		}
		if _, body, ok := strings.Cut(string(buf), "\r\n\r\n"); ok && strings.HasSuffix(strings.TrimSpace(body), "}") {
			break
		}
	}
	return string(buf), nil
}

func travelTimeoutText(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("Read timed out")
	}
	return err
}

func travelStatusLine(resp string) string {
	first, _, _ := strings.Cut(resp, "\n")
	first = strings.TrimSpace(first)
	if strings.HasPrefix(first, "HTTP/") {
		return first
	}
	return ""
}

func travelDNSQuery() []byte {
	id := uint16(time.Now().UnixNano())
	out := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"ipv4only", "arpa"} {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0, 0x00, 0x1C, 0x00, 0x01) // AAAA, IN
	return out
}

// travelParsePrefixes returns /96 prefixes from AAAA answers whose last 32 bits are 192.0.0.170 or .171.
func travelParsePrefixes(msg []byte) ([]string, error) {
	if len(msg) < 12 {
		return nil, errors.New("short DNS answer")
	}
	if rcode := msg[3] & 0x0F; rcode != 0 {
		return nil, fmt.Errorf("DNS RCODE=%d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	i := 12
	var err error
	for q := 0; q < qd; q++ {
		if i, err = travelSkipName(msg, i); err != nil {
			return nil, err
		}
		i += 4
	}
	var out []string
	for a := 0; a < an; a++ {
		if i, err = travelSkipName(msg, i); err != nil {
			return nil, err
		}
		if i+10 > len(msg) {
			break
		}
		kind := binary.BigEndian.Uint16(msg[i : i+2])
		rdLen := int(binary.BigEndian.Uint16(msg[i+8 : i+10]))
		rd := i + 10
		if rd+rdLen > len(msg) {
			break
		}
		if kind == 28 && rdLen == 16 {
			tail := msg[rd+12 : rd+16]
			if tail[0] == 192 && tail[1] == 0 && tail[2] == 0 && (tail[3] == 170 || tail[3] == 171) {
				var b [16]byte
				copy(b[:12], msg[rd:rd+12])
				s := netip.AddrFrom16(b).String()
				dup := false
				for _, o := range out {
					if o == s {
						dup = true
					}
				}
				if !dup {
					out = append(out, s)
				}
			}
		}
		i = rd + rdLen
	}
	return out, nil
}

func travelSkipName(msg []byte, i int) (int, error) {
	for i < len(msg) {
		l := msg[i]
		if l == 0 {
			return i + 1, nil
		}
		if l&0xC0 == 0xC0 {
			return i + 2, nil
		}
		i += int(l) + 1
	}
	return 0, errors.New("bad DNS name")
}

// --- dialers ---

// travelNetstackDial dials straight on an outer netstack (AWG hop).
func travelNetstackDial(tnet *netstack.Net) travelDial {
	return func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
		cctx, cancel := context.WithTimeout(ctx, travelConnectTimeout)
		defer cancel()
		c, err := tnet.DialContextTCPAddrPort(cctx, addr)
		if err != nil {
			if cctx.Err() != nil {
				err = errors.New("connect timed out")
			}
			return nil, &travelStageError{"IPv6 connect (TCP handshake through tunnel)", err}
		}
		return c, nil
	}
}

// travelSocksDial dials through a local SOCKS5 (MASQUE hop: usque).
func travelSocksDial(socksPort int) travelDial {
	return func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
		d := net.Dialer{Timeout: travelConnectTimeout}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(socksPort)))
		if err != nil {
			return nil, &travelStageError{"socks connect", err}
		}
		fail := func(stage string, err error) (net.Conn, error) {
			_ = c.Close()
			return nil, &travelStageError{stage, travelTimeoutText(err)}
		}
		_ = c.SetDeadline(time.Now().Add(travelReadTimeout))
		if _, err := c.Write([]byte{5, 1, 0}); err != nil {
			return fail("socks greeting", err)
		}
		var greet [2]byte
		if _, err := io.ReadFull(c, greet[:]); err != nil {
			return fail("socks greeting", err)
		}
		if greet != [2]byte{5, 0} {
			return fail("socks greeting", errors.New("SOCKS5 greeting refused"))
		}
		ip := addr.Addr().As16()
		req := append([]byte{5, 1, 0, 4}, ip[:]...)
		req = binary.BigEndian.AppendUint16(req, addr.Port())
		const stage = "IPv6 CONNECT (TCP handshake through tunnel)"
		if _, err := c.Write(req); err != nil {
			return fail(stage, err)
		}
		var head [4]byte
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return fail(stage, err)
		}
		if head[0] != 5 {
			return fail(stage, errors.New("bad SOCKS5 reply"))
		}
		if head[1] != 0 {
			return fail(stage, fmt.Errorf("SOCKS5 CONNECT REP=%d", head[1]))
		}
		skip := 0
		switch head[3] {
		case 1:
			skip = 4
		case 4:
			skip = 16
		case 3:
			var l [1]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				return fail(stage, err)
			}
			skip = int(l[0])
		default:
			return fail(stage, errors.New("unknown ATYP"))
		}
		if _, err := io.CopyN(io.Discard, c, int64(skip+2)); err != nil {
			return fail(stage, err)
		}
		_ = c.SetDeadline(time.Time{})
		return c, nil
	}
}
