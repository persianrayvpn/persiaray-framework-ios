package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// socksConfig is the live-tunnel JSON. Host lists are injected by the iOS
// app from PolicyDomains — this binary never ships domain lists.
type socksConfig struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	Address       string `json:"address"`
	Endpoint      string `json:"endpoint"`
	DNS           string `json:"dns"`
	Jc            int    `json:"jc"`
	Jmin          int    `json:"jmin"`
	Jmax          int    `json:"jmax"`
	I1            string `json:"i1"`
	I1Sni         string `json:"i1_sni"`
	Bind          string `json:"bind"`
	SocksPort     int    `json:"socks_port"`

	// Hop stacks inner Warp Plus WG inside this process, sent through the
	// outer AWG netstack (Amnezia junk/I1 apply to the outer only).
	Hop            bool     `json:"hop"`
	HopShield      bool     `json:"hop_shield"`
	InnerPrivateKey    string   `json:"inner_private_key"`
	InnerPeerPublicKey string   `json:"inner_peer_public_key"`
	InnerAddress       string   `json:"inner_address"`
	InnerEndpoint      string   `json:"inner_endpoint"`
	InnerEndpoints     []string `json:"inner_endpoints"`

	// TravelCountries turns on Travel Mode for the hop: the inner dials Warp
	// through a NAT64 gateway in one of these countries. AddressV6 is the
	// outer tunnel's IPv6, which the gateways are reached over.
	TravelCountries []string `json:"travel_countries"`
	AddressV6       string   `json:"address_v6"`


	// ApplyPolicy is true only for a real Connect. Ping probes omit it
	// (or set false) so ads / local bypass / Safe Search never run there.
	ApplyPolicy bool `json:"apply_policy"`

	BlockAds     bool `json:"block_ads"`
	BlockAdult   bool `json:"block_adult"`
	SafeSearch   bool `json:"safe_search"`
	BypassLocal  bool `json:"bypass_local"`
	BlockQuic    bool `json:"block_quic"`
	SafeSearchVIP string `json:"safe_search_vip"`

	AdExact          []string `json:"ad_exact"`
	AdSuffix         []string `json:"ad_suffix"`
	AdultExact       []string `json:"adult_exact"`
	AdultSuffix      []string `json:"adult_suffix"`
	LocalSuffix      []string `json:"local_suffix"`
	SafeSearchExact  []string `json:"safe_search_exact"`
	DoHExact         []string `json:"doh_exact"`
	DoHSuffix        []string `json:"doh_suffix"`
}

func parseConfigJSON(raw []byte) (*socksConfig, error) {
	var c socksConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.PrivateKey == "" || c.PeerPublicKey == "" || c.Endpoint == "" {
		return nil, fmt.Errorf("config needs private_key, peer_public_key, endpoint")
	}
	if c.Address == "" {
		c.Address = "172.16.0.2/32"
	}
	if c.DNS == "" {
		c.DNS = "1.1.1.1"
	}
	if c.Bind == "" {
		c.Bind = "127.0.0.1"
	}
	if c.SocksPort < 0 || c.SocksPort > 65535 {
		return nil, fmt.Errorf("invalid socks_port")
	}
	if c.Jmax < c.Jmin {
		c.Jmax = c.Jmin
	}
	if strings.TrimSpace(c.SafeSearchVIP) == "" {
		c.SafeSearchVIP = "216.239.38.120"
	}
	if c.Hop {
		if c.InnerPrivateKey == "" || c.InnerPeerPublicKey == "" {
			return nil, fmt.Errorf("hop needs inner_private_key and inner_peer_public_key")
		}
		if c.InnerAddress == "" {
			c.InnerAddress = "172.16.0.2/32"
		}
		if strings.TrimSpace(c.InnerEndpoint) == "" && len(c.InnerEndpoints) == 0 {
			c.InnerEndpoint = "188.114.97.170:2408"
		}
	}
	c.TravelCountries = travelNormalizeCountries(c.TravelCountries)
	return &c, nil
}

// travel reports whether this hop runs under Travel Mode.
func (c *socksConfig) travel() bool {
	return c.Hop && len(c.TravelCountries) > 0
}

func (c *socksConfig) uapi() (string, error) {
	return c.uapiPeer(c.PrivateKey, c.PeerPublicKey, c.Endpoint, true, c.travel(), 25)
}

func (c *socksConfig) innerUAPI(endpoint string) (string, error) {
	keepalive := 25
	if c.travel() {
		keepalive = travelKeepaliveSec
	}
	return c.uapiPeer(c.InnerPrivateKey, c.InnerPeerPublicKey, endpoint, false, false, keepalive)
}

func (c *socksConfig) uapiPeer(privB64, pubB64, endpoint string, spoof, ipv6 bool, keepalive int) (string, error) {
	priv, err := keyToHex(privB64)
	if err != nil {
		return "", fmt.Errorf("private_key: %w", err)
	}
	pub, err := keyToHex(pubB64)
	if err != nil {
		return "", fmt.Errorf("peer_public_key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	if spoof {
		if c.Jc > 0 {
			fmt.Fprintf(&b, "jc=%d\n", c.Jc)
			fmt.Fprintf(&b, "jmin=%d\n", c.Jmin)
			fmt.Fprintf(&b, "jmax=%d\n", c.Jmax)
		}
		if i1 := buildI1(c.I1, c.I1Sni); i1 != "" {
			fmt.Fprintf(&b, "i1=%s\n", i1)
		}
	}
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	if ipv6 {
		b.WriteString("allowed_ip=::/0\n")
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	return b.String(), nil
}

func keyToHex(b64 string) (string, error) {
	s := strings.TrimSpace(b64)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	for len(s)%4 != 0 {
		s += "="
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func (c *socksConfig) cloneForPing(endpoint string) *socksConfig {
	out := *c
	out.Endpoint = endpoint
	out.ApplyPolicy = false
	out.BlockAds = false
	out.BlockAdult = false
	out.SafeSearch = false
	out.BypassLocal = false
	out.BlockQuic = false
	out.AdExact = nil
	out.AdSuffix = nil
	out.AdultExact = nil
	out.AdultSuffix = nil
	out.LocalSuffix = nil
	out.SafeSearchExact = nil
	out.DoHExact = nil
	out.DoHSuffix = nil
	out.SocksPort = 0
	out.Bind = "127.0.0.1"
	out.HopShield = false
	out.InnerEndpoints = nil
	return &out
}

func (c *socksConfig) hopInnerHosts() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = normalizeEndpoint(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(c.InnerEndpoint)
	for _, e := range c.InnerEndpoints {
		add(e)
	}
	if len(out) == 0 {
		add("188.114.97.170:2408")
	}
	return out
}

func normalizeEndpoint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, ":") {
		return net.JoinHostPort(s, "2408")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, port)
}
