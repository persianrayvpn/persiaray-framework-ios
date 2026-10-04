// Package mobile exposes a session-oriented USQUE API for in-process embedders.
// It deliberately does not use cmd.Execute or the config package globals.
package mobile

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type AccountConfig struct {
	PrivateKey     string `json:"private_key"`
	EndpointV4     string `json:"endpoint_v4"`
	EndpointV6     string `json:"endpoint_v6"`
	EndpointH2V4   string `json:"endpoint_h2_v4"`
	EndpointH2V6   string `json:"endpoint_h2_v6"`
	EndpointPubKey string `json:"endpoint_pub_key"`
	ID             string `json:"id"`
	AccessToken    string `json:"access_token"`
	IPv4           string `json:"ipv4"`
	IPv6           string `json:"ipv6"`
}

type RegisterRequest struct {
	Model      string `json:"model"`
	Locale     string `json:"locale"`
	DeviceName string `json:"device_name"`
	JWT        string `json:"jwt"`
	AcceptTOS  bool   `json:"accept_tos"`
}

type StartRequest struct {
	ID                string        `json:"id"`
	Config            AccountConfig `json:"config"`
	Transport         string        `json:"transport"`
	UseIPv6           bool          `json:"use_ipv6"`
	ConnectPort       int           `json:"connect_port"`
	Bind              string        `json:"bind"`
	SocksPort         int           `json:"socks_port"`
	Username          string        `json:"username"`
	Password          string        `json:"password"`
	DNS               []string      `json:"dns"`
	MTU               int           `json:"mtu"`
	KeepaliveSeconds  int           `json:"keepalive_seconds"`
	ReconnectMillis   int           `json:"reconnect_millis"`
	UDPTimeoutSeconds int           `json:"udp_timeout_seconds"`
	Insecure          bool          `json:"insecure"`
	SNI               string        `json:"sni"`
	SpoofRecordSplit  bool          `json:"spoofRecordSplit"`
	SpoofSplitAtHost  bool          `json:"spoofSplitAtHost"`
	SpoofUTLS         bool          `json:"spoofUtls"`
	SpoofH2Pad        bool          `json:"spoofH2Pad"`
	SpoofTcpSplit     bool          `json:"spoofTcpSplit"`
	// UDPSpoof is a MASQUE UDP preset id (junk, quic, dns_stun, junk_quic, split, reorder, full).
	UDPSpoof          string `json:"udpSpoof"`
	InitialPacketSize uint16 `json:"initial_packet_size"`
	// NoTunnelIPv6 drops the tunnel IPv6 address and IPv6 DNS servers.
	// IPv6 needs MTU >= 1280; below that IPv6 dials hang without a SYN.
	NoTunnelIPv6 bool `json:"no_tunnel_ipv6"`
}

type session struct {
	id        string
	ctx       context.Context
	cancel    context.CancelFunc
	dev       tun.Device
	stack     *netstack.Net
	socks     *socksServer
	relay     *udpRelay
	endpoint  string
	transport string
	port      int
	ready     atomic.Bool
	stopped   atomic.Bool
	mu        sync.RWMutex
	lastErr   string
}

var registry = struct {
	sync.RWMutex
	next uint64
	m    map[string]*session
}{m: make(map[string]*session)}

func Register(requestJSON string) string {
	var req RegisterRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return failure("", fmt.Errorf("invalid request: %w", err))
	}
	if !req.AcceptTOS {
		return failure("", errors.New("accept_tos must be true"))
	}
	if req.Model == "" {
		req.Model = internal.DefaultModel
	}
	if req.Locale == "" {
		req.Locale = internal.DefaultLocale
	}
	account, err := api.Register(req.Model, req.Locale, req.JWT, true)
	if err != nil {
		return failure("", err)
	}
	privateDER, publicDER, err := internal.GenerateEcKeyPair()
	if err != nil {
		return failure("", err)
	}
	enrolled, err := api.EnrollKey(account.ID, account.Token, publicDER, req.DeviceName)
	if err != nil {
		return failure("", err)
	}
	if len(enrolled.Config.Peers) == 0 {
		return failure("", errors.New("registration returned no MASQUE peer"))
	}
	peer := enrolled.Config.Peers[0]
	v4, err := optionalEndpointHost(peer.Endpoint.V4)
	if err != nil {
		return failure("", fmt.Errorf("invalid registered IPv4 endpoint: %w", err))
	}
	v6, err := optionalEndpointHost(peer.Endpoint.V6)
	if err != nil {
		return failure("", fmt.Errorf("invalid registered IPv6 endpoint: %w", err))
	}
	cfg := AccountConfig{
		PrivateKey: base64.StdEncoding.EncodeToString(privateDER), EndpointV4: v4,
		EndpointV6: v6, EndpointH2V4: config.DefaultEndpointH2V4,
		EndpointH2V6: config.DefaultEndpointH2V6, EndpointPubKey: peer.PublicKey,
		ID: enrolled.ID, AccessToken: account.Token,
		IPv4: enrolled.Config.Interface.Addresses.V4, IPv6: enrolled.Config.Interface.Addresses.V6,
	}
	return success("", map[string]any{"config": cfg})
}

func Start(requestJSON string) string {
	return startWithContext(context.Background(), requestJSON)
}

func startWithContext(parent context.Context, requestJSON string) string {
	var req StartRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return failure("", fmt.Errorf("invalid request: %w", err))
	}
	applyDefaults(&req)
	if req.Transport != "h2" && req.Transport != "h3" {
		return failure(req.ID, errors.New("transport must be h2 or h3"))
	}
	priv, peer, cert, err := credentials(req.Config)
	if err != nil {
		return failure(req.ID, err)
	}
	sni := req.SNI
	if sni == "" {
		sni = internal.ConnectSNI
	}
	tlsConfig, err := api.PrepareTlsConfig(priv, peer, cert, sni, req.Insecure)
	if err != nil {
		return failure(req.ID, err)
	}
	endpoint, err := selectEndpoint(parent, req)
	if err != nil {
		return failure(req.ID, err)
	}
	local, err := tunnelAddresses(req.Config)
	if err != nil {
		return failure(req.ID, err)
	}
	dns, err := parseAddresses(req.DNS)
	if err != nil {
		return failure(req.ID, fmt.Errorf("invalid DNS address: %w", err))
	}
	if req.NoTunnelIPv6 {
		local, dns = onlyIPv4(local), onlyIPv4(dns)
		if len(local) == 0 || len(dns) == 0 {
			return failure(req.ID, errors.New("no IPv4 tunnel address or DNS server"))
		}
	}
	udpSpoof, err := udpSpoofFor(req, sni)
	if err != nil {
		return failure(req.ID, err)
	}
	dev, stack, err := netstack.CreateNetTUN(local, dns, req.MTU)
	if err != nil {
		return failure(req.ID, fmt.Errorf("create netstack: %w", err))
	}
	ctx, cancel := context.WithCancel(parent)
	id := req.ID
	if id == "" {
		id = fmt.Sprintf("usque-%d", atomic.AddUint64(&registry.next, 1))
	}
	s := &session{id: id, ctx: ctx, cancel: cancel, dev: dev, stack: stack, endpoint: endpoint.String(), transport: req.Transport}
	socks, err := newSocksServer(ctx, req.Bind, req.SocksPort, req.Username, req.Password, stack, time.Duration(req.UDPTimeoutSeconds)*time.Second)
	if err != nil {
		cancel()
		_ = dev.Close()
		return failure(id, err)
	}
	s.socks, s.port = socks, socks.port()
	registry.Lock()
	if _, exists := registry.m[id]; exists {
		registry.Unlock()
		s.close()
		return failure(id, errors.New("session ID already exists"))
	}
	registry.m[id] = s
	registry.Unlock()

	go func() {
		if err := socks.serve(); err != nil && ctx.Err() == nil {
			s.setError(fmt.Errorf("SOCKS server: %w", err))
		}
	}()
	go api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
		TLSConfig: tlsConfig, KeepalivePeriod: time.Duration(req.KeepaliveSeconds) * time.Second,
		InitialPacketSize: req.InitialPacketSize,
		Endpoint:          endpoint, Device: api.NewNetstackAdapter(dev), MTU: req.MTU,
		ReconnectDelay: time.Duration(req.ReconnectMillis) * time.Millisecond, AlwaysReconnect: true,
		UseHTTP2: req.Transport == "h2",
		H2Spoof:  h2SpoofFor(req),
		UDPSpoof: udpSpoof,
		OnReady:  func() { s.ready.Store(true) },
		OnError:  func(err error) { s.ready.Store(false); s.setError(err) },
	})
	return success(id, s.snapshot())
}

func Stop(id string) string {
	registry.Lock()
	s := registry.m[id]
	delete(registry.m, id)
	registry.Unlock()
	if s == nil {
		return failure(id, errors.New("unknown session"))
	}
	s.close()
	return success(id, map[string]any{"stopped": true})
}

func StopAll() string {
	registry.Lock()
	all := registry.m
	registry.m = make(map[string]*session)
	registry.Unlock()
	for _, s := range all {
		s.close()
	}
	return success("", map[string]any{"stopped": len(all)})
}

func Status(id string) string {
	registry.RLock()
	s := registry.m[id]
	registry.RUnlock()
	if s == nil {
		return failure(id, errors.New("unknown session"))
	}
	return success(id, s.snapshot())
}

func IsReady(id string) bool {
	registry.RLock()
	s := registry.m[id]
	registry.RUnlock()
	return s != nil && s.ready.Load()
}

func LastError(id string) string {
	registry.RLock()
	s := registry.m[id]
	registry.RUnlock()
	if s == nil {
		return failure(id, errors.New("unknown session"))
	}
	s.mu.RLock()
	lastErr := s.lastErr
	s.mu.RUnlock()
	return success(id, map[string]any{"last_error": lastErr})
}

// Invoke implements the stable dictionary-based ABI consumed by PersianRay's
// dynamically linked Swift runtime.
func Invoke(requestJSON string) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(requestJSON), &raw); err != nil {
		return failure("", fmt.Errorf("invalid request: %w", err))
	}
	var method string
	_ = json.Unmarshal(raw["method"], &method)
	switch method {
	case "register":
		var req struct {
			ConfigPath string `json:"configPath"`
			Idempotent bool   `json:"idempotent"`
		}
		_ = json.Unmarshal([]byte(requestJSON), &req)
		if req.ConfigPath == "" {
			return failure("", errors.New("configPath is required"))
		}
		if req.Idempotent {
			if _, err := loadAccountConfig(req.ConfigPath); err == nil {
				return encode(map[string]any{"ok": true})
			}
		}
		var response map[string]any
		if err := json.Unmarshal([]byte(Register(`{"accept_tos":true}`)), &response); err != nil {
			return failure("", err)
		}
		if response["ok"] != true {
			return encode(response)
		}
		data, _ := response["data"].(map[string]any)
		cfg := data["config"]
		if err := saveConfig(req.ConfigPath, cfg); err != nil {
			return failure("", err)
		}
		return encode(map[string]any{"ok": true, "configPath": req.ConfigPath})

	case "start":
		req, hop, err := compatibilityStartRequest(requestJSON)
		if err != nil {
			return failure("default", err)
		}
		req.ID = "default"
		response := Start(encode(req))
		if !responseOK(response) {
			return response
		}
		if err := waitReady(req.ID, 20*time.Second); err != nil {
			_ = Stop(req.ID)
			return failure(req.ID, err)
		}
		if hop != nil {
			if _, err := setHopRelay(req.ID, *hop); err != nil {
				_ = Stop(req.ID)
				return failure(req.ID, err)
			}
		}
		return flattenResponse(Status(req.ID))

	case "setHopRelay":
		var req struct {
			ID         string `json:"id"`
			Bind       string `json:"bind"`
			RelayPort  int    `json:"relayPort"`
			TargetHost string `json:"targetHost"`
			TargetPort int    `json:"targetPort"`
		}
		if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
			return failure("default", err)
		}
		if req.ID == "" {
			req.ID = "default"
		}
		hop := hopRelayRequest{
			Bind: req.Bind, RelayPort: req.RelayPort,
			TargetHost: req.TargetHost, TargetPort: req.TargetPort,
		}
		port, err := setHopRelay(req.ID, hop)
		if err != nil {
			return failure(req.ID, err)
		}
		return encode(map[string]any{"ok": true, "relayPort": port})

	case "stop":
		registry.RLock()
		_, exists := registry.m["default"]
		registry.RUnlock()
		if !exists {
			return encode(map[string]any{"ok": true})
		}
		return flattenResponse(Stop("default"))

	case "abortProbes":
		registry.Lock()
		var probes []*session
		for id, s := range registry.m {
			if strings.HasPrefix(id, "probe-") {
				probes = append(probes, s)
				delete(registry.m, id)
			}
		}
		registry.Unlock()
		for _, s := range probes {
			s.close()
		}
		return encode(map[string]any{"ok": true, "stopped": len(probes)})

	case "probe":
		start, _, err := compatibilityStartRequest(requestJSON)
		if err != nil {
			return failure("", err)
		}
		var req struct {
			TimeoutMS int  `json:"timeoutMs"`
			Warmup    bool `json:"warmup"`
		}
		_ = json.Unmarshal([]byte(requestJSON), &req)
		if req.TimeoutMS <= 0 {
			req.TimeoutMS = 10000
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutMS)*time.Millisecond)
		defer cancel()
		start.ID = fmt.Sprintf("probe-%d", atomic.AddUint64(&registry.next, 1))
		start.SocksPort = 0
		startResponse := startWithContext(ctx, encode(start))
		if !responseOK(startResponse) {
			return startResponse
		}
		defer Stop(start.ID)

		err = waitReadyContext(ctx, start.ID)
		if err != nil {
			return failure(start.ID, err)
		}
		registry.RLock()
		s := registry.m[start.ID]
		registry.RUnlock()
		if s == nil {
			return failure(start.ID, errors.New("probe session disappeared"))
		}
		elapsed, err := runGenerate204Probe(s.ctx, req.Warmup, func(ctx context.Context, network, address string) (net.Conn, error) {
			return s.stack.DialContext(ctx, network, address)
		})
		if err != nil {
			return failure(start.ID, err)
		}
		return encode(map[string]any{"ok": true, "ms": elapsed.Milliseconds()})

	case "startProbe":
		start, hop, err := compatibilityStartRequest(requestJSON)
		if err != nil {
			return failure("", err)
		}
		var req struct {
			TimeoutMS int `json:"timeoutMs"`
		}
		_ = json.Unmarshal([]byte(requestJSON), &req)
		if req.TimeoutMS <= 0 {
			req.TimeoutMS = 15000
		}
		start.ID = fmt.Sprintf("probe-%d", atomic.AddUint64(&registry.next, 1))
		start.SocksPort = 0
		startResponse := startWithContext(context.Background(), encode(start))
		if !responseOK(startResponse) {
			return startResponse
		}
		waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutMS)*time.Millisecond)
		err = waitReadyContext(waitCtx, start.ID)
		waitCancel()
		if err != nil {
			_ = Stop(start.ID)
			return failure(start.ID, err)
		}
		registry.RLock()
		s := registry.m[start.ID]
		registry.RUnlock()
		if s == nil {
			return failure(start.ID, errors.New("probe session disappeared"))
		}
		relayPort := 0
		if hop != nil {
			port, hopErr := setHopRelay(start.ID, *hop)
			if hopErr != nil {
				_ = Stop(start.ID)
				return failure(start.ID, hopErr)
			}
			relayPort = port
		}
		return encode(map[string]any{
			"ok": true, "id": start.ID,
			"socksPort": s.port, "relayPort": relayPort,
		})
	default:
		return failure("", fmt.Errorf("unknown method %q", method))
	}
}

type hopRelayRequest struct {
	Bind       string `json:"bind"`
	RelayPort  int    `json:"port"`
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
}

func compatibilityStartRequest(input string) (StartRequest, *hopRelayRequest, error) {
	var compat struct {
		ConfigPath       string           `json:"configPath"`
		Bind             string           `json:"bind"`
		SocksPort        int              `json:"socksPort"`
		EndpointHost     string           `json:"endpointHost"`
		EndpointPort     int              `json:"endpointPort"`
		SNI              string           `json:"sni"`
		HTTP2            bool             `json:"http2"`
		Insecure         bool             `json:"insecure"`
		KeepaliveSeconds int              `json:"keepaliveSeconds"`
		SpoofRecordSplit bool             `json:"spoofRecordSplit"`
		SpoofSplitAtHost bool             `json:"spoofSplitAtHost"`
		SpoofUTLS        bool             `json:"spoofUtls"`
		SpoofH2Pad       bool             `json:"spoofH2Pad"`
		SpoofTcpSplit    bool             `json:"spoofTcpSplit"`
		UDPSpoof         string           `json:"udpSpoof"`
		HopRelay         *hopRelayRequest `json:"hopRelay"`
	}
	if err := json.Unmarshal([]byte(input), &compat); err != nil {
		return StartRequest{}, nil, err
	}
	cfg, err := loadAccountConfig(compat.ConfigPath)
	if err != nil {
		return StartRequest{}, nil, err
	}
	transport := "h3"
	if compat.HTTP2 {
		transport = "h2"
	}
	if compat.EndpointHost != "" {
		if transport == "h2" {
			cfg.EndpointH2V4 = compat.EndpointHost
		} else {
			cfg.EndpointV4 = compat.EndpointHost
		}
	}
	req := StartRequest{
		Config: cfg, Transport: transport, ConnectPort: compat.EndpointPort,
		Bind: compat.Bind, SocksPort: compat.SocksPort, SNI: compat.SNI,
		Insecure: compat.Insecure, KeepaliveSeconds: compat.KeepaliveSeconds,
		SpoofRecordSplit: compat.HTTP2 && compat.SpoofRecordSplit,
		SpoofSplitAtHost: compat.HTTP2 && compat.SpoofSplitAtHost,
		SpoofUTLS:        compat.HTTP2 && compat.SpoofUTLS,
		SpoofH2Pad:       compat.HTTP2 && compat.SpoofH2Pad,
		SpoofTcpSplit:    compat.HTTP2 && compat.SpoofTcpSplit,
	}
	if !compat.HTTP2 {
		// Inner MTU 1000 is what carried location and Telegram.
		// 1280 is the client packet cap that still completed the handshake.
		req.MTU = 1000
		req.InitialPacketSize = 1280
		req.NoTunnelIPv6 = true
		req.UDPSpoof = compat.UDPSpoof
	}
	return req, compat.HopRelay, nil
}

func udpSpoofFor(req StartRequest, sni string) (api.UDPSpoof, error) {
	if req.Transport != "h3" {
		return api.UDPSpoof{}, nil
	}
	spoof, err := api.UDPSpoofPreset(req.UDPSpoof)
	if err != nil {
		return api.UDPSpoof{}, err
	}
	spoof.SNI = sni
	return spoof, nil
}

func onlyIPv4(addrs []netip.Addr) []netip.Addr {
	out := addrs[:0:0]
	for _, a := range addrs {
		if a.Is4() {
			out = append(out, a)
		}
	}
	return out
}

func h2SpoofFor(req StartRequest) api.H2Spoof {
	if req.Transport != "h2" {
		return api.H2Spoof{}
	}
	recordSplit := req.SpoofRecordSplit || req.SpoofSplitAtHost
	return api.H2Spoof{
		RecordSplit: recordSplit,
		SplitAtHost: req.SpoofSplitAtHost,
		UTLS:        req.SpoofUTLS,
		H2Pad:       req.SpoofH2Pad,
		TcpSplit:    req.SpoofTcpSplit && !recordSplit,
	}
}

func loadAccountConfig(path string) (AccountConfig, error) {
	var cfg AccountConfig
	if path == "" {
		return cfg, errors.New("configPath is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read USQUE config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("decode USQUE config: %w", err)
	}
	if cfg.PrivateKey == "" || cfg.EndpointPubKey == "" {
		return cfg, errors.New("USQUE config is incomplete")
	}
	return cfg, nil
}

func saveConfig(path string, cfg any) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit config: %w", err)
	}
	return nil
}

func waitReady(id string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return waitReadyContext(ctx, id)
}

func waitReadyContext(ctx context.Context, id string) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		registry.RLock()
		s := registry.m[id]
		registry.RUnlock()
		if s == nil {
			return errors.New("MASQUE session was stopped")
		}
		if s.ready.Load() {
			return nil
		}
		select {
		case <-ctx.Done():
			s.mu.RLock()
			last := s.lastErr
			s.mu.RUnlock()
			if last != "" {
				return fmt.Errorf("MASQUE readiness failed: %s: %w", last, ctx.Err())
			}
			return fmt.Errorf("MASQUE readiness failed: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type contextDialer func(context.Context, string, string) (net.Conn, error)

const generate204Address = "www.gstatic.com:80"

func runGenerate204Probe(ctx context.Context, warmup bool, dial contextDialer) (time.Duration, error) {
	if warmup {
		if _, err := generate204WithRetries(ctx, dial); err != nil {
			return 0, fmt.Errorf("generate_204 warmup: %w", err)
		}
	}
	elapsed, err := generate204WithRetries(ctx, dial)
	if err != nil {
		return 0, fmt.Errorf("generate_204 probe: %w", err)
	}
	return elapsed, nil
}

func generate204WithRetries(ctx context.Context, dial contextDialer) (time.Duration, error) {
	const attempts = 3
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		elapsed, err := measureGenerate204(ctx, dial)
		if err == nil {
			return elapsed, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if attempt+1 < attempts {
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return 0, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return 0, fmt.Errorf("failed after %d attempts: %w", attempts, lastErr)
}

func measureGenerate204(ctx context.Context, dial contextDialer) (time.Duration, error) {
	started := time.Now()
	conn, err := dial(ctx, "tcp", generate204Address)
	if err != nil {
		return 0, fmt.Errorf("dial %s: %w", generate204Address, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return 0, fmt.Errorf("set request deadline: %w", err)
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://www.gstatic.com/generate_204", nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Connection", "close")
	if err := request.Write(conn); err != nil {
		return 0, fmt.Errorf("write generate_204 request: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		return 0, fmt.Errorf("read generate_204 response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return 0, fmt.Errorf("generate_204 returned HTTP %d", response.StatusCode)
	}
	return time.Since(started), nil
}

func responseOK(response string) bool {
	var object struct {
		OK bool `json:"ok"`
	}
	_ = json.Unmarshal([]byte(response), &object)
	return object.OK
}

func flattenResponse(response string) string {
	var object map[string]any
	if json.Unmarshal([]byte(response), &object) != nil {
		return response
	}
	data, _ := object["data"].(map[string]any)
	for key, value := range data {
		object[key] = value
	}
	delete(object, "data")
	return encode(object)
}

type ProbeRequest struct {
	ID            string `json:"id"`
	Network       string `json:"network"`
	Address       string `json:"address"`
	Payload       string `json:"payload_base64"`
	TimeoutMillis int    `json:"timeout_millis"`
}

func Probe(requestJSON string) string {
	var req ProbeRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return failure("", fmt.Errorf("invalid request: %w", err))
	}
	registry.RLock()
	s := registry.m[req.ID]
	registry.RUnlock()
	if s == nil {
		return failure(req.ID, errors.New("unknown session"))
	}
	if !s.ready.Load() {
		return failure(req.ID, errors.New("MASQUE session is not ready"))
	}
	if req.Network != "tcp" && req.Network != "udp" {
		return failure(req.ID, errors.New("network must be tcp or udp"))
	}
	if req.TimeoutMillis <= 0 {
		req.TimeoutMillis = 5000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.TimeoutMillis)*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := s.stack.DialContext(ctx, req.Network, req.Address)
	if err != nil {
		return failure(req.ID, fmt.Errorf("endpoint probe dial: %w", err))
	}
	defer conn.Close()
	if req.Payload != "" {
		payload, decodeErr := base64.StdEncoding.DecodeString(req.Payload)
		if decodeErr != nil {
			return failure(req.ID, fmt.Errorf("payload_base64: %w", decodeErr))
		}
		_ = conn.SetDeadline(time.Now().Add(time.Duration(req.TimeoutMillis) * time.Millisecond))
		if _, err = conn.Write(payload); err != nil {
			return failure(req.ID, fmt.Errorf("endpoint probe write: %w", err))
		}
		buf := make([]byte, 2048)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			return failure(req.ID, fmt.Errorf("endpoint probe read: %w", readErr))
		}
		return success(req.ID, map[string]any{"reachable": true, "rtt_ms": time.Since(start).Milliseconds(), "response_base64": base64.StdEncoding.EncodeToString(buf[:n])})
	}
	return success(req.ID, map[string]any{"reachable": true, "rtt_ms": time.Since(start).Milliseconds()})
}

func (s *session) close() {
	if s.stopped.Swap(true) {
		return
	}
	s.ready.Store(false)
	s.cancel()
	if s.socks != nil {
		s.socks.close()
	}
	s.mu.Lock()
	relay := s.relay
	s.relay = nil
	s.mu.Unlock()
	if relay != nil {
		relay.close()
	}
	_ = s.dev.Close()
}

func (s *session) setError(err error) {
	s.mu.Lock()
	s.lastErr = err.Error()
	s.mu.Unlock()
}

func (s *session) snapshot() map[string]any {
	s.mu.RLock()
	lastErr := s.lastErr
	s.mu.RUnlock()
	return map[string]any{"ready": s.ready.Load(), "stopped": s.stopped.Load(), "socks_port": s.port, "endpoint": s.endpoint, "transport": s.transport, "last_error": lastErr}
}

func applyDefaults(r *StartRequest) {
	if r.Transport == "" {
		r.Transport = "h3"
	}
	if r.ConnectPort == 0 {
		r.ConnectPort = 443
	}
	if r.Bind == "" {
		r.Bind = "127.0.0.1"
	}
	if r.MTU == 0 {
		r.MTU = 1280
	}
	if r.KeepaliveSeconds == 0 {
		r.KeepaliveSeconds = 30
	}
	if r.ReconnectMillis == 0 {
		r.ReconnectMillis = 1000
	}
	if r.UDPTimeoutSeconds == 0 {
		r.UDPTimeoutSeconds = 60
	}
	if len(r.DNS) == 0 {
		r.DNS = []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"}
	}
}

func credentials(c AccountConfig) (*ecdsa.PrivateKey, *ecdsa.PublicKey, [][]byte, error) {
	der, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("private key base64: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("private key: %w", err)
	}
	block, _ := pem.Decode([]byte(c.EndpointPubKey))
	if block == nil {
		return nil, nil, nil, errors.New("endpoint public key is not PEM")
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("endpoint public key: %w", err)
	}
	peer, ok := value.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, errors.New("endpoint public key is not ECDSA")
	}
	cert, err := internal.GenerateCert(priv, &priv.PublicKey)
	return priv, peer, cert, err
}

func selectEndpoint(ctx context.Context, r StartRequest) (net.Addr, error) {
	host := r.Config.EndpointV4
	if r.UseIPv6 {
		host = r.Config.EndpointV6
	}
	if r.Transport == "h2" {
		host = r.Config.EndpointH2V4
		if r.UseIPv6 {
			host = r.Config.EndpointH2V6
		}
		if host == "" && !r.UseIPv6 {
			host = config.DefaultEndpointH2V4
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s endpoint %q: %w", r.Transport, host, err)
		}
		for _, candidate := range resolved {
			if (candidate.IP.To4() == nil) == r.UseIPv6 {
				ip = candidate.IP
				break
			}
		}
	}
	if ip == nil {
		return nil, fmt.Errorf("%s endpoint %q has no requested address family", r.Transport, host)
	}
	if r.Transport == "h2" {
		return &net.TCPAddr{IP: ip, Port: r.ConnectPort}, nil
	}
	return &net.UDPAddr{IP: ip, Port: r.ConnectPort}, nil
}

func tunnelAddresses(c AccountConfig) ([]netip.Addr, error) {
	return parseAddresses([]string{c.IPv4, c.IPv6})
}

func parseAddresses(values []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		addr, err := netip.ParseAddr(strings.Split(value, "/")[0])
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, errors.New("no addresses configured")
	}
	return out, nil
}

func endpointHost(value string) (string, error) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return "", err
	}
	return host, nil
}

func optionalEndpointHost(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	return endpointHost(value)
}

func success(id string, data any) string {
	return encode(map[string]any{"ok": true, "id": id, "data": data})
}
func failure(id string, err error) string {
	return encode(map[string]any{"ok": false, "id": id, "error": err.Error()})
}
func encode(v any) string { b, _ := json.Marshal(v); return string(b) }

type socksServer struct {
	ctx        context.Context
	cancel     context.CancelFunc
	tcp        net.Listener
	udp        *net.UDPConn
	stack      *netstack.Net
	user, pass string
	timeout    time.Duration
	mu         sync.Mutex
	flows      map[string]net.Conn
	udpSem     chan struct{}
}

func newSocksServer(parent context.Context, bind string, port int, user, pass string, stack *netstack.Net, timeout time.Duration) (*socksServer, error) {
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen SOCKS TCP: %w", err)
	}
	tcpAddr := tcp.Addr().(*net.TCPAddr)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone})
	if err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("listen SOCKS UDP: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	return &socksServer{
		ctx: ctx, cancel: cancel, tcp: tcp, udp: udp, stack: stack,
		user: user, pass: pass, timeout: timeout, flows: make(map[string]net.Conn),
		udpSem: make(chan struct{}, 256),
	}, nil
}

func (s *socksServer) port() int { return s.tcp.Addr().(*net.TCPAddr).Port }
func (s *socksServer) serve() error {
	go s.serveUDP()
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleTCP(c)
	}
}
func (s *socksServer) close() {
	s.cancel()
	_ = s.tcp.Close()
	_ = s.udp.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.flows {
		_ = c.Close()
	}
	s.flows = make(map[string]net.Conn)
}

func (s *socksServer) handleTCP(c net.Conn) {
	defer c.Close()
	if err := s.negotiate(c); err != nil {
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return
	}
	host, err := readAddress(c, head[3])
	if err != nil {
		writeReply(c, 8, nil)
		return
	}
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(c, portBytes); err != nil {
		return
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes))))
	switch head[1] {
	case 1:
		remote, dialErr := s.stack.DialContext(s.ctx, "tcp", address)
		if dialErr != nil {
			writeReply(c, 5, nil)
			return
		}
		defer remote.Close()
		writeReply(c, 0, remote.LocalAddr())
		relay(c, remote)
	case 3:
		writeReply(c, 0, s.udp.LocalAddr())
		_, _ = io.Copy(io.Discard, c)
	default:
		writeReply(c, 7, nil)
	}
}

func (s *socksServer) negotiate(c net.Conn) error {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 5 {
		return errors.New("bad greeting")
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	required := byte(0)
	if s.user != "" || s.pass != "" {
		required = 2
	}
	found := false
	for _, m := range methods {
		if m == required {
			found = true
		}
	}
	if !found {
		_, _ = c.Write([]byte{5, 0xff})
		return errors.New("no auth method")
	}
	_, _ = c.Write([]byte{5, required})
	if required == 0 {
		return nil
	}
	auth := make([]byte, 2)
	if _, err := io.ReadFull(c, auth); err != nil || auth[0] != 1 {
		return errors.New("bad auth")
	}
	u := make([]byte, int(auth[1]))
	if _, err := io.ReadFull(c, u); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, auth[:1]); err != nil {
		return err
	}
	p := make([]byte, int(auth[0]))
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	if string(u) != s.user || string(p) != s.pass {
		_, _ = c.Write([]byte{1, 1})
		return errors.New("auth failed")
	}
	_, _ = c.Write([]byte{1, 0})
	return nil
}

func (s *socksServer) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, client, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		frame := append([]byte(nil), buf[:n]...)
		select {
		case s.udpSem <- struct{}{}:
			go func() {
				defer func() { <-s.udpSem }()
				s.forwardUDP(client, frame)
			}()
		default:
		}
	}
}

func (s *socksServer) forwardUDP(client *net.UDPAddr, frame []byte) {
	if len(frame) < 4 || frame[2] != 0 {
		return
	}
	host, used, err := addressFromBytes(frame[3], frame[4:])
	if err != nil || len(frame) < 4+used+2 {
		return
	}
	pos := 4 + used
	dst := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(frame[pos:pos+2]))))
	key := client.String() + "|" + dst
	s.mu.Lock()
	conn := s.flows[key]
	if conn == nil {
		if len(s.flows) >= 256 {
			s.mu.Unlock()
			return
		}
		conn, err = s.stack.DialContext(s.ctx, "udp", dst)
		if err == nil {
			s.flows[key] = conn
			go s.readUDPReply(key, client, dst, conn)
		}
	}
	s.mu.Unlock()
	if err == nil {
		_, _ = conn.Write(frame[pos+2:])
	}
}

func (s *socksServer) readUDPReply(key string, client *net.UDPAddr, dst string, conn net.Conn) {
	defer func() { s.mu.Lock(); delete(s.flows, key); s.mu.Unlock(); _ = conn.Close() }()
	buf := make([]byte, 65507)
	for {
		if s.timeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
		}
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		host, portText, err := net.SplitHostPort(dst)
		if err != nil {
			return
		}
		port, _ := strconv.Atoi(portText)
		frame := []byte{0, 0, 0}
		frame = append(frame, encodeAddress(host)...)
		p := make([]byte, 2)
		binary.BigEndian.PutUint16(p, uint16(port))
		frame = append(frame, p...)
		frame = append(frame, buf[:n]...)
		_, _ = s.udp.WriteToUDP(frame, client)
	}
}

func readAddress(r io.Reader, atyp byte) (string, error) {
	var raw []byte
	switch atyp {
	case 1:
		raw = make([]byte, 4)
	case 4:
		raw = make([]byte, 16)
	case 3:
		n := []byte{0}
		if _, err := io.ReadFull(r, n); err != nil {
			return "", err
		}
		raw = make([]byte, int(n[0]))
	default:
		return "", errors.New("bad address type")
	}
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", err
	}
	if atyp == 3 {
		return string(raw), nil
	}
	return net.IP(raw).String(), nil
}
func addressFromBytes(atyp byte, b []byte) (string, int, error) {
	switch atyp {
	case 1:
		if len(b) < 4 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[:4]).String(), 4, nil
	case 4:
		if len(b) < 16 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(b[:16]).String(), 16, nil
	case 3:
		if len(b) < 1+int(b[0]) {
			return "", 0, io.ErrUnexpectedEOF
		}
		return string(b[1 : 1+int(b[0])]), 1 + int(b[0]), nil
	}
	return "", 0, errors.New("bad address type")
}
func encodeAddress(host string) []byte {
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		return append([]byte{1}, v4...)
	}
	if v6 := ip.To16(); v6 != nil {
		return append([]byte{4}, v6...)
	}
	b := []byte(host)
	return append([]byte{3, byte(len(b))}, b...)
}
func writeReply(c net.Conn, status byte, addr net.Addr) {
	host, port := "0.0.0.0", 0
	if addr != nil {
		if h, p, e := net.SplitHostPort(addr.String()); e == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
	}
	out := []byte{5, status, 0}
	out = append(out, encodeAddress(host)...)
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	out = append(out, p...)
	_, _ = c.Write(out)
}
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}

type udpRelay struct {
	ctx    context.Context
	cancel context.CancelFunc
	local  *net.UDPConn
	stack  *netstack.Net
	target string
	mu     sync.Mutex
	flows  map[string]net.Conn
}

func setHopRelay(id string, req hopRelayRequest) (int, error) {
	registry.RLock()
	s := registry.m[id]
	registry.RUnlock()
	if s == nil {
		return 0, errors.New("USQUE session is not running")
	}
	if s.stopped.Load() {
		return 0, errors.New("USQUE session is stopping")
	}
	if req.Bind == "" {
		req.Bind = "127.0.0.1"
	}
	if req.TargetPort == 0 || net.ParseIP(req.TargetHost) == nil {
		return 0, errors.New("hop relay requires target IP and target port")
	}
	// Unicast UDP has no SO_REUSEADDR, so a relay moving to another target on
	// the same fixed port must free it first.
	if req.RelayPort != 0 {
		s.mu.Lock()
		if s.relay != nil && s.relay.port() == req.RelayPort {
			s.relay.close()
			s.relay = nil
		}
		s.mu.Unlock()
	}
	relay, err := newUDPRelay(context.Background(), req.Bind, req.RelayPort, req.TargetHost, req.TargetPort, s.stack)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	if s.stopped.Load() {
		s.mu.Unlock()
		relay.close()
		return 0, errors.New("USQUE session is stopping")
	}
	old := s.relay
	s.relay = relay
	s.mu.Unlock()
	if old != nil {
		old.close()
	}
	go relay.serve()
	return relay.port(), nil
}

func newUDPRelay(parent context.Context, bind string, port int, targetHost string, targetPort int, stack *netstack.Net) (*udpRelay, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	local, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen hop UDP relay: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	return &udpRelay{
		ctx: ctx, cancel: cancel, local: local, stack: stack,
		target: net.JoinHostPort(targetHost, strconv.Itoa(targetPort)),
		flows:  make(map[string]net.Conn),
	}, nil
}

func (r *udpRelay) port() int {
	if r == nil || r.local == nil {
		return 0
	}
	addr, ok := r.local.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		return 0
	}
	return addr.Port
}

func (r *udpRelay) serve() {
	buf := make([]byte, 65535)
	for {
		n, client, err := r.local.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		conn := r.flows[client.String()]
		if conn == nil {
			conn, err = r.stack.DialContext(r.ctx, "udp", r.target)
			if err == nil {
				r.flows[client.String()] = conn
				go r.readReplies(client, conn)
			}
		}
		r.mu.Unlock()
		if err == nil {
			_, _ = conn.Write(buf[:n])
		}
	}
}

func (r *udpRelay) readReplies(client *net.UDPAddr, conn net.Conn) {
	defer func() {
		r.mu.Lock()
		delete(r.flows, client.String())
		r.mu.Unlock()
		_ = conn.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if _, err := r.local.WriteToUDP(buf[:n], client); err != nil {
			return
		}
	}
}

func (r *udpRelay) close() {
	r.cancel()
	_ = r.local.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, conn := range r.flows {
		_ = conn.Close()
	}
	r.flows = make(map[string]net.Conn)
}
