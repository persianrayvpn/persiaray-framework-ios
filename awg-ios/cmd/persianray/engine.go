package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

type awgTunnel struct {
	mu          sync.Mutex
	outerDev    *device.Device
	innerDev    *device.Device
	outerNet    *netstack.Net
	innerNet    *netstack.Net
	outerLocal  netip.Addr
	// outerLocal6 is set only under Travel Mode; NAT64 targets are IPv6.
	outerLocal6 netip.Addr
	innerLocal  netip.Addr
	ln          net.Listener
	port        int
	cfg         *socksConfig
}

func parseAddr(cidr string) (netip.Addr, error) {
	s := strings.TrimSpace(cidr)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return netip.ParseAddr(s)
}

func (t *awgTunnel) socksTarget() (*netstack.Net, netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.innerNet != nil {
		return t.innerNet, t.innerLocal
	}
	return t.outerNet, t.outerLocal
}

func openTunnel(cfg *socksConfig) (*awgTunnel, error) {
	uapi, err := cfg.uapi()
	if err != nil {
		return nil, err
	}
	local, err := parseAddr(cfg.Address)
	if err != nil {
		return nil, err
	}
	dns, err := netip.ParseAddr(cfg.DNS)
	if err != nil {
		dns = netip.MustParseAddr("1.1.1.1")
	}
	addrs := []netip.Addr{local}
	var local6 netip.Addr
	if cfg.travel() && strings.TrimSpace(cfg.AddressV6) != "" {
		if v6, err := parseAddr(cfg.AddressV6); err == nil && v6.Is6() {
			local6 = v6
			addrs = append(addrs, v6)
		} else {
			travelLog("Travel Mode: address_v6 %q is not IPv6", cfg.AddressV6)
		}
	}
	tun, tnet, err := netstack.CreateNetTUN(addrs, []netip.Addr{dns}, 1280)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("ipc: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("up: %w", err)
	}
	t := &awgTunnel{
		outerDev:    dev,
		outerNet:    tnet,
		outerLocal:  local,
		outerLocal6: local6,
		cfg:         cfg,
	}
	if cfg.Hop {
		if err := t.startHop(cfg); err != nil {
			t.close()
			return nil, err
		}
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.Bind, fmt.Sprintf("%d", cfg.SocksPort)))
	if err != nil {
		t.close()
		return nil, err
	}
	t.ln = ln
	t.port = ln.Addr().(*net.TCPAddr).Port
	go func() { _ = serveSocks(ln, t, cfg) }()
	return t, nil
}

func (t *awgTunnel) close() {
	if t == nil {
		return
	}
	if t.ln != nil {
		_ = t.ln.Close()
	}
	if t.innerDev != nil {
		t.innerDev.Close()
		t.innerDev = nil
		t.innerNet = nil
	}
	if t.outerDev != nil {
		t.outerDev.Close()
		t.outerDev = nil
	}
}

func (t *awgTunnel) setHopInner(endpoint string) error {
	if t.cfg == nil || !t.cfg.Hop {
		return fmt.Errorf("not a hop tunnel")
	}
	ep := normalizeEndpoint(endpoint)
	if ep == "" {
		return fmt.Errorf("bad inner endpoint")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.replaceInner(t.cfg, ep)
}

var (
	liveMu sync.Mutex
	live   *awgTunnel
)

func startLive(cfg *socksConfig) error {
	liveMu.Lock()
	defer liveMu.Unlock()
	if live != nil {
		live.close()
		live = nil
	}
	t, err := openTunnel(cfg)
	if err != nil {
		return err
	}
	live = t
	return nil
}

func stopLive() {
	liveMu.Lock()
	defer liveMu.Unlock()
	if live != nil {
		live.close()
		live = nil
	}
}

func setLiveHopInner(endpoint string) error {
	liveMu.Lock()
	defer liveMu.Unlock()
	if live == nil {
		return fmt.Errorf("awg not running")
	}
	return live.setHopInner(endpoint)
}
