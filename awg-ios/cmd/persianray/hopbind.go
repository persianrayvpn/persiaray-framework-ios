package main

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// hopBind sends inner WireGuard UDP through the outer AWG netstack.
type hopBind struct {
	tnet   *netstack.Net
	local  netip.Addr
	mu     sync.Mutex
	pc     net.PacketConn
	closed bool
}

type hopEndpoint struct {
	netip.AddrPort
}

func (e *hopEndpoint) ClearSrc()           {}
func (e *hopEndpoint) SrcToString() string { return "" }
func (e *hopEndpoint) DstToString() string { return e.AddrPort.String() }
func (e *hopEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}
func (e *hopEndpoint) DstIP() netip.Addr { return e.AddrPort.Addr() }
func (e *hopEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func (b *hopBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	laddr := netip.AddrPortFrom(b.local, port)
	pc, err := b.tnet.ListenUDPAddrPort(laddr)
	if err != nil {
		return nil, 0, err
	}
	actual := uint16(0)
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		actual = uint16(ua.Port)
	}
	b.pc = pc
	b.closed = false
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

func (b *hopBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.mu.Lock()
	pc := b.pc
	closed := b.closed
	b.mu.Unlock()
	if pc == nil || closed {
		return 0, net.ErrClosed
	}
	n, addr, err := pc.ReadFrom(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	ua, _ := addr.(*net.UDPAddr)
	if ua == nil {
		return 1, nil
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return 1, nil
	}
	eps[0] = &hopEndpoint{AddrPort: netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port))}
	return 1, nil
}

func (b *hopBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.pc != nil {
		err := b.pc.Close()
		b.pc = nil
		return err
	}
	return nil
}

func (b *hopBind) SetMark(uint32) error { return nil }

func (b *hopBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	he, ok := ep.(*hopEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	ua := net.UDPAddrFromAddrPort(he.AddrPort)
	for _, buf := range bufs {
		if _, err := pc.WriteTo(buf, ua); err != nil {
			return err
		}
	}
	return nil
}

func (b *hopBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		host, portStr = s, "2408"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, _ := netip.AddrFromSlice(ip)
		return &hopEndpoint{AddrPort: netip.AddrPortFrom(addr.Unmap(), uint16(port))}, nil
	}
	addrs, err := b.tnet.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("no addresses")
		}
		return nil, err
	}
	addr, err := netip.ParseAddr(addrs[0])
	if err != nil {
		return nil, err
	}
	return &hopEndpoint{AddrPort: netip.AddrPortFrom(addr.Unmap(), uint16(port))}, nil
}

func (b *hopBind) BatchSize() int { return 1 }
