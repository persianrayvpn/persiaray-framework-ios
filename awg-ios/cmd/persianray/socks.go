package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func serveSocks(ln net.Listener, t *awgTunnel, cfg *socksConfig) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		tnet, local := t.socksTarget()
		go handleSocks(c, tnet, local, cfg)
	}
}

func handleSocks(client net.Conn, tnet *netstack.Net, local netip.Addr, cfg *socksConfig) {
	defer client.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil || req[0] != 5 {
		return
	}
	host, port, err := readSocksAddr(client, req[3])
	if err != nil {
		return
	}
	switch req[1] {
	case 1:
		proxyConnect(client, tnet, host, port, cfg)
	case 3:
		proxyUDP(client, tnet, local, cfg)
	default:
		_, _ = client.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func socksFail(client net.Conn, rep byte) {
	_, _ = client.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}

func proxyConnect(client net.Conn, tnet *netstack.Net, host string, port int, cfg *socksConfig) {
	switch cfg.action(host, port) {
	case actBlockAds:
		adBlockPending.Add(1)
		socksFail(client, 2)
		return
	case actBlock:
		socksFail(client, 2)
		return
	case actDirect:
		proxyDirect(client, host, port)
		return
	case actSafeSearch:
		host = cfg.SafeSearchVIP
	case actTunnel:
	}

	remote, err := tnet.Dial("tcp", joinHostPort(host, port))
	if err != nil {
		socksFail(client, 5)
		return
	}
	defer remote.Close()
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(remote, client) }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, remote) }()
	wg.Wait()
}

func proxyDirect(client net.Conn, host string, port int) {
	remote, err := net.Dial("tcp", joinHostPort(host, port))
	if err != nil {
		socksFail(client, 5)
		return
	}
	defer remote.Close()
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(remote, client) }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, remote) }()
	wg.Wait()
}

func proxyUDP(client net.Conn, tnet *netstack.Net, local netip.Addr, cfg *socksConfig) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		socksFail(client, 1)
		return
	}
	defer udp.Close()
	la := udp.LocalAddr().(*net.UDPAddr)
	reply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], uint16(la.Port))
	if _, err := client.Write(reply); err != nil {
		return
	}
	tunUDP, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(local, 0))
	if err != nil {
		return
	}
	defer tunUDP.Close()

	var mu sync.Mutex
	var clientAddr net.Addr
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			host, port, payload, err := parseSocksUDP(buf[:n])
			if err != nil {
				continue
			}
			if cfg.dropQUIC(port) {
				continue
			}
			switch cfg.action(host, port) {
			case actBlockAds:
				adBlockPending.Add(1)
				continue
			case actBlock:
				continue
			case actDirect, actSafeSearch:
				continue
			}
			mu.Lock()
			clientAddr = addr
			mu.Unlock()
			raddr, err := net.ResolveUDPAddr("udp", joinHostPort(host, port))
			if err != nil {
				continue
			}
			_, _ = tunUDP.WriteTo(payload, raddr)
		}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := tunUDP.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			dst := clientAddr
			mu.Unlock()
			if dst == nil {
				continue
			}
			_, _ = udp.WriteTo(encodeSocksUDP(from, buf[:n]), dst)
		}
	}()
	io.Copy(io.Discard, client)
}

func readSocksAddr(r io.Reader, atyp byte) (string, int, error) {
	switch atyp {
	case 1:
		addr := make([]byte, 6)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", 0, err
		}
		return net.IP(addr[:4]).String(), int(binary.BigEndian.Uint16(addr[4:])), nil
	case 4:
		addr := make([]byte, 18)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", 0, err
		}
		return net.IP(addr[:16]).String(), int(binary.BigEndian.Uint16(addr[16:])), nil
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return "", 0, err
		}
		rest := make([]byte, int(lb[0])+2)
		if _, err := io.ReadFull(r, rest); err != nil {
			return "", 0, err
		}
		host := string(rest[:len(rest)-2])
		port := int(binary.BigEndian.Uint16(rest[len(rest)-2:]))
		return host, port, nil
	default:
		return "", 0, fmt.Errorf("atyp %d", atyp)
	}
}

func parseSocksUDP(b []byte) (host string, port int, payload []byte, err error) {
	if len(b) < 4 || b[2] != 0 {
		return "", 0, nil, fmt.Errorf("short")
	}
	switch b[3] {
	case 1:
		if len(b) < 10 {
			return "", 0, nil, fmt.Errorf("short v4")
		}
		return net.IP(b[4:8]).String(), int(binary.BigEndian.Uint16(b[8:10])), b[10:], nil
	case 4:
		if len(b) < 22 {
			return "", 0, nil, fmt.Errorf("short v6")
		}
		return net.IP(b[4:20]).String(), int(binary.BigEndian.Uint16(b[20:22])), b[22:], nil
	case 3:
		if len(b) < 5 {
			return "", 0, nil, fmt.Errorf("short name")
		}
		n := int(b[4])
		if len(b) < 7+n {
			return "", 0, nil, fmt.Errorf("short name2")
		}
		return string(b[5 : 5+n]), int(binary.BigEndian.Uint16(b[5+n : 7+n])), b[7+n:], nil
	default:
		return "", 0, nil, fmt.Errorf("atyp")
	}
}

func encodeSocksUDP(from net.Addr, payload []byte) []byte {
	host, portStr, _ := net.SplitHostPort(from.String())
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	out := []byte{0, 0, 0}
	if v4 := ip.To4(); v4 != nil {
		out = append(out, 1)
		out = append(out, v4...)
	} else if ip != nil {
		out = append(out, 4)
		out = append(out, ip.To16()...)
	} else {
		return payload
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	out = append(out, pb[:]...)
	return append(out, payload...)
}
