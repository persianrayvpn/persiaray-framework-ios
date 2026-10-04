package api

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// UDPSpoof is the MASQUE UDP spoof preface. Before each new QUIC Initial
// (new DCID) it sends junk and decoy datagrams on the same socket. The zero
// value sends nothing.
type UDPSpoof struct {
	Junk      int
	QuicDecoy bool
	DNS       bool
	STUN      bool
	SIP       bool
	// SNI is the decoy hostname. Empty or invalid falls back to www.google.com.
	SNI string
	// Split sends the QUIC ClientHello in two Initial packets. It is not a
	// preface datagram. The patched quic-go packer reads it during Dial.
	Split bool
	// Reorder sends the later ClientHello bytes, including the hostname,
	// before the earlier bytes. It is not a preface datagram.
	Reorder bool
}

// Active reports whether any preface datagram is sent.
func (s UDPSpoof) Active() bool {
	return s.Junk > 0 || s.QuicDecoy || s.DNS || s.STUN || s.SIP
}

// UDPSpoofPreset returns the preface for a preset id. The ids match
// PersianRay's MasqueUdpSpoofPreset. "split" and "reorder" have no preface.
// "full" is the preface plus a split ClientHello, matching Android.
func UDPSpoofPreset(id string) (UDPSpoof, error) {
	switch strings.TrimSpace(strings.ToLower(id)) {
	case "", "off":
		return UDPSpoof{}, nil
	case "split":
		return UDPSpoof{Split: true}, nil
	case "reorder":
		return UDPSpoof{Reorder: true}, nil
	case "junk":
		return UDPSpoof{Junk: 3}, nil
	case "quic":
		return UDPSpoof{QuicDecoy: true}, nil
	case "dns_stun":
		return UDPSpoof{DNS: true, STUN: true}, nil
	case "junk_quic":
		return UDPSpoof{Junk: 2, QuicDecoy: true}, nil
	case "full":
		return UDPSpoof{Junk: 2, QuicDecoy: true, DNS: true, STUN: true, SIP: true, Split: true}, nil
	}
	return UDPSpoof{}, fmt.Errorf("unknown udp spoof preset %q", id)
}

// spoofPacketConn must not expose ReadMsgUDP/WriteMsgUDP. quic-go would use
// those directly and skip WriteTo, so the preface would never be sent.
type spoofPacketConn struct {
	conn  *net.UDPConn
	spoof UDPSpoof
	mu    sync.Mutex
	seen  map[string]struct{}
}

func newSpoofPacketConn(conn *net.UDPConn, spoof UDPSpoof) *spoofPacketConn {
	return &spoofPacketConn{conn: conn, spoof: spoof, seen: make(map[string]struct{})}
}

func (c *spoofPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.conn.ReadFrom(p)
		if err != nil || !isQUICVersionNegotiation(p[:n]) {
			return n, addr, err
		}
	}
}

func (c *spoofPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if dcid := quicInitialDCID(p); dcid != nil {
		c.mu.Lock()
		_, dup := c.seen[string(dcid)]
		if !dup {
			c.seen[string(dcid)] = struct{}{}
		}
		c.mu.Unlock()
		if !dup {
			if err := c.sendPreface(addr); err != nil {
				log.Printf("MASQUE UDP preface failed: %v", err)
			}
		}
	}
	return c.conn.WriteTo(p, addr)
}

func (c *spoofPacketConn) Close() error                       { return c.conn.Close() }
func (c *spoofPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *spoofPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *spoofPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *spoofPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *spoofPacketConn) SetReadBuffer(n int) error          { return c.conn.SetReadBuffer(n) }
func (c *spoofPacketConn) SetWriteBuffer(n int) error         { return c.conn.SetWriteBuffer(n) }

func (c *spoofPacketConn) sendPreface(addr net.Addr) error {
	s := c.spoof
	junk := s.Junk
	if junk > 8 {
		junk = 8
	}
	for i := 0; i < junk; i++ {
		b := randBytes(200 + randIntn(601))
		b[0] &^= 0x40
		if _, err := c.conn.WriteTo(b, addr); err != nil {
			return err
		}
	}
	name := decoyName(s.SNI)
	var extra [][]byte
	if s.DNS {
		extra = append(extra, dnsQuery(name))
	}
	if s.STUN {
		extra = append(extra, stunBinding())
	}
	if s.SIP {
		extra = append(extra, []byte("OPTIONS sip:"+name+" SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n\r\n"))
	}
	if s.QuicDecoy {
		extra = append(extra, fakeQUICInitial(name))
	}
	for _, b := range extra {
		if _, err := c.conn.WriteTo(b, addr); err != nil {
			return err
		}
	}
	return nil
}

func decoyName(sni string) string {
	host := strings.ToLower(strings.TrimSpace(sni))
	if len(host) < 3 || len(host) > 200 {
		return "www.google.com"
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return "www.google.com"
		}
	}
	return host
}

func dnsQuery(name string) []byte {
	var out bytes.Buffer
	out.Write(randBytes(2))
	out.Write([]byte{0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		out.WriteByte(byte(len(label)))
		out.WriteString(label)
	}
	out.Write([]byte{0, 0, 1, 0, 1})
	return out.Bytes()
}

func stunBinding() []byte {
	out := make([]byte, 20)
	out[1] = 0x01
	binary.BigEndian.PutUint32(out[4:8], 0x2112A442)
	copy(out[8:], randBytes(12))
	return out
}

// fakeQUICInitial clears the QUIC fixed bit. A real long header here would be
// the first QUIC packet Cloudflare sees, and the real Initial gets no answer.
func fakeQUICInitial(name string) []byte {
	b := randBytes(1200)
	b[0] &^= 0x40
	if len(name) > 0 && len(name) < len(b)-32 {
		copy(b[32:], name)
	}
	return b
}

// quicInitialDCID returns the DCID of a long-header Initial, or nil.
func quicInitialDCID(p []byte) []byte {
	if len(p) < 7 || p[0]&0x80 == 0 || p[0]&0x40 == 0 || (p[0]&0x30)>>4 != 0 {
		return nil
	}
	if binary.BigEndian.Uint32(p[1:5]) == 0 {
		return nil
	}
	n := int(p[5])
	if n < 1 || n > 20 || len(p) < 6+n {
		return nil
	}
	return p[6 : 6+n]
}

func isQUICVersionNegotiation(p []byte) bool {
	return len(p) >= 5 && p[0]&0x80 != 0 && binary.BigEndian.Uint32(p[1:5]) == 0
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randIntn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
