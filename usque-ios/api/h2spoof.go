package api

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// H2Spoof is the MASQUE TCP spoof path. The zero value keeps the stock
// crypto/tls handshake and unsplit HTTP/2 records.
type H2Spoof struct {
	// RecordSplit rewraps the ClientHello as two large TLS records.
	RecordSplit bool
	// SplitAtHost cuts that record through the SNI hostname. Off keeps the
	// middle cut. It implies RecordSplit.
	SplitAtHost bool
	// UTLS uses a Chrome ClientHello. Off uses crypto/tls, as before.
	UTLS bool
	// H2Pad splits the first application bytes into small TLS records so
	// HTTP/2 frame sizes are not one burst. Off writes records unchanged.
	H2Pad bool
	// TcpSplit sends one intact ClientHello as two TCP segments, cut through
	// the SNI hostname. Off sends the hello in one write. It is not a TLS
	// record split, and it stays off when RecordSplit or SplitAtHost is on.
	TcpSplit bool
}

func dialH2TLS(ctx context.Context, raw net.Conn, cfg *tls.Config, spoof H2Spoof) (net.Conn, error) {
	if tcp, ok := raw.(*net.TCPConn); ok && spoof.TcpSplit {
		_ = tcp.SetNoDelay(true)
	}
	if spoof.RecordSplit || spoof.SplitAtHost {
		raw = &handshakeRecordSplitter{Conn: raw, atHost: spoof.SplitAtHost}
	} else if spoof.TcpSplit {
		raw = newTCPSegmentSplitter(raw)
	}
	// A stuck handshake otherwise sits until the process is killed.
	deadline := time.Now().Add(8 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = raw.SetDeadline(deadline)
	defer func() { _ = raw.SetDeadline(time.Time{}) }()

	var out net.Conn
	if spoof.UTLS {
		// Chrome_120, not HelloChrome_Auto: current Chrome adds a post-quantum
		// key share and the ClientHello spills into a second packet that filtered
		// networks drop, so the handshake never finishes.
		uconn := utls.UClient(raw, utlsConfig(cfg), utls.HelloChrome_120)
		if err := uconn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		out = uconn
	} else {
		tlsConn := tls.Client(raw, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		out = tlsConn
	}
	if spoof.H2Pad {
		out = &tlsRecordSplitter{Conn: out, budget: 4096}
	}
	return out, nil
}

func utlsConfig(cfg *tls.Config) *utls.Config {
	certs := make([]utls.Certificate, 0, len(cfg.Certificates))
	for _, c := range cfg.Certificates {
		certs = append(certs, utls.Certificate{
			Certificate: c.Certificate,
			PrivateKey:  c.PrivateKey,
			Leaf:        c.Leaf,
		})
	}
	return &utls.Config{
		Certificates:         certs,
		ServerName:           cfg.ServerName,
		NextProtos:           []string{"h2"},
		InsecureSkipVerify:   true,
		VerifyPeerCertificate: cfg.VerifyPeerCertificate,
	}
}

// tlsRecordSplitter breaks the first budget bytes of post-handshake writes
// into small TLS records. Later writes pass through.
type tlsRecordSplitter struct {
	net.Conn
	budget int
}

func (c *tlsRecordSplitter) Write(p []byte) (int, error) {
	if c.budget <= 0 || len(p) <= 64 {
		n, err := c.Conn.Write(p)
		if n > 0 && c.budget > 0 {
			c.budget -= n
		}
		return n, err
	}
	written := 0
	for len(p) > 0 && c.budget > 0 {
		n := 64
		if n > len(p) {
			n = len(p)
		}
		if n > c.budget {
			n = c.budget
		}
		wn, err := c.Conn.Write(p[:n])
		written += wn
		c.budget -= wn
		if err != nil || wn == 0 {
			return written, err
		}
		p = p[wn:]
	}
	if len(p) == 0 {
		return written, nil
	}
	wn, err := c.Conn.Write(p)
	return written + wn, err
}

const tcpSplitGap = 50 * time.Millisecond

// tcpSegmentSplitter sends the first ClientHello as two TCP segments and
// leaves the TLS record intact. The cut falls in the SNI hostname.
type tcpSegmentSplitter struct {
	net.Conn
	gap  time.Duration
	mu   sync.Mutex
	buf  []byte
	done bool
}

func newTCPSegmentSplitter(conn net.Conn) *tcpSegmentSplitter {
	return &tcpSegmentSplitter{Conn: conn, gap: tcpSplitGap}
}

func (c *tcpSegmentSplitter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return c.Conn.Write(p)
	}
	c.buf = append(c.buf, p...)
	rec, rest, ok := firstHandshakeRecord(c.buf)
	if !ok {
		if len(c.buf) > 17000 {
			c.done = true
			out := c.buf
			c.buf = nil
			_, err := c.Conn.Write(out)
			return len(p), err
		}
		return len(p), nil
	}
	c.buf = nil
	c.done = true
	cut := tcpHelloCut(rec)
	if cut > 0 && cut < len(rec) {
		if _, err := c.Conn.Write(rec[:cut]); err != nil {
			return 0, err
		}
		if c.gap > 0 {
			time.Sleep(c.gap)
		}
		if _, err := c.Conn.Write(rec[cut:]); err != nil {
			return 0, err
		}
	} else if _, err := c.Conn.Write(rec); err != nil {
		return 0, err
	}
	if len(rest) > 0 {
		if _, err := c.Conn.Write(rest); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// tcpHelloCut is a byte offset in the TLS record that falls inside the SNI
// hostname. -1 keeps the hello in one write.
func tcpHelloCut(rec []byte) int {
	if len(rec) < 5 || rec[0] != 0x16 {
		return -1
	}
	body := rec[5:]
	if len(body) <= 160 {
		return -1
	}
	n := hostnameCut(body)
	if n < 20 || n >= len(body)-20 {
		n = middleCut(body)
	}
	cut := 5 + n
	if cut <= 0 || cut >= len(rec) {
		return -1
	}
	return cut
}

// handshakeRecordSplitter rewraps the first TLS handshake record as two
// records, then splices. A 1-byte first record makes Cloudflare wait.
type handshakeRecordSplitter struct {
	net.Conn
	atHost bool
	mu     sync.Mutex
	buf    []byte
	done   bool
}

func (c *handshakeRecordSplitter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return c.Conn.Write(p)
	}
	c.buf = append(c.buf, p...)
	rec, rest, ok := firstHandshakeRecord(c.buf)
	if !ok {
		if len(c.buf) > 17000 {
			c.done = true
			out := c.buf
			c.buf = nil
			_, err := c.Conn.Write(out)
			return len(p), err
		}
		return len(p), nil
	}
	split := splitHandshakeRecords(rec, c.atHost)
	out := append(split, rest...)
	c.buf = nil
	c.done = true
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func firstHandshakeRecord(raw []byte) (rec, rest []byte, ok bool) {
	if len(raw) < 5 || raw[0] != 0x16 {
		return nil, nil, false
	}
	n := int(raw[3])<<8 | int(raw[4])
	if len(raw) < 5+n {
		return nil, nil, false
	}
	return raw[:5+n], raw[5+n:], true
}

func splitHandshakeRecords(raw []byte, atHost bool) []byte {
	if len(raw) < 5 || raw[0] != 0x16 {
		return raw
	}
	body := raw[5:]
	if len(body) <= 160 {
		return raw
	}
	n := len(body) / 2
	if atHost {
		if cut := hostnameCut(body); cut >= 20 && cut < len(body)-20 {
			n = cut
		} else {
			n = middleCut(body)
		}
	} else {
		n = middleCut(body)
	}
	first := tlsRecord(raw[1], raw[2], body[:n])
	second := tlsRecord(raw[1], raw[2], body[n:])
	return append(first, second...)
}

func middleCut(body []byte) int {
	n := len(body)/2 + rand.Intn(41) - 20
	if n < 80 {
		n = 80
	}
	if n > len(body)-80 {
		n = len(body) - 80
	}
	return n
}

// hostnameCut is an index inside the handshake body that falls in the SNI
// hostname. -1 means the hello has no usable name, so the caller keeps the
// middle cut.
func hostnameCut(hs []byte) int {
	if len(hs) < 44 || hs[0] != 0x01 {
		return -1
	}
	i := 4 + 34
	if i >= len(hs) {
		return -1
	}
	sidLen := int(hs[i])
	i += 1 + sidLen
	if i+2 > len(hs) {
		return -1
	}
	csLen := u16(hs, i)
	i += 2 + csLen
	if i+1 > len(hs) {
		return -1
	}
	compLen := int(hs[i])
	i += 1 + compLen
	if i+2 > len(hs) {
		return -1
	}
	extEnd := i + 2 + u16(hs, i)
	i += 2
	if extEnd > len(hs) {
		return -1
	}
	for i+4 <= extEnd {
		typ := u16(hs, i)
		n := u16(hs, i+2)
		i += 4
		if i+n > extEnd {
			return -1
		}
		if typ == 0 && n >= 5 {
			nameLen := u16(hs, i+3)
			nameAt := i + 5
			if nameLen >= 2 && nameAt+nameLen <= i+n {
				return nameAt + nameLen/2
			}
		}
		i += n
	}
	return -1
}

func u16(b []byte, i int) int {
	return int(b[i])<<8 | int(b[i+1])
}

func tlsRecord(ver0, ver1 byte, body []byte) []byte {
	rec := make([]byte, 5+len(body))
	rec[0] = 0x16
	rec[1] = ver0
	rec[2] = ver1
	rec[3] = byte(len(body) >> 8)
	rec[4] = byte(len(body))
	copy(rec[5:], body)
	return rec
}
