package internal

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/txthinking/socks5"
)

var traceConnID atomic.Int64

type traceDir struct {
	bytes int64
	first time.Duration
	end   time.Duration
	err   error
}

func traceErr(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, io.EOF):
		return "EOF"
	default:
		return err.Error()
	}
}

// tracedConnect is CmdConnect with logging at each stage. "up" is client to
// remote, "down" is remote to client. A connection that never logs "closed"
// is still waiting on the side shown in its last "done" line.
func (s *SOCKS5Server) tracedConnect(srv *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	id := traceConnID.Add(1)
	dst := r.Address()
	start := time.Now()
	dialDone := make(chan struct{})
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-dialDone:
				return
			case <-t.C:
				log.Printf("trace conn#%d %s still dialing after %dms", id, dst, time.Since(start).Milliseconds())
			}
		}
	}()
	rc, err := r.Connect(c)
	close(dialDone)
	dial := time.Since(start)
	if err != nil {
		log.Printf("trace conn#%d %s dial failed after %dms: %v", id, dst, dial.Milliseconds(), err)
		return err
	}
	defer func() { _ = rc.Close() }()
	log.Printf("trace conn#%d %s dialed in %dms", id, dst, dial.Milliseconds())

	timeout := time.Duration(srv.TCPTimeout) * time.Second
	var up, down traceDir
	var wg sync.WaitGroup
	wg.Add(2)
	relay := func(name string, d *traceDir, to, from net.Conn) {
		defer wg.Done()
		bp := tcpRelayBufPool.Get().(*[]byte)
		buf := *bp
		defer tcpRelayBufPool.Put(bp)
		for {
			if timeout > 0 {
				if err := from.SetReadDeadline(time.Now().Add(timeout)); err != nil {
					d.err = err
					break
				}
			}
			n, err := from.Read(buf)
			if n > 0 {
				if d.bytes == 0 {
					d.first = time.Since(start)
				}
				d.bytes += int64(n)
				if _, writeErr := to.Write(buf[:n]); writeErr != nil {
					d.err = writeErr
					break
				}
			}
			if err != nil {
				d.err = err
				if cw, ok := to.(closeWriter); ok {
					_ = cw.CloseWrite()
				}
				break
			}
		}
		d.end = time.Since(start)
		log.Printf("trace conn#%d %s %s done at %dms: %d B (first byte at %dms) end=%s",
			id, dst, name, d.end.Milliseconds(), d.bytes, d.first.Milliseconds(), traceErr(d.err))
	}
	go relay("up", &up, rc, c)
	go relay("down", &down, c, rc)
	wg.Wait()
	log.Printf("trace conn#%d %s closed after %dms: up %d B, down %d B",
		id, dst, time.Since(start).Milliseconds(), up.bytes, down.bytes)
	return nil
}

// tracedTunnelDial is TunNet.DialContext split into its lookup and per-address
// connect steps so each one is logged. Behaviour is unchanged: no deadlines,
// addresses tried in the netstack's order (IPv6 first when the tunnel has IPv6).
func (s *SOCKS5Server) tracedTunnelDial(network, raddr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	addrs := []string{host}
	if net.ParseIP(host) == nil {
		start := time.Now()
		addrs, err = s.cfg.TunNet.LookupContextHost(ctx, host)
		if err != nil {
			log.Printf("trace dns %s failed after %dms: %v", host, time.Since(start).Milliseconds(), err)
			return nil, err
		}
		log.Printf("trace dns %s resolved in %dms: %v", host, time.Since(start).Milliseconds(), addrs)
	}
	var firstErr error
	for _, a := range addrs {
		target := net.JoinHostPort(a, port)
		start := time.Now()
		c, err := s.cfg.TunNet.DialContext(ctx, network, target)
		if err == nil {
			log.Printf("trace tcp %s (%s) connected in %dms", target, host, time.Since(start).Milliseconds())
			return c, nil
		}
		log.Printf("trace tcp %s (%s) failed after %dms: %v", target, host, time.Since(start).Milliseconds(), err)
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no addresses")
	}
	return nil, firstErr
}
