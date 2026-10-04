package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type pingRequest struct {
	Parallel  int           `json:"parallel"`
	TimeoutMs int           `json:"timeout_ms"`
	ProbeHost string        `json:"probe_host"`
	ProbePort int           `json:"probe_port"`
	ProbePath string        `json:"probe_path"`
	Identity  socksConfig   `json:"identity"`
	Probes    []pingProbeIn `json:"probes"`
}

type pingProbeIn struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
}

type pingResult struct {
	ID    string `json:"id"`
	Ms    int64  `json:"ms,omitempty"`
	Error string `json:"error,omitempty"`
}

func runPing(raw []byte) ([]byte, error) {
	var req pingRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if req.Parallel < 1 {
		req.Parallel = 1
	}
	if req.Parallel > 8 {
		req.Parallel = 8
	}
	if req.TimeoutMs < 250 {
		req.TimeoutMs = 8000
	}
	if req.ProbeHost == "" {
		req.ProbeHost = "www.gstatic.com"
	}
	if req.ProbePort == 0 {
		req.ProbePort = 80
	}
	if req.ProbePath == "" {
		req.ProbePath = "/generate_204"
	}
	if req.Identity.PrivateKey == "" || req.Identity.PeerPublicKey == "" {
		return nil, fmt.Errorf("ping identity needs private_key and peer_public_key")
	}

	out := make([]pingResult, len(req.Probes))
	sem := make(chan struct{}, req.Parallel)
	var wg sync.WaitGroup
	for i, p := range req.Probes {
		wg.Add(1)
		go func(i int, p pingProbeIn) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms, err := pingOne(&req, p)
			if err != nil {
				out[i] = pingResult{ID: p.ID, Error: err.Error()}
				return
			}
			out[i] = pingResult{ID: p.ID, Ms: ms}
		}(i, p)
	}
	wg.Wait()
	return json.Marshal(map[string]any{"results": out})
}

func pingOne(req *pingRequest, p pingProbeIn) (int64, error) {
	if strings.TrimSpace(p.Endpoint) == "" {
		return 0, fmt.Errorf("missing endpoint")
	}
	cfg := req.Identity.cloneForPing(p.Endpoint)
	t, err := openTunnel(cfg)
	if err != nil {
		return 0, err
	}
	defer t.close()
	deadline := time.Now().Add(time.Duration(req.TimeoutMs) * time.Millisecond)
	return socksGenerate204("127.0.0.1", t.port, req.ProbeHost, req.ProbePort, req.ProbePath, deadline)
}

func socksGenerate204(socksHost string, socksPort int, host string, port int, path string, deadline time.Time) (int64, error) {
	start := time.Now()
	d := net.Dialer{Deadline: deadline}
	c, err := d.Dial("tcp", net.JoinHostPort(socksHost, fmt.Sprintf("%d", socksPort)))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(deadline)

	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return 0, err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		return 0, err
	}
	if greet[0] != 5 || greet[1] != 0 {
		return 0, fmt.Errorf("socks greeting refused")
	}

	hb := []byte(host)
	req := []byte{5, 1, 0, 3, byte(len(hb))}
	req = append(req, hb...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		return 0, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return 0, err
	}
	if head[0] != 5 || head[1] != 0 {
		return 0, fmt.Errorf("socks connect failed")
	}
	switch head[3] {
	case 1:
		if _, err := io.CopyN(io.Discard, c, 4); err != nil {
			return 0, err
		}
	case 4:
		if _, err := io.CopyN(io.Discard, c, 16); err != nil {
			return 0, err
		}
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return 0, err
		}
		if _, err := io.CopyN(io.Discard, c, int64(lb[0])); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("bad atyp")
	}
	if _, err := io.CopyN(io.Discard, c, 2); err != nil {
		return 0, err
	}

	httpReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: persianray-ios-awg-ping/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host)
	if _, err := io.WriteString(c, httpReq); err != nil {
		return 0, err
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)
	if !strings.Contains(line, " 204") {
		return 0, fmt.Errorf("unexpected HTTP status: %s", line)
	}
	return time.Since(start).Milliseconds(), nil
}
