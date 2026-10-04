package mobile

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndpointHost(t *testing.T) {
	for input, want := range map[string]string{
		"162.159.193.10:0":            "162.159.193.10",
		"[2606:4700:d0::a29f:c001]:0": "2606:4700:d0::a29f:c001",
	} {
		got, err := endpointHost(input)
		if err != nil {
			t.Fatalf("endpointHost(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("endpointHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSOCKSAddressRoundTrip(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "example.com"} {
		wire := encodeAddress(host)
		got, used, err := addressFromBytes(wire[0], wire[1:])
		if err != nil {
			t.Fatalf("decode %q: %v", host, err)
		}
		if got != host || used != len(wire)-1 {
			t.Fatalf("round trip %q = %q (%d bytes)", host, got, used)
		}
	}
}

func TestSelectEndpointProtocol(t *testing.T) {
	base := StartRequest{Config: AccountConfig{EndpointV4: "192.0.2.1", EndpointH2V4: "192.0.2.2"}, ConnectPort: 443}
	base.Transport = "h3"
	if endpoint, err := selectEndpoint(context.Background(), base); err != nil {
		t.Fatal(err)
	} else if _, ok := endpoint.(*net.UDPAddr); !ok {
		t.Fatalf("h3 endpoint type = %T", endpoint)
	}
	base.Transport = "h2"
	if endpoint, err := selectEndpoint(context.Background(), base); err != nil {
		t.Fatal(err)
	} else if _, ok := endpoint.(*net.TCPAddr); !ok {
		t.Fatalf("h2 endpoint type = %T", endpoint)
	}
}

func TestRegisterRequiresExplicitTOS(t *testing.T) {
	var response map[string]any
	if err := json.Unmarshal([]byte(Register(`{}`)), &response); err != nil {
		t.Fatal(err)
	}
	if response["ok"] != false {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestSwiftCompatibilityRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usque.json")
	cfg := AccountConfig{
		PrivateKey: "private", EndpointV4: "192.0.2.1",
		EndpointH2V4: "192.0.2.2", EndpointPubKey: "public",
		IPv4: "172.16.0.2", IPv6: "2606:4700:110::2",
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{
		"configPath": path, "bind": "127.0.0.1", "socksPort": 10809,
		"endpointHost": "198.51.100.4", "endpointPort": 8443,
		"http2": true, "keepaliveSeconds": 10,
		"hopRelay": map[string]any{
			"bind": "127.0.0.1", "port": 10810,
			"targetHost": "203.0.113.5", "targetPort": 2408,
		},
	})
	start, hop, err := compatibilityStartRequest(string(input))
	if err != nil {
		t.Fatal(err)
	}
	if start.Transport != "h2" || start.Config.EndpointH2V4 != "198.51.100.4" || start.ConnectPort != 8443 {
		t.Fatalf("unexpected start request: %#v", start)
	}
	if hop == nil || hop.RelayPort != 10810 || hop.TargetPort != 2408 {
		t.Fatalf("unexpected hop request: %#v", hop)
	}
}

func TestInvokeStopIsIdempotent(t *testing.T) {
	var response map[string]any
	if err := json.Unmarshal([]byte(Invoke(`{"method":"stop"}`)), &response); err != nil {
		t.Fatal(err)
	}
	if response["ok"] != true {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestInvokeAbortProbesIsIdempotent(t *testing.T) {
	var response struct {
		OK      bool `json:"ok"`
		Stopped int  `json:"stopped"`
	}
	if err := json.Unmarshal([]byte(Invoke(`{"method":"abortProbes"}`)), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Stopped != 0 {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestEphemeralHopRelayBindsPort(t *testing.T) {
	relay, err := newUDPRelay(context.Background(), "127.0.0.1", 0, "203.0.113.5", 2408, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.close()
	if relay.port() <= 0 {
		t.Fatalf("ephemeral hop relay port = %d", relay.port())
	}
}

func TestMeasureGenerate204RequiresHTTP204(t *testing.T) {
	for status, wantError := range map[int]bool{204: false, 200: true, 503: true} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := measureGenerate204(ctx, responseDialer(t, status, nil))
			if (err != nil) != wantError {
				t.Fatalf("status %d error = %v", status, err)
			}
		})
	}
}

func TestGenerate204WarmupDiscardsFirstSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	requests := make(chan string, 2)
	elapsed, err := runGenerate204Probe(ctx, true, responseDialer(t, 204, requests))
	if err != nil {
		t.Fatal(err)
	}
	if elapsed < 0 {
		t.Fatalf("negative latency: %v", elapsed)
	}
	if len(requests) != 2 {
		t.Fatalf("request count = %d, want 2", len(requests))
	}
	for i := 0; i < 2; i++ {
		request := <-requests
		if request != "GET /generate_204 HTTP/1.1" {
			t.Fatalf("request line = %q", request)
		}
	}
}

func TestGenerate204RetriesAreBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var calls int
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("offline")
	}
	if _, err := runGenerate204Probe(ctx, false, dial); err == nil {
		t.Fatal("expected probe failure")
	}
	if calls != 3 {
		t.Fatalf("dial attempts = %d, want 3", calls)
	}
}

func TestGenerate204HonorsContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	dial := func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			<-ctx.Done()
			_ = server.Close()
		}()
		return client, nil
	}
	started := time.Now()
	if _, err := runGenerate204Probe(ctx, false, dial); err == nil {
		t.Fatal("expected deadline failure")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("deadline took %v", elapsed)
	}
}

func responseDialer(t *testing.T, status int, requests chan<- string) contextDialer {
	t.Helper()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != generate204Address {
			return nil, fmt.Errorf("unexpected target %s %s", network, address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if requests != nil {
				requests <- strings.TrimSpace(line)
			}
			for {
				line, err = reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			_, _ = io.WriteString(server, fmt.Sprintf(
				"HTTP/1.1 %d Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
				status,
			))
		}()
		return client, nil
	}
}
