package api

import (
	"net"
	"testing"
	"time"
)

func initialPacket(dcid byte) []byte {
	p := make([]byte, 1200)
	p[0] = 0xc0
	p[4] = 1
	p[5] = 8
	for i := 0; i < 8; i++ {
		p[6+i] = dcid
	}
	return p
}

func TestUDPSpoofPresetMatchesAndroid(t *testing.T) {
	split, err := UDPSpoofPreset("split")
	if err != nil || !split.Split || split.Reorder || split.Active() {
		t.Fatalf("split = %+v err=%v", split, err)
	}
	reorder, err := UDPSpoofPreset("reorder")
	if err != nil || reorder.Split || !reorder.Reorder || reorder.Active() {
		t.Fatalf("reorder = %+v err=%v", reorder, err)
	}
	full, err := UDPSpoofPreset("full")
	if err != nil || !full.Split || full.Reorder || !full.Active() || full.Junk != 2 || !full.SIP {
		t.Fatalf("full = %+v err=%v", full, err)
	}
	junk, err := UDPSpoofPreset("junk")
	if err != nil || junk.Split || junk.Reorder || junk.Junk != 3 {
		t.Fatalf("junk = %+v err=%v", junk, err)
	}
}

func TestSpoofPacketConnPrefaceOncePerDCID(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	spoof, _ := UDPSpoofPreset("full")
	conn := newSpoofPacketConn(client, spoof)
	defer conn.Close()

	dst := server.LocalAddr()
	for _, p := range [][]byte{initialPacket(1), initialPacket(1), {0x40, 1, 2}, initialPacket(2)} {
		if _, err := conn.WriteTo(p, dst); err != nil {
			t.Fatal(err)
		}
	}
	// full = 2 junk + DNS + STUN + SIP + QUIC decoy = 6 per new DCID.
	want := 6 + 4 + 6
	buf := make([]byte, 2048)
	got := 0
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	for {
		if _, _, err := server.ReadFrom(buf); err != nil {
			break
		}
		got++
	}
	if got != want {
		t.Fatalf("got %d datagrams, want %d", got, want)
	}

	vn := []byte{0x80, 0, 0, 0, 0, 0}
	if _, err := server.WriteTo(vn, client.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := server.WriteTo([]byte{0x40, 9}, client.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil || n != 2 || buf[1] != 9 {
		t.Fatalf("read n=%d err=%v; version negotiation was not dropped", n, err)
	}
}
