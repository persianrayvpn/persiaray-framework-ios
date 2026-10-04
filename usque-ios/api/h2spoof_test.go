package api

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestTcpSegmentSplitterCutsInsideSNI(t *testing.T) {
	const name = "www.google.com"
	rec := clientHelloWithSNI(name)
	cut := tcpHelloCut(rec)
	at := bytes.Index(rec, []byte(name))
	if at < 0 || cut <= at || cut >= at+len(name) {
		t.Fatalf("cut %d, name at %d len %d, record %d", cut, at, len(name), len(rec))
	}

	left, right := net.Pipe()
	spl := newTCPSegmentSplitter(left)
	spl.gap = 0
	errc := make(chan error, 1)
	go func() {
		_, err := spl.Write(rec)
		errc <- err
	}()

	_ = right.SetReadDeadline(time.Now().Add(2 * time.Second))
	first := make([]byte, cut)
	if _, err := readFull(right, first); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, rec[:cut]) {
		t.Fatal("first segment is not the hostname prefix")
	}
	second := make([]byte, len(rec)-cut)
	if _, err := readFull(right, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, rec[cut:]) {
		t.Fatal("second segment does not finish the same TLS record")
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	_ = left.Close()
	_ = right.Close()
}

func readFull(c net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := c.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func clientHelloWithSNI(name string) []byte {
	body := []byte{0x01, 0, 0, 0, 0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	ext := sniExtension(name)
	ext = append(ext, paddingExtension(220)...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hsLen := len(body) - 4
	body[1] = byte(hsLen >> 16)
	body[2] = byte(hsLen >> 8)
	body[3] = byte(hsLen)
	rec := make([]byte, 5+len(body))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	rec[3] = byte(len(body) >> 8)
	rec[4] = byte(len(body))
	copy(rec[5:], body)
	return rec
}

func sniExtension(name string) []byte {
	nb := []byte(name)
	listLen := 1 + 2 + len(nb)
	data := make([]byte, 2+listLen)
	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)
	data[3] = byte(len(nb) >> 8)
	data[4] = byte(len(nb))
	copy(data[5:], nb)
	out := []byte{0, 0, byte(len(data) >> 8), byte(len(data))}
	return append(out, data...)
}

func paddingExtension(n int) []byte {
	out := []byte{0, 21, byte(n >> 8), byte(n)}
	return append(out, make([]byte, n)...)
}
