package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func buildI1(kind, sni string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	sni = strings.TrimSpace(sni)
	if sni == "" {
		sni = "www.cloudflare.com"
	}
	var pkt []byte
	switch kind {
	case "", "none":
		return ""
	case "awg":
		pkt = quicInitial(sni)
	case "dns":
		pkt = dnsQuery(sni)
	case "sip":
		pkt = sipOptions(sni)
	case "stun":
		pkt = stunBinding()
	case "quic":
		pkt = quicInitial(sni)
	default:
		return ""
	}
	if len(pkt) == 0 {
		return ""
	}
	return "<b 0x" + hex.EncodeToString(pkt) + ">"
}

func dnsQuery(name string) []byte {
	id := make([]byte, 2)
	_, _ = rand.Read(id)
	var b []byte
	b = append(b, id...)
	b = append(b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(strings.Trim(name, "."), ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0x00, 0x00, 0x01, 0x00, 0x01)
	return b
}

func sipOptions(host string) []byte {
	branch := make([]byte, 8)
	_, _ = rand.Read(branch)
	tag := hex.EncodeToString(branch)
	msg := fmt.Sprintf(
		"OPTIONS sip:%s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK%s\r\n"+
			"From: <sip:user@192.0.2.1>;tag=%s\r\n"+
			"To: <sip:%s>\r\n"+
			"Call-ID: %s@192.0.2.1\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Contact: <sip:user@192.0.2.1:5060>\r\n"+
			"Max-Forwards: 70\r\n"+
			"Content-Length: 0\r\n\r\n",
		host, tag[:8], tag[8:], host, tag,
	)
	return []byte(msg)
}

func stunBinding() []byte {
	pkt := make([]byte, 20)
	pkt[0], pkt[1] = 0x00, 0x01
	binary.BigEndian.PutUint16(pkt[2:4], 0)
	binary.BigEndian.PutUint32(pkt[4:8], 0x2112A442)
	_, _ = rand.Read(pkt[8:20])
	return pkt
}

func quicInitial(sni string) []byte {
	dcid := make([]byte, 8)
	scid := make([]byte, 8)
	_, _ = rand.Read(dcid)
	_, _ = rand.Read(scid)
	ch := tlsClientHello(sni)
	var payload []byte
	payload = append(payload, 0x06) // CRYPTO frame
	payload = append(payload, 0x00) // offset 0
	payload = append(payload, encodeVarint(uint64(len(ch)))...)
	payload = append(payload, ch...)
	for len(payload) < 120 {
		payload = append(payload, 0x00)
	}

	var b []byte
	b = append(b, 0xC3) // long header, Initial, 1-byte PN
	b = append(b, 0x00, 0x00, 0x00, 0x01)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	b = append(b, 0x00) // token length
	pnAndPayload := append([]byte{0x00}, payload...)
	b = append(b, encodeVarint(uint64(len(pnAndPayload)))...)
	b = append(b, pnAndPayload...)
	if len(b) > 1200 {
		b = b[:1200]
	}
	return b
}

func encodeVarint(n uint64) []byte {
	switch {
	case n < 64:
		return []byte{byte(n)}
	case n < 16384:
		return []byte{byte(0x40 | (n >> 8)), byte(n)}
	default:
		v := uint32(n)
		return []byte{byte(0x80 | (v >> 24)), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

func tlsClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	extSNI := []byte{0x00, 0x00}
	sniListLen := 3 + len(sniBytes)
	extBody := make([]byte, 0, 2+sniListLen)
	extBody = append(extBody, byte(sniListLen>>8), byte(sniListLen))
	extBody = append(extBody, 0x00)
	extBody = append(extBody, byte(len(sniBytes)>>8), byte(len(sniBytes)))
	extBody = append(extBody, sniBytes...)
	extSNI = append(extSNI, byte(len(extBody)>>8), byte(len(extBody)))
	extSNI = append(extSNI, extBody...)

	extVersions := []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}
	extensions := append(extSNI, extVersions...)

	random := make([]byte, 32)
	_, _ = rand.Read(random)
	session := []byte{0x00}
	cipher := []byte{0x00, 0x02, 0x13, 0x01}
	comp := []byte{0x01, 0x00}

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, session...)
	body = append(body, cipher...)
	body = append(body, comp...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	var hs []byte
	hs = append(hs, 0x01)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}
