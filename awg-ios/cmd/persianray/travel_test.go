package main

import (
	"net/netip"
	"strings"
	"testing"
)

func TestTravelNat64EmbedsIPv4(t *testing.T) {
	got, ok := travelNat64("2a00:1098:2b:0:0:1::", "162.159.192.1")
	if !ok || netip.MustParseAddr(got) != netip.MustParseAddr("2a00:1098:2b:0:0:1:a29f:c001") {
		t.Fatalf("got %q", got)
	}
	a, _ := travelPrefixKey("2a00:1098:2b::1:0:0")
	b, _ := travelPrefixKey("2a00:1098:2b:0:0:1::")
	if a != b {
		t.Fatal("same /96 written differently must match")
	}
}

func TestTravelEveryCountryHasPrefix(t *testing.T) {
	for _, c := range travelCountries {
		found := false
		for _, p := range travelPrefixes {
			if p.country == c {
				found = true
			}
		}
		if !found {
			t.Fatalf("no prefix for %s", c)
		}
	}
}

func TestTravelNormalizeAndExit(t *testing.T) {
	got := travelNormalizeCountries([]string{"gb", "US", "XX", "us"})
	if strings.Join(got, ",") != "US,GB" {
		t.Fatalf("got %v", got)
	}
	if !travelExitIn(got, "us") || travelExitIn(got, "NL") || travelExitIn(got, "") {
		t.Fatal("exit check wrong")
	}
}

func TestTravelConfigUAPI(t *testing.T) {
	raw := `{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","peer_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
"endpoint":"162.159.192.1:2408","hop":true,"inner_private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
"inner_peer_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","travel_countries":["US"],"address_v6":"2606:4700::1/128"}`
	cfg, err := parseConfigJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	outer, _ := cfg.uapi()
	if !strings.Contains(outer, "allowed_ip=::/0") {
		t.Fatal("travel outer must allow IPv6")
	}
	inner, _ := cfg.innerUAPI("[2602:fc59:b0:64::a29f:c001]:2408")
	if !strings.Contains(inner, "persistent_keepalive_interval=15") || strings.Contains(inner, "::/0") {
		t.Fatalf("inner uapi: %s", inner)
	}
	cfg.TravelCountries = nil
	plain, _ := cfg.uapi()
	if strings.Contains(plain, "::/0") || !strings.Contains(plain, "persistent_keepalive_interval=25") {
		t.Fatal("without Travel Mode the outer must stay as before")
	}
}

func TestTravelParsePrefixes(t *testing.T) {
	msg := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	q := travelDNSQuery()[12:]
	msg = append(msg, q...)
	msg = append(msg, 0xC0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	addr := netip.MustParseAddr("2a00:1098:2b::1:c000:aa").As16()
	msg = append(msg, addr[:]...)
	got, err := travelParsePrefixes(msg)
	if err != nil || len(got) != 1 || netip.MustParseAddr(got[0]) != netip.MustParseAddr("2a00:1098:2b::1:0:0") {
		t.Fatalf("got %v %v", got, err)
	}
}
