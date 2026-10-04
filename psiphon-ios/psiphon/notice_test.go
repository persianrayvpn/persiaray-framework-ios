package psiphon

import (
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestRouteBypassIPAddressForNoticeUsesDirectDialAddress(t *testing.T) {
	dialParams := &DialParameters{
		ServerEntry:       &protocol.ServerEntry{IpAddress: "198.51.100.20"},
		DirectDialAddress: "203.0.113.10:443",
	}
	dialParams.MeekResolvedIPAddress.Store("")

	if got := routeBypassIPAddressForNotice(dialParams); got != "203.0.113.10" {
		t.Fatalf("routeBypassIPAddressForNotice = %q, want direct dial IP", got)
	}
}

func TestRouteBypassIPAddressForNoticePrefersMeekResolvedIPAddress(t *testing.T) {
	dialParams := &DialParameters{
		ServerEntry:       &protocol.ServerEntry{IpAddress: "198.51.100.20"},
		DirectDialAddress: "203.0.113.10:443",
	}
	dialParams.MeekResolvedIPAddress.Store("192.0.2.44")

	if got := routeBypassIPAddressForNotice(dialParams); got != "192.0.2.44" {
		t.Fatalf("routeBypassIPAddressForNotice = %q, want meek resolved IP", got)
	}
}
