package psiphon

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestEdgeFrontingScanBuiltInCandidateSetsValidate(t *testing.T) {

	names := make(map[string]struct{})
	for _, candidateSet := range edgeFrontingScanBuiltInCandidateSets {
		if candidateSet.name == "" {
			t.Fatal("empty built-in candidate set name")
		}
		if _, ok := names[candidateSet.name]; ok {
			t.Fatalf("duplicate built-in candidate set name: %s", candidateSet.name)
		}
		names[candidateSet.name] = struct{}{}

		if err := candidateSet.spec.Validate(); err != nil {
			t.Fatalf("invalid built-in candidate set %s: %v", candidateSet.name, err)
		}
		if candidateSet.spec.CandidateCount() == 0 {
			t.Fatalf("empty built-in candidate set: %s", candidateSet.name)
		}
		testEdgeFrontingScanBuiltInIPCandidatesNotCovered(
			t,
			candidateSet.name,
			candidateSet.spec.IPCandidates)
	}
}

func TestEdgeFrontingScanBuiltInIncludesCuratedAdditions(t *testing.T) {

	expectedPriorityOrder := []string{
		"built-in-legacy-android-overrides",
		"built-in-curated-fronting",
		"built-in-psiphon-akamai",
		"built-in-fastly",
		"built-in-psiphon-bunny",
	}
	for i, expectedName := range expectedPriorityOrder {
		if edgeFrontingScanBuiltInCandidateSets[i].name != expectedName {
			t.Fatalf(
				"unexpected built-in priority at %d: %s",
				i,
				edgeFrontingScanBuiltInCandidateSets[i].name)
		}
	}

	if !testEdgeFrontingScanStringSliceContains(
		edgeFrontingScanBuiltInLegacyAndroidOverrideIPCandidates,
		"92.123.102.43") {
		t.Fatal("missing legacy Android CDN edge IP candidate")
	}
	if !testEdgeFrontingScanStringSliceContains(
		edgeFrontingScanBuiltInLegacyAndroidOverrideSNIServerNames,
		"a248.e.akamai.net") {
		t.Fatal("missing legacy Android CDN edge SNI candidate")
	}

	if len(edgeFrontingScanBuiltInCuratedIPCandidates) != 95 {
		t.Fatalf(
			"unexpected curated IP candidate count: %d",
			len(edgeFrontingScanBuiltInCuratedIPCandidates))
	}
	if len(edgeFrontingScanBuiltInCuratedSNIServerNames) != 15 {
		t.Fatalf(
			"unexpected curated SNI candidate count: %d",
			len(edgeFrontingScanBuiltInCuratedSNIServerNames))
	}

	for _, ipAddress := range []string{
		"2.16.221.37",
		"151.101.128.223",
		"185.200.232.50",
	} {
		if !testEdgeFrontingScanStringSliceContains(
			edgeFrontingScanBuiltInCuratedIPCandidates,
			ipAddress) {
			t.Fatalf("missing curated IP candidate: %s", ipAddress)
		}
	}

	for _, sniServerName := range []string{
		"bbe-getimage.akamaized.net",
		"prod.global.ssl.fastly.net",
		"b-cdn.net",
	} {
		if !testEdgeFrontingScanStringSliceContains(
			edgeFrontingScanBuiltInCuratedSNIServerNames,
			sniServerName) {
			t.Fatalf("missing curated SNI candidate: %s", sniServerName)
		}
	}

	for _, testCase := range []struct {
		name   string
		values []string
		value  string
	}{
		{
			name:   "akamai",
			values: edgeFrontingScanBuiltInAkamaiSNIServerNames,
			value:  "bbe-getimage.akamaized.net",
		},
		{
			name:   "fastly",
			values: edgeFrontingScanBuiltInFastlySNIServerNames,
			value:  "prod.global.ssl.fastly.net",
		},
		{
			name:   "fastly",
			values: edgeFrontingScanBuiltInFastlySNIServerNames,
			value:  "quic.map.fastly.net",
		},
		{
			name:   "google",
			values: edgeFrontingScanBuiltInGoogleSNIServerNames,
			value:  "google.com",
		},
	} {
		if !testEdgeFrontingScanStringSliceContains(
			testCase.values,
			testCase.value) {
			t.Fatalf(
				"missing %s SNI candidate: %s",
				testCase.name,
				testCase.value)
		}
	}

	for _, excludedIPAddress := range []string{
		"5.160.13.85",
		"37.191.95.70",
		"78.39.234.140",
		"80.191.243.226",
		"185.208.174.167",
	} {
		if testEdgeFrontingScanStringSliceContains(
			edgeFrontingScanBuiltInCuratedIPCandidates,
			excludedIPAddress) {
			t.Fatalf("unexpected curated IP candidate: %s", excludedIPAddress)
		}
	}
}

func TestEdgeFrontingScanSelectionPriority(t *testing.T) {

	originalBuiltInCandidateSets := edgeFrontingScanBuiltInCandidateSets
	defer func() {
		edgeFrontingScanBuiltInCandidateSets = originalBuiltInCandidateSets
	}()

	edgeFrontingScanBuiltInCandidateSets = []edgeFrontingScanCandidateSet{
		{
			name: "test-built-in",
			spec: parameters.EdgeFrontingScanSpec{
				IPCandidates:   []string{"198.51.100.1"},
				SNIServerNames: []string{"built-in.example.com"},
			},
		},
	}

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("parameters.NewParameters failed: %v", err)
	}

	_, err = params.Set("", 0, map[string]interface{}{
		parameters.EdgeFrontingScanSpecParameter: parameters.EdgeFrontingScanSpec{
			IPCandidates:   []string{"192.0.2.1"},
			SNIServerNames: []string{"user.example.com"},
		},
		parameters.EdgeFrontingScanUseBuiltInSpec: true,
		parameters.EdgeFrontingDialOverrides: parameters.EdgeFrontingDialOverrideSpecs{
			&parameters.EdgeFrontingDialOverride{
				OverrideID:                     "test-override",
				MatchFrontingProviderIDRegexes: []string{"test-provider"},
				DialAddresses:                  []string{"203.0.113.1"},
				SNIServerName:                  "override.example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("params.Set failed: %v", err)
	}

	override, scanCandidate, _, ok, err := selectEdgeFrontingScanOverride(
		params.Get(),
		"test-network",
		"test-provider",
		"front.example.com",
		"host.example.com",
		0)
	if err != nil || !ok {
		t.Fatalf("select user candidate failed: ok=%t err=%v", ok, err)
	}
	if override.DialAddress != "192.0.2.1" ||
		scanCandidate == nil ||
		scanCandidate.IPAddress != "192.0.2.1" {
		t.Fatalf("unexpected first candidate: override=%+v scan=%+v", override, scanCandidate)
	}

	override, scanCandidate, _, ok, err = selectEdgeFrontingScanOverride(
		params.Get(),
		"test-network",
		"test-provider",
		"front.example.com",
		"host.example.com",
		2)
	if err != nil || !ok {
		t.Fatalf("select override candidate failed: ok=%t err=%v", ok, err)
	}
	if override.DialAddress != "203.0.113.1" || scanCandidate != nil {
		t.Fatalf("unexpected override candidate: override=%+v scan=%+v", override, scanCandidate)
	}

	override, scanCandidate, _, ok, err = selectEdgeFrontingScanOverride(
		params.Get(),
		"test-network",
		"test-provider",
		"front.example.com",
		"host.example.com",
		3)
	if err != nil || !ok {
		t.Fatalf("select built-in candidate failed: ok=%t err=%v", ok, err)
	}
	if override.DialAddress != "198.51.100.1" ||
		scanCandidate == nil ||
		scanCandidate.IPAddress != "198.51.100.1" {
		t.Fatalf("unexpected built-in candidate: override=%+v scan=%+v", override, scanCandidate)
	}
}

func TestEdgeFrontingScanPreservesOverrideWrapping(t *testing.T) {

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("parameters.NewParameters failed: %v", err)
	}

	_, err = params.Set("", 0, map[string]interface{}{
		parameters.EdgeFrontingDialOverrides: parameters.EdgeFrontingDialOverrideSpecs{
			&parameters.EdgeFrontingDialOverride{
				OverrideID:                     "test-override",
				MatchFrontingProviderIDRegexes: []string{"test-provider"},
				DialAddresses:                  []string{"203.0.113.1"},
				SNIServerName:                  "override.example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("params.Set failed: %v", err)
	}

	override, scanCandidate, _, ok, err := selectEdgeFrontingScanOverride(
		params.Get(),
		"test-network",
		"test-provider",
		"front.example.com",
		"host.example.com",
		3)
	if err != nil || !ok {
		t.Fatalf("select wrapped override candidate failed: ok=%t err=%v", ok, err)
	}
	if override.DialAddress != "203.0.113.1" || scanCandidate != nil {
		t.Fatalf("unexpected wrapped override candidate: override=%+v scan=%+v", override, scanCandidate)
	}
}

func TestEdgeFrontingScanRecordResultDoesNotEmitFoundNotice(t *testing.T) {

	foundNoticeCount := 0
	err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		noticeType, payload, err := GetNotice(notice)
		if err != nil {
			t.Errorf("GetNotice failed: %v", err)
			return
		}
		message, _ := payload["message"].(string)
		if noticeType == "Info" && strings.HasPrefix(message, "edge fronting scan found") {
			foundNoticeCount += 1
		}
	}))
	if err != nil {
		t.Fatalf("SetNoticeWriter failed: %v", err)
	}
	defer ResetNoticeWriter()

	state := &edgeFrontingScanState{
		datastoreKey: "test-fronted-meek-cdn-scan-found-notice",
		entries:      make(map[string]*edgeFrontingScanCacheEntry),
	}

	state.recordResult(parameters.EdgeFrontingScanCandidate{
		IPAddress:     "192.0.2.1",
		SNIServerName: "one.example.com",
	}, true)
	state.recordResult(parameters.EdgeFrontingScanCandidate{
		IPAddress:     "192.0.2.1",
		SNIServerName: "one.example.com",
	}, true)
	state.recordResult(parameters.EdgeFrontingScanCandidate{
		IPAddress:     "192.0.2.2",
		SNIServerName: "two.example.com",
	}, true)

	if foundNoticeCount != 0 {
		t.Fatalf("found notice count = %d, want 0", foundNoticeCount)
	}
}

func TestEdgeFrontingScanFoundNoticeFromDialParams(t *testing.T) {

	foundNoticeMessage := ""
	err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		noticeType, payload, err := GetNotice(notice)
		if err != nil {
			t.Errorf("GetNotice failed: %v", err)
			return
		}
		message, _ := payload["message"].(string)
		if noticeType == "Info" && strings.HasPrefix(message, "edge fronting scan found") {
			foundNoticeMessage = message
		}
	}))
	if err != nil {
		t.Fatalf("SetNoticeWriter failed: %v", err)
	}
	defer ResetNoticeWriter()

	dialParams := &DialParameters{
		EdgeFrontingScanCandidate: true,
		MeekFrontingDialOverrideID:  edgeFrontingScanOverrideID,
		MeekFrontingDialAddress:     "192.0.2.4",
		MeekSNIServerName:           "",
		edgeFrontingScanSelectedCandidate: parameters.EdgeFrontingScanCandidate{
			IPAddress:     "192.0.2.1",
			SNIServerName: "selected.example.com",
		},
	}
	if !isEdgeFrontingScanDialParams(dialParams) {
		t.Fatalf("expected scan dial params to be detected as edge scan dial params")
	}

	noticeEdgeFrontingScanConnected(dialParams)

	expectedMessage := "edge fronting scan found (ip: 192\\.0\\.2\\.4, sni: none)"
	if foundNoticeMessage != expectedMessage {
		t.Fatalf("found notice message = %q, want %q", foundNoticeMessage, expectedMessage)
	}
}

func TestEdgeFrontingScanFoundNoticeFromReplayDialParams(t *testing.T) {

	foundNoticeMessage := ""
	err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		noticeType, payload, err := GetNotice(notice)
		if err != nil {
			t.Errorf("GetNotice failed: %v", err)
			return
		}
		message, _ := payload["message"].(string)
		if noticeType == "Info" && strings.HasPrefix(message, "edge fronting scan found") {
			foundNoticeMessage = message
		}
	}))
	if err != nil {
		t.Fatalf("SetNoticeWriter failed: %v", err)
	}
	defer ResetNoticeWriter()

	dialParams := &DialParameters{
		MeekFrontingDialOverrideID: edgeFrontingScanOverrideID,
		MeekFrontingDialAddress:    "192.0.2.3",
		MeekSNIServerName:          "cached.example.com",
	}
	if !isEdgeFrontingScanDialParams(dialParams) {
		t.Fatalf("expected replay dial params to be detected as edge scan dial params")
	}

	noticeEdgeFrontingScanConnected(dialParams)

	expectedMessage := "edge fronting scan found (ip: 192\\.0\\.2\\.3, sni: cached.example.com)"
	if foundNoticeMessage != expectedMessage {
		t.Fatalf("found notice message = %q, want %q", foundNoticeMessage, expectedMessage)
	}
}

func TestEdgeFrontingScanFoundNoticeFromConnectedCDNProtocol(t *testing.T) {

	foundNoticeMessage := ""
	err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		noticeType, payload, err := GetNotice(notice)
		if err != nil {
			t.Errorf("GetNotice failed: %v", err)
			return
		}
		message, _ := payload["message"].(string)
		if noticeType == "Info" && strings.HasPrefix(message, "edge fronting scan found") {
			foundNoticeMessage = message
		}
	}))
	if err != nil {
		t.Fatalf("SetNoticeWriter failed: %v", err)
	}
	defer ResetNoticeWriter()

	dialParams := &DialParameters{
		TunnelProtocol:          protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP_EDGE,
		MeekFrontingDialAddress: "203.0.113.9",
		MeekSNIServerName:       "",
	}
	if isEdgeFrontingScanDialParams(dialParams) {
		t.Fatalf("did not expect connected CDN protocol dial params to be scan-marked")
	}

	noticeEdgeFrontingScanConnected(dialParams)

	expectedMessage := "edge fronting scan found (ip: 203\\.0\\.113\\.9, sni: none)"
	if foundNoticeMessage != expectedMessage {
		t.Fatalf("found notice message = %q, want %q", foundNoticeMessage, expectedMessage)
	}
}

func testEdgeFrontingScanStringSliceContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func testEdgeFrontingScanBuiltInIPCandidatesNotCovered(
	t *testing.T,
	name string,
	candidates []string) {

	t.Helper()

	prefixes := make([]netip.Prefix, 0, len(candidates))
	for _, candidate := range candidates {
		prefix, err := netip.ParsePrefix(candidate)
		if err != nil {
			addr, addrErr := netip.ParseAddr(candidate)
			if addrErr != nil {
				t.Fatalf("invalid built-in IP candidate %s in %s", candidate, name)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	for i, prefix := range prefixes {
		for j, otherPrefix := range prefixes {
			if i == j {
				continue
			}
			if testEdgeFrontingScanPrefixContains(prefix, otherPrefix) {
				t.Fatalf(
					"built-in IP candidate %s in %s is covered by %s",
					candidates[j],
					name,
					candidates[i])
			}
		}
	}
}

func testEdgeFrontingScanPrefixContains(prefix, otherPrefix netip.Prefix) bool {
	return prefix.Contains(otherPrefix.Addr()) &&
		prefix.Contains(testEdgeFrontingScanPrefixLastAddr(otherPrefix))
}

func testEdgeFrontingScanPrefixLastAddr(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	addrBytes := addr.As4()
	value := binary.BigEndian.Uint32(addrBytes[:])
	value += uint32((uint64(1) << (32 - uint(prefix.Bits()))) - 1)
	var lastBytes [4]byte
	binary.BigEndian.PutUint32(lastBytes[:], value)
	return netip.AddrFrom4(lastBytes)
}
