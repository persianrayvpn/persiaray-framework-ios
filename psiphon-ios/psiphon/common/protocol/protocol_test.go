/*
 * Copyright (c) 2018, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package protocol

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func TestTunnelProtocolValidation(t *testing.T) {

	validSupportedProtocols := make(TunnelProtocols, 0)
	for _, p := range SupportedTunnelProtocols {
		if common.Contains(DisabledTunnelProtocols, p) {
			continue
		}
		validSupportedProtocols = append(validSupportedProtocols, p)
	}

	if len(validSupportedProtocols) == len(SupportedTunnelProtocols) {

		err := SupportedTunnelProtocols.Validate()
		if err != nil {
			t.Errorf("unexpected Validate error: %s", err)
		}

	} else {

		err := SupportedTunnelProtocols.Validate()
		if err == nil {
			t.Errorf("unexpected Validate success")
		}

		err = validSupportedProtocols.Validate()
		if err != nil {
			t.Errorf("unexpected Validate error: %s", err)
		}

	}

	invalidProtocols := TunnelProtocols{"OSSH", "INVALID-PROTOCOL"}
	err := invalidProtocols.Validate()
	if err == nil {
		t.Errorf("unexpected Validate success")
	}

	pruneProtocols := make(TunnelProtocols, 0)
	for i, p := range SupportedTunnelProtocols {
		pruneProtocols = append(pruneProtocols, fmt.Sprintf("INVALID-PROTOCOL-%d", i))
		pruneProtocols = append(pruneProtocols, p)
	}
	pruneProtocols = append(pruneProtocols, fmt.Sprintf("INVALID-PROTOCOL-%d", len(SupportedTunnelProtocols)))

	prunedProtocols := pruneProtocols.PruneInvalid()

	if !reflect.DeepEqual(prunedProtocols, validSupportedProtocols) {
		t.Errorf("unexpected %+v != %+v", prunedProtocols, validSupportedProtocols)
	}
}

func TestEdgeFrontingProtocolVariants(t *testing.T) {

	testCases := []struct {
		name               string
		cdnProtocol        string
		baseProtocol       string
		expectedCapability string
		usesHTTP           bool
		usesQUIC           bool
		defaultDisabled    bool
		inproxyCompatible  bool
		supportsUpstream   bool
		mayUseClientBPF    bool
	}{
		{
			name:               "HTTPS",
			cdnProtocol:        TUNNEL_PROTOCOL_FRONTED_MEEK_EDGE,
			baseProtocol:       TUNNEL_PROTOCOL_FRONTED_MEEK,
			expectedCapability: "FRONTED-MEEK",
			supportsUpstream:   true,
			mayUseClientBPF:    true,
		},
		{
			name:               "HTTP",
			cdnProtocol:        TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP_EDGE,
			baseProtocol:       TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
			expectedCapability: "FRONTED-MEEK-HTTP",
			usesHTTP:           true,
			supportsUpstream:   true,
			mayUseClientBPF:    true,
		},
		{
			name:               "QUIC",
			cdnProtocol:        TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_EDGE_OSSH,
			baseProtocol:       TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH,
			expectedCapability: "FRONTED-MEEK-QUIC",
			usesQUIC:           true,
			defaultDisabled:    true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if !common.Contains(SupportedTunnelProtocols, testCase.cdnProtocol) {
				t.Fatalf("missing supported protocol: %s", testCase.cdnProtocol)
			}
			if TunnelProtocolBase(testCase.cdnProtocol) != testCase.baseProtocol {
				t.Fatalf("unexpected base protocol")
			}
			if GetCapability(testCase.cdnProtocol) != testCase.expectedCapability {
				t.Fatalf("unexpected capability")
			}
			if !TunnelProtocolUsesFrontedMeek(testCase.cdnProtocol) {
				t.Fatalf("expected fronted meek")
			}
			if !TunnelProtocolUsesFrontedMeekEdge(testCase.cdnProtocol) {
				t.Fatalf("expected fronted meek CDN")
			}
			if TunnelProtocolUsesMeekHTTP(testCase.cdnProtocol) != testCase.usesHTTP {
				t.Fatalf("unexpected HTTP classification")
			}
			if TunnelProtocolUsesQUIC(testCase.cdnProtocol) != testCase.usesQUIC {
				t.Fatalf("unexpected QUIC classification")
			}
			if common.Contains(DefaultDisabledTunnelProtocols, testCase.cdnProtocol) != testCase.defaultDisabled {
				t.Fatalf("unexpected default-disabled classification")
			}
			if TunnelProtocolIsCompatibleWithInproxy(testCase.cdnProtocol) != testCase.inproxyCompatible {
				t.Fatalf("unexpected in-proxy compatibility")
			}
			if TunnelProtocolSupportsUpstreamProxy(testCase.cdnProtocol) != testCase.supportsUpstream {
				t.Fatalf("unexpected upstream proxy support")
			}
			if TunnelProtocolMayUseClientBPF(testCase.cdnProtocol) != testCase.mayUseClientBPF {
				t.Fatalf("unexpected client BPF support")
			}
			if TunnelProtocolSupportsTactics(testCase.cdnProtocol) {
				t.Fatalf("CDN variants should not support tactics")
			}
		})
	}
}

func TestTLSProfileValidation(t *testing.T) {

	// Test: valid profiles

	err := SupportedTLSProfiles.Validate(nil)
	if err != nil {
		t.Errorf("unexpected Validate error: %s", err)
	}

	// Test: invalid profile

	profiles := TLSProfiles{TLS_PROFILE_RANDOMIZED, "INVALID-TLS-PROFILE"}
	err = profiles.Validate(nil)
	if err == nil {
		t.Errorf("unexpected Validate success")
	}

	// Test: valid custom profile

	customProfiles := []string{"CUSTOM-TLS-PROFILE"}

	profiles = TLSProfiles{TLS_PROFILE_RANDOMIZED, "CUSTOM-TLS-PROFILE"}
	err = profiles.Validate(customProfiles)
	if err != nil {
		t.Errorf("unexpected Validate error: %s", err)
	}

	// Test: prune invalid profiles

	pruneProfiles := make(TLSProfiles, 0)
	for i, p := range SupportedTLSProfiles {
		pruneProfiles = append(pruneProfiles, fmt.Sprintf("INVALID-PROFILE-%d", i))
		pruneProfiles = append(pruneProfiles, p)
	}
	pruneProfiles = append(pruneProfiles, fmt.Sprintf("INVALID-PROFILE-%d", len(SupportedTLSProfiles)))

	prunedProfiles := pruneProfiles.PruneInvalid(nil)

	if !reflect.DeepEqual(prunedProfiles, SupportedTLSProfiles) {
		t.Errorf("unexpected %+v != %+v", prunedProfiles, SupportedTLSProfiles)
	}

	// Test: don't prune valid custom profiles

	pruneProfiles = TLSProfiles{TLS_PROFILE_RANDOMIZED, "CUSTOM-TLS-PROFILE"}

	prunedProfiles = pruneProfiles.PruneInvalid(customProfiles)

	if !reflect.DeepEqual(prunedProfiles, pruneProfiles) {
		t.Errorf("unexpected %+v != %+v", prunedProfiles, pruneProfiles)
	}
}
