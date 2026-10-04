package psiphon

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const persianRaySafeSearchVIP = "216.239.38.120"

type persianRayAction int

const (
	prTunnel persianRayAction = iota
	prDirect
	prBlockAds
	prBlock
	prSafeSearch
)

// Matches Android AdBlockStats.add: lock-free increment on the dial path.
// A 1s ticker emits one notice with the batch so the UI is not on the hot path.
var (
	persianRayAdBlockPending atomic.Int64
	persianRayAdBlockTick    sync.Once
)

func notePersianRayAdBlock() {
	persianRayAdBlockTick.Do(func() {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for range t.C {
				n := persianRayAdBlockPending.Swap(0)
				if n > 0 {
					NoticeInfo("persianray-block-ads %d", n)
				}
			}
		}()
	})
	persianRayAdBlockPending.Add(1)
}

func (config *Config) policyEnabled() bool {
	if config == nil {
		return false
	}
	return config.PersianRayBlockAds ||
		config.PersianRayBlockAdult ||
		config.PersianRaySafeSearch ||
		config.PersianRayBypassLocal
}

func (config *Config) persianRayAction(target string) persianRayAction {
	if config == nil || !config.policyEnabled() {
		return prTunnel
	}
	host, port, ok := splitHostPort(target)
	if !ok {
		return prTunnel
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if config.PersianRayBlockAds && matchHost(h, config.adExact(), config.adSuffix()) {
		return prBlockAds
	}
	if config.PersianRayBlockAdult && matchHost(h, config.adultExact(), config.adultSuffix()) {
		return prBlock
	}
	if config.PersianRaySafeSearch {
		if port == "853" {
			return prBlock
		}
		if matchHost(h, config.dohExact(), config.dohSuffix()) {
			return prBlock
		}
		if matchHost(h, config.safeSearchExact(), nil) {
			return prSafeSearch
		}
	}
	if config.PersianRayBypassLocal && matchHost(h, nil, config.localSuffix()) {
		return prDirect
	}
	return prTunnel
}

func DialPersianRay(
	config *Config,
	tunneler Tunneler,
	target string,
	downstream net.Conn,
) (net.Conn, error) {
	switch config.persianRayAction(target) {
	case prBlockAds:
		notePersianRayAdBlock()
		return nil, errors.TraceNew("persianray: blocked")
	case prBlock:
		return nil, errors.TraceNew("persianray: blocked")
	case prDirect:
		return tunneler.DirectDial(target)
	case prSafeSearch:
		_, port, err := net.SplitHostPort(target)
		if err != nil || port == "" {
			port = "443"
		}
		return tunneler.Dial(net.JoinHostPort(persianRaySafeSearchVIP, port), downstream)
	default:
		return tunneler.Dial(target, downstream)
	}
}

func splitHostPort(target string) (string, string, bool) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		if strings.Contains(target, ":") {
			return "", "", false
		}
		return target, "0", true
	}
	if _, err := strconv.Atoi(port); err != nil {
		return host, port, true
	}
	return host, port, true
}

func (config *Config) clientHostLists() bool {
	if config == nil {
		return false
	}
	return len(config.PersianRayAdExact)+len(config.PersianRayAdSuffix)+
		len(config.PersianRayAdultExact)+len(config.PersianRayAdultSuffix)+
		len(config.PersianRayLocalSuffix)+
		len(config.PersianRaySafeSearchExact)+
		len(config.PersianRayDoHExact)+len(config.PersianRayDoHSuffix) > 0
}

func pickHosts(client []string, fallback []string, useClient bool) []string {
	if useClient {
		return client
	}
	return fallback
}

func (config *Config) adExact() []string {
	return pickHosts(config.PersianRayAdExact, persianRayAdExact, config.clientHostLists())
}
func (config *Config) adSuffix() []string {
	return pickHosts(config.PersianRayAdSuffix, persianRayAdSuffix, config.clientHostLists())
}
func (config *Config) adultExact() []string {
	return pickHosts(config.PersianRayAdultExact, persianRayAdultExact, config.clientHostLists())
}
func (config *Config) adultSuffix() []string {
	return pickHosts(config.PersianRayAdultSuffix, persianRayAdultSuffix, config.clientHostLists())
}
func (config *Config) localSuffix() []string {
	return pickHosts(config.PersianRayLocalSuffix, persianRayLocalSuffix, config.clientHostLists())
}
func (config *Config) safeSearchExact() []string {
	return pickHosts(config.PersianRaySafeSearchExact, persianRaySafeSearchExact, config.clientHostLists())
}
func (config *Config) dohExact() []string {
	return pickHosts(config.PersianRayDoHExact, persianRayDoHExact, config.clientHostLists())
}
func (config *Config) dohSuffix() []string {
	return pickHosts(config.PersianRayDoHSuffix, persianRayDoHSuffix, config.clientHostLists())
}

func matchHost(host string, exact []string, suffix []string) bool {
	for _, e := range exact {
		if host == e {
			return true
		}
	}
	for _, s := range suffix {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}
