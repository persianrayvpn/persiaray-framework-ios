package main

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
)

// Policy is evaluated only when socksConfig.ApplyPolicy is true (Connect).
// Host lists come from the JSON the iOS app builds from PolicyDomains.

type policyAction int

const (
	actTunnel policyAction = iota
	actDirect
	actBlockAds
	actBlock
	actSafeSearch
)

var adBlockPending atomic.Int64

func (c *socksConfig) policyOn() bool {
	if c == nil || !c.ApplyPolicy {
		return false
	}
	return c.BlockAds || c.BlockAdult || c.SafeSearch || c.BypassLocal || c.BlockQuic
}

func (c *socksConfig) action(host string, port int) policyAction {
	if !c.policyOn() {
		return actTunnel
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if c.BlockAds && matchHost(h, c.AdExact, c.AdSuffix) {
		return actBlockAds
	}
	if c.BlockAdult && matchHost(h, c.AdultExact, c.AdultSuffix) {
		return actBlock
	}
	if c.SafeSearch {
		if port == 853 {
			return actBlock
		}
		if matchHost(h, c.DoHExact, c.DoHSuffix) {
			return actBlock
		}
		if matchHost(h, c.SafeSearchExact, nil) {
			return actSafeSearch
		}
	}
	if c.BypassLocal && matchHost(h, nil, c.LocalSuffix) {
		return actDirect
	}
	return actTunnel
}

func (c *socksConfig) dropQUIC(port int) bool {
	if c == nil || !c.ApplyPolicy {
		return false
	}
	return (c.BlockQuic || c.SafeSearch) && port == 443
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

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
