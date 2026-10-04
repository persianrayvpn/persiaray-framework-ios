package psiphon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

const (
	edgeFrontingScanCacheKeyPrefix     = "edgeFrontingScanCache"
	edgeFrontingScanOverrideID         = "cdn-scan"
	edgeFrontingScanSuccessTTL         = 7 * 24 * time.Hour
	edgeFrontingScanFailureCooldown    = 2 * time.Hour
	edgeFrontingScanProgressInterval   = 50
	edgeFrontingScanAggressiveFanout   = 8
	edgeFrontingScanConservativeFanout = 1
	edgeFrontingScanMaxCandidateCount  = int(1<<31 - 1)
)

type edgeFrontingScanCandidateSet struct {
	name string
	spec parameters.EdgeFrontingScanSpec
}

type edgeFrontingScanCacheEntry struct {
	IPAddress            string
	SNIServerName        string
	LastSuccessTimestamp time.Time `json:",omitempty"`
	LastFailureTimestamp time.Time `json:",omitempty"`
	SuccessCount         int       `json:",omitempty"`
	FailureCount         int       `json:",omitempty"`
}

type edgeFrontingScanCacheRecord struct {
	Entries     map[string]*edgeFrontingScanCacheEntry
	ShuffleSeed string `json:",omitempty"`
}

type edgeFrontingScanState struct {
	mutex               sync.Mutex
	datastoreKey        string
	loaded              bool
	entries             map[string]*edgeFrontingScanCacheEntry
	shuffleSeed         string
	attempts            int
	lastProgressAttempt int
	exhaustedLogged     bool
}

var edgeFrontingScanStates sync.Map

func noticeEdgeFrontingScanActive(
	p parameters.ParametersAccessor,
	networkID string,
	workerPoolSize int,
	aggressive bool) {

	candidateSets := makeEdgeFrontingScanCandidateSets(p)
	if edgeFrontingScanCandidateSetCount(candidateSets) == 0 {
		return
	}
	getEdgeFrontingScanState(networkID, candidateSets).resetEstablishment()

	mode := "normal"
	if aggressive {
		mode = "beast"
	}

	NoticeInfo(
		"edge fronting scan active (mode: %s, workers: %d)",
		mode,
		workerPoolSize)
}

func edgeFrontingScanCandidateFanout(
	p parameters.ParametersAccessor,
	aggressive bool) int {

	candidateCount := edgeFrontingScanCandidateSetCount(
		makeEdgeFrontingScanCandidateSets(p))
	if candidateCount == 0 {
		return 1
	}
	if !aggressive {
		return edgeFrontingScanConservativeFanout
	}
	if candidateCount < edgeFrontingScanAggressiveFanout {
		return candidateCount
	}
	return edgeFrontingScanAggressiveFanout
}

func selectEdgeFrontingScanOverride(
	p parameters.ParametersAccessor,
	networkID string,
	frontingProviderID string,
	dialAddress string,
	hostHeader string,
	candidateNumber int) (
	*parameters.EdgeFrontingDialOverrideParameters,
	*parameters.EdgeFrontingScanCandidate,
	string,
	bool,
	error) {

	userCandidateSets := makeEdgeFrontingScanUserCandidateSets(p)
	builtInCandidateSets := makeEdgeFrontingScanBuiltInCandidateSets(p)
	candidateSets := append(
		append([]edgeFrontingScanCandidateSet{}, userCandidateSets...),
		builtInCandidateSets...)

	scanCandidateCount := edgeFrontingScanCandidateSetCount(candidateSets)
	userCandidateCount := edgeFrontingScanCandidateSetCount(userCandidateSets)
	builtInCandidateCount := edgeFrontingScanCandidateSetCount(builtInCandidateSets)

	overrides := p.EdgeFrontingDialOverrides(parameters.EdgeFrontingDialOverrides)
	overrideCandidateCount, err := overrides.CandidateCount(
		frontingProviderID,
		dialAddress,
		hostHeader)
	if err != nil {
		return nil, nil, "", false, errors.Trace(err)
	}

	candidateCount := edgeFrontingScanSaturatedAdd(
		scanCandidateCount,
		overrideCandidateCount)
	if candidateCount == 0 {
		return nil, nil, "", false, nil
	}
	if scanCandidateCount == 0 {
		override, ok, err := overrides.SelectCandidateParameters(
			frontingProviderID,
			dialAddress,
			hostHeader,
			candidateNumber)
		return override, nil, "", ok, errors.Trace(err)
	}

	state := getEdgeFrontingScanState(networkID, candidateSets)
	preferredCandidates, skippedCandidates, shuffleKey := state.candidateHints()
	if candidateNumber >= len(preferredCandidates)+candidateCount {
		state.recordExhausted()
		return nil, nil, "", false, nil
	}

	var candidate *parameters.EdgeFrontingScanCandidate
	if candidateNumber < len(preferredCandidates) {
		selected := preferredCandidates[candidateNumber]
		candidate = &selected
	} else {
		sourceCandidateNumber := candidateNumber - len(preferredCandidates)
		if sourceCandidateNumber < userCandidateCount {
			var ok bool
			candidate, ok, err = selectEdgeFrontingScanCandidate(
				userCandidateSets,
				sourceCandidateNumber,
				skippedCandidates,
				shuffleKey)
			if err != nil {
				return nil, nil, "", false, errors.Trace(err)
			}
			if !ok {
				return nil, nil, "", false, nil
			}
		} else {
			sourceCandidateNumber -= userCandidateCount
			if sourceCandidateNumber < overrideCandidateCount {
				override, ok, err := overrides.SelectCandidateParametersNoWrap(
					frontingProviderID,
					dialAddress,
					hostHeader,
					sourceCandidateNumber)
				if err != nil {
					return nil, nil, "", false, errors.Trace(err)
				}
				return override, nil, "", ok, nil
			}

			sourceCandidateNumber -= overrideCandidateCount
			if sourceCandidateNumber >= builtInCandidateCount {
				return nil, nil, "", false, nil
			}

			var ok bool
			candidate, ok, err = selectEdgeFrontingScanCandidate(
				builtInCandidateSets,
				sourceCandidateNumber,
				skippedCandidates,
				shuffleKey)
			if err != nil {
				return nil, nil, "", false, errors.Trace(err)
			}
			if !ok {
				return nil, nil, "", false, nil
			}
		}
	}

	state.recordAttempt()

	return &parameters.EdgeFrontingDialOverrideParameters{
			OverrideID:        edgeFrontingScanOverrideID,
			DialAddress:       candidate.IPAddress,
			SNIServerName:     candidate.SNIServerName,
			VerifyServerNames: makeEdgeFrontingScanVerifyServerNames(*candidate),
			ALPNProtocols:     []string{"http/1.1"},
			TLSProfile:        "Chrome-83",
		},
		candidate,
		state.datastoreKey,
		true,
		nil
}

func recordEdgeFrontingScanResult(dialParams *DialParameters, success bool) {
	if dialParams == nil ||
		!dialParams.EdgeFrontingScanCandidate ||
		dialParams.edgeFrontingScanStateKey == "" {
		return
	}

	value, ok := edgeFrontingScanStates.Load(dialParams.edgeFrontingScanStateKey)
	if !ok {
		return
	}
	state := value.(*edgeFrontingScanState)
	state.recordResult(dialParams.edgeFrontingScanSelectedCandidate, success)
}

func isEdgeFrontingScanDialParams(dialParams *DialParameters) bool {
	return dialParams != nil &&
		(dialParams.EdgeFrontingScanCandidate ||
			dialParams.MeekFrontingDialOverrideID == edgeFrontingScanOverrideID)
}

func edgeFrontingScanCandidateFromDialParams(
	dialParams *DialParameters) parameters.EdgeFrontingScanCandidate {

	if dialParams == nil {
		return parameters.EdgeFrontingScanCandidate{}
	}
	candidate := parameters.EdgeFrontingScanCandidate{
		IPAddress:     dialParams.MeekFrontingDialAddress,
		SNIServerName: dialParams.MeekSNIServerName,
	}
	if candidate.IPAddress == "" && dialParams.EdgeFrontingScanCandidate {
		return dialParams.edgeFrontingScanSelectedCandidate
	}
	return candidate
}

func noticeEdgeFrontingScanConnected(dialParams *DialParameters) {

	if dialParams == nil ||
		(!isEdgeFrontingScanDialParams(dialParams) &&
			!protocol.TunnelProtocolUsesFrontedMeekEdge(dialParams.TunnelProtocol)) {
		return
	}
	noticeEdgeFrontingScanFound(
		edgeFrontingScanCandidateFromDialParams(dialParams))
}

func makeEdgeFrontingScanCandidateSets(
	p parameters.ParametersAccessor) []edgeFrontingScanCandidateSet {

	candidateSets := makeEdgeFrontingScanUserCandidateSets(p)
	candidateSets = append(candidateSets, makeEdgeFrontingScanBuiltInCandidateSets(p)...)

	return candidateSets
}

func makeEdgeFrontingScanUserCandidateSets(
	p parameters.ParametersAccessor) []edgeFrontingScanCandidateSet {

	candidateSets := make([]edgeFrontingScanCandidateSet, 0, 1)
	userSpec := p.EdgeFrontingScanSpec(parameters.EdgeFrontingScanSpecParameter)
	if userSpec.CandidateCount() > 0 {
		candidateSets = append(candidateSets, edgeFrontingScanCandidateSet{
			name: "user",
			spec: userSpec,
		})
	}

	return candidateSets
}

func makeEdgeFrontingScanBuiltInCandidateSets(
	p parameters.ParametersAccessor) []edgeFrontingScanCandidateSet {

	if !p.Bool(parameters.EdgeFrontingScanUseBuiltInSpec) {
		return nil
	}
	return edgeFrontingScanBuiltInCandidateSets
}

func edgeFrontingScanCandidateSetCount(
	candidateSets []edgeFrontingScanCandidateSet) int {

	total := 0
	for _, candidateSet := range candidateSets {
		count := candidateSet.spec.CandidateCount()
		if count <= 0 {
			continue
		}
		if total > edgeFrontingScanMaxCandidateCount-count {
			return edgeFrontingScanMaxCandidateCount
		}
		total += count
	}
	return total
}

func edgeFrontingScanSaturatedAdd(a, b int) int {
	if a > edgeFrontingScanMaxCandidateCount-b {
		return edgeFrontingScanMaxCandidateCount
	}
	return a + b
}

func edgeFrontingScanCandidateSetsCacheKey(
	candidateSets []edgeFrontingScanCandidateSet) string {

	hash := sha256.New()
	for _, candidateSet := range candidateSets {
		if candidateSet.spec.CandidateCount() == 0 {
			continue
		}
		hash.Write([]byte(candidateSet.name))
		hash.Write([]byte{0})
		hash.Write([]byte(candidateSet.spec.CacheKey()))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func selectEdgeFrontingScanCandidate(
	candidateSets []edgeFrontingScanCandidateSet,
	candidateNumber int,
	skippedCandidates map[string]struct{},
	shuffleKey string) (*parameters.EdgeFrontingScanCandidate, bool, error) {

	if candidateNumber < 0 {
		candidateNumber = 0
	}

	for _, candidateSet := range candidateSets {
		count := candidateSet.spec.CandidateCount()
		if count <= 0 {
			continue
		}
		if candidateNumber >= count {
			candidateNumber -= count
			continue
		}
		candidate, ok, err := candidateSet.spec.SelectCandidateWithShuffleKey(
			candidateNumber,
			skippedCandidates,
			shuffleKey)
		return candidate, ok, errors.Trace(err)
	}

	return nil, false, nil
}

func getEdgeFrontingScanState(
	networkID string,
	candidateSets []edgeFrontingScanCandidateSet) *edgeFrontingScanState {

	datastoreKey := strings.Join([]string{
		edgeFrontingScanCacheKeyPrefix,
		networkID,
		edgeFrontingScanCandidateSetsCacheKey(candidateSets),
	}, ":")

	value, _ := edgeFrontingScanStates.LoadOrStore(
		datastoreKey,
		&edgeFrontingScanState{
			datastoreKey: datastoreKey,
			entries:      make(map[string]*edgeFrontingScanCacheEntry),
		})
	state := value.(*edgeFrontingScanState)
	state.load()
	return state
}

func (state *edgeFrontingScanState) load() {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.loaded {
		return
	}
	state.loaded = true
	defer func() {
		if state.shuffleSeed == "" {
			state.shuffleSeed = prng.HexString(16)
		}
	}()

	jsonCache, err := GetKeyValue(state.datastoreKey)
	if err != nil || jsonCache == "" {
		return
	}

	var record edgeFrontingScanCacheRecord
	err = json.Unmarshal([]byte(jsonCache), &record)
	if err != nil || record.Entries == nil {
		return
	}

	state.entries = record.Entries
	state.shuffleSeed = record.ShuffleSeed
}

func (state *edgeFrontingScanState) resetEstablishment() {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.attempts = 0
	state.lastProgressAttempt = 0
	state.exhaustedLogged = false
}

func (state *edgeFrontingScanState) candidateHints() (
	[]parameters.EdgeFrontingScanCandidate,
	map[string]struct{},
	string) {

	now := time.Now()
	preferredCandidates := make([]*edgeFrontingScanCacheEntry, 0)
	skippedCandidates := make(map[string]struct{})

	state.mutex.Lock()
	defer state.mutex.Unlock()
	shuffleKey := state.shuffleSeed

	for key, entry := range state.entries {
		failureIsCurrent := !entry.LastFailureTimestamp.IsZero() &&
			entry.LastFailureTimestamp.After(entry.LastSuccessTimestamp)
		if failureIsCurrent &&
			now.Sub(entry.LastFailureTimestamp) < edgeFrontingScanFailureCooldown {
			skippedCandidates[key] = struct{}{}
			continue
		}
		if !entry.LastSuccessTimestamp.IsZero() &&
			now.Sub(entry.LastSuccessTimestamp) < edgeFrontingScanSuccessTTL &&
			!failureIsCurrent {
			preferredCandidates = append(preferredCandidates, entry)
		}
	}

	sort.Slice(preferredCandidates, func(i, j int) bool {
		if preferredCandidates[i].LastSuccessTimestamp.Equal(
			preferredCandidates[j].LastSuccessTimestamp) {
			return preferredCandidates[i].SuccessCount > preferredCandidates[j].SuccessCount
		}
		return preferredCandidates[i].LastSuccessTimestamp.After(
			preferredCandidates[j].LastSuccessTimestamp)
	})

	candidates := make([]parameters.EdgeFrontingScanCandidate, 0, len(preferredCandidates))
	for _, entry := range preferredCandidates {
		candidates = append(candidates, parameters.EdgeFrontingScanCandidate{
			IPAddress:     entry.IPAddress,
			SNIServerName: entry.SNIServerName,
		})
	}

	return candidates, skippedCandidates, shuffleKey
}

func (state *edgeFrontingScanState) recordAttempt() {

	state.mutex.Lock()
	state.attempts += 1
	attempts := state.attempts
	shouldLog := attempts == 1 ||
		attempts-state.lastProgressAttempt >= edgeFrontingScanProgressInterval
	if shouldLog {
		state.lastProgressAttempt = attempts
	}
	working := state.workingCountLocked()
	state.mutex.Unlock()

	if shouldLog {
		NoticeInfo(
			"edge fronting scan progress (attempts: %d, working: %d)",
			attempts,
			working)
	}
}

func (state *edgeFrontingScanState) recordExhausted() {

	state.mutex.Lock()
	if state.exhaustedLogged {
		state.mutex.Unlock()
		return
	}
	state.exhaustedLogged = true
	attempts := state.attempts
	working := state.workingCountLocked()
	state.mutex.Unlock()

	NoticeInfo(
		"edge fronting scan exhausted (attempts: %d, working: %d)",
		attempts,
		working)
}

func (state *edgeFrontingScanState) recordResult(
	candidate parameters.EdgeFrontingScanCandidate,
	success bool) {

	now := time.Now()
	key := candidate.Key()

	state.mutex.Lock()
	entry := state.entries[key]
	if entry == nil {
		entry = &edgeFrontingScanCacheEntry{
			IPAddress:     candidate.IPAddress,
			SNIServerName: candidate.SNIServerName,
		}
		state.entries[key] = entry
	}

	if success {
		entry.LastSuccessTimestamp = now
		entry.SuccessCount += 1
	} else {
		entry.LastFailureTimestamp = now
		entry.FailureCount += 1
	}
	jsonCache := state.marshalLocked()
	state.mutex.Unlock()

	if jsonCache != nil {
		_ = SetKeyValue(state.datastoreKey, string(jsonCache))
	}
}

func noticeEdgeFrontingScanFound(candidate parameters.EdgeFrontingScanCandidate) {

	if candidate.IPAddress == "" {
		return
	}
	sniServerName := candidate.SNIServerName
	if sniServerName == "" {
		sniServerName = "none"
	}
	NoticeInfo(
		"edge fronting scan found (ip: %s, sni: %s)",
		common.EscapeRedactIPAddressString(candidate.IPAddress),
		sniServerName)
}

func (state *edgeFrontingScanState) marshalLocked() []byte {
	entries := make(map[string]*edgeFrontingScanCacheEntry, len(state.entries))
	for key, entry := range state.entries {
		copyEntry := *entry
		entries[key] = &copyEntry
	}
	record := &edgeFrontingScanCacheRecord{
		Entries:     entries,
		ShuffleSeed: state.shuffleSeed,
	}
	jsonCache, err := json.Marshal(record)
	if err != nil {
		return nil
	}
	return jsonCache
}

func (state *edgeFrontingScanState) workingCountLocked() int {
	now := time.Now()
	count := 0
	for _, entry := range state.entries {
		if !entry.LastSuccessTimestamp.IsZero() &&
			now.Sub(entry.LastSuccessTimestamp) < edgeFrontingScanSuccessTTL &&
			(entry.LastFailureTimestamp.IsZero() ||
				entry.LastSuccessTimestamp.After(entry.LastFailureTimestamp)) {
			count += 1
		}
	}
	return count
}

func makeEdgeFrontingScanVerifyServerNames(
	candidate parameters.EdgeFrontingScanCandidate) []string {

	verifyServerNames := make([]string, 0, 8)
	seen := make(map[string]struct{})

	add := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		verifyServerNames = append(verifyServerNames, value)
	}

	add(candidate.SNIServerName)
	add(candidate.IPAddress)
	add("a248.e.akamai.net")
	add("a.akamaized.net")
	add("a.akamaized-staging.net")
	add("a.akamaihd.net")
	add("a.akamaihd-staging.net")
	add("www.akamai.com")

	return verifyServerNames
}
