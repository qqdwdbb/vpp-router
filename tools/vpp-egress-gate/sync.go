package gate

import (
	"fmt"
	"log"
	"net/netip"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type ApplyResult struct {
	Add, Delete, Conflicts, Excluded, Desired int
	Winners                                   []Route
}

func orderedWinners(cfg *Config, required []Route, claimed map[RouteKey]Route) ([]Route, error) {
	var mappings []Mapping
	for _, m := range cfg.Mappings {
		if m.Enabled {
			mappings = append(mappings, m)
		}
	}
	_, exclusions := exclusionIndex(cfg)
	for _, route := range required {
		if prefixExcluded(cfg, route.PrefixNet()) {
			return nil, fmt.Errorf("DNS route barrier rejected an excluded or conflicting route")
		}
	}
	extra := map[MappingKey]map[string]struct{}{}
	for _, route := range required {
		var candidates []Mapping
		for _, mapping := range mappings {
			if mapping.MatchesPath(route.Table, route.Via, route.Interface) {
				candidates = append(candidates, mapping)
			}
		}
		if len(candidates) == 0 {
			return nil, fmt.Errorf("route has no configured mapping")
		}
		for _, mapping := range candidates {
			set := extra[mapping.Key()]
			if set == nil {
				set = map[string]struct{}{}
				extra[mapping.Key()] = set
			}
			set[route.Prefix] = struct{}{}
		}
	}
	var needed []netip.Prefix
	allHosts := true
	for _, route := range required {
		n := route.PrefixNet()
		needed = append(needed, n)
		if n.Bits() != n.Addr().BitLen() {
			allHosts = false
		}
	}
	prefixSets := map[MappingKey]map[string]struct{}{}
	for k, v := range extra {
		set := map[string]struct{}{}
		for p := range v {
			set[p] = struct{}{}
		}
		prefixSets[k] = set
	}
	if allHosts {
		index := staticPrefixIndex(cfg)
		for _, network := range needed {
			for _, value := range index.Covering(network, 0) {
				pair, ok := value.([2]any)
				if !ok {
					continue
				}
				key, _ := pair[0].(MappingKey)
				prefix, _ := pair[1].(string)
				set := prefixSets[key]
				if set == nil {
					set = map[string]struct{}{}
					prefixSets[key] = set
				}
				set[prefix] = struct{}{}
			}
		}
	} else {
		for key, prefixes := range cfg.StaticPrefixes {
			for prefix := range prefixes {
				network, err := parsePrefixStrict(prefix)
				if err != nil {
					continue
				}
				for _, other := range needed {
					if prefixesOverlap(network, other) {
						set := prefixSets[key]
						if set == nil {
							set = map[string]struct{}{}
							prefixSets[key] = set
						}
						set[prefix] = struct{}{}
						break
					}
				}
			}
		}
	}
	byPath := map[[3]string]MappingKey{}
	for _, mapping := range mappings {
		for _, via := range mapping.EachVia() {
			byPath[[3]string{fmtUint(mapping.FibTable), via, mapping.Interface}] = mapping.Key()
		}
	}
	for _, route := range claimed {
		key, ok := byPath[[3]string{fmtUint(route.Table), route.Via, route.Interface}]
		if !ok {
			continue
		}
		network := route.PrefixNet()
		for _, other := range needed {
			if prefixesOverlap(network, other) {
				set := prefixSets[key]
				if set == nil {
					set = map[string]struct{}{}
					prefixSets[key] = set
				}
				set[route.Prefix] = struct{}{}
				break
			}
		}
	}
	desired, _, err := collectDesired(mappings, prefixSets, nil, exclusions, "first")
	if err != nil {
		return nil, err
	}
	return coveringRoutes(desired, required)
}

func fmtUint(v uint32) string { return fmt.Sprintf("%d", v) }

func addMemoryHosts(cfg *Config, backend Backend, required []Route, mutex *sync.Mutex) (ApplyResult, error) {
	store := currentStore()
	path := cfg.StateFile
	generation, err := backend.Generation()
	if err != nil {
		return ApplyResult{}, err
	}
	lock := mutex
	if lock == nil {
		lock = new(sync.Mutex)
	}
	lock.Lock()
	store.lock.Lock()
	owned, pending, index, err := store.Ledger(path, generation)
	if err != nil {
		store.lock.Unlock()
		lock.Unlock()
		return ApplyResult{}, err
	}
	claimed := map[RouteKey]Route{}
	for _, route := range required {
		for _, value := range index.Covering(route.PrefixNet(), route.Table) {
			key, ok := value.(RouteKey)
			if !ok {
				continue
			}
			if candidate, ok := pending[key]; ok {
				claimed[key] = candidate
			} else if candidate, ok := owned[key]; ok {
				claimed[key] = candidate
			}
		}
	}
	var winners []Route
	if cfg.OverlapPolicy == "first" {
		winners, err = orderedWinners(cfg, required, claimed)
		if err != nil {
			store.lock.Unlock()
			lock.Unlock()
			return ApplyResult{}, err
		}
	} else {
		desired := map[RouteKey]Route{}
		var exclusions []netip.Prefix
		for _, n := range cfg.ExcludePrefixes {
			p, err := parsePrefixStrict(n)
			if err != nil {
				store.lock.Unlock()
				lock.Unlock()
				return ApplyResult{}, err
			}
			exclusions = append(exclusions, p)
		}
		for _, route := range required {
			if existing, ok := desired[route.Key()]; ok && existing != route {
				store.lock.Unlock()
				lock.Unlock()
				return ApplyResult{}, fmt.Errorf("direct route install found a conflicting local route claim")
			}
			prev, ok := pending[route.Key()]
			if !ok {
				prev, ok = owned[route.Key()]
			}
			if ok && prev != route {
				store.lock.Unlock()
				lock.Unlock()
				return ApplyResult{}, fmt.Errorf("direct route install found a conflicting local route claim")
			}
			if isExcluded(route.PrefixNet(), nil, exclusions) {
				store.lock.Unlock()
				lock.Unlock()
				return ApplyResult{}, fmt.Errorf("DNS route barrier rejected an excluded or conflicting route")
			}
			desired[route.Key()] = route
		}
		winners = sortedRouteValues(desired)
	}
	newKeys := 0
	for _, r := range winners {
		if _, ok := owned[r.Key()]; !ok {
			if _, ok := pending[r.Key()]; !ok {
				newKeys++
			}
		}
	}
	if len(owned)+countNotIn(pending, owned)+newKeys > cfg.MaxRoutes {
		store.lock.Unlock()
		lock.Unlock()
		return ApplyResult{}, fmt.Errorf("max_routes exceeded")
	}
	var remove []Route
	for _, route := range winners {
		previous, ok := pending[route.Key()]
		if !ok {
			previous, ok = owned[route.Key()]
		}
		if ok && previous != route {
			remove = append(remove, previous)
		}
		pending[route.Key()] = route
		index.Add(route.PrefixNet(), route.Key(), route.Table)
	}
	store.dirty[filepath.Clean(path)] = struct{}{}
	store.lock.Unlock()
	lock.Unlock()
	var lines []string
	for _, r := range remove {
		lines = append(lines, r.Command("del"))
	}
	for _, r := range winners {
		lines = append(lines, r.Command("add"))
	}
	if err := backend.Apply(lines); err != nil {
		return ApplyResult{}, err
	}
	gen, err := backend.Generation()
	if err != nil {
		return ApplyResult{}, err
	}
	if gen != generation {
		return ApplyResult{}, fmt.Errorf("VPP restarted during reconciliation; retrying")
	}
	lock.Lock()
	store.lock.Lock()
	owned, pending, _, err = store.Ledger(path, generation)
	if err != nil {
		store.lock.Unlock()
		lock.Unlock()
		return ApplyResult{}, err
	}
	for _, route := range winners {
		if pending[route.Key()] == route {
			owned[route.Key()] = route
			delete(pending, route.Key())
		}
	}
	store.dirty[filepath.Clean(path)] = struct{}{}
	store.lock.Unlock()
	lock.Unlock()
	return ApplyResult{Add: len(winners), Delete: len(remove), Desired: len(winners), Winners: winners}, nil
}

func countNotIn(a, b map[RouteKey]Route) int {
	n := 0
	for k := range a {
		if _, ok := b[k]; !ok {
			n++
		}
	}
	return n
}

func addOrderedRoutes(cfg *Config, backend Backend, required []Route, mutex *sync.Mutex) (ApplyResult, error) {
	lock := mutex
	if lock == nil {
		lock = new(sync.Mutex)
	}
	var add, remove []Route
	var winners []Route
	var generation string
	lock.Lock()
	generation, err := backend.Generation()
	if err != nil {
		lock.Unlock()
		return ApplyResult{}, err
	}
	state, ownedMap, pendingMap, err := splitState(cfg.StateFile, generation)
	if err != nil {
		lock.Unlock()
		return ApplyResult{}, err
	}
	claimed := map[RouteKey]Route{}
	for k, r := range ownedMap {
		claimed[k] = r
	}
	for k, r := range pendingMap {
		claimed[k] = r
	}
	winners, err = orderedWinners(cfg, required, claimed)
	if err != nil {
		lock.Unlock()
		return ApplyResult{}, err
	}
	for _, route := range winners {
		previous, ok := ownedMap[route.Key()]
		if !ok {
			previous, ok = pendingMap[route.Key()]
		}
		if ok && previous != route {
			remove = append(remove, previous)
		}
		add = append(add, route)
		pendingMap[route.Key()] = route
	}
	add = uniqueRoutes(add)
	remove = uniqueRoutes(remove)
	sortRoutes(add)
	sortRoutes(remove)
	if len(ownedMap)+countNotIn(pendingMap, ownedMap) > cfg.MaxRoutes {
		lock.Unlock()
		return ApplyResult{}, fmt.Errorf("max_routes exceeded")
	}
	if len(add) > 0 || len(remove) > 0 {
		pendingState := map[string]any{
			"version":     1,
			"generation":  generation,
			"owned":       routesToJSON(sortedRouteValues(ownedMap)),
			"pending_add": routesToJSON(sortedRouteValues(pendingMap)),
		}
		if v, ok := state["audited_at"]; ok {
			pendingState["audited_at"] = v
		}
		if err := AtomicJSON(cfg.StateFile, pendingState); err != nil {
			lock.Unlock()
			return ApplyResult{}, err
		}
	}
	lock.Unlock()
	if len(add) > 0 || len(remove) > 0 {
		var lines []string
		for _, r := range remove {
			lines = append(lines, r.Command("del"))
		}
		for _, r := range add {
			lines = append(lines, r.Command("add"))
		}
		if err := backend.Apply(lines); err != nil {
			return ApplyResult{}, err
		}
		gen, err := backend.Generation()
		if err != nil {
			return ApplyResult{}, err
		}
		if gen != generation {
			return ApplyResult{}, fmt.Errorf("VPP restarted during reconciliation; retrying")
		}
	}
	lock.Lock()
	defer lock.Unlock()
	state, ownedMap, pendingMap, err = splitState(cfg.StateFile, generation)
	if err != nil {
		return ApplyResult{}, err
	}
	for _, route := range remove {
		if ownedMap[route.Key()] == route {
			delete(ownedMap, route.Key())
		}
		if pendingMap[route.Key()] == route {
			delete(pendingMap, route.Key())
		}
	}
	for _, route := range winners {
		ownedMap[route.Key()] = route
		delete(pendingMap, route.Key())
	}
	final := map[string]any{
		"version":     1,
		"generation":  generation,
		"pending_add": routesToJSON(sortedRouteValues(pendingMap)),
		"owned":       routesToJSON(sortedRouteValues(ownedMap)),
	}
	if v, ok := state["audited_at"]; ok {
		final["audited_at"] = v
	}
	if err := AtomicJSON(cfg.StateFile, final); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Add: len(add), Delete: len(remove), Desired: len(winners), Winners: winners}, nil
}

func uniqueRoutes(in []Route) []Route {
	seen := map[Route]struct{}{}
	var out []Route
	for _, r := range in {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

func EnsureRoutes(cfg *Config, backend Backend, required []Route, mutex *sync.Mutex) (ApplyResult, error) {
	result, err := AddRoutes(cfg, backend, required, mutex)
	if err != nil {
		return result, err
	}
	if linux, ok := backend.(interface{ EnsureLinuxExits() error }); ok {
		if err := linux.EnsureLinuxExits(); err != nil {
			return result, err
		}
	}
	return result, nil
}

func AddRoutes(cfg *Config, backend Backend, required []Route, mutex *sync.Mutex) (ApplyResult, error) {
	set := uniqueRoutes(required)
	sortRoutes(set)
	required = set
	store := currentStore()
	allHosts := true
	for _, r := range required {
		n := r.PrefixNet()
		if n.Bits() != n.Addr().BitLen() {
			allHosts = false
			break
		}
	}
	if len(required) > 0 && store != nil && store.Handles(cfg.StateFile) && allHosts {
		return addMemoryHosts(cfg, backend, required, mutex)
	}
	if len(required) > 0 && cfg.OverlapPolicy == "first" {
		return addOrderedRoutes(cfg, backend, required, mutex)
	}
	if len(required) == 0 {
		return ApplyResult{}, nil
	}
	desired := map[RouteKey]Route{}
	for _, route := range required {
		if existing, ok := desired[route.Key()]; ok && existing != route {
			return ApplyResult{}, fmt.Errorf("conflicting mappings for %s; refusing partial reconciliation", route.Prefix)
		}
		desired[route.Key()] = route
	}
	var exclusions []netip.Prefix
	for _, n := range cfg.ExcludePrefixes {
		p, err := parsePrefixStrict(n)
		if err != nil {
			return ApplyResult{}, err
		}
		exclusions = append(exclusions, p)
	}
	for _, route := range desired {
		if isExcluded(route.PrefixNet(), nil, exclusions) {
			return ApplyResult{}, fmt.Errorf("DNS route barrier rejected an excluded or conflicting route")
		}
	}
	lock := mutex
	if lock == nil {
		lock = new(sync.Mutex)
	}
	var add []Route
	var generation string
	lock.Lock()
	generation, err := backend.Generation()
	if err != nil {
		lock.Unlock()
		return ApplyResult{}, err
	}
	state, ownedMap, pendingMap, err := splitState(cfg.StateFile, generation)
	if err != nil {
		lock.Unlock()
		return ApplyResult{}, err
	}
	for _, route := range desired {
		previous, ok := ownedMap[route.Key()]
		if !ok {
			previous, ok = pendingMap[route.Key()]
		}
		if ok && previous != route {
			lock.Unlock()
			return ApplyResult{}, fmt.Errorf("direct route install found a conflicting local route claim")
		}
		add = append(add, route)
	}
	sortRoutes(add)
	claimed := map[RouteKey]struct{}{}
	for k := range ownedMap {
		claimed[k] = struct{}{}
	}
	for k := range pendingMap {
		claimed[k] = struct{}{}
	}
	for _, r := range add {
		claimed[r.Key()] = struct{}{}
	}
	if len(claimed) > cfg.MaxRoutes {
		lock.Unlock()
		return ApplyResult{}, fmt.Errorf("max_routes exceeded")
	}
	if len(add) > 0 {
		for _, route := range add {
			pendingMap[route.Key()] = route
		}
		pendingState := map[string]any{
			"version":     1,
			"generation":  generation,
			"owned":       routesToJSON(sortedRouteValues(ownedMap)),
			"pending_add": routesToJSON(sortedRouteValues(pendingMap)),
		}
		if v, ok := state["audited_at"]; ok {
			pendingState["audited_at"] = v
		}
		if err := AtomicJSON(cfg.StateFile, pendingState); err != nil {
			lock.Unlock()
			return ApplyResult{}, err
		}
	}
	lock.Unlock()
	if len(add) > 0 {
		var lines []string
		for _, r := range add {
			lines = append(lines, r.Command("add"))
		}
		if err := backend.Apply(lines); err != nil {
			return ApplyResult{}, err
		}
		gen, err := backend.Generation()
		if err != nil {
			return ApplyResult{}, err
		}
		if gen != generation {
			return ApplyResult{}, fmt.Errorf("VPP restarted during reconciliation; retrying")
		}
	}
	lock.Lock()
	defer lock.Unlock()
	state, ownedMap, pendingMap, err = splitState(cfg.StateFile, generation)
	if err != nil {
		return ApplyResult{}, err
	}
	for _, route := range desired {
		if ownedMap[route.Key()] == route || pendingMap[route.Key()] == route {
			ownedMap[route.Key()] = route
			delete(pendingMap, route.Key())
		}
	}
	final := map[string]any{
		"version":     1,
		"generation":  generation,
		"pending_add": routesToJSON(sortedRouteValues(pendingMap)),
		"owned":       routesToJSON(sortedRouteValues(ownedMap)),
	}
	if v, ok := state["audited_at"]; ok {
		final["audited_at"] = v
	}
	if err := AtomicJSON(cfg.StateFile, final); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Add: len(add), Desired: len(desired), Winners: sortedRouteValues(desired)}, nil
}

type preparedSync struct {
	Path       string
	Generation string
	State      map[string]any
	Mappings   []Mapping
	Protected  []netip.Prefix
	Exclusions []netip.Prefix
	Live       map[RouteKey]PathSet
	Withdraw   bool
	Audit      bool
	// MissingExits are interfaces VPP lacks; their rules sit out this sync.
	MissingExits map[string]bool
	// Orphans are recorded routes through those interfaces. VPP keeps them, unresolved,
	// until they are deleted, and nothing else would delete them: they no longer match.
	Orphans []Route
}

func mappingInterfaces(cfg *Config) []string {
	set := map[string]bool{}
	for _, m := range cfg.Mappings {
		if m.Enabled {
			set[m.Interface] = true
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func PrepareSync(cfg *Config, backend Backend, withdraw bool, audit *bool) (preparedSync, error) {
	path := cfg.StateFile
	generation, err := backend.Generation()
	if err != nil {
		return preparedSync{}, err
	}
	state, owned, pending, err := splitState(path, generation)
	if err != nil {
		return preparedSync{}, err
	}
	candidates := append(sortedRouteValues(owned), sortedRouteValues(pending)...)
	doAudit := true
	if audit != nil {
		doAudit = *audit
	} else {
		interval := cfg.FibAuditSeconds
		last := 0.0
		if v := state["audited_at"]; v != nil {
			if n, err := asInt(v); err == nil {
				last = float64(n)
			}
		}
		gen, _ := state["generation"].(string)
		doAudit = interval <= 0 || time.Now().Unix()-int64(last) >= int64(interval) || gen != generation
	}
	var mappings []Mapping
	var missing map[string]bool
	if !withdraw {
		if missing, err = backend.MissingInterfaces(mappingInterfaces(cfg)); err != nil {
			return preparedSync{}, err
		}
		for _, m := range cfg.Mappings {
			if m.Enabled && !missing[m.Interface] {
				mappings = append(mappings, m)
			}
		}
	}
	var exclusions []netip.Prefix
	for _, n := range cfg.ExcludePrefixes {
		p, err := parsePrefixStrict(n)
		if err != nil {
			return preparedSync{}, err
		}
		exclusions = append(exclusions, p)
	}
	var markers []Route
	for _, mapping := range mappings {
		for _, via := range mapping.EachVia() {
			prefix := "0.0.0.0/32"
			if viaFamily(via) == 6 {
				prefix = "::/128"
			}
			markers = append(markers, Route{mapping.FibTable, prefix, via, mapping.Interface})
		}
	}
	live := map[RouteKey]PathSet{}
	if doAudit {
		live, err = backend.Snapshot(append(markers, candidates...))
		if err != nil {
			return preparedSync{}, err
		}
	}
	var orphans []Route
	for _, route := range candidates {
		if missing[route.Interface] {
			orphans = append(orphans, route)
		}
	}
	return preparedSync{
		Orphans: orphans,
		Path:    path, Generation: generation, State: state, Mappings: mappings,
		Exclusions: exclusions, Live: live, Withdraw: withdraw, Audit: doAudit, MissingExits: missing,
	}, nil
}

func protectConcurrent(desired map[RouteKey]Route, candidates []Route, preparedState map[string]any, generation string) {
	preparedKeys := map[RouteKey]struct{}{}
	gen, _ := preparedState["generation"].(string)
	if gen == generation {
		for _, name := range []string{"owned", "pending_add"} {
			arr, _ := preparedState[name].([]any)
			for _, item := range arr {
				if r, ok := routeFromJSON(item); ok {
					preparedKeys[r.Key()] = struct{}{}
				}
			}
		}
	}
	for _, route := range candidates {
		if _, ok := preparedKeys[route.Key()]; !ok {
			if _, ok := desired[route.Key()]; !ok {
				desired[route.Key()] = route
			}
		}
	}
}

func CommitSync(cfg *Config, backend Backend, prepared preparedSync, extraPrefixes map[MappingKey]map[string]struct{}, mutex *sync.Mutex, prefixLocks *PrefixLocks, refreshPrefixes func() map[MappingKey]map[string]struct{}, onWithdraw func([]RouteKey), verifyApply bool) (ApplyResult, error) {
	generation := prepared.Generation
	gen, err := backend.Generation()
	if err != nil {
		return ApplyResult{}, err
	}
	if gen != generation {
		return ApplyResult{}, fmt.Errorf("VPP restarted during snapshot; retrying")
	}
	mappings := prepared.Mappings
	exclusions := prepared.Exclusions
	path := prepared.Path
	prefixSets := map[MappingKey]map[string]struct{}{}
	for k, prefixes := range extraPrefixes {
		set := prefixSets[k]
		if set == nil {
			set = map[string]struct{}{}
			prefixSets[k] = set
		}
		for p := range prefixes {
			set[p] = struct{}{}
		}
	}
	desired, excluded, err := collectDesired(mappings, prefixSets, nil, exclusions, cfg.OverlapPolicy)
	if err != nil {
		return ApplyResult{}, err
	}
	live := map[RouteKey]PathSet{}
	for k, v := range prepared.Live {
		live[k] = v
	}
	previewState, previewOwned, previewPending, err := splitState(path, generation)
	if err != nil {
		return ApplyResult{}, err
	}
	preview := append(sortedRouteValues(previewOwned), sortedRouteValues(previewPending)...)
	audit := prepared.Audit
	if audit {
		var refresh []Route
		for _, route := range preview {
			if _, ok := live[route.Key()]; !ok {
				refresh = append(refresh, route)
			}
		}
		if len(refresh) > 0 && len(refresh) <= exactLookupLim {
			part, err := backend.Lookup(refresh)
			if err != nil {
				return ApplyResult{}, err
			}
			for k, v := range part {
				live[k] = v
			}
		}
	} else {
		if gen, _ := previewState["generation"].(string); gen == generation {
			if arr, ok := previewState["owned"].([]any); ok {
				for _, item := range arr {
					if route, ok := routeFromJSON(item); ok {
						if _, present := live[route.Key()]; !present {
							live[route.Key()] = pathSetOf(route.Via, route.Interface)
						}
					}
				}
			}
		}
	}
	lock := mutex
	if lock == nil {
		lock = new(sync.Mutex)
	}
	lock.Lock()
	state, ownedMap, pendingMap, err := splitState(path, generation)
	if err != nil {
		lock.Unlock()
		return ApplyResult{}, err
	}
	candidates := append(sortedRouteValues(ownedMap), sortedRouteValues(pendingMap)...)
	protectConcurrent(desired, candidates, prepared.State, generation)
	if len(desired) > cfg.MaxRoutes {
		lock.Unlock()
		return ApplyResult{}, fmt.Errorf("max_routes exceeded")
	}
	remove, add, owned, conflicts := plan(desired, candidates, live)
	plannedKeys := map[RouteKey]struct{}{}
	for _, r := range candidates {
		plannedKeys[r.Key()] = struct{}{}
	}
	summary := ApplyResult{Add: len(add), Delete: len(remove), Conflicts: len(conflicts), Excluded: excluded, Desired: len(desired)}
	if len(remove) > 0 || len(add) > 0 {
		ckOwned := map[RouteKey]Route{}
		for _, r := range owned {
			ckOwned[r.Key()] = r
		}
		ckPending := map[RouteKey]Route{}
		for _, r := range add {
			ckPending[r.Key()] = r
		}
		for key, route := range ownedMap {
			if _, ok := ckOwned[key]; !ok {
				if _, ok := ckPending[key]; !ok {
					ckOwned[key] = route
				}
			}
		}
		for key, route := range pendingMap {
			if _, ok := ckOwned[key]; !ok {
				if _, ok := ckPending[key]; !ok {
					ckPending[key] = route
				}
			}
		}
		if err := AtomicJSON(path, map[string]any{
			"version": 1, "generation": generation,
			"owned":       routesToJSON(sortedRouteValues(ckOwned)),
			"pending_add": routesToJSON(sortedRouteValues(ckPending)),
		}); err != nil {
			lock.Unlock()
			return ApplyResult{}, err
		}
	}
	lock.Unlock()

	if err := backend.SyncTProxy(); err != nil {
		return ApplyResult{}, err
	}

	runApply := func(toAdd, toRemove []Route) error {
		if len(toAdd) == 0 && len(toRemove) == 0 {
			return nil
		}
		var lines []string
		for _, r := range toRemove {
			lines = append(lines, r.Command("del"))
		}
		for _, r := range toAdd {
			lines = append(lines, r.Command("add"))
		}
		if err := backend.Apply(lines); err != nil {
			return err
		}
		changed := append(append([]Route{}, toAdd...), toRemove...)
		if verifyApply {
			fresh, err := backend.Lookup(changed)
			if err != nil {
				return err
			}
			for _, route := range changed {
				if paths, ok := fresh[route.Key()]; ok {
					live[route.Key()] = paths
				} else {
					delete(live, route.Key())
				}
			}
		} else {
			for _, route := range toRemove {
				delete(live, route.Key())
			}
			for _, route := range toAdd {
				live[route.Key()] = pathSetOf(route.Via, route.Interface)
			}
		}
		gen, err := backend.Generation()
		if err != nil {
			return err
		}
		if gen != generation {
			return fmt.Errorf("VPP restarted during reconciliation; retrying")
		}
		if verifyApply {
			for _, r := range toAdd {
				if !Matches(r, live) {
					return fmt.Errorf("VPP batch verification failed; persisted intent will be retried: %s has %v", r.Command("add"), live[r.Key()])
				}
			}
			removeSet := map[Route]struct{}{}
			for _, r := range toAdd {
				removeSet[r] = struct{}{}
			}
			for _, r := range toRemove {
				if _, alsoAdd := removeSet[r]; !alsoAdd && Matches(r, live) {
					return fmt.Errorf("VPP batch verification failed; persisted intent will be retried: %s is still there", r.Command("del"))
				}
			}
		}
		return nil
	}

	removeKeys := map[RouteKey]struct{}{}
	for _, r := range remove {
		removeKeys[r.Key()] = struct{}{}
	}
	var firstAdd []Route
	for _, r := range add {
		if _, ok := removeKeys[r.Key()]; !ok {
			firstAdd = append(firstAdd, r)
		}
	}
	if err := runApply(firstAdd, nil); err != nil {
		return ApplyResult{}, err
	}
	if prefixLocks != nil && len(remove) > 0 {
		release := prefixLocks.Hold(keysOf(remove))
		defer release()
		if !prepared.Withdraw {
			extra := extraPrefixes
			if refreshPrefixes != nil {
				extra = refreshPrefixes()
			}
			prefixSets = map[MappingKey]map[string]struct{}{}
			for k, prefixes := range extra {
				set := prefixSets[k]
				if set == nil {
					set = map[string]struct{}{}
					prefixSets[k] = set
				}
				for p := range prefixes {
					set[p] = struct{}{}
				}
			}
			desiredNow, _, err := collectDesired(mappings, prefixSets, nil, exclusions, cfg.OverlapPolicy)
			if err != nil {
				return ApplyResult{}, err
			}
			var kept []Route
			for _, route := range remove {
				if desiredNow[route.Key()] != route {
					kept = append(kept, route)
				}
			}
			remove = kept
			summary.Delete = len(remove)
		}
	}
	var replaceAdd []Route
	for _, r := range add {
		if _, ok := removeKeys[r.Key()]; ok {
			replaceAdd = append(replaceAdd, r)
		}
	}
	if err := runApply(replaceAdd, remove); err != nil {
		return ApplyResult{}, err
	}
	if onWithdraw != nil && len(remove) > 0 {
		onWithdraw(keysOf(remove))
	}
	lock.Lock()
	defer lock.Unlock()
	state, latestOwned, latestPending, err := splitState(path, generation)
	if err != nil {
		return ApplyResult{}, err
	}
	removed := map[RouteKey]struct{}{}
	for _, r := range remove {
		removed[r.Key()] = struct{}{}
	}
	keep := map[RouteKey]Route{}
	for _, r := range append(append([]Route{}, owned...), add...) {
		if Matches(r, live) {
			keep[r.Key()] = r
		}
	}
	for key, route := range latestOwned {
		if _, ok := keep[key]; ok {
			continue
		}
		if _, ok := removed[key]; ok {
			continue
		}
		if _, ok := plannedKeys[key]; ok {
			continue
		}
		keep[key] = route
	}
	pending := map[RouteKey]Route{}
	for key, route := range latestPending {
		if _, ok := keep[key]; !ok {
			pending[key] = route
		}
	}
	final := map[string]any{
		"version":     1,
		"generation":  generation,
		"pending_add": routesToJSON(sortedRouteValues(pending)),
		"owned":       routesToJSON(sortedRouteValues(keep)),
	}
	if audit {
		final["audited_at"] = int(time.Now().Unix())
	} else if v, ok := state["audited_at"]; ok {
		final["audited_at"] = v
	}
	if err := AtomicJSON(path, final); err != nil {
		return ApplyResult{}, err
	}
	if err := backend.SyncTProxy(); err != nil {
		return ApplyResult{}, err
	}
	return summary, nil
}

func keysOf(routes []Route) []RouteKey {
	out := make([]RouteKey, len(routes))
	for i, r := range routes {
		out[i] = r.Key()
	}
	return out
}

func SyncAll(cfg *Config, backend Backend, extraPrefixes map[MappingKey]map[string]struct{}) (ApplyResult, error) {
	prepared, err := PrepareSync(cfg, backend, false, nil)
	if err != nil {
		return ApplyResult{}, err
	}
	return CommitSync(cfg, backend, prepared, extraPrefixes, nil, nil, nil, nil, true)
}

func init() { log.SetFlags(0) }
