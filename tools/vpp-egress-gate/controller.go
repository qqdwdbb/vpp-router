package gate

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type suffixNode struct {
	children map[string]*suffixNode
	rules    []int
}

type ruleIndex struct {
	rules    []Rule
	suffixes *suffixNode
	keywords [][2]any
}

type Controller struct {
	ConfigPath       string
	LeasePath        string
	DomainRoutesPath string
	BackendFactory   BackendFactory

	mutex       sync.Mutex
	reloadLock  sync.RWMutex
	cacheLock   sync.Mutex
	flightLock  sync.Mutex
	orderedLock sync.Mutex
	PrefixLocks *PrefixLocks
	inFlight    map[RouteKey]chan struct{}
	verified    map[RouteKey]Route
	verifiedGen string
	lockEpoch   [][2]any

	config        *Config
	rules         []Rule
	index         *ruleIndex
	backgroundSig bgSig
	missingExits  map[string]bool // exits VPP lacked at the last full sync
	installFail   int
	Seen          map[SeenKey]int64

	baseExcludes     []string
	underlay         map[string][]string
	underlayDiscover func(context.Context, string) ([]string, bool, error)
}

func NewController(configPath, leasePath string, factory BackendFactory, domainRoutesPath string) (*Controller, error) {
	if domainRoutesPath == "" {
		return nil, fmt.Errorf("configuration needs routes or domain_routes_file")
	}
	if factory == nil {
		factory = NewVPPBackend
	}
	c := &Controller{
		ConfigPath:       configPath,
		LeasePath:        leasePath,
		DomainRoutesPath: domainRoutesPath,
		BackendFactory:   factory,
		PrefixLocks:      NewPrefixLocks(),
		inFlight:         map[RouteKey]chan struct{}{},
		verified:         map[RouteKey]Route{},
		Seen:             map[SeenKey]int64{},
	}
	if _, err := os.Stat(leasePath); err == nil {
		raw := readJSONFile(leasePath, []any{})
		if arr, ok := raw.([]any); ok {
			c.Seen = DecodeSeen(arr)
		}
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// mergedExcludes requires cacheLock.
func (c *Controller) mergedExcludes() []string {
	merged := append([]string{}, c.baseExcludes...)
	seen := map[string]bool{}
	for _, prefix := range merged {
		seen[prefix] = true
	}
	var interfaces []string
	for name := range c.underlay {
		interfaces = append(interfaces, name)
	}
	sort.Strings(interfaces)
	for _, name := range interfaces {
		for _, prefix := range c.underlay[name] {
			if !seen[prefix] {
				seen[prefix] = true
				merged = append(merged, prefix)
			}
		}
	}
	return merged
}

// refreshLinuxUnderlay excludes the current tunnel endpoints of Linux exits. The
// exclusions take effect on every route path, and the next reconciliation
// withdraws an already installed route that would loop.
func (c *Controller) refreshLinuxUnderlay(ctx context.Context) {
	c.cacheLock.Lock()
	cfg := c.config
	discover := c.underlayDiscover
	next := map[string][]string{}
	for name, prefixes := range c.underlay {
		next[name] = prefixes
	}
	c.cacheLock.Unlock()
	if cfg == nil || !hasLinuxExits(cfg) {
		return
	}
	if discover == nil {
		discover = linuxExitUnderlay
	}
	for _, m := range cfg.Mappings {
		if !m.Enabled || m.LinuxExit == nil {
			continue
		}
		prefixes, present, err := discover(ctx, m.LinuxExit.Interface)
		if err != nil {
			log.Printf("Linux exit endpoint check failed: %s", err)
			continue
		}
		if present && len(prefixes) == 0 {
			delete(next, m.LinuxExit.Interface)
		} else if present {
			sort.Strings(prefixes)
			next[m.LinuxExit.Interface] = prefixes
		}
	}
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	if underlayEqual(c.underlay, next) {
		return
	}
	c.underlay = next
	updated := *c.config
	updated.ExcludePrefixes = c.mergedExcludes()
	updated.exclusionIndex, updated.exclusionNets = nil, nil
	exclusionIndex(&updated)
	c.config = &updated
	for key, route := range c.verified {
		if prefixExcluded(&updated, route.PrefixNet()) {
			delete(c.verified, key)
		}
	}
	// A new revision makes the next background pass recompute desired routes.
	c.installFail++
	log.Printf("Linux exit tunnel endpoints excluded from routing: %v", next)
}

func underlayEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, prefixes := range a {
		other, ok := b[name]
		if !ok || strings.Join(prefixes, ",") != strings.Join(other, ",") {
			return false
		}
	}
	return true
}

func seenEqual(a, b map[SeenKey]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// loaded returns the current configuration and exclusions.
func (c *Controller) loaded() (*Config, []Rule) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	return c.config, c.rules
}

// load reads configuration and collection contents while route writers are excluded.
func (c *Controller) load() error {
	rulePaths, err := DomainRoutePaths(c.DomainRoutesPath)
	if err != nil {
		return err
	}
	cfg, err := LoadConfig(c.ConfigPath)
	if err != nil {
		return err
	}
	c.cacheLock.Lock()
	c.baseExcludes = append([]string{}, cfg.ExcludePrefixes...)
	cfg.ExcludePrefixes = c.mergedExcludes()
	c.cacheLock.Unlock()
	cfg.IgnoreListProblems = true
	// An empty routes list is valid: forward DNS and divert nothing until rules arrive.
	rules, err := DomainRoutesFromFile(c.DomainRoutesPath, cfg)
	if err != nil {
		return err
	}
	cfg.StaticPrefixes = map[MappingKey]map[string]struct{}{}
	for key, prefixes := range cfg.IPRangePrefixes {
		set := cfg.StaticPrefixes[key]
		if set == nil {
			set = map[string]struct{}{}
			cfg.StaticPrefixes[key] = set
		}
		for p := range prefixes {
			set[p] = struct{}{}
		}
	}
	for network, entry := range cfg.FakeIPPools {
		if prefixExcluded(cfg, network) {
			err = fmt.Errorf("Fake-IP pool overlaps an excluded prefix")
			return err
		}
		for _, mapping := range cfg.Mappings {
			key := mapping.Key()
			for prefix := range cfg.StaticPrefixes[key] {
				other, err := parsePrefixStrict(prefix)
				if err != nil {
					continue
				}
				if network.Addr().BitLen() == other.Addr().BitLen() && prefixesOverlap(network, other) &&
					!mapping.MatchesPath(entry.Route.Table, entry.Route.Via, entry.Route.Interface) {
					err := fmt.Errorf("Fake-IP pool overlaps a different static exit")
					return err
				}
			}
		}
		set := cfg.StaticPrefixes[entry.Mapping]
		if set == nil {
			set = map[string]struct{}{}
			cfg.StaticPrefixes[entry.Mapping] = set
		}
		set[prefixString(network)] = struct{}{}
	}
	staticPrefixIndex(cfg)
	exclusionIndex(cfg)

	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	valid := map[[2]any]struct{}{}
	for _, rule := range rules {
		for _, t := range rule.Targets {
			valid[[2]any{t.Mapping.Key(), rule.Pattern}] = struct{}{}
		}
	}
	sourceHash, err := DomainSourceHash(rulePaths)
	if err != nil {
		return err
	}
	outletHashes, err := domainOutletHashes(c.DomainRoutesPath)
	if err != nil {
		return err
	}
	mappingKeys := map[string]MappingKey{}
	for _, mapping := range cfg.Mappings {
		mappingKeys[mapping.Set] = mapping.Key()
	}
	current := map[SeenKey]int64{}
	for key, ts := range c.Seen {
		if key.Kind == 3 {
			if _, ok := valid[[2]any{key.Mapping, key.Domain}]; ok {
				current[key] = ts
			}
		} else if key.Kind == 4 && key.Domain == migratedDomain {
			if _, ok := mappingKeys[key.Mapping.Set]; ok && (key.SourceHash == sourceHash || key.SourceHash == outletHashes[key.Mapping.Set]) {
				migrated := SeenKey{Mapping: mappingKeys[key.Mapping.Set], Prefix: key.Prefix, Domain: migratedDomain, SourceHash: outletHashes[key.Mapping.Set], Kind: 4}
				current[migrated] = ts
			}
		} else if key.Kind == 2 {
			if mk, ok := mappingKeys[key.Mapping.Set]; ok {
				migrated := SeenKey{Mapping: mk, Prefix: key.Prefix, Domain: migratedDomain, SourceHash: outletHashes[key.Mapping.Set], Kind: 4}
				current[migrated] = ts
			}
		}
	}
	filtered := map[SeenKey]int64{}
	for key, ts := range current {
		n, err := parsePrefixStrict(key.Prefix)
		if err != nil {
			continue
		}
		drop := false
		for pool := range cfg.FakeIPPools {
			if n.Addr().BitLen() == pool.Addr().BitLen() && prefixSubnetOf(n, pool) {
				drop = true
				break
			}
		}
		if !drop {
			filtered[key] = ts
		}
	}
	current = filtered
	if !seenEqual(current, c.Seen) {
		_ = AtomicJSON(c.LeasePath, EncodeSeen(current))
		c.Seen = current
	}
	c.config = cfg
	c.rules = rules
	c.index = indexRules(rules)
	return nil
}

func stringsJoin(s []string, sep string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += sep
		}
		out += v
	}
	return out
}

func indexRules(rules []Rule) *ruleIndex {
	idx := &ruleIndex{rules: rules, suffixes: &suffixNode{children: map[string]*suffixNode{}}}
	for i, rule := range rules {
		if rule.Match == "contains" {
			idx.keywords = append(idx.keywords, [2]any{i, rule.Pattern})
			continue
		}
		node := idx.suffixes
		labels := splitLabels(rule.Pattern)
		for i := len(labels) - 1; i >= 0; i-- {
			next := node.children[labels[i]]
			if next == nil {
				next = &suffixNode{children: map[string]*suffixNode{}}
				node.children[labels[i]] = next
			}
			node = next
		}
		node.rules = append(node.rules, i)
	}
	return idx
}

func splitLabels(name string) []string {
	if name == "" {
		return nil
	}
	var labels []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	labels = append(labels, name[start:])
	return labels
}

func (c *Controller) matchingRules(rules []Rule, names []string) []Rule {
	c.cacheLock.Lock()
	index := c.index
	c.cacheLock.Unlock()
	if index == nil || !sameRules(index.rules, rules) {
		index = indexRules(rules)
	}
	matched := map[int]struct{}{}
	for _, name := range names {
		name = toLowerTrim(name)
		node := index.suffixes
		labels := splitLabels(name)
		ok := true
		for i := len(labels) - 1; i >= 0; i-- {
			next := node.children[labels[i]]
			if next == nil {
				ok = false
				break
			}
			node = next
			for _, pos := range node.rules {
				matched[pos] = struct{}{}
			}
		}
		_ = ok
		for _, kw := range index.keywords {
			pos := kw[0].(int)
			pattern := kw[1].(string)
			if containsString(name, pattern) {
				matched[pos] = struct{}{}
			}
		}
	}
	positions := make([]int, 0, len(matched))
	for p := range matched {
		positions = append(positions, p)
	}
	sort.Ints(positions)
	out := make([]Rule, 0, len(positions))
	for _, p := range positions {
		out = append(out, rules[p])
	}
	return out
}

func sameRules(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return &a[0] == &b[0]
}

func toLowerTrim(name string) string {
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func containsString(s, sub string) bool {
	return strings.Contains(s, sub)
}

// familyRule recognizes separately configured IPv4 and IPv6 halves of the
// same outlet while preserving the first rule's policy priority.
func familyRule(matched []Rule, family int) *Rule {
	if len(matched) == 0 {
		return nil
	}
	first := &matched[0]
	if family != 4 && family != 6 {
		return first
	}
	for _, target := range first.Targets {
		if target.Mapping.ViaFor(family) != "" {
			return first
		}
	}
	for i := 1; i < len(matched); i++ {
		candidate := &matched[i]
		if candidate.Pattern != first.Pattern || candidate.Match != first.Match ||
			(first.Upstream == nil) != (candidate.Upstream == nil) ||
			(first.Upstream != nil && *first.Upstream != *candidate.Upstream) {
			continue
		}
		for _, original := range first.Targets {
			for _, target := range candidate.Targets {
				if original.Mapping.Interface == target.Mapping.Interface &&
					original.Mapping.FibTable == target.Mapping.FibTable &&
					original.Mapping.HasFakeIP() == target.Mapping.HasFakeIP() &&
					target.Mapping.ViaFor(family) != "" {
					return candidate
				}
			}
		}
	}
	return first
}

func (c *Controller) dnsRule(cfg *Config, rules []Rule, q Question) *Rule {
	matched := c.matchingRules(rules, []string{q.Name})
	if cfg.DNSUpstreamPolicy == "first" && len(matched) > 0 {
		return familyRule(matched, queryFamily(q))
	}
	for i := range matched {
		rule := &matched[i]
		if cfg.DNSUpstreamPolicy == "first" {
			var version *int
			switch q.Type {
			case 1:
				v := 4
				version = &v
			case 28:
				v := 6
				version = &v
			}
			if version != nil {
				ok := false
				for _, t := range rule.Targets {
					if t.Version == nil || *t.Version == *version {
						ok = true
						break
					}
				}
				if !ok {
					continue
				}
			}
			return rule
		}
		if rule.Upstream != nil {
			return rule
		}
	}
	return nil
}

func (c *Controller) SuppressAAAA(q Question) bool {
	if q.Type != 28 {
		return false
	}
	_, rules := c.loaded()
	matched := c.matchingRules(rules, []string{q.Name})
	if len(matched) == 0 {
		return false
	}
	hasV4, hasV6 := false, false
	selected := familyRule(matched, 6)
	for _, t := range matched[0].Targets {
		if t.Mapping.ViaFor(4) != "" {
			hasV4 = true
		}
	}
	for _, t := range selected.Targets {
		if t.Mapping.ViaFor(6) != "" {
			hasV6 = true
		}
	}
	return hasV4 && !hasV6
}

func (c *Controller) DNSUpstream(q Question) *Upstream {
	upstream, _ := c.DNSUpstreamRoute(q)
	return upstream
}

// DNSUpstreamRoute also returns the socket mark that sends the query through a Linux exit.
func (c *Controller) DNSUpstreamRoute(q Question) (*Upstream, uint32) {
	cfg, rules := c.loaded()
	rule := c.dnsRule(cfg, rules, q)
	if rule == nil {
		return nil, 0
	}
	return rule.Upstream, rule.UpstreamMark
}

func (c *Controller) AnswerTTL(q Question) *uint32 {
	cfg, rules := c.loaded()
	if cfg.FakeIPTTL == 0 {
		return nil
	}
	rule := c.dnsRule(cfg, rules, q)
	if rule != nil {
		family := queryFamily(q)
		for _, t := range rule.Targets {
			if family == 0 && t.Mapping.HasFakeIP() || family != 0 && t.Mapping.FakeIPFor(family) != "" {
				ttl := uint32(cfg.FakeIPTTL)
				return &ttl
			}
		}
	}
	return nil
}

func queryFamily(q Question) int {
	switch q.Type {
	case 1:
		return 4
	case 28:
		return 6
	default:
		return 0
	}
}

func (c *Controller) dnsRoutes(cfg *Config, rules []Rule, records []Record, q Question) ([]SeenKey, []Route) {
	selected := c.dnsRule(cfg, rules, q)
	if selected != nil {
		family := queryFamily(q)
		for _, t := range selected.Targets {
			if family == 0 && t.Mapping.HasFakeIP() || family != 0 && t.Mapping.FakeIPFor(family) != "" {
				return nil, nil
			}
		}
	}
	names := map[string]struct{}{q.Name: {}}
	for _, rec := range records {
		names[rec.Owner] = struct{}{}
		if !isIP(rec.Value) {
			names[rec.Value] = struct{}{}
		}
	}
	nameList := make([]string, 0, len(names))
	for n := range names {
		nameList = append(nameList, n)
	}
	type trip struct {
		pattern string
		version *int
		mapping Mapping
	}
	var targets []trip
	var claims []trip
	claimed := map[string]struct{}{}
	for _, name := range nameList {
		key := toLowerTrim(name)
		if _, ok := claimed[key]; ok {
			continue
		}
		matched := c.matchingRules(rules, []string{name})
		if len(matched) == 0 {
			continue
		}
		claimed[key] = struct{}{}
		rule := *familyRule(matched, queryFamily(q))
		for _, candidate := range matched {
			for _, t := range candidate.Targets {
				claims = append(claims, trip{candidate.Pattern, t.Version, t.Mapping})
			}
		}
		for _, t := range rule.Targets {
			targets = append(targets, trip{rule.Pattern, t.Version, t.Mapping})
		}
	}
	var extra []SeenKey
	required := map[Route]struct{}{}
	for _, rec := range records {
		if !isIP(rec.Value) {
			continue
		}
		ip, err := netip.ParseAddr(rec.Value)
		if err != nil {
			continue
		}
		family := 4
		if ip.Is6() {
			family = 6
		}
		for _, t := range targets {
			if t.version != nil && *t.version != family {
				continue
			}
			via := t.mapping.ViaFor(family)
			if via == "" {
				continue
			}
			route := Route{t.mapping.FibTable, prefixString(hostPrefix(ip)), via, t.mapping.Interface}
			required[route] = struct{}{}
		}
		for _, t := range claims {
			if t.version != nil && *t.version != family || t.mapping.ViaFor(family) == "" || t.mapping.FakeIPFor(family) != "" {
				continue
			}
			extra = append(extra, SeenKey{Mapping: t.mapping.Key(), Prefix: prefixString(hostPrefix(ip)), Domain: t.pattern, Kind: 3})
		}
	}
	out := make([]Route, 0, len(required))
	for r := range required {
		out = append(out, r)
	}
	return extra, out
}

func (c *Controller) rememberSeen(cfg *Config, extra []SeenKey) (map[SeenKey]int64, error) {
	now := time.Now().Unix()
	idle := cfg.IdleSeconds
	persistAfter := seenPersist
	if idle > 0 && idle < persistAfter {
		persistAfter = idle
	}
	observed := map[SeenKey]struct{}{}
	for _, key := range extra {
		observed[key] = struct{}{}
	}
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	store := currentStore()
	if len(extra) > 0 && store != nil && store.Handles(c.LeasePath) {
		newCount := 0
		for key := range observed {
			if _, ok := c.Seen[key]; !ok {
				newCount++
			}
		}
		if len(c.Seen)+newCount <= cfg.MaxRoutes {
			for key := range observed {
				c.Seen[key] = now
			}
			store.Defer(c.LeasePath, func() any {
				c.cacheLock.Lock()
				defer c.cacheLock.Unlock()
				return EncodeSeen(c.Seen)
			})
			return nil, nil
		}
	}
	current := map[SeenKey]int64{}
	for k, v := range c.Seen {
		current[k] = v
	}
	if idle > 0 {
		for k, ts := range current {
			if _, ok := observed[k]; !ok && now-ts > int64(idle) {
				delete(current, k)
			}
		}
	}
	changed := !seenEqual(current, c.Seen)
	for key := range observed {
		stored, ok := current[key]
		current[key] = now
		if !ok || now-stored >= int64(persistAfter) {
			changed = true
		}
	}
	if len(current) > cfg.MaxRoutes {
		type pair struct {
			ts  int64
			key SeenKey
		}
		var overflow []pair
		for k, ts := range current {
			if _, ok := observed[k]; !ok {
				overflow = append(overflow, pair{ts, k})
			}
		}
		sort.Slice(overflow, func(i, j int) bool {
			if overflow[i].ts != overflow[j].ts {
				return overflow[i].ts < overflow[j].ts
			}
			return overflow[i].key.less(overflow[j].key)
		})
		drop := len(current) - cfg.MaxRoutes
		for i := 0; i < drop && i < len(overflow); i++ {
			delete(current, overflow[i].key)
			changed = true
		}
		if len(current) > cfg.MaxRoutes {
			return nil, fmt.Errorf("desired route limit exceeded")
		}
	}
	if changed {
		if store != nil && store.Handles(c.LeasePath) {
			store.Defer(c.LeasePath, func() any {
				c.cacheLock.Lock()
				defer c.cacheLock.Unlock()
				return EncodeSeen(c.Seen)
			})
		} else if err := AtomicJSON(c.LeasePath, EncodeSeen(current)); err != nil {
			return nil, err
		}
	}
	c.Seen = current
	cp := map[SeenKey]int64{}
	for k, v := range current {
		cp[k] = v
	}
	return cp, nil
}

func (c *Controller) extraPrefixes(cfg *Config) map[MappingKey]map[string]struct{} {
	extra := map[MappingKey]map[string]struct{}{}
	for k, prefixes := range cfg.StaticPrefixes {
		set := map[string]struct{}{}
		for p := range prefixes {
			set[p] = struct{}{}
		}
		extra[k] = set
	}
	seen, _ := c.rememberSeen(cfg, nil)
	if seen == nil {
		c.cacheLock.Lock()
		seen = map[SeenKey]int64{}
		for k, v := range c.Seen {
			seen[k] = v
		}
		c.cacheLock.Unlock()
	}
	for key := range seen {
		set := extra[key.Mapping]
		if set == nil {
			set = map[string]struct{}{}
			extra[key.Mapping] = set
		}
		set[key.Prefix] = struct{}{}
	}
	return extra
}

func (c *Controller) interfaceLocks(cfg *Config) (func(), error) {
	return sharedLockFiles(cfg.LockFiles)
}

func (c *Controller) interfaceLocksContext(ctx context.Context, cfg *Config) (func(), error) {
	return sharedLockFilesContext(ctx, cfg.LockFiles)
}

func (c *Controller) epochValid(generation string, stamp [][2]any) bool {
	if c.verifiedGen != "" && c.verifiedGen != generation {
		return false
	}
	if c.lockEpoch != nil && !epochEqual(c.lockEpoch, stamp) {
		return false
	}
	return true
}

func epochEqual(a, b [][2]any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *Controller) lockStamp(cfg *Config) [][2]any {
	names := append([]string{}, cfg.LockFiles...)
	sort.Strings(names)
	var stamps [][2]any
	seen := map[string]struct{}{}
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		info, err := os.Stat(name)
		mtime := 0.0
		if err == nil {
			mtime = float64(info.ModTime().UnixNano()) / 1e9
		}
		stamps = append(stamps, [2]any{name, mtime})
	}
	return stamps
}

func (c *Controller) mark(routes []Route, generation string) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	if c.verifiedGen != "" && c.verifiedGen != generation {
		c.verified = map[RouteKey]Route{}
	}
	c.verifiedGen = generation
	for _, route := range routes {
		c.verified[route.Key()] = route
	}
}

func (c *Controller) dropStale(generation string, owned []Route) {
	keep := map[RouteKey]Route{}
	for _, r := range owned {
		keep[r.Key()] = r
	}
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	if c.verifiedGen != "" && c.verifiedGen != generation {
		c.verified = map[RouteKey]Route{}
	} else {
		next := map[RouteKey]Route{}
		for key, route := range c.verified {
			if keep[key] == route {
				next[key] = route
			}
		}
		for k, r := range keep {
			next[k] = r
		}
		c.verified = next
	}
	c.verifiedGen = generation
}

func (c *Controller) excluded(cfg *Config, routes []Route) []Route {
	var out []Route
	for _, route := range routes {
		if prefixExcluded(cfg, route.PrefixNet()) {
			out = append(out, route)
		}
	}
	return out
}

func (c *Controller) forget(routes []Route) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	for _, route := range routes {
		if c.verified[route.Key()] == route {
			delete(c.verified, route.Key())
		}
	}
}

func (c *Controller) ensure(ctx context.Context, cfg *Config, backend Backend, routes []Route) error {
	desired := map[RouteKey]Route{}
	for _, route := range routes {
		if existing, ok := desired[route.Key()]; ok && existing != route {
			return fmt.Errorf("conflicting mappings for %s; refusing partial reconciliation", route.Prefix)
		}
		desired[route.Key()] = route
	}
	remaining := sortedRouteValues(desired)
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(remaining) == 0 {
			return nil
		}
		var lead []Route
		var waitFor []chan struct{}
		c.flightLock.Lock()
		for _, route := range remaining {
			ev, ok := c.inFlight[route.Key()]
			if !ok {
				ev = make(chan struct{})
				c.inFlight[route.Key()] = ev
				lead = append(lead, route)
			}
			waitFor = append(waitFor, ev)
		}
		c.flightLock.Unlock()
		var applyErr error
		if len(lead) > 0 {
			unlock, err := c.interfaceLocksContext(ctx, cfg)
			if err != nil {
				applyErr = err
			} else if err := ctx.Err(); err != nil {
				unlock()
				applyErr = err
			} else {
				_, applyErr = EnsureRoutes(cfg, backend, lead, &c.mutex)
				unlock()
			}
			if applyErr == nil {
				gen, err := backend.Generation()
				if err != nil {
					applyErr = err
				} else {
					c.mark(lead, gen)
				}
			}
			c.flightLock.Lock()
			for _, route := range lead {
				ch := c.inFlight[route.Key()]
				delete(c.inFlight, route.Key())
				close(ch)
			}
			c.flightLock.Unlock()
		}
		for _, ch := range waitFor {
			select {
			case <-ch:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if applyErr != nil {
			return applyErr
		}
		c.cacheLock.Lock()
		var next []Route
		for _, route := range remaining {
			if c.verified[route.Key()] != route {
				next = append(next, route)
			}
		}
		c.cacheLock.Unlock()
		remaining = next
		if len(remaining) == 0 {
			return nil
		}
	}
	return fmt.Errorf("DNS route barrier rejected an excluded or conflicting route")
}

func (c *Controller) Reconcile(ctx context.Context, records []Record, q *Question, forceAudit bool) error {
	c.reloadLock.RLock()
	defer c.reloadLock.RUnlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg, rules := c.loaded()
	var recErr error
	if cfg.OverlapPolicy == "first" {
		if records != nil && !forceAudit {
			extra, required := c.dnsRoutes(cfg, rules, records, *q)
			recErr = c.reconcile(ctx, records, q, forceAudit, extra, required, true)
		} else {
			c.orderedLock.Lock()
			recErr = c.reconcile(ctx, records, q, forceAudit, nil, nil, false)
			c.orderedLock.Unlock()
		}
	} else {
		recErr = c.reconcile(ctx, records, q, forceAudit, nil, nil, false)
	}
	if recErr != nil {
		if records != nil {
			c.cacheLock.Lock()
			c.installFail++
			c.cacheLock.Unlock()
		}
		return recErr
	}
	return nil
}

func (c *Controller) reconcile(ctx context.Context, records []Record, q *Question, forceAudit bool, extra []SeenKey, required []Route, prepared bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cfg, rules := c.loaded()
	if records != nil {
		if !prepared {
			extra, required = c.dnsRoutes(cfg, rules, records, *q)
		}
		if exit := c.answerExitMissing(cfg, rules, *q, required); exit != "" {
			return fmt.Errorf("exit %s is missing from VPP", exit)
		}
		if len(required) == 0 {
			return nil
		}
	}
	var orderedRequired []Route
	if len(required) > 0 && cfg.OverlapPolicy == "first" {
		if len(c.excluded(cfg, required)) > 0 {
			return fmt.Errorf("DNS route barrier rejected an excluded route")
		}
		backend := withBackendContext(c.BackendFactory(cfg), ctx)
		if !forceAudit {
			release, err := c.PrefixLocks.HoldContext(ctx, keysOf(required))
			if err != nil {
				return err
			}
			defer release()
			if _, err := c.rememberSeen(cfg, extra); err != nil {
				return err
			}
			unlock, err := c.interfaceLocksContext(ctx, cfg)
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				unlock()
				return err
			}
			result, err := EnsureRoutes(cfg, backend, required, &c.mutex)
			unlock()
			if err != nil {
				return err
			}
			gen, err := backend.Generation()
			if err != nil {
				return err
			}
			c.mark(result.Winners, gen)
			return nil
		}
		orderedRequired = append([]Route{}, required...)
		if _, err := c.rememberSeen(cfg, extra); err != nil {
			return err
		}
		required = nil
	}
	if len(required) > 0 {
		blocked := c.excluded(cfg, required)
		if len(blocked) > 0 {
			c.forget(blocked)
			return fmt.Errorf("DNS route barrier rejected an excluded or conflicting route")
		}
		release, err := c.PrefixLocks.HoldContext(ctx, keysOf(required))
		if err != nil {
			return err
		}
		defer release()
		if _, err := c.rememberSeen(cfg, extra); err != nil {
			return err
		}
		backend := withBackendContext(c.BackendFactory(cfg), ctx)
		generation, err := backend.Generation()
		if err != nil {
			return err
		}
		stamp := c.lockStamp(cfg)
		c.cacheLock.Lock()
		if !c.epochValid(generation, stamp) {
			c.verified = map[RouteKey]Route{}
		}
		c.verifiedGen = generation
		c.lockEpoch = stamp
		c.cacheLock.Unlock()
		sortRoutes(required)
		if err := c.ensure(ctx, cfg, backend, required); err != nil {
			return err
		}
		return nil
	}
	backend := withBackendContext(c.BackendFactory(cfg), ctx)
	generation, err := backend.Generation()
	if err != nil {
		return err
	}
	stamp := c.lockStamp(cfg)
	c.cacheLock.Lock()
	changedEpoch := !c.epochValid(generation, stamp)
	if changedEpoch {
		c.verified = map[RouteKey]Route{}
	}
	c.verifiedGen = generation
	c.lockEpoch = stamp
	c.cacheLock.Unlock()
	extraSets := c.extraPrefixes(cfg)
	c.cacheLock.Lock()
	failureRevision := c.installFail
	c.cacheLock.Unlock()
	sig := makeBgSig(generation, stamp, failureRevision, extraSets)
	previous := c.backgroundSig
	if !forceAudit && previous.generation != "" && backgroundPrefix(previous, sig) {
		if usesTProxy(cfg) || hasLinuxExits(cfg) {
			unlock, err := c.interfaceLocksContext(ctx, cfg)
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				unlock()
				return err
			}
			err = backend.SyncTProxy()
			unlock()
			if err != nil {
				return err
			}
		}
		gen, err := backend.Generation()
		if err != nil {
			return err
		}
		if gen != generation {
			return fmt.Errorf("VPP restarted at DNS route barrier")
		}
		c.backgroundSig = sig
		return nil
	}
	audit := forceAudit
	preparedSync, err := PrepareSync(cfg, backend, false, &audit)
	if err != nil {
		return err
	}
	c.noteMissingExits(preparedSync.MissingExits)
	syncDrops(cfg, backend, generation, desiredDrops(cfg, extraSets))
	if len(preparedSync.Orphans) > 0 {
		lines := make([]string, 0, len(preparedSync.Orphans))
		for _, route := range preparedSync.Orphans {
			lines = append(lines, route.Command("del"))
		}
		if err := backend.Apply(lines); err != nil {
			return err
		}
	}
	forget := func(keys []RouteKey) {
		c.cacheLock.Lock()
		defer c.cacheLock.Unlock()
		for _, key := range keys {
			delete(c.verified, key)
		}
	}
	unlock, err := c.interfaceLocksContext(ctx, cfg)
	if err != nil {
		return err
	}
	_, err = CommitSync(cfg, backend, preparedSync, extraSets, &c.mutex, c.PrefixLocks, func() map[MappingKey]map[string]struct{} {
		return c.extraPrefixes(cfg)
	}, forget, forceAudit)
	unlock()
	if err != nil {
		return err
	}
	gen, err := backend.Generation()
	if err != nil {
		return err
	}
	if gen != generation {
		return fmt.Errorf("VPP restarted at DNS route barrier")
	}
	raw := ReadJSON(cfg.StateFile, map[string]any{})
	state, _ := raw.(map[string]any)
	var owned []Route
	if state != nil {
		if g, _ := state["generation"].(string); g == generation {
			if arr, ok := state["owned"].([]any); ok {
				for _, item := range arr {
					if r, ok := routeFromJSON(item); ok {
						owned = append(owned, r)
					}
				}
			}
		}
	}
	c.dropStale(generation, owned)
	c.backgroundSig = sig
	if len(orderedRequired) > 0 {
		prefixSets := map[MappingKey]map[string]struct{}{}
		for k, prefixes := range extraSets {
			set := prefixSets[k]
			if set == nil {
				set = map[string]struct{}{}
				prefixSets[k] = set
			}
			for p := range prefixes {
				set[p] = struct{}{}
			}
		}
		desired, _, err := collectDesired(preparedSync.Mappings, prefixSets, preparedSync.Protected, preparedSync.Exclusions, "first")
		if err != nil {
			return err
		}
		winners, err := coveringRoutes(desired, orderedRequired)
		if err != nil {
			return err
		}
		live, err := backend.Lookup(winners)
		if err != nil {
			return err
		}
		gen, err := backend.Generation()
		if err != nil {
			return err
		}
		if gen != generation {
			return fmt.Errorf("ordered DNS route verification failed")
		}
		for _, route := range winners {
			if !Matches(route, live) {
				return fmt.Errorf("ordered DNS route verification failed")
			}
		}
	}
	return nil
}

// answerExitMissing names a missing exit this answer depends on. Such a query fails rather
// than sending the client somewhere the rule did not mean; every other rule is unaffected.
// Fake-IP answers need no route of their own, so their exit is looked at separately.
func (c *Controller) answerExitMissing(cfg *Config, rules []Rule, q Question, required []Route) string {
	c.cacheLock.Lock()
	exits := c.missingExits // replaced whole, never changed in place
	c.cacheLock.Unlock()
	if len(exits) == 0 {
		return ""
	}
	for _, route := range required {
		if exits[route.Interface] {
			return route.Interface
		}
	}
	if selected := c.dnsRule(cfg, rules, q); selected != nil {
		family := queryFamily(q)
		for _, t := range selected.Targets {
			if (family == 0 && t.Mapping.HasFakeIP() || family != 0 && t.Mapping.FakeIPFor(family) != "") && exits[t.Mapping.Interface] {
				return t.Mapping.Interface
			}
		}
	}
	return ""
}

func (c *Controller) noteMissingExits(missing map[string]bool) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	for name := range missing {
		if !c.missingExits[name] {
			log.Printf("exit %s is missing from VPP: its routes and DNS are off until it appears", name)
		}
	}
	for name := range c.missingExits {
		if !missing[name] {
			log.Printf("exit %s is back in VPP", name)
		}
	}
	c.missingExits = missing
}

// exitsChanged asks VPP whether a full sync would now see different exits. It also says
// whether any are missing, so that the caller can look again soon.
func (c *Controller) exitsChanged(ctx context.Context) (changed, anyMissing bool, err error) {
	cfg, _ := c.loaded()
	missing, err := withBackendContext(c.BackendFactory(cfg), ctx).MissingInterfaces(mappingInterfaces(cfg))
	if err != nil {
		return false, false, err
	}
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	changed = len(missing) != len(c.missingExits)
	for name := range missing {
		changed = changed || !c.missingExits[name]
	}
	return changed, len(missing) > 0, nil
}

type bgSig struct {
	generation string
	stamp      [][2]any
	fail       int
	extra      map[MappingKey]map[string]struct{}
}

func makeBgSig(generation string, stamp [][2]any, fail int, extra map[MappingKey]map[string]struct{}) bgSig {
	copied := map[MappingKey]map[string]struct{}{}
	for k, prefixes := range extra {
		set := map[string]struct{}{}
		for p := range prefixes {
			set[p] = struct{}{}
		}
		copied[k] = set
	}
	stampCopy := append([][2]any{}, stamp...)
	return bgSig{generation, stampCopy, fail, copied}
}

func backgroundPrefix(prev, sig bgSig) bool {
	if prev.generation != sig.generation || prev.fail != sig.fail {
		return false
	}
	if !epochEqual(prev.stamp, sig.stamp) {
		return false
	}
	for key, prefixes := range prev.extra {
		have := sig.extra[key]
		for p := range prefixes {
			if _, ok := have[p]; !ok {
				return false
			}
		}
	}
	return true
}

func (c *Controller) Config() *Config {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	return c.config
}

func (c *Controller) InFlightHas(key RouteKey) bool {
	c.flightLock.Lock()
	defer c.flightLock.Unlock()
	_, ok := c.inFlight[key]
	return ok
}

func (c *Controller) VerifiedHas(key RouteKey) bool {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	_, ok := c.verified[key]
	return ok
}
