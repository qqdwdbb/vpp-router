package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type harness struct {
	dir        string
	configPath string
	routesPath string
	leasePath  string
	backend    *FakeBackend
	controller *Controller
}

func writeJSON(t testing.TB, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	writeJSON(t, configPath, map[string]any{
		"state_file":       filepath.Join(dir, "state.json"),
		"lock_files":       []any{},
		"exclude_prefixes": []any{"10.64.20.3/32"},
	})
	routesPath := filepath.Join(dir, "routes.json")
	writeJSON(t, routesPath, map[string]any{"routes": []any{altroute("routing.example.net")}})
	leasePath := filepath.Join(dir, "leases.json")
	backend := NewFakeBackend()
	c, err := NewController(configPath, leasePath, func(*Config) Backend { return backend }, routesPath)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{dir, configPath, routesPath, leasePath, backend, c}
}

func altroute(domains ...any) map[string]any {
	return map[string]any{"name": "altroute", "interface": "wg1", "via": "10.62.30.1", "domains": domains}
}

func proxylist(domains ...any) map[string]any {
	return map[string]any{"name": "proxylist", "interface": "loop200", "via": "10.61.20.2", "domains": domains}
}

// writeRoutes replaces the route list and restarts on it.
func (h *harness) writeRoutes(t testing.TB, routes ...any) {
	t.Helper()
	writeJSON(t, h.routesPath, map[string]any{"routes": routes})
	h.restart(t)
}

// tryRestart stops Gate cleanly and starts it again on the files as they are now.
func (h *harness) tryRestart() error {
	if err := AtomicJSON(h.leasePath, EncodeSeen(h.controller.Seen)); err != nil {
		return err
	}
	c, err := NewController(h.controller.ConfigPath, h.leasePath, func(*Config) Backend { return h.backend }, h.controller.DomainRoutesPath)
	if err != nil {
		return err
	}
	h.controller = c
	return nil
}

func (h *harness) restart(t testing.TB) {
	t.Helper()
	if err := h.tryRestart(); err != nil {
		t.Fatal(err)
	}
}

// rangeFile writes an ip_range_files list and returns its path.
func (h *harness) rangeFile(t testing.TB, name, text string) string {
	t.Helper()
	path := filepath.Join(h.dir, name)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (h *harness) question() Question { return Question{"www.routing.example.net", 1, 1} }
func (h *harness) records() []Record {
	return []Record{{"www.routing.example.net", "198.51.100.77", 60}}
}

func (h *harness) reconcileDNS(t testing.TB) {
	t.Helper()
	q := h.question()
	if err := h.controller.Reconcile(context.Background(), h.records(), &q, false); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) reconcile(t testing.TB) {
	t.Helper()
	if err := h.controller.Reconcile(context.Background(), nil, nil, false); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) ordered(t testing.TB) {
	t.Helper()
	raw, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	config["overlap_policy"] = "first"
	writeJSON(t, h.configPath, config)
	writeJSON(t, h.routesPath, map[string]any{"routes": []any{altroute("routing.example.net"), proxylist("routing.example.net")}})
	c, err := NewController(h.configPath, h.leasePath, func(*Config) Backend { return h.backend }, h.routesPath)
	if err != nil {
		t.Fatal(err)
	}
	h.controller = c
}

func pathEquals(t *testing.T, b *FakeBackend, prefix, via, iface string) {
	t.Helper()
	p, ok := b.RoutePath(0, prefix)
	if !ok || p.Via != via || p.Interface != iface {
		t.Fatalf("%s: got %v present=%v, want %s %s", prefix, p, ok, via, iface)
	}
}

func TestIPRangeMembersAreRoutedAndRestored(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	alt := altroute("routing.example.net")
	alt["ip_range_files"] = []any{h.rangeFile(t, "alt.ranges", "203.0.113.1\n")}
	proxy := proxylist("routing.example.net")
	proxy["ip_range_files"] = []any{h.rangeFile(t, "proxy.ranges", "198.51.100.0-198.51.100.3\n")}
	h.writeRoutes(t, alt, proxy)
	if err := h.controller.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	pathEquals(t, h.backend, "203.0.113.1/32", "10.62.30.1", "wg1")
	pathEquals(t, h.backend, "198.51.100.0/30", "10.61.20.2", "loop200")
	h.backend.Live = map[RouteKey]PathSet{}
	h.backend.Instance = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	h.restart(t)
	if err := h.controller.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "203.0.113.1/32") {
		t.Fatal("range member not restored")
	}
	h.rangeFile(t, "alt.ranges", "")
	h.restart(t)
	if err := h.controller.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if h.backend.HasRoute(0, "203.0.113.1/32") {
		t.Fatal("removed range member still routed")
	}
}

// Switching a rule's exit restarts Gate, whose first reconciliation moves what it owns.
func TestIPRangeFollowsItsRuleToAnotherExit(t *testing.T) {
	h := newHarness(t)
	ranges := []any{h.rangeFile(t, "alt.ranges", "203.0.113.0/24\n")}
	h.writeRoutes(t, map[string]any{"name": "altroute", "interface": "wg1", "via": "10.62.30.1", "ip_range_files": ranges})
	h.reconcile(t)
	pathEquals(t, h.backend, "203.0.113.0/24", "10.62.30.1", "wg1")
	h.writeRoutes(t, map[string]any{"name": "altroute", "interface": "loop200", "via": "10.61.20.2", "ip_range_files": ranges})
	h.reconcile(t)
	pathEquals(t, h.backend, "203.0.113.0/24", "10.61.20.2", "loop200")
	if paths := h.backend.Live[RouteKey{0, "203.0.113.0/24"}]; len(paths) != 1 {
		t.Fatalf("the old path stayed: %v", paths)
	}
}

func TestStaticPriorityAppliesToFirstDNSAnswer(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	alt := map[string]any{"name": "altroute", "interface": "wg1", "via": "10.62.30.1",
		"ip_range_files": []any{h.rangeFile(t, "alt.ranges", "198.51.100.64/26\n")}}
	h.writeRoutes(t, alt, proxylist("routing.example.net"))
	q := h.question()
	if err := h.controller.Reconcile(context.Background(), h.records(), &q, false); err != nil {
		t.Fatal(err)
	}
	pathEquals(t, h.backend, "198.51.100.64/26", "10.62.30.1", "wg1")
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("host route installed under covering static prefix")
	}
}

func TestFakeIPRangeFilesAreInstalled(t *testing.T) {
	h := newHarness(t)
	ranges4 := filepath.Join(h.dir, "fakeip.ipv4")
	ranges6 := filepath.Join(h.dir, "fakeip.ipv6")
	if err := os.WriteFile(ranges4, []byte("198.18.0.0/15\n203.0.113.0/24\n203.0.114.1-203.0.114.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ranges6, []byte("2001:2::/48\n2001:db8:10::/48\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.dir, "domain-routes.json")
	writeJSON(t, path, map[string]any{"routes": []any{
		map[string]any{"name": "proxy", "interface": "tap2490",
			"via":     []any{"10.63.30.2", "fd42:1111:2222:30::2"},
			"domains": []any{"plist.example"}, "ip_range_files": []any{ranges4, ranges6},
			"fakeip_range": []any{"198.18.0.0/15", "2001:2::/48"}, "fake_dns": []any{"127.0.0.1", 5354}},
	}})
	raw, _ := os.ReadFile(h.configPath)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	config["overlap_policy"] = "first"
	config["dns_upstream_policy"] = "first"
	writeJSON(t, h.configPath, config)
	c, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	h.controller = c
	h.reconcile(t)
	pathEquals(t, h.backend, "198.18.0.0/15", "10.63.30.2", "tap2490")
	pathEquals(t, h.backend, "203.0.113.0/24", "10.63.30.2", "tap2490")
	pathEquals(t, h.backend, "203.0.114.1/32", "10.63.30.2", "tap2490")
	pathEquals(t, h.backend, "2001:2::/48", "fd42:1111:2222:30::2", "tap2490")
	pathEquals(t, h.backend, "2001:db8:10::/48", "fd42:1111:2222:30::2", "tap2490")
}

func TestUnusableIPRangesAreRefusedBySyncAndIgnoredByGate(t *testing.T) {
	for name, line := range map[string]string{"wrong family": "2001:db8::/32\n", "default route": "0.0.0.0/0\n"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			ranges := filepath.Join(h.dir, "bad.ranges")
			path := filepath.Join(h.dir, "domain-routes.json")
			writeJSON(t, path, map[string]any{"routes": []any{map[string]any{
				"name": "bad", "interface": "tap2490", "via": "10.63.30.2",
				"domains": []any{"bad.example"}, "ip_range_files": []any{ranges},
			}}})
			if err := os.WriteFile(ranges, []byte(line), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := DomainRoutesFromFile(path, &Config{}); err == nil {
				t.Fatal("a sync would accept it")
			}
			c, err := NewController(h.configPath, h.leasePath, func(*Config) Backend { return h.backend }, path)
			if err != nil {
				t.Fatalf("it stopped Gate: %v", err)
			}
			cfg, rules := c.loaded()
			if len(rules) != 1 || rules[0].Pattern != "bad.example" {
				t.Fatalf("the rest of the rule is gone: %+v", rules)
			}
			for _, prefixes := range cfg.StaticPrefixes {
				if len(prefixes) != 0 {
					t.Fatalf("installed %v", prefixes)
				}
			}
		})
	}
}

func TestOrderedDNSInstallSkipsFIBDump(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	h.reconcileDNS(t)
	if h.backend.Snapshots != 0 {
		t.Fatalf("snapshots %d", h.backend.Snapshots)
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("missing host route")
	}
}

func TestDNSPathDoesNotFullSync(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	if h.backend.Snapshots != 0 || h.backend.LookupCount() != 0 {
		t.Fatalf("dns path queried fib snap=%d lookups=%d", h.backend.Snapshots, h.backend.LookupCount())
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("missing dns route")
	}
}

func TestConflictOverwritesWithoutLookup(t *testing.T) {
	h := newHarness(t)
	h.backend.Live[RouteKey{0, "198.51.100.77/32"}] = pathSetOf("10.61.20.1", "host-vpp-wan")
	h.reconcileDNS(t)
	if h.backend.LookupCount() != 0 {
		t.Fatal("dns path looked up fib")
	}
	pathEquals(t, h.backend, "198.51.100.77/32", "10.62.30.1", "wg1")
}

func TestEndpointIsNotAcknowledged(t *testing.T) {
	h := newHarness(t)
	q := h.question()
	err := h.controller.Reconcile(context.Background(), []Record{{"www.routing.example.net", "10.64.20.3", 60}}, &q, false)
	if err == nil {
		t.Fatal("excluded endpoint was acknowledged")
	}
}

func TestUnselectedDomainDoesNotChangeRoutes(t *testing.T) {
	h := newHarness(t)
	q := Question{"example.org", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"example.org", "198.51.100.77", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	if h.backend.BatchCount() != 0 {
		t.Fatal("unselected domain installed routes")
	}
}

func TestCNAMETargetMatchesMapping(t *testing.T) {
	h := newHarness(t)
	q := Question{"outside.test", 1, 1}
	recs := []Record{{"outside.test", "www.routing.example.net", 60}, {"www.routing.example.net", "198.51.100.77", 60}}
	if err := h.controller.Reconcile(context.Background(), recs, &q, false); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("cname target was not routed")
	}
}

func TestRestartKeepsClientCacheLease(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	other, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, h.routesPath)
	if err != nil {
		t.Fatal(err)
	}
	h.backend.Live = map[RouteKey]PathSet{}
	h.backend.Instance = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := other.Reconcile(context.Background(), nil, nil, false); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("lease was not restored after restart")
	}
}

func TestCacheHitWithoutNftMembershipAndExpiry(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("missing route")
	}
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("background dropped live lease")
	}
	h.controller.cacheLock.Lock()
	for k := range h.controller.Seen {
		h.controller.Seen[k] = time.Now().Unix() - 8*24*3600
	}
	h.controller.cacheLock.Unlock()
	h.reconcile(t)
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("idle lease was not withdrawn")
	}
}

func TestBackgroundDoesNotAuditFIB(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	h.reconcile(t)
	if h.backend.Snapshots != 0 {
		t.Fatalf("snapshots %d", h.backend.Snapshots)
	}
	h.reconcile(t)
	if h.backend.Snapshots != 0 || h.backend.LookupCount() != 0 {
		t.Fatal("background audited fib")
	}
	h.controller.cacheLock.Lock()
	for k := range h.controller.Seen {
		h.controller.Seen[k] = time.Now().Unix() - 8*24*3600
	}
	h.controller.cacheLock.Unlock()
	h.reconcile(t)
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("expired lease still live")
	}
	if h.backend.Snapshots != 0 {
		t.Fatal("expiry used fib dump")
	}
}

func TestIdleZeroKeepsUnobservedRoute(t *testing.T) {
	h := newHarness(t)
	raw, _ := os.ReadFile(h.configPath)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	config["idle_seconds"] = 0
	writeJSON(t, h.configPath, config)
	h.restart(t)
	h.reconcileDNS(t)
	h.controller.cacheLock.Lock()
	for k := range h.controller.Seen {
		h.controller.Seen[k] = time.Now().Unix() - 90*24*3600
	}
	h.controller.cacheLock.Unlock()
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("idle_seconds=0 dropped unobserved route")
	}
}

func TestGenerationChangeReinstalls(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	h.backend.Live = map[RouteKey]PathSet{}
	h.backend.Instance = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	h.reconcileDNS(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("route not reinstalled after generation change")
	}
}

func TestExcludePrefixesChangeRejectsCachedIP(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	raw, _ := os.ReadFile(h.configPath)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	config["exclude_prefixes"] = []any{"198.51.100.0/24"}
	writeJSON(t, h.configPath, config)
	h.restart(t)
	q := h.question()
	if err := h.controller.Reconcile(context.Background(), h.records(), &q, false); err == nil {
		t.Fatal("excluded prefix was acknowledged")
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("live route was withdrawn on reject")
	}
	if h.controller.VerifiedHas(RouteKey{0, "198.51.100.77/32"}) {
		t.Fatal("verified cache kept excluded route")
	}
}

func TestNewLeasePersistedAndRepeatSkipsRewrite(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	data, err := os.ReadFile(h.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []map[string]any
	if err := json.Unmarshal(data, &onDisk); err != nil || len(onDisk) == 0 {
		t.Fatalf("lease %s: %v", data, err)
	}
	if onDisk[0]["prefix"] != "198.51.100.77/32" {
		t.Fatalf("prefix %v", onDisk[0]["prefix"])
	}
	if _, ok := onDisk[0]["seen"].(float64); !ok {
		t.Fatalf("seen %T", onDisk[0]["seen"])
	}
	mtime := ageFile(t, h.leasePath)
	h.reconcileDNS(t)
	h.reconcileDNS(t)
	if fileMod(t, h.leasePath) != mtime {
		t.Fatal("repeat query rewrote lease")
	}
}

// ageFile backdates a file, so that a rewrite shows even within one tick of the
// kernel's file timestamps, which is longer than these tests take.
func ageFile(t *testing.T, path string) int64 {
	t.Helper()
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return fileMod(t, path)
}

func fileMod(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.ModTime().UnixNano()
}

func TestLastSeenRewrittenAfterPersistInterval(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	h.controller.cacheLock.Lock()
	var key SeenKey
	for k := range h.controller.Seen {
		key = k
		h.controller.Seen[k] = time.Now().Unix() - 61
	}
	h.controller.cacheLock.Unlock()
	before := ageFile(t, h.leasePath)
	h.reconcileDNS(t)
	if fileMod(t, h.leasePath) == before {
		t.Fatal("lease was not rewritten after persist interval")
	}
	h.controller.cacheLock.Lock()
	if h.controller.Seen[key] < time.Now().Unix()-5 {
		t.Fatal("seen timestamp not refreshed")
	}
	h.controller.cacheLock.Unlock()
}

func TestLeaseUpdatesStayInMemoryUntilStop(t *testing.T) {
	h := newHarness(t)
	var before []byte
	if data, err := os.ReadFile(h.leasePath); err == nil {
		before = data
	}
	store := NewDeferredState([]string{h.leasePath})
	store.Enter()
	h.reconcileDNS(t)
	var after []byte
	if data, err := os.ReadFile(h.leasePath); err == nil {
		after = data
	}
	if string(after) != string(before) {
		t.Fatal("lease was written before stop")
	}
	raw := ReadJSON(h.leasePath, []any{})
	if raw == nil {
		t.Fatal("in-memory lease missing")
	}
	store.Exit()
	if _, err := os.Stat(h.leasePath); err != nil {
		t.Fatal("lease not flushed on stop")
	}
}

func TestEveryDNSAnswerRestoresDeletedRoute(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		h := newHarness(t)
		if ordered {
			h.ordered(t)
		}
		h.reconcileDNS(t)
		h.backend.Live = map[RouteKey]PathSet{}
		batches := h.backend.BatchCount()
		h.reconcileDNS(t)
		if h.backend.BatchCount() != batches+1 {
			t.Fatalf("ordered=%v batches %d -> %d", ordered, batches, h.backend.BatchCount())
		}
		if !h.backend.HasRoute(0, "198.51.100.77/32") {
			t.Fatal("deleted route not restored")
		}
		if h.backend.Snapshots != 0 || h.backend.LookupCount() != 0 {
			t.Fatal("restore used fib")
		}
		h.backend.FailNext(0)
		q := h.question()
		if err := h.controller.Reconcile(context.Background(), h.records(), &q, false); err == nil {
			t.Fatal("failed apply succeeded")
		}
	}
}

func TestFrozenRulesReadOnce(t *testing.T) {
	h := newHarness(t)
	start := func() *Controller {
		c, err := NewController(h.configPath, h.leasePath,
			func(*Config) Backend { return h.backend }, h.routesPath)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := start()
	h.writeRoutes(t, altroute("example.org"))
	_, rules := first.loaded()
	if len(first.matchingRules(rules, []string{"www.routing.example.net"})) == 0 {
		t.Fatal("frozen controller lost original rules")
	}
	if len(first.matchingRules(rules, []string{"example.org"})) != 0 {
		t.Fatal("frozen controller picked up new rules")
	}
	restarted := start()
	_, rules = restarted.loaded()
	if len(restarted.matchingRules(rules, []string{"www.routing.example.net"})) != 0 {
		t.Fatal("restarted controller kept old rules")
	}
	if len(restarted.matchingRules(rules, []string{"example.org"})) == 0 {
		t.Fatal("restarted controller missed new rules")
	}
}

func TestRuleIndexMatchesLinearRules(t *testing.T) {
	h := newHarness(t)
	v4 := 4
	rules := []Rule{
		{Pattern: "example.com", Targets: nil, Match: "suffix"},
		{Pattern: "api.example.com", Targets: nil, Match: "suffix"},
		{Pattern: "proxy", Targets: nil, Upstream: &Upstream{"127.0.0.1", 54}, Match: "contains"},
		{Pattern: "example.com", Targets: nil, Upstream: &Upstream{"127.0.0.1", 55}, Match: "suffix"},
	}
	h.controller.index = indexRules(rules)
	cases := [][]string{
		{"WWW.API.EXAMPLE.COM."},
		{"badexample.com"},
		{"proxy.example.com"},
		{"cdn.example.com", "dualstack.proxy.net"},
	}
	for _, names := range cases {
		got := h.controller.matchingRules(rules, names)
		var want []Rule
		for _, rule := range rules {
			for _, name := range names {
				if RuleMatches(name, rule.Pattern, rule.Match) {
					want = append(want, rule)
					break
				}
			}
		}
		if len(got) != len(want) {
			t.Fatalf("names %v: got %d want %d", names, len(got), len(want))
		}
		for i := range got {
			if got[i].Pattern != want[i].Pattern || got[i].Match != want[i].Match {
				t.Fatalf("names %v: got %+v want %+v", names, got, want)
			}
		}
	}
	_ = v4
	replacement := []Rule{{Pattern: "other.net", Match: "suffix"}}
	got := h.controller.matchingRules(replacement, []string{"www.other.net"})
	if len(got) != 1 || got[0].Pattern != "other.net" {
		t.Fatalf("replacement %+v", got)
	}
}

func bumpMtime(t testing.TB, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	next := st.ModTime().Add(time.Second)
	if err := os.Chtimes(path, next, next); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) domainRoutes(t testing.TB, domains []string) (string, map[string]any) {
	t.Helper()
	path := filepath.Join(h.dir, "domain-routes.json")
	if domains == nil {
		domains = []string{"routing.example.net"}
	}
	doms := make([]any, len(domains))
	for i, d := range domains {
		doms[i] = d
	}
	route := map[string]any{"name": "altroute", "interface": "wg1", "via": "10.62.30.1", "domains": doms}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	c, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	h.controller = c
	return path, route
}

func (h *harness) fakeIP(t *testing.T, pools bool) string {
	t.Helper()
	raw, _ := os.ReadFile(h.configPath)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	config["overlap_policy"] = "first"
	config["dns_upstream_policy"] = "first"
	writeJSON(t, h.configPath, config)
	fake := map[string]any{"name": "proxy", "interface": "tap2490",
		"via":     []any{"10.63.30.2", "fd42:1111:2222:30::2"},
		"domains": []any{"example.com"}, "dns": []any{"127.0.0.1", 5354}}
	if pools {
		fake["fake_dns"] = []any{"127.0.0.1", 5354}
		fake["fakeip_range"] = []any{"198.18.0.0/15", "2001:2::/48"}
	}
	routes := []any{
		map[string]any{"name": "real", "interface": "wg1", "via": "10.62.30.1", "domains": []any{"real.example.com"}},
		fake,
	}
	path := filepath.Join(h.dir, "domain-routes.json")
	writeJSON(t, path, map[string]any{"routes": routes})
	c, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	h.controller = c
	return path
}

func TestFakeIPPoolsInstallOnceAndAnswersWriteNoRoutes(t *testing.T) {
	h := newHarness(t)
	h.fakeIP(t, true)
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.18.0.0/15") || !h.backend.HasRoute(0, "2001:2::/48") {
		t.Fatalf("pools missing: %v", h.backend.LiveKeys())
	}
	if len(h.backend.LiveKeys()) != 2 {
		t.Fatalf("unexpected routes %v", h.backend.LiveKeys())
	}
	batches := h.backend.BatchCount()
	for _, tc := range []struct {
		kind uint16
		ip   string
	}{{1, "198.18.0.12"}, {28, "2001:2::12"}, {65, "198.18.0.12"}, {64, "2001:2::12"}} {
		q := Question{"www.example.com", tc.kind, 1}
		up := h.controller.DNSUpstream(q)
		if up == nil || up.Host != "127.0.0.1" || up.Port != 5354 {
			t.Fatalf("upstream %+v", up)
		}
		ttl := h.controller.AnswerTTL(q)
		if ttl != nil {
			t.Fatalf("ttl %+v", ttl)
		}
		for i := 0; i < 3; i++ {
			if err := h.controller.Reconcile(context.Background(), []Record{{"www.example.com", tc.ip, 60}}, &q, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	h.reconcile(t)
	if h.backend.BatchCount() != batches {
		t.Fatal("fake-ip answers wrote routes")
	}
	if len(h.controller.Seen) != 0 {
		t.Fatal("fake-ip answers wrote leases")
	}
}

func TestRealDNSDomainStillInstallsHostRoute(t *testing.T) {
	h := newHarness(t)
	h.fakeIP(t, true)
	h.reconcile(t)
	q := Question{"real.example.com", 1, 1}
	up := h.controller.DNSUpstream(q)
	if up != nil {
		t.Fatalf("unexpected upstream %+v", up)
	}
	ttl := h.controller.AnswerTTL(q)
	if ttl != nil {
		t.Fatalf("unexpected ttl %+v", ttl)
	}
	if err := h.controller.Reconcile(context.Background(), []Record{{"real.example.com", "198.51.100.12", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.12/32") {
		t.Fatal("real domain host route missing")
	}
	if len(h.controller.Seen) == 0 {
		t.Fatal("real domain wrote no lease")
	}
}

func TestFakeIPMigrationRemovesOldHostRoutes(t *testing.T) {
	h := newHarness(t)
	path := h.fakeIP(t, false)
	for _, tc := range []struct {
		name string
		kind uint16
		ip   string
	}{
		{"www.example.com", 1, "198.18.0.12"},
		{"www.example.com", 28, "2001:2::12"},
		{"real.example.com", 1, "198.51.100.12"},
	} {
		q := Question{tc.name, tc.kind, 1}
		if err := h.controller.Reconcile(context.Background(), []Record{{tc.name, tc.ip, 60}}, &q, false); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(path)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	routes := doc["routes"].([]any)
	for _, item := range routes[1:] {
		route := item.(map[string]any)
		route["fakeip_range"] = []any{"198.18.0.0/15", "2001:2::/48"}
	}
	writeJSON(t, path, doc)
	c, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	h.controller = c
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.18.0.0/15") || !h.backend.HasRoute(0, "2001:2::/48") || !h.backend.HasRoute(0, "198.51.100.12/32") {
		t.Fatalf("after migration %v", h.backend.LiveKeys())
	}
	if h.backend.HasRoute(0, "198.18.0.12/32") || h.backend.HasRoute(0, "2001:2::12/128") {
		t.Fatal("old fake-ip host routes survived")
	}
	h.controller.cacheLock.Lock()
	for k := range h.controller.Seen {
		if k.Prefix != "198.51.100.12/32" {
			t.Fatalf("unexpected lease %v", k)
		}
	}
	h.controller.cacheLock.Unlock()
}

func TestDomainListUpdatesRoutes(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	h.reconcileDNS(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("domain list did not install")
	}
	route["domains"] = []any{"example.org"}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	h.restart(t)
	h.reconcile(t)
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("removed domain kept its route")
	}
	q := Question{"example.org", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"example.org", "198.51.100.88", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.88/32") {
		t.Fatal("new domain was not routed")
	}
}

func TestDomainKeywordRoutesAndSelectsUpstream(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "domain-routes.json")
	writeJSON(t, path, map[string]any{"routes": []any{
		map[string]any{"name": "altroute", "interface": "wg1", "via": "10.62.30.1",
			"domain_keywords": []any{"routing"}, "dns_upstream": []any{"127.0.0.1", 5353}},
	}})
	c, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	h.controller = c
	q := h.question()
	up := h.controller.DNSUpstream(q)
	if up == nil || up.Port != 5353 {
		t.Fatalf("upstream %+v", up)
	}
	if err := h.controller.Reconcile(context.Background(), h.records(), &q, false); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("keyword rule did not install")
	}
}

func TestRouteWithoutContentFailsClosed(t *testing.T) {
	h := newHarness(t)
	writeJSON(t, h.routesPath, map[string]any{"routes": []any{altroute()}})
	if err := h.tryRestart(); err == nil {
		t.Fatal("a route without content was loaded")
	}
}

func TestNewControllerNeedsRoutes(t *testing.T) {
	h := newHarness(t)
	_, err := NewController(h.configPath, h.leasePath, func(*Config) Backend { return h.backend }, "")
	if err == nil || !strings.Contains(err.Error(), "routes") {
		t.Fatalf("err %v", err)
	}
}

func TestRecoveryForcesFIBAudit(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	h.reconcile(t)
	h.backend.Live = map[RouteKey]PathSet{}
	snapshots := h.backend.Snapshots
	if err := h.controller.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if h.backend.Snapshots <= snapshots {
		t.Fatal("force_audit did not dump fib")
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("audit did not restore route")
	}
}

func TestFakeIPPoolInstallFailureRetries(t *testing.T) {
	h := newHarness(t)
	h.fakeIP(t, true)
	h.backend.FailNext(0)
	if err := h.controller.Reconcile(context.Background(), nil, nil, false); err == nil {
		t.Fatal("failed pool install succeeded")
	}
	if len(h.backend.LiveKeys()) != 0 {
		t.Fatal("partial pool install leaked")
	}
	h.reconcile(t)
	h.backend.Instance = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	h.backend.Live = map[RouteKey]PathSet{}
	h.reconcile(t)
	q := Question{"www.example.com", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"www.example.com", "198.18.0.12", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	if len(h.backend.LiveKeys()) != 2 {
		t.Fatalf("pools %v", h.backend.LiveKeys())
	}
}

func TestSamePrefixQueriesWaitForSuccessfulAdd(t *testing.T) {
	h := newHarness(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.backend.ApplyFn = func(lines []string) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-time.After(2 * time.Second):
			return fmt.Errorf("test timed out")
		}
		return h.backend.DoApply(lines)
	}
	errCh := make(chan error, 2)
	worker := func() {
		q := h.question()
		errCh <- h.controller.Reconcile(context.Background(), h.records(), &q, false)
	}
	go worker()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first apply did not start")
	}
	go worker()
	deadline := time.Now().Add(2 * time.Second)
	seen := false
	for time.Now().Before(deadline) {
		if h.controller.InFlightHas(RouteKey{0, "198.51.100.77/32"}) {
			seen = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !seen {
		t.Fatal("second query did not wait on in-flight add")
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if h.backend.BatchCount() != 2 {
		t.Fatalf("batches %d", h.backend.BatchCount())
	}
}

func TestFakeIPTTLOverrideIsExplicitAndCanBeRemoved(t *testing.T) {
	h := newHarness(t)
	path := h.fakeIP(t, true)
	var doc map[string]any
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []int{300, 0} {
		if ttl == 0 {
			delete(doc, "fakeip_ttl")
		} else {
			doc["fakeip_ttl"] = ttl
		}
		writeJSON(t, path, doc)
		h.restart(t)
		for _, kind := range []uint16{1, 28} {
			got := h.controller.AnswerTTL(Question{"www.example.com", kind, 1})
			if ttl == 0 {
				if got != nil {
					t.Fatalf("default override = %v", *got)
				}
			} else if got == nil || *got != uint32(ttl) {
				t.Fatalf("override = %v", got)
			}
			if got := h.controller.AnswerTTL(Question{"real.example.com", kind, 1}); got != nil {
				t.Fatal("real DNS answer got Fake-IP override")
			}
		}
	}
}
