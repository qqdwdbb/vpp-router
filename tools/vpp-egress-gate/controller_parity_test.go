package gate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOrderedCachedDNSDoesNotReadFIB(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	h.reconcileDNS(t)
	snapshots := h.backend.Snapshots
	h.reconcileDNS(t)
	if h.backend.Snapshots != snapshots {
		t.Fatal("cached ordered DNS read fib")
	}
	if err := h.controller.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if h.backend.Snapshots <= snapshots {
		t.Fatal("force_audit did not dump fib")
	}
}

func TestOrderedDNSAcceptsAPISuccessWithoutFIBQueries(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	h.backend.Live[RouteKey{0, "198.51.100.77/32"}] = pathSetOf("10.61.10.1", "external")
	h.reconcileDNS(t)
	if h.backend.LookupCount() != 0 {
		t.Fatal("ordered DNS looked up fib")
	}
	if h.backend.BatchCount() == 0 {
		t.Fatal("ordered DNS did not apply")
	}
}

func TestCacheHitNotBlockedByBackground(t *testing.T) {
	h := newHarness(t)
	testCacheHitNotBlocked(t, h)
}

func TestOrderedCacheHitNotBlockedByBackground(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	testCacheHitNotBlocked(t, h)
}

func testCacheHitNotBlocked(t *testing.T, h *harness) {
	t.Helper()
	h.reconcileDNS(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.backend.SnapshotFn = func(routes []Route) (map[RouteKey]PathSet, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-time.After(2 * time.Second):
			return nil, errTimeout()
		}
		return h.backend.DoSnapshot(routes)
	}
	done := make(chan error, 1)
	go func() { done <- h.controller.Reconcile(context.Background(), nil, nil, true) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("background audit did not start")
	}
	finished := make(chan struct{})
	go func() {
		q := h.question()
		if err := h.controller.Reconcile(context.Background(), h.records(), &q, false); err != nil {
			t.Error(err)
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("cache hit blocked by background audit")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOrderedFirstSeenNotBlockedByBackground(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.backend.SnapshotFn = func(routes []Route) (map[RouteKey]PathSet, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-time.After(2 * time.Second):
			return nil, errTimeout()
		}
		return h.backend.DoSnapshot(routes)
	}
	done := make(chan error, 1)
	go func() { done <- h.controller.Reconcile(context.Background(), nil, nil, true) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("background audit did not start")
	}
	finished := make(chan struct{})
	go func() {
		h.reconcileDNS(t)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("ordered first-seen blocked by background audit")
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("first-seen route missing")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNewIPNotBlockedByBackgroundFIBDump(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.backend.SnapshotFn = func(routes []Route) (map[RouteKey]PathSet, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-time.After(2 * time.Second):
			return nil, errTimeout()
		}
		return h.backend.DoSnapshot(routes)
	}
	done := make(chan error, 1)
	go func() { done <- h.controller.Reconcile(context.Background(), nil, nil, true) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("background dump did not start")
	}
	finished := make(chan struct{})
	go func() {
		q := h.question()
		if err := h.controller.Reconcile(context.Background(), []Record{{"www.routing.example.net", "198.51.100.88", 60}}, &q, false); err != nil {
			t.Error(err)
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("new IP blocked by background FIB dump")
	}
	if !h.backend.HasRoute(0, "198.51.100.88/32") {
		t.Fatal("new IP missing")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNewIPNotBlockedByBackgroundApply(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	q := h.question()
	if err := h.controller.Reconcile(context.Background(), []Record{{"www.routing.example.net", "198.51.100.1", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	delete(h.backend.Live, RouteKey{0, "198.51.100.1/32"})
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.backend.ApplyFn = func(lines []string) error {
		for _, line := range lines {
			if strings.Contains(line, "198.51.100.1/32") {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-release:
				case <-time.After(2 * time.Second):
					return errTimeout()
				}
			}
		}
		return h.backend.DoApply(lines)
	}
	done := make(chan error, 1)
	go func() { done <- h.controller.Reconcile(context.Background(), nil, nil, true) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("background apply did not start")
	}
	finished := make(chan struct{})
	go func() {
		if err := h.controller.Reconcile(context.Background(), []Record{{"www.routing.example.net", "198.51.100.88", 60}}, &q, false); err != nil {
			t.Error(err)
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("new IP blocked by background apply")
	}
	if !h.backend.HasRoute(0, "198.51.100.88/32") {
		t.Fatal("new IP missing")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.88/32") {
		t.Fatal("new IP lost after background")
	}
	raw, err := os.ReadFile(h.controller.Config().StateFile)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	owned := false
	if arr, ok := state["owned"].([]any); ok {
		for _, item := range arr {
			obj, ok := item.(map[string]any)
			if ok && obj["prefix"] == "198.51.100.88/32" {
				owned = true
			}
		}
	}
	if !owned {
		t.Fatalf("owned %v", state["owned"])
	}
}

func TestRenewalNotDeletedByInflightWithdraw(t *testing.T) {
	h := newHarness(t)
	testRenewalNotDeleted(t, h)
}

func TestOrderedRenewalWaitsForInflightWithdraw(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	testRenewalNotDeleted(t, h)
}

func testRenewalNotDeleted(t *testing.T, h *harness) {
	t.Helper()
	h.reconcileDNS(t)
	h.controller.cacheLock.Lock()
	for k := range h.controller.Seen {
		h.controller.Seen[k] = time.Now().Unix() - 8*24*3600
	}
	h.controller.cacheLock.Unlock()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.backend.ApplyFn = func(lines []string) error {
		for _, line := range lines {
			if strings.HasPrefix(line, "ip route del") && strings.Contains(line, "198.51.100.77/32") {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-release:
				case <-time.After(2 * time.Second):
					return errTimeout()
				}
			}
		}
		return h.backend.DoApply(lines)
	}
	bg := make(chan error, 1)
	go func() { bg <- h.controller.Reconcile(context.Background(), nil, nil, false) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("background did not reach delete")
	}
	finished := make(chan struct{})
	go func() {
		h.reconcileDNS(t)
		close(finished)
	}()
	select {
	case <-finished:
		t.Fatal("renewal completed during same-prefix withdraw")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("renewal did not finish")
	}
	if err := <-bg; err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("renewed route missing")
	}
}

func TestSharedFlockDoesNotInvalidateVerified(t *testing.T) {
	h := newHarness(t)
	lock := filepath.Join(h.dir, "wg.lock")
	if err := os.WriteFile(lock, []byte("epoch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(h.configPath)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	config["lock_files"] = []any{lock}
	writeJSON(t, h.configPath, config)
	h.restart(t)
	before, _ := os.ReadFile(lock)
	beforeMod := fileMod(t, lock)
	h.reconcileDNS(t)
	lookups := h.backend.LookupCount()
	cfg, _ := h.controller.loaded()
	unlock, err := h.controller.interfaceLocks(cfg)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	after, _ := os.ReadFile(lock)
	if string(after) != string(before) || fileMod(t, lock) != beforeMod {
		t.Fatal("shared flock mutated lock file")
	}
	h.reconcileDNS(t)
	if h.backend.LookupCount() != lookups {
		t.Fatal("shared flock invalidated verified cache")
	}
}

func TestLockFileEpochReinstalls(t *testing.T) {
	h := newHarness(t)
	lock := filepath.Join(h.dir, "wg.lock")
	if err := os.WriteFile(lock, []byte("epoch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(h.configPath)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	config["lock_files"] = []any{lock}
	writeJSON(t, h.configPath, config)
	h.restart(t)
	h.reconcileDNS(t)
	lookups := h.backend.LookupCount()
	h.reconcileDNS(t)
	if h.backend.LookupCount() != lookups {
		t.Fatal("repeat dns queried fib")
	}
	if err := os.WriteFile(lock, []byte("rebuilt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, lock)
	h.backend.Live = map[RouteKey]PathSet{}
	h.reconcileDNS(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("lock epoch did not reinstall")
	}
	if h.backend.LookupCount() != lookups {
		t.Fatal("lock epoch used fib lookup")
	}
}

func TestBackgroundRetriesFailedAddWithoutFIBReads(t *testing.T) {
	h := newHarness(t)
	cfg := h.controller.Config()
	cfg.StaticPrefixes[MappingKey{"inet", "dns_gate", "altroute"}] = map[string]struct{}{"198.51.100.77/32": {}}
	cfg.staticIndex = nil
	h.backend.FailNext(0)
	if err := h.controller.Reconcile(context.Background(), nil, nil, false); err == nil {
		t.Fatal("failed static add succeeded")
	}
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("failed add leaked")
	}
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("retry did not install")
	}
	if h.backend.Snapshots != 0 || h.backend.LookupCount() != 0 {
		t.Fatal("retry used fib")
	}
}

func TestUnchangedBackgroundSkipsBulkPlanningButRepairsInterception(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	h.controller.Config().Mappings[0].TProxyPort = 2082
	repairs := 0
	h.backend.SyncTProxyFn = func() { repairs++ }
	h.reconcileDNS(t)
	h.reconcile(t)
	repairs = 0
	h.backend.SnapshotFn = func([]Route) (map[RouteKey]PathSet, error) {
		t.Fatal("unneeded bulk sync")
		return nil, errTimeout()
	}
	h.reconcileDNS(t)
	h.reconcile(t)
	if repairs != 1 {
		t.Fatalf("tproxy repairs %d", repairs)
	}
	h.backend.SnapshotFn = nil
	h.controller.cacheLock.Lock()
	for k := range h.controller.Seen {
		h.controller.Seen[k] = time.Now().Unix() - 8*24*3600
	}
	h.controller.cacheLock.Unlock()
	h.reconcile(t)
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("expired lease still live")
	}
}

func TestLastTProxyPolicyRemovalStillSyncs(t *testing.T) {
	h := newHarness(t)
	path := h.fakeIP(t, true)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	fake := doc["routes"].([]any)[1].(map[string]any)
	fake["tproxy_port"] = 2082
	writeJSON(t, path, doc)
	h.restart(t)
	calls := 0
	h.backend.SyncTProxyFn = func() { calls++ }
	h.reconcile(t)
	if calls == 0 {
		t.Fatal("TPROXY policy was never synced")
	}
	delete(fake, "tproxy_port")
	writeJSON(t, path, doc)
	h.restart(t)
	before := calls
	h.reconcile(t)
	if calls == before {
		t.Fatal("removing the last TPROXY policy skipped SyncTProxy")
	}
}

func TestSuccessfulNewDNSClaimSkipsBulkSyncButFailedAddIsRetried(t *testing.T) {
	h := newHarness(t)
	h.ordered(t)
	h.reconcileDNS(t)
	h.reconcile(t)
	q := h.question()
	if err := h.controller.Reconcile(context.Background(), []Record{{"www.routing.example.net", "198.51.100.88", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	h.backend.SnapshotFn = func([]Route) (map[RouteKey]PathSet, error) {
		t.Fatal("unneeded bulk sync")
		return nil, errTimeout()
	}
	h.reconcile(t)
	h.backend.SnapshotFn = nil
	h.backend.FailNext(0)
	if err := h.controller.Reconcile(context.Background(), []Record{{"www.routing.example.net", "198.51.100.99", 60}}, &q, false); err == nil {
		t.Fatal("failed add succeeded")
	}
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.51.100.99/32") {
		t.Fatal("failed add was not retried")
	}
	if h.backend.LookupCount() != 0 || h.backend.Snapshots != 0 {
		t.Fatal("retry used fib")
	}
}

func TestFakeIPPoolConflictingExitIsRejected(t *testing.T) {
	h := newHarness(t)
	path := h.fakeIP(t, true)
	raw, _ := os.ReadFile(path)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	routes := doc["routes"].([]any)
	other := map[string]any{}
	for k, v := range routes[1].(map[string]any) {
		other[k] = v
	}
	other["name"] = "other"
	other["via"] = "10.62.30.1"
	other["interface"] = "wg1"
	doc["routes"] = append(routes, other)
	writeJSON(t, path, doc)
	if err := h.tryRestart(); err == nil {
		t.Fatal("conflicting fake-ip pool accepted")
	}
}

func TestDomainListRoutesCNAMEAnswer(t *testing.T) {
	h := newHarness(t)
	h.domainRoutes(t, []string{"routing.example.net"})
	q := Question{"outside.test", 1, 1}
	recs := []Record{{"outside.test", "www.routing.example.net", 60}, {"www.routing.example.net", "198.51.100.77", 60}}
	if err := h.controller.Reconcile(context.Background(), recs, &q, false); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("cname answer was not routed")
	}
}

func TestFirstDNSUpstreamPreservesHigherPriorityRealExit(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	later := map[string]any{"name": "proxylist", "interface": "loop200", "via": "10.61.20.2",
		"dns_upstream": []any{"127.0.0.1", 5354}, "domains": route["domains"]}
	writeJSON(t, path, map[string]any{"routes": []any{route, later}})
	h.restart(t)
	up := h.controller.DNSUpstream(h.question())
	if up == nil || up.Port != 5354 {
		t.Fatalf("first-upstream %+v", up)
	}
	raw, _ := os.ReadFile(h.configPath)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	config["dns_upstream_policy"] = "first"
	writeJSON(t, h.configPath, config)
	h.restart(t)
	up = h.controller.DNSUpstream(h.question())
	if up != nil {
		t.Fatalf("policy first should use altroute without upstream, got %+v", up)
	}
	later["name"] = "proxylist6"
	later["via"] = "fd42:1111:2222:10::2"
	writeJSON(t, path, map[string]any{"routes": []any{route, later}})
	h.restart(t)
	aaaa := Question{"www.routing.example.net", 28, 1}
	up = h.controller.DNSUpstream(aaaa)
	if up != nil {
		t.Fatalf("v4-only altroute must not fall through to later AAAA upstream, got %+v", up)
	}
	suppress := h.controller.SuppressAAAA(aaaa)
	if !suppress {
		t.Fatalf("v4-only altroute must hide AAAA, got %v", suppress)
	}
}

func TestDomainFileChangeAppliesAfterRestart(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	names := filepath.Join(h.dir, "altroute.domains")
	if err := os.WriteFile(names, []byte("# research sites\nrouting.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	delete(route, "domains")
	route["domain_files"] = []any{filepath.Join(h.dir, "altroute.domains")}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	h.restart(t)
	h.reconcileDNS(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("domain file did not install")
	}
	if err := os.WriteFile(names, []byte("example.org # moved\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	h.reconcile(t)
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("old domain file member kept")
	}
	q := Question{"example.org", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"example.org", "198.51.100.88", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.88/32") {
		t.Fatal("new domain file member missing")
	}
}

func TestAMissingListFileTurnsOnlyItsRuleOff(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	delete(route, "domains")
	route["domain_files"] = []any{filepath.Join(h.dir, "missing.domains")}
	other := map[string]any{"name": "other", "interface": "wg1", "via": "10.62.30.1", "domains": []any{"example.org"}}
	writeJSON(t, path, map[string]any{"routes": []any{route, other}})
	out := captureLog(t)
	if err := h.tryRestart(); err != nil {
		t.Fatalf("a missing list file stopped Gate: %v", err)
	}
	_, rules := h.controller.loaded()
	if len(rules) != 1 || rules[0].Pattern != "example.org" {
		t.Fatalf("rules %+v", rules)
	}
	for _, want := range []string{"list file ignored", "missing.domains", "rule altroute is off"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("%q missing from:\n%s", want, out.String())
		}
	}
}

func TestABadPartOfAListFileGoesAlone(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	delete(route, "domains")
	good, missing := filepath.Join(h.dir, "good.domains"), filepath.Join(h.dir, "missing.domains")
	if err := os.WriteFile(good, []byte("example.org\nbad domain!\n# a comment\nexample.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	route["domain_files"] = []any{missing, good}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	out := captureLog(t)
	if err := h.tryRestart(); err != nil {
		t.Fatal(err)
	}
	_, rules := h.controller.loaded()
	if len(rules) != 2 || rules[0].Pattern != "example.org" || rules[1].Pattern != "example.net" {
		t.Fatalf("rules %+v", rules)
	}
	if !strings.Contains(out.String(), "good.domains:2: invalid domain: bad domain!") {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String(), "is off") {
		t.Fatalf("a rule with content went off:\n%s", out.String())
	}
}

func TestABadRangeLineGoesAlone(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	delete(route, "domains")
	ranges := filepath.Join(h.dir, "r.ranges")
	// The IPv6 line has no next hop here, the last one is no range, and 0.0.0.0/0 is refused.
	if err := os.WriteFile(ranges, []byte("198.51.100.0/24\n2001:db8::/32\n203.0.113.9-203.0.113.1\n0.0.0.0/0\nnonsense\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	route["ip_range_files"] = []any{ranges}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	out := captureLog(t)
	if err := h.tryRestart(); err != nil {
		t.Fatal(err)
	}
	cfg, _ := h.controller.loaded()
	total := 0
	for _, set := range cfg.StaticPrefixes {
		total += len(set)
		if _, ok := set["198.51.100.0/24"]; !ok {
			t.Fatalf("the good line is gone: %v", set)
		}
	}
	if total != 1 {
		t.Fatalf("%d prefixes: %v", total, cfg.StaticPrefixes)
	}
	if got := strings.Count(out.String(), "line ignored"); got != 4 {
		t.Fatalf("%d warnings:\n%s", got, out.String())
	}
}

func TestAnEmptiedListFileTurnsItsRuleOff(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	delete(route, "domains")
	empty := filepath.Join(h.dir, "empty.domains")
	if err := os.WriteFile(empty, []byte("# nothing yet\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	route["domain_files"] = []any{empty}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	if err := h.tryRestart(); err != nil {
		t.Fatal(err)
	}
	if _, rules := h.controller.loaded(); len(rules) != 0 {
		t.Fatalf("rules %+v", rules)
	}
}

// What the JSON itself says is still an error: it has a last sync to fall back on.
func TestAnInvalidInlineDomainStillStopsGate(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	route["domains"] = []any{"bad domain!"}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	if err := h.tryRestart(); err == nil {
		t.Fatal("an invalid domain in the JSON was accepted")
	}
}

func TestAPlainLoadStillRefusesAListProblem(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "gate.json")
	writeJSON(t, missing, map[string]any{"routes": []any{map[string]any{"name": "x", "interface": "wg1", "via": "10.62.30.1", "domain_files": []any{filepath.Join(dir, "no.domains")}}}})
	if _, err := DomainRoutesFromFile(missing, &Config{}); err == nil {
		t.Fatal("a missing list file passed the check a sync relies on")
	}
	bad := filepath.Join(dir, "bad.domains")
	if err := os.WriteFile(bad, []byte("bad domain!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, missing, map[string]any{"routes": []any{map[string]any{"name": "x", "interface": "wg1", "via": "10.62.30.1", "domain_files": []any{bad}}}})
	if _, err := DomainRoutesFromFile(missing, &Config{}); err == nil {
		t.Fatal("a bad line passed the check a sync relies on")
	}
}

func TestLegacyLeasesSurviveMigrationUntilDomainFileChanges(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	path := filepath.Join(h.dir, "domain-routes.json")
	names := filepath.Join(h.dir, "altroute.domains")
	if err := os.WriteFile(names, []byte("routing.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, path, map[string]any{"routes": []any{
		map[string]any{"name": "altroute", "interface": "wg1", "via": "10.62.30.1", "domain_files": []any{filepath.Join(h.dir, "altroute.domains")}},
	}})
	writeJSON(t, h.leasePath, []any{
		map[string]any{"mapping": []any{"inet", "mangle", "altroute"}, "prefix": "198.51.100.77/32", "seen": time.Now().Unix()},
	})
	c, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	h.controller = c
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("route lost during controller rebuild")
	}
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("migrated lease was withdrawn")
	}
	foundLegacy := false
	h.controller.cacheLock.Lock()
	for k := range h.controller.Seen {
		if k.Kind == 4 {
			foundLegacy = true
		}
	}
	h.controller.cacheLock.Unlock()
	if !foundLegacy {
		t.Fatal("legacy lease was not migrated")
	}
	c, err = NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	h.controller = c
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("restarted controller dropped migrated lease")
	}
	if err := os.WriteFile(names, []byte("example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	h.reconcile(t)
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("changed domain file kept migrated lease")
	}
}

func TestEditingOneDomainFileKeepsOtherOutletMigration(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "domain-routes.json")
	writeJSON(t, path, map[string]any{"routes": []any{
		map[string]any{"name": "altroute", "interface": "wg1", "via": "10.62.30.1", "domain_files": []any{filepath.Join(h.dir, "altroute.domains")}},
		map[string]any{"name": "proxylist", "interface": "loop200", "via": "10.61.20.2", "domain_files": []any{filepath.Join(h.dir, "proxylist.domains")}},
	}})
	if err := os.WriteFile(filepath.Join(h.dir, "altroute.domains"), []byte("routing.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "proxylist.domains"), []byte("example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	writeJSON(t, h.leasePath, []any{
		map[string]any{"mapping": []any{"inet", "mangle", "altroute"}, "prefix": "198.51.100.77/32", "seen": now},
		map[string]any{"mapping": []any{"inet", "mangle", "proxylist"}, "prefix": "198.51.100.88/32", "seen": now},
	})
	c, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Seen) != 2 {
		t.Fatalf("seen %d", len(c.Seen))
	}
	if err := os.WriteFile(filepath.Join(h.dir, "altroute.domains"), []byte("new.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err = NewController(h.configPath, h.leasePath, func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string]struct{}{}
	for k := range c.Seen {
		sets[k.Mapping.Set] = struct{}{}
	}
	if len(sets) != 1 {
		t.Fatalf("sets %v", sets)
	}
	if _, ok := sets["proxylist"]; !ok {
		t.Fatalf("kept %v", sets)
	}
}

func TestUpgradeConvertsGlobalMigrationHash(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "domain-routes.json")
	writeJSON(t, path, map[string]any{"routes": []any{
		map[string]any{"name": "altroute", "interface": "wg1", "via": "10.62.30.1", "domain_files": []any{filepath.Join(h.dir, "altroute.domains")}},
	}})
	if err := os.WriteFile(filepath.Join(h.dir, "altroute.domains"), []byte("routing.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	paths, err := DomainRoutePaths(path)
	if err != nil {
		t.Fatal(err)
	}
	oldHash, err := DomainSourceHash(paths)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, h.leasePath, []any{
		map[string]any{"mapping": []any{"inet", "dns_gate", "altroute"}, "prefix": "198.51.100.77/32",
			"domain": migratedDomain, "source_hash": oldHash, "seen": time.Now().Unix()},
	})
	c, err := NewController(h.configPath, h.leasePath,
		func(*Config) Backend { return h.backend }, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Seen) != 1 {
		t.Fatalf("seen %d", len(c.Seen))
	}
	for k := range c.Seen {
		if k.SourceHash == oldHash {
			t.Fatal("global source hash was not converted to outlet hash")
		}
	}
}

func TestMultipleDomainFilesAndInlineDomains(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, []string{"inline.example"})
	if err := os.WriteFile(filepath.Join(h.dir, "first.domains"), []byte("routing.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "second.domains"), []byte("example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	route["domain_files"] = []any{filepath.Join(h.dir, "first.domains"), filepath.Join(h.dir, "second.domains")}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	h.restart(t)
	h.reconcileDNS(t)
	q := Question{"example.org", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"example.org", "198.51.100.88", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	q = Question{"inline.example", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"inline.example", "198.51.100.99", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	if len(h.backend.LiveKeys()) != 3 {
		t.Fatalf("live %v", h.backend.LiveKeys())
	}
}

func TestDomainOutletChangeReconcilesExistingAddress(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, nil)
	h.reconcileDNS(t)
	route["via"] = "10.62.30.9"
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	h.restart(t)
	if err := h.controller.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	pathEquals(t, h.backend, "198.51.100.77/32", "10.62.30.9", "wg1")
}

func TestSharedAddressStaysWhenOneDomainIsRemoved(t *testing.T) {
	h := newHarness(t)
	path, route := h.domainRoutes(t, []string{"routing.example.net", "example.org"})
	h.reconcileDNS(t)
	q := Question{"example.org", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"example.org", "198.51.100.77", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	route["domains"] = []any{"example.org"}
	writeJSON(t, path, map[string]any{"routes": []any{route}})
	h.restart(t)
	if err := h.controller.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("shared address was withdrawn")
	}
}

func TestInvalidDomainListStopsStartup(t *testing.T) {
	h := newHarness(t)
	path, _ := h.domainRoutes(t, nil)
	if err := os.WriteFile(path, []byte("{bad json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.tryRestart(); err == nil {
		t.Fatal("invalid domain list was loaded")
	}
}

func errTimeout() error { return errTimeoutValue }

type timeoutError struct{}

func (timeoutError) Error() string { return "test timed out" }

var errTimeoutValue error = timeoutError{}
