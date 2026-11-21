package gate

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func (h *harness) twoExitsWithRanges(t *testing.T) {
	t.Helper()
	tunnel := altroute("routing.example.net")
	tunnel["ip_range_files"] = []any{h.rangeFile(t, "tunnel.ipv4", "203.0.113.0/24\n")}
	lan := proxylist("lan.example")
	lan["ip_range_files"] = []any{h.rangeFile(t, "lan.ipv4", "198.51.100.0/24\n")}
	h.writeRoutes(t, tunnel, lan)
}

func (h *harness) forceSync(t *testing.T) {
	t.Helper()
	if err := h.controller.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestAMissingExitLeavesTheOtherRulesWorking(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.reconcile(t)
	if !h.backend.HasRoute(0, "198.51.100.0/24") {
		t.Fatal("a rule with a working exit was not installed")
	}
	if h.backend.HasRoute(0, "203.0.113.0/24") {
		t.Fatal("a route was installed through a missing exit")
	}
}

func TestDNSThroughAMissingExitFailsAndOthersAnswer(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.reconcile(t)
	batches := len(h.backend.Batches)
	q := h.question()
	if err := h.controller.Reconcile(context.Background(), h.records(), &q, false); err == nil {
		t.Fatal("a query through a missing exit succeeded")
	}
	if len(h.backend.Batches) != batches {
		t.Fatal("a query through a missing exit reached VPP")
	}
	other := Question{"www.lan.example", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"www.lan.example", "192.0.2.9", 60}}, &other, false); err != nil {
		t.Fatalf("a query through a working exit failed: %v", err)
	}
	if !h.backend.HasRoute(0, "192.0.2.9/32") {
		t.Fatal("the working exit's route is missing")
	}
}

func TestAnExitThatAppearsGetsItsRoutes(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.reconcile(t)
	if changed, missing, err := h.controller.exitsChanged(context.Background()); err != nil || changed || !missing {
		t.Fatalf("changed=%v missing=%v err=%v", changed, missing, err)
	}
	h.backend.Absent = nil
	changed, missing, err := h.controller.exitsChanged(context.Background())
	if err != nil || !changed || missing {
		t.Fatalf("changed=%v missing=%v err=%v", changed, missing, err)
	}
	h.forceSync(t)
	if !h.backend.HasRoute(0, "203.0.113.0/24") {
		t.Fatal("the exit came back without its routes")
	}
	h.reconcileDNS(t)
	if !h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("DNS did not recover with the exit")
	}
}

func TestAnExitThatGoesAwayDoesNotStopTheSync(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.reconcile(t)
	h.reconcileDNS(t)
	if !h.backend.HasRoute(0, "203.0.113.0/24") {
		t.Fatal("setup: no route")
	}
	h.backend.Absent = map[string]bool{"wg1": true}
	changed, _, err := h.controller.exitsChanged(context.Background())
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	h.forceSync(t)
	if !h.backend.HasRoute(0, "198.51.100.0/24") {
		t.Fatal("the working exit lost its route")
	}
}

func TestFakeIPOnAMissingExitFailsOnlyItsOwnQueries(t *testing.T) {
	h := newHarness(t)
	h.fakeIP(t, true)
	h.backend.Absent = map[string]bool{"tap2490": true}
	h.reconcile(t)
	if h.backend.HasRoute(0, "198.18.0.0/15") {
		t.Fatal("a Fake-IP pool was installed through a missing exit")
	}
	fake := Question{"www.example.com", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"www.example.com", "198.18.0.5", 60}}, &fake, false); err == nil {
		t.Fatal("a Fake-IP answer for a missing exit was allowed")
	}
	real := Question{"real.example.com", 1, 1}
	if err := h.controller.Reconcile(context.Background(), []Record{{"real.example.com", "192.0.2.10", 60}}, &real, false); err != nil {
		t.Fatalf("a rule on a working exit failed: %v", err)
	}
}

var tunnelRange = DropRoute{0, "203.0.113.0/24"}

func TestAMissingExitDiscardsItsTraffic(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.reconcile(t)
	if !h.backend.Drops[tunnelRange] {
		t.Fatalf("the missing exit's range would leak: %v", h.backend.Drops)
	}
	if !h.backend.Drops[DropRoute{0, "198.51.100.0/24"}] || !h.backend.HasRoute(0, "198.51.100.0/24") {
		t.Fatal("a working exit needs its real route above its drop route")
	}
}

func TestLearnedAddressesOfAMissingExitAreDiscarded(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.reconcile(t)
	h.reconcileDNS(t)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.forceSync(t)
	if !h.backend.Drops[DropRoute{0, "198.51.100.77/32"}] {
		t.Fatalf("a learned address would leak: %v", h.backend.Drops)
	}
}

func TestDropRoutesBelongToOneVPPRun(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.reconcile(t)
	h.backend.Instance = strings.Repeat("b", 32)
	h.backend.Drops = nil
	h.backend.Live = map[RouteKey]PathSet{}
	h.forceSync(t)
	if !h.backend.Drops[tunnelRange] {
		t.Fatal("a new VPP run did not get its drop routes")
	}
}

func TestAnExcludedPrefixIsNotDropped(t *testing.T) {
	h := newHarness(t)
	tunnel := altroute("routing.example.net")
	tunnel["ip_range_files"] = []any{h.rangeFile(t, "excluded.ipv4", "10.64.20.0/24\n")}
	if err := func() error {
		writeJSON(t, h.routesPath, map[string]any{"routes": []any{tunnel}})
		return h.tryRestart()
	}(); err != nil {
		t.Skipf("Gate refuses this overlap outright: %v", err)
	}
	h.backend.Absent = map[string]bool{"wg1": true}
	h.reconcile(t)
	if h.backend.Drops[DropRoute{0, "10.64.20.0/24"}] {
		t.Fatal("an excluded prefix was dropped")
	}
}

func TestAFakeIPPoolOfAMissingExitIsDropped(t *testing.T) {
	h := newHarness(t)
	h.fakeIP(t, true)
	h.backend.Absent = map[string]bool{"tap2490": true}
	h.reconcile(t)
	if !h.backend.Drops[DropRoute{0, "198.18.0.0/15"}] {
		t.Fatalf("drops=%v", h.backend.Drops)
	}
}

func TestFlushRemovesDropRoutes(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.reconcile(t)
	cfg, _ := h.controller.loaded()
	if _, err := flushRoutes(cfg, h.backend, ""); err != nil {
		t.Fatal(err)
	}
	if len(h.backend.Drops) != 0 {
		t.Fatalf("drops=%v", h.backend.Drops)
	}
}

func TestDropRoutesAreInPlaceBeforeRealOnesAndStay(t *testing.T) {
	h := newHarness(t)
	sawReal := false
	h.backend.ApplyFn = func(lines []string) error {
		for _, line := range lines {
			if strings.Contains(line, "203.0.113.0/24") && strings.Contains(line, " add ") {
				sawReal = true
				if !h.backend.Drops[tunnelRange] {
					t.Error("a real route went in with no drop route under it")
				}
			}
		}
		return h.backend.DoApply(lines)
	}
	h.twoExitsWithRanges(t)
	h.reconcile(t)
	if !sawReal || !h.backend.Drops[tunnelRange] || !h.backend.HasRoute(0, "203.0.113.0/24") {
		t.Fatalf("real=%v drops=%v", sawReal, h.backend.Drops)
	}
}

func TestExitsComingAndGoingLeaveDropRoutesAlone(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.reconcile(t)
	before := len(h.backend.Drops)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.forceSync(t)
	h.backend.Absent = nil
	h.forceSync(t)
	if len(h.backend.Drops) != before || !h.backend.Drops[tunnelRange] || !h.backend.HasRoute(0, "203.0.113.0/24") {
		t.Fatalf("drops=%v", h.backend.Drops)
	}
}

func TestDropRoutesGoWithTheirRuleEvenAfterAGateRestart(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.reconcile(t)
	lan := proxylist("lan.example")
	lan["ip_range_files"] = []any{filepath.Join(h.dir, "lan.ipv4")}
	h.writeRoutes(t, lan)
	h.reconcile(t)
	if h.backend.Drops[tunnelRange] {
		t.Fatalf("a removed rule left its drop route: %v", h.backend.Drops)
	}
	if !h.backend.Drops[DropRoute{0, "198.51.100.0/24"}] {
		t.Fatalf("a kept rule lost its drop route: %v", h.backend.Drops)
	}
}

func TestRoutesThroughAVanishedExitAreRemoved(t *testing.T) {
	h := newHarness(t)
	h.twoExitsWithRanges(t)
	h.reconcile(t)
	h.reconcileDNS(t)
	h.backend.Absent = map[string]bool{"wg1": true}
	h.backend.Batches = nil
	h.forceSync(t)
	removed := false
	for _, batch := range h.backend.Batches {
		for _, line := range batch {
			removed = removed || strings.Contains(line, "ip route del 203.0.113.0/24")
		}
	}
	if !removed {
		t.Fatalf("a route through the vanished exit was left in VPP: %v", h.backend.Batches)
	}
	h.backend.Batches = nil
	h.forceSync(t)
	if len(h.backend.Batches) != 0 {
		t.Fatalf("removed again on the next sync: %v", h.backend.Batches)
	}
}
