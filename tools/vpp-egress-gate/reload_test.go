package gate

import (
	"context"
	"os"
	"testing"
)

func TestReloadListsAppliesStaticRouteDifference(t *testing.T) {
	h := newHarness(t)
	path := h.rangeFile(t, "hot.ranges", "203.0.113.0/24\n198.51.100.0/24\n")
	route := altroute("routing.example.net")
	route["ip_range_files"] = []any{path}
	h.writeRoutes(t, route)
	h.reconcile(t)
	if err := os.WriteFile(path, []byte("203.0.113.0/24\n192.0.2.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := NewGate(h.controller, Upstream{})
	defer g.Shutdown()
	result := g.ReloadLists(context.Background(), h.controller)
	if result.Error != "" || result.Restart {
		t.Fatal(result)
	}
	for prefix, present := range map[string]bool{"203.0.113.0/24": true, "192.0.2.0/24": true, "198.51.100.0/24": false} {
		if h.backend.HasRoute(0, prefix) != present {
			t.Fatalf("%s present=%v", prefix, !present)
		}
	}
}

func TestReloadListsReplacesDomainIndex(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	writeJSON(t, h.routesPath, map[string]any{"routes": []any{altroute("new.example")}})
	g := NewGate(h.controller, Upstream{})
	defer g.Shutdown()
	if result := g.ReloadLists(context.Background(), h.controller); result.Error != "" || result.Restart {
		t.Fatal(result)
	}
	q := h.question()
	cfg, rules := h.controller.loaded()
	_, required := h.controller.dnsRoutes(cfg, rules, h.records(), q)
	if len(required) != 0 {
		t.Fatal("removed domain still matched")
	}
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("removed domain route survived reload")
	}
}

func TestReloadListsRejectsDeviceChangesWithoutPublishing(t *testing.T) {
	h := newHarness(t)
	before, _ := h.controller.loaded()
	route := altroute("routing.example.net")
	route["interface"] = "wg2"
	writeJSON(t, h.routesPath, map[string]any{"routes": []any{route}})
	g := NewGate(h.controller, Upstream{})
	defer g.Shutdown()
	result := g.ReloadLists(context.Background(), h.controller)
	if !result.Restart || result.Error != "" {
		t.Fatal(result)
	}
	after, _ := h.controller.loaded()
	if after != before {
		t.Fatal("device change was published before restart")
	}
}
