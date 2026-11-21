package gate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testSyncConfig(t *testing.T, dir string) *Config {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	writeJSON(t, path, map[string]any{
		"state_file":       filepath.Join(dir, "state.json"),
		"lock_files":       []any{},
		"exclude_prefixes": []any{"10.64.20.3/32"},
	})
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Mappings = []Mapping{{Enabled: true, Family: "inet", Table: "dns_gate", Set: "altroute", Interface: "wg1", Via: "10.62.30.1"}}
	return cfg
}

func TestEnsureRoutesAddsOnlyRequiredPrefix(t *testing.T) {
	dir := t.TempDir()
	cfg := testSyncConfig(t, dir)
	backend := NewFakeBackend()
	required := []Route{{0, "198.51.100.77/32", "10.62.30.1", "wg1"}}
	result, err := EnsureRoutes(cfg, backend, required, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Add != 1 {
		t.Fatalf("add %d", result.Add)
	}
	if backend.Snapshots != 0 || len(backend.CLICalls) != 0 {
		t.Fatal("ensure read fib")
	}
	if !backend.HasRoute(0, "198.51.100.77/32") || backend.HasRoute(0, "198.51.100.99/32") {
		t.Fatalf("live %v", backend.LiveKeys())
	}
	raw, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	owned := state["owned"].([]any)
	if len(owned) != 1 || owned[0].(map[string]any)["prefix"] != "198.51.100.77/32" {
		t.Fatalf("owned %v", owned)
	}
}

func TestEnsureRoutesIsIdempotentAndDoesNotDeleteOthers(t *testing.T) {
	dir := t.TempDir()
	cfg := testSyncConfig(t, dir)
	backend := NewFakeBackend()
	extra := map[MappingKey]map[string]struct{}{cfg.Mappings[0].Key(): {"198.51.100.77/32": {}, "198.51.100.88/32": {}}}
	if _, err := SyncAll(cfg, backend, extra); err != nil {
		t.Fatal(err)
	}
	snapshots, lookups := backend.Snapshots, backend.LookupCount()
	required := []Route{{0, "198.51.100.77/32", "10.62.30.1", "wg1"}}
	if _, err := EnsureRoutes(cfg, backend, required, nil); err != nil {
		t.Fatal(err)
	}
	if backend.BatchCount() != 2 {
		t.Fatalf("batches %d", backend.BatchCount())
	}
	if backend.LookupCount() != lookups || backend.Snapshots != snapshots {
		t.Fatal("ensure used fib")
	}
	if !backend.HasRoute(0, "198.51.100.88/32") {
		t.Fatal("sibling prefix was deleted")
	}
	result, err := SyncAll(cfg, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Delete != 2 {
		t.Fatalf("delete %d", result.Delete)
	}
}

func TestEnsureRoutesConflictAndEndpoint(t *testing.T) {
	dir := t.TempDir()
	cfg := testSyncConfig(t, dir)
	backend := NewFakeBackend()
	backend.Live[RouteKey{0, "198.51.100.77/32"}] = pathSetOf("10.61.20.1", "host-vpp-wan")
	required := []Route{{0, "198.51.100.77/32", "10.62.30.1", "wg1"}}
	if _, err := EnsureRoutes(cfg, backend, required, nil); err != nil {
		t.Fatal(err)
	}
	if backend.LookupCount() != 0 {
		t.Fatal("ensure looked up fib")
	}
	pathEquals(t, backend, "198.51.100.77/32", "10.62.30.1", "wg1")
	if _, err := EnsureRoutes(cfg, backend, []Route{{0, "10.64.20.3/32", "10.62.30.1", "wg1"}}, nil); err == nil {
		t.Fatal("excluded endpoint installed")
	}
	if backend.BatchCount() != 1 {
		t.Fatalf("batches %d", backend.BatchCount())
	}
}

func TestEnsureRoutesRejectsMatchingRouteAfterExclude(t *testing.T) {
	dir := t.TempDir()
	cfg := testSyncConfig(t, dir)
	backend := NewFakeBackend()
	required := []Route{{0, "198.51.100.77/32", "10.62.30.1", "wg1"}}
	if _, err := EnsureRoutes(cfg, backend, required, nil); err != nil {
		t.Fatal(err)
	}
	cfg.ExcludePrefixes = []string{"198.51.100.0/24"}
	if _, err := EnsureRoutes(cfg, backend, required, nil); err == nil {
		t.Fatal("excluded route was installed")
	}
	if !Matches(required[0], backend.Live) {
		t.Fatal("live route was removed")
	}
}

func TestLedgerRejectsUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	writeJSON(t, path, map[string]any{"version": 2, "generation": "x", "owned": []any{}})
	store := NewDeferredState([]string{path})
	store.lock.Lock()
	_, _, _, err := store.Ledger(path, "x")
	store.lock.Unlock()
	if err == nil {
		t.Fatal("unsupported version accepted")
	}
	writeJSON(t, path, map[string]any{"generation": "x"})
	store = NewDeferredState([]string{path})
	store.lock.Lock()
	_, _, _, err = store.Ledger(path, "x")
	store.lock.Unlock()
	if err == nil {
		t.Fatal("missing version accepted")
	}
}

func TestEnsureRecordsOwnershipSoBackgroundCanWithdraw(t *testing.T) {
	dir := t.TempDir()
	cfg := testSyncConfig(t, dir)
	backend := NewFakeBackend()
	required := []Route{{0, "198.51.100.77/32", "10.62.30.1", "wg1"}}
	if _, err := EnsureRoutes(cfg, backend, required, nil); err != nil {
		t.Fatal(err)
	}
	result, err := SyncAll(cfg, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Delete != 1 {
		t.Fatalf("delete %d", result.Delete)
	}
	if backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("owned route was not withdrawn")
	}
}

func TestFlushRemovesOnlyOwnedRoutesAndLeases(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	if err := AtomicJSON(h.leasePath, EncodeSeen(h.controller.Seen)); err != nil {
		t.Fatal(err)
	}
	foreign := Route{0, "203.0.113.9/32", "10.62.30.1", "wg1"}
	if err := h.backend.Apply([]string{foreign.Command("add")}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := flushRoutes(cfg, h.backend, h.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Delete != 1 || h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatalf("owned route stayed: %+v", result)
	}
	if !h.backend.HasRoute(0, "203.0.113.9/32") {
		t.Fatal("flush removed a route Gate does not own")
	}
	if _, err := os.Stat(h.leasePath); !os.IsNotExist(err) {
		t.Fatalf("leases stayed: %v", err)
	}
	// Nothing comes back from the next start, and a second flush has nothing to do.
	h2, err := NewController(h.configPath, h.leasePath, func(*Config) Backend { return h.backend }, h.routesPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := h2.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("flushed route came back")
	}
	if result, err = flushRoutes(cfg, h.backend, h.leasePath); err != nil || result.Delete != 0 {
		t.Fatalf("second flush %+v %v", result, err)
	}
}

func TestFlushKeepsLeasesWhenRoutesCannotBeRemoved(t *testing.T) {
	h := newHarness(t)
	h.reconcileDNS(t)
	if err := AtomicJSON(h.leasePath, EncodeSeen(h.controller.Seen)); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	h.backend.FailNext(0)
	if _, err := flushRoutes(cfg, h.backend, h.leasePath); err == nil {
		t.Fatal("failed flush reported success")
	}
	if _, err := os.Stat(h.leasePath); err != nil {
		t.Fatalf("leases went before the routes: %v", err)
	}
	if _, err := flushRoutes(cfg, h.backend, h.leasePath); err != nil {
		t.Fatal(err)
	}
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("retry left the route")
	}
}

func TestFlushClearsPendingRoutes(t *testing.T) {
	h := newHarness(t)
	cfg, err := LoadConfig(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := h.backend.Generation()
	if err != nil {
		t.Fatal(err)
	}
	// A stop between the journal and the batch: one route made it into VPP, one did not.
	installed := Route{0, "198.51.100.1/32", "10.62.30.1", "wg1"}
	missing := Route{0, "198.51.100.2/32", "10.62.30.1", "wg1"}
	if err := h.backend.Apply([]string{installed.Command("add")}); err != nil {
		t.Fatal(err)
	}
	if err := AtomicJSON(cfg.StateFile, map[string]any{"version": 1, "generation": generation,
		"owned": routesToJSON(nil), "pending_add": routesToJSON([]Route{installed, missing})}); err != nil {
		t.Fatal(err)
	}
	if _, err := flushRoutes(cfg, h.backend, h.leasePath); err != nil {
		t.Fatal(err)
	}
	if h.backend.HasRoute(0, "198.51.100.1/32") {
		t.Fatal("pending route that reached VPP stayed")
	}
	_, owned, pending, err := splitState(cfg.StateFile, generation)
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 0 || len(pending) != 0 {
		t.Fatalf("ledger not empty: %v %v", owned, pending)
	}
}
