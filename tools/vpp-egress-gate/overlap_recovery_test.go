package gate

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOverlappingClaimsSurviveFirstRemoval(t *testing.T) {
	dir := t.TempDir()
	first := map[string]any{"name": "first", "interface": "wg1", "via": "10.62.30.1", "domains": []any{"shared.example"}}
	second := map[string]any{"name": "second", "interface": "loop10", "via": "10.63.30.2", "domains": []any{"shared.example"}}
	config, domain, b, _ := writePolicy(t, dir, []any{first, second})
	writeJSON(t, domain, map[string]any{"overlap_policy": "first", "routes": []any{first, second}})
	leases := filepath.Join(dir, "leases.json")
	start := func() *Controller {
		t.Helper()
		c, err := NewController(config, leases, func(*Config) Backend { return b }, domain)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := start()
	store := NewDeferredState([]string{c.Config().StateFile, leases})
	store.Enter()
	q := Question{"shared.example", 1, 1}
	if e := c.Reconcile(context.Background(), []Record{{"shared.example", "198.51.100.77", 60}}, &q, false); e != nil {
		t.Fatal(e)
	}
	if !b.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("initial route missing")
	}
	writeJSON(t, domain, map[string]any{"overlap_policy": "first", "routes": []any{second}})
	// A clean stop writes the routes and leases that the next start reads.
	if err := store.Exit(); err != nil {
		t.Fatal(err)
	}
	c = start()
	store = NewDeferredState([]string{c.Config().StateFile, leases})
	store.Enter()
	defer store.Exit()
	if e := c.Reconcile(context.Background(), nil, nil, false); e != nil {
		t.Fatal(e)
	}
	p, ok := b.RoutePath(0, "198.51.100.77/32")
	if !ok || p.Interface != "loop10" {
		t.Fatalf("no replacement route after removing first policy: %v %v", p, ok)
	}
}
