package gate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
)

const gateLockPath = "/run/lock/vpp-egress-gate.lock"

// Flush undoes what Gate did at run time. It takes the lock Gate holds, so Gate must be stopped.
// Devices stay: they belong to the device sync, and VPP may hold them until it restarts.
func Flush(configPath string, dryRun bool) error {
	g, err := LoadGateFile(configPath)
	if err != nil {
		return err
	}
	routePath := g.RouteConfig
	if routePath == "" {
		routePath = configPath
	}
	// LoadConfig reads no routes, so the plan is to want nothing.
	cfg, err := LoadConfig(routePath)
	if err != nil {
		return err
	}
	lock, err := exclusiveLock(gateLockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	backend := NewVPPBackend(cfg)
	if dryRun {
		return printFlushPlan(cfg, backend, g.LeaseFile)
	}
	// The default route first: its pins keep tunnel endpoints off the exit while the halves exist.
	if err := flushDefaultRoutes(context.Background(), cfg, backend, false); err != nil {
		return err
	}
	result, err := flushRoutes(cfg, backend, g.LeaseFile)
	if err != nil {
		return err
	}
	clearVPPHijack(cfg)
	// Only Gate uses this table: the DNS hijack and TPROXY chains are all it holds.
	if err := applyNft([]string{"add table inet egress_gate\ndelete table inet egress_gate"}, "flush"); err != nil {
		return err
	}
	log.Printf("flushed %d routes recorded in %s", result.Delete, cfg.StateFile)
	return nil
}

func printFlushPlan(cfg *Config, backend Backend, leaseFile string) error {
	generation, err := backend.Generation()
	if err != nil {
		return err
	}
	_, owned, pending, err := splitState(cfg.StateFile, generation)
	if err != nil {
		return err
	}
	fmt.Printf("route ledger: %s\n", cfg.StateFile)
	for _, route := range append(sortedRouteValues(owned), sortedRouteValues(pending)...) {
		fmt.Println(route.Command("del"))
	}
	for _, route := range sortedDrops(readDrops(cfg, generation)) {
		fmt.Println(route.command("del"))
	}
	if err := flushDefaultRoutes(context.Background(), cfg, backend, true); err != nil {
		return err
	}
	if leaseFile != "" {
		fmt.Printf("delete leases: %s\n", leaseFile)
	}
	return nil
}

// The leases go last: a flush that fails can run again, and they would bring routes back.
func flushRoutes(cfg *Config, backend Backend, leaseFile string) (ApplyResult, error) {
	audit := true
	prepared, err := PrepareSync(cfg, backend, true, &audit)
	if err != nil {
		return ApplyResult{}, err
	}
	result, err := CommitSync(cfg, backend, prepared, nil, nil, nil, nil, nil, true)
	if err != nil {
		return ApplyResult{}, err
	}
	syncDrops(cfg, backend, prepared.Generation, nil)
	// A route still pending was never installed, or has just been removed, and Gate is stopped.
	if err := AtomicJSON(cfg.StateFile, map[string]any{
		"version": 1, "generation": prepared.Generation,
		"owned": routesToJSON(nil), "pending_add": routesToJSON(nil),
	}); err != nil {
		return ApplyResult{}, err
	}
	if leaseFile != "" {
		if err := os.Remove(leaseFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return ApplyResult{}, err
		}
	}
	return result, nil
}
