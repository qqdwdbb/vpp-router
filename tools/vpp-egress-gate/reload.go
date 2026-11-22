package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"time"
)

type ListReloadResult struct {
	Error   string `json:"error,omitempty"`
	Restart bool   `json:"restart,omitempty"`
}

// ReloadLists serializes configuration replacement with DNS exchanges and route writers.
func (g *Gate) ReloadLists(ctx context.Context, c *Controller) ListReloadResult {
	g.reloadLock.Lock()
	defer g.reloadLock.Unlock()
	c.reloadLock.Lock()
	defer c.reloadLock.Unlock()
	c.cacheLock.Lock()
	oldConfig, oldRules, oldIndex := c.config, c.rules, c.index
	oldSeen, oldExcludes := c.Seen, c.baseExcludes
	oldBackground := c.backgroundSig
	c.cacheLock.Unlock()
	restore := func() error {
		c.cacheLock.Lock()
		c.config, c.rules, c.index = oldConfig, oldRules, oldIndex
		c.Seen, c.baseExcludes = oldSeen, oldExcludes
		c.backgroundSig = bgSig{}
		c.cacheLock.Unlock()
		return AtomicJSON(c.LeasePath, EncodeSeen(oldSeen))
	}
	if err := c.load(); err != nil {
		return ListReloadResult{Error: errors.Join(err, restore()).Error()}
	}
	next, _ := c.loaded()
	// List contents may change the enabled mappings (an empty list becomes active).
	// Device and listener changes still use the existing restart transaction.
	if !reflect.DeepEqual(oldConfig.Mappings, next.Mappings) {
		if err := restore(); err != nil {
			return ListReloadResult{Error: err.Error()}
		}
		c.backgroundSig = oldBackground
		return ListReloadResult{Restart: true}
	}
	c.backgroundSig = bgSig{}
	c.cacheLock.Lock()
	c.verified = map[RouteKey]Route{}
	c.cacheLock.Unlock()
	if err := c.reconcile(ctx, nil, nil, true, nil, nil, false); err != nil {
		if restoreErr := restore(); restoreErr != nil {
			return ListReloadResult{Error: errors.Join(err, restoreErr).Error()}
		}
		rollbackCtx, cancel := context.WithTimeout(g.context(), 30*time.Second)
		defer cancel()
		if rollbackErr := c.reconcile(rollbackCtx, nil, nil, true, nil, nil, false); rollbackErr != nil {
			return ListReloadResult{Error: fmt.Sprintf("%v; restoring routes: %v", err, rollbackErr)}
		}
		return ListReloadResult{Error: err.Error()}
	}
	return ListReloadResult{}
}

func startListReloadServer(cfg *Config, gate *Gate, c *Controller, stop <-chan struct{}) error {
	path := cfg.StateSocket
	if path == "" {
		path = "/run/vpp-egress-gate/state.sock"
	}
	path += ".reload"
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	go func() { <-stop; ln.Close(); os.Remove(path) }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			ctx, cancel := context.WithTimeout(gate.context(), 30*time.Second)
			result := gate.ReloadLists(ctx, c)
			cancel()
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			json.NewEncoder(conn).Encode(result)
			conn.Close()
		}
	}()
	return nil
}
