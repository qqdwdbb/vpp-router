package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Store totals and their counter baseline together so restarting the monitor
// can resume without counting previously saved bytes again.
type lanTotalState struct {
	Since int64               `json:"since"`
	ByMAC map[string]LANBytes `json:"by_mac"`
	Key   string              `json:"counter_key"`
	Up    []uint64            `json:"up"`
	Down  []uint64            `json:"down"`
}

type LANBytes struct {
	Up   uint64 `json:"up_bytes"`
	Down uint64 `json:"down_bytes"`
}

type lanTotals struct {
	path string
	lanTotalState
	loadErr error
	dirty   bool
}

func loadLANTotals(path string) lanTotals {
	t := lanTotals{path: path, lanTotalState: lanTotalState{ByMAC: map[string]LANBytes{}}}
	if path == "" {
		return t
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return t
	}
	var saved lanTotalState
	if err == nil {
		err = json.Unmarshal(data, &saved)
	}
	if err == nil && (saved.Since <= 0 || saved.ByMAC == nil || saved.Key == "" || len(saved.Up) != len(saved.Down)) {
		err = errors.New("invalid LAN totals checkpoint")
	}
	if err != nil {
		t.loadErr = err
		log.Printf("reading LAN totals %s: %v", path, err)
		return t
	}
	t.lanTotalState = saved
	return t
}

func (t *lanTotals) record(file meterFile, key string, up, down []uint64, now time.Time) {
	n := len(file.Rules)
	up, down = up[:n], down[:n]
	if t.Since == 0 {
		t.Since = now.Unix()
	}
	sameRules := key == t.Key && len(t.Up) == n && len(t.Down) == n
	if sameRules && slices.Equal(up, t.Up) && slices.Equal(down, t.Down) {
		return
	}
	for i, rule := range file.Rules {
		total := t.ByMAC[rule.MAC]
		if sameRules {
			total.Up += byteDelta(up[i], t.Up[i])
			total.Down += byteDelta(down[i], t.Down[i])
		}
		t.ByMAC[rule.MAC] = total
	}
	t.Key, t.Up, t.Down = key, up, down
	t.dirty = true
}

func byteDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

// Save only on orderly shutdown to avoid writes during normal monitoring.
func (t *lanTotals) save() {
	if t.path == "" || t.loadErr != nil || !t.dirty {
		return
	}
	if err := t.write(); err != nil {
		log.Printf("saving LAN totals %s: %v", t.path, err)
		return
	}
	t.dirty = false
}

func (t *lanTotals) write() error {
	dir := filepath.Dir(t.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".lan-totals-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(t.lanTotalState)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), t.path)
}
