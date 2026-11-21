package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.fd.io/govpp/adapter"
)

func TestRestartsAreCountedAcrossMonitorRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "runs.json")
	now := time.Unix(100000, 0)
	runs := loadVPPRuns(path)
	runs.observe(99000, 1000, now)
	runs.observe(99001, 1010, now.Add(10*time.Second)) // the same run, clock adjusted
	if list, restarts := runs.snapshot(); len(list) != 1 || restarts != 0 || list[0].Started != 99000 {
		t.Fatalf("%+v %d", list, restarts)
	}
	reloaded := loadVPPRuns(path)
	reloaded.observe(99000, 2000, now.Add(1000*time.Second))
	if _, restarts := reloaded.snapshot(); restarts != 0 {
		t.Fatalf("a monitor restart counted as a VPP restart: %d", restarts)
	}
	reloaded.observe(105000, 30, now.Add(5030*time.Second))
	list, restarts := reloaded.snapshot()
	if restarts != 1 || list[0].Boot != 105000 || list[0].Started != 105000 || list[0].PreviousSeconds != 6000 || list[1].Boot != 99000 {
		t.Fatalf("%+v %d", list, restarts)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
}

func TestRunHistoryIsBounded(t *testing.T) {
	runs := loadVPPRuns("")
	now := time.Unix(1000000, 0)
	for i := int64(0); i < vppRunsKept+7; i++ {
		runs.observe(1000+i*100, 1, now.Add(time.Duration(i)*time.Hour))
	}
	list, restarts := runs.snapshot()
	if len(list) != vppRunsKept || restarts != vppRunsKept-1 || list[0].Boot != 1000+(vppRunsKept+6)*100 {
		t.Fatalf("%d runs, %d restarts, newest %d", len(list), restarts, list[0].Boot)
	}
}

func TestCorruptRunHistoryStartsAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.json")
	os.WriteFile(path, []byte("not json"), 0o600)
	runs := loadVPPRuns(path)
	runs.observe(5000, 1, time.Unix(6000, 0))
	if list, _ := runs.snapshot(); len(list) != 1 {
		t.Fatalf("%+v", list)
	}
	runs.observe(0, 1, time.Unix(6000, 0))
	if list, _ := runs.snapshot(); len(list) != 1 {
		t.Fatalf("a missing boot time was recorded: %+v", list)
	}
}

func TestUptimeAndRestartsReachTheStatus(t *testing.T) {
	f := &fakeStats{slow: []adapter.StatEntry{entry("/sys/boottime", adapter.ScalarStat(990)), entry("/sys/last_update", adapter.ScalarStat(20))}}
	c, now := newTestCollector(f)
	c.runs = loadVPPRuns("")
	stepSlow(c, now)
	got := c.Status()
	if got.VPPUptimeSeconds != 20 || got.VPPRestarts != 0 || len(got.VPPRuns) != 1 || got.VPPRuns[0].Started != now.Unix()-20 {
		t.Fatalf("%+v", got)
	}
	f.slow = []adapter.StatEntry{entry("/sys/boottime", adapter.ScalarStat(5000)), entry("/sys/last_update", adapter.ScalarStat(3))}
	stepSlow(c, now)
	if got := c.Status(); got.VPPRestarts != 1 || got.VPPUptimeSeconds != 3 {
		t.Fatalf("%+v", got)
	}
}
