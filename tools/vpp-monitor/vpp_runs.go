package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const vppRunsKept = 20

// VPPRun is one start of VPP. PreviousSeconds is how long the run before it lasted, downtime
// included, or 0 when it is the first run seen.
type VPPRun struct {
	Boot            int64 `json:"boot"`
	Started         int64 `json:"started"`
	PreviousSeconds int64 `json:"previous_seconds"`
}

// vppRuns remembers VPP's starts across restarts of both programs, as stability is about
// history that a process's own uptime loses. The file is written only when VPP has restarted.
type vppRuns struct {
	path string

	mu   sync.Mutex
	runs []VPPRun
}

func loadVPPRuns(path string) *vppRuns {
	log_ := &vppRuns{path: path}
	if path == "" {
		return log_
	}
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &log_.runs)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("VPP run history %s is unreadable and starts again: %v", path, err)
		log_.runs = nil
	}
	return log_
}

// observe records a run not seen before. boot only identifies the run, as a host without a
// battery clock can have the wrong time when VPP starts. Started comes from VPP's own
// monotonic uptime, so it is right whatever the clock said then.
func (l *vppRuns) observe(boot int64, uptime float64, now time.Time) {
	if boot <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := len(l.runs); n > 0 {
		if difference := boot - l.runs[n-1].Boot; difference >= -2 && difference <= 2 {
			return
		}
	}
	run := VPPRun{Boot: boot, Started: now.Add(-time.Duration(uptime * float64(time.Second))).Unix()}
	if n := len(l.runs); n > 0 && run.Started > l.runs[n-1].Started {
		run.PreviousSeconds = run.Started - l.runs[n-1].Started
	}
	l.runs = append(l.runs, run)
	if len(l.runs) > vppRunsKept {
		l.runs = l.runs[len(l.runs)-vppRunsKept:]
	}
	if len(l.runs) > 1 {
		log.Printf("VPP restarted, run %d in the history", len(l.runs))
	}
	l.save()
}

func (l *vppRuns) save() {
	if l.path == "" {
		return
	}
	data, err := json.Marshal(l.runs)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		log.Printf("saving VPP run history: %v", err)
		return
	}
	temp := l.path + ".new"
	if err := os.WriteFile(temp, data, 0o600); err == nil {
		err = os.Rename(temp, l.path)
		if err != nil {
			log.Printf("saving VPP run history: %v", err)
		}
	} else {
		log.Printf("saving VPP run history: %v", err)
	}
}

// snapshot returns the runs newest first and how many restarts they hold.
func (l *vppRuns) snapshot() ([]VPPRun, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	runs := make([]VPPRun, 0, len(l.runs))
	for i := len(l.runs) - 1; i >= 0; i-- {
		runs = append(runs, l.runs[i])
	}
	restarts := len(l.runs) - 1
	if restarts < 0 {
		restarts = 0
	}
	return runs, restarts
}
