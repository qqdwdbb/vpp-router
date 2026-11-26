package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func managedCPUService(t *testing.T, existing bool) (*Service, *fakeVPP, *clock, *int) {
	t.Helper()
	s, v, c := newTestService(t)
	dir := filepath.Dir(s.opts.StartConf)
	s.opts.RouterEnv = filepath.Join(dir, "router.env")
	s.opts.UnitFile = filepath.Join(dir, "vpp-router.service")
	s.opts.CPUAffinityFile = filepath.Join(dir, "system.conf.d/90-vpp-router-cpu.conf")
	writeTestFile(t, filepath.Join(s.host.cpuDir(), "online"), "0-7\n")
	writeTestFile(t, s.opts.RouterEnv, "# environment\nSYSTEM_CPUS=0-1,4-7\nKEEP=value\nNICS=(\n)\n")
	writeTestFile(t, s.opts.UnitFile, "[Unit]\nDescription=router\n[Service]\nCPUAffinity=0-7\nExecStart=/usr/local/bin/vpp\n[Install]\nWantedBy=multi-user.target\n")
	if existing {
		writeTestFile(t, s.opts.CPUAffinityFile, "[Manager]\nCPUAffinity=0-1,4-7\n")
	}
	reloads := new(int)
	s.reloadCPU = func() error { *reloads++; return nil }
	t.Cleanup(func() {
		if s.timer != nil {
			s.timer.Stop()
		}
	})
	return s, v, c, reloads
}

func TestWorkerCPUFilesConfirm(t *testing.T) {
	s, _, _, reloads := managedCPUService(t, true)
	state, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: []int{4}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || len(state.Pending.Files) != 4 || *reloads != 1 {
		t.Fatalf("pending %+v reloads %d", state.Pending, *reloads)
	}
	if text := readFile(t, s.opts.RouterEnv); !strings.Contains(text, "SYSTEM_CPUS=0-3,5-7\nKEEP=value\nNICS=(\n)\n") {
		t.Fatal(text)
	}
	if text := readFile(t, s.opts.CPUAffinityFile); !strings.Contains(text, "CPUAffinity=0-3,5-7\n") {
		t.Fatal(text)
	}
	if text := readFile(t, s.opts.UnitFile); strings.Count(text, "CPUAffinity=") != 1 || !strings.Contains(text, "CPUAffinity=0-7\n") {
		t.Fatal(text)
	}
	if _, err := s.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerCPUFilesRollback(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, workers := range [][]int{{4}, nil} {
			s, _, c, reloads := managedCPUService(t, existing)
			env, unit := readFile(t, s.opts.RouterEnv), readFile(t, s.opts.UnitFile)
			if _, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: workers}, "admin"); err != nil {
				t.Fatal(err)
			}
			if len(workers) == 0 {
				if !strings.Contains(readFile(t, s.opts.RouterEnv), "SYSTEM_CPUS=\n") || !strings.Contains(readFile(t, s.opts.CPUAffinityFile), "CPUAffinity=0-7\n") {
					t.Fatal("worker removal did not release CPUs")
				}
			}
			c.t = c.t.Add(2 * time.Minute)
			// Start reads the persisted transaction, including files absent before the change.
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			if s.last.Outcome != "rolled-back" || *reloads != 2 || readFile(t, s.opts.StartConf) != installerConf || readFile(t, s.opts.RouterEnv) != env || readFile(t, s.opts.UnitFile) != unit {
				t.Fatalf("rollback %+v reloads %d", s.last, *reloads)
			}
			if existing {
				if text := readFile(t, s.opts.CPUAffinityFile); text != "[Manager]\nCPUAffinity=0-1,4-7\n" {
					t.Fatal(text)
				}
			} else if _, err := os.Stat(s.opts.CPUAffinityFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("new default file survived rollback: %v", err)
			}
		}
	}
}

func TestWorkerCPUReloadFailureRollsBack(t *testing.T) {
	s, _, _, reloads := managedCPUService(t, true)
	env := readFile(t, s.opts.RouterEnv)
	s.reloadCPU = func() error {
		*reloads++
		if *reloads == 1 {
			return errors.New("reexec failed")
		}
		return nil
	}
	if _, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: []int{4}}, "admin"); err == nil {
		t.Fatal("accepted failed manager reload")
	}
	if *reloads != 2 || s.last.Outcome != "rolled-back" || readFile(t, s.opts.StartConf) != installerConf || readFile(t, s.opts.RouterEnv) != env {
		t.Fatalf("%+v reloads %d", s.last, *reloads)
	}
}

func TestWorkerCPUVerificationFailureRollsBack(t *testing.T) {
	s, fake, _, reloads := managedCPUService(t, true)
	env := readFile(t, s.opts.RouterEnv)
	s.restart = func(string) error {
		fake.start()
		if fake.run == 2 {
			fake.threads = nil
		}
		return nil
	}
	if _, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: []int{4}}, "admin"); err == nil {
		t.Fatal("accepted incorrect running layout")
	}
	if *reloads != 2 || s.last.Outcome != "rolled-back" || readFile(t, s.opts.RouterEnv) != env {
		t.Fatalf("%+v", s.last)
	}
}

func TestWorkerCPURestoreReloadFailureKeepsBackups(t *testing.T) {
	s, _, _, _ := managedCPUService(t, true)
	if _, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: []int{4}}, "admin"); err != nil {
		t.Fatal(err)
	}
	s.reloadCPU = func() error { return errors.New("reexec failed") }
	if _, err := s.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if s.pending == nil || s.last.Outcome != "rollback-failed" {
		t.Fatalf("transaction lost: %+v", s.last)
	}
	if _, err := os.Stat(s.backupPath(s.opts.CPUAffinityFile)); err != nil {
		t.Fatal(err)
	}
	s.reloadCPU = func() error { return nil }
	if _, err := s.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if s.pending != nil || s.last.Outcome != "rolled-back" {
		t.Fatalf("retry failed: %+v", s.last)
	}
}

func TestWorkerCPUIsolationOptIn(t *testing.T) {
	s, _, _, reloads := managedCPUService(t, true)
	writeTestFile(t, s.opts.RouterEnv, "NICS=(\n)\n")
	unit := readFile(t, s.opts.UnitFile)
	if _, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: []int{4}}, "admin"); err != nil {
		t.Fatal(err)
	}
	if *reloads != 0 || len(s.pending.Files) != 1 || readFile(t, s.opts.UnitFile) != unit {
		t.Fatal("changed an installation without managed isolation")
	}
	if _, err := s.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerCPUAddFirstWorker(t *testing.T) {
	s, fake, _, reloads := managedCPUService(t, false)
	writeTestFile(t, s.opts.StartConf, strings.Replace(installerConf, "corelist-workers 2-3", "", 1))
	writeTestFile(t, s.opts.RouterEnv, "SYSTEM_CPUS=\nNICS=(\n)\n")
	writeTestFile(t, s.opts.UnitFile, "[Service]\nExecStart=/usr/local/bin/vpp\n")
	fake.start()
	if _, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: []int{4}}, "admin"); err != nil {
		t.Fatal(err)
	}
	if *reloads != 1 || !strings.Contains(readFile(t, s.opts.UnitFile), "CPUAffinity=0-7\n") || !strings.Contains(readFile(t, s.opts.RouterEnv), "SYSTEM_CPUS=0-3,5-7\n") {
		t.Fatal("first worker did not enable isolation")
	}
	if _, err := s.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, s.opts.CPUAffinityFile), "CPUAffinity=0-3,5-7\n") {
		t.Fatal("default affinity was not kept")
	}
}
