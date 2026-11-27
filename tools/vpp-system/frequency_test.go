package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFrequencyFloorWaitsForQueuedKernelUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scaling_min_freq")
	writeTestFile(t, path, "408000\n")
	done := make(chan error, 1)
	go func() { time.Sleep(10 * time.Millisecond); done <- os.WriteFile(path, []byte("1200000\n"), 0o644) }()
	if actual := waitFrequencyFloor(path, 1200000, time.Second); actual != 1200000 {
		t.Fatalf("readback %d", actual)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if actual := waitFrequencyFloor(path, 1800000, 5*time.Millisecond); actual != 1200000 {
		t.Fatalf("timeout readback %d", actual)
	}
	writeTestFile(t, path, "1800000\n")
	if actual := waitFrequencyFloor(path, 1200000, time.Second); actual != 1800000 {
		t.Fatalf("higher effective floor %d", actual)
	}
}

func frequencyService(t *testing.T) (*Service, string) {
	t.Helper()
	s, _, _ := newTestService(t)
	dir := filepath.Join(s.host.cpuDir(), "cpufreq", "policy2")
	for name, text := range map[string]string{
		"cpuinfo_min_freq": "408000", "cpuinfo_max_freq": "2256000",
		"scaling_min_freq": "408000", "scaling_max_freq": "2256000",
		"scaling_available_frequencies": "2256000 1608000 1200000 408000",
	} {
		writeTestFile(t, filepath.Join(dir, name), text+"\n")
	}
	return s, dir
}

func TestFrequencyFloorPreservesScalingAndRestoresOriginal(t *testing.T) {
	s, dir := frequencyService(t)
	state, err := s.SetFrequencyFloor("policy2", 1200000, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.FrequencyFloors["policy2"] != 1200000 || readTrim(filepath.Join(dir, "scaling_min_freq")) != "1200000" {
		t.Fatal(state.FrequencyFloors)
	}
	if readTrim(filepath.Join(dir, "scaling_governor")) != "performance" || readTrim(filepath.Join(dir, "scaling_max_freq")) != "2256000" {
		t.Fatal("changed governor or ceiling")
	}
	if _, err := s.SetFrequencyFloor("policy2", 1608000, "admin"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(s.opts.ConfigFile)
	if err != nil || cfg.FrequencyFloors["policy2"].OriginalKHz != 408000 {
		t.Fatalf("%+v %v", cfg, err)
	}
	if _, err := s.SetFrequencyFloor("policy2", 0, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(s.cfg.FrequencyFloors) != 0 || readTrim(filepath.Join(dir, "scaling_min_freq")) != "408000" {
		t.Fatal("original limit not restored")
	}
}

func TestFrequencyFloorRejectsInvalidPolicyAndLimits(t *testing.T) {
	s, dir := frequencyService(t)
	for _, request := range []struct {
		policy string
		khz    int
	}{
		{"policy2", -1}, {"policy2", 100000}, {"policy2", 2400000}, {"policy2", 1300000},
		{"../policy2", 1200000}, {"policy999", 1200000},
	} {
		if _, err := s.SetFrequencyFloor(request.policy, request.khz, "admin"); err == nil {
			t.Fatalf("accepted %+v", request)
		}
	}
	if readTrim(filepath.Join(dir, "scaling_min_freq")) != "408000" || len(s.cfg.FrequencyFloors) != 0 {
		t.Fatal("failed validation changed settings")
	}
	writeTestFile(t, filepath.Join(dir, "scaling_max_freq"), "1200000\n")
	if _, err := s.SetFrequencyFloor("policy2", 1608000, "admin"); err == nil {
		t.Fatal("ignored current frequency ceiling")
	}
}

func TestFrequencyFloorSaveFailureRestoresKernel(t *testing.T) {
	s, dir := frequencyService(t)
	block := filepath.Join(t.TempDir(), "file")
	writeTestFile(t, block, "not a directory")
	s.opts.ConfigFile = filepath.Join(block, "system.json")
	if _, err := s.SetFrequencyFloor("policy2", 1200000, "admin"); err == nil {
		t.Fatal("save should fail")
	}
	if readTrim(filepath.Join(dir, "scaling_min_freq")) != "408000" || len(s.cfg.FrequencyFloors) != 0 {
		t.Fatal("failed save left a live guard")
	}
}

func TestFrequencyFloorStartAndGovernorReapply(t *testing.T) {
	s, dir := frequencyService(t)
	if _, err := s.SetFrequencyFloor("policy2", 1200000, "admin"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "scaling_min_freq"), "408000\n")
	again, err := NewService(s.opts, s.dial)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	if readTrim(filepath.Join(dir, "scaling_min_freq")) != "1200000" {
		t.Fatal("floor not restored at service start")
	}
	writeTestFile(t, filepath.Join(dir, "scaling_min_freq"), "408000\n")
	if _, err := again.SetGovernor("policy2", "schedutil", "admin"); err != nil {
		t.Fatal(err)
	}
	if readTrim(filepath.Join(dir, "scaling_min_freq")) != "1200000" {
		t.Fatal("governor change did not establish guard")
	}
}

func TestFrequencyGuardCommandAndPartialFailure(t *testing.T) {
	s, dir := frequencyService(t)
	s.cfg.FrequencyFloors = map[string]frequencyFloor{"policy2": {MinKHz: 1200000, OriginalKHz: 408000}}
	if err := s.cfg.save(s.opts.ConfigFile); err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", s.opts.ConfigFile, "--sysfs", s.opts.Sysfs}
	if err := runFrequencyGuard(args); err != nil {
		t.Fatal(err)
	}
	if readTrim(filepath.Join(dir, "scaling_min_freq")) != "1200000" {
		t.Fatal("guard command did not apply floor")
	}
	writeTestFile(t, filepath.Join(dir, "scaling_min_freq"), "408000\n")
	s.cfg.FrequencyFloors["policy999"] = frequencyFloor{MinKHz: 1200000}
	if err := s.cfg.save(s.opts.ConfigFile); err != nil {
		t.Fatal(err)
	}
	if err := runFrequencyGuard(args); err == nil {
		t.Fatal("accepted absent policy")
	}
	if readTrim(filepath.Join(dir, "scaling_min_freq")) != "408000" {
		t.Fatal("partial guard application not rolled back")
	}
	if err := runFrequencyGuard(append(args, "unexpected")); err == nil {
		t.Fatal("accepted positional argument")
	}
}

func TestFrequencyGuardFailureRemainsVisibleAndSkipsGovernor(t *testing.T) {
	s, dir := frequencyService(t)
	s.cfg.FrequencyFloors = map[string]frequencyFloor{"policy2": {MinKHz: 1300000}}
	s.cfg.Governors = map[string]string{"policy2": "schedutil"}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if readTrim(filepath.Join(dir, "scaling_governor")) != "performance" {
		t.Fatal("changed governor despite failed guard")
	}
	if !strings.Contains(strings.Join(s.State().Warnings, " "), "最低频率保护未生效") {
		t.Fatal("failed guard is invisible")
	}
	if _, err := s.SetGovernor("policy2", "schedutil", "admin"); err == nil {
		t.Fatal("accepted governor change without requested guard")
	}
}

func TestFrequencyFloorAPIAndContinuousDriver(t *testing.T) {
	s, dir := frequencyService(t)
	if err := os.Remove(filepath.Join(dir, "scaling_available_frequencies")); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/system/frequency-floor", strings.NewReader(`{"policy":"policy2","min_khz":1300000}`))
	response := httptest.NewRecorder()
	s.Handler(nil).ServeHTTP(response, request)
	if response.Code != 200 || readTrim(filepath.Join(dir, "scaling_min_freq")) != "1300000" {
		t.Fatalf("%d %s", response.Code, response.Body)
	}
}
