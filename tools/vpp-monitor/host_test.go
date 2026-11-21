package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.fd.io/govpp/adapter"
)

func hostFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hostGauges(gauges []hostGauge) map[string]float64 {
	out := make(map[string]float64)
	for _, g := range gauges {
		out[g.key] = g.value
	}
	return out
}

func hostFixture(t *testing.T) string {
	root := t.TempDir()
	hostFile(t, root, "proc/stat", "cpu  100 0 0 900 0 0 0 0 0 0\ncpu0 50 0 0 450 0 0 0 0 0 0\ncpu1 50 0 0 450 0 0 0 0 0 0\nintr 1 2 3\n")
	hostFile(t, root, "proc/uptime", "321.50 100.00\n")
	hostFile(t, root, "proc/meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n")
	hostFile(t, root, "sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "1512000\n")
	hostFile(t, root, "sys/class/thermal/thermal_zone0/type", "cpu-thermal\n")
	hostFile(t, root, "sys/class/thermal/thermal_zone0/temp", "53000\n")
	return root
}

func TestHostCPUUseNeedsTwoReadings(t *testing.T) {
	root := hostFixture(t)
	h := &hostReader{root: root}
	status, gauges := h.read()
	if status.Cores != nil || status.CPU != 0 {
		t.Fatalf("first reading = %+v", status)
	}
	if _, ok := hostGauges(gauges)["host/cpu/busy"]; ok {
		t.Fatal("CPU use from one reading")
	}
	// core 0 spends 75 of 100 jiffies working, core 1 is idle apart from 25 of iowait.
	hostFile(t, root, "proc/stat", "cpu  175 0 0 925 0 0 0 0 0 0\ncpu0 125 0 0 475 0 0 0 0 0 0\ncpu1 50 0 0 450 100 0 0 0 0 0\n")
	status, gauges = h.read()
	if status.Cores[0].Busy != 75 || status.Cores[1].Busy != 0 || status.Cores[0].MHz != 1512 || status.Cores[1].MHz != 0 {
		t.Fatalf("cores = %+v", status.Cores)
	}
	if status.CPU != 75 || hostGauges(gauges)["host/cpu/cpu0/busy"] != 75 {
		t.Fatalf("cpu = %v, gauges = %v", status.CPU, gauges)
	}
}

func TestHostSystemValues(t *testing.T) {
	h := &hostReader{root: hostFixture(t)}
	status, gauges := h.read()
	if status.MemTotal != 1000*1024 || status.MemUsed != 600*1024 || status.SwapUsed != 50*1024 {
		t.Fatalf("memory = %+v", status)
	}
	if status.Temps[0].Name != "cpu-thermal" || status.Temps[0].Celsius != 53 || status.UptimeSeconds != 321.5 {
		t.Fatalf("status = %+v", status)
	}
	if status.DiskTotal == 0 {
		t.Fatal("no disk size")
	}
	got := hostGauges(gauges)
	if got["host/temp/thermal_zone0"] != 53 || got["host/mem/used"] != 600*1024 {
		t.Fatalf("gauges = %v", got)
	}
}

func TestHwmonIsUsedOnlyWithoutThermalZones(t *testing.T) {
	root := t.TempDir()
	hostFile(t, root, "sys/class/hwmon/hwmon0/name", "coretemp\n")
	hostFile(t, root, "sys/class/hwmon/hwmon0/temp1_input", "61000\n")
	hostFile(t, root, "sys/class/hwmon/hwmon0/temp1_label", "Package id 0\n")
	h := &hostReader{root: root}
	status, _ := h.read()
	if len(status.Temps) != 1 || status.Temps[0].Name != "coretemp Package id 0" || status.Temps[0].Celsius != 61 {
		t.Fatalf("temps = %+v", status.Temps)
	}
	hostFile(t, root, "sys/class/thermal/thermal_zone0/type", "soc\n")
	hostFile(t, root, "sys/class/thermal/thermal_zone0/temp", "40000\n")
	status, _ = h.read()
	if len(status.Temps) != 1 || status.Temps[0].Name != "soc" {
		t.Fatalf("temps = %+v", status.Temps)
	}
}

func TestPlaceholderTemperaturesAreSkipped(t *testing.T) {
	root := t.TempDir()
	hostFile(t, root, "sys/class/thermal/thermal_zone0/type", "absent\n")
	hostFile(t, root, "sys/class/thermal/thermal_zone0/temp", "-273000\n")
	h := &hostReader{root: root}
	if status, _ := h.read(); len(status.Temps) != 0 {
		t.Fatalf("temps = %+v", status.Temps)
	}
}

func TestMissingSourcesLeaveEmptyValues(t *testing.T) {
	h := &hostReader{root: "/nonexistent-root"}
	status, gauges := h.read()
	if len(gauges) != 0 || status.Cores != nil || status.MemTotal != 0 || status.DiskTotal != 0 {
		t.Fatalf("status = %+v, gauges = %v", status, gauges)
	}
}

// The host is worth watching most when VPP is not running.
func TestHostValuesContinueWhileVPPIsDown(t *testing.T) {
	store := NewStore(tiersFor(1, 10))
	c := NewCollector(Config{Fast: time.Second, Slow: 10 * time.Second, StaleAfter: 30 * time.Second}, store,
		func() (adapter.StatsAPI, error) { return nil, adapter.ErrStatsDisconnected })
	c.host.root = hostFixture(t)
	now := time.Unix(1000, 0)
	c.tick(now, now.Unix(), true)
	got := c.Status()
	if got.State != stateDown || got.Host.MemTotal == 0 || len(got.Host.Temps) != 1 {
		t.Fatalf("status = %+v", got)
	}
}

func TestCounterClassification(t *testing.T) {
	normal := []string{"no error", "replies_sent", "L2 input packets", "L2 flood packets", "L2 learn packets", "L2 output packets",
		"DHCP discover packets sent", "DHCP bind success", "Extract", "ACL permit packets", "checked packets", "request_sent", "Classify hits after chain walk", "DHCPV6 packets relayed to clients"}
	attention := []string{"unknown ethernet type", "unknown_protocol", "rpf_failure", "no translation", "blackholed packets", "ACL deny packets",
		"time_expired", "L2 learn misses", "Warning: packets sent to the handoff trace node!", "DHCP packets which are too big.", "something new from a plugin"}
	for _, reason := range normal {
		if !isNormalCounter(reason) {
			t.Errorf("%q should be normal", reason)
		}
	}
	for _, reason := range attention {
		if isNormalCounter(reason) {
			t.Errorf("%q should need attention", reason)
		}
	}
}
