package gate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncOnStartAppliesTheConfiguration(t *testing.T) {
	useDeviceDirs(t)
	respond, _ := fakeLinuxTools(t)
	respond("systemctl is-system-running", "out", "running\n")
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	path := writeDualStackConfig(t, exitRule("wg1"))
	if err := SyncOnStart(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(deviceStateDir, "gate.json")); err != nil {
		t.Fatal(err)
	}
}

// systemctl reports these with a failing exit status, and they are still not a boot.
func TestSyncOnStartTreatsADegradedSystemAsRunning(t *testing.T) {
	useDeviceDirs(t)
	respond, _ := fakeLinuxTools(t)
	respond("systemctl is-system-running", "out", "degraded\n")
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	if err := SyncOnStart(writeDualStackConfig(t, exitRule("wg1"))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(deviceStateDir, "gate.json")); err != nil {
		t.Fatal(err)
	}
}

func TestSyncOnStartLeavesABootToTheLastSync(t *testing.T) {
	for _, state := range []string{"initializing", "starting"} {
		t.Run(state, func(t *testing.T) {
			useDeviceDirs(t)
			respond, calls := fakeLinuxTools(t)
			respond("systemctl is-system-running", "out", state+"\n")
			if err := SyncOnStart(writeDualStackConfig(t, exitRule("wg1"))); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(deviceStateDir, "gate.json")); !os.IsNotExist(err) {
				t.Fatalf("a boot synced: %v", err)
			}
			if strings.Contains(calls(), "ip ") || strings.Contains(calls(), "nft ") {
				t.Fatalf("a boot touched the host:\n%s", calls())
			}
		})
	}
}

func TestSyncOnStartWithoutAConfiguration(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("systemctl is-system-running", "out", "running\n")
	if err := SyncOnStart(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(calls(), "nft ") {
		t.Fatalf("touched the host:\n%s", calls())
	}
}

func TestSyncOnStartKeepsTheLastSyncWhenTheConfigurationIsBad(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("systemctl is-system-running", "out", "running\n")
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	if err := SyncOnStart(writeDualStackConfig(t, exitRule("wg1"))); err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(deviceStateDir, "gate.json")
	before, err := os.ReadFile(generated)
	if err != nil {
		t.Fatal(err)
	}
	journal, _ := os.ReadFile(filepath.Join(deviceStateDir, "devices.json"))
	applied := calls()
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{half an edit"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = SyncOnStart(bad)
	if err == nil || !strings.Contains(err.Error(), "last successful sync") {
		t.Fatalf("got %v", err)
	}
	after, _ := os.ReadFile(generated)
	journalAfter, _ := os.ReadFile(filepath.Join(deviceStateDir, "devices.json"))
	if string(after) != string(before) || string(journalAfter) != string(journal) {
		t.Fatal("a bad configuration changed what the last sync left")
	}
	// Asking systemctl whether the system is booting changes nothing.
	if added := strings.TrimPrefix(calls(), applied); strings.TrimSpace(added) != "systemctl is-system-running" {
		t.Fatalf("a bad configuration touched the host:\n%s", added)
	}
}

func TestSyncOnStartAppliesTheRestWhenAListFileIsBad(t *testing.T) {
	useDeviceDirs(t)
	respond, _ := fakeLinuxTools(t)
	respond("systemctl is-system-running", "out", "running\n")
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	respond("ip -d -j link show dev tap-wg2", "out", strings.ReplaceAll(fakeTapLink, "tap-wg1", "tap-wg2"))
	gone := exitRule("wg1")
	delete(gone, "domains")
	gone["domain_files"] = []any{filepath.Join(t.TempDir(), "gone.domains")}
	path := writeDualStackConfig(t, gone, exitRule("wg2"))
	if err := SyncDevices(path, true); err == nil {
		t.Fatal("a plain sync accepted a missing list file")
	}
	out := captureLog(t)
	if err := SyncOnStart(path); err != nil {
		t.Fatalf("a bad list file stopped the rest: %v", err)
	}
	generated, err := os.ReadFile(filepath.Join(deviceStateDir, "gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The rule keeps its device, so that the file coming back needs only a restart.
	for _, want := range []string{"tap2100", "tap2101", "wg2.example"} {
		if !strings.Contains(string(generated), want) {
			t.Fatalf("%q missing from:\n%s", want, generated)
		}
	}
	if !strings.Contains(out.String(), "list file ignored") {
		t.Fatal(out.String())
	}
	if syncIgnoresListProblems {
		t.Fatal("the next sync would be lenient too")
	}
}
