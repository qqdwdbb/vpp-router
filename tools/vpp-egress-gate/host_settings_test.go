package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func useHostSettings(t *testing.T) string {
	t.Helper()
	useDeviceDirs(t)
	useFakeSysctl(t)
	previous := hostSettingsFile
	hostSettingsFile = filepath.Join(deviceStateDir, "host-settings.json")
	t.Cleanup(func() { hostSettingsFile = previous })
	return hostSettingsFile
}

func writeSysctl(t *testing.T, name, value string) {
	t.Helper()
	path := filepath.Join(linuxSysctlRoot, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readHostSettings(t *testing.T, path string) []hostSetting {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Settings []hostSetting `json:"settings"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	return record.Settings
}

func TestHostSettingsKeepTheFirstValueInOrder(t *testing.T) {
	path := useHostSettings(t)
	writeSysctl(t, "net/ipv4/ip_forward", "0")
	writeSysctl(t, "net/ipv4/conf/all/rp_filter", "2")
	for _, step := range []struct{ name, value string }{
		{"net/ipv4/ip_forward", "1"},
		{"net/ipv4/conf/all/rp_filter", "0"},
		{"net/ipv4/ip_forward", "0"},
		{"net/ipv4/ip_forward", "1"},
	} {
		if err := setSysctl(step.name, step.value); err != nil {
			t.Fatal(err)
		}
	}
	got := readHostSettings(t, path)
	want := []hostSetting{{"net/ipv4/ip_forward", "0", "1"}, {"net/ipv4/conf/all/rp_filter", "2", "0"}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v", got)
	}
}

func TestHostSettingsRecordNothingWithoutAChange(t *testing.T) {
	path := useHostSettings(t)
	writeSysctl(t, "net/ipv4/ip_forward", "1")
	if err := setSysctl("net/ipv4/ip_forward", "1"); err != nil {
		t.Fatal(err)
	}
	if err := setSysctl("net/ipv4/conf/gone/rp_filter", "0"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a record without a change: %v", err)
	}
}

func TestSettingStopsWhenItCannotBeRecorded(t *testing.T) {
	path := useHostSettings(t)
	writeSysctl(t, "net/ipv4/ip_forward", "0")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setSysctl("net/ipv4/ip_forward", "1"); err == nil {
		t.Fatal("changed a setting without recording it")
	}
	data, _ := os.ReadFile(filepath.Join(linuxSysctlRoot, "net/ipv4/ip_forward"))
	if string(data) != "0\n" {
		t.Fatalf("value changed to %q", data)
	}
}

func TestExitRPFilterIsRecorded(t *testing.T) {
	path := useHostSettings(t)
	writeSysctl(t, "net/ipv4/conf/wg9/rp_filter", "2")
	writeSysctl(t, "net/ipv4/conf/all/rp_filter", "0")
	note := ensureLinuxExitRPFilter(Mapping{Via: "172.30.10.2", LinuxExit: &LinuxExit{InputInterface: "tap-gone", Interface: "wg9"}})
	if note != "" {
		t.Fatal(note)
	}
	got := readHostSettings(t, path)
	if len(got) != 1 || got[0] != (hostSetting{"net/ipv4/conf/wg9/rp_filter", "2", "0"}) {
		t.Fatalf("got %+v", got)
	}
}
