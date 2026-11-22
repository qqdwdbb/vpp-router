package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestUnitFromCgroup(t *testing.T) {
	for text, want := range map[string]string{
		"0::/system.slice/vpp-system.service\n":                               "vpp-system.service",
		"12:pids:/system.slice/vpp-monitor.service\n0::/system.slice/x.scope": "vpp-monitor.service",
		"0::/user.slice/user-1000.slice/session-3.scope\n":                    "",
		"0::/system.slice/vpp-router.service/vpp\n":                           "vpp-router.service",
	} {
		if got := unitFromCgroup(text); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
}

const showOutput = `Id=vpp-router.service
Description=VPP router
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
StateChangeTimestamp=@1800000000
MainPID=1234
MemoryCurrent=104857600
NRestarts=2
Result=success
FragmentPath=/etc/systemd/system/vpp-router.service
After=network-pre.target

Id=vpp-monitor.service
Description=VPP stats dashboard
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
StateChangeTimestamp=@1800000100
MainPID=99
MemoryCurrent=[not set]
NRestarts=0
Result=success
FragmentPath=%s/vpp-monitor.service

Id=nextcloud.service
Description=Nextcloud
LoadState=loaded
ActiveState=failed
SubState=failed
UnitFileState=enabled
StateChangeTimestamp=
MainPID=0
MemoryCurrent=18446744073709551615
NRestarts=0
Result=exit-code
FragmentPath=%s/nextcloud.service

Id=gate.service
Description=Gate
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
MainPID=7
NRestarts=0
Result=success
After=vpp-router.service network.target

Id=old.service
LoadState=masked
`

func newTestMaint(t *testing.T) (*Maint, *Service, *[][]string) {
	t.Helper()
	s, _, _ := newTestService(t)
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "vpp-monitor.service"), "[Service]\nExecStart=/usr/local/bin/vpp-monitor\n")
	writeTestFile(t, filepath.Join(dir, "nextcloud.service"), "[Service]\nExecStart=/usr/bin/php\n")
	writeTestFile(t, filepath.Join(dir, "gate.service"), "[Service]\nExecStart=/usr/local/bin/gate\n")
	writeTestFile(t, filepath.Join(dir, "getty@.service"), "")
	writeTestFile(t, filepath.Join(dir, "README"), "")
	os.Symlink("/dev/null", filepath.Join(dir, "old.service"))
	calls := &[][]string{}
	m := &Maint{s: s, unitDir: dir, extra: []string{"sing-box"}, selfUnit: "vpp-system.service"}
	m.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		*calls = append(*calls, append([]string{name}, args...))
		if name == "systemctl" && args[0] == "show" {
			return []byte(strings.ReplaceAll(showOutput, "%s", dir)), nil
		}
		return nil, nil
	}
	return m, s, calls
}

func TestUnits(t *testing.T) {
	m, _, calls := newTestMaint(t)
	names := m.unitNames()
	want := []string{"gate.service", "nextcloud.service", "sing-box.service", "vpp-monitor.service", "vpp-router.service"}
	if !slices.Equal(names, want) {
		t.Fatalf("names %v, want %v", names, want)
	}
	view, err := m.units(context.Background(), "vpp-monitor.service")
	if err != nil {
		t.Fatal(err)
	}
	if len((*calls)[0]) < 6 || (*calls)[0][4] != "--" {
		t.Fatalf("show call %v", (*calls)[0])
	}
	got := map[string]Unit{}
	for _, u := range view.Units {
		got[u.Name] = u
	}
	if len(got) != 4 {
		t.Fatalf("units %+v", view.Units)
	}
	if u := got["vpp-router.service"]; u.Role != "vpp" || !u.Related || u.Since != 1800000000 || u.Memory != 104857600 || u.Restarts != 2 || u.PID != 1234 {
		t.Errorf("vpp %+v", u)
	}
	if u := got["vpp-monitor.service"]; u.Role != "panel" || !u.Related || u.Memory != 0 {
		t.Errorf("panel %+v", u)
	}
	if u := got["nextcloud.service"]; u.Related || u.Memory != 0 || u.Active != "failed" {
		t.Errorf("nextcloud %+v", u)
	}
	if u := got["gate.service"]; !u.Related {
		t.Errorf("gate is ordered after VPP: %+v", u)
	}
}

func TestUnitAction(t *testing.T) {
	m, s, calls := newTestMaint(t)
	ctx := context.Background()
	if err := m.UnitAction(ctx, "vpp-router.service", "stop", "vpp-monitor.service", "admin"); err == nil {
		t.Error("stopping VPP was allowed")
	}
	if err := m.UnitAction(ctx, "vpp-monitor.service", "stop", "vpp-monitor.service", "admin"); err == nil {
		t.Error("stopping the panel was allowed")
	}
	if err := m.UnitAction(ctx, "ssh.service", "restart", "", "admin"); err == nil {
		t.Error("a unit not listed was restarted")
	}
	if err := m.UnitAction(ctx, "gate.service", "kill", "", "admin"); err == nil {
		t.Error("unknown action")
	}
	*calls = nil
	if err := m.UnitAction(ctx, "nextcloud.service", "start", "", "admin"); err != nil {
		t.Fatal(err)
	}
	last := (*calls)[len(*calls)-1]
	if !slices.Equal(last, []string{"systemctl", "start", "--no-block", "--", "nextcloud.service"}) {
		t.Errorf("start ran %v", last)
	}
	if err := m.UnitAction(ctx, "vpp-monitor.service", "restart", "vpp-monitor.service", "admin"); err != nil {
		t.Fatal(err)
	}
	last = (*calls)[len(*calls)-1]
	if last[0] != "systemd-run" || !slices.Contains(last, "--on-active") || last[len(last)-1] != "vpp-monitor.service" {
		t.Errorf("panel restart ran %v", last)
	}

	writeTestFile(t, s.opts.OtherPending, "{}")
	if err := m.UnitAction(ctx, "vpp-router.service", "restart", "", "admin"); err == nil || !strings.Contains(err.Error(), "确认") {
		t.Errorf("VPP restarted while a change waits: %v", err)
	}
	if err := m.UnitAction(ctx, "", "reboot", "", "admin"); err == nil {
		t.Error("rebooted while a change waits")
	}
	os.Remove(s.opts.OtherPending)
	*calls = nil
	if err := m.UnitAction(ctx, "vpp-router.service", "restart", "", "admin"); err != nil {
		t.Fatal(err)
	}
	if last := (*calls)[len(*calls)-1]; !slices.Equal(last, []string{"systemctl", "restart", "--no-block", "--", "vpp-router.service"}) {
		t.Errorf("VPP restart ran %v", last)
	}
	if err := m.UnitAction(ctx, "", "reboot", "", "admin"); err != nil {
		t.Fatal(err)
	}
	if last := (*calls)[len(*calls)-1]; last[0] != "systemd-run" || last[len(last)-1] != "reboot" {
		t.Errorf("reboot ran %v", last)
	}
}

const journalOutput = `{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1800000000000000","PRIORITY":"6","SYSLOG_IDENTIFIER":"vpp-system","MESSAGE":"audit: admin: restart gate"}
{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1800000001000000","PRIORITY":"3","_SYSTEMD_UNIT":"gate.service","MESSAGE":"Gate failed"}
{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"1800000002000000","_TRANSPORT":"kernel","MESSAGE":[104,105,255]}
not json
{"__CURSOR":"c4","__REALTIME_TIMESTAMP":"1800000003000000","PRIORITY":"6","SYSLOG_IDENTIFIER":"vpp","MESSAGE":"Audit again"}
`

func TestParseJournal(t *testing.T) {
	view := parseJournal([]byte(journalOutput), LogQuery{}, 10)
	if len(view.Entries) != 4 || view.Cursor != "c4" || view.Truncated {
		t.Fatalf("%+v", view)
	}
	if e := view.Entries[1]; e.Source != "gate" || e.Priority != 3 || e.Time != 1800000001000000 {
		t.Errorf("unit source %+v", e)
	}
	if e := view.Entries[2]; e.Source != "kernel" || e.Message != "hi�" || e.Priority != 6 {
		t.Errorf("byte message %+v", e)
	}
	view = parseJournal([]byte(journalOutput), LogQuery{Grep: "AUDIT", After: "c0"}, 1)
	if len(view.Entries) != 1 || view.Entries[0].Message != "Audit again" || !view.Truncated || view.Cursor != "c4" {
		t.Errorf("grep %+v", view)
	}
	view = parseJournal(nil, LogQuery{After: "c9"}, 10)
	if view.Cursor != "c9" || len(view.Entries) != 0 {
		t.Errorf("nothing new keeps the cursor: %+v", view)
	}
}

func TestJournalArgs(t *testing.T) {
	m, _, _ := newTestMaint(t)
	ctx := context.Background()
	q, err := parseLogQuery(url.Values{"unit": {"gate.service"}, "lines": {"50"}, "since": {"1800000000"}, "priority": {"4"}, "grep": {"x"}, "after": {"c1"}, "boot": {"1"}})
	if err != nil {
		t.Fatal(err)
	}
	args, err := m.journalArgs(ctx, q, 50, "json")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--unit gate.service", "--boot", "--since @1800000000", "--priority 4", "--after-cursor c1", "--lines 20000"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q lacks %q", joined, want)
		}
	}
	if _, err := m.journalArgs(ctx, LogQuery{Unit: "ssh.service", Priority: -1}, 10, "json"); err == nil {
		t.Error("a unit not listed was read")
	}
	if args, _ := m.journalArgs(ctx, LogQuery{Unit: "kernel", Priority: -1}, 10, "json"); !slices.Contains(args, "--dmesg") {
		t.Errorf("kernel %v", args)
	}
	for _, bad := range []url.Values{{"lines": {"0"}}, {"priority": {"8"}}, {"since": {"x"}}, {"grep": {strings.Repeat("a", 201)}}} {
		if _, err := parseLogQuery(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestCheckHost(t *testing.T) {
	for _, good := range []string{"1.1.1.1", "2001:db8::1", "example.com", "example.com.", "a", "xn--fiq.cn", "_dmarc.example.com"} {
		if err := checkHost(good); err != nil {
			t.Errorf("%q refused", good)
		}
	}
	for _, bad := range []string{"", "-c1", "a b", "a;b", "example.com-", ".example", strings.Repeat("a", 254), "$(x)"} {
		if err := checkHost(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, bad := range []string{"-eth0", "eth 0", ""} {
		if interfacePattern.MatchString(bad) {
			t.Errorf("interface %q accepted", bad)
		}
	}
}

func TestParseServer(t *testing.T) {
	for text, want := range map[string]string{"1.1.1.1": "1.1.1.1:53", "10.0.0.1:5353": "10.0.0.1:5353", "2001:db8::1": "[2001:db8::1]:53", "[2001:db8::1]:54": "[2001:db8::1]:54"} {
		got, err := parseServer(text)
		if err != nil || got.String() != want {
			t.Errorf("%q: %v %v", text, got, err)
		}
	}
	if _, err := parseServer("dns.google"); err == nil {
		t.Error("a name was accepted")
	}
}

func TestParseInterfaceNames(t *testing.T) {
	text := `              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
local0                            0     down          0/0/0/0
loop0                             3      up          9000/0/0/0     rx packets                    12
                                                                    tx packets                    10
port0                             1      up          9000/0/0/0
port0.100                         2      up           0/0/0/0
`
	if got := parseInterfaceNames(text); !slices.Equal(got, []string{"loop0", "port0", "port0.100"}) {
		t.Errorf("%v", got)
	}
}

func TestWriteBackup(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc/vpp")
	writeTestFile(t, filepath.Join(etc, "router.conf"), "unix {}\n")
	writeTestFile(t, filepath.Join(etc, "wireguard/wg0.conf"), "[Interface]\n")
	os.Symlink("router.conf", filepath.Join(etc, "startup.conf"))
	writeTestFile(t, filepath.Join(dir, "unit.service"), "[Service]\n")
	var buf bytes.Buffer
	paths := []string{etc, filepath.Join(dir, "unit.service"), filepath.Join(dir, "missing"), etc}
	if err := writeBackup(&buf, paths, time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		if _, dup := files[h.Name]; dup {
			t.Errorf("%s twice", h.Name)
		}
		files[h.Name] = string(data)
		if h.Typeflag == tar.TypeSymlink {
			files[h.Name] = "-> " + h.Linkname
		}
	}
	prefix := strings.TrimPrefix(dir, "/")
	if files[prefix+"/etc/vpp/router.conf"] != "unix {}\n" || files[prefix+"/etc/vpp/wireguard/wg0.conf"] != "[Interface]\n" ||
		files[prefix+"/etc/vpp/startup.conf"] != "-> router.conf" || files[prefix+"/unit.service"] != "[Service]\n" {
		t.Errorf("%v", files)
	}
	if !strings.Contains(files["MANIFEST.txt"], filepath.Join(etc, "router.conf")+" 8") {
		t.Errorf("manifest %q", files["MANIFEST.txt"])
	}
}
