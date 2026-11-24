package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const installerFile = `# 由 vpp-router-install.sh 生成
set interface promiscuous on eth0
set interface state eth0 up
create sub-interface eth0 100 dot1q 100 exact-match
set interface mtu packet 1500 eth0.100
set interface state eth0.100 up

# LAN：桥域 1，BVI loop0 为网关
create bridge-domain 1
create loopback interface mac 02:00:00:00:00:01 instance 0
set interface l2 bridge loop0 1 bvi
set interface mtu packet 1500 loop0
set interface ip address loop0 10.61.30.1/24
set interface state loop0 up
set int l2 bridge eth0 1

# WAN
set interface ip address eth0.100 10.61.10.2/24
ip route add 0.0.0.0/0 via 10.61.10.1 eth0.100

nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384
nat44 ei add interface address eth0.100
set interface nat44 ei out eth0.100 output-feature
`

func pfx(text string) netip.Prefix { return netip.MustParsePrefix(text) }

func installerLive() *liveState {
	return &liveState{
		Bridges: map[uint32]bool{1: true},
		Interfaces: []*liveInterface{
			{Index: 0, Name: "local0"},
			{Index: 1, Name: "eth0", Hardware: true, Up: true, Link: true, MTU: 9000, Bridge: 1},
			{Index: 2, Name: "eth0.100", Parent: "eth0", Sub: true, SubID: 100, VLAN: 100, Exact: true, Plain: true, Up: true, MTU: 1500, Addresses: []netip.Prefix{pfx("10.61.10.2/24")}},
			{Index: 3, Name: "loop0", Hardware: true, Up: true, MTU: 1500, Addresses: []netip.Prefix{pfx("10.61.30.1/24")}, Bridge: 1, BVI: true},
			{Index: 4, Name: "wg0", Hardware: true, Up: true, MTU: 1420, Addresses: []netip.Prefix{pfx("10.9.0.1/24")}},
			{Index: 5, Name: "eth1", Hardware: true, MTU: 1500},
		},
		NAT: natEI,
	}
}

type fakeSystem struct {
	live      *liveState
	commands  []string
	failOn    string
	restarts  int
	readyErr  error
	stampNow  fileStamp
	readError error
	reads     func() *liveState
}

func (f *fakeSystem) cli(command string) (string, error) {
	f.commands = append(f.commands, command)
	if f.failOn != "" && command == f.failOn {
		return "", errors.New("failed: " + command)
	}
	return "", nil
}
func (f *fakeSystem) read() (*liveState, error) {
	if f.reads != nil {
		return f.reads(), nil
	}
	return f.live, f.readError
}
func (f *fakeSystem) restart(string) error          { f.restarts++; return nil }
func (f *fakeSystem) ready(string, fileStamp) error { return f.readyErr }
func (f *fakeSystem) stamp() (fileStamp, error)     { return f.stampNow, nil }

func setup(t *testing.T, content string, unit string) (*Service, *fakeSystem, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "router.vpp")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sys := &fakeSystem{live: installerLive(), stampNow: fileStamp{Ino: 1}}
	s, err := NewService(Options{CLIFile: path, VPPUnit: unit, StateDir: filepath.Join(dir, "state"), Confirm: time.Minute}, sys)
	if err != nil {
		t.Fatal(err)
	}
	s.sleep = func(time.Duration) {}
	t.Cleanup(func() {
		if s.timer != nil {
			s.timer.Stop()
		}
	})
	return s, sys, path
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseKeepsTheFile(t *testing.T) {
	for _, text := range []string{installerFile, "", "set interface state eth0 up", "a\r\nb\n"} {
		if got := parseCLI(text).String(); got != strings.ReplaceAll(text, "\r", "") {
			t.Errorf("round trip changed %q into %q", text, got)
		}
	}
	file := parseCLI(installerFile)
	if got := file.own("eth0", lineBridge); len(got) != 1 {
		t.Errorf("abbreviated bridge line not understood: %v", got)
	}
	if got := file.own("loop0", lineLoopback); len(got) != 1 {
		t.Errorf("loopback with mac and instance not understood")
	}
	if refs := file.references("eth0.100"); len(refs) != 0 {
		t.Errorf("references of eth0.100: %d, want none: the NAT lines and the default route are its own", len(refs))
	}
	if !file.mentions("eth0") || file.mentions("wg0") {
		t.Error("mentions")
	}
}

func TestCLIFileFromConfig(t *testing.T) {
	for text, want := range map[string]string{
		"unix {\n  nodaemon\n  startup-config /etc/vpp/router.vpp\n}\n": "/etc/vpp/router.vpp",
		"unix { exec /etc/vpp/rk3588.vpp }":                                "/etc/vpp/rk3588.vpp",
		"unix {\n # startup-config /old\n}":                             "",
	} {
		if got := cliFileFromConfig(text); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
}

func TestSetAddressesAndRollback(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	state, err := s.SetAddresses("loop0", []string{"192.168.9.1/24", "fd00::1/64"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || state.SecondsRemaining <= 0 {
		t.Fatal("no pending change")
	}
	want := []string{
		"set interface ip address del loop0 10.61.30.1/24",
		"set interface ip address loop0 192.168.9.1/24",
		"set interface ip address loop0 fd00::1/64",
	}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("commands %q", sys.commands)
	}
	got := read(t, path)
	if !strings.Contains(got, "set interface mtu packet 1500 loop0\nset interface ip address loop0 192.168.9.1/24\nset interface ip address loop0 fd00::1/64\nset interface state loop0 up\n") {
		t.Fatalf("addresses not replaced in place:\n%s", got)
	}
	if _, err := s.SetMTU("loop0", 1400, "admin"); err == nil {
		t.Fatal("a second change was accepted while one waits")
	}
	sys.commands = nil
	if _, err := s.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	want = []string{
		"set interface ip address del loop0 fd00::1/64",
		"set interface ip address del loop0 192.168.9.1/24",
		"set interface ip address loop0 10.61.30.1/24",
	}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("undo commands %q", sys.commands)
	}
	if read(t, path) != installerFile {
		t.Fatal("file not restored")
	}
	if s.last.Outcome != "rolled-back" || s.pending != nil {
		t.Fatalf("last %+v", s.last)
	}
}

func TestAddressRefusals(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	for name, addresses := range map[string][]string{
		"eth0":     {"10.0.0.1/24"},    // in a bridge
		"wg0":      {"10.9.0.2/24"},    // not in the file
		"eth1":     {"10.61.30.2/24"}, // overlaps loop0
		"eth0.100": {"10.61.10.0/24"}, // network address
		"loop0":    {"10.61.30.1/24"}, // unchanged
		"eth0.200": {"10.0.0.1/24"},    // does not exist
		"eth1 ":    {"not an address"}, // does not exist either
	} {
		if _, err := s.SetAddresses(name, addresses, "admin"); err == nil {
			t.Errorf("%s %v accepted", name, addresses)
		}
	}
	if len(sys.commands) != 0 || read(t, path) != installerFile {
		t.Fatal("a refused change did something")
	}
}

func TestAddressOnUnusedPortGoesAtTheEnd(t *testing.T) {
	s, _, path := setup(t, installerFile, "")
	if _, err := s.SetAddresses("eth1", []string{"10.1.0.1/24"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, path); !strings.HasSuffix(got, "output-feature\nset interface ip address eth1 10.1.0.1/24\n") {
		t.Fatalf("got:\n%s", got)
	}
	if _, err := s.Confirm("admin"); err != nil || s.pending != nil || s.last.Outcome != "confirmed" {
		t.Fatal("confirm", err)
	}
	if _, err := os.Stat(s.backupPath()); !os.IsNotExist(err) {
		t.Fatal("backup kept after confirmation")
	}
}

func TestBridgeLeaveAndJoin(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	if _, err := s.SetBridge("eth0.100", 1, false, "admin"); err == nil {
		t.Fatal("joined a bridge with an address")
	}
	if _, err := s.SetBridge("eth1", 1, true, "admin"); err == nil {
		t.Fatal("a physical port became a BVI")
	}
	if _, err := s.SetBridge("eth1", 7, false, "admin"); err == nil {
		t.Fatal("joined a bridge that does not exist")
	}
	if _, err := s.SetBridge("eth0", 0, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"set interface l3 eth0"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if strings.Contains(read(t, path), "bridge eth0 1") {
		t.Fatal("bridge line kept")
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"set interface l2 bridge eth0 1"}) {
		t.Fatalf("undo %q", sys.commands)
	}
}

func TestSubinterfaceLifecycle(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	if _, err := s.CreateSubif("eth0", 0, 100, "admin"); err == nil {
		t.Fatal("VLAN 100 used twice")
	}
	if _, err := s.CreateSubif("eth0.100", 0, 5, "admin"); err == nil {
		t.Fatal("a sub-interface on a sub-interface")
	}
	if _, err := s.CreateSubif("eth0", 0, 200, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"create sub-interface eth0 200 dot1q 200 exact-match", "set interface state eth0.200 up"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	got := read(t, path)
	if !strings.Contains(got, "set int l2 bridge eth0 1\ncreate sub-interface eth0 200 dot1q 200 exact-match\nset interface state eth0.200 up\n") {
		t.Fatalf("not after eth0's lines:\n%s", got)
	}
	s.Confirm("admin")

	// It exists now; put it in bridge 1, which takes its tag off.
	sys.live.Interfaces = append(sys.live.Interfaces, &liveInterface{Index: 6, Name: "eth0.200", Parent: "eth0", Sub: true, SubID: 200, VLAN: 200, Exact: true, Plain: true, Up: true, MTU: 1500})
	sys.commands = nil
	if _, err := s.SetBridge("eth0.200", 1, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"set interface l2 bridge eth0.200 1", "set interface l2 tag-rewrite eth0.200 pop 1"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if got := read(t, path); !strings.Contains(got, "set interface state eth0.200 up\nset interface l2 bridge eth0.200 1\nset interface l2 tag-rewrite eth0.200 pop 1\n") {
		t.Fatalf("bridge lines:\n%s", got)
	}
	s.Confirm("admin")

	sys.live.Interfaces[6].Bridge = 1
	if _, err := s.DeleteSubif("eth0.100", "admin"); err == nil || !strings.Contains(err.Error(), "网关") {
		t.Fatalf("deleted an interface the routes and NAT use: %v", err)
	}
	sys.commands = nil
	if _, err := s.DeleteSubif("eth0.200", "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"set interface l3 eth0.200", "delete sub-interface eth0.200"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if read(t, path) != installerFile {
		t.Fatalf("lines left:\n%s", read(t, path))
	}
	sys.commands = nil
	s.Rollback("admin")
	want := []string{
		"create sub-interface eth0 200 dot1q 200 exact-match", "set interface state eth0.200 up",
		"set interface l2 bridge eth0.200 1", "set interface l2 tag-rewrite eth0.200 pop 1",
	}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("undo %q", sys.commands)
	}
}

func TestChangeVLANRestarts(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	if _, err := s.ChangeVLAN("eth0.100", 300, "admin"); err == nil {
		t.Fatal("restarted without a unit")
	}
	s, sys, path = setup(t, installerFile, "vpp-router.service")
	if _, err := s.ChangeVLAN("eth0.100", 300, "admin"); err != nil {
		t.Fatal(err)
	}
	if sys.restarts != 1 || len(sys.commands) != 0 {
		t.Fatalf("restarts %d, commands %q", sys.restarts, sys.commands)
	}
	if !strings.Contains(read(t, path), "create sub-interface eth0 100 dot1q 300 exact-match\n") {
		t.Fatal("file not changed")
	}
	s.Rollback("admin")
	if sys.restarts != 2 || read(t, path) != installerFile {
		t.Fatal("rollback did not restart with the old file")
	}
}

func TestFailedRestartRollsBack(t *testing.T) {
	s, sys, path := setup(t, installerFile, "vpp-router.service")
	sys.readyErr = errors.New("no")
	if _, err := s.ChangeVLAN("eth0.100", 300, "admin"); err == nil {
		t.Fatal("no error")
	}
	if sys.restarts != 2 || read(t, path) != installerFile || s.pending != nil {
		t.Fatalf("restarts %d pending %v", sys.restarts, s.pending)
	}
}

func TestFailedCommandUndoesTheOthers(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	sys.failOn = "set interface ip address loop0 192.168.9.1/24"
	if _, err := s.SetAddresses("loop0", []string{"192.168.9.1/24"}, "admin"); err == nil {
		t.Fatal("no error")
	}
	want := []string{"set interface ip address del loop0 10.61.30.1/24", sys.failOn, "set interface ip address loop0 10.61.30.1/24"}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("commands %q", sys.commands)
	}
	if read(t, path) != installerFile || s.pending != nil {
		t.Fatal("file changed")
	}
}

func TestVPPRestartedMeanwhileRestartsOnRollback(t *testing.T) {
	s, sys, path := setup(t, installerFile, "vpp-router.service")
	if _, err := s.SetMTU("eth0.100", 1492, "admin"); err != nil {
		t.Fatal(err)
	}
	sys.stampNow = fileStamp{Ino: 2}
	sys.commands = nil
	s.Rollback("admin")
	if sys.restarts != 1 || len(sys.commands) != 0 || read(t, path) != installerFile {
		t.Fatalf("restarts %d commands %q", sys.restarts, sys.commands)
	}
}

func TestPendingSurvivesRestartAndExpires(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	if _, err := s.SetState("eth1", true, "admin"); err != nil {
		t.Fatal(err)
	}
	s.timer.Stop()
	// Restarted in time: the countdown goes on.
	again, err := NewService(s.opts, sys)
	if err != nil || again.pending == nil {
		t.Fatal("pending lost", err)
	}
	again.timer.Stop()
	// Restarted too late: rolled back at once.
	sys.commands = nil
	late, err := NewService(s.opts, sys)
	if err != nil {
		t.Fatal(err)
	}
	late.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	late.expire()
	if late.pending != nil || read(t, path) != installerFile || !slices.Equal(sys.commands, []string{"set interface state eth1 down"}) {
		t.Fatalf("not rolled back: %q", sys.commands)
	}
}

func TestCreateBridgeWithBVI(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	if _, err := s.CreateBridge(1, false, nil, "admin"); err == nil {
		t.Fatal("bridge 1 created twice")
	}
	if _, err := s.CreateBridge(2, true, []string{"10.61.30.5/24"}, "admin"); err == nil {
		t.Fatal("overlapping BVI address accepted")
	}
	if _, err := s.CreateBridge(2, true, []string{"10.61.50.1/24"}, "admin"); err != nil {
		t.Fatal(err)
	}
	want := "\ncreate bridge-domain 2\ncreate loopback interface instance 2\nset interface l2 bridge loop2 2 bvi\nset interface ip address loop2 10.61.50.1/24\nset interface state loop2 up\n"
	if got := read(t, path); !strings.HasSuffix(got, want) {
		t.Fatalf("got:\n%s", got)
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"delete loopback interface intfc loop2", "create bridge-domain 2 del"}) {
		t.Fatalf("undo %q", sys.commands)
	}
}

func TestStateView(t *testing.T) {
	s, _, _ := setup(t, installerFile, "")
	state := s.State()
	views := map[string]InterfaceView{}
	for _, view := range state.Interfaces {
		views[view.Name] = view
	}
	if _, ok := views["local0"]; ok {
		t.Error("local0 listed")
	}
	if v := views["wg0"]; v.Reason == "" || v.Kind != "other" {
		t.Errorf("wg0 %+v", v)
	}
	if v := views["eth0"]; v.AddressReason == "" || v.Kind != "physical" || v.Reason != "" {
		t.Errorf("eth0 %+v", v)
	}
	if v := views["eth0.100"]; v.VLANReason == "" || v.DeleteReason == "" || len(v.References) != 0 || !v.NAT || v.VLAN != 100 {
		t.Errorf("eth0.100 %+v", v)
	}
	if v := views["loop0"]; v.AddressReason != "" || v.Kind != "loopback" {
		t.Errorf("loop0 %+v", v)
	}
	if len(state.Bridges) != 1 || state.Bridges[0].BVI != "loop0" || !slices.Equal(state.Bridges[0].Members, []string{"eth0"}) || !state.Bridges[0].InFile {
		t.Errorf("bridges %+v", state.Bridges)
	}
}

func TestRestartWaitsForTheFileToRun(t *testing.T) {
	s, sys, _ := setup(t, installerFile, "vpp-router.service")
	// VPP answers before it has run the file: eth0.100 is missing for the first readings.
	full := sys.live
	partial := &liveState{Bridges: map[uint32]bool{}, Interfaces: full.Interfaces[:2]}
	reads := 0
	sys.reads = func() *liveState {
		reads++
		if reads <= 4 {
			return partial
		}
		return full
	}
	if err := s.restartVPP(); err != nil {
		t.Fatal(err)
	}
	if reads != 6 {
		t.Fatalf("settled after %d readings, want 6: four partial, then the full one twice", reads)
	}
	sys.reads = func() *liveState { return partial }
	if err := s.restartVPP(); err == nil {
		t.Fatal("settled without the file's interfaces")
	}
}

const dhcpFile = `create sub-interface eth0 100 dot1q 100 exact-match
set interface state eth0.100 up
set dhcp client intfc eth0.100 hostname router
nat44 ei add interface address eth0.100
`

func TestAddressingLinesAndModes(t *testing.T) {
	file := parseCLI(installerFile + "ip6 nd address autoconfig eth0.100 default-route\ndhcp6 client eth0.100\nip route add ::/0 via fe80::1 eth0.100\n")
	v4, v6 := fileFamily(file, "eth0.100", false), fileFamily(file, "eth0.100", true)
	if v4.mode != modeStatic || v4.gateway != netip.MustParseAddr("10.61.10.1") || len(v4.addresses) != 1 {
		t.Errorf("IPv4 %+v", v4)
	}
	if v6.mode != modeDHCP6 || v6.gateway.IsValid() == false {
		t.Errorf("IPv6 %+v", v6)
	}
	d := fileFamily(parseCLI(dhcpFile), "eth0.100", false)
	if d.mode != modeDHCP || d.hostname != "router" {
		t.Errorf("DHCP %+v", d)
	}
	for _, text := range []string{"ip route add 10.0.0.0/8 via 10.61.10.1 eth0.100", "ip route add 0.0.0.0/0 via fd00::1 eth0.100", "set dhcp client intfc eth0.100 hostname", "dhcp6 client eth0.100 disable"} {
		if kind := parseLine(text).kind; kind != lineOther {
			t.Errorf("%q understood as %d", text, kind)
		}
	}
}

func TestStaticToDHCPAndBack(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	if _, err := s.SetFamily("eth0.100", false, Family{Mode: modeDHCP, Hostname: "router"}, "admin"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip route del 0.0.0.0/0 via 10.61.10.1 eth0.100",
		"set interface ip address del eth0.100 10.61.10.2/24",
		"set dhcp client intfc eth0.100 hostname router",
	}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("commands %q", sys.commands)
	}
	if got := read(t, path); !strings.Contains(got, "# WAN\nset dhcp client intfc eth0.100 hostname router\n\nnat44") {
		t.Fatalf("not in place:\n%s", got)
	}
	sys.commands = nil
	s.Rollback("admin")
	want = []string{
		"set dhcp client del intfc eth0.100",
		"set interface ip address eth0.100 10.61.10.2/24",
		"ip route add 0.0.0.0/0 via 10.61.10.1 eth0.100",
	}
	if !slices.Equal(sys.commands, want) || read(t, path) != installerFile {
		t.Fatalf("undo %q", sys.commands)
	}
}

func TestDHCPToStaticKeepsTheLeasedAddress(t *testing.T) {
	s, sys, path := setup(t, dhcpFile, "")
	sys.live.Interfaces[2].Addresses = []netip.Prefix{pfx("10.61.20.253/24")}
	if _, err := s.SetFamily("eth0.100", false, Family{Mode: modeStatic, Addresses: []string{"10.61.20.253/24"}, Gateway: "10.61.20.1"}, "admin"); err != nil {
		t.Fatal(err)
	}
	// Releasing the lease removes the address, so it is added back as static.
	want := []string{
		"set dhcp client del intfc eth0.100",
		"set interface ip address eth0.100 10.61.20.253/24",
		"ip route add 0.0.0.0/0 via 10.61.20.1 eth0.100",
	}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("commands %q", sys.commands)
	}
	if got := read(t, path); !strings.Contains(got, "up\nset interface ip address eth0.100 10.61.20.253/24\nip route add 0.0.0.0/0 via 10.61.20.1 eth0.100\nnat44") {
		t.Fatalf("file:\n%s", got)
	}
}

func TestIPv6Modes(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	if _, err := s.SetFamily("eth0.100", true, Family{Mode: modeSLAAC}, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"ip6 nd address autoconfig eth0.100 default-route"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if got := read(t, path); !strings.Contains(got, "ip route add 0.0.0.0/0 via 10.61.10.1 eth0.100\nip6 nd address autoconfig eth0.100 default-route\n") {
		t.Fatalf("file:\n%s", got)
	}
	s.Confirm("admin")
	sys.commands = nil
	if _, err := s.SetFamily("eth0.100", true, Family{Mode: modeDHCP6}, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"dhcp6 client eth0.100"}) {
		t.Fatalf("SLAAC to DHCPv6 keeps the router advertisements: %q", sys.commands)
	}
	s.Confirm("admin")
	sys.commands = nil
	if _, err := s.SetFamily("eth0.100", true, Family{Mode: modeStatic, Addresses: []string{"fd00::2/64"}, Gateway: "fe80::1"}, "admin"); err != nil {
		t.Fatal(err)
	}
	want := []string{"dhcp6 client eth0.100 disable", "ip6 nd address autoconfig eth0.100 disable", "set interface ip address eth0.100 fd00::2/64", "ip route add ::/0 via fe80::1 eth0.100"}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("commands %q", sys.commands)
	}
	s.Confirm("admin")
	sys.commands = nil
	if _, err := s.SetFamily("eth0.100", true, Family{Mode: modeNone}, "admin"); err != nil {
		t.Fatal(err)
	}
	// The address was never in the fake's running state, so only the route goes.
	if !slices.Equal(sys.commands, []string{"ip route del ::/0 via fe80::1 eth0.100"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if read(t, path) != installerFile {
		t.Fatalf("IPv6 lines left:\n%s", read(t, path))
	}
}

func TestAddressingRefusals(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	for _, c := range []struct {
		name string
		v6   bool
		f    Family
	}{
		{"eth0.100", false, Family{Mode: modeStatic}},
		{"eth0.100", false, Family{Mode: modeStatic, Addresses: []string{"10.1.0.2/24"}, Gateway: "10.2.0.1"}},
		{"eth0.100", false, Family{Mode: modeStatic, Addresses: []string{"fd00::1/64"}}},
		{"eth0.100", false, Family{Mode: modeSLAAC}},
		{"eth0.100", true, Family{Mode: modeDHCP}},
		{"eth0.100", false, Family{Mode: modeDHCP, Hostname: "bad name"}},
		{"eth0.100", false, Family{Mode: modeStatic, Addresses: []string{"10.61.10.2/24"}, Gateway: "10.61.10.1"}}, // unchanged
		{"eth0", false, Family{Mode: modeDHCP}},                                                                      // in a bridge
		{"loop0", false, Family{Mode: modeDHCP}},                                                                     // no link
		{"wg0", true, Family{Mode: modeSLAAC}},                                                                       // not in the file
	} {
		if _, err := s.SetFamily(c.name, c.v6, c.f, "admin"); err == nil {
			t.Errorf("%s v6=%v %+v accepted", c.name, c.v6, c.f)
		}
	}
	if len(sys.commands) != 0 || read(t, path) != installerFile {
		t.Fatal("a refused change did something")
	}
}

func TestDynamicAddressingBlocksBridgeAndDelete(t *testing.T) {
	s, sys, _ := setup(t, dhcpFile+"create sub-interface eth0 200 dot1q 200 exact-match\nip6 nd address autoconfig eth0.200 default-route\n", "")
	sys.live.Interfaces = append(sys.live.Interfaces, &liveInterface{Index: 9, Name: "eth0.200", Parent: "eth0", Sub: true, SubID: 200, VLAN: 200, Exact: true, Plain: true})
	if _, err := s.DeleteSubif("eth0.200", "admin"); err == nil {
		t.Fatal("deleted a sub-interface still on SLAAC")
	}
	if _, err := s.SetBridge("eth0.200", 1, false, "admin"); err == nil {
		t.Fatal("bridged an interface still on SLAAC")
	}
	if len(sys.commands) != 0 {
		t.Fatalf("commands %q", sys.commands)
	}
}

func TestFileExits(t *testing.T) {
	file := parseCLI("set int ip address GigabitEthernet0 192.0.2.2/24\nip route add 0.0.0.0/0 via 192.0.2.1 GigabitEthernet0\n" +
		"set dhcp client intfc GigabitEthernet1.100 hostname r\nip route add ::/0 via fe80::1 GigabitEthernet0\nip route add 10.0.0.0/8 via 192.0.2.9 GigabitEthernet0\n")
	got, _ := json.Marshal(fileExits(file))
	want := `[{"interface":"GigabitEthernet0","via":"192.0.2.1"},{"interface":"GigabitEthernet0","via":"fe80::1"},{"interface":"GigabitEthernet1.100","dhcp":true}]`
	if string(got) != want {
		t.Fatalf("%s", got)
	}
	dir := t.TempDir()
	cli := filepath.Join(dir, "router.vpp")
	if err := os.WriteFile(cli, []byte(file.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Service{opts: Options{CLIFile: cli, ExitsFile: filepath.Join(dir, "run", "exits.json")}}
	s.publishExits()
	data, err := os.ReadFile(s.opts.ExitsFile)
	if err != nil || strings.TrimSpace(string(data)) != want {
		t.Fatalf("%s %v", data, err)
	}
}

func TestNATOnASecondUplink(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	if _, err := s.SetNAT("eth1", true, "admin"); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("NAT without an address: %v", err)
	}
	if _, err := s.SetFamily("eth1", false, Family{Mode: modeDHCP}, "admin"); err != nil {
		t.Fatal(err)
	}
	s.Confirm("admin")
	sys.commands = nil
	state, err := s.SetNAT("eth1", true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"nat44 ei add interface address eth1", "set interface nat44 ei out eth1 output-feature"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	got := read(t, path)
	if !strings.HasSuffix(got, "set interface nat44 ei out eth0.100 output-feature\nset dhcp client intfc eth1\nnat44 ei add interface address eth1\nset interface nat44 ei out eth1 output-feature\n") {
		t.Fatalf("NAT lines go after the plugin is enabled:\n%s", got)
	}
	for _, v := range state.Interfaces {
		if v.Name == "eth1" && !v.NAT {
			t.Fatal("view does not show the exit")
		}
	}
	if _, err := s.SetBridge("eth1", 1, false, "admin"); err == nil {
		t.Fatal("pending change, and an exit cannot join a bridge anyway")
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"set interface nat44 ei out eth1 output-feature del", "nat44 ei add interface address eth1 del"}) {
		t.Fatalf("undo %q", sys.commands)
	}
	if strings.Contains(read(t, path), "address eth1") {
		t.Fatal("rollback left the NAT lines")
	}
}

func TestNATEnablesThePlugin(t *testing.T) {
	file := strings.Replace(installerFile, "nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384\nnat44 ei add interface address eth0.100\nset interface nat44 ei out eth0.100 output-feature\n", "", 1)
	s, sys, path := setup(t, file, "")
	if _, err := s.SetNAT("eth0.100", true, "admin"); err != nil {
		t.Fatal(err)
	}
	want := []string{natEnableCommand(natEI), natTimeoutCommand(natEI), "nat44 ei add interface address eth0.100", "set interface nat44 ei out eth0.100 output-feature"}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("commands %q", sys.commands)
	}
	if got := read(t, path); !strings.Contains(got, "ip route add 0.0.0.0/0 via 10.61.10.1 eth0.100\n"+strings.Join(want, "\n")+"\n") {
		t.Fatalf("file:\n%s", got)
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"set interface nat44 ei out eth0.100 output-feature del", "nat44 ei add interface address eth0.100 del", "nat44 ei plugin disable"}) {
		t.Fatalf("undo %q", sys.commands)
	}
}

func TestNATOffAndRefusals(t *testing.T) {
	s, sys, path := setup(t, installerFile+"nat44 ei add identity mapping external eth0.100 udp 500\n", "")
	if _, err := s.SetNAT("eth0.100", false, "admin"); err == nil || !strings.Contains(err.Error(), "identity mapping") {
		t.Fatalf("NAT off under a mapping: %v", err)
	}
	for _, name := range []string{"loop0", "eth0"} {
		if _, err := s.SetNAT(name, true, "admin"); err == nil {
			t.Fatalf("%s became an exit", name)
		}
	}
	s, sys, path = setup(t, installerFile, "")
	if _, err := s.SetNAT("eth0.100", true, "admin"); err == nil {
		t.Fatal("no change accepted")
	}
	if _, err := s.SetNAT("eth0.100", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"set interface nat44 ei out eth0.100 output-feature del", "nat44 ei add interface address eth0.100 del"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if got := read(t, path); strings.Contains(got, "ei add interface address") || !strings.Contains(got, "nat44 ei plugin enable") {
		t.Fatalf("file:\n%s", got)
	}
}

// edFile is installerFile as the installer writes it for NAT44-ED.
var edFile = strings.Replace(installerFile, "nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384\nnat44 ei add interface address eth0.100\nset interface nat44 ei out eth0.100 output-feature\n",
	"nat44 plugin enable sessions 65536\nset nat timeout tcp-established 1800 tcp-transitory 120\nnat44 add interface address eth0.100\nset interface nat44 out eth0.100 output-feature\n", 1)

func TestNATUnderED(t *testing.T) {
	s, sys, path := setup(t, edFile, "")
	sys.live.NAT = natED
	state := s.State()
	for _, v := range state.Interfaces {
		if v.Name == "eth0.100" && !v.NAT {
			t.Fatal("the ED lines do not make eth0.100 an exit")
		}
	}
	if _, err := s.SetFamily("eth1", false, Family{Mode: modeDHCP}, "admin"); err != nil {
		t.Fatal(err)
	}
	s.Confirm("admin")
	sys.commands = nil
	if _, err := s.SetNAT("eth1", true, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"nat44 add interface address eth1", "set interface nat44 out eth1 output-feature"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if got := read(t, path); !strings.HasSuffix(got, "set interface nat44 out eth0.100 output-feature\nset dhcp client intfc eth1\nnat44 add interface address eth1\nset interface nat44 out eth1 output-feature\n") {
		t.Fatalf("file:\n%s", got)
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"set interface nat44 out eth1 output-feature del", "nat44 add interface address eth1 del"}) {
		t.Fatalf("undo %q", sys.commands)
	}
	sys.commands = nil
	if _, err := s.SetNAT("eth0.100", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"set interface nat44 out eth0.100 output-feature del", "nat44 add interface address eth0.100 del"}) {
		t.Fatalf("off %q", sys.commands)
	}
}

func TestNATEnablesTheEDPlugin(t *testing.T) {
	file := strings.Replace(installerFile, "nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384\nnat44 ei add interface address eth0.100\nset interface nat44 ei out eth0.100 output-feature\n", "", 1)
	s, sys, _ := setup(t, file, "")
	sys.live.NAT = natED
	if _, err := s.SetNAT("eth0.100", true, "admin"); err != nil {
		t.Fatal(err)
	}
	want := []string{"nat44 plugin enable sessions 65536", "set nat timeout tcp-established 1800 tcp-transitory 120", "nat44 add interface address eth0.100", "set interface nat44 out eth0.100 output-feature"}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("commands %q", sys.commands)
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"set interface nat44 out eth0.100 output-feature del", "nat44 add interface address eth0.100 del", "nat44 plugin disable"}) {
		t.Fatalf("undo %q", sys.commands)
	}
}

func TestNATModeMismatch(t *testing.T) {
	s, sys, _ := setup(t, installerFile, "")
	if _, err := s.SetFamily("eth1", false, Family{Mode: modeDHCP}, "admin"); err != nil {
		t.Fatal(err)
	}
	s.Confirm("admin")
	sys.live.NAT = natED
	if _, err := s.SetNAT("eth1", true, "admin"); err == nil || !strings.Contains(err.Error(), "NAT44-ED") {
		t.Fatalf("EI lines with ED running: %v", err)
	}
	file := strings.Replace(installerFile, "nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384\nnat44 ei add interface address eth0.100\nset interface nat44 ei out eth0.100 output-feature\n", "", 1)
	s, sys, _ = setup(t, file, "")
	sys.live.NAT = ""
	if _, err := s.SetNAT("eth0.100", true, "admin"); err == nil || !strings.Contains(err.Error(), "nat_plugin.so") {
		t.Fatalf("no NAT plugin: %v", err)
	}
}

func TestCreateDevices(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	s.linkExists = func(name string) bool { return name == "enp3s0" || name == "vpp-host" }
	cases := []struct {
		q       DeviceRequest
		command string
		name    string
	}{
		{DeviceRequest{Kind: "loopback"}, "create loopback interface instance 1", "loop1"},
		{DeviceRequest{Kind: "tap", Host: "vpp-lab", HostAddresses: []string{"10.20.0.2/24", "fd20::2/64"}}, "create tap id 1 host-if-name vpp-lab host-ip4-addr 10.20.0.2/24 host-ip6-addr fd20::2/64", "tap1"},
		{DeviceRequest{Kind: "vxlan", Local: "10.61.10.2", Peer: "10.61.10.9", VNI: 42}, "create vxlan tunnel src 10.61.10.2 dst 10.61.10.9 vni 42 instance 0", "vxlan_tunnel0"},
		{DeviceRequest{Kind: "gre", Local: "10.61.10.2", Peer: "10.61.10.9", L2: true}, "create gre tunnel src 10.61.10.2 dst 10.61.10.9 teb instance 0", "gre0"},
		{DeviceRequest{Kind: "ipip", Local: "10.61.10.2", Peer: "10.61.10.9"}, "create ipip tunnel src 10.61.10.2 dst 10.61.10.9 instance 0", "ipip0"},
		{DeviceRequest{Kind: "af_packet", Host: "enp3s0"}, "create host-interface name enp3s0", "host-enp3s0"},
	}
	for _, tc := range cases {
		sys.commands = nil
		if _, err := s.CreateDevice(tc.q, "admin"); err != nil {
			t.Fatalf("%s: %v", tc.q.Kind, err)
		}
		if !slices.Equal(sys.commands, []string{tc.command, "set interface state " + tc.name + " up"}) {
			t.Fatalf("%s: commands %q", tc.q.Kind, sys.commands)
		}
		if !strings.HasSuffix(read(t, path), tc.command+"\nset interface state "+tc.name+" up\n") {
			t.Fatalf("%s: file\n%s", tc.q.Kind, read(t, path))
		}
		if line := createdBy(parseCLI(read(t, path)), tc.name); line == nil {
			t.Fatalf("%s: the file's line is not read back as creating %s", tc.q.Kind, tc.name)
		}
		sys.commands = nil
		s.Rollback("admin")
		undo := deleteCommand(parseLine(tc.command), &liveInterface{Name: tc.name})
		if tc.q.Kind == "ipip" {
			undo = "" // needs the index, see TestIPIPUndoReadsTheIndex
		}
		if undo != "" && !slices.Equal(sys.commands, []string{undo}) {
			t.Fatalf("%s: undo %q", tc.q.Kind, sys.commands)
		}
		if read(t, path) != installerFile {
			t.Fatalf("%s: rollback left\n%s", tc.q.Kind, read(t, path))
		}
	}
}

func TestIPIPUndoReadsTheIndex(t *testing.T) {
	s, sys, _ := setup(t, installerFile, "")
	if _, err := s.CreateDevice(DeviceRequest{Kind: "ipip", Local: "10.61.10.2", Peer: "10.61.10.9"}, "admin"); err != nil {
		t.Fatal(err)
	}
	sys.live.Interfaces = append(sys.live.Interfaces, &liveInterface{Index: 9, Name: "ipip0"})
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"delete ipip tunnel sw_if_index 9"}) {
		t.Fatalf("undo %q", sys.commands)
	}
}

func TestCreateDeviceRefusals(t *testing.T) {
	s, _, _ := setup(t, installerFile, "")
	s.linkExists = func(name string) bool { return name == "vpp-host" }
	for name, q := range map[string]DeviceRequest{
		"unknown kind":          {Kind: "macvlan"},
		"TAP name taken":        {Kind: "tap", Host: "vpp-host"},
		"bad TAP name":          {Kind: "tap", Host: "a b"},
		"two IPv4 on the TAP":   {Kind: "tap", Host: "x", HostAddresses: []string{"10.0.0.1/24", "10.0.0.2/24"}},
		"local not in VPP":      {Kind: "vxlan", Local: "10.0.0.1", Peer: "10.0.0.2", VNI: 1},
		"mixed families":        {Kind: "gre", Local: "10.61.10.2", Peer: "fd00::1"},
		"no VNI":                {Kind: "vxlan", Local: "10.61.10.2", Peer: "10.61.10.9"},
		"no such Linux NIC":     {Kind: "af_packet", Host: "enp9s0"},
		"loopback as AF_PACKET": {Kind: "af_packet", Host: "lo"},
	} {
		if _, err := s.CreateDevice(q, "admin"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestDeleteDevice(t *testing.T) {
	file := installerFile + "create vxlan tunnel src 10.61.10.2 dst 10.61.10.9 vni 42 instance 3\nset interface state vxlan_tunnel3 up\nset interface ip address vxlan_tunnel3 10.30.0.1/30\n"
	s, sys, path := setup(t, file, "")
	sys.live.Interfaces = append(sys.live.Interfaces, &liveInterface{Index: 7, Name: "vxlan_tunnel3", Up: true, Addresses: []netip.Prefix{pfx("10.30.0.1/30")}})
	state := s.State()
	for _, v := range state.Interfaces {
		switch v.Name {
		case "vxlan_tunnel3":
			if v.Kind != "vxlan" || v.DeleteReason != "" {
				t.Fatalf("view %+v", v)
			}
		case "loop0", "eth0":
			if v.DeleteReason == "" {
				t.Fatalf("%s may be deleted", v.Name)
			}
		}
	}
	if _, err := s.DeleteDevice("vxlan_tunnel3", "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"set interface ip address del vxlan_tunnel3 10.30.0.1/30", "create vxlan tunnel src 10.61.10.2 dst 10.61.10.9 vni 42 instance 3 del"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if read(t, path) != installerFile {
		t.Fatalf("lines left\n%s", read(t, path))
	}
	sys.commands = nil
	s.Rollback("admin")
	want := []string{"create vxlan tunnel src 10.61.10.2 dst 10.61.10.9 vni 42 instance 3", "set interface state vxlan_tunnel3 up", "set interface ip address vxlan_tunnel3 10.30.0.1/30"}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("undo %q", sys.commands)
	}
	for _, name := range []string{"loop0", "eth0.100", "wg0"} {
		if _, err := s.DeleteDevice(name, "admin"); err == nil {
			t.Fatalf("deleted %s", name)
		}
	}
}

func TestInstallerTapsAreProtected(t *testing.T) {
	// The installer's management TAP is in the LAN bridge, and so not deleted by accident.
	file := installerFile + "create tap id 0 host-if-name vpp-host host-mac-addr 02:00:00:00:00:02 host-mtu-size 1500\nset interface l2 bridge tap0 1\nset interface state tap0 up\n"
	s, sys, _ := setup(t, file, "")
	sys.live.Interfaces = append(sys.live.Interfaces, &liveInterface{Index: 8, Name: "tap0", Up: true, Bridge: 1})
	if _, err := s.DeleteDevice("tap0", "admin"); err == nil || !strings.Contains(err.Error(), "网桥") {
		t.Fatalf("management TAP: %v", err)
	}
}

func TestSystemPendingRefuses(t *testing.T) {
	s, _, path := setup(t, installerFile, "")
	s.opts.OtherPending = filepath.Join(t.TempDir(), "pending.json")
	if err := os.WriteFile(s.opts.OtherPending, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMTU("eth0.100", 1492, "admin"); err == nil || !strings.Contains(err.Error(), "系统页") {
		t.Fatalf("change while vpp-system waits: %v", err)
	}
	if read(t, path) != installerFile {
		t.Fatal("file changed")
	}
	os.Remove(s.opts.OtherPending)
	if _, err := s.SetMTU("eth0.100", 1492, "admin"); err != nil {
		t.Fatal(err)
	}
}
