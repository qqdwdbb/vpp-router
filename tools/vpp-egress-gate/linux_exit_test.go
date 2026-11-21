package gate

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func linuxTestConfig(t *testing.T) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "domains.json")
	writeJSON(t, path, map[string]any{"routes": []any{
		map[string]any{"name": "wg", "interface": "tap10", "via": "172.30.10.2", "domains": []any{"example.org"}, "linux_exit": map[string]any{"input_interface": "gate-in", "interface": "gate-wg", "table": 1001, "mark": 101, "priority": 11001, "masquerade": true}},
		map[string]any{"name": "ppp", "interface": "tun11", "via": "172.30.11.2", "domains": []any{"example.net"}, "linux_exit": map[string]any{"input_interface": "gate-in2", "interface": "gate-ppp", "table": 1002, "mark": 102, "priority": 11002}},
	}})
	cfg := &Config{StateFile: filepath.Join(t.TempDir(), "state.json"), MaxRoutes: 1000, OverlapPolicy: "first"}
	if _, err := DomainRoutesFromFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestLinuxExitConfigurationAndFirewall(t *testing.T) {
	cfg := linuxTestConfig(t)
	script := linuxExitNftScript(cfg, nil)
	for _, want := range []string{"table inet egress_gate_linux", `iifname "gate-in" meta nfproto ipv4 meta mark set 101 return`, `iifname "gate-in2" meta nfproto ipv4 meta mark set 102 return`, `iifname "gate-in" oifname "gate-wg" meta mark 101 masquerade`, `iifname "gate-in" drop`, `iifname "gate-in2" drop`} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in:\n%s", want, script)
		}
	}
	if strings.Contains(script, "daddr @") || strings.Contains(script, " set e") {
		t.Fatalf("Linux holds per-destination state:\n%s", script)
	}
	if strings.Contains(script, `oifname "gate-ppp" meta mark 102 masquerade`) {
		t.Fatal("NAT enabled without request")
	}
	if strings.Contains(script, "flush ruleset") || strings.Contains(script, "tproxy") {
		t.Fatal("modified unrelated firewall")
	}
	// A family without a next hop has no policy rule, so it must stay unmarked and be dropped.
	if strings.Contains(script, "nfproto ipv6 meta mark set") {
		t.Fatalf("marked a family the exit does not use:\n%s", script)
	}
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"same_vpp_interface", func(c *Config) { c.Mappings[1].Interface = "tap10" }},
		{"same_input_interface", func(c *Config) { c.Mappings[1].LinuxExit.InputInterface = "gate-in" }},
		{"input_is_another_exit", func(c *Config) { c.Mappings[1].LinuxExit.Interface = "gate-in" }},
		{"same_mark", func(c *Config) { c.Mappings[1].LinuxExit.Mark = 101 }},
		{"same_table", func(c *Config) { c.Mappings[1].LinuxExit.Table = 1001 }},
		{"same_priority", func(c *Config) { c.Mappings[1].LinuxExit.Priority = 11001 }},
		{"bad_interface", func(c *Config) { c.Mappings[1].LinuxExit.Interface = "bad;name" }},
		{"fakeip", func(c *Config) { c.Mappings[1].FakeIP = "198.18.0.0/15" }},
		{"bad_gateway_family", func(c *Config) { c.Mappings[1].LinuxExit.Gateway = "::1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := linuxTestConfig(t)
			tc.change(cfg)
			if validateLinuxExits(cfg) == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

// Gate looks only at names, so a hand-written rule may still name a TUN, and a device may
// sit in its own FIB table. Generated devices are always TAPs.
func TestLinuxExitMixesDeviceKinds(t *testing.T) {
	cfg := linuxTestConfig(t)
	if err := validateLinuxExits(cfg); err != nil {
		t.Fatalf("exits on differently named devices refused: %v", err)
	}
	cfg.Mappings[1].FibTable = 7
	if err := validateLinuxExits(cfg); err != nil {
		t.Fatalf("exits in separate FIB tables refused: %v", err)
	}
}

type linuxBarrierBackend struct {
	*FakeBackend
	fail  error
	calls int
}

func (b *linuxBarrierBackend) EnsureLinuxExits() error {
	b.calls++
	return b.fail
}

func TestLinuxExitFailurePropagatesAtRouteBarrier(t *testing.T) {
	cfg := linuxTestConfig(t)
	r := Route{0, "203.0.113.7/32", "172.30.10.2", "tap10"}
	b := &linuxBarrierBackend{FakeBackend: NewFakeBackend(), fail: errors.New("nft failed")}
	var mu sync.Mutex
	if _, err := EnsureRoutes(cfg, b, []Route{r}, &mu); err == nil || !strings.Contains(err.Error(), "nft failed") {
		t.Fatalf("firewall failure lost: %v", err)
	}
	b.fail = nil
	if _, err := EnsureRoutes(cfg, b, []Route{r}, &mu); err != nil {
		t.Fatal(err)
	}
	if b.calls != 2 {
		t.Fatalf("retry skipped firewall barrier: %+v", b)
	}
}

// Run explicitly inside an isolated Linux network namespace; never against host networking.
func TestLinuxExitKernel(t *testing.T) {
	if os.Getenv("GATE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	ctx := context.Background()
	for _, name := range []string{"gate-in", "gate-in2", "gate-wg", "gate-ppp"} {
		if _, err := runCmdContext(ctx, "ip", "link", "add", name, "type", "dummy"); err != nil {
			t.Fatal(err)
		}
		if _, err := runCmdContext(ctx, "ip", "link", "set", name, "up"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := runCmdContext(ctx, "ip", "addr", "add", "192.0.2.1/24", "dev", "gate-in"); err != nil {
		t.Fatal(err)
	}
	if _, err := runCmdContext(ctx, "ip", "-6", "addr", "add", "2001:db8:1::1/64", "dev", "gate-in", "nodad"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"addr", "add", "172.30.10.2/24", "dev", "gate-in"},
		{"addr", "add", "172.30.11.2/24", "dev", "gate-in2"},
		{"-6", "addr", "add", "fd00:10::2/64", "dev", "gate-in", "nodad"},
		{"-6", "addr", "add", "fd00:11::2/64", "dev", "gate-in2", "nodad"},
	} {
		if _, err := runCmdContext(ctx, "ip", args...); err != nil {
			t.Fatal(err)
		}
	}
	cfg := linuxTestConfig(t)
	cfg.Mappings[0].Via6 = "fd00:10::2"
	cfg.Mappings[1].Via6 = "fd00:11::2"
	for _, m := range cfg.Mappings {
		if up, err := prepareLinuxExit(ctx, m); err != nil || !up {
			t.Fatalf("prepare: up=%v err=%v", up, err)
		}
		if up, err := prepareLinuxExit(ctx, m); err != nil || !up {
			t.Fatalf("not idempotent: up=%v err=%v", up, err)
		}
	}
	// An absent exit must fail closed without stopping preparation.
	absent := cfg.Mappings[1]
	absentExit := *absent.LinuxExit
	absentExit.Interface, absentExit.Table, absentExit.Mark, absentExit.Priority = "gate-gone", 1003, 103, 11003
	absent.LinuxExit = &absentExit
	if up, err := prepareLinuxExit(ctx, absent); err != nil || up {
		t.Fatalf("absent exit: up=%v err=%v", up, err)
	}
	if out, err := runCmdContext(ctx, "ip", "route", "show", "table", "1003"); err != nil || !strings.Contains(out, "unreachable default") || strings.Contains(out, "dev") {
		t.Fatalf("absent exit table: %s %v", out, err)
	}
	if err := removeLinuxExit(ctx, absent); err != nil {
		t.Fatal(err)
	}
	// A foreign route in the table must be refused, not outvoted by metric.
	if _, err := runCmdContext(ctx, "ip", "route", "add", "local", "default", "dev", "lo", "table", "1004"); err != nil {
		t.Fatal(err)
	}
	occupied := absent
	occupiedExit := absentExit
	occupiedExit.Interface, occupiedExit.Table = "gate-wg", 1004
	occupied.LinuxExit = &occupiedExit
	if _, err := prepareLinuxExit(ctx, occupied); err == nil || !strings.Contains(err.Error(), "occupied") {
		t.Fatalf("occupied table accepted: %v", err)
	}
	if _, err := runCmdContext(ctx, "ip", "route", "del", "local", "default", "dev", "lo", "table", "1004"); err != nil {
		t.Fatal(err)
	}
	// Replies from the exit must not be filtered; "all" is outside a namespace test's control.
	rpFilter := "/proc/sys/net/ipv4/conf/gate-wg/rp_filter"
	if err := os.WriteFile(rpFilter, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (&VPPBackend{Config: cfg}).prepareLinuxExits(&linuxExitState{ready: true}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(rpFilter); err != nil || strings.TrimSpace(string(data)) != "0" {
		t.Fatalf("rp_filter: %q %v", data, err)
	}
	// Real rtnetlink messages must parse into events for the interfaces of interest.
	source, err := openLinkEvents()
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan struct{}, 1)
	go watchLinkEvents(source, map[string]bool{"gate-wg": true}, interfaceNameByIndex, 10*time.Millisecond, events)
	if _, err := runCmdContext(ctx, "ip", "link", "add", "gate-other", "type", "dummy"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
		t.Fatal("event for an unrelated interface")
	case <-time.After(200 * time.Millisecond):
	}
	for _, args := range [][]string{{"link", "set", "gate-wg", "down"}, {"link", "set", "gate-wg", "up"}, {"addr", "add", "198.51.100.1/24", "dev", "gate-wg"}} {
		if _, err := runCmdContext(ctx, "ip", args...); err != nil {
			t.Fatal(err)
		}
		select {
		case <-events:
		case <-time.After(2 * time.Second):
			t.Fatalf("no link event after ip %v", args)
		}
	}
	source.Close()
	// Taking the link down removed its default route; this is what an event-driven pass repairs.
	if up, err := prepareLinuxExit(ctx, cfg.Mappings[0]); err != nil || !up {
		t.Fatalf("recover after link change: up=%v err=%v", up, err)
	}
	// A marked socket really leaves through the exit: the source address proves the route used.
	dialer := net.Dialer{Control: markedDialControl(101)}
	conn, err := dialer.Dial("udp4", "203.0.113.7:53")
	if err != nil {
		t.Fatal(err)
	}
	if local := conn.LocalAddr().(*net.UDPAddr).IP.String(); local != "198.51.100.1" {
		t.Fatalf("marked socket source %s", local)
	}
	conn.Close()
	cfg.Mappings[0].LinuxExit.BlockInput = true
	if err := applyNft([]string{linuxExitNftScript(cfg, map[string]int{"gate-wg": 1420})}, "kernel test"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, mark, iface string }{{"gate-in", "101", "gate-wg"}, {"gate-in2", "102", "gate-ppp"}} {
		out, err := runCmdContext(ctx, "ip", "route", "get", "203.0.113.7", "from", "192.0.2.10", "iif", tc.input, "mark", tc.mark)
		if err != nil || !strings.Contains(out, "dev "+tc.iface) {
			t.Fatalf("policy lookup: %s %v", out, err)
		}
	}
	out, err := runCmdContext(ctx, "ip", "-6", "route", "get", "2001:db8:2::7", "from", "2001:db8:1::10", "iif", "gate-in", "mark", "101")
	if err != nil || !strings.Contains(out, "dev gate-wg") {
		t.Fatalf("IPv6 policy lookup: %s %v", out, err)
	}
	for _, m := range cfg.Mappings {
		if err := removeLinuxExit(ctx, m); err != nil {
			t.Fatal(err)
		}
		if err := removeLinuxExit(ctx, m); err != nil {
			t.Fatalf("cleanup not idempotent: %v", err)
		}
	}
}

func TestLinuxExitFiltersExitTraffic(t *testing.T) {
	cfg := linuxTestConfig(t)
	script := linuxExitNftScript(cfg, nil)
	for _, name := range []string{"gate-wg", "gate-ppp"} {
		accept := strings.Index(script, `iifname "`+name+`" ct state established,related accept`)
		dnat := strings.Index(script, `iifname "`+name+`" ct status dnat accept`)
		drop := strings.Index(script, `iifname "`+name+`" drop`)
		if accept < 0 || dnat <= accept || drop <= dnat {
			t.Fatalf("%s is not reply-only:\n%s", name, script)
		}
	}
	if strings.Contains(script, "hook input") {
		t.Fatal("input filtering must be opt-in")
	}

	cfg.Mappings[0].LinuxExit.BlockInput = true
	script = linuxExitNftScript(cfg, nil)
	start := strings.Index(script, "chain input")
	end := strings.Index(script, "chain nat")
	if start < 0 || end < start {
		t.Fatalf("missing input chain:\n%s", script)
	}
	input := script[start:end]
	for _, want := range []string{`iifname "gate-wg" ct state established,related accept`, `iifname "gate-wg" icmpv6 type { nd-neighbor-solicit`, `iifname "gate-wg" drop`} {
		if !strings.Contains(input, want) {
			t.Fatalf("missing %q in:\n%s", want, input)
		}
	}
	if strings.Contains(input, "gate-ppp") {
		t.Fatalf("input filter applied to another exit:\n%s", input)
	}

	// Mappings sharing an exit get one rule set.
	cfg.Mappings[1].LinuxExit.Interface = "gate-wg"
	if n := strings.Count(linuxExitNftScript(cfg, nil), `iifname "gate-wg" ct status dnat accept`+"\n iifname"); n != 2 {
		t.Fatalf("expected one forward and one input rule, got %d", n)
	}
}

func TestLinuxExitOccupancy(t *testing.T) {
	e := &LinuxExit{InputInterface: "gate-forward", Interface: "ppp0", Table: 1002, Mark: 102, Priority: 11003}
	for _, tc := range []struct {
		name, routes string
		wantErr      bool
	}{
		{"empty", "", false},
		{"empty_json", "[ ]", false},
		// Captured from iproute2 6.1.
		{"own_routes", `[{"dst":"default","dev":"ppp0","scope":"link","metric":100,"flags":[]},{"type":"unreachable","dst":"default","metric":32767,"flags":[]}]`, false},
		{"own_routes_ipv6", `[{"dst":"default","dev":"ppp0","metric":100,"flags":[],"pref":"medium"},{"type":"unreachable","dst":"default","dev":"lo","metric":32767,"flags":[],"pref":"medium"}]`, false},
		{"installer_tproxy_table", `[{"type":"local","dst":"default","dev":"lo","scope":"host","flags":[]}]`, true},
		{"other_device", `[{"dst":"default","dev":"wg0","metric":100,"flags":[]}]`, true},
		{"other_prefix", `[{"dst":"10.0.0.0/8","dev":"ppp0","metric":100,"flags":[]}]`, true},
		{"other_metric", `[{"dst":"default","dev":"ppp0","flags":[]}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkLinuxExitTable(tc.routes, e, 4); (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for _, tc := range []struct {
		name, rules             string
		transit, local, wantErr bool
	}{
		{"none", `[{"priority":0,"src":"all","table":"255"},{"priority":32766,"src":"all","table":"254"}]`, false, false, false},
		{"transit_only", `[{"priority":11003,"src":"all","iif":"gate-forward","fwmark":"0x66","table":"1002"}]`, true, false, false},
		{"both", `[{"priority":11003,"src":"all","iif":"gate-forward","fwmark":"0x66","table":"1002"},{"priority":11003,"src":"all","iif":"lo","fwmark":"0x66","table":"1002"}]`, true, true, false},
		{"installer_rule_reads_table", `[{"priority":11002,"src":"all","iif":"gate-tproxy","fwmark":"0x1","table":"1002"}]`, false, false, true},
		{"priority_taken", `[{"priority":11003,"src":"all","iif":"gate-tproxy","fwmark":"0x1","table":"1005"}]`, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transit, local, err := linuxExitRulesPresent(tc.rules, e, 4)
			if transit != tc.transit || local != tc.local || (err != nil) != tc.wantErr {
				t.Fatalf("transit=%v local=%v err=%v", transit, local, err)
			}
		})
	}
}

// fakeLinuxTools puts recording ip, nft and wg commands first in PATH. A command
// prints <key>.out or fails with <key>.err, where key is its arguments with
// spaces and slashes replaced. <key>.hook runs first to simulate races.
func fakeLinuxTools(t *testing.T) (respond func(key, suffix, text string), calls func() string) {
	t.Helper()
	dir := t.TempDir()
	useFakeSysctl(t)
	script := "#!/bin/sh\nname=$(basename \"$0\")\necho \"$name $*\" >> \"$FAKE_DIR/log\"\n" +
		"key=$(echo \"$name $*\" | tr ' /' '__')\n" +
		"[ -f \"$FAKE_DIR/$key.hook\" ] && sh \"$FAKE_DIR/$key.hook\"\n" +
		"if [ -f \"$FAKE_DIR/$key.err\" ]; then cat \"$FAKE_DIR/$key.err\" >&2; exit 1; fi\n" +
		"[ -f \"$FAKE_DIR/$key.out\" ] && cat \"$FAKE_DIR/$key.out\"\nexit 0\n"
	// nft reads its script from stdin; keep every attempt, including failed ones.
	nft := strings.Replace(script, "key=$(", "cat >> \"$FAKE_DIR/nft.stdin\"\nkey=$(", 1)
	for name, text := range map[string]string{"ip": script, "nft": nft, "wg": script, "iptables": script, "ip6tables": script, "systemctl": script} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DIR", dir)
	respond = func(key, suffix, text string) {
		t.Helper()
		name := strings.NewReplacer(" ", "_", "/", "_").Replace(key) + "." + suffix
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	calls = func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "log"))
		return string(data)
	}
	// linuxTestConfig's next hops are configured unless a test says otherwise.
	respond("ip -j -4 addr show dev gate-in", "out", `[{"ifname":"gate-in","addr_info":[{"family":"inet","local":"172.30.10.2","prefixlen":24}]}]`)
	respond("ip -j -4 addr show dev gate-in2", "out", `[{"ifname":"gate-in2","addr_info":[{"family":"inet","local":"172.30.11.2","prefixlen":24}]}]`)
	return respond, calls
}

// useFakeSysctl returns a helper that creates a sysctl below a temporary root.
func useFakeSysctl(t *testing.T) func(name, value string) string {
	t.Helper()
	previous := linuxSysctlRoot
	linuxSysctlRoot = t.TempDir()
	t.Cleanup(func() { linuxSysctlRoot = previous })
	root := linuxSysctlRoot
	return func(name, value string) string {
		t.Helper()
		path := filepath.Join(root, "net/ipv4/conf", name, "rp_filter")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
}

const (
	fakeLinkUp   = `[{"ifname":"x","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"mtu":1420}]`
	fakeLinkDown = `[{"ifname":"x","flags":["POINTOPOINT","NOARP"]}]`
)

func TestPrepareLinuxExitAvailability(t *testing.T) {
	const fallback = "ip -4 route replace unreachable default table 1001 metric 32767"
	const exitRoute = "ip -4 route replace table 1001 default metric 100 dev gate-wg"
	const rule = "ip -4 rule add priority 11001 iif gate-in fwmark 101 lookup 1001"
	link := "ip -j link show dev gate-wg"
	for _, tc := range []struct {
		name   string
		setup  func(respond func(string, string, string))
		up     bool
		want   []string
		absent []string
	}{
		{"up", func(r func(string, string, string)) { r(link, "out", fakeLinkUp) }, true, []string{fallback, exitRoute, rule}, nil},
		{"missing", func(r func(string, string, string)) {
			r(link, "err", `Device "gate-wg" does not exist.`)
		}, false, []string{fallback, rule}, []string{exitRoute}},
		{"down", func(r func(string, string, string)) { r(link, "out", fakeLinkDown) }, false, []string{fallback, rule}, []string{exitRoute}},
		{"empty_table_error", func(r func(string, string, string)) {
			r(link, "out", fakeLinkUp)
			r("ip -j -4 route show table 1001", "err", "Error: ipv4: FIB table does not exist.")
		}, true, []string{fallback, exitRoute, rule}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			respond, calls := fakeLinuxTools(t)
			tc.setup(respond)
			up, err := prepareLinuxExit(context.Background(), linuxTestConfig(t).Mappings[0])
			if err != nil || up != tc.up {
				t.Fatalf("up=%v err=%v", up, err)
			}
			for _, want := range tc.want {
				if !strings.Contains(calls(), want+"\n") {
					t.Fatalf("missing %q in:\n%s", want, calls())
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(calls(), absent) {
					t.Fatalf("unexpected %q in:\n%s", absent, calls())
				}
			}
		})
	}

	t.Run("link_lost_during_route_change", func(t *testing.T) {
		respond, calls := fakeLinuxTools(t)
		respond(link, "out", fakeLinkUp)
		respond(exitRoute, "err", "RTNETLINK answers: Network is down")
		respond(exitRoute, "hook", `printf '%s' '`+fakeLinkDown+`' > "$FAKE_DIR/ip_-j_link_show_dev_gate-wg.out"`)
		up, err := prepareLinuxExit(context.Background(), linuxTestConfig(t).Mappings[0])
		if err != nil || up {
			t.Fatalf("up=%v err=%v", up, err)
		}
		if !strings.Contains(calls(), rule) {
			t.Fatalf("rule not installed:\n%s", calls())
		}
	})
	t.Run("route_error_on_live_link", func(t *testing.T) {
		respond, _ := fakeLinuxTools(t)
		respond(link, "out", fakeLinkUp)
		respond(exitRoute, "err", "RTNETLINK answers: Invalid argument")
		if _, err := prepareLinuxExit(context.Background(), linuxTestConfig(t).Mappings[0]); err == nil {
			t.Fatal("route failure hidden")
		}
	})
	t.Run("occupied_table_changes_nothing", func(t *testing.T) {
		respond, calls := fakeLinuxTools(t)
		respond(link, "out", fakeLinkUp)
		respond("ip -j -4 route show table 1001", "out", `[{"type":"local","dst":"default","dev":"lo","scope":"host","flags":[]}]`)
		if _, err := prepareLinuxExit(context.Background(), linuxTestConfig(t).Mappings[0]); err == nil || !strings.Contains(err.Error(), "table 1001 is occupied") {
			t.Fatalf("occupied table accepted: %v", err)
		}
		if strings.Contains(calls(), "replace") || strings.Contains(calls(), "rule add") {
			t.Fatalf("modified occupied table:\n%s", calls())
		}
	})
}

func TestLinuxExitsAreIsolated(t *testing.T) {
	missingPPP := func(respond func(string, string, string)) {
		respond("ip -j link show dev gate-wg", "out", fakeLinkUp)
		respond("ip -j link show dev gate-ppp", "err", `Device "gate-ppp" does not exist.`)
	}
	t.Run("missing_exit_does_not_block_startup", func(t *testing.T) {
		respond, calls := fakeLinuxTools(t)
		missingPPP(respond)
		cfg := linuxTestConfig(t)
		cfg.Mappings = append([]Mapping{cfg.Mappings[1]}, cfg.Mappings[0])
		defer delete(linuxExitStates, cfg.StateFile)
		if err := (&VPPBackend{Config: cfg}).EnsureLinuxExits(); err != nil {
			t.Fatal(err)
		}
		log := calls()
		for _, want := range []string{"default metric 100 dev gate-wg", "unreachable default table 1002", "lookup 1002", "nft -f -"} {
			if !strings.Contains(log, want) {
				t.Fatalf("missing %q in:\n%s", want, log)
			}
		}
		if strings.Contains(log, "dev gate-ppp") && !strings.Contains(log, "show dev gate-ppp") {
			t.Fatalf("route installed on missing exit:\n%s", log)
		}
		state := linuxExitStates[cfg.StateFile]
		if state == nil || !state.ready || !strings.Contains(state.status["gate-ppp/1002"], "unavailable") {
			t.Fatalf("state %+v", state)
		}
	})
	t.Run("startup_rejects_occupied_table", func(t *testing.T) {
		respond, _ := fakeLinuxTools(t)
		respond("ip -j link show dev gate-wg", "out", fakeLinkUp)
		respond("ip -j -4 route show table 1001", "out", `[{"type":"local","dst":"default","dev":"lo","flags":[]}]`)
		cfg := linuxTestConfig(t)
		defer delete(linuxExitStates, cfg.StateFile)
		if err := (&VPPBackend{Config: cfg}).EnsureLinuxExits(); err == nil || !strings.Contains(err.Error(), "occupied") {
			t.Fatalf("occupied table accepted: %v", err)
		}
	})
	t.Run("runtime_failure_keeps_other_exits_working", func(t *testing.T) {
		respond, calls := fakeLinuxTools(t)
		respond("ip -j link show dev gate-wg", "err", "RTNETLINK answers: Operation not permitted")
		respond("ip -j link show", "out", `[{"ifname":"gate-wg"}]`)
		respond("ip -j link show dev gate-ppp", "out", fakeLinkUp)
		cfg := linuxTestConfig(t)
		state := &linuxExitState{ready: true}
		if err := (&VPPBackend{Config: cfg}).prepareLinuxExits(state); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(calls(), "default metric 100 dev gate-ppp") {
			t.Fatalf("second exit skipped:\n%s", calls())
		}
		if !strings.Contains(state.status["gate-wg/1001"], "not permitted") || state.status["gate-ppp/1002"] != "available" {
			t.Fatalf("status %+v", state.status)
		}
	})
	t.Run("recovery_reinstalls_route", func(t *testing.T) {
		respond, calls := fakeLinuxTools(t)
		missingPPP(respond)
		cfg := linuxTestConfig(t)
		state := &linuxExitState{ready: true}
		backend := &VPPBackend{Config: cfg}
		if err := backend.prepareLinuxExits(state); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(os.Getenv("FAKE_DIR"), "ip_-j_link_show_dev_gate-ppp.err")); err != nil {
			t.Fatal(err)
		}
		respond("ip -j link show dev gate-ppp", "out", fakeLinkUp)
		if err := backend.prepareLinuxExits(state); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(calls(), "default metric 100 dev gate-ppp") || state.status["gate-ppp/1002"] != "available" {
			t.Fatalf("exit not restored: %+v\n%s", state.status, calls())
		}
	})
}

func TestLinuxExitUnderlayDiscovery(t *testing.T) {
	got := parseWireGuardEndpoints("key1\t203.0.113.9:51820\nkey2\t(none)\nkey3\t[2001:db8::9]:51820\nkey4\t[::ffff:198.51.100.9]:1\n")
	want := "203.0.113.9/32,2001:db8::9/128,198.51.100.9/32"
	if strings.Join(got, ",") != want {
		t.Fatalf("endpoints %v", got)
	}

	respond, _ := fakeLinuxTools(t)
	ctx := context.Background()
	respond("ip -d -j link show dev wg0", "out", `[{"ifname":"wg0","linkinfo":{"info_kind":"wireguard"}}]`)
	respond("wg show wg0 endpoints", "out", "key\t203.0.113.9:51820\n")
	if prefixes, present, err := linuxExitUnderlay(ctx, "wg0"); err != nil || !present || len(prefixes) != 1 || prefixes[0] != "203.0.113.9/32" {
		t.Fatalf("wireguard: %v %v %v", prefixes, present, err)
	}
	respond("ip -d -j link show dev gre0", "out", `[{"ifname":"gre0","linkinfo":{"info_kind":"gre","info_data":{"local":"192.0.2.1","remote":"203.0.113.10"}}}]`)
	if prefixes, _, err := linuxExitUnderlay(ctx, "gre0"); err != nil || len(prefixes) != 1 || prefixes[0] != "203.0.113.10/32" {
		t.Fatalf("gre: %v %v", prefixes, err)
	}
	respond("ip -d -j link show dev ppp0", "out", `[{"ifname":"ppp0"}]`)
	if prefixes, present, err := linuxExitUnderlay(ctx, "ppp0"); err != nil || !present || len(prefixes) != 0 {
		t.Fatalf("ppp: %v %v %v", prefixes, present, err)
	}
	respond("ip -d -j link show dev gone", "err", `Device "gone" does not exist.`)
	if _, present, err := linuxExitUnderlay(ctx, "gone"); err != nil || present {
		t.Fatalf("missing interface: %v %v", present, err)
	}
}

func TestLinuxExitEndpointCannotBeRouted(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	writeJSON(t, configPath, map[string]any{"state_file": filepath.Join(dir, "state.json"), "lock_files": []any{}, "overlap_policy": "first", "exclude_prefixes": []any{"192.168.0.0/16"}})
	domainPath := filepath.Join(dir, "domains.json")
	writeJSON(t, domainPath, map[string]any{"routes": []any{
		map[string]any{"name": "wg", "interface": "tap10", "via": "172.30.10.2", "domains": []any{"example.org"}, "linux_exit": map[string]any{"input_interface": "gate-in", "interface": "gate-wg", "table": 1001, "mark": 101, "priority": 11001}},
	}})
	backend := NewFakeBackend()
	c, err := NewController(configPath, filepath.Join(dir, "leases.json"), func(*Config) Backend { return backend }, domainPath)
	if err != nil {
		t.Fatal(err)
	}
	endpoints, present := []string{}, true
	var discoverErr error
	c.underlayDiscover = func(context.Context, string) ([]string, bool, error) {
		return append([]string{}, endpoints...), present, discoverErr
	}
	ctx := context.Background()
	q := Question{"www.example.org", 1, 1}
	answer := func(ip string) error {
		return c.Reconcile(ctx, []Record{{"www.example.org", ip, 60}}, &q, false)
	}
	if err := answer("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if !backend.HasRoute(0, "203.0.113.9/32") {
		t.Fatalf("route missing: %v", backend.LiveKeys())
	}
	// Record the background signature, as a running Gate has already done.
	if err := c.Reconcile(ctx, nil, nil, false); err != nil {
		t.Fatal(err)
	}

	// A tunnel endpoint that is already routed is withdrawn; new answers are refused.
	endpoints = []string{"203.0.113.9/32"}
	c.refreshLinuxUnderlay(ctx)
	if err := c.Reconcile(ctx, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	if backend.HasRoute(0, "203.0.113.9/32") {
		t.Fatalf("looping route kept: %v", backend.LiveKeys())
	}
	if err := answer("203.0.113.9"); err == nil {
		t.Fatal("answer for tunnel endpoint accepted")
	}
	if cfg := c.Config(); !strings.Contains(strings.Join(cfg.ExcludePrefixes, ","), "192.168.0.0/16") {
		t.Fatalf("configured exclusions lost: %v", cfg.ExcludePrefixes)
	}

	// Absent links and failed probes keep the last known endpoint.
	present = false
	c.refreshLinuxUnderlay(ctx)
	if err := answer("203.0.113.9"); err == nil {
		t.Fatal("endpoint forgotten while the interface is absent")
	}
	present, discoverErr = true, errors.New("wg failed")
	c.refreshLinuxUnderlay(ctx)
	if err := answer("203.0.113.9"); err == nil {
		t.Fatal("endpoint forgotten after a failed probe")
	}

	// A moved endpoint releases the old address.
	discoverErr, endpoints = nil, []string{"203.0.113.10/32"}
	c.refreshLinuxUnderlay(ctx)
	if err := answer("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if err := answer("203.0.113.10"); err == nil {
		t.Fatal("new endpoint accepted")
	}
}

func TestLinuxExitClampsMSS(t *testing.T) {
	cfg := linuxTestConfig(t)
	cfg.Mappings[0].Via6 = "fd00:10::2"
	script := linuxExitNftScript(cfg, map[string]int{"gate-wg": 1420})
	const syn = "tcp flags & (syn|rst) == syn tcp option maxseg size set"
	for _, want := range []string{
		`iifname "gate-in" oifname "gate-wg" meta mark 101 ` + syn + " rt mtu",
		`iifname "gate-in2" oifname "gate-ppp" meta mark 102 ` + syn + " rt mtu",
		`iifname "gate-wg" oifname "gate-in" meta nfproto ipv4 ` + syn + " 1380",
		`iifname "gate-wg" oifname "gate-in" meta nfproto ipv6 ` + syn + " 1360",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in:\n%s", want, script)
		}
	}
	if strings.Contains(script, `iifname "gate-ppp" oifname "gate-in2" meta nfproto ipv6`) {
		t.Fatalf("clamp for a family the exit does not use:\n%s", script)
	}
	if strings.Contains(script, `iifname "gate-ppp" oifname "gate-in2" meta nfproto ipv4`) {
		t.Fatalf("clamp without a known MTU:\n%s", script)
	}
	// An accept ends the chain, so a clamp after one would never run.
	last := strings.LastIndex(script, "maxseg")
	if first := strings.Index(script, "meta mark 101 accept"); first < last {
		t.Fatalf("clamp after accept:\n%s", script)
	}
}

func TestLinuxExitRequiresConfiguredNextHop(t *testing.T) {
	const addr = "ip -j -4 addr show dev gate-in"
	const link = "ip -j link show dev gate-wg"
	t.Run("missing_alias", func(t *testing.T) {
		for _, text := range []string{`[{"ifname":"gate-in","addr_info":[{"family":"inet","local":"172.30.10.3","prefixlen":24}]}]`, `[{}]`, `[ ]`} {
			respond, calls := fakeLinuxTools(t)
			respond(link, "out", fakeLinkUp)
			respond(addr, "out", text)
			if _, err := prepareLinuxExit(context.Background(), linuxTestConfig(t).Mappings[0]); err == nil || !strings.Contains(err.Error(), "172.30.10.2 is not configured on gate-in") {
				t.Fatalf("%s: %v", text, err)
			}
			if strings.Contains(calls(), "replace") {
				t.Fatalf("changed routes without a next hop:\n%s", calls())
			}
		}
	})
	t.Run("absent_tap_is_not_an_error", func(t *testing.T) {
		respond, _ := fakeLinuxTools(t)
		respond(link, "out", fakeLinkUp)
		respond(addr, "err", `Device "gate-in" does not exist.`)
		if up, err := prepareLinuxExit(context.Background(), linuxTestConfig(t).Mappings[0]); err != nil || !up {
			t.Fatalf("up=%v err=%v", up, err)
		}
	})
	t.Run("ipv6_textual_form", func(t *testing.T) {
		respond, _ := fakeLinuxTools(t)
		respond(link, "out", fakeLinkUp)
		respond("ip -j -6 addr show dev gate-in", "out", `[{"addr_info":[{"family":"inet6","local":"fd00:10::2","prefixlen":64}]}]`)
		cfg := linuxTestConfig(t)
		cfg.Mappings[0].Via6 = "fd00:10:0:0::2"
		if _, err := prepareLinuxExit(context.Background(), cfg.Mappings[0]); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLinuxExitFirewallIsStaticAfterSetup(t *testing.T) {
	respond, _ := fakeLinuxTools(t)
	respond("ip -j link show dev gate-wg", "out", fakeLinkUp)
	respond("ip -j link show dev gate-ppp", "out", fakeLinkUp)
	cfg := linuxTestConfig(t)
	defer delete(linuxExitStates, cfg.StateFile)
	backend := &VPPBackend{Config: cfg}
	if err := backend.EnsureLinuxExits(); err != nil {
		t.Fatal(err)
	}
	stdin := filepath.Join(os.Getenv("FAKE_DIR"), "nft.stdin")
	data, err := os.ReadFile(stdin)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `iifname "gate-wg" oifname "gate-in" meta nfproto ipv4 tcp flags & (syn|rst) == syn tcp option maxseg size set 1380`) {
		t.Fatalf("exit MTU not used:\n%s", data)
	}
	if err := os.Remove(stdin); err != nil {
		t.Fatal(err)
	}
	// DNS answers must not wait for nftables, or fail with it, once the rules are in place.
	respond("nft -f -", "err", "Error: nft failed")
	if err := backend.EnsureLinuxExits(); err != nil {
		t.Fatalf("route barrier touched nftables: %v", err)
	}
	if _, err := os.Stat(stdin); err == nil {
		t.Fatal("route barrier ran nft")
	}
	// A background pass does rebuild the table, and reports a failure.
	if err := backend.syncLinuxExits(true); err == nil {
		t.Fatal("firewall failure hidden")
	}
	if err := os.Remove(filepath.Join(os.Getenv("FAKE_DIR"), "nft_-f_-.err")); err != nil {
		t.Fatal(err)
	}
	if err := backend.syncLinuxExits(true); err != nil {
		t.Fatal(err)
	}
	if data, err = os.ReadFile(stdin); err != nil || !strings.Contains(string(data), "table inet egress_gate_linux {") {
		t.Fatalf("no rebuild: %s %v", data, err)
	}
}

func TestLinuxExitDisablesRPFilter(t *testing.T) {
	read := func(t *testing.T, path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(data))
	}
	t.Run("both_interfaces_are_corrected", func(t *testing.T) {
		sysctl := useFakeSysctl(t)
		sysctl("all", "0")
		strict, loose, other := sysctl("gate-wg", "1"), sysctl("gate-in", "2"), sysctl("eth0", "1")
		if note := ensureLinuxExitRPFilter(linuxTestConfig(t).Mappings[0]); note != "" {
			t.Fatal(note)
		}
		if read(t, strict) != "0" || read(t, loose) != "0" {
			t.Fatalf("not disabled: %s %s", read(t, strict), read(t, loose))
		}
		if read(t, other) != "1" {
			t.Fatal("changed an unrelated interface")
		}
	})
	t.Run("absent_interface_is_ignored", func(t *testing.T) {
		sysctl := useFakeSysctl(t)
		sysctl("all", "0")
		if note := ensureLinuxExitRPFilter(linuxTestConfig(t).Mappings[0]); note != "" {
			t.Fatal(note)
		}
	})
	t.Run("all_is_reported_not_changed", func(t *testing.T) {
		sysctl := useFakeSysctl(t)
		all := sysctl("all", "1")
		note := ensureLinuxExitRPFilter(linuxTestConfig(t).Mappings[0])
		if !strings.Contains(note, "net.ipv4.conf.all.rp_filter=1") {
			t.Fatalf("note %q", note)
		}
		if read(t, all) != "1" {
			t.Fatal("changed a host-wide sysctl")
		}
	})
	t.Run("ipv6_only_exit_is_skipped", func(t *testing.T) {
		sysctl := useFakeSysctl(t)
		path := sysctl("gate-wg", "1")
		m := linuxTestConfig(t).Mappings[0]
		m.Via, m.Via6 = "", "fd00:10::2"
		ensureLinuxExitRPFilter(m)
		if read(t, path) != "1" {
			t.Fatal("changed IPv4 setting for an IPv6-only exit")
		}
	})
	t.Run("recreated_interface_is_corrected_again", func(t *testing.T) {
		respond, _ := fakeLinuxTools(t)
		respond("ip -j link show dev gate-wg", "out", fakeLinkUp)
		respond("ip -j link show dev gate-ppp", "out", fakeLinkUp)
		path := filepath.Join(linuxSysctlRoot, "net/ipv4/conf/gate-wg/rp_filter")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		backend := &VPPBackend{Config: linuxTestConfig(t)}
		state := &linuxExitState{}
		for range 2 {
			if err := os.WriteFile(path, []byte("2\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := backend.prepareLinuxExits(state); err != nil {
				t.Fatal(err)
			}
			if read(t, path) != "0" {
				t.Fatal("rp_filter not corrected")
			}
		}
	})
	t.Run("host_wide_problem_reaches_status_without_failing", func(t *testing.T) {
		respond, _ := fakeLinuxTools(t)
		respond("ip -j link show dev gate-wg", "out", fakeLinkUp)
		respond("ip -j link show dev gate-ppp", "out", fakeLinkUp)
		path := filepath.Join(linuxSysctlRoot, "net/ipv4/conf/all/rp_filter")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		state := &linuxExitState{}
		if err := (&VPPBackend{Config: linuxTestConfig(t)}).prepareLinuxExits(state); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(state.status["gate-wg/1001"], "all.rp_filter=1") {
			t.Fatalf("status %+v", state.status)
		}
	})
}

func TestLinuxExitLocalPolicyRule(t *testing.T) {
	respond, calls := fakeLinuxTools(t)
	respond("ip -j link show dev gate-wg", "out", fakeLinkUp)
	m := linuxTestConfig(t).Mappings[0]
	if _, err := prepareLinuxExit(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "ip -4 rule add priority 11001 iif lo fwmark 101 lookup 1001\n") {
		t.Fatalf("no rule for local sockets:\n%s", calls())
	}
	if err := removeLinuxExit(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "ip -4 rule del priority 11001 iif lo fwmark 101 lookup 1001\n") {
		t.Fatalf("local rule not removed:\n%s", calls())
	}
}

func TestLinuxExitMarkedTrafficCannotLeaveElsewhere(t *testing.T) {
	script := linuxExitNftScript(linuxTestConfig(t), nil)
	start, end := strings.Index(script, "chain output"), strings.Index(script, "chain nat")
	if start < 0 || end < start {
		t.Fatalf("no output chain:\n%s", script)
	}
	output := script[start:end]
	for _, want := range []string{`meta mark 101 oifname != "gate-wg" oifname != "lo" drop`, `meta mark 102 oifname != "gate-ppp" oifname != "lo" drop`} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q in:\n%s", want, output)
		}
	}
}

func TestLinuxExitDNSUpstreamConfiguration(t *testing.T) {
	load := func(t *testing.T, route map[string]any) (*Config, []Rule, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "domains.json")
		writeJSON(t, path, map[string]any{"routes": []any{route}})
		cfg := &Config{StateFile: filepath.Join(t.TempDir(), "state.json"), MaxRoutes: 1000, OverlapPolicy: "first"}
		rules, err := DomainRoutesFromFile(path, cfg)
		return cfg, rules, err
	}
	route := func(via any, dns []any, direct bool) map[string]any {
		exit := map[string]any{"input_interface": "gate-in", "interface": "gate-wg", "table": 1001, "mark": 101, "priority": 11001, "dns_direct": direct}
		out := map[string]any{"name": "wg", "interface": "tap10", "via": via, "domains": []any{"example.org"}, "domain_keywords": []any{"videos"}, "linux_exit": exit}
		if dns != nil {
			out["dns"] = dns
		}
		return out
	}
	expect := func(t *testing.T, rules []Rule, mark uint32) {
		t.Helper()
		if len(rules) != 2 {
			t.Fatalf("rules %+v", rules)
		}
		for _, rule := range rules {
			if rule.UpstreamMark != mark {
				t.Fatalf("%s mark %d, want %d", rule.Pattern, rule.UpstreamMark, mark)
			}
		}
	}
	t.Run("dedicated_upstream_uses_exit", func(t *testing.T) {
		_, rules, err := load(t, route("172.30.10.2", []any{"8.8.8.8", 53}, false))
		if err != nil {
			t.Fatal(err)
		}
		expect(t, rules, 101)
	})
	t.Run("dns_direct_opts_out", func(t *testing.T) {
		_, rules, err := load(t, route("172.30.10.2", []any{"10.61.20.1", 53}, true))
		if err != nil {
			t.Fatal(err)
		}
		expect(t, rules, 0)
	})
	t.Run("global_upstream_is_not_marked", func(t *testing.T) {
		_, rules, err := load(t, route("172.30.10.2", nil, false))
		if err != nil {
			t.Fatal(err)
		}
		expect(t, rules, 0)
	})
	t.Run("family_without_exit_route_is_rejected", func(t *testing.T) {
		if _, _, err := load(t, route("172.30.10.2", []any{"2001:4860:4860::8888", 53}, false)); err == nil || !strings.Contains(err.Error(), "same family") {
			t.Fatalf("IPv6 upstream on an IPv4 exit accepted: %v", err)
		}
		if _, _, err := load(t, route("172.30.10.2", []any{"2001:4860:4860::8888", 53}, true)); err != nil {
			t.Fatalf("dns_direct rejected: %v", err)
		}
		if _, _, err := load(t, route([]any{"172.30.10.2", "fd00:10::2"}, []any{"2001:4860:4860::8888", 53}, false)); err != nil {
			t.Fatalf("dual-stack exit rejected: %v", err)
		}
	})
}

type markResolver struct {
	upstream *Upstream
	mark     uint32
}

func (r *markResolver) DNSUpstreamRoute(Question) (*Upstream, uint32) {
	return r.upstream, r.mark
}
func (r *markResolver) AnswerTTL(Question) *uint32 { return nil }
func (r *markResolver) SuppressAAAA(Question) bool { return false }
func (r *markResolver) Reconcile(context.Context, []Record, *Question, bool) error {
	return nil
}

// startRepeatingUpstream answers any number of queries over UDP and TCP on one port.
func startRepeatingUpstream(t *testing.T, truncateUDP bool) *Upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	host, port := splitHostPort(t, ln.Addr().String())
	pc, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			_, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := replyPacket(60)
			if truncateUDP {
				reply[2] |= 0x02
			}
			_, _ = pc.WriteTo(reply, peer)
		}
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if _, err := readPrefixed(conn); err == nil {
				reply := replyPacket(60)
				_, _ = conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...))
			}
			conn.Close()
		}
	}()
	return &Upstream{host, port}
}

func TestDNSQueryUsesExitMark(t *testing.T) {
	var mu sync.Mutex
	var marks []uint32
	previous := socketMarker
	var failure error
	socketMarker = func(_ uintptr, mark uint32) error {
		mu.Lock()
		defer mu.Unlock()
		marks = append(marks, mark)
		return failure
	}
	defer func() { socketMarker = previous }()
	seen := func() []uint32 {
		mu.Lock()
		defer mu.Unlock()
		out := marks
		marks = nil
		return out
	}
	query := queryPacket()
	isFailure := func(answer []byte) bool {
		msg, err := Decode(answer)
		return err != nil || msg.Flags&15 == 2
	}
	upstream := startRepeatingUpstream(t, false)
	for _, tcp := range []bool{false, true} {
		if answer := NewGate(&markResolver{upstream, 101}, Upstream{"127.0.0.1", 1}).Exchange(query, tcp); isFailure(answer) {
			t.Fatalf("tcp=%v: marked query failed", tcp)
		}
		if got := seen(); len(got) != 1 || got[0] != 101 {
			t.Fatalf("tcp=%v: marks %v", tcp, got)
		}
		if answer := NewGate(&markResolver{upstream, 0}, Upstream{"127.0.0.1", 1}).Exchange(query, tcp); isFailure(answer) {
			t.Fatalf("tcp=%v: unmarked query failed", tcp)
		}
		if got := seen(); len(got) != 0 {
			t.Fatalf("tcp=%v: unexpected marks %v", tcp, got)
		}
	}

	// A truncated UDP answer is retried over TCP, which must keep the mark.
	if answer := NewGate(&markResolver{startRepeatingUpstream(t, true), 101}, Upstream{"127.0.0.1", 1}).Exchange(query, false); isFailure(answer) {
		t.Fatal("TCP retry failed")
	}
	if got := seen(); len(got) != 2 || got[0] != 101 || got[1] != 101 {
		t.Fatalf("retry marks %v", got)
	}

	// No mark means no query at all, instead of a leak through the main table.
	failure = errors.New("operation not permitted")
	if answer := NewGate(&markResolver{upstream, 101}, Upstream{"127.0.0.1", 1}).Exchange(query, false); !isFailure(answer) {
		t.Fatal("query sent without its exit mark")
	}
}

func TestControllerSelectsExitMarkForDNS(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	writeJSON(t, configPath, map[string]any{"state_file": filepath.Join(dir, "state.json"), "lock_files": []any{}, "overlap_policy": "first"})
	domainPath := filepath.Join(dir, "domains.json")
	writeJSON(t, domainPath, map[string]any{"routes": []any{
		map[string]any{"name": "wg", "interface": "tap10", "via": "172.30.10.2", "domains": []any{"example.org"}, "dns": []any{"8.8.8.8", 53}, "linux_exit": map[string]any{"input_interface": "gate-in", "interface": "gate-wg", "table": 1001, "mark": 101, "priority": 11001}},
		map[string]any{"name": "ppp", "interface": "tun11", "via": "172.30.11.2", "domains": []any{"example.net"}, "linux_exit": map[string]any{"input_interface": "gate-in2", "interface": "gate-ppp", "table": 1002, "mark": 102, "priority": 11002}},
	}})
	c, err := NewController(configPath, filepath.Join(dir, "leases.json"), func(*Config) Backend { return NewFakeBackend() }, domainPath)
	if err != nil {
		t.Fatal(err)
	}
	upstream, mark := c.DNSUpstreamRoute(Question{"www.example.org", 1, 1})
	if upstream == nil || upstream.Host != "8.8.8.8" || mark != 101 {
		t.Fatalf("dedicated upstream: %v %d", upstream, mark)
	}
	for _, name := range []string{"www.example.net", "unrelated.test"} {
		if upstream, mark = c.DNSUpstreamRoute(Question{name, 1, 1}); upstream != nil || mark != 0 {
			t.Fatalf("%s: %v %d", name, upstream, mark)
		}
	}
}

func netlinkMessage(kind uint16, body []byte) []byte {
	out := make([]byte, nlmsgHdrLen, netlinkAlign(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint32(out, uint32(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint16(out[4:], kind)
	out = append(out, body...)
	return append(out, make([]byte, netlinkAlign(len(out))-len(out))...)
}

func netlinkAttr(kind uint16, value []byte) []byte {
	out := make([]byte, rtaHdrLen, netlinkAlign(rtaHdrLen+len(value)))
	binary.NativeEndian.PutUint16(out, uint16(rtaHdrLen+len(value)))
	binary.NativeEndian.PutUint16(out[2:], kind)
	out = append(out, value...)
	return append(out, make([]byte, netlinkAlign(len(out))-len(out))...)
}

func netlinkLink(kind uint16, name string) []byte {
	body := make([]byte, ifinfomsgLen)
	body = append(body, netlinkAttr(13, []byte{0, 0, 5, 0xdc})...) // An unrelated attribute comes first.
	body = append(body, netlinkAttr(iflaIfname, append([]byte(name), 0))...)
	return netlinkMessage(kind, body)
}

func netlinkAddr(kind uint16, index uint32) []byte {
	body := make([]byte, ifaddrmsgLen)
	binary.NativeEndian.PutUint32(body[4:], index)
	return netlinkMessage(kind, body)
}

func TestNetlinkInterfaceNames(t *testing.T) {
	nameOf := func(index int) string {
		if index == 7 {
			return "wg0"
		}
		return ""
	}
	batch := bytes.Join([][]byte{
		netlinkLink(rtmNewLink, "ppp0"),
		netlinkLink(rtmDelLink, "abc"),
		netlinkAddr(rtmNewAddr, 7),
		netlinkAddr(rtmDelAddr, 7),
		netlinkAddr(rtmNewAddr, 9),
		netlinkMessage(24, make([]byte, 32)), // A route message is not a link change.
		netlinkLink(rtmNewLink, "tail"),
	}, nil)
	got := strings.Join(netlinkInterfaceNames(batch, nameOf), ",")
	if got != "ppp0,abc,wg0,wg0,tail" {
		t.Fatalf("names %s", got)
	}
	// The top bits of an attribute type are flags, not part of the type.
	flagged := netlinkMessage(rtmNewLink, append(make([]byte, ifinfomsgLen), netlinkAttr(iflaIfname|0x8000, []byte("wg1\x00"))...))
	if names := netlinkInterfaceNames(flagged, nameOf); len(names) != 1 || names[0] != "wg1" {
		t.Fatalf("flagged attribute: %v", names)
	}
	message := netlinkLink(rtmNewLink, "ppp0")
	for n := range message {
		netlinkInterfaceNames(message[:n], nameOf) // Must not panic.
	}
	zero := make([]byte, 64)
	if names := netlinkInterfaceNames(zero, nameOf); len(names) != 0 {
		t.Fatalf("zero length message: %v", names)
	}
	short := netlinkMessage(rtmNewLink, make([]byte, 4))
	if names := netlinkInterfaceNames(short, nameOf); len(names) != 0 {
		t.Fatalf("short body: %v", names)
	}
	badAttr := netlinkMessage(rtmNewLink, append(make([]byte, ifinfomsgLen), 0, 0, 0, 0))
	if names := netlinkInterfaceNames(badAttr, nameOf); len(names) != 0 {
		t.Fatalf("zero length attribute: %v", names)
	}
}

func TestLinuxExitInterfacesOfInterest(t *testing.T) {
	cfg := linuxTestConfig(t)
	got := linuxExitInterfaces(cfg)
	if len(got) != 4 || !got["gate-in"] || !got["gate-in2"] || !got["gate-wg"] || !got["gate-ppp"] {
		t.Fatalf("interfaces %v", got)
	}
	cfg.Mappings[1].Enabled = false
	if linuxExitInterfaces(cfg)["gate-ppp"] {
		t.Fatal("disabled exit watched")
	}
}

// scriptedReader returns queued reads and then blocks until closed.
type scriptedReader struct {
	reads chan any
}

func (r *scriptedReader) Read(buf []byte) (int, error) {
	switch item := (<-r.reads).(type) {
	case []byte:
		return copy(buf, item), nil
	case error:
		return 0, item
	}
	return 0, io.EOF
}

func TestWatchLinkEvents(t *testing.T) {
	const delay = 20 * time.Millisecond
	start := func(t *testing.T) (*scriptedReader, chan struct{}, chan struct{}) {
		t.Helper()
		reader := &scriptedReader{reads: make(chan any, 16)}
		events, finished := make(chan struct{}, 1), make(chan struct{})
		go func() {
			watchLinkEvents(reader, map[string]bool{"ppp0": true}, func(int) string { return "ppp0" }, delay, events)
			close(finished)
		}()
		t.Cleanup(func() {
			reader.reads <- io.EOF
			<-finished
		})
		return reader, events, finished
	}
	expect := func(t *testing.T, events chan struct{}) {
		t.Helper()
		select {
		case <-events:
		case <-time.After(2 * time.Second):
			t.Fatal("no event")
		}
	}
	quiet := func(t *testing.T, events chan struct{}) {
		t.Helper()
		select {
		case <-events:
			t.Fatal("unexpected event")
		case <-time.After(5 * delay):
		}
	}
	t.Run("only_interesting_links_signal", func(t *testing.T) {
		reader, events, _ := start(t)
		reader.reads <- netlinkLink(rtmNewLink, "eth9")
		quiet(t, events)
		reader.reads <- netlinkLink(rtmNewLink, "ppp0")
		expect(t, events)
	})
	t.Run("address_changes_signal", func(t *testing.T) {
		reader, events, _ := start(t)
		reader.reads <- netlinkAddr(rtmNewAddr, 3)
		expect(t, events)
	})
	t.Run("burst_is_merged", func(t *testing.T) {
		reader, events, _ := start(t)
		for range 5 {
			reader.reads <- netlinkLink(rtmNewLink, "ppp0")
		}
		expect(t, events)
		quiet(t, events)
	})
	t.Run("change_after_burst_signals_again", func(t *testing.T) {
		reader, events, _ := start(t)
		reader.reads <- netlinkLink(rtmNewLink, "ppp0")
		expect(t, events)
		reader.reads <- netlinkLink(rtmDelLink, "ppp0")
		expect(t, events)
	})
	t.Run("signal_stays_pending_during_reconciliation", func(t *testing.T) {
		reader, events, _ := start(t)
		for range 2 {
			reader.reads <- netlinkLink(rtmNewLink, "ppp0")
			time.Sleep(5 * delay)
		}
		expect(t, events)
		quiet(t, events)
	})
	t.Run("lost_messages_signal_and_continue", func(t *testing.T) {
		reader, events, _ := start(t)
		reader.reads <- fmt.Errorf("read: %w", syscall.ENOBUFS)
		expect(t, events)
		reader.reads <- netlinkLink(rtmNewLink, "ppp0")
		expect(t, events)
	})
	t.Run("closing_on_shutdown_is_not_reported", func(t *testing.T) {
		var logged bytes.Buffer
		log.SetOutput(&logged)
		defer log.SetOutput(os.Stderr)
		reader := &scriptedReader{reads: make(chan any, 1)}
		reader.reads <- fmt.Errorf("read rtnetlink: %w", os.ErrClosed)
		watchLinkEvents(reader, nil, func(int) string { return "" }, delay, make(chan struct{}, 1))
		if logged.Len() != 0 {
			t.Fatalf("logged: %s", logged.String())
		}
	})
	t.Run("read_failure_stops_only_the_watcher", func(t *testing.T) {
		reader := &scriptedReader{reads: make(chan any, 1)}
		finished := make(chan struct{})
		go func() {
			watchLinkEvents(reader, nil, func(int) string { return "" }, delay, make(chan struct{}, 1))
			close(finished)
		}()
		reader.reads <- errors.New("socket failed")
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatal("watcher kept reading a failed socket")
		}
	})
}

func TestLinuxExitAllowsTapInIptables(t *testing.T) {
	const checkIn = "iptables -w 2 -C FORWARD -i gate-in -j ACCEPT"
	const checkOut = "iptables -w 2 -C FORWARD -o gate-in -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
	const addIn = "iptables -w 2 -I FORWARD 1 -i gate-in -j ACCEPT"
	const addOut = "iptables -w 2 -I FORWARD 2 -o gate-in -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
	setup := func(t *testing.T) (func(string, string, string), func() string, *VPPBackend) {
		t.Helper()
		respond, calls := fakeLinuxTools(t)
		respond("ip -j link show dev gate-wg", "out", fakeLinkUp)
		respond("ip -j link show dev gate-ppp", "out", fakeLinkUp)
		return respond, calls, &VPPBackend{Config: linuxTestConfig(t)}
	}
	t.Run("restored_firewall_loses_rules_and_they_return", func(t *testing.T) {
		respond, calls, backend := setup(t)
		respond(checkIn, "err", "iptables: Bad rule")
		respond(checkOut, "err", "iptables: Bad rule")
		if err := backend.prepareLinuxExits(&linuxExitState{}); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{addIn, addOut} {
			if !strings.Contains(calls(), want+"\n") {
				t.Fatalf("missing %q in:\n%s", want, calls())
			}
		}
	})
	t.Run("present_rules_are_left_alone_and_each_device_checked_once", func(t *testing.T) {
		_, calls, backend := setup(t)
		if err := backend.prepareLinuxExits(&linuxExitState{}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(calls(), " -I FORWARD") {
			t.Fatalf("rule added twice:\n%s", calls())
		}
		if n := strings.Count(calls(), checkIn); n != 1 {
			t.Fatalf("checked %d times:\n%s", n, calls())
		}
	})
	t.Run("failure_is_reported_and_keeps_exits_working", func(t *testing.T) {
		respond, calls, backend := setup(t)
		respond(checkIn, "err", "iptables: Bad rule")
		respond(addIn, "err", "iptables: Permission denied")
		state := &linuxExitState{}
		if err := backend.prepareLinuxExits(state); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(state.status["iptables/gate-in"], "cannot allow gate-in") {
			t.Fatalf("status %+v", state.status)
		}
		if !strings.Contains(calls(), "default metric 100 dev gate-ppp") {
			t.Fatalf("exits not prepared:\n%s", calls())
		}
	})
}
