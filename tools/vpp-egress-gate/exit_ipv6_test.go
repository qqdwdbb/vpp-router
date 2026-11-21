package gate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No test reads the host's interfaces to decide a device's IPv6.
func TestMain(m *testing.M) {
	linuxExitHasIPv6 = func(context.Context, string, bool, string) bool { return false }
	os.Exit(m.Run())
}

func stubExitIPv6(t *testing.T, has map[string]bool) {
	t.Helper()
	previous := linuxExitHasIPv6
	linuxExitHasIPv6 = func(_ context.Context, iface string, _ bool, _ string) bool { return has[iface] }
	t.Cleanup(func() { linuxExitHasIPv6 = previous })
}

func TestGeneratedDeviceIPv6FollowsTheExit(t *testing.T) {
	stubExitIPv6(t, map[string]bool{"wg1": true, "wg2": true})
	off := exitRule("wg2")
	off["ipv6"] = false
	plan, err := PlanDevices(writeDualStackConfig(t, exitRule("wg1"), off, exitRule("ppp0")), emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatalf("%v\n%s", err, plan.Effective)
	}
	routes := planRoutes(t, plan)
	if via, _ := routes[0]["via"].([]any); len(via) != 2 || via[1] != "fd67:7465:6500::2" {
		t.Fatalf("an exit with IPv6 got no IPv6 device: %v", routes[0]["via"])
	}
	if routes[1]["via"] != "172.30.10.6" {
		t.Fatalf("ipv6 false did not stand: %v", routes[1]["via"])
	}
	if routes[2]["via"] != "172.30.10.10" {
		t.Fatalf("an exit without IPv6 got it: %v", routes[2]["via"])
	}
	if !plan.Devices[0].IPv6 || plan.Devices[1].IPv6 || plan.Devices[2].IPv6 {
		t.Fatalf("devices %+v", plan.Devices)
	}

	// Client networks without IPv6 leave it off, and are no error.
	plan, err = PlanDevices(writeGateConfig(t, exitRule("wg1")), emptyDeviceState())
	if err != nil || plan.Devices[0].IPv6 {
		t.Fatalf("err=%v devices %+v", err, plan.Devices)
	}
}

func TestGeneratedDeviceKeepsIPv6WhileTheExitLosesIt(t *testing.T) {
	stubExitIPv6(t, nil)
	state := emptyDeviceState()
	state.Devices["tap-wg1"] = &DeviceEntry{Host: "tap-wg1", ID: 2100, Slot: 0, Exit: "wg1", Table: 1101, Mark: 101, Priority: 11101, ReturnTable: 2101, ReturnPriority: 12101, IPv6: true, IPv6Found: true}
	plan, err := PlanDevices(writeDualStackConfig(t, exitRule("wg1")), state)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Devices[0].IPv6 {
		t.Fatal("IPv6 dropped when the exit lost it for a while")
	}
	// IPv6 the rule asked for ends with the asking, unless the exit has it.
	state.Devices["tap-wg1"].IPv6Found = false
	if plan, err = PlanDevices(writeDualStackConfig(t, exitRule("wg1")), state); err != nil || plan.Devices[0].IPv6 {
		t.Fatalf("err=%v devices %+v", err, plan.Devices)
	}
}

func TestLinuxExitHasIPv6(t *testing.T) {
	stubExitIPv6(t, nil)
	linuxExitHasIPv6 = linuxExitHasIPv6Real
	const global = `[{"ifname":"x","addr_info":[{"family":"inet6","local":"2001:db8::5","prefixlen":64,"scope":"global"}]}]`
	const router = `[{"dst":"default","gateway":"fe80::1","dev":"eth1","protocol":"ra","metric":600}]`
	for _, tc := range []struct {
		name            string
		address, routes string
		gateway         bool
		gateway6        string
		want            bool
	}{
		{"gateway6", "", "", true, "fe80::9", true},
		{"tunnel_with_address", global, "", false, "", true},
		{"tunnel_without_address", "[]", "", false, "", false},
		{"gateway_with_router", global, router, true, "", true},
		{"gateway_without_router", global, "[]", true, "", false},
		{"duplicate_address", `[{"ifname":"x","addr_info":[{"family":"inet6","local":"2001:db8::5","dadfailed":true}]}]`, router, true, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			respond, _ := fakeLinuxTools(t)
			respond("ip -j -6 address show dev eth1 scope global", "out", tc.address)
			respond("ip -j -6 route show default dev eth1", "out", tc.routes)
			if got := linuxExitHasIPv6(context.Background(), "eth1", tc.gateway, tc.gateway6); got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

// gatewayExitMapping is a Linux exit reached through an IPv4 gateway, with IPv6 on and no gateway6.
func gatewayExitMapping(t *testing.T) Mapping {
	t.Helper()
	path := filepath.Join(t.TempDir(), "domains.json")
	writeJSON(t, path, map[string]any{"routes": []any{
		map[string]any{"name": "eth1", "interface": "tap10", "via": []any{"172.30.10.2", "fd67:7465:6500::2"}, "domains": []any{"example.org"},
			"linux_exit": map[string]any{"input_interface": "gate-in", "interface": "eth1", "gateway": "192.0.2.1", "table": 1001, "mark": 101, "priority": 11001}},
	}})
	cfg := &Config{StateFile: filepath.Join(t.TempDir(), "state.json"), MaxRoutes: 1000, OverlapPolicy: "first"}
	if _, err := DomainRoutesFromFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Mappings[0]
}

func TestGatewayExitTakesItsIPv6RouterFromTheInterface(t *testing.T) {
	const learned = "ip -6 route replace table 1001 default metric 100 via fe80::1 onlink dev eth1"
	const removal = "ip -6 route del table 1001 default metric 100"
	setup := func(t *testing.T) (func(string, string, string), func() string) {
		respond, calls := fakeLinuxTools(t)
		respond("ip -j link show dev eth1", "out", `[{"ifname":"eth1","flags":["BROADCAST","UP","LOWER_UP"],"mtu":1500}]`)
		respond("ip -j -6 addr show dev gate-in", "out", `[{"ifname":"gate-in","addr_info":[{"family":"inet6","local":"fd67:7465:6500::2","prefixlen":126}]}]`)
		return respond, calls
	}
	t.Run("router", func(t *testing.T) {
		respond, calls := setup(t)
		respond("ip -j -6 route show default dev eth1", "out", `[{"dst":"default","gateway":"fe80::2","dev":"eth1","metric":1024},{"dst":"default","gateway":"fe80::1","dev":"eth1","metric":600}]`)
		if up, err := prepareLinuxExit(context.Background(), gatewayExitMapping(t)); err != nil || !up {
			t.Fatalf("up=%v err=%v", up, err)
		}
		if !strings.Contains(calls(), learned+"\n") || !strings.Contains(calls(), "ip -4 route replace table 1001 default metric 100 via 192.0.2.1 onlink dev eth1\n") {
			t.Fatalf("routes:\n%s", calls())
		}
	})
	t.Run("no_router", func(t *testing.T) {
		respond, calls := setup(t)
		respond("ip -j -6 route show default dev eth1", "out", "[]")
		respond("ip -j -6 route show table 1001", "out", `[{"dst":"default","gateway":"fe80::1","dev":"eth1","metric":100},{"type":"unreachable","dst":"default","dev":"lo","metric":32767}]`)
		if _, err := prepareLinuxExit(context.Background(), gatewayExitMapping(t)); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(calls(), "ip -6 route replace table 1001 default metric 100") || !strings.Contains(calls(), removal+"\n") {
			t.Fatalf("a route without a router:\n%s", calls())
		}
		// The rule still sends the exit's IPv6 traffic to the table, where the fallback rejects it.
		if !strings.Contains(calls(), "ip -6 rule add priority 11001 iif gate-in fwmark 101 lookup 1001\n") {
			t.Fatalf("no rule:\n%s", calls())
		}
	})
	t.Run("no_router_nothing_to_remove", func(t *testing.T) {
		respond, calls := setup(t)
		respond("ip -j -6 route show default dev eth1", "out", "[]")
		if _, err := prepareLinuxExit(context.Background(), gatewayExitMapping(t)); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(calls(), removal) {
			t.Fatalf("removed a route that was not there:\n%s", calls())
		}
	})
}

func TestGeneratedIPv6ReadsTheJournal(t *testing.T) {
	useDeviceDirs(t)
	stubExitIPv6(t, map[string]bool{"eth2": true, "wg0": true, "wg9": true})
	exitIPv6Cache.entries = map[string]exitIPv6Entry{}
	devices := map[string]any{
		"tap-wlan0": map[string]any{"host": "tap-wlan0", "id": 2100, "slot": 0, "exit": "wlan0", "ipv6": true},
		"tap-wg0":   map[string]any{"host": "tap-wg0", "id": 2101, "slot": 1, "exit": "wg0"},
		"gm-up2":    map[string]any{"host": "gm-up2", "id": 2102, "slot": 2, "exit": "eth1", "parent": "gw-eth1", "ipv6": true},
		"tap-ppp0":  map[string]any{"host": "tap-ppp0", "id": 2103, "slot": 3, "exit": "ppp0", "ipv6": true, "ipv6_found": true, "retired": true},
		"tap-wg9":   map[string]any{"host": "tap-wg9", "id": 2104, "slot": 4, "exit": "wg9", "retired": true},
	}
	journal := func(lans ...any) {
		writeJSON(t, filepath.Join(deviceStateDir, "devices.json"), map[string]any{"devices": devices, "lan_prefixes": lans})
	}
	journal("10.61.30.0/24", "fd99::/64")
	exit := func(iface string) map[string]any {
		return map[string]any{"linux_exit": map[string]any{"interface": iface, "gateway": "192.0.2.1"}}
	}
	for iface, want := range map[string]bool{
		"wlan0": true,  // a live device with IPv6
		"wg0":   false, // a live device without it, though the exit has it now
		"ppp0":  true,  // retired, and Gate had found IPv6 on it
		"wg9":   true,  // retired without IPv6: Gate looks again, and the exit has it
		"eth2":  true,  // no device yet, the exit has IPv6
		"eth3":  false, // no device yet, the exit has none
	} {
		if got := GeneratedIPv6(exit(iface)); got != want {
			t.Errorf("%s: got %v", iface, got)
		}
	}
	named := exit("eth1")
	named["name"] = "up2"
	if !GeneratedIPv6(named) {
		t.Error("a gateway of a shared interface is found by its name")
	}
	stated := exit("wlan0")
	stated["ipv6"] = false
	if GeneratedIPv6(stated) {
		t.Error("the rule's own ipv6 is Gate's to read, not the journal's")
	}
	journal("10.61.30.0/24")
	if GeneratedIPv6(exit("wlan0")) || GeneratedIPv6(exit("eth2")) {
		t.Error("IPv6 without client networks that have it")
	}
}
