package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useDeviceDirs(t *testing.T) {
	t.Helper()
	stateDir := deviceStateDir
	deviceStateDir = t.TempDir()
	t.Cleanup(func() { deviceStateDir = stateDir })
}

func exitRule(iface string) map[string]any {
	return map[string]any{"domains": []any{iface + ".example"}, "linux_exit": map[string]any{"interface": iface, "masquerade": true}}
}

func proxyRule() map[string]any {
	return map[string]any{"name": "proxy", "domains": []any{"proxy.example"}, "fake_dns": []any{"127.0.0.1", 5354}, "fakeip_range": "198.18.0.0/15"}
}

func writeGateConfig(t *testing.T, routes ...map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "egress-gate.json")
	list := make([]any, len(routes))
	for i, route := range routes {
		list[i] = route
	}
	// Never the default socket: on a machine running VPP, a sync would attach to the real one.
	socket := filepath.Join(filepath.Dir(path), "no-vpp.sock")
	writeJSON(t, path, map[string]any{"upstream": []any{"10.61.20.2", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "vpp_socket": socket, "routes": list})
	return path
}

func emptyDeviceState() *DeviceState { return &DeviceState{Devices: map[string]*DeviceEntry{}} }

func planRoutes(t *testing.T, plan *DevicePlan) []map[string]any {
	t.Helper()
	var doc struct {
		Routes []map[string]any `json:"routes"`
	}
	if err := json.Unmarshal([]byte(plan.Effective), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Routes
}

func TestPlanDevicesGeneratesRulesAndDevices(t *testing.T) {
	path := writeGateConfig(t, exitRule("wg1"), exitRule("ppp0"), exitRule("eth0.5"),
		map[string]any{"name": "native", "interface": "wg2", "via": "10.62.30.1", "domains": []any{"native.example"}}, proxyRule())
	before, _ := os.ReadFile(path)
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatalf("Gate refuses the generated configuration: %v\n%s", err, plan.Effective)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the user's configuration was changed")
	}
	routes := planRoutes(t, plan)
	for i, want := range []struct{ name, iface, via, input string }{
		{"wg1", "tap2100", "172.30.10.2", "tap-wg1"},
		{"ppp0", "tap2101", "172.30.10.6", "tap-ppp0"},
		{"eth0_5", "tap2102", "172.30.10.10", "tap-eth0.5"},
	} {
		exit := routes[i]["linux_exit"].(map[string]any)
		if routes[i]["name"] != want.name || routes[i]["interface"] != want.iface || routes[i]["via"] != want.via || exit["input_interface"] != want.input {
			t.Fatalf("route %d: %v", i, routes[i])
		}
		if _, leaked := routes[i]["device"]; leaked {
			t.Fatalf("device reached Gate: %v", routes[i])
		}
	}
	if routes[3]["interface"] != "wg2" || routes[3]["via"] != "10.62.30.1" {
		t.Fatalf("a rule naming its interface changed: %v", routes[3])
	}
	if routes[4]["interface"] != "tap2081" || routes[4]["tproxy_interface"] != deviceProxyHost || routes[4]["tproxy_port"] != float64(2082) {
		t.Fatalf("proxy: %v", routes[4])
	}
	if strings.Contains(plan.Effective, "lan_prefixes") {
		t.Fatal("lan_prefixes reached Gate")
	}
	for _, want := range []string{
		"create tap id 2100 host-if-name tap-wg1 hw-addr 02:67:74:08:34:01 host-mac-addr 02:67:74:08:34:02 host-mtu-size 1500 attach persist\n",
		"set interface mtu packet 1500 tap2100\n",
		"set interface ip address tap2100 172.30.10.1/30\n",
		"set interface rx-mode tap2100 interrupt\n",
		"create tap id 2101 host-if-name tap-ppp0 hw-addr 02:67:74:08:35:01 host-mac-addr 02:67:74:08:35:02 host-mtu-size 1500 attach persist\n",
		"create tap id 2081 host-if-name gate-tproxy",
		"set interface ip address tap2081 172.30.20.1/24\n",
	} {
		if !strings.Contains(plan.CLI, want) {
			t.Fatalf("missing %q in:\n%s", want, plan.CLI)
		}
	}
	for _, want := range []string{`iifname "tap-wg1" meta mark 0 drop`, `iifname "tap-eth0.5" meta mark 0 drop`, `iifname "gate-tproxy" drop`} {
		if !strings.Contains(plan.Fixed, want) {
			t.Fatalf("missing %q in:\n%s", want, plan.Fixed)
		}
	}
	if strings.Contains(plan.Fixed, "wg2") {
		t.Fatalf("guard for a device it does not own:\n%s", plan.Fixed)
	}
}

// The README's input must really complete to the full form it shows.
func TestReadmeExampleCompletesToItsDocumentedForm(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	var documents []map[string]any
	for _, block := range strings.Split(string(raw), "```json\n")[1:] {
		text, _, _ := strings.Cut(block, "```")
		if !strings.Contains(text, `"linux_exit"`) {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(text), &doc); err != nil {
			t.Fatalf("README example is not JSON: %v\n%s", err, text)
		}
		documents = append(documents, doc)
	}
	if len(documents) != 2 {
		t.Fatalf("expected the input and its full form, found %d examples", len(documents))
	}
	path := filepath.Join(t.TempDir(), "gate.json")
	writeJSON(t, path, documents[0])
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatal(err)
	}
	got, _ := json.MarshalIndent(planRoutes(t, plan), "", " ")
	want, _ := json.MarshalIndent(documents[1]["routes"], "", " ")
	if string(got) != string(want) {
		t.Fatalf("README shows:\n%s\ngenerated:\n%s", want, got)
	}
	// Everything the generated CLI does for a device must appear in the hand-written recipe.
	for _, line := range deviceCLILines(plan.Devices[0])[:2] {
		if !strings.Contains(string(raw), line) {
			t.Fatalf("README's hand-written setup lacks %q", line)
		}
	}
}

func TestPlanDevicesSkipsRulesWithNothingToDivert(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	empty := write("empty.domains", "# add one domain per line\n\n   \n")
	full := write("full.domains", "# a comment\nexample.org\n")
	ranges := write("full.ranges", "203.0.113.0/24\n")
	exit := func(iface string, extra map[string]any) map[string]any {
		rule := map[string]any{"linux_exit": map[string]any{"interface": iface}}
		for key, value := range extra {
			rule[key] = value
		}
		return rule
	}
	path := filepath.Join(dir, "gate.json")
	doc := map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "routes": []any{
		exit("wg0", nil),
		exit("wg1", map[string]any{"domains": []any{}}),
		exit("wg2", map[string]any{"domain_files": []any{empty}}),
		exit("wg3", map[string]any{"domain_files": []any{full}}),
		exit("wg4", map[string]any{"ip_range_files": ranges, "via": nil}),
		exit("wg5", map[string]any{"domains": []any{"example.net"}}),
		map[string]any{"name": "native", "interface": "wg9", "via": "10.62.30.1", "domains": []any{"native.example"}},
		map[string]any{"name": "vpp-wg8", "interface": "wg8", "via": "10.1.6.1", "domain_files": []any{empty}},
	}}
	delete(doc["routes"].([]any)[4].(map[string]any), "via")
	writeJSON(t, path, doc)
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatalf("%v\n%s", err, plan.Effective)
	}
	var hosts []string
	for _, d := range plan.Devices {
		hosts = append(hosts, d.Host)
	}
	if strings.Join(hosts, ",") != "tap-wg3,tap-wg4,tap-wg5" {
		t.Fatalf("devices %v", hosts)
	}
	if routes := planRoutes(t, plan); len(routes) != 4 || routes[3]["interface"] != "wg9" {
		t.Fatalf("routes %v", routes)
	}
	// Rules stop asking for a device when they lose their last domain.
	state := journalFrom(t, plan)
	if err := os.WriteFile(full, []byte("# nothing left\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	next, err := PlanDevices(path, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Retired) != 1 || next.Retired[0].Host != "tap-wg3" {
		t.Fatalf("retired %+v", next.Retired)
	}
	// Gate's loader reports a missing file; it is not an empty rule.
	writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"},
		"routes": []any{exit("wg0", map[string]any{"domain_files": []any{filepath.Join(dir, "missing.domains")}})}})
	plan, err = PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err == nil {
		t.Fatal("a missing file went unnoticed")
	}
}

func writeDualStackConfig(t *testing.T, routes ...map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gate.json")
	list := make([]any, len(routes))
	for i, route := range routes {
		list[i] = route
	}
	writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24", "fd99:77::/64"},
		"vpp_socket": filepath.Join(filepath.Dir(path), "no-vpp.sock"), "routes": list})
	return path
}

func TestPlanDevicesIPv6(t *testing.T) {
	v6 := exitRule("wg1")
	v6["ipv6"] = true
	v4 := exitRule("ppp0")
	proxy := proxyRule()
	proxy["fakeip_range"] = []any{"198.18.0.0/15", "2001:2::/48"}
	plan, err := PlanDevices(writeDualStackConfig(t, v6, v4, proxy), emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatalf("%v\n%s", err, plan.Effective)
	}
	routes := planRoutes(t, plan)
	if via := routes[0]["via"].([]any); len(via) != 2 || via[0] != "172.30.10.2" || via[1] != "fd67:7465:6500::2" {
		t.Fatalf("via %v", via)
	}
	if routes[1]["via"] != "172.30.10.6" {
		t.Fatalf("an exit that did not ask for IPv6 got it: %v", routes[1]["via"])
	}
	if via := routes[2]["via"].([]any); via[1] != "fd67:7465:6501::2" {
		t.Fatalf("proxy via %v", via)
	}
	if strings.Contains(plan.Effective, `"ipv6"`) {
		t.Fatalf("ipv6 reached Gate:\n%s", plan.Effective)
	}
	for _, want := range []string{"set interface ip address tap2100 fd67:7465:6500::1/126\n", "set interface ip address tap2081 fd67:7465:6501::1/64\n"} {
		if !strings.Contains(plan.CLI, want) {
			t.Fatalf("missing %q in:\n%s", want, plan.CLI)
		}
	}
	if strings.Contains(plan.CLI, "fd67:7465:6500::5/") {
		t.Fatalf("IPv6 on a device that did not ask:\n%s", plan.CLI)
	}
	// The VPP address must come first in the CLI before the interface comes up.
	if strings.Index(plan.CLI, "fd67:7465:6500::1/126") > strings.Index(plan.CLI, "set interface state tap2100 up") {
		t.Fatalf("order:\n%s", plan.CLI)
	}
}

func TestSyncDevicesIPv6Commands(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "err", `Device "tap-wg1" does not exist.`)
	respond("ip -d -j link show dev tap-ppp0", "err", `Device "tap-ppp0" does not exist.`)
	for name, value := range map[string]string{"net/ipv6/conf/all/forwarding": "0", "net/ipv6/conf/wlan0/accept_ra": "1", "net/ipv6/conf/br0/accept_ra": "0", "net/ipv6/conf/tap-wg1/accept_ra": "1", "net/ipv6/conf/tap-wg1/autoconf": "1"} {
		path := filepath.Join(linuxSysctlRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) string {
		data, _ := os.ReadFile(filepath.Join(linuxSysctlRoot, name))
		return strings.TrimSpace(string(data))
	}
	v6 := exitRule("wg1")
	v6["ipv6"] = true
	// The first device has no IPv6, so the second holds the main table route of that family.
	if err := SyncDevices(writeDualStackConfig(t, exitRule("ppp0"), v6), false); err != nil {
		t.Fatal(err)
	}
	log := calls()
	for _, want := range []string{
		"ip -6 address replace fd67:7465:6500::6/126 dev tap-wg1 nodad\n",
		"ip -6 route replace fd99:77::/64 via fd67:7465:6500::5 dev tap-wg1 table 2102\n",
		"ip -6 rule add priority 12102 iif wg1 lookup 2102\n",
		"ip -6 route replace fd99:77::/64 via fd67:7465:6500::5 dev tap-wg1\n",
		"ip -4 route replace 10.64.30.0/24 via 172.30.10.1 dev tap-ppp0\n",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Contains(log, "ip -6 address replace fd67:7465:6500::2") || strings.Contains(log, "ip -6 rule add priority 12101") {
		t.Fatalf("IPv6 on the device that did not ask:\n%s", log)
	}
	if read("net/ipv6/conf/all/forwarding") != "1" || read("net/ipv6/conf/wlan0/accept_ra") != "2" || read("net/ipv6/conf/br0/accept_ra") != "0" {
		t.Fatalf("forwarding %s, wlan0 %s, br0 %s", read("net/ipv6/conf/all/forwarding"), read("net/ipv6/conf/wlan0/accept_ra"), read("net/ipv6/conf/br0/accept_ra"))
	}
	if read("net/ipv6/conf/tap-wg1/accept_ra") != "0" || read("net/ipv6/conf/tap-wg1/autoconf") != "0" {
		t.Fatal("a device must not take addresses from router advertisements")
	}
}

func TestIPv6ForwardingLeavesAnEnabledHostAlone(t *testing.T) {
	useDeviceDirs(t)
	respond, _ := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	for name, value := range map[string]string{"net/ipv6/conf/all/forwarding": "2", "net/ipv6/conf/eth0/accept_ra": "1"} {
		path := filepath.Join(linuxSysctlRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	v6 := exitRule("wg1")
	v6["ipv6"] = true
	if err := SyncDevices(writeDualStackConfig(t, v6), false); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"net/ipv6/conf/all/forwarding": "2", "net/ipv6/conf/eth0/accept_ra": "1"} {
		data, _ := os.ReadFile(filepath.Join(linuxSysctlRoot, name))
		if strings.TrimSpace(string(data)) != want {
			t.Fatalf("%s changed to %s", name, data)
		}
	}
}

func TestIPv6TurnsOffOnALiveDevice(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	v6 := exitRule("wg1")
	v6["ipv6"] = true
	path := writeDualStackConfig(t, v6)
	if err := SyncDevices(path, false); err != nil {
		t.Fatal(err)
	}
	respond("ip -j -6 route show table 2101", "out", `[{"dst":"fd99:77::/64","dev":"tap-wg1"}]`)
	if err := SyncDevices(writeDualStackConfig(t, exitRule("wg1")), false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ip -6 address del fd67:7465:6500::2/126 dev tap-wg1\n", "ip -6 rule del priority 12101 iif wg1 lookup 2101\n", "ip -6 route del fd99:77::/64 table 2101\n"} {
		if !strings.Contains(calls(), want) {
			t.Fatalf("missing %q in:\n%s", want, calls())
		}
	}
}

func TestRunningVPPFollowsIPv6OnAnExistingDevice(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "out", fakeUsedLink)
	vppctl, err := os.ReadFile(filepath.Join(os.Getenv("FAKE_DIR"), "ip"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("FAKE_DIR"), "vppctl"), vppctl, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "cli.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(ipv6 bool) string {
		rule := exitRule("wg1")
		if ipv6 {
			rule["ipv6"] = true
		}
		path := filepath.Join(t.TempDir(), "gate.json")
		writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24", "fd99:77::/64"}, "vpp_socket": socket, "routes": []any{rule}})
		return path
	}
	respond("vppctl -s "+socket+" show interface", "out", "tap2100   5   up\n")
	respond("vppctl -s "+socket+" show interface addr", "out", "tap2100 (up):\r\n  L3 172.30.10.1/30\r\n")
	if err := SyncDevices(write(true), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "vppctl -s "+socket+" set interface ip address tap2100 fd67:7465:6500::1/126\n") {
		t.Fatalf("VPP did not get IPv6:\n%s", calls())
	}
	respond("vppctl -s "+socket+" show interface addr", "out", "tap2100 (up):\r\n  L3 172.30.10.1/30\r\n  L3 fd67:7465:6500::1/126\r\n")
	if err := SyncDevices(write(false), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "set interface ip address del tap2100 fd67:7465:6500::1/126\n") {
		t.Fatalf("VPP kept IPv6:\n%s", calls())
	}
}

func TestIPv6ForwardingWaitsForAnExitThatUsesIt(t *testing.T) {
	useDeviceDirs(t)
	respond, _ := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg0", "out", fakeTapLink)
	path := filepath.Join(linuxSysctlRoot, "net/ipv6/conf/all/forwarding")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SyncDevices(writeDualStackConfig(t, exitRule("wg0")), false); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); strings.TrimSpace(string(data)) != "0" {
		t.Fatalf("forwarding %s with no IPv6 exit", data)
	}
}

func gatewayRule(name, iface, gateway string) map[string]any {
	return map[string]any{"name": name, "owner": "host", "domains": []any{name + ".example"}, "linux_exit": map[string]any{"interface": iface, "gateway": gateway, "masquerade": true}}
}

func TestPlanDevicesSharedTAP(t *testing.T) {
	a, b := gatewayRule("eth1-a", "eth1", "192.0.2.1"), gatewayRule("eth1-b", "eth1", "192.0.2.2")
	plan, err := PlanDevices(writeGateConfig(t, exitRule("wg1"), a, b), emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatalf("Gate refuses two gateways on one interface: %v\n%s", err, plan.Effective)
	}
	var hosts []string
	for _, d := range plan.Devices {
		hosts = append(hosts, d.Host)
	}
	if strings.Join(hosts, ",") != "tap-wg1,gw-eth1,gm-eth1-a,gm-eth1-b" {
		t.Fatalf("devices %v", hosts)
	}
	routes := planRoutes(t, plan)
	if routes[1]["interface"] != routes[2]["interface"] {
		t.Fatalf("VPP must see one device: %v %v", routes[1]["interface"], routes[2]["interface"])
	}
	if routes[1]["via"] == routes[2]["via"] {
		t.Fatalf("next hops must differ: %v", routes[1]["via"])
	}
	exitA := routes[1]["linux_exit"].(map[string]any)
	exitB := routes[2]["linux_exit"].(map[string]any)
	if exitA["input_interface"] != "gm-eth1-a" || exitA["gateway"] != "192.0.2.1" || exitB["input_interface"] != "gm-eth1-b" || exitA["table"] == exitB["table"] || exitA["mark"] == exitB["mark"] {
		t.Fatalf("exits %v %v", exitA, exitB)
	}
	if strings.Count(plan.CLI, "create tap id") != 2 || !strings.Contains(plan.CLI, "host-if-name gw-eth1 ") {
		t.Fatalf("CLI:\n%s", plan.CLI)
	}
	name := plan.Devices[1].vppInterface()
	for _, d := range plan.Devices[2:] {
		if !strings.Contains(plan.CLI, fmt.Sprintf("set interface ip address %s %s/30\n", name, d.vppAddress())) {
			t.Fatalf("missing the address of %s:\n%s", d.Host, plan.CLI)
		}
	}
	if strings.Index(plan.CLI, "host-if-name gw-eth1 ") > strings.Index(plan.CLI, plan.Devices[2].vppAddress().String()) {
		t.Fatalf("the TAP must come first:\n%s", plan.CLI)
	}
	for _, want := range []string{`iifname "gm-eth1-a" meta mark 0 drop`, `iifname "gm-eth1-b" meta mark 0 drop`, `iifname "gw-eth1" drop`} {
		if !strings.Contains(plan.Fixed, want) {
			t.Fatalf("missing %q:\n%s", want, plan.Fixed)
		}
	}
	// One gateway alone is an ordinary device, with no macvlan.
	single, err := PlanDevices(writeGateConfig(t, gatewayRule("eth2-a", "eth2", "192.0.2.1")), emptyDeviceState())
	if err != nil || len(single.Devices) != 1 || single.Devices[0].Host != "tap-eth2" {
		t.Fatalf("%+v %v", single, err)
	}
}

func TestPlanDevicesSharedTAPRefusals(t *testing.T) {
	noName := gatewayRule("x", "eth1", "192.0.2.2")
	delete(noName, "name")
	badName := gatewayRule("a b", "eth1", "192.0.2.2")
	noGateway := exitRule("eth1")
	noGateway["name"] = "c"
	named := map[string]any{"name": "d", "interface": "tap9", "via": "172.31.0.2", "domains": []any{"d.example"}, "linux_exit": map[string]any{"interface": "eth1", "input_interface": "x", "table": 1500, "mark": 500, "priority": 15000, "gateway": "192.0.2.2"}}
	for name, tc := range map[string]struct {
		rule map[string]any
		want string
	}{
		"name": {noName, "needs a name"}, "bad_name": {badName, "needs a name"},
		"no_gateway": {noGateway, "its own gateway"}, "same_gateway": {gatewayRule("e", "eth1", "192.0.2.1"), "its own gateway"},
		"named_device": {named, "cannot name a device"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PlanDevices(writeGateConfig(t, gatewayRule("a", "eth1", "192.0.2.1"), tc.rule), emptyDeviceState()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestGateStillRefusesOtherSharedInterfaces(t *testing.T) {
	// Two different Linux exits on one VPP interface could not be told apart by next hop alone.
	cfg := linuxTestConfig(t)
	cfg.Mappings[1].Interface = cfg.Mappings[0].Interface
	if err := validateLinuxExits(cfg); err == nil {
		t.Fatal("two exits on one VPP interface accepted")
	}
	cfg.Mappings[1].LinuxExit.Interface = cfg.Mappings[0].LinuxExit.Interface
	if err := validateLinuxExits(cfg); err != nil {
		t.Fatalf("gateways of one interface refused: %v", err)
	}
}

func TestSyncDevicesSharedTAPCommands(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev gw-eth1", "err", `Device "gw-eth1" does not exist.`)
	respond("ip -d -j link show dev gm-a", "err", `Device "gm-a" does not exist.`)
	respond("ip -d -j link show dev gm-b", "err", `Device "gm-b" does not exist.`)
	for name, value := range map[string]string{"net/ipv4/conf/gw-eth1/arp_ignore": "0", "net/ipv6/conf/gw-eth1/disable_ipv6": "0", "net/ipv4/conf/gm-a/arp_ignore": "0", "net/ipv4/conf/gm-a/arp_announce": "0"} {
		path := filepath.Join(linuxSysctlRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	two := writeGateConfig(t, gatewayRule("a", "eth1", "192.0.2.1"), gatewayRule("b", "eth1", "192.0.2.2"))
	if err := SyncDevices(two, false); err != nil {
		t.Fatal(err)
	}
	log := calls()
	parent, child := strings.Index(log, "ip tuntap add mode tap multi_queue name gw-eth1"), strings.Index(log, "ip link add gm-a link gw-eth1 address 02:67:6d:00:00:02 type macvlan mode bridge")
	if parent < 0 || child < parent {
		t.Fatalf("the TAP must exist before its macvlans:\n%s", log)
	}
	for _, want := range []string{
		"ip link add gm-b link gw-eth1 address 02:67:6d:00:01:02 type macvlan mode bridge\n",
		"ip link set dev gw-eth1 up\n",
		"ip address replace 172.30.10.2/30 dev gm-a\n",
		"ip address replace 172.30.10.6/30 dev gm-b\n",
		"ip -4 rule add priority 12101 iif eth1 lookup 2101\n",
		"ip -4 route replace 10.64.30.0/24 via 172.30.10.1 dev gm-a\n",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Contains(log, "dev gw-eth1 table") || strings.Contains(log, "address replace 172.30.10.1") || strings.Contains(log, "dev gw-eth1\n") && strings.Contains(log, "address replace") && strings.Contains(log, "/30 dev gw-eth1") {
		t.Fatalf("the shared TAP takes no address or route:\n%s", log)
	}
	read := func(name string) string {
		data, _ := os.ReadFile(filepath.Join(linuxSysctlRoot, name))
		return strings.TrimSpace(string(data))
	}
	if read("net/ipv4/conf/gw-eth1/arp_ignore") != "8" || read("net/ipv6/conf/gw-eth1/disable_ipv6") != "1" || read("net/ipv4/conf/gm-a/arp_ignore") != "1" || read("net/ipv4/conf/gm-a/arp_announce") != "2" {
		t.Fatal("ARP settings")
	}
	// A device already in place stays.
	for _, name := range []string{"gw-eth1", "gm-a", "gm-b"} {
		if err := os.Remove(filepath.Join(os.Getenv("FAKE_DIR"), "ip_-d_-j_link_show_dev_"+name+".err")); err != nil {
			t.Fatal(err)
		}
	}
	respond("ip -d -j link show dev gw-eth1", "out", fakeUsedLink)
	respond("ip -d -j link show dev gm-a", "out", `[{"link":"gw-eth1","linkinfo":{"info_kind":"macvlan"}}]`)
	respond("ip -d -j link show dev gm-b", "out", `[{"link":"gw-eth1","linkinfo":{"info_kind":"macvlan"}}]`)
	if err := os.WriteFile(filepath.Join(os.Getenv("FAKE_DIR"), "log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetupLinks(); err != nil {
		t.Fatal(err)
	}
	if log := calls(); strings.Contains(log, "ip link add") || strings.Contains(log, "tuntap add") || strings.Contains(log, "vppctl") {
		t.Fatalf("setup-links recreated devices or touched VPP:\n%s", log)
	}
	// One of two leaves: the macvlan goes at once, its TAP stays, the other gateway is untouched.
	respond("ip -j -4 route show table 2102", "out", `[{"dst":"10.64.30.0/24","dev":"gm-b"}]`)
	if err := SyncDevices(writeGateConfig(t, gatewayRule("a", "eth1", "192.0.2.1")), false); err != nil {
		t.Fatal(err)
	}
	log = calls()
	if !strings.Contains(log, "ip link delete dev gm-b\n") || strings.Contains(log, "ip link delete dev gm-a") {
		t.Fatalf("retire:\n%s", log)
	}
	state, _ := loadDeviceState()
	if tap := state.Devices["gw-eth1"]; tap == nil || tap.Retired || !tap.SharedTAP {
		t.Fatalf("the last gateway must keep its TAP: %+v", state.Devices)
	}
	if last := state.Devices["gm-a"]; last == nil || last.Retired || last.Parent != "gw-eth1" {
		t.Fatalf("the last gateway must keep its macvlan: %+v", state.Devices)
	}
	if state.Devices["tap-eth1"] != nil {
		t.Fatalf("a gateway that stays must not move: %+v", state.Devices)
	}
	if state.Devices["gw-eth1"].ID != state.Devices["gm-a"].ID || state.Devices["gw-eth1"].ID != 2100 {
		t.Fatalf("the shared TAP must keep its VPP interface: %+v %+v", *state.Devices["gw-eth1"], *state.Devices["gm-a"])
	}
}

func TestRunningVPPGetsAGatewayOnAnExistingSharedTAP(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev gw-eth1", "out", fakeUsedLink)
	for _, name := range []string{"gm-a", "gm-b", "gm-c"} {
		respond("ip -d -j link show dev "+name, "out", `[{"link":"gw-eth1","linkinfo":{"info_kind":"macvlan"}}]`)
	}
	vppctl, err := os.ReadFile(filepath.Join(os.Getenv("FAKE_DIR"), "ip"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("FAKE_DIR"), "vppctl"), vppctl, 0o755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "cli.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	config := func(rules ...any) string {
		path := filepath.Join(t.TempDir(), "gate.json")
		writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "vpp_socket": socket, "routes": rules})
		return path
	}
	a, b, c := func() map[string]any { return gatewayRule("a", "eth1", "192.0.2.1") }, func() map[string]any { return gatewayRule("b", "eth1", "192.0.2.2") }, func() map[string]any { return gatewayRule("c", "eth1", "192.0.2.3") }
	respond("vppctl -s "+socket+" show interface", "out", "tap2100   5   up\n")
	respond("vppctl -s "+socket+" show interface addr", "out", "tap2100 (up):\r\n  L3 172.30.10.1/30\r\n  L3 172.30.10.5/30\r\n")
	if err := SyncDevices(config(a(), b()), false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(calls(), "create tap") || strings.Contains(calls(), "set interface ip address tap2100") {
		t.Fatalf("VPP has all of this:\n%s", calls())
	}
	if err := SyncDevices(config(a(), b(), c()), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "set interface ip address tap2100 172.30.10.9/30\n") {
		t.Fatalf("a new gateway needs its address on the running TAP:\n%s", calls())
	}
	respond("vppctl -s "+socket+" show interface addr", "out", "tap2100 (up):\r\n  L3 172.30.10.1/30\r\n  L3 172.30.10.5/30\r\n  L3 172.30.10.9/30\r\n")
	if err := SyncDevices(config(a(), c()), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "set interface ip address del tap2100 172.30.10.5/30\n") {
		t.Fatalf("a gateway that left keeps its address:\n%s", calls())
	}
	if strings.Contains(calls(), "create tap") || strings.Contains(calls(), "tap2101") {
		t.Fatalf("a gateway leaving must not give VPP another interface:\n%s", calls())
	}
}

func TestRouteOwner(t *testing.T) {
	vpp := func() map[string]any {
		return map[string]any{"name": "vpp-wg1", "owner": "vpp", "interface": "wg1", "via": "10.62.30.1", "domains": []any{"a.example"}}
	}
	host := exitRule("wg1")
	host["owner"] = "host"
	// The same interface name on both sides is fine, because the owner says which is which.
	plan, err := PlanDevices(writeGateConfig(t, vpp(), host), emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatal(err)
	}
	routes := planRoutes(t, plan)
	if routes[0]["interface"] != "wg1" || routes[1]["interface"] != "tap2100" {
		t.Fatalf("routes %v", routes)
	}
	if len(plan.Devices) != 1 || plan.Devices[0].Host != "tap-wg1" {
		t.Fatalf("a VPP rule made a device: %+v", plan.Devices)
	}
	if strings.Contains(plan.Effective, `"owner"`) {
		t.Fatalf("owner reached Gate:\n%s", plan.Effective)
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
		want   string
	}{
		{"unknown", func(r map[string]any) { r["owner"] = "linux" }, "owner must be host or vpp"},
		{"vpp_with_exit", func(r map[string]any) { r["linux_exit"] = map[string]any{"interface": "wg1"} }, "owner vpp cannot have linux_exit"},
		{"vpp_without_interface", func(r map[string]any) { delete(r, "interface") }, "owner vpp needs interface and via"},
		{"vpp_without_via", func(r map[string]any) { delete(r, "via") }, "owner vpp needs interface and via"},
		{"host_without_exit", func(r map[string]any) { r["owner"] = "host"; delete(r, "interface"); delete(r, "via") }, "owner host needs linux_exit"},
		{"checked_while_empty", func(r map[string]any) { r["owner"] = "linux"; delete(r, "domains") }, "owner must be host or vpp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := vpp()
			tc.change(rule)
			if _, err := PlanDevices(writeGateConfig(t, rule), emptyDeviceState()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	// An empty VPP rule waits like any other, and a hand-written TAP path stays allowed.
	empty := vpp()
	delete(empty, "domains")
	path := map[string]any{"name": "proxy-path", "owner": "host", "interface": "tap2490", "via": "10.63.30.2", "domains": []any{"b.example"}}
	if plan, err = PlanDevices(writeGateConfig(t, empty, path), emptyDeviceState()); err != nil {
		t.Fatal(err)
	}
	if routes := planRoutes(t, plan); len(routes) != 1 || routes[0]["interface"] != "tap2490" {
		t.Fatalf("routes %v", routes)
	}
	// A VPP rule may be missing the field, as older files are.
	legacy := vpp()
	delete(legacy, "owner")
	if plan, err = PlanDevices(writeGateConfig(t, legacy), emptyDeviceState()); err != nil || len(plan.Devices) != 0 {
		t.Fatalf("%+v %v", plan, err)
	}
}

// The rule install.py always offers: inert when empty, a TAP once it has a domain.
func TestTProxyTemplate(t *testing.T) {
	dir := t.TempDir()
	domains := filepath.Join(dir, "proxy.domains")
	if err := os.WriteFile(domains, []byte("# empty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gate.json")
	writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "routes": []any{
		map[string]any{"name": "proxy", "owner": "host", "domain_files": []any{filepath.Join(dir, "proxy.domains")}, "fake_dns": []any{"127.0.0.1", 5354},
			"fakeip_range": "198.18.0.0/15", "tproxy_port": 2082},
	}})
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Devices) != 0 || len(planRoutes(t, plan)) != 0 {
		t.Fatalf("an empty template took effect: %+v", plan.Devices)
	}
	if err := os.WriteFile(domains, []byte("example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if plan, err = PlanDevices(path, emptyDeviceState()); err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Devices) != 1 || plan.Devices[0].Host != deviceProxyHost {
		t.Fatalf("%+v", plan.Devices)
	}
	route := planRoutes(t, plan)[0]
	if route["interface"] != "tap2081" || route["via"] != "172.30.20.2" || route["tproxy_interface"] != deviceProxyHost || route["tproxy_port"] != float64(2082) {
		t.Fatalf("%v", route)
	}
	if !strings.Contains(plan.CLI, "create tap id 2081 host-if-name gate-tproxy") {
		t.Fatalf("%s", plan.CLI)
	}
}

func TestPlanDevicesWithOnlyEmptyRules(t *testing.T) {
	path := writeGateConfig(t, map[string]any{"linux_exit": map[string]any{"interface": "wg0"}})
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatalf("Gate refuses a configuration with no rules yet: %v", err)
	}
	if len(plan.Devices) != 0 || !strings.Contains(plan.Effective, `"routes": []`) {
		t.Fatalf("%+v\n%s", plan.Devices, plan.Effective)
	}
}

// With no rules yet, Gate still forwards DNS. It once crashed on the first query.
func TestGateWithNoRulesForwardsDNS(t *testing.T) {
	path := writeGateConfig(t, map[string]any{"linux_exit": map[string]any{"interface": "wg0"}})
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	effective := filepath.Join(dir, "gate.json")
	var doc map[string]any
	if err := json.Unmarshal([]byte(plan.Effective), &doc); err != nil {
		t.Fatal(err)
	}
	doc["state_file"], doc["lease_file"] = filepath.Join(dir, "state.json"), filepath.Join(dir, "leases.json")
	doc["lock_files"] = []any{}
	writeJSON(t, effective, doc)
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			answer := append([]byte{}, buf[:n]...)
			answer[2], answer[3] = 0x81, 0x80
			answer[7] = 1
			answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 9)
			_, _ = server.WriteTo(answer, peer)
		}
	}()
	backend := NewFakeBackend()
	c, err := NewController(effective, filepath.Join(dir, "leases.json"), func(*Config) Backend { return backend }, effective)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Reconcile(context.Background(), nil, nil, false); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"unrelated", "example"} {
		query = append(append(query, byte(len(label))), label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	upstream := Upstream{"127.0.0.1", server.LocalAddr().(*net.UDPAddr).Port}
	answer := NewGate(c, upstream).Exchange(query, false)
	if len(answer) < 12 || answer[3]&0x0f != 0 || answer[7] != 1 || answer[len(answer)-1] != 9 {
		t.Fatalf("answer % x", answer)
	}
}

func journalFrom(t *testing.T, plan *DevicePlan) *DeviceState {
	t.Helper()
	state := emptyDeviceState()
	for _, list := range [][]DeviceEntry{plan.Devices, plan.Retired} {
		for i := range list {
			state.Devices[list[i].Host] = &list[i]
		}
	}
	return state
}

func TestPlanDevicesKeepsNumbersAcrossChanges(t *testing.T) {
	first, err := PlanDevices(writeGateConfig(t, exitRule("wg1"), exitRule("wg2"), exitRule("ppp0")), emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	state := journalFrom(t, first)
	// A new rule comes first and one goes away; the others keep everything they had.
	second, err := PlanDevices(writeGateConfig(t, exitRule("wg9"), exitRule("wg1"), exitRule("ppp0")), state)
	if err != nil {
		t.Fatal(err)
	}
	devices := map[string]DeviceEntry{}
	for _, d := range second.Devices {
		devices[d.Host] = d
	}
	if devices["tap-wg1"] != first.Devices[0] || devices["tap-ppp0"] != first.Devices[2] {
		t.Fatalf("existing devices renumbered:\n%+v\n%+v", first.Devices, second.Devices)
	}
	added, removed := devices["tap-wg9"], first.Devices[1]
	if added.ID == removed.ID || added.Slot == removed.Slot || added.Table == removed.Table || added.Mark == removed.Mark {
		t.Fatalf("a retired device's numbers were reused while VPP may hold it: %+v", added)
	}
	if len(second.Retired) != 1 || second.Retired[0].Host != "tap-wg2" || !strings.Contains(second.Fixed, `iifname "tap-wg2" drop`) {
		t.Fatalf("retired %+v\n%s", second.Retired, second.Fixed)
	}
	if strings.Contains(second.CLI, "tap-wg2") {
		t.Fatalf("VPP would attach a retired device:\n%s", second.CLI)
	}
	// Once the device is gone, its numbers are free again.
	third, err := PlanDevices(writeGateConfig(t, exitRule("wg1"), exitRule("wg3")), journalFrom(t, first))
	if err != nil {
		t.Fatal(err)
	}
	if third.Devices[1].ID == first.Devices[1].ID {
		t.Fatalf("%+v", third.Devices)
	}
}

func TestPlanDevicesChosenValuesStand(t *testing.T) {
	a, b := exitRule("wg0"), exitRule("ppp0")
	for key, value := range map[string]any{"table": 1101, "mark": 101, "priority": 11101} {
		b["linux_exit"].(map[string]any)[key] = value
	}
	plan, err := PlanDevices(writeGateConfig(t, a, b), emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if d := plan.Devices[1]; d.Table != 1101 || d.Mark != 101 || d.Priority != 11101 {
		t.Fatalf("%+v", d)
	}
	if d := plan.Devices[0]; d.Table == 1101 || d.Mark == 101 || d.Priority == 11101 {
		t.Fatalf("allocated a chosen value: %+v", d)
	}
}

func TestPlanDevicesRefusals(t *testing.T) {
	long := "a234567890123456"
	for _, tc := range []struct {
		name   string
		routes []map[string]any
		want   string
	}{
		{"bad_name", []map[string]any{exitRule("bad;name")}, "invalid Linux exit interface"},
		{"too_long", []map[string]any{exitRule(long)}, "invalid Linux exit interface"},
		{"same_exit_without_gateways", []map[string]any{exitRule("wg0"), exitRule("wg0")}, "each needs its own gateway"},
		{"exit_named_like_device", []map[string]any{exitRule("wg0"), exitRule("tap-wg0")}, "name of a generated device"},
		{"same_name", []map[string]any{exitRule("eth0.5"), exitRule("eth0_5")}, "names must be unique"},
		{"device_tun", []map[string]any{{"device": "tun", "domains": []any{"a.example"}, "linux_exit": map[string]any{"interface": "wg0"}}}, "device is no longer an option"},
		{"device_tap", []map[string]any{{"device": "tap", "domains": []any{"a.example"}, "linux_exit": map[string]any{"interface": "wg0"}}}, "device is no longer an option"},
		{"device_on_an_empty_rule", []map[string]any{{"device": "tun", "linux_exit": map[string]any{"interface": "wg0"}}}, "device is no longer an option"},
		{"device_on_proxy", []map[string]any{{"name": "p", "device": "tun", "domains": []any{"a.example"}, "fake_dns": []any{"127.0.0.1", 5354}, "fakeip_range": "198.18.0.0/15"}}, "device is no longer an option"},
		{"via_without_interface", []map[string]any{{"via": "10.0.0.2", "domains": []any{"a.example"}, "linux_exit": map[string]any{"interface": "wg0"}}}, "via requires interface"},
		{"input_without_interface", []map[string]any{{"domains": []any{"a.example"}, "linux_exit": map[string]any{"interface": "wg0", "input_interface": "x"}}}, "input_interface requires interface"},
		{"plain_rule", []map[string]any{{"name": "plain", "domains": []any{"a.example"}}}, "needs interface and via"},
		{"second_proxy", []map[string]any{proxyRule(), proxyRule()}, "names must be unique"},
		{"ipv6_pool_without_lan", []map[string]any{{"name": "p", "domains": []any{"a.example"}, "fake_dns": []any{"127.0.0.1", 5354}, "fakeip_range": []any{"198.18.0.0/15", "2001:2::/48"}}}, "needs an IPv6 entry"},
		{"ipv6_exit_without_lan", []map[string]any{{"ipv6": true, "domains": []any{"a.example"}, "linux_exit": map[string]any{"interface": "wg0"}}}, "needs an IPv6 entry"},
		{"ipv6_not_a_bool", []map[string]any{{"ipv6": "yes", "domains": []any{"a.example"}, "linux_exit": map[string]any{"interface": "wg0"}}}, "ipv6 must be true or false"},
		{"ipv6_on_a_named_interface", []map[string]any{{"name": "n", "ipv6": true, "interface": "wg9", "via": "10.0.0.1", "domains": []any{"a.example"}}}, "ipv6 is for generated devices"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PlanDevices(writeGateConfig(t, tc.routes...), emptyDeviceState()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	var many []map[string]any
	for i := 0; i < deviceMaxExits+1; i++ {
		many = append(many, exitRule("e"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	if _, err := PlanDevices(writeGateConfig(t, many...), emptyDeviceState()); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("too many exits: %v", err)
	}
	for name, doc := range map[string]map[string]any{
		"no_upstream": {"lan_prefixes": []any{"10.64.30.0/24"}, "routes": []any{exitRule("wg0")}},
		"no_lan":      {"upstream": []any{"127.0.0.1", 53}, "routes": []any{exitRule("wg0")}},
		"transit_lan": {"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"172.30.10.0/24"}, "routes": []any{exitRule("wg0")}},
		"bad_lan":     {"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.1/24"}, "routes": []any{exitRule("wg0")}},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gate.json")
			writeJSON(t, path, doc)
			if _, err := PlanDevices(path, emptyDeviceState()); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPlanDevicesKeepsSettingsAndResolvesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wg.domains"), []byte("example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gate.json")
	writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"},
		"listen": []any{[]any{"10.61.20.2", 1053}}, "state_file": "/data/state.json", "exclude_prefixes": []any{"10.0.0.0/8"},
		"routes": []any{map[string]any{"domain_files": []any{filepath.Join(dir, "wg.domains")}, "linux_exit": map[string]any{"interface": "wg0"}}}})
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(plan.Effective), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["state_file"] != "/data/state.json" || len(doc["exclude_prefixes"].([]any)) != 1 || doc["overlap_policy"] != "first" {
		t.Fatalf("settings: %v", doc)
	}
	files := doc["routes"].([]any)[0].(map[string]any)["domain_files"].([]any)
	if files[0] != filepath.Join(dir, "wg.domains") {
		t.Fatalf("relative file not resolved: %v", files)
	}
}

// The generated configuration moves, so a bare domain list name must already be resolved in it.
func TestPlanDevicesKeepsBareDomainFileInDefaultDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gate.json")
	writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"},
		"routes": []any{map[string]any{"domain_files": "wg.domains", "domains": []any{"example.org"}, "linux_exit": map[string]any{"interface": "wg0"}}}})
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(plan.Effective), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc["routes"].([]any)[0].(map[string]any)["domain_files"]; got != "/etc/vpp/gate/wg.domains" {
		t.Fatalf("domain_files %v", got)
	}
}

func TestPlanDevicesSplitConfiguration(t *testing.T) {
	dir := t.TempDir()
	runtime, routes, entry := filepath.Join(dir, "runtime.json"), filepath.Join(dir, "routes.json"), filepath.Join(dir, "entry.json")
	writeJSON(t, runtime, map[string]any{"vpp_socket": "/run/test/cli.sock", "overlap_policy": "first"})
	writeJSON(t, routes, map[string]any{"routes": []any{exitRule("wg0"), proxyRule()}})
	writeJSON(t, entry, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "route_config": runtime, "domain_routes_file": routes})
	plan, err := PlanDevices(entry, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatal(err)
	}
	if plan.VPPSocket != "/run/test/cli.sock" {
		t.Fatalf("socket %s", plan.VPPSocket)
	}
	if strings.Contains(plan.Effective, "domain_routes_file") {
		t.Fatalf("routes not merged:\n%s", plan.Effective)
	}
	writeJSON(t, entry, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "domain_routes_file": "routes.json"})
	if _, err := PlanDevices(entry, emptyDeviceState()); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative link: %v", err)
	}
}

const (
	fakeNoLink   = `Device "%s" does not exist.`
	fakeTapLink  = `[{"linkinfo":{"info_kind":"tun","info_data":{"type":"tap","multi_queue":true,"persist":true}}}]`
	fakeUsedLink = `[{"linkinfo":{"info_kind":"tun","info_data":{"type":"tap","multi_queue":true,"persist":true,"numqueues":1}}}]`
)

func TestSyncDevicesCommands(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "err", `Device "tap-wg1" does not exist.`)
	respond("ip -d -j link show dev tap-ppp0", "err", `Device "tap-ppp0" does not exist.`)
	path := writeGateConfig(t, exitRule("wg1"), exitRule("ppp0"))
	if err := SyncDevices(path, false); err != nil {
		t.Fatal(err)
	}
	log := calls()
	guard := strings.Index(log, "nft -f")
	create := strings.Index(log, "ip tuntap add mode tap multi_queue name tap-wg1")
	up := strings.Index(log, "ip link set dev tap-wg1 up")
	if guard < 0 || create < guard || up < create {
		t.Fatalf("the guard must come first, then the device:\n%s", log)
	}
	for _, want := range []string{
		"ip tuntap add mode tap multi_queue name tap-ppp0\n",
		"ip link set dev tap-ppp0 address 02:67:74:08:35:02\n",
		"ip address replace 172.30.10.2/30 dev tap-wg1\n",
		"ip -4 route replace 10.64.30.0/24 via 172.30.10.1 dev tap-wg1 table 2101\n",
		"ip -4 route replace 10.64.30.0/24 via 172.30.10.5 dev tap-ppp0 table 2102\n",
		"ip -4 route replace 10.64.30.0/24 via 172.30.10.1 dev tap-wg1\n",
		"ip -4 rule add priority 12101 iif wg1 lookup 2101\n",
		"ip -4 rule add priority 12102 iif ppp0 lookup 2102\n",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Contains(log, "via 172.30.10.5 dev tap-ppp0\n") {
		t.Fatalf("a client network has one main table route:\n%s", log)
	}
	if strings.Contains(log, "vppctl") {
		t.Fatalf("VPP's socket does not exist, nothing may talk to it:\n%s", log)
	}
	for _, file := range []string{filepath.Join(deviceStateDir, "devices.json"), filepath.Join(deviceStateDir, "vpp-devices.cli"), filepath.Join(deviceStateDir, "fixed.nft"), filepath.Join(deviceStateDir, "gate.json")} {
		if _, err := os.Stat(file); err != nil {
			t.Fatal(err)
		}
	}
	generated, err := LoadGateFile(filepath.Join(deviceStateDir, "gate.json"))
	if err != nil || generated.Upstream.Host != "10.61.20.2" {
		t.Fatalf("generated configuration: %+v %v", generated, err)
	}
}

func TestSyncDevicesLeavesForeignObjects(t *testing.T) {
	path := func(t *testing.T) string { return writeGateConfig(t, exitRule("wg1")) }
	const link = "ip -d -j link show dev tap-wg1"
	t.Run("interface_it_did_not_make", func(t *testing.T) {
		useDeviceDirs(t)
		respond, calls := fakeLinuxTools(t)
		respond(link, "out", `[{"linkinfo":{"info_kind":"wireguard"}}]`)
		if err := SyncDevices(path(t), false); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("took over an interface: %v", err)
		}
		if strings.Contains(calls(), "tuntap") {
			t.Fatal(calls())
		}
	})
	t.Run("rerun_keeps_a_device", func(t *testing.T) {
		useDeviceDirs(t)
		respond, calls := fakeLinuxTools(t)
		respond(link, "out", fakeTapLink)
		if err := SyncDevices(path(t), false); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(calls(), "tuntap") {
			t.Fatalf("recreated a device:\n%s", calls())
		}
	})
	t.Run("a_tun_of_the_same_name_is_not_ours", func(t *testing.T) {
		useDeviceDirs(t)
		respond, calls := fakeLinuxTools(t)
		respond(link, "out", strings.Replace(fakeTapLink, `"type":"tap"`, `"type":"tun"`, 1))
		if err := SyncDevices(path(t), false); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(calls(), "tuntap") {
			t.Fatal(calls())
		}
	})
	t.Run("occupied_rule_priority", func(t *testing.T) {
		useDeviceDirs(t)
		respond, calls := fakeLinuxTools(t)
		respond(link, "out", fakeTapLink)
		respond("ip -N -j -4 rule show", "out", `[{"priority":12101,"src":"all","table":"77"}]`)
		if err := SyncDevices(path(t), false); err == nil || !strings.Contains(err.Error(), "occupied") {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(calls(), "rule add") {
			t.Fatal(calls())
		}
	})
	t.Run("occupied_return_table", func(t *testing.T) {
		useDeviceDirs(t)
		respond, _ := fakeLinuxTools(t)
		respond(link, "out", fakeTapLink)
		respond("ip -j -4 route show table 2101", "out", `[{"dst":"10.9.0.0/16","dev":"eth0"}]`)
		if err := SyncDevices(path(t), false); err == nil || !strings.Contains(err.Error(), "occupied") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("host_route_to_the_lan_stands", func(t *testing.T) {
		useDeviceDirs(t)
		respond, calls := fakeLinuxTools(t)
		respond(link, "out", fakeTapLink)
		respond("ip -j -4 route show exact 10.64.30.0/24", "out", `[{"dst":"10.64.30.0/24","dev":"br0"}]`)
		if err := SyncDevices(path(t), false); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(calls(), "ip -4 route replace 10.64.30.0/24 via 172.30.10.1 dev tap-wg1\n") {
			t.Fatalf("replaced the host's route:\n%s", calls())
		}
	})
}

func TestSyncDevicesRetiresALeftDevice(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	respond("ip -d -j link show dev tap-wg2", "out", fakeUsedLink)
	if err := SyncDevices(writeGateConfig(t, exitRule("wg1"), exitRule("wg2")), false); err != nil {
		t.Fatal(err)
	}
	path := writeGateConfig(t, exitRule("wg1"))
	// VPP still holds it: the steering goes, the device stays and stays guarded.
	respond("ip -j -4 route show table 2102", "out", `[{"dst":"10.64.30.0/24","dev":"tap-wg2"}]`)
	if err := SyncDevices(path, false); err != nil {
		t.Fatal(err)
	}
	log := calls()
	for _, want := range []string{"ip -4 rule del priority 12102 iif wg2 lookup 2102\n", "ip -4 route del 10.64.30.0/24 table 2102\n"} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Contains(log, "ip link delete") {
		t.Fatalf("deleted a device VPP holds:\n%s", log)
	}
	fixed, _ := os.ReadFile(filepath.Join(deviceStateDir, "fixed.nft"))
	if !strings.Contains(string(fixed), `iifname "tap-wg2" drop`) {
		t.Fatalf("guard gone:\n%s", fixed)
	}
	state, err := loadDeviceState()
	if err != nil || state.Devices["tap-wg2"] == nil || !state.Devices["tap-wg2"].Retired {
		t.Fatalf("journal lost it: %+v %v", state, err)
	}
	// After VPP has let go, as at boot.
	respond("ip -d -j link show dev tap-wg2", "out", fakeTapLink)
	if err := SyncDevices(path, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "ip link delete dev tap-wg2\n") {
		t.Fatalf("device left behind:\n%s", calls())
	}
	state, err = loadDeviceState()
	if err != nil || state.Devices["tap-wg2"] != nil {
		t.Fatalf("journal keeps it: %+v %v", state, err)
	}
}

// A main table route through a device that just retired is ours, not the host's.
func TestSyncDevicesMovesTheMainRouteOffARetiredDevice(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "out", fakeUsedLink)
	respond("ip -d -j link show dev tap-ppp0", "out", fakeUsedLink)
	if err := SyncDevices(writeGateConfig(t, exitRule("wg1"), exitRule("ppp0")), false); err != nil {
		t.Fatal(err)
	}
	// The first device held the main table route, and it leaves.
	respond("ip -j -4 route show exact 10.64.30.0/24", "out", `[{"dst":"10.64.30.0/24","gateway":"172.30.10.1","dev":"tap-wg1"}]`)
	if err := SyncDevices(writeGateConfig(t, exitRule("ppp0")), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "ip -4 route replace 10.64.30.0/24 via 172.30.10.5 dev tap-ppp0\n") {
		t.Fatalf("main route left on the retired device:\n%s", calls())
	}
}

func TestSyncDevicesAttachesARunningVPP(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	respond("ip -d -j link show dev tap-wg2", "out", fakeTapLink)
	dir := t.TempDir()
	socket := filepath.Join(dir, "cli.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	vppctl, err := os.ReadFile(filepath.Join(os.Getenv("FAKE_DIR"), "ip"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("FAKE_DIR"), "vppctl"), vppctl, 0o755); err != nil {
		t.Fatal(err)
	}
	respond("vppctl -s "+socket+" show interface", "out", "              Name\ntap2100   5   up\n")
	path := filepath.Join(t.TempDir(), "gate.json")
	writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "vpp_socket": socket,
		"routes": []any{exitRule("wg1"), exitRule("wg2")}})
	if err := SyncDevices(path, false); err != nil {
		t.Fatal(err)
	}
	log := calls()
	if strings.Contains(log, "create tap id 2100") {
		t.Fatalf("attached a device VPP has:\n%s", log)
	}
	if !strings.Contains(log, "create tap id 2101 host-if-name tap-wg2 hw-addr 02:67:74:08:35:01 host-mac-addr 02:67:74:08:35:02 host-mtu-size 1500 attach persist\n") || !strings.Contains(log, "set interface state tap2101 up\n") {
		t.Fatalf("did not attach the missing one:\n%s", log)
	}
}

func TestSetupLinksUsesOnlyTheJournal(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "err", `Device "tap-wg1" does not exist.`)
	respond("ip -d -j link show dev tap-ppp0", "err", `Device "tap-ppp0" does not exist.`)
	config := writeGateConfig(t, exitRule("wg1"), exitRule("ppp0"))
	if err := SyncDevices(config, false); err != nil {
		t.Fatal(err)
	}
	cli, _ := os.ReadFile(filepath.Join(deviceStateDir, "vpp-devices.cli"))
	gateConfig, _ := os.ReadFile(filepath.Join(deviceStateDir, "gate.json"))
	journal, _ := os.ReadFile(filepath.Join(deviceStateDir, "devices.json"))
	// A half-edited JSON must not reach a boot, and neither may a running VPP.
	if err := os.WriteFile(config, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("FAKE_DIR"), "log"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SetupLinks(); err != nil {
		t.Fatal(err)
	}
	log := calls()
	for _, want := range []string{
		"nft -f ",
		"ip tuntap add mode tap multi_queue name tap-wg1\n",
		"ip address replace 172.30.10.6/30 dev tap-ppp0\n",
		"ip -4 route replace 10.64.30.0/24 via 172.30.10.5 dev tap-ppp0 table 2102\n",
		"ip -4 route replace 10.64.30.0/24 via 172.30.10.1 dev tap-wg1\n",
		"ip -4 rule add priority 12101 iif wg1 lookup 2101\n",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Contains(log, "vppctl") {
		t.Fatalf("--setup-links talked to VPP:\n%s", log)
	}
	for name, before := range map[string][]byte{"vpp-devices.cli": cli, "gate.json": gateConfig, "devices.json": journal} {
		if after, _ := os.ReadFile(filepath.Join(deviceStateDir, name)); string(after) != string(before) {
			t.Fatalf("--setup-links changed %s", name)
		}
	}
}

func TestSetupLinksWithoutASync(t *testing.T) {
	useDeviceDirs(t)
	_, calls := fakeLinuxTools(t)
	if err := SetupLinks(); err != nil {
		t.Fatal(err)
	}
	if calls() != "" {
		t.Fatalf("ran commands:\n%s", calls())
	}
}

// VPP may start first, in which case its attach has created the device.
func TestSetupLinksAcceptsADeviceVPPCreated(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "out", fakeUsedLink)
	if err := SyncDevices(writeGateConfig(t, exitRule("wg1")), false); err != nil {
		t.Fatal(err)
	}
	if err := SetupLinks(); err != nil {
		t.Fatal(err)
	}
	log := calls()
	if strings.Contains(log, "tuntap") || strings.Contains(log, "ip link delete") {
		t.Fatalf("recreated a device in use:\n%s", log)
	}
	if !strings.Contains(log, "ip address replace 172.30.10.2/30 dev tap-wg1\n") {
		t.Fatalf("device left unconfigured:\n%s", log)
	}
}

func TestSetupLinksRemovesARetiredDeviceAtBoot(t *testing.T) {
	useDeviceDirs(t)
	respond, calls := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
	respond("ip -d -j link show dev tap-wg2", "out", fakeUsedLink)
	if err := SyncDevices(writeGateConfig(t, exitRule("wg1"), exitRule("wg2")), false); err != nil {
		t.Fatal(err)
	}
	if err := SyncDevices(writeGateConfig(t, exitRule("wg1")), false); err != nil {
		t.Fatal(err)
	}
	if state, _ := loadDeviceState(); state.Devices["tap-wg2"] == nil {
		t.Fatal("VPP holds it, so it must stay recorded")
	}
	// After a boot nothing holds it.
	respond("ip -d -j link show dev tap-wg2", "out", fakeTapLink)
	if err := SetupLinks(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls(), "ip link delete dev tap-wg2\n") {
		t.Fatalf("device left behind:\n%s", calls())
	}
	if state, _ := loadDeviceState(); state.Devices["tap-wg2"] != nil {
		t.Fatal("journal keeps it")
	}
	fixed, _ := os.ReadFile(filepath.Join(deviceStateDir, "fixed.nft"))
	if strings.Contains(string(fixed), "tap-wg2") {
		t.Fatalf("guard for a device that is gone:\n%s", fixed)
	}
}

func TestHostSettingsWaitForTheFirstExit(t *testing.T) {
	useDeviceDirs(t)
	respond, _ := fakeLinuxTools(t)
	respond("ip -d -j link show dev tap-wg0", "out", fakeTapLink)
	for name, value := range map[string]string{"net/ipv4/ip_forward": "0", "net/ipv4/conf/all/rp_filter": "2"} {
		path := filepath.Join(linuxSysctlRoot, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) string {
		data, _ := os.ReadFile(filepath.Join(linuxSysctlRoot, name))
		return strings.TrimSpace(string(data))
	}
	empty := writeGateConfig(t, map[string]any{"linux_exit": map[string]any{"interface": "wg0"}})
	if err := SyncDevices(empty, false); err != nil {
		t.Fatal(err)
	}
	if read("net/ipv4/ip_forward") != "0" || read("net/ipv4/conf/all/rp_filter") != "2" {
		t.Fatal("host settings changed with no exit in use")
	}
	if err := SyncDevices(writeGateConfig(t, exitRule("wg0")), false); err != nil {
		t.Fatal(err)
	}
	if read("net/ipv4/ip_forward") != "1" || read("net/ipv4/conf/all/rp_filter") != "0" {
		t.Fatal("host settings not applied for an exit")
	}
}

func TestSyncDevicesDryRunChangesNothing(t *testing.T) {
	useDeviceDirs(t)
	_, calls := fakeLinuxTools(t)
	if err := SyncDevices(writeGateConfig(t, exitRule("wg1")), true); err != nil {
		t.Fatal(err)
	}
	if calls() != "" {
		t.Fatalf("a dry run ran commands:\n%s", calls())
	}
	if entries, _ := os.ReadDir(deviceStateDir); len(entries) != 0 {
		t.Fatalf("a dry run wrote files: %v", entries)
	}
}

// Real persistent devices in an isolated namespace.
func TestSyncDevicesKernel(t *testing.T) {
	if os.Getenv("GATE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	useDeviceDirs(t)
	ctx := context.Background()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := runCmdContext(ctx, name, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	two := writeGateConfig(t, exitRule("gk-wg"), exitRule("gk-ppp"), proxyRule())
	for range 2 {
		if err := SyncDevices(two, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, device := range []struct{ host, kind, address string }{
		{"tap-gk-wg", "tap", "172.30.10.2/30"}, {"tap-gk-ppp", "tap", "172.30.10.6/30"}, {deviceProxyHost, "tap", "172.30.20.2/24"},
	} {
		link, err := readDeviceLink(ctx, device.host)
		if err != nil || link == nil {
			t.Fatalf("%s: %v", device.host, err)
		}
		if data := link.Info.Data; link.Info.Kind != "tun" || data.Type != device.kind || !data.Persist || !data.MultiQueue {
			t.Fatalf("%s: %+v", device.host, link.Info)
		}
		if out := run("ip", "-4", "addr", "show", "dev", device.host); strings.Count(out, "inet ") != 1 || !strings.Contains(out, device.address) {
			t.Fatalf("%s address:\n%s", device.host, out)
		}
	}
	if out := run("ip", "link", "show", "dev", "tap-gk-ppp"); !strings.Contains(out, "02:67:74:08:35:02") {
		t.Fatalf("TAP MAC:\n%s", out)
	}
	rules := run("ip", "-4", "rule", "show")
	for _, want := range []string{"iif gk-wg", "iif gk-ppp", "iif gate-tproxy"} {
		if strings.Count(rules, want) != 1 {
			t.Fatalf("%q in rules, for exits that do not exist yet:\n%s", want, rules)
		}
	}
	if out := run("ip", "-4", "route", "show", "table", "2102"); !strings.Contains(out, "10.64.30.0/24 via 172.30.10.5 dev tap-gk-ppp") {
		t.Fatalf("return table:\n%s", out)
	}
	if out := run("ip", "-4", "route", "show", "exact", "10.64.30.0/24"); !strings.Contains(out, "dev tap-gk-wg") || strings.Contains(out, "tap-gk-ppp") {
		t.Fatalf("main table:\n%s", out)
	}
	if out := run("nft", "list", "table", "inet", "gate_fixed"); strings.Count(out, `iifname "tap-gk-wg"`) != 1 {
		t.Fatalf("guard:\n%s", out)
	}
	// Boot: every device is gone, and the JSON plays no part.
	for _, host := range []string{"tap-gk-wg", "tap-gk-ppp", deviceProxyHost} {
		run("ip", "link", "delete", "dev", host)
	}
	run("ip", "route", "flush", "table", "2102")
	if err := SetupLinks(); err != nil {
		t.Fatal(err)
	}
	if out := run("ip", "-4", "addr", "show", "dev", "tap-gk-wg"); !strings.Contains(out, "172.30.10.2/30") {
		t.Fatalf("not restored:\n%s", out)
	}
	if out := run("ip", "-4", "route", "show", "table", "2102"); !strings.Contains(out, "dev tap-gk-ppp") {
		t.Fatalf("return table not restored:\n%s", out)
	}
	// VPP came first: its attach made the device, unconfigured, before --setup-links ran.
	run("ip", "-4", "addr", "flush", "dev", "tap-gk-wg")
	if err := SetupLinks(); err != nil {
		t.Fatal(err)
	}
	if out := run("ip", "-4", "addr", "show", "dev", "tap-gk-wg"); !strings.Contains(out, "172.30.10.2/30") {
		t.Fatalf("existing device not configured:\n%s", out)
	}
	// Both families on a device, a return table and a TPROXY path of its own.
	v6 := exitRule("gk-six")
	v6["ipv6"] = true
	dual := proxyRule()
	dual["fakeip_range"] = []any{"198.18.0.0/15", "2001:2::/48"}
	for range 2 {
		if err := SyncDevices(writeDualStackConfig(t, v6, dual), false); err != nil {
			t.Fatal(err)
		}
		v6 = exitRule("gk-six")
		v6["ipv6"] = true
		dual = proxyRule()
		dual["fakeip_range"] = []any{"198.18.0.0/15", "2001:2::/48"}
	}
	if out := run("ip", "-6", "addr", "show", "dev", "tap-gk-six"); strings.Count(out, "inet6 fd67") != 1 || strings.Contains(out, "tentative") {
		t.Fatalf("IPv6 address:\n%s", out)
	}
	journal, err := loadDeviceState()
	if err != nil || journal.Devices["tap-gk-six"] == nil {
		t.Fatalf("journal: %+v %v", journal, err)
	}
	if out := run("ip", "-6", "route", "show", "table", fmt.Sprint(journal.Devices["tap-gk-six"].ReturnTable)); !strings.Contains(out, "fd99:77::/64 via fd67:7465:6500") || !strings.Contains(out, "dev tap-gk-six") {
		t.Fatalf("IPv6 return table:\n%s", out)
	}
	if rules := run("ip", "-6", "rule", "show"); strings.Count(rules, "iif gk-six") != 1 || strings.Count(rules, "iif gate-tproxy") != 1 {
		t.Fatalf("IPv6 rules:\n%s", rules)
	}
	if out := run("ip", "-6", "route", "show", "table", "1002"); !strings.Contains(out, "local default dev lo") {
		t.Fatalf("IPv6 TPROXY table:\n%s", out)
	}
	run("ip", "link", "delete", "dev", "tap-gk-six")
	if err := SyncDevices(writeGateConfig(t, exitRule("gk-wg"), exitRule("gk-ppp"), proxyRule()), false); err != nil {
		t.Fatal(err)
	}
	// The proxy device stays with IPv6 off, so its IPv6 side must go.
	if out := run("ip", "-6", "addr", "show", "dev", deviceProxyHost); strings.Contains(out, "fd67:") {
		t.Fatalf("IPv6 address left on a device that turned it off:\n%s", out)
	}
	if rules, _ := runCmdContext(ctx, "ip", "-6", "rule", "show"); strings.Contains(rules, "gk-six") || strings.Contains(rules, "gate-tproxy") {
		t.Fatalf("IPv6 rules left behind:\n%s", rules)
	}
	if out, _ := runCmdContext(ctx, "ip", "-6", "route", "show", "table", "1002"); strings.Contains(out, "local") {
		t.Fatalf("IPv6 TPROXY table left behind:\n%s", out)
	}
	// Two gateways on one interface: a real TAP with real macvlans.
	if _, err := runCmdContext(ctx, "ip", "link", "add", "gk-up", "type", "dummy"); err != nil {
		t.Fatal(err)
	}
	if err := SyncDevices(writeGateConfig(t, gatewayRule("gk-a", "gk-up", "192.0.2.1"), gatewayRule("gk-b", "gk-up", "192.0.2.2")), false); err != nil {
		t.Fatal(err)
	}
	if link, _ := readDeviceLink(ctx, "gw-gk-up"); link == nil || link.Info.Data.Type != "tap" || !link.Info.Data.Persist {
		t.Fatalf("shared TAP: %+v", link)
	}
	for _, name := range []string{"gm-gk-a", "gm-gk-b"} {
		link, err := readDeviceLink(ctx, name)
		if err != nil || link == nil || link.Info.Kind != "macvlan" || link.Link != "gw-gk-up" {
			t.Fatalf("%s: %+v %v", name, link, err)
		}
		if out := run("ip", "-4", "addr", "show", "dev", name); strings.Count(out, "inet ") != 1 {
			t.Fatalf("%s:\n%s", name, out)
		}
	}
	if out := run("ip", "-4", "addr", "show", "dev", "gw-gk-up"); strings.Contains(out, "inet ") {
		t.Fatalf("the shared TAP took an address:\n%s", out)
	}
	if err := SetupLinks(); err != nil {
		t.Fatalf("setup-links over existing macvlans: %v", err)
	}
	// Macvlans gone, TAP in place: what a sync must repair.
	run("ip", "link", "delete", "dev", "gm-gk-a")
	if err := SetupLinks(); err != nil {
		t.Fatal(err)
	}
	if link, _ := readDeviceLink(ctx, "gm-gk-a"); link == nil {
		t.Fatal("macvlan not restored")
	}
	// A rule leaves. Nothing holds the device, so everything goes.
	if err := SyncDevices(writeGateConfig(t, exitRule("gk-wg")), false); err != nil {
		t.Fatal(err)
	}
	if link, _ := readDeviceLink(ctx, "tap-gk-ppp"); link != nil {
		t.Fatal("retired device left behind")
	}
	if link, _ := readDeviceLink(ctx, deviceProxyHost); link != nil {
		t.Fatal("retired TPROXY device left behind")
	}
	rules = run("ip", "-4", "rule", "show")
	if strings.Contains(rules, "gk-ppp") || strings.Contains(rules, "gate-tproxy") {
		t.Fatalf("rules left behind:\n%s", rules)
	}
	if out, _ := runCmdContext(ctx, "ip", "-4", "route", "show", "table", "2102"); out != "" {
		t.Fatalf("return table left behind:\n%s", out)
	}
	state, err := loadDeviceState()
	if err != nil || len(state.Devices) != 1 {
		t.Fatalf("journal: %+v %v", state, err)
	}
	// An interface it did not make stays, and stops the sync.
	run("ip", "link", "add", "tap-gk-x", "type", "dummy")
	if err := SyncDevices(writeGateConfig(t, exitRule("gk-x")), false); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("took over a foreign interface: %v", err)
	}
	if out := run("ip", "-d", "link", "show", "dev", "tap-gk-x"); !strings.Contains(out, "dummy") {
		t.Fatal(out)
	}
}

func TestDeviceNameFitsLinux(t *testing.T) {
	for _, tc := range []struct{ prefix, name, want string }{
		{deviceExitPrefix, "wg0", "tap-wg0"},
		{deviceExitPrefix, "elevenchars", "tap-elevenchars"},
		{deviceSharedPrefix, "twelve-chars", "gw-twelve-chars"},
		{deviceGatewayPrefix, "twelve-chars", "gm-twelve-chars"},
	} {
		if got := deviceName(tc.prefix, tc.name); got != tc.want {
			t.Errorf("%s%s: got %s", tc.prefix, tc.name, got)
		}
	}
	for _, prefix := range []string{deviceExitPrefix, deviceSharedPrefix, deviceGatewayPrefix} {
		long := deviceName(prefix, "enp12s3f0np0-and-more")
		if len(long) != deviceNameMax || !strings.HasPrefix(long, prefix+"enp12s") {
			t.Errorf("%s: got %s", prefix, long)
		}
		if long != deviceName(prefix, "enp12s3f0np0-and-more") {
			t.Errorf("%s: the name must not change between syncs", prefix)
		}
	}
	// These differ only past what is kept.
	if deviceName(deviceExitPrefix, "enp12s3f0np0") == deviceName(deviceExitPrefix, "enp12s3f0np1") {
		t.Error("long names that differ at the end share a device")
	}
}

func TestLongExitNamesGetDevices(t *testing.T) {
	useDeviceDirs(t)
	out := captureLog(t)
	plan, err := PlanDevices(writeGateConfig(t, exitRule("enp12s3f0np0"), gatewayRule("enp12s3f1np10-1", "enp12s3f1np10", "192.0.2.1"), gatewayRule("enp12s3f1np10-2", "enp12s3f1np10", "192.0.2.2")), emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatalf("Gate refuses the plan: %v\n%s", err, plan.Effective)
	}
	want := []string{
		deviceName(deviceExitPrefix, "enp12s3f0np0"), deviceName(deviceSharedPrefix, "enp12s3f1np10"),
		deviceName(deviceGatewayPrefix, "enp12s3f1np10-1"), deviceName(deviceGatewayPrefix, "enp12s3f1np10-2"),
	}
	for i, d := range plan.Devices {
		if d.Host != want[i] || len(d.Host) > deviceNameMax {
			t.Fatalf("devices %+v, want %v", plan.Devices, want)
		}
	}
	if !strings.Contains(plan.CLI, "host-if-name "+want[0]+" ") {
		t.Fatalf("VPP is not told the device:\n%s", plan.CLI)
	}
	routes := planRoutes(t, plan)
	if routes[0]["linux_exit"].(map[string]any)["interface"] != "enp12s3f0np0" {
		t.Fatalf("the exit lost its real name: %v", routes[0])
	}
	if !strings.Contains(out.String(), "enp12s3f0np0 uses device "+want[0]) {
		t.Fatalf("the name of the device is not logged:\n%s", out)
	}
	if strings.Count(out.String(), "enp12s3f1np10 uses device") != 1 {
		t.Fatalf("the shared TAP must be logged once:\n%s", out)
	}
}

// The tag is short, so two long names can meet. That must stop the sync, not merge them.
func TestLongNamesWithTheSameDeviceAreRefused(t *testing.T) {
	useDeviceDirs(t)
	seen := map[string]string{}
	for i := 0; ; i++ {
		name := fmt.Sprintf("enp16s%06d", i)
		host := deviceName(deviceExitPrefix, name)
		if first, met := seen[host]; met {
			_, err := PlanDevices(writeGateConfig(t, exitRule(first), exitRule(name)), emptyDeviceState())
			if err == nil || !strings.Contains(err.Error(), "two rules ask for device "+host) {
				t.Fatalf("%s and %s: err = %v", first, name, err)
			}
			return
		}
		seen[host] = name
	}
}
