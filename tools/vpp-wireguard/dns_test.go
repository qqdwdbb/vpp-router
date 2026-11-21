package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The TAP is in a bridge, as installed routers have it, so its addresses are on the BVI.
const testVPPAddrs = "loop0 (up):\r\n  L2 bridge bd-id 1 idx 1 shg 0 bvi\r\n  L3 10.61.20.1/24\r\n  L3 fd00::1/64\r\n" +
	"tap0 (up):\r\n  L2 bridge bd-id 1 idx 1 shg 0\r\nport0.100 (up):\r\n  L3 10.61.10.2/24\r\n"

func testWGDNS() *WireGuardDNS {
	return &WireGuardDNS{IPv4: "10.61.20.2:1053", IPv6: "[fd00::2]:1053", VPPInterface: "loop0", HostInterface: "vpp-host", VPPIPv4: "10.61.20.1", VPPIPv6: "fd00::1"}
}

func TestWGLinkAddress(t *testing.T) {
	routed := "tap0 (up):\n  L3 10.61.20.1/24 ip4 table-id 0 fib-idx 0\nloop9 (up):\n  L3 10.61.20.9/24\n"
	for _, test := range []struct {
		output, iface, own string
	}{
		{testVPPAddrs, "loop0", "10.61.20.1"},
		{routed, "tap0", "10.61.20.1"},
	} {
		iface, own, err := wgLinkAddress(test.output, netip.MustParseAddr("10.61.20.2"), "tap0")
		if err != nil || iface != test.iface || own.String() != test.own {
			t.Fatalf("got %s %s %v, want %s %s", iface, own, err, test.iface, test.own)
		}
	}
	if _, _, err := wgLinkAddress(testVPPAddrs, netip.MustParseAddr("10.0.0.2"), "tap0"); err == nil {
		t.Fatal("found a link for an address VPP has no subnet for")
	}
	if _, _, err := wgLinkAddress("loop1 (up):\n  L3 10.61.20.1/24\nloop2 (up):\n  L3 10.61.20.3/24\n", netip.MustParseAddr("10.61.20.2"), "tap0"); err == nil {
		t.Fatal("picked one of two candidate interfaces")
	}
}

func TestWGDNSLifecycle(t *testing.T) {
	f := newFixture(t)
	addWGConfig(t, f)
	body, _ := json.Marshal(map[string]any{"interface": "wg100", "source": "10.61.10.2", "dns": map[string]any{}})
	w := httptest.NewRecorder()
	f.admin.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/wireguard/config/edit", strings.NewReader(string(body))))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), wgPrivateKey) {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	if len(f.sys.nftBatches) != 0 {
		t.Fatal("saving a stopped configuration changed nftables")
	}
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	c := wgFindConfig(f.store(t), "wg100")
	if *c.DNS != *testWGDNS() {
		t.Fatalf("DNS was not resolved from Gate/TAP: %+v", c.DNS)
	}
	batch := f.sys.nftBatches[0]
	for _, own := range c.subnets() {
		if !strings.Contains(batch, "daddr "+own.Addr().String()+" ") {
			t.Fatalf("no rule for %s: %s", own, batch)
		}
	}
	for _, want := range []string{"priority -102", `iifname "vpp-host"`, "dnat ip to 10.61.20.2:1053", "dnat ip6 to [fd00::2]:1053", "udp dport 53"} {
		if !strings.Contains(batch, want) {
			t.Fatalf("missing %q: %s", want, batch)
		}
	}
	commands := strings.Join(f.sys.commands, "\n")
	if strings.Contains(commands, "tcp") || strings.Contains(batch, "tcp") {
		t.Fatal("TCP is handled, but only UDP queries are forwarded")
	}
	for _, want := range []string{"set punt udp 53", "set punt ipv6 udp 53",
		"ip punt redirect rx wg100 via 10.61.20.2 loop0", "ip6 punt redirect rx wg100 via fd00::2 loop0"} {
		if !strings.Contains(commands, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Index(commands, "set punt udp 53") > strings.Index(commands, "ip punt redirect") {
		t.Fatal("redirect set before port 53 was punted")
	}
	routes := strings.Join(f.sys.ipCommands, "\n")
	for _, own := range c.subnets() {
		via := "10.61.20.1"
		if !own.Addr().Is4() {
			via = "fd00::1"
		}
		if want := "route replace " + own.Masked().String() + " via " + via + " dev vpp-host"; !strings.Contains(routes, want) {
			t.Fatalf("missing %q: %s", want, routes)
		}
	}
	if _, err := f.admin.UpdateWireGuardDNS("wg100", nil, "admin"); err == nil {
		t.Fatal("changed DNS on an enabled configuration")
	}
	f.sys.ifaces += "wg100 12 up 1400/0/0/0\n"
	f.sys.commands = nil
	if _, err := f.admin.StopWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	last := f.sys.nftBatches[len(f.sys.nftBatches)-1]
	if strings.Contains(last, "add rule") || !strings.Contains(last, "flush chain inet vpp_wireguard_dns wg100") {
		t.Fatalf("stop did not clear its own rules: %s", last)
	}
	if !strings.Contains(strings.Join(f.sys.commands, "\n"), "ip6 punt redirect del rx wg100 via fd00::2 loop0") {
		t.Fatal("stop left IPv6 redirect")
	}
	if strings.Contains(strings.Join(f.sys.commands, "\n"), "set punt") && strings.Contains(strings.Join(f.sys.commands, "\n"), " del 53") {
		t.Fatal("stop removed the shared port 53 punt")
	}
	if !strings.Contains(strings.Join(f.sys.ipCommands, "\n"), "route del ") {
		t.Fatal("stop left the return routes")
	}
	if _, err := f.admin.UpdateWireGuardDNS("wg100", nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if wgFindConfig(f.store(t), "wg100").DNS != nil {
		t.Fatal("DNS remained enabled")
	}
}

func TestWGDNSDiscoversGateAndPairedTAP(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(f.opts.GateConfig, []byte(`{"listen":[["10.61.20.2",1053],["fd00::2",1053]],"hijack_dns":true,"hijack_interfaces":["other-host","vpp-host"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dns, err := f.admin.resolveWGDNS()
	if err != nil {
		t.Fatal(err)
	}
	if *dns != *testWGDNS() {
		t.Fatalf("discovered %+v", dns)
	}
}

func TestWGDNSStartFailuresRollback(t *testing.T) {
	for _, failure := range []string{"nft", "ip6 punt redirect", "set punt", "route replace"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t)
			addWGConfig(t, f)
			if _, err := f.admin.UpdateWireGuardDNS("wg100", testWGDNS(), "admin"); err != nil {
				t.Fatal(err)
			}
			if failure == "nft" {
				f.sys.nftErr = errors.New("nft unavailable")
			} else if failure == "route replace" {
				f.sys.ipFail = failure
			} else {
				f.sys.cliFail = failure
			}
			if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err == nil {
				t.Fatal("DNS failure reported success")
			}
			if wgFindConfig(f.store(t), "wg100").Enabled {
				t.Fatal("failed startup persisted enabled state")
			}
			if !strings.Contains(strings.Join(f.sys.commands, "\n"), "wireguard delete wg100") {
				t.Fatal("failed startup left tunnel behind")
			}
		})
	}
}

func TestWGDNSRestoreExistingTunnelAndIsolation(t *testing.T) {
	f := newFixture(t)
	store := f.store(t)
	store.Configs[0].DNS = testWGDNS()
	if err := f.admin.saveWGStore(store); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if !f.admin.reconcileWireGuard() {
			t.Fatal("restore failed")
		}
	}
	if len(f.sys.nftBatches) != 2 || f.sys.nftBatches[0] != f.sys.nftBatches[1] {
		t.Fatal("existing tunnel DNS was not restored idempotently")
	}
	for _, batch := range f.sys.nftBatches {
		if strings.Contains(batch, "flush table") || strings.Contains(batch, "wg100") {
			t.Fatal("restoring one tunnel affected another")
		}
	}
	if strings.Contains(strings.Join(f.sys.commands, "\n"), "wireguard create") {
		t.Fatal("recreated existing tunnel")
	}
}

// Opt in on a Linux test host with CAP_SYS_ADMIN. All changes are confined to
// a new network namespace; the host's firewall and VPP are never touched.
func TestWGDNSNftNamespace(t *testing.T) {
	if os.Getenv("VPP_WG_DNS_TEST_NFT") != "1" {
		t.Skip("set VPP_WG_DNS_TEST_NFT=1 to validate nftables in an isolated network namespace")
	}
	c := &wgStored{Instance: 100, Addresses: []string{"10.9.0.1/24", "fd09::1/64"}, DNS: testWGDNS()}
	other := &wgStored{Instance: 101, Addresses: []string{"10.10.0.1/24", "fd10::1/64"}, DNS: testWGDNS()}
	batch := wgDNSBatch(c, c.DNS, true) + wgDNSBatch(c, c.DNS, true) + wgDNSBatch(other, other.DNS, true) + wgDNSBatch(c, c.DNS, false)
	cmd := exec.Command("unshare", "--net", "sh", "-c", "nft -f - && nft list table inet vpp_wireguard_dns")
	cmd.Stdin = strings.NewReader(batch)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated nftables: %v\n%s", err, output)
	}
	text := string(output)
	if strings.Contains(text, "10.9.0.1") || strings.Contains(text, "fd09::1") || strings.Count(text, "dnat") != 2 || !strings.Contains(text, "10.10.0.1") || !strings.Contains(text, "fd10::1") {
		t.Fatalf("unexpected rules after repeated apply and single-tunnel cleanup:\n%s", text)
	}
}

func TestWGDNSOnAdd(t *testing.T) {
	f := newFixture(t)
	body, _ := json.Marshal(map[string]any{"name": "home", "source": "10.61.10.2", "text": wgConf, "dns": map[string]any{"vpp_interface": "evil"}})
	w := httptest.NewRecorder()
	f.admin.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/wireguard/config", strings.NewReader(string(body))))
	if w.Code != http.StatusOK {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	if c := wgFindConfig(f.store(t), "wg100"); c == nil || c.DNS == nil || *c.DNS != (WireGuardDNS{}) {
		t.Fatalf("DNS not enabled, or panel fields kept: %+v", c)
	}

	plain := newFixture(t)
	addWGConfig(t, plain)
	if wgFindConfig(plain.store(t), "wg100").DNS != nil {
		t.Fatal("DNS enabled without being asked")
	}

	broken := newFixture(t)
	if err := os.WriteFile(broken.opts.GateConfig, []byte(`{"listen":[["10.61.20.2",1053]],"hijack_dns":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := broken.admin.AddWireGuardConfig("home", "10.61.10.2", wgConf, "", "", "", true, "admin"); err == nil {
		t.Fatal("added DNS forwarding without a usable Gate")
	}
	if wgFindConfig(broken.store(t), "wg100") != nil {
		t.Fatal("a refused configuration was stored")
	}
}
