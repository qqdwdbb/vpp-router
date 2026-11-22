package gate

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDNSHijackNftScriptRedirectsPort53(t *testing.T) {
	script := strings.Join(dnsHijackNftScript([]string{"br-mgmt", "lan"}, 1053, nil), "\n")
	for _, want := range []string{
		"table inet egress_gate",
		"chain hijack",
		"priority dstnat",
		`iifname { "br-mgmt", "lan" }`,
		"th dport 53",
		"redirect to :1053",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in %s", want, script)
		}
	}
	single := strings.Join(dnsHijackNftScript([]string{"br-mgmt"}, 1053, nil), "\n")
	if !strings.Contains(single, `iifname "br-mgmt"`) || strings.Contains(single, `iifname {`) {
		t.Fatalf("single iface %s", single)
	}
}

func TestDNSHijackUsesBoundIPv6TargetsBeforeRedirect(t *testing.T) {
	script := strings.Join(dnsHijackNftScript([]string{"vpp-host", "br0"}, 1053, map[string][]netip.Addr{
		"vpp-host": {netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::2")},
		"br0":      {netip.MustParseAddr("fd00:1::2")},
	}), "\n")
	last := -1
	for _, want := range []string{
		`iifname "vpp-host" ip6 daddr 2001:db8::2 meta l4proto { tcp, udp } th dport 53 dnat ip6 to [2001:db8::2]:1053`,
		`iifname "vpp-host" meta nfproto ipv6 meta l4proto { tcp, udp } th dport 53 dnat ip6 to [fd00::2]:1053`,
		`iifname "br0" meta nfproto ipv6 meta l4proto { tcp, udp } th dport 53 dnat ip6 to [fd00:1::2]:1053`,
		`iifname { "vpp-host", "br0" } meta l4proto { tcp, udp } th dport 53 redirect to :1053`,
	} {
		pos := strings.Index(script, want)
		if pos <= last {
			t.Fatalf("missing or out of order: %q in %s", want, script)
		}
		last = pos
	}
}

func TestDNSHijackClearScriptDropsChain(t *testing.T) {
	script := strings.Join(dnsHijackClearScript(), "\n")
	if !strings.Contains(script, "flush chain inet egress_gate hijack") ||
		!strings.Contains(script, "delete chain inet egress_gate hijack") {
		t.Fatalf("clear %s", script)
	}
}

func TestTproxyPortNftScriptOwnsDedicatedTable(t *testing.T) {
	a, _ := netip.ParsePrefix("198.18.0.0/15")
	b, _ := netip.ParsePrefix("2001:2::/48")
	script := strings.Join(tproxyPortNftScript([]TProxyListen{
		{Interface: "vpp-tproxy", Prefix: a, Port: 2082},
		{Interface: "vpp-tproxy", Prefix: b, Port: 2082},
	}), "\n")
	for _, want := range []string{
		"table inet egress_gate",
		"flush chain inet egress_gate gate_tproxy",
		`iifname "vpp-tproxy" ip daddr 198.18.0.0/15`,
		"tproxy ip to :2082",
		`iifname "vpp-tproxy" ip6 daddr 2001:2::/48`,
		"tproxy ip6 to :2082",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in %s", want, script)
		}
	}
}

func TestTproxyPortNftScriptNamesTheProxyAddress(t *testing.T) {
	a, _ := netip.ParsePrefix("198.18.0.0/15")
	b, _ := netip.ParsePrefix("2001:2::/48")
	script := strings.Join(tproxyPortNftScript([]TProxyListen{
		{Interface: "gate-tproxy", Prefix: a, Port: 7893, Address: netip.MustParseAddr("127.0.0.1")},
		{Interface: "gate-tproxy", Prefix: b, Port: 7893, Address: netip.MustParseAddr("::1")},
	}), "\n")
	for _, want := range []string{"tproxy ip to 127.0.0.1:7893", "tproxy ip6 to [::1]:7893"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %q in %s", want, script)
		}
	}
}

func TestTproxyAddressFollowsEachPool(t *testing.T) {
	cfg := &Config{Mappings: []Mapping{{Enabled: true, FakeIP: "198.18.0.0/15", FakeIP6: "2001:2::/48", TProxyPort: 7893,
		TProxyAddress: []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1")}}}}
	rules := tproxyPortRules(cfg)
	if len(rules) != 2 || rules[0].Address.String() != "127.0.0.1" || rules[1].Address.String() != "::1" {
		t.Fatalf("%+v", rules)
	}
}

func TestTproxyPortNftScriptFlushesBeforeReplace(t *testing.T) {
	a, _ := netip.ParsePrefix("198.18.0.0/15")
	first := strings.Join(tproxyPortNftScript([]TProxyListen{{Interface: "vpp-tproxy", Prefix: a, Port: 2082}}), "\n")
	second := strings.Join(tproxyPortNftScript([]TProxyListen{{Interface: "vpp-tproxy", Prefix: a, Port: 2083}}), "\n")
	for i, script := range []string{first, second} {
		if !strings.Contains(script, "flush chain inet egress_gate gate_tproxy") {
			t.Fatalf("sync %d missing flush: %s", i, script)
		}
	}
	if strings.Count(first, "tproxy ip to :2082") != 1 || strings.Contains(first, ":2083") {
		t.Fatalf("first %s", first)
	}
	if strings.Count(second, "tproxy ip to :2083") != 1 || strings.Contains(second, ":2082") {
		t.Fatalf("port change kept old rule: %s", second)
	}
}

func TestTproxyPortNftScriptClearsWhenEmpty(t *testing.T) {
	script := strings.Join(tproxyPortNftScript(nil), "\n")
	if !strings.Contains(script, "flush chain inet egress_gate gate_tproxy") ||
		!strings.Contains(script, "delete chain inet egress_gate gate_tproxy") {
		t.Fatalf("clear %s", script)
	}
	if strings.Contains(script, "tproxy ip to") {
		t.Fatalf("empty rules still install: %s", script)
	}
}

func TestParseFIBIgnoresStackedNextHop(t *testing.T) {
	text := `ipv4-VRF:0, fib_index:0
198.51.100.77/32
  unicast-ip4-chain
    [0] [@6]: ipv4 [features] via 10.62.30.1 wg1: mtu:1280
        stacked-on:
          [0] [@5]: ipv4 via 10.61.20.1 host-vpp-wan: mtu:1500
198.51.100.78/32
    [0] [@0]: dpo-drop ip4
`
	got, err := parseFIB(text, 0)
	if err != nil {
		t.Fatal(err)
	}
	paths, ok := got[RouteKey{0, "198.51.100.77/32"}]
	if !ok || !pathSetEqual(paths, pathSetOf("10.62.30.1", "wg1")) {
		t.Fatalf("got %v", got)
	}
	drop, ok := got[RouteKey{0, "198.51.100.78/32"}]
	if !ok || len(drop) != 0 {
		t.Fatalf("drop route %v present=%v", drop, ok)
	}
}

func TestParseFIBIPv6Multipath(t *testing.T) {
	text := `ipv6-VRF:7, fib_index:1
2001:db8::77/128
    [0] [@6]: ipv6 [features] via fd42:1111:2222:90::2 wg0: mtu:1420
    [1] [@6]: ipv6 [features] via fd42:1111:2222:90::5 wg0: mtu:1420
`
	got, err := parseFIB(text, 7)
	if err != nil {
		t.Fatal(err)
	}
	paths := got[RouteKey{7, "2001:db8::77/128"}]
	if !pathSetEqual(paths, PathSet{Path{"fd42:1111:2222:90::2", "wg0"}: {}, Path{"fd42:1111:2222:90::5", "wg0"}: {}}) {
		t.Fatalf("got %v", paths)
	}
}

func TestUDPSizeLimit(t *testing.T) {
	q := queryPacket()
	if UDPSizeLimit(q) != 512 {
		t.Fatal("default not 512")
	}
	opt := []byte{0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0}
	binaryPut := func() []byte {
		out := append([]byte{}, q...)
		binarySet := out
		binarySet[11] = 1
		return append(binarySet, opt...)
	}
	edns := binaryPut()
	if got := UDPSizeLimit(edns); got != 1232 {
		t.Fatalf("edns size %d", got)
	}
}
