package gate

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealTProxySharesTransitWithFakeIP(t *testing.T) {
	real := func(name string) map[string]any {
		return map[string]any{"name": name, "tproxy_exit": "real", "tproxy_port": 7893, "domains": []any{name + ".example"}}
	}
	fake := proxyRule()
	fake["name"], fake["tproxy_exit"] = "fake", "fake"
	path := writeGateConfig(t, real("one"), real("two"), fake)
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Devices) != 1 {
		t.Fatalf("devices: %+v", plan.Devices)
	}
	routes := planRoutes(t, plan)
	for _, r := range routes {
		if r["interface"] != plan.Devices[0].vppInterface() || r["tproxy_interface"] != deviceProxyHost {
			t.Fatalf("route: %+v", r)
		}
	}
}

func TestRealTProxyNftAfterFakePools(t *testing.T) {
	cfg := &Config{Mappings: []Mapping{
		{Enabled: true, Via: "172.30.20.2", TProxyInterface: deviceProxyHost, TProxyPort: 7893, RealAddresses: true},
		{Enabled: true, Via: "172.30.20.2", FakeIP: "198.18.0.0/15", TProxyInterface: deviceProxyHost, TProxyPort: 7894},
	}}
	rules := tproxyPortRules(cfg)
	if len(rules) != 2 || rules[0].Prefix != netip.MustParsePrefix("198.18.0.0/15") || rules[1].Prefix.Bits() != 0 {
		t.Fatalf("rules: %+v", rules)
	}
	script := strings.Join(tproxyPortNftScript(rules), "\n")
	if !strings.Contains(script, `iifname "gate-tproxy" ip daddr 0.0.0.0/0 meta l4proto { tcp, udp } tproxy ip to :7893`) {
		t.Fatal(script)
	}
}

// A Fake-IP rule with address ranges sends the ranges' real addresses to the same listener, so
// it intercepts all addresses on the transit as well as its pool.
func TestFakeIPRuleWithRangesTakesRealAddresses(t *testing.T) {
	ranges := filepath.Join(t.TempDir(), "static.ranges")
	if err := os.WriteFile(ranges, []byte("91.108.4.0/22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mixed := proxyRule()
	mixed["name"], mixed["tproxy_exit"], mixed["tproxy_port"] = "mixed", "tproxy", 2082
	mixed["ip_range_files"] = []any{ranges}
	plan, err := PlanDevices(writeGateConfig(t, mixed), emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	effective := filepath.Join(t.TempDir(), "gate.json")
	if err := os.WriteFile(effective, []byte(plan.Effective), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(effective)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DomainRoutesFromFile(effective, cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Mappings) != 1 || !cfg.Mappings[0].HasFakeIP() || !cfg.Mappings[0].RealAddresses {
		t.Fatalf("mappings: %+v", cfg.Mappings)
	}
	script := strings.Join(tproxyPortNftScript(tproxyPortRules(cfg)), "\n")
	for _, want := range []string{"ip daddr 198.18.0.0/15", "ip daddr 0.0.0.0/0"} {
		if !strings.Contains(script, want+" meta l4proto { tcp, udp } tproxy ip to :2082") {
			t.Fatalf("missing %s:\n%s", want, script)
		}
	}
}
