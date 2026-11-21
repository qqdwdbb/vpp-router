package gate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicy(t *testing.T, dir string, routes []any) (configPath, domainPath string, backend *FakeBackend, c *Controller) {
	t.Helper()
	configPath = filepath.Join(dir, "runtime.json")
	writeJSON(t, configPath, map[string]any{
		"state_file":       filepath.Join(dir, "state.json"),
		"lock_files":       []any{},
		"exclude_prefixes": []any{"192.168.0.0/16"},
		"max_routes":       10000,
	})
	domainPath = filepath.Join(dir, "domains.json")
	writeJSON(t, domainPath, map[string]any{"routes": routes})
	backend = NewFakeBackend()
	var err error
	c, err = NewController(configPath, filepath.Join(dir, "leases.json"),
		func(*Config) Backend { return backend }, domainPath)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestDomainFileSelectsExitAndUpstream(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "altroute.domains"), []byte("routing.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy.domains"), []byte("blocked.example\nrouting.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, backend, c := writePolicy(t, dir, []any{
		map[string]any{
			"name": "altroute", "interface": "wg1", "via": "10.62.30.1",
			"domain_files": filepath.Join(dir, "altroute.domains"),
			"dns":          []any{"8.8.8.8", 53},
		},
		map[string]any{
			"name": "proxy", "interface": "tap2490",
			"via":              []any{"10.63.30.2", "fd42:1111:2222:30::2"},
			"domain_files":     filepath.Join(dir, "proxy.domains"),
			"fake_dns":         []any{"127.0.0.1", 5354},
			"fakeip_range":     []any{"198.18.0.0/15", "2001:2::/48"},
			"tproxy_port":      2082,
			"tproxy_interface": "vpp-tproxy",
		},
	})
	up := c.DNSUpstream(Question{"www.routing.example.net", 1, 1})
	if up == nil || up.Host != "8.8.8.8" || up.Port != 53 {
		t.Fatalf("altroute upstream %v", up)
	}
	up = c.DNSUpstream(Question{"www.blocked.example", 1, 1})
	if up == nil || up.Host != "127.0.0.1" || up.Port != 5354 {
		t.Fatalf("fake dns %v", up)
	}
	aaaa := Question{"www.routing.example.net", 28, 1}
	up = c.DNSUpstream(aaaa)
	if up == nil || up.Host != "8.8.8.8" || up.Port != 53 {
		t.Fatalf("altroute still owns AAAA, got %v", up)
	}
	suppress := c.SuppressAAAA(aaaa)
	if !suppress {
		t.Fatalf("v4-only altroute must hide AAAA, got %v", suppress)
	}
	suppress = c.SuppressAAAA(Question{"www.routing.example.net", 1, 1})
	if suppress {
		t.Fatalf("A must not be hidden, got %v", suppress)
	}
	suppress = c.SuppressAAAA(Question{"www.blocked.example", 28, 1})
	if suppress {
		t.Fatalf("dual-stack proxy must keep AAAA, got %v", suppress)
	}
	suppress = c.SuppressAAAA(Question{"example.org", 28, 1})
	if suppress {
		t.Fatalf("unmatched AAAA must not be hidden, got %v", suppress)
	}
	up = c.DNSUpstream(Question{"example.org", 1, 1})
	if up != nil {
		t.Fatalf("unmatched upstream %v", up)
	}
	store := NewDeferredState([]string{c.Config().StateFile, filepath.Join(dir, "leases.json")})
	store.Enter()
	defer store.Exit()
	if err := c.Reconcile(context.Background(), nil, nil, false); err != nil {
		t.Fatal(err)
	}
	pathEquals(t, backend, "198.18.0.0/15", "10.63.30.2", "tap2490")
	pathEquals(t, backend, "2001:2::/48", "fd42:1111:2222:30::2", "tap2490")
	q := Question{"www.routing.example.net", 1, 1}
	if err := c.Reconcile(context.Background(), []Record{{"www.routing.example.net", "198.51.100.77", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	pathEquals(t, backend, "198.51.100.77/32", "10.62.30.1", "wg1")
	if err := c.Reconcile(context.Background(), []Record{{"www.routing.example.net", "2001:db8::77", 60}}, &aaaa, false); err != nil {
		t.Fatal(err)
	}
	if backend.HasRoute(0, "2001:db8::77/128") {
		t.Fatal("v4-only exit must not install an AAAA host route")
	}
	cfg, _ := c.loaded()
	rules := tproxyPortRules(cfg)
	if len(rules) != 2 {
		t.Fatalf("tproxy rules %v", rules)
	}
	for _, rule := range rules {
		if rule.Port != 2082 || rule.Interface != "vpp-tproxy" {
			t.Fatalf("tproxy must use one nic and port: %v", rule)
		}
	}
	script := strings.Join(tproxyPortNftScript(rules), "\n")
	if !strings.Contains(script, "tproxy ip to :2082") || !strings.Contains(script, "tproxy ip6 to :2082") ||
		!strings.Contains(script, `iifname "vpp-tproxy"`) || strings.Count(script, "iifname") != 2 {
		t.Fatalf("nft script %s", script)
	}
}

func TestDualStackExitSharesOneInterface(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vpn.domains"), []byte("vpn.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, backend, c := writePolicy(t, dir, []any{map[string]any{
		"name": "vpn", "interface": "loop10",
		"via":          []any{"10.61.50.1", "fd42:1111:2222:20::1"},
		"domain_files": filepath.Join(dir, "vpn.domains"),
	}})
	store := NewDeferredState([]string{c.Config().StateFile, filepath.Join(dir, "leases.json")})
	store.Enter()
	defer store.Exit()
	q := Question{"www.vpn.example", 1, 1}
	if err := c.Reconcile(context.Background(), []Record{{"www.vpn.example", "198.51.100.9", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	aaaa := Question{"www.vpn.example", 28, 1}
	if err := c.Reconcile(context.Background(), []Record{{"www.vpn.example", "2001:db8::9", 60}}, &aaaa, false); err != nil {
		t.Fatal(err)
	}
	pathEquals(t, backend, "198.51.100.9/32", "10.61.50.1", "loop10")
	pathEquals(t, backend, "2001:db8::9/128", "fd42:1111:2222:20::1", "loop10")
	suppress := c.SuppressAAAA(aaaa)
	if suppress {
		t.Fatalf("dual-stack vpn must keep AAAA, got %v", suppress)
	}
}

func TestSeparateAddressFamiliesShareOneOutlet(t *testing.T) {
	dir := t.TempDir()
	_, _, backend, c := writePolicy(t, dir, []any{
		map[string]any{"name": "vpn", "interface": "loop10", "via": "10.61.50.1", "domains": []any{"vpn.example"}},
		map[string]any{"name": "vpn6", "interface": "loop10", "via": "fd42:1111:2222:20::1", "domains": []any{"vpn.example"}},
	})
	store := NewDeferredState([]string{c.Config().StateFile, filepath.Join(dir, "leases.json")})
	store.Enter()
	defer store.Exit()
	q := Question{"www.vpn.example", 28, 1}
	if c.SuppressAAAA(q) {
		t.Fatal("IPv6 outlet suppressed")
	}
	if err := c.Reconcile(context.Background(), []Record{{q.Name, "2001:db8::9", 60}}, &q, false); err != nil {
		t.Fatal(err)
	}
	pathEquals(t, backend, "2001:db8::9/128", "fd42:1111:2222:20::1", "loop10")
}

func TestLoadConfigAllowsMissingMappings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime.json")
	writeJSON(t, path, map[string]any{
		"state_file": filepath.Join(dir, "state.json"),
		"lock_files": []any{},
	})
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Mappings) != 0 {
		t.Fatalf("mappings %v", cfg.Mappings)
	}
}

func TestFakeDNSRequiresPool(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.json")
	writeJSON(t, configPath, map[string]any{"state_file": filepath.Join(dir, "state.json"), "lock_files": []any{}})
	path := filepath.Join(dir, "domains.json")
	writeJSON(t, path, map[string]any{"routes": []any{map[string]any{
		"name": "proxy", "interface": "tap2490", "via": "10.63.30.2",
		"domains": []any{"blocked.example"}, "fake_dns": []any{"127.0.0.1", 5354},
	}}})
	_, err := NewController(configPath, filepath.Join(dir, "leases.json"),
		func(*Config) Backend { return NewFakeBackend() }, path)
	if err == nil || !strings.Contains(err.Error(), "fake_dns requires fakeip_range") {
		t.Fatalf("err %v", err)
	}
}

func TestTproxyPortRequiresFakeIP(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "runtime.json")
	writeJSON(t, configPath, map[string]any{"state_file": filepath.Join(dir, "state.json"), "lock_files": []any{}})
	path := filepath.Join(dir, "domains.json")
	writeJSON(t, path, map[string]any{"routes": []any{map[string]any{
		"name": "proxy", "interface": "tap2490", "via": "10.63.30.2",
		"domains": []any{"blocked.example"}, "dns": []any{"127.0.0.1", 5354},
		"tproxy_port": 2082,
	}}})
	_, err := NewController(configPath, filepath.Join(dir, "leases.json"),
		func(*Config) Backend { return NewFakeBackend() }, path)
	if err == nil || !strings.Contains(err.Error(), "real-address tproxy_port requires tproxy_interface") {
		t.Fatalf("err %v", err)
	}
}

func TestTproxyAddress(t *testing.T) {
	load := func(address any) (*Config, error) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "runtime.json")
		writeJSON(t, configPath, map[string]any{"state_file": filepath.Join(dir, "state.json"), "lock_files": []any{}})
		path := filepath.Join(dir, "domains.json")
		writeJSON(t, path, map[string]any{"routes": []any{map[string]any{
			"name": "proxy", "interface": "tap2490", "via": []any{"10.63.30.2", "fd42:1111:2222:30::2"},
			"domains": []any{"blocked.example"}, "fake_dns": []any{"127.0.0.1", 5354},
			"fakeip_range": []any{"198.18.0.0/15", "2001:2::/48"}, "tproxy_port": 7893, "tproxy_address": address,
		}}})
		c, err := NewController(configPath, filepath.Join(dir, "leases.json"),
			func(*Config) Backend { return NewFakeBackend() }, path)
		if err != nil {
			return nil, err
		}
		cfg, _ := c.loaded()
		return cfg, nil
	}
	cfg, err := load([]any{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	if rules := tproxyPortRules(cfg); len(rules) != 2 || rules[0].Address.String() != "127.0.0.1" || rules[1].Address.String() != "::1" {
		t.Fatalf("%+v", rules)
	}
	for address, message := range map[any]string{
		"127.0.0.1": "no address for the Fake-IP pool 2001:2::/48",
		"0.0.0.0":   "leave it out",
		"nonsense":  "invalid tproxy_address",
	} {
		if _, err := load(address); err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("%v: %v", address, err)
		}
	}
	if _, err := load([]any{"127.0.0.1", "127.0.0.2"}); err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("%v", err)
	}
}

func TestUnifiedGateFileLoadsRoutes(t *testing.T) {
	dir := t.TempDir()
	gate := filepath.Join(dir, "egress-gate.json")
	if err := os.WriteFile(filepath.Join(dir, "altroute.domains"), []byte("routing.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, gate, map[string]any{
		"listen":     []any{[]any{"127.0.0.1", 1053}},
		"upstream":   []any{"127.0.0.1", 53},
		"lease_file": filepath.Join(dir, "leases.json"),
		"state_file": filepath.Join(dir, "state.json"),
		"lock_files": []any{},
		"routes": []any{map[string]any{
			"name": "altroute", "interface": "wg1", "via": "10.62.30.1",
			"domain_files": []any{filepath.Join(dir, "altroute.domains")},
		}},
	})
	g, err := LoadGateFile(gate)
	if err != nil {
		t.Fatal(err)
	}
	if !g.HasRoutes {
		t.Fatal("expected routes in gate file")
	}
	cfg, err := LoadConfig(gate)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := DomainRoutesFromFile(gate, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Pattern != "routing.example.net" {
		t.Fatalf("rules %v", rules)
	}
	if len(cfg.Mappings) != 1 || cfg.Mappings[0].Via != "10.62.30.1" {
		t.Fatalf("mappings %v", cfg.Mappings)
	}
	if g.HijackDNS {
		t.Fatal("hijack_dns defaults to off")
	}
}

func TestLoadGateFileHijackDNS(t *testing.T) {
	dir := t.TempDir()
	gate := filepath.Join(dir, "egress-gate.json")
	writeJSON(t, gate, map[string]any{
		"listen":            []any{[]any{"10.61.20.2", 1053}, []any{"fd42:1111:2222:10::2", 1053}},
		"upstream":          []any{"10.61.20.2", 53},
		"lease_file":        filepath.Join(dir, "leases.json"),
		"hijack_dns":        true,
		"hijack_interfaces": []any{"br-mgmt", "lan"},
	})
	g, err := LoadGateFile(gate)
	if err != nil {
		t.Fatal(err)
	}
	if !g.HijackDNS || len(g.HijackInterfaces) != 2 || g.HijackInterfaces[0] != "br-mgmt" {
		t.Fatalf("hijack %+v", g)
	}

	writeJSON(t, gate, map[string]any{
		"listen":     []any{[]any{"10.61.20.2", 1053}},
		"upstream":   []any{"10.61.20.2", 53},
		"lease_file": filepath.Join(dir, "leases.json"),
		"hijack_dns": true,
	})
	if _, err := LoadGateFile(gate); err == nil || !strings.Contains(err.Error(), "hijack_interfaces") {
		t.Fatalf("missing interfaces: %v", err)
	}

	writeJSON(t, gate, map[string]any{
		"listen":            []any{[]any{"10.61.20.2", 1053}, []any{"fd42:1111:2222:10::2", 5353}},
		"upstream":          []any{"10.61.20.2", 53},
		"lease_file":        filepath.Join(dir, "leases.json"),
		"hijack_dns":        true,
		"hijack_interfaces": "br-mgmt",
	})
	if _, err := LoadGateFile(gate); err == nil || !strings.Contains(err.Error(), "same port") {
		t.Fatalf("mismatched ports: %v", err)
	}
}

func TestV4OnlyExchangeHidesAAAA(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "altroute.domains"), []byte("routing.example.net\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, _, c := writePolicy(t, dir, []any{map[string]any{
		"name": "altroute", "interface": "wg1", "via": "10.62.30.1",
		"domain_files": filepath.Join(dir, "altroute.domains"),
		"dns":          []any{"8.8.8.8", 53},
	}})
	g := NewGate(c, Upstream{"127.0.0.1", 1})
	answer := g.Exchange(aaaaQueryPacket(), false)
	got, err := Decode(answer)
	if err != nil || got.Flags&15 != 0 || len(got.Records) != 0 {
		t.Fatalf("AAAA NODATA got %+v %v", got, err)
	}
	if got.Question.Type != 28 {
		t.Fatalf("question %+v", got.Question)
	}
}

func TestListFilePathForms(t *testing.T) {
	for _, key := range []string{"domain_files", "ip_range_files"} {
		for name, want := range map[string]string{"/data/a.list": "/data/a.list", "a.list": "/etc/vpp/gate/a.list"} {
			if got, err := resolveListFile(key, name); err != nil || got != want {
				t.Fatalf("%s %s: got %s %v, want %s", key, name, got, err, want)
			}
		}
		for _, name := range []string{"gate/a.list", "./a.list", "../a.list"} {
			if _, err := resolveListFile(key, name); err == nil {
				t.Fatalf("%s %s was accepted", key, name)
			}
		}
	}
}

func TestDomainFileWithRelativeDirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "gate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gate", "a.domains"), []byte("example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "gate.json")
	route := map[string]any{"name": "a", "interface": "wg1", "via": "10.62.30.1", "domain_files": []any{"gate/a.domains"}}
	writeJSON(t, config, map[string]any{"state_file": filepath.Join(dir, "state.json"), "lock_files": []any{},
		"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "routes": []any{route}})
	_, err := NewController(config, filepath.Join(dir, "leases.json"), func(*Config) Backend { return NewFakeBackend() }, config)
	if err == nil || !strings.Contains(err.Error(), "file name or an absolute path") {
		t.Fatalf("gate: %v", err)
	}
	if _, err := PlanDevices(config, emptyDeviceState()); err == nil || !strings.Contains(err.Error(), "file name or an absolute path") {
		t.Fatalf("sync: %v", err)
	}
}
