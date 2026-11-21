package gate

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"go.fd.io/govpp/binapi/fib_types"
)

func wanPath() defaultPath {
	return defaultPath{SwIfIndex: 1, Type: fib_types.FIB_API_PATH_TYPE_NORMAL, Proto: fib_types.FIB_API_PATH_NH_PROTO_IP4, Next: netip.MustParseAddr("192.0.2.1"), Weight: 1}
}

func wan6Path() defaultPath {
	return defaultPath{SwIfIndex: 1, Type: fib_types.FIB_API_PATH_TYPE_NORMAL, Proto: fib_types.FIB_API_PATH_NH_PROTO_IP6, Next: netip.MustParseAddr("fe80::1"), Weight: 1}
}

func observation() defaultObservation {
	return defaultObservation{
		Interfaces: map[string]vppInterfaceState{"wan0": {Index: 1, Up: true}, "wg100": {Index: 7, Up: true}, "tap2101": {Index: 8, Up: true}},
		Fallback: map[RouteKey][]defaultPath{
			{0, "0.0.0.0/0"}: {wanPath()},
			{0, "::/0"}:      {wan6Path()},
		},
		Endpoints: []defaultEndpoint{{0, netip.MustParseAddr("203.0.113.9")}, {0, netip.MustParseAddr("2001:db8::9")}, {5, netip.MustParseAddr("198.51.100.1")}},
	}
}

func up(string) bool { return true }

func TestDefaultRoutePlanTakesHalvesAndPinsEndpoints(t *testing.T) {
	exits := map[int]defaultExit{4: {Interface: "wg100", Via: "10.9.0.1"}}
	desired, status := planDefaultRoutes(exits, []string{"10.0.0.0/8", "fd00::/8", "0.0.0.0/0"}, observation(), up)
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		route, ok := desired[RouteKey{0, prefix}]
		if !ok || len(route.Paths) != 1 || route.Paths[0].SwIfIndex != 7 || route.Paths[0].Next.String() != "10.9.0.1" {
			t.Fatalf("%s: %+v", prefix, route)
		}
	}
	for _, prefix := range []string{"203.0.113.9/32", "10.0.0.0/8"} {
		route, ok := desired[RouteKey{0, prefix}]
		if !ok || route.signature() != (defaultRoute{Paths: []defaultPath{wanPath()}}).signature() {
			t.Fatalf("pin %s: %+v", prefix, route)
		}
	}
	// IPv6 has no exit, another table is not this exit's, and a /0 exclusion would be the default itself.
	for _, prefix := range []string{"::/1", "2001:db8::9/128", "fd00::/8", "198.51.100.1/32", "0.0.0.0/0"} {
		if _, ok := desired[RouteKey{0, prefix}]; ok {
			t.Fatalf("unexpected %s", prefix)
		}
	}
	if len(desired) != 4 || status.Interface != "wg100" || len(status.Active) != 1 || status.Active[0] != 4 || status.Problem != "" {
		t.Fatalf("%d routes, status %+v", len(desired), status)
	}
}

func TestDefaultRoutePlanFallsBackWhenTheExitIsUnusable(t *testing.T) {
	exits := map[int]defaultExit{4: {Interface: "wg100", Via: "10.9.0.1"}, 6: {Interface: "wg100", Via: "fd09::1"}}
	for name, change := range map[string]func(*defaultObservation) (linuxUp func(string) bool){
		"missing": func(o *defaultObservation) func(string) bool { delete(o.Interfaces, "wg100"); return up },
		"down": func(o *defaultObservation) func(string) bool {
			o.Interfaces["wg100"] = vppInterfaceState{Index: 7}
			return up
		},
	} {
		obs := observation()
		linuxUp := change(&obs)
		desired, status := planDefaultRoutes(exits, []string{"10.0.0.0/8"}, obs, linuxUp)
		if len(desired) != 0 || len(status.Active) != 0 || len(status.Families) != 2 || !strings.Contains(status.Problem, "wg100") {
			t.Fatalf("%s: %v %+v", name, desired, status)
		}
	}
	linux := map[int]defaultExit{4: {Interface: "tap2101", Via: "172.30.1.2", LinuxExit: "wg0"}}
	desired, status := planDefaultRoutes(linux, nil, observation(), func(name string) bool { return name != "wg0" })
	if len(desired) != 0 || !strings.Contains(status.Problem, "wg0") {
		t.Fatalf("Linux exit down: %v %+v", desired, status)
	}
	desired, _ = planDefaultRoutes(linux, nil, observation(), up)
	if _, ok := desired[RouteKey{0, "128.0.0.0/1"}]; !ok {
		t.Fatalf("Linux exit up: %v", desired)
	}
}

func TestDefaultRoutePlanPinsNothingWithoutAFallback(t *testing.T) {
	exits := map[int]defaultExit{4: {Interface: "wg100", Via: "10.9.0.1"}}
	obs := observation()
	obs.Fallback[RouteKey{0, "0.0.0.0/0"}] = nil
	desired, _ := planDefaultRoutes(exits, []string{"10.0.0.0/8"}, obs, up)
	if len(desired) != 2 {
		t.Fatalf("without 0.0.0.0/0 only the halves: %v", desired)
	}
	// 0.0.0.0/0 through the exit itself: copying it would send the endpoints into the tunnel.
	obs.Fallback[RouteKey{0, "0.0.0.0/0"}] = []defaultPath{{SwIfIndex: 7, Type: fib_types.FIB_API_PATH_TYPE_NORMAL, Proto: fib_types.FIB_API_PATH_NH_PROTO_IP4, Weight: 1}}
	desired, _ = planDefaultRoutes(exits, []string{"10.0.0.0/8"}, obs, up)
	if len(desired) != 2 {
		t.Fatalf("0.0.0.0/0 through the exit: %v", desired)
	}
}

type fakeDefaultAPI struct {
	gen     string
	obs     defaultObservation
	routes  map[RouteKey]string
	log     []string
	failAdd map[string]bool
}

func (f *fakeDefaultAPI) generation() (string, error) { return f.gen, nil }
func (f *fakeDefaultAPI) observe([]uint32) (defaultObservation, error) {
	f.log = append(f.log, "observe")
	return f.obs, nil
}
func (f *fakeDefaultAPI) add(route defaultRoute) error {
	if f.failAdd[route.Prefix] {
		return errors.New("refused")
	}
	f.routes[route.Key()] = route.signature()
	f.log = append(f.log, "add "+route.Prefix)
	return nil
}
func (f *fakeDefaultAPI) remove(key RouteKey) error {
	delete(f.routes, key)
	f.log = append(f.log, "del "+key.Prefix)
	return nil
}

func defaultConfig(t *testing.T, dir string, routes []any) *Config {
	t.Helper()
	path := filepath.Join(dir, "routes.json")
	writeJSON(t, path, map[string]any{"routes": routes})
	cfg := &Config{StateFile: filepath.Join(dir, "state.json"), ExcludePrefixes: []string{"10.0.0.0/8"}, OverlapPolicy: "error", DNSUpstreamPolicy: "first-upstream"}
	if _, err := DomainRoutesFromFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDefaultRouteKeeperFollowsTheExit(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig(t, dir, []any{map[string]any{"name": "default", "interface": "wg100", "via": "10.9.0.1", "default_route": true}})
	api := &fakeDefaultAPI{gen: "g1", obs: observation(), routes: map[RouteKey]string{}}
	k := newDefaultRouteKeeper(func() *Config { return cfg }, api)
	k.linuxUp = up
	k.ensure()
	want := []string{"observe", "add 10.0.0.0/8", "add 203.0.113.9/32", "add 0.0.0.0/1", "add 128.0.0.0/1"}
	if strings.Join(api.log, ",") != strings.Join(want, ",") {
		t.Fatalf("pins go in before the halves: %v", api.log)
	}
	if got := readDefaultState(defaultStatePath(cfg), "g1"); len(got) != 4 {
		t.Fatalf("recorded %v", got)
	}

	// Nothing changed: nothing is touched.
	api.log = nil
	k.ensure()
	if strings.Join(api.log, ",") != "observe" {
		t.Fatalf("steady state: %v", api.log)
	}

	// The tunnel stops: the halves go, and so do the pins, which only matter while they exist.
	api.log = nil
	delete(api.obs.Interfaces, "wg100")
	k.ensure()
	if len(api.routes) != 0 || k.Status().Problem == "" {
		t.Fatalf("fallback: %v %+v", api.routes, k.Status())
	}

	// A new Gate on the same VPP run removes what the old one left, once nothing is chosen.
	api.obs = observation()
	k.ensure()
	plain := &Config{StateFile: cfg.StateFile}
	next := newDefaultRouteKeeper(func() *Config { return plain }, api)
	next.ensure()
	if len(api.routes) != 0 || len(readDefaultState(defaultStatePath(cfg), "g1")) != 0 {
		t.Fatalf("left behind: %v", api.routes)
	}

	// With nothing chosen and nothing recorded, VPP is not asked anything.
	api.log = nil
	next.ensure()
	if len(api.log) != 0 {
		t.Fatalf("idle keeper asked VPP: %v", api.log)
	}
}

func TestDefaultRouteKeeperForgetsAnEarlierVPPRun(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig(t, dir, []any{map[string]any{"name": "default", "interface": "wg100", "via": "10.9.0.1", "default_route": true}})
	api := &fakeDefaultAPI{gen: "g1", obs: observation(), routes: map[RouteKey]string{}}
	k := newDefaultRouteKeeper(func() *Config { return cfg }, api)
	k.ensure()
	api.gen, api.routes, api.log = "g2", map[RouteKey]string{}, nil
	k.ensure()
	if len(api.routes) != 4 || strings.Contains(strings.Join(api.log, ","), "del") {
		t.Fatalf("a restarted VPP gets everything again: %v %v", api.routes, api.log)
	}
}

func TestDefaultRouteKeeperRetriesAFailedRoute(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig(t, dir, []any{map[string]any{"name": "default", "interface": "wg100", "via": "10.9.0.1", "default_route": true}})
	api := &fakeDefaultAPI{gen: "g1", obs: observation(), routes: map[RouteKey]string{}, failAdd: map[string]bool{"128.0.0.0/1": true}}
	k := newDefaultRouteKeeper(func() *Config { return cfg }, api)
	k.ensure()
	if !strings.Contains(k.Status().Problem, "refused") {
		t.Fatalf("status %+v", k.Status())
	}
	if _, recorded := readDefaultState(defaultStatePath(cfg), "g1")[RouteKey{0, "128.0.0.0/1"}]; !recorded {
		t.Fatal("a route that may be in VPP must stay recorded")
	}
	api.failAdd = nil
	k.ensure()
	if _, ok := api.routes[RouteKey{0, "128.0.0.0/1"}]; !ok || k.Status().Problem != "" {
		t.Fatalf("retry: %v %+v", api.routes, k.Status())
	}
}

func TestDefaultRouteConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig(t, dir, []any{
		map[string]any{"name": "v4", "interface": "wg100", "via": "10.9.0.1", "default_route": true},
		map[string]any{"name": "v6", "interface": "wg100", "via": "fd09::1", "default_route": true},
		map[string]any{"name": "other", "interface": "wg1", "via": "10.1.0.1", "domains": []any{"example.org"}},
	})
	exits := defaultExits(cfg)
	if exits[4].Interface != "wg100" || exits[6].Via != "fd09::1" || len(exits) != 2 {
		t.Fatalf("exits %+v", exits)
	}
	for name, routes := range map[string][]any{
		"two exits": {
			map[string]any{"name": "a", "interface": "wg100", "via": "10.9.0.1", "default_route": true},
			map[string]any{"name": "b", "interface": "wg1", "via": "10.1.0.1", "default_route": true},
		},
		"not a boolean": {map[string]any{"name": "a", "interface": "wg100", "via": "10.9.0.1", "default_route": "yes"}},
		"Fake-IP": {map[string]any{"name": "a", "interface": "tap2081", "via": "172.30.20.2", "default_route": true,
			"fakeip_range": "198.18.0.0/15", "fake_dns": []any{"127.0.0.1", 5354}, "domains": []any{"example.org"}}},
		"empty without it": {map[string]any{"name": "a", "interface": "wg100", "via": "10.9.0.1"}},
	} {
		path := filepath.Join(dir, "bad.json")
		writeJSON(t, path, map[string]any{"routes": routes})
		cfg := &Config{StateFile: filepath.Join(dir, "state.json"), OverlapPolicy: "error", DNSUpstreamPolicy: "first-upstream"}
		if _, err := DomainRoutesFromFile(path, cfg); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestDefaultRouteKeepsAnEmptyRuleInTheSync(t *testing.T) {
	if !routeHasRules(map[string]any{"name": "a", "default_route": true}) {
		t.Fatal("a rule carrying the default route is active without lists")
	}
	if routeHasRules(map[string]any{"name": "a", "default_route": false}) {
		t.Fatal("an empty rule without the default route stays off")
	}
}

func TestDefaultRouteThroughADHCPLease(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig(t, dir, []any{map[string]any{"name": "default", "interface": "wan1", "dhcp_gateway": true, "via": "fe80::1", "default_route": true}})
	exits := defaultExits(cfg)
	if !exits[4].DHCP || exits[4].Via != "" || exits[6].Via != "fe80::1" {
		t.Fatalf("exits %+v", exits)
	}
	obs := observation()
	obs.Interfaces["wan1"] = vppInterfaceState{Index: 3, Up: true}
	desired, status := planDefaultRoutes(exits, nil, obs, up)
	if _, ok := desired[RouteKey{0, "0.0.0.0/1"}]; ok || !strings.Contains(status.Problem, "DHCP") {
		t.Fatalf("no lease yet: %v %+v", desired, status)
	}
	if _, ok := desired[RouteKey{0, "::/1"}]; !ok {
		t.Fatal("IPv6 has a fixed next hop and does not wait for the lease")
	}
	obs.Leases = map[string]netip.Addr{"wan1": netip.MustParseAddr("100.64.0.1")}
	desired, _ = planDefaultRoutes(exits, nil, obs, up)
	route := desired[RouteKey{0, "128.0.0.0/1"}]
	if len(route.Paths) != 1 || route.Paths[0].SwIfIndex != 3 || route.Paths[0].Next.String() != "100.64.0.1" {
		t.Fatalf("lease router: %+v", route)
	}
	// A new lease router changes the route.
	k := newDefaultRouteKeeper(func() *Config { return cfg }, &fakeDefaultAPI{gen: "g", obs: obs, routes: map[RouteKey]string{}})
	k.linuxUp = up
	k.ensure()
	api := k.api.(*fakeDefaultAPI)
	api.obs.Leases = map[string]netip.Addr{"wan1": netip.MustParseAddr("100.64.0.9")}
	api.log = nil
	k.ensure()
	if !strings.Contains(strings.Join(api.log, ","), "del 0.0.0.0/1") || !strings.Contains(strings.Join(api.log, ","), "add 0.0.0.0/1") {
		t.Fatalf("new router: %v", api.log)
	}
}

func TestDHCPGatewayIsOnlyForTheDefaultRoute(t *testing.T) {
	dir := t.TempDir()
	for name, route := range map[string]map[string]any{
		"without default_route": {"name": "a", "interface": "wan1", "dhcp_gateway": true, "domains": []any{"example.org"}},
		"with domains":          {"name": "a", "interface": "wan1", "dhcp_gateway": true, "default_route": true, "domains": []any{"example.org"}},
		"with an IPv4 via":      {"name": "a", "interface": "wan1", "dhcp_gateway": true, "default_route": true, "via": "192.0.2.1"},
	} {
		path := filepath.Join(dir, "bad.json")
		writeJSON(t, path, map[string]any{"routes": []any{route}})
		cfg := &Config{StateFile: filepath.Join(dir, "state.json"), OverlapPolicy: "error", DNSUpstreamPolicy: "first-upstream"}
		if _, err := DomainRoutesFromFile(path, cfg); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestControllerLoadsADefaultCarrier(t *testing.T) {
	dir := t.TempDir()
	_, _, _, c := writePolicy(t, dir, []any{
		map[string]any{"name": "default", "interface": "wan1", "dhcp_gateway": true, "default_route": true},
		map[string]any{"name": "wg", "interface": "wg1", "via": "10.1.0.1", "domains": []any{"example.org"}},
	})
	cfg, _ := c.loaded()
	if exits := defaultExits(cfg); !exits[4].DHCP {
		t.Fatalf("%+v", exits)
	}
	if err := c.Reconcile(context.Background(), nil, nil, true); err != nil {
		t.Fatalf("a carrier with nothing to route must not upset reconciliation: %v", err)
	}
}
