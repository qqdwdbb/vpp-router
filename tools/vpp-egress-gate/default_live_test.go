package gate

import (
	"os"
	"testing"

	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
)

// TestLiveDefaultRoute runs the default route keeper against a VPP set up for it, never the
// one carrying traffic: GATE_LIVE_DEFAULT_SOCK names its API socket. That VPP has
//   - loop1 198.51.100.2/24 and ip route add 0.0.0.0/0 via 198.51.100.1 loop1
//   - wg0 10.9.0.2/24, up, with a peer whose endpoint is 203.0.113.9
type liveGeneration struct{ vppDefaultRouteAPI }

func (liveGeneration) generation() (string, error) { return "live", nil }

func TestLiveDefaultRoute(t *testing.T) {
	sock := os.Getenv("GATE_LIVE_DEFAULT_SOCK")
	if sock == "" {
		t.Skip("GATE_LIVE_DEFAULT_SOCK is not set")
	}
	dir := t.TempDir()
	cfg := defaultConfig(t, dir, []any{map[string]any{"name": "default", "interface": "wg0", "via": "10.9.0.1", "default_route": true}})
	cfg.APISocket = sock
	cfg.ExcludePrefixes = []string{"10.0.0.0/8"}
	api := liveGeneration{vppDefaultRouteAPI{cfg: cfg}}
	k := newDefaultRouteKeeper(func() *Config { return cfg }, api)
	k.linuxUp = up

	lookup := func(prefix string) []defaultPath {
		t.Helper()
		var paths []defaultPath
		if err := api.session(func(s *vppAPISession) error {
			var err error
			paths, err = s.lookupExact(0, prefix)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return paths
	}
	index := func(name string) uint32 {
		t.Helper()
		var states map[string]vppInterfaceState
		api.session(func(s *vppAPISession) error {
			var err error
			states, err = s.dumpInterfaceStates()
			return err
		})
		return states[name].Index
	}
	setUp := func(name string, up bool) {
		t.Helper()
		flags := interface_types.IfStatusFlags(0)
		if up {
			flags = interface_types.IF_STATUS_API_FLAG_ADMIN_UP
		}
		which := interface_types.InterfaceIndex(index(name)) // before the session: it takes the API lock too
		if err := api.session(func(s *vppAPISession) error {
			reply := &interfaces.SwInterfaceSetFlagsReply{}
			return s.ch.SendRequest(&interfaces.SwInterfaceSetFlags{SwIfIndex: which, Flags: flags}).ReceiveReply(reply)
		}); err != nil {
			t.Fatal(err)
		}
	}
	wg, wan := index("wg0"), index("loop1")
	before := lookup("0.0.0.0/0")
	if len(before) != 1 || before[0].SwIfIndex != wan || before[0].Next.String() != "198.51.100.1" {
		t.Fatalf("set up 0.0.0.0/0 via 198.51.100.1 loop1 first: %+v", before)
	}

	k.ensure()
	if status := k.Status(); len(status.Active) != 1 || status.Problem != "" {
		t.Fatalf("status %+v", status)
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if paths := lookup(half); len(paths) != 1 || paths[0].SwIfIndex != wg || paths[0].Next.String() != "10.9.0.1" {
			t.Fatalf("%s: %+v", half, paths)
		}
	}
	for _, pin := range []string{"203.0.113.9/32", "10.0.0.0/8"} {
		if paths := lookup(pin); len(paths) != 1 || paths[0].SwIfIndex != wan || paths[0].Next.String() != "198.51.100.1" {
			t.Fatalf("pin %s: %+v", pin, paths)
		}
	}
	if paths := lookup("0.0.0.0/0"); len(paths) != 1 || paths[0].SwIfIndex != wan {
		t.Fatalf("0.0.0.0/0 changed: %+v", paths)
	}

	// The tunnel goes down: back to 0.0.0.0/0.
	setUp("wg0", false)
	k.ensure()
	if paths := lookup("0.0.0.0/1"); len(paths) != 0 {
		t.Fatalf("half left while the exit is down: %+v", paths)
	}
	if status := k.Status(); len(status.Active) != 0 || status.Problem == "" {
		t.Fatalf("status %+v", status)
	}
	setUp("wg0", true)
	k.ensure()
	if paths := lookup("128.0.0.0/1"); len(paths) != 1 {
		t.Fatalf("not back: %+v", paths)
	}

	// VPP with the DHCP plugin and no clients answers with none.
	if err := api.session(func(s *vppAPISession) error {
		states, err := s.dumpInterfaceStates()
		if err != nil {
			return err
		}
		_, err = s.dhcpRouters(states)
		return err
	}); err != nil {
		t.Fatalf("DHCP dump: %v", err)
	}

	// What the state file records is everything there is to take away.
	flushAPI := vppDefaultRouteAPI{cfg: cfg}
	for _, key := range sortedRouteKeys(readDefaultState(defaultStatePath(cfg), "live")) {
		if err := flushAPI.remove(key); err != nil {
			t.Fatal(err)
		}
	}
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "203.0.113.9/32", "10.0.0.0/8"} {
		if paths := lookup(prefix); len(paths) != 0 {
			t.Fatalf("%s left: %+v", prefix, paths)
		}
	}
	if paths := lookup("0.0.0.0/0"); len(paths) != 1 || paths[0].SwIfIndex != wan {
		t.Fatalf("0.0.0.0/0 changed: %+v", paths)
	}
}

// TestLiveDefaultRouteThroughDHCP needs, in the same VPP, host-vdt0 with a bound DHCP lease.
func TestLiveDefaultRouteThroughDHCP(t *testing.T) {
	sock := os.Getenv("GATE_LIVE_DEFAULT_SOCK")
	if sock == "" {
		t.Skip("GATE_LIVE_DEFAULT_SOCK is not set")
	}
	cfg := defaultConfig(t, t.TempDir(), []any{map[string]any{"name": "default", "interface": "host-vdt0", "dhcp_gateway": true, "default_route": true}})
	cfg.APISocket = sock
	api := liveGeneration{vppDefaultRouteAPI{cfg: cfg}}
	obs, err := api.observe([]uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	router := obs.Leases["host-vdt0"]
	if !router.IsValid() {
		t.Fatalf("no lease read: %+v", obs.Leases)
	}
	k := newDefaultRouteKeeper(func() *Config { return cfg }, api)
	k.linuxUp = up
	k.ensure()
	var paths []defaultPath
	api.session(func(s *vppAPISession) error {
		paths, err = s.lookupExact(0, "128.0.0.0/1")
		return err
	})
	if len(paths) != 1 || paths[0].Next != router || paths[0].SwIfIndex != obs.Interfaces["host-vdt0"].Index {
		t.Fatalf("half %+v, router %s", paths, router)
	}
	t.Logf("128.0.0.0/1 via %s host-vdt0 from the lease", router)
	for _, key := range sortedRouteKeys(readDefaultState(defaultStatePath(cfg), "live")) {
		if err := api.remove(key); err != nil {
			t.Fatal(err)
		}
	}
}
