package gate

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func useLANPrefixFile(t *testing.T) {
	t.Helper()
	path := lanPrefixFile
	lanPrefixFile = filepath.Join(t.TempDir(), "lan-prefixes.json")
	t.Cleanup(func() { lanPrefixFile = path })
}

// An IPv6 rule needs a client network; one that a LAN interface will have later will do.
func TestPlanDevicesIPv6FromLANInterfaces(t *testing.T) {
	v6 := exitRule("wg1")
	v6["ipv6"] = true
	path := filepath.Join(t.TempDir(), "gate.json")
	writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "lan_interfaces": []any{"loop0"},
		"vpp_socket": filepath.Join(filepath.Dir(path), "no-vpp.sock"), "routes": []any{v6}})
	plan, err := PlanDevices(path, emptyDeviceState())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Devices) != 1 || !plan.Devices[0].IPv6 || !slices.Equal(plan.LANIfaces, []string{"loop0"}) {
		t.Fatalf("devices %+v, interfaces %v", plan.Devices, plan.LANIfaces)
	}
	// The running Gate reads the interfaces from what the sync generates.
	if err := validateEffective(plan); err != nil {
		t.Fatalf("%v\n%s", err, plan.Effective)
	}
	if !strings.Contains(plan.Effective, `"lan_interfaces"`) {
		t.Fatalf("lan_interfaces did not reach Gate:\n%s", plan.Effective)
	}
	writeJSON(t, path, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24"}, "lan_interfaces": []any{"bad name"}, "routes": []any{v6}})
	if _, err := PlanDevices(path, emptyDeviceState()); err == nil {
		t.Fatal("a bad interface name was accepted")
	}
}

func TestUsableLANPrefix(t *testing.T) {
	fixed := []netip.Prefix{netip.MustParsePrefix("10.64.30.0/24"), netip.MustParsePrefix("fd99:77::/64")}
	for text, want := range map[string]bool{
		"2001:db8:4b73::/64": true,
		"fdab:c65c:8cbc:123c::/64": true,
		"fd99:77::/64":             false, // listed already
		"fd99::/16":                false, // covers a listed one
		"fe80::/64":                false,
		"ff02::/16":                false,
		"::1/128":                  false,
		"2001:db8::1/128":          false, // an address, not a network
		deviceExitNet6:             false,
		"10.61.50.0/24":          false, // IPv4 comes from lan_prefixes only
	} {
		if got := usableLANPrefix(netip.MustParsePrefix(text), fixed); got != want {
			t.Errorf("%s: %v", text, got)
		}
	}
}

func TestClientNetworksAddWhatWasLearned(t *testing.T) {
	state := &DeviceState{LANs: []string{"10.64.30.0/24", "fd99:77::/64"}, LANInterfaces: []string{"loop0"}}
	learned := learnedLANs{Interfaces: []string{"loop0"}, Prefixes: []string{"2001:db8:4b73::/64", "fd99:77::/64", "garbage"}}
	if got := state.clientNetworks(learned); !slices.Equal(got, []string{"10.64.30.0/24", "fd99:77::/64", "2001:db8:4b73::/64"}) {
		t.Fatalf("got %v", got)
	}
	// Learned for other interfaces: an earlier configuration's.
	learned.Interfaces = []string{"loop1"}
	if got := state.clientNetworks(learned); !slices.Equal(got, state.LANs) {
		t.Fatalf("other interfaces: %v", got)
	}
	state.LANInterfaces = nil
	learned.Interfaces = nil
	if got := state.clientNetworks(learned); !slices.Equal(got, state.LANs) {
		t.Fatalf("no interfaces: %v", got)
	}
}

// The keeper applies a new prefix once, keeps the routes while VPP cannot be asked, and
// follows a renumbering; what it found is there for the next sync.
func TestLANPrefixKeeperFollowsTheDelegation(t *testing.T) {
	useDeviceDirs(t)
	useLANPrefixFile(t)
	state := &DeviceState{Devices: map[string]*DeviceEntry{}, LANs: []string{"10.64.30.0/24"}, LANInterfaces: []string{"loop0"}}
	if err := durableJSON(filepath.Join(deviceStateDir, "devices.json"), state); err != nil {
		t.Fatal(err)
	}
	found := []netip.Prefix{netip.MustParsePrefix("2001:db8:4b73::/64"), netip.MustParsePrefix("fe80::/64")}
	var readErr error
	var applied [][]string
	k := newLANPrefixKeeper([]string{"loop0"}, nil)
	k.read = func() ([]netip.Prefix, []string, error) { return found, nil, readErr }
	k.apply = func(_ context.Context, _ *DeviceState, lans []string) error {
		applied = append(applied, lans)
		return nil
	}
	k.tick()
	k.tick()
	if len(applied) != 1 || !slices.Equal(applied[0], []string{"10.64.30.0/24", "2001:db8:4b73::/64"}) {
		t.Fatalf("applied %v", applied)
	}
	loaded, err := loadDeviceState()
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.clientNetworks(readLearnedLANs()); !slices.Equal(got, applied[0]) {
		t.Fatalf("a sync would use %v", got)
	}
	readErr = errors.New("VPP is restarting")
	k.tick()
	if len(applied) != 1 || !slices.Equal(readLearnedLANs().Prefixes, []string{"2001:db8:4b73::/64"}) {
		t.Fatalf("VPP away: applied %v, file %v", applied, readLearnedLANs())
	}
	readErr = nil
	found = []netip.Prefix{netip.MustParsePrefix("2001:db8:4b74::/64")}
	k.tick()
	if len(applied) != 2 || !slices.Equal(applied[1], []string{"10.64.30.0/24", "2001:db8:4b74::/64"}) {
		t.Fatalf("renumbered: %v", applied)
	}
	// Withdrawn: back to the fixed networks.
	found = nil
	k.tick()
	if len(applied) != 3 || !slices.Equal(applied[2], []string{"10.64.30.0/24"}) {
		t.Fatalf("withdrawn: %v", applied)
	}
	// A journal for other interfaces is not changed behind its back.
	state.LANInterfaces = []string{"loop9"}
	if err := durableJSON(filepath.Join(deviceStateDir, "devices.json"), state); err != nil {
		t.Fatal(err)
	}
	found = []netip.Prefix{netip.MustParsePrefix("2001:db8:4b75::/64")}
	k.tick()
	if len(applied) != 3 {
		t.Fatalf("applied against another journal: %v", applied)
	}
}
