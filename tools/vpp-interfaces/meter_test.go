package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.fd.io/govpp/binapi/acl_types"
)

type fakeACL struct {
	tag   string
	rules []acl_types.ACLRule
}

type fakeMeterVPP struct {
	acls     map[uint32]fakeACL
	next     uint32
	in, out  map[uint32][]uint32
	counters bool
	neigh    []neighbor
	taps     map[uint32]string
	calls    []string
}

func newFakeMeterVPP() *fakeMeterVPP {
	return &fakeMeterVPP{acls: map[uint32]fakeACL{2: {tag: "someone-else"}}, next: 10,
		in: map[uint32][]uint32{3: {2}}, out: map[uint32][]uint32{}}
}

func (f *fakeMeterVPP) aclTag(index uint32) (string, bool, error) {
	a, ok := f.acls[index]
	return a.tag, ok, nil
}
func (f *fakeMeterVPP) replaceACL(index uint32, tag string, rules []acl_types.ACLRule) (uint32, error) {
	if index == noACL {
		index = f.next
		f.next++
		f.calls = append(f.calls, "create "+tag)
	} else {
		f.calls = append(f.calls, "replace "+tag)
	}
	f.acls[index] = fakeACL{tag, rules}
	return index, nil
}
func (f *fakeMeterVPP) deleteACL(index uint32) error {
	delete(f.acls, index)
	f.calls = append(f.calls, "delete")
	return nil
}
func (f *fakeMeterVPP) interfaceACLs(sw uint32) ([]uint32, []uint32, error) {
	return f.in[sw], f.out[sw], nil
}
func (f *fakeMeterVPP) attachACL(sw, index uint32, input, add bool) error {
	list := f.out
	if input {
		list = f.in
	}
	if add {
		list[sw] = append(list[sw], index)
	} else {
		list[sw] = slices.DeleteFunc(list[sw], func(i uint32) bool { return i == index })
	}
	return nil
}
func (f *fakeMeterVPP) countersEnabled() (bool, error) { return f.counters, nil }
func (f *fakeMeterVPP) enableCounters(on bool) error   { f.counters = on; return nil }
func (f *fakeMeterVPP) neighbors(uint32) ([]neighbor, error) {
	return f.neigh, nil
}
func (f *fakeMeterVPP) tapHosts() (map[uint32]string, error) { return f.taps, nil }

func meterSetup(t *testing.T) (*Meter, *fakeMeterVPP, *dhcpFixture) {
	t.Helper()
	f := newDHCPFixture(t)
	vpp := newFakeMeterVPP()
	vpp.neigh = []neighbor{
		{IP: netip.MustParseAddr("2001:db8:30::5"), MAC: "02:00:00:00:30:02"},
		{IP: netip.MustParseAddr("fe80::5"), MAC: "02:00:00:00:30:02"},
		{IP: netip.MustParseAddr("10.61.30.101"), MAC: "02:00:00:00:30:02"},
	}
	live := func() (*liveState, error) { return installerLive(), nil }
	// The fixture's LAN is 10.61.30.0/24 with gateway 10.61.30.1, which loop0 (index 3), the
	// BVI of bridge 1, holds; eth0 (index 1) is the bridge's only other member.
	m, err := NewMeter(MeterOptions{State: filepath.Join(f.dir, "meter-state.json"), Published: filepath.Join(f.dir, "run", "meter.json")}, vpp, f.d, live, "vpp-host")
	if err != nil {
		t.Fatal(err)
	}
	clock := dhcpNow
	m.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	return m, vpp, f
}

func published(t *testing.T, m *Meter) MeterStatus {
	t.Helper()
	var s MeterStatus
	if err := json.Unmarshal([]byte(read(t, m.opts.Published)), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMeterCountsEveryDeviceAddressAndCleansUp(t *testing.T) {
	m, vpp, f := meterSetup(t)
	m.Reconcile()
	if len(vpp.calls) != 0 || published(t, m).Enabled {
		t.Fatalf("off by default: %v", vpp.calls)
	}
	status, err := m.Set(true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// Static host .20, active leases .101 and .103 (not the expired .102), the neighbour's
	// global IPv6 address; not its link-local one.
	var addrs []string
	for _, r := range status.Rules {
		addrs = append(addrs, r.Address+"="+r.MAC)
	}
	want := []string{"10.61.30.20=02:00:00:00:30:01", "10.61.30.101=02:00:00:00:30:02", "10.61.30.103=02:00:00:00:30:04", "2001:db8:30::5=02:00:00:00:30:02"}
	if !slices.Equal(addrs, want) {
		t.Fatalf("rules %v", addrs)
	}
	// On the device port, as L2; the firewall's ACL on the gateway is left alone.
	if status.Interface != "eth0" || !slices.Equal(vpp.in[1], []uint32{status.ACLIn}) || !slices.Equal(vpp.out[1], []uint32{status.ACLOut}) ||
		!slices.Equal(vpp.in[3], []uint32{2}) || len(vpp.out[3]) != 0 {
		t.Fatalf("attached %+v in %v out %v", status, vpp.in, vpp.out)
	}
	in := vpp.acls[status.ACLIn].rules
	out := vpp.acls[status.ACLOut].rules
	offset := len(status.LocalPrefixes)
	if offset == 0 || len(in) != offset+6 || len(out) != offset+6 {
		t.Fatalf("unexpected ACL sizes in %d out %d local %v", len(in), len(out), status.LocalPrefixes)
	}
	if !slices.Contains(status.LocalPrefixes, netip.MustParsePrefix("10.61.30.0/24")) {
		t.Fatalf("LAN prefix not excluded: %v", status.LocalPrefixes)
	}
	for i, prefix := range status.LocalPrefixes {
		if in[i].DstPrefix.String() != prefix.String() || out[i].SrcPrefix.String() != prefix.String() ||
			in[i].SrcPrefix.Len != 0 || out[i].DstPrefix.Len != 0 ||
			in[i].IsPermit != acl_types.ACL_ACTION_API_PERMIT || out[i].IsPermit != acl_types.ACL_ACTION_API_PERMIT {
			t.Fatalf("local permit %s: input %+v output %+v", prefix, in[i], out[i])
		}
	}
	in, out = in[offset:], out[offset:]
	if in[0].SrcPrefix.String() != "10.61.30.20/32" || in[3].SrcPrefix.String() != "2001:db8:30::5/128" ||
		in[4].SrcPrefix.String() != "0.0.0.0/0" || in[5].SrcPrefix.String() != "::/0" {
		t.Fatalf("input rules %v", in)
	}
	if out[1].DstPrefix.String() != "10.61.30.101/32" || out[1].SrcPrefix.String() != "0.0.0.0/0" {
		t.Fatalf("output rules %v", out)
	}
	if !vpp.counters || published(t, m).Generation != status.Generation {
		t.Fatal("counters off or not published")
	}
	// Nothing changed: nothing is sent.
	vpp.calls = nil
	m.Reconcile()
	if len(vpp.calls) != 0 {
		t.Fatalf("calls %v", vpp.calls)
	}
	// A new lease replaces the rules in place, and the counters start over.
	write(t, f.leases, read(t, f.leases)+"0 02:00:00:00:30:09 10.61.30.109 cam *\n")
	m.Reconcile()
	again := m.Status()
	if !slices.Equal(vpp.calls, []string{"replace lan-meter-in", "replace lan-meter-out"}) || again.ACLIn != status.ACLIn ||
		again.Generation == status.Generation || len(again.Rules) != 5 {
		t.Fatalf("calls %v status %+v", vpp.calls, again)
	}
	// VPP restarted: the ACLs are gone, and their indexes were taken by someone else.
	firstIn := status.ACLIn
	vpp.acls = map[uint32]fakeACL{firstIn: {tag: "other"}}
	vpp.in, vpp.out, vpp.counters = map[uint32][]uint32{}, map[uint32][]uint32{}, false
	vpp.calls = nil
	m.Reconcile()
	after := m.Status()
	if !slices.Equal(vpp.calls, []string{"create lan-meter-in", "create lan-meter-out"}) || after.ACLIn == status.ACLIn ||
		vpp.acls[status.ACLIn].tag != "other" || !slices.Contains(vpp.in[1], after.ACLIn) || !vpp.counters {
		t.Fatalf("not remade: %v %+v %v", vpp.calls, after, vpp.in)
	}
	// Off: detached, deleted, and the counters back off as they were before.
	status, err = m.Set(false, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if status.Enabled || len(vpp.in[1]) != 0 || len(vpp.out[1]) != 0 || vpp.counters {
		t.Fatalf("not cleaned: %+v in %v out %v counters %v", status, vpp.in, vpp.out, vpp.counters)
	}
	if len(vpp.acls) != 1 || vpp.acls[firstIn].tag != "other" {
		t.Fatalf("our ACLs left, or someone else's touched: %v", vpp.acls)
	}
	// The state survives a restart of the service.
	if state := read(t, m.opts.State); !strings.Contains(state, `"enabled": false`) {
		t.Fatalf("state %s", state)
	}
}

func TestMeterLeavesCountersOnWhenTheyWereOn(t *testing.T) {
	m, vpp, _ := meterSetup(t)
	vpp.counters = true
	if _, err := m.Set(true, "admin"); err != nil {
		t.Fatal(err)
	}
	// A restart of this service finds the meter on, from its state file.
	again, err := NewMeter(m.opts, vpp, m.dhcp, m.live, m.hostTap)
	if err != nil || !again.st.Enabled || again.st.CountersBefore == nil || !*again.st.CountersBefore {
		t.Fatalf("state %+v %v", again.st, err)
	}
	if _, err := again.Set(false, "admin"); err != nil {
		t.Fatal(err)
	}
	if !vpp.counters {
		t.Fatal("turned off counters that were on before")
	}
}

func TestMeterWithoutTheGatewayInterface(t *testing.T) {
	m, _, _ := meterSetup(t)
	m.live = func() (*liveState, error) { return &liveState{}, nil }
	if _, err := m.Set(true, "admin"); err == nil || !strings.Contains(err.Error(), "10.61.30.1") {
		t.Fatal(err)
	}
	if s := published(t, m); !s.Enabled || s.Error == "" {
		t.Fatalf("published %+v", s)
	}
	os.Remove(m.opts.Published)
}

func TestMeterPortsAreTheBridgeMembersFacingDevices(t *testing.T) {
	m, vpp, _ := meterSetup(t)
	live := installerLive()
	live.Interfaces = append(live.Interfaces,
		&liveInterface{Index: 7, Name: "tap0", Bridge: 1}, &liveInterface{Index: 8, Name: "tap5", Bridge: 1},
		&liveInterface{Index: 9, Name: "lan1", Bridge: 2})
	vpp.taps = map[uint32]string{7: "vpp-host", 8: "vm1"}
	m.live = func() (*liveState, error) { return live, nil }
	status, err := m.Set(true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// eth0 and the VM's TAP, not the TAP to Linux, the BVI or another bridge's port.
	if status.Interface != "eth0, tap5" || len(vpp.in[7]) != 0 || len(vpp.in[9]) != 0 || !slices.Equal(vpp.in[8], []uint32{status.ACLIn}) {
		t.Fatalf("ports %q in %v", status.Interface, vpp.in)
	}
	// The VM's TAP leaves the bridge: the ACLs come off it.
	live.Interfaces[len(live.Interfaces)-2].Bridge = 0
	m.Reconcile()
	if len(vpp.in[8]) != 0 || len(vpp.out[8]) != 0 || m.Status().Interface != "eth0" {
		t.Fatalf("left on a former port: %v %v", vpp.in, m.Status().Interface)
	}
}

func TestMeterMovesOffTheGatewayAfterAnUpgrade(t *testing.T) {
	m, vpp, f := meterSetup(t)
	// The state an earlier version left: ACLs 20 and 21 on loop0.
	vpp.acls[20], vpp.acls[21] = fakeACL{tag: meterTagIn}, fakeACL{tag: meterTagOut}
	vpp.in[3], vpp.out[3] = []uint32{2, 20}, []uint32{21}
	write(t, m.opts.State, `{"enabled":true,"acl_in":20,"acl_out":21,"interface":3,"attached":true}`)
	again, err := NewMeter(m.opts, vpp, f.d, m.live, "vpp-host")
	if err != nil {
		t.Fatal(err)
	}
	again.Reconcile()
	if !slices.Equal(vpp.in[3], []uint32{2}) || len(vpp.out[3]) != 0 || !slices.Equal(vpp.in[1], []uint32{20}) || again.Status().Error != "" {
		t.Fatalf("in %v out %v status %+v", vpp.in, vpp.out, again.Status())
	}
}

func TestMeterWithoutABridgeUsesTheGatewayInterface(t *testing.T) {
	m, vpp, _ := meterSetup(t)
	live := installerLive()
	for _, iface := range live.Interfaces {
		if iface.Name == "loop0" {
			iface.BVI, iface.Bridge = false, 0
		}
	}
	m.live = func() (*liveState, error) { return live, nil }
	if status, err := m.Set(true, "admin"); err != nil || status.Interface != "loop0" || !slices.Contains(vpp.in[3], status.ACLIn) {
		t.Fatalf("%v %+v %v", err, status, vpp.in)
	}
}
