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
func (f *fakeMeterVPP) enableCounters(on bool) error  { f.counters = on; return nil }
func (f *fakeMeterVPP) neighbors(uint32) ([]neighbor, error) {
	return f.neigh, nil
}

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
	// The fixture's LAN is 10.61.30.0/24 with gateway 10.61.30.1, which loop0 (index 3) holds.
	m, err := NewMeter(MeterOptions{State: filepath.Join(f.dir, "meter-state.json"), Published: filepath.Join(f.dir, "run", "meter.json")}, vpp, f.d, live)
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
	if status.Interface != "loop0" || !slices.Equal(vpp.in[3], []uint32{2, status.ACLIn}) || !slices.Equal(vpp.out[3], []uint32{status.ACLOut}) {
		t.Fatalf("attached %+v in %v out %v", status, vpp.in[3], vpp.out[3])
	}
	in := vpp.acls[status.ACLIn].rules
	if len(in) != 6 || in[0].SrcPrefix.String() != "10.61.30.20/32" || in[3].SrcPrefix.String() != "2001:db8:30::5/128" ||
		in[4].SrcPrefix.String() != "0.0.0.0/0" || in[5].SrcPrefix.String() != "::/0" {
		t.Fatalf("input rules %v", in)
	}
	if out := vpp.acls[status.ACLOut].rules; out[1].DstPrefix.String() != "10.61.30.101/32" || out[1].SrcPrefix.String() != "0.0.0.0/0" {
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
		vpp.acls[status.ACLIn].tag != "other" || !slices.Contains(vpp.in[3], after.ACLIn) || !vpp.counters {
		t.Fatalf("not remade: %v %+v %v", vpp.calls, after, vpp.in)
	}
	// Off: detached, deleted, and the counters back off as they were before.
	status, err = m.Set(false, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if status.Enabled || len(vpp.in[3]) != 0 || len(vpp.out[3]) != 0 || vpp.counters {
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
	again, err := NewMeter(m.opts, vpp, m.dhcp, m.live)
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
