package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.fd.io/govpp/binapi/acl_types"
	"go.fd.io/govpp/binapi/ip_types"
)

// fakeVPP keeps what VPP would, with its quirks: a mapping on an interface shows twice once
// the interface has an address, and an applied ACL cannot be deleted.
type fakeVPP struct {
	ifaces   []iface
	outside  []uint32
	mappings []mapping
	acls     []aclEntry
	lists    map[uint32]aclList
	nextACL  uint32
	calls    int
	failAdd  func(m mapping) bool
	noACL    bool
	// reads counts readings, staticReads those that dumped the static mappings.
	reads, staticReads int
}

func newFake() *fakeVPP {
	return &fakeVPP{
		ifaces: []iface{
			{Index: 1, Name: "loop0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.61.30.1/24"), netip.MustParsePrefix("2001:db8:73::1/64")}},
			{Index: 2, Name: "port0.100", Addrs: []netip.Prefix{netip.MustParsePrefix("10.61.10.3/24"), netip.MustParsePrefix("2001:db8:70::23/64"), netip.MustParsePrefix("fe80::1/64")}},
			{Index: 3, Name: "wg100", Addrs: []netip.Prefix{netip.MustParsePrefix("10.62.10.1/24")}},
		},
		outside: []uint32{2},
		lists:   map[uint32]aclList{},
	}
}

// wireguard adds an identity mapping the way vpp-wireguard's CLI does: no tag.
func (f *fakeVPP) wireguard(port uint16) {
	f.add(mapping{Identity: true, Proto: protoUDP, ExternalPort: port, ExternalIf: 2})
}

func (f *fakeVPP) wan4(index uint32) (netip.Addr, bool) {
	for _, in := range f.ifaces {
		if in.Index == index {
			for _, a := range in.Addrs {
				if a.Addr().Is4() {
					return a.Addr(), true
				}
			}
		}
	}
	return netip.Addr{}, false
}

func (f *fakeVPP) add(m mapping) {
	f.mappings = append(f.mappings, m)
	if addr, ok := f.wan4(m.ExternalIf); ok {
		resolved := m
		resolved.ExternalIf, resolved.ExternalIP = noIndex, addr
		f.mappings = append(f.mappings, resolved)
	}
}

func (f *fakeVPP) Read(all, statics bool, wanted func(string, bool) bool) (*vppState, error) {
	f.reads++
	if statics {
		f.staticReads++
	}
	st := &vppState{NAT: true, ACL: !f.noACL, NATOutside: slices.Clone(f.outside), Statics: statics, Lists: map[uint32]aclList{}}
	for _, m := range f.mappings {
		if statics || m.Identity {
			st.Mappings = append(st.Mappings, m)
		}
	}
	for _, in := range f.ifaces {
		copy := iface{Index: in.Index, Name: in.Name}
		if all || wanted(in.Name, slices.Contains(f.outside, in.Index)) {
			copy.Addrs = slices.Clone(in.Addrs)
		}
		st.Interfaces = append(st.Interfaces, copy)
	}
	for _, a := range f.acls {
		st.ACLs = append(st.ACLs, aclEntry{a.Index, a.Tag, slices.Clone(a.Rules)})
	}
	for k, v := range f.lists {
		st.Lists[k] = aclList{slices.Clone(v.Input), slices.Clone(v.Output)}
	}
	return st, nil
}

func (f *fakeVPP) Mapping(m mapping, add bool) error {
	f.calls++
	if add {
		if f.failAdd != nil && f.failAdd(m) {
			return errors.New("VPP refused")
		}
		for _, have := range f.mappings {
			if have.ExternalIf == m.ExternalIf && have.Proto == m.Proto && have.ExternalPort == m.ExternalPort && have.ExternalIf != noIndex {
				return errors.New("exists")
			}
		}
		f.add(m)
		return nil
	}
	n := len(f.mappings)
	addr, _ := f.wan4(m.ExternalIf)
	f.mappings = slices.DeleteFunc(f.mappings, func(h mapping) bool {
		same := h.Identity == m.Identity && h.Proto == m.Proto && h.ExternalPort == m.ExternalPort && h.LocalIP == m.LocalIP && h.LocalPort == m.LocalPort
		return same && (h.ExternalIf == m.ExternalIf || (h.ExternalIf == noIndex && h.ExternalIP == addr))
	})
	if n == len(f.mappings) {
		return errors.New("no such mapping")
	}
	return nil
}

func (f *fakeVPP) ReplaceACL(index uint32, tag string, rules []acl_types.ACLRule) (uint32, error) {
	f.calls++
	if index == noIndex {
		index = f.nextACL
		f.nextACL++
		f.acls = append(f.acls, aclEntry{index, tag, slices.Clone(rules)})
		return index, nil
	}
	for i := range f.acls {
		if f.acls[i].Index == index {
			f.acls[i].Tag, f.acls[i].Rules = tag, slices.Clone(rules)
			return index, nil
		}
	}
	return 0, errors.New("no such ACL")
}

func (f *fakeVPP) DeleteACL(index uint32) error {
	f.calls++
	for _, l := range f.lists {
		if slices.Contains(l.Input, index) || slices.Contains(l.Output, index) {
			return errors.New("ACL in use")
		}
	}
	f.acls = slices.DeleteFunc(f.acls, func(a aclEntry) bool { return a.Index == index })
	return nil
}

func (f *fakeVPP) SetACLList(sw uint32, list aclList) error {
	f.calls++
	if len(list.Input)+len(list.Output) == 0 {
		delete(f.lists, sw)
	} else {
		f.lists[sw] = list
	}
	return nil
}

func (f *fakeVPP) Close() {}

// restart is VPP starting again: it keeps nothing of what was added at run time.
func (f *fakeVPP) restart() {
	f.mappings, f.acls, f.lists, f.nextACL = nil, nil, map[uint32]aclList{}, 0
}

func (f *fakeVPP) aclByTag(tag string) *aclEntry {
	for i := range f.acls {
		if f.acls[i].Tag == tag {
			return &f.acls[i]
		}
	}
	return nil
}

func (f *fakeVPP) ours() []mapping {
	var out []mapping
	for _, m := range f.mappings {
		if m.Tag == natTag && m.ExternalIf != noIndex {
			out = append(out, m)
		}
	}
	return out
}

func newTestService(t *testing.T, f *fakeVPP) *Service {
	t.Helper()
	path := filepath.Join(t.TempDir(), "firewall.json")
	s, err := NewService(Options{ConfigFile: path, APISocket: "api.sock", VPPUnit: "vpp-router.service"}, func() (vppAPI, error) { return f, nil })
	if err != nil {
		t.Fatal(err)
	}
	s.stamp = func(string) (fileStamp, error) { return fileStamp{Ino: 1, Ctime: 1}, nil }
	s.unitActive = func(string) bool { return true }
	return s
}

func savedConfig(t *testing.T, s *Service) *Config {
	t.Helper()
	cfg, err := loadConfig(s.opts.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestForwardAddsTaggedMappingsAndDeletes(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	state, err := s.AddForward(Forward{Name: "web", Protocol: "both", ExternalPort: 8080, InternalIP: "10.61.30.10", InternalPort: 80}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	ours := f.ours()
	if len(ours) != 2 || ours[0].Proto != protoTCP || ours[1].Proto != protoUDP || ours[0].ExternalIf != 2 || ours[0].LocalPort != 80 || ours[0].LocalIP != netip.MustParseAddr("10.61.30.10") {
		t.Fatalf("mappings %+v", ours)
	}
	if len(state.Forwards) != 1 || state.Forwards[0].Interface != "port0.100" || state.Forwards[0].ID == 0 {
		t.Fatalf("state %+v", state.Forwards)
	}
	if cfg := savedConfig(t, s); len(cfg.Forwards) != 1 {
		t.Fatalf("saved %+v", cfg)
	}
	if _, err := s.Delete(state.Forwards[0].ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(f.mappings) != 0 {
		t.Fatalf("left %+v", f.mappings)
	}
}

func TestForwardRange(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	if _, err := s.AddForward(Forward{Protocol: "udp", ExternalPort: 5000, LastPort: 5003, InternalIP: "10.61.30.10", InternalPort: 6000}, "admin"); err != nil {
		t.Fatal(err)
	}
	ours := f.ours()
	if len(ours) != 4 || ours[3].ExternalPort != 5003 || ours[3].LocalPort != 6003 {
		t.Fatalf("mappings %+v", ours)
	}
	if _, err := s.AddForward(Forward{Protocol: "udp", ExternalPort: 10000, LastPort: 10000 + rangeLimit, InternalIP: "10.61.30.10"}, "admin"); err == nil {
		t.Fatalf("a range of %d ports was accepted", rangeLimit+1)
	}
}

func TestLargeRangesAndTheMappingLimit(t *testing.T) {
	f := newFake()
	// coturn's relay range, added by host-path: a thousand mappings someone else owns.
	for port := uint16(49152); port <= 50151; port++ {
		f.add(mapping{Proto: protoUDP, ExternalPort: port, ExternalIf: 2, LocalIP: netip.MustParseAddr("10.61.30.2"), LocalPort: port, Tag: "host-path"})
	}
	s := newTestService(t, f)
	state, err := s.AddForward(Forward{Protocol: "both", ExternalPort: 10000, LastPort: 10000 + rangeLimit - 1, InternalIP: "10.61.30.10"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(f.ours()); n != 2*rangeLimit {
		t.Fatalf("%d mappings, want %d", n, 2*rangeLimit)
	}
	// Adding one more forward adds only its own ports.
	calls := f.calls
	if state, err = s.AddForward(Forward{Protocol: "both", ExternalPort: 20000, LastPort: 20000 + rangeLimit - 1, InternalIP: "10.61.30.11"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if f.calls-calls != 2*rangeLimit {
		t.Fatalf("a second forward made %d calls, want %d", f.calls-calls, 2*rangeLimit)
	}
	// The two fill the limit.
	if _, err := s.AddPort(Port{Protocol: "udp", Port: 30000}, "admin"); err == nil || !strings.Contains(err.Error(), "最多") {
		t.Fatalf("a mapping over the limit: %v", err)
	}
	// A range over someone else's ports names the first one taken.
	if _, err := s.Delete(state.Forwards[1].ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddForward(Forward{Protocol: "udp", ExternalPort: 49000, LastPort: 49999, InternalIP: "10.61.30.12"}, "admin"); err == nil || !strings.Contains(err.Error(), "49152") {
		t.Fatalf("a range over coturn's: %v", err)
	}
	// The page shows coturn's thousand mappings as one row.
	var others []ForwardView
	for _, fw := range s.State().Forwards {
		if fw.Other {
			others = append(others, fw)
		}
	}
	if len(others) != 1 || others[0].ExternalPort != 49152 || others[0].LastPort != 50151 || others[0].InternalPort != 49152 || others[0].Name != "host-path" {
		t.Fatalf("others %+v", others)
	}
}

func TestOthersRowsJoinOnlyConsecutive(t *testing.T) {
	f := newFake()
	host := netip.MustParseAddr("10.61.30.2")
	for _, m := range []mapping{
		{Proto: protoTCP, ExternalPort: 100, LocalPort: 200},
		{Proto: protoTCP, ExternalPort: 101, LocalPort: 201},
		{Proto: protoTCP, ExternalPort: 102, LocalPort: 300}, // another inside port: not part of the run
		{Proto: protoUDP, ExternalPort: 103, LocalPort: 301}, // another protocol
		{Proto: protoTCP, ExternalPort: 105, LocalPort: 303}, // a gap
	} {
		m.ExternalIf, m.LocalIP = 2, host
		f.add(m)
	}
	f.wireguard(51820)
	f.wireguard(51821)
	s := newTestService(t, f)
	state := s.State()
	var got []string
	for _, fw := range state.Forwards {
		got = append(got, fmt.Sprintf("%s %d-%d→%d", fw.Protocol, fw.ExternalPort, fw.LastPort, fw.InternalPort))
	}
	want := []string{"tcp 100-101→200", "tcp 102-0→300", "tcp 105-0→303", "udp 103-0→301"}
	if !slices.Equal(got, want) {
		t.Fatalf("forwards %v, want %v", got, want)
	}
	if len(state.Ports) != 1 || state.Ports[0].Port.Port != 51820 || state.Ports[0].LastPort != 51821 {
		t.Fatalf("ports %+v", state.Ports)
	}
}

func TestPeriodicCheckAndPageSkipStaticDumps(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	if _, err := s.AddForward(Forward{Protocol: "both", ExternalPort: 20000, LastPort: 21023, InternalIP: "10.61.30.10"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetPing(false, "admin"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.applied = fileStamp{Ino: 1, Ctime: 1}
	s.mu.Unlock()
	// The periodic check: no static dump, nothing re-added, the ACL kept up.
	reads, statics, calls := f.reads, f.staticReads, f.calls
	now = now.Add(checkEvery)
	s.tick(now)
	if f.reads == reads || f.staticReads != statics || f.calls != calls {
		t.Fatalf("check: %d reads, %d static dumps, %d calls", f.reads-reads, f.staticReads-statics, f.calls-calls)
	}
	// A mapping someone removed by hand is not put back by it either; a VPP restart does that.
	f.mappings = f.mappings[2:]
	now = now.Add(checkEvery)
	s.tick(now)
	if f.calls != calls {
		t.Fatalf("the check touched static mappings: %d calls", f.calls-calls)
	}

	// The page reuses the static mappings of the change for a minute.
	statics = f.staticReads
	state := s.State()
	if f.staticReads != statics || len(state.Forwards) != 1 {
		t.Fatalf("page: %d static dumps, forwards %+v", f.staticReads-statics, state.Forwards)
	}
	f.add(mapping{Proto: protoTCP, ExternalPort: 2222, ExternalIf: 2, LocalIP: netip.MustParseAddr("10.61.30.2"), LocalPort: 22})
	if state = s.State(); len(state.Forwards) != 1 {
		t.Fatalf("a new mapping of someone else's showed before the minute: %+v", state.Forwards)
	}
	now = now.Add(staticsEvery)
	if state = s.State(); f.staticReads != statics+1 || len(state.Forwards) != 2 {
		t.Fatalf("after a minute: %d static dumps, forwards %+v", f.staticReads-statics, state.Forwards)
	}
	// A VPP restart reads them again at once.
	s.stamp = func(string) (fileStamp, error) { return fileStamp{Ino: 2, Ctime: 2}, nil }
	if s.State(); f.staticReads != statics+2 {
		t.Fatalf("after a VPP restart: %d static dumps", f.staticReads-statics)
	}
}

func TestRefusedRangeIsOneMessage(t *testing.T) {
	f := newFake()
	f.failAdd = func(m mapping) bool { return m.ExternalPort >= 5010 }
	s := newTestService(t, f)
	_, err := s.AddForward(Forward{Protocol: "udp", ExternalPort: 5000, LastPort: 5099, InternalIP: "10.61.30.10"}, "admin")
	if err == nil || strings.Count(err.Error(), "VPP refused") != 1 || !strings.Contains(err.Error(), "共 90 个") {
		t.Fatalf("error %v", err)
	}
	if len(f.mappings) != 0 {
		t.Fatalf("%d mappings left after a refused range", len(f.mappings))
	}
}

func TestRouterPortRangeIsOneIPv6Rule(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	if _, err := s.AddPort(Port{Protocol: "udp", Port: 40000, LastPort: 40999}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetIPv6Firewall(true, "admin"); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range f.aclByTag(aclInTag).Rules {
		if r.Proto == protoUDP && r.DstPrefix.Len == 128 && r.DstportOrIcmpcodeFirst >= 40000 && r.DstportOrIcmpcodeLast <= 40999 {
			n++
			if r.DstportOrIcmpcodeFirst != 40000 || r.DstportOrIcmpcodeLast != 40999 {
				t.Fatalf("rule %+v", r)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d IPv6 rules for one range", n)
	}
}

func TestForwardValidation(t *testing.T) {
	f := newFake()
	f.wireguard(11111)
	s := newTestService(t, f)
	for _, tc := range []struct {
		forward Forward
		want    string
	}{
		{Forward{Protocol: "udp", ExternalPort: 11111, InternalIP: "10.61.30.10"}, "其他程序"},
		{Forward{Protocol: "tcp", ExternalPort: 80, InternalIP: "10.9.9.9"}, "不在"},
		{Forward{Protocol: "tcp", ExternalPort: 80, InternalIP: "10.61.30.1"}, "VPP 自己"},
		{Forward{Protocol: "tcp", ExternalPort: 80, InternalIP: "10.61.30.255"}, "广播"},
		{Forward{Protocol: "tcp", ExternalPort: 80, InternalIP: "10.61.10.50"}, "不在"},
		{Forward{Protocol: "tcp", ExternalPort: 80, InternalIP: "2001:db8:73::5"}, "IPv4"},
		{Forward{Protocol: "icmp", ExternalPort: 80, InternalIP: "10.61.30.10"}, "协议"},
		{Forward{Protocol: "tcp", ExternalPort: 70000, InternalIP: "10.61.30.10"}, "端口"},
		{Forward{Protocol: "tcp", Interface: "loop0", ExternalPort: 80, InternalIP: "10.61.30.10"}, "不是 WAN"},
	} {
		if _, err := s.AddForward(tc.forward, "admin"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: got %v, want %q", tc.forward, err, tc.want)
		}
	}
	// One inside address and port, one forward.
	if _, err := s.AddForward(Forward{Protocol: "tcp", ExternalPort: 81, InternalIP: "10.61.30.20", InternalPort: 80}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddForward(Forward{Protocol: "both", ExternalPort: 82, InternalIP: "10.61.30.20", InternalPort: 80}, "admin"); err == nil || !strings.Contains(err.Error(), "只能转发一次") {
		t.Fatalf("second forward to one inside port: %v", err)
	}
	// Forwarding to a host behind a tunnel is fine.
	if _, err := s.AddForward(Forward{Protocol: "tcp", ExternalPort: 80, InternalIP: "10.62.10.5"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPort(Port{Protocol: "both", Port: 80}, "admin"); err == nil || !strings.Contains(err.Error(), "转发") {
		t.Fatalf("router port on a forwarded port: %v", err)
	}
}

func TestOverrideWANWithoutNAT(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	s.cfg.WANInterfaces = []string{"port0.100", "wg100"}
	if _, err := s.AddPort(Port{Protocol: "udp", Interface: "wg100", Port: 51820}, "admin"); err == nil || !strings.Contains(err.Error(), "NAT 出口") {
		t.Fatalf("router port on a WAN without NAT: %v", err)
	}
	// The IPv6 firewall still covers it.
	if _, err := s.SetIPv6Firewall(true, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.lists[3].Input, f.aclByTag(aclInTag).Index) {
		t.Fatalf("lists %+v", f.lists)
	}
}

func TestOthersMappingsShownReadOnly(t *testing.T) {
	f := newFake()
	f.wireguard(11111)
	f.add(mapping{Proto: protoTCP, ExternalPort: 2222, ExternalIf: 2, LocalIP: netip.MustParseAddr("10.61.30.2"), LocalPort: 22})
	s := newTestService(t, f)
	state := s.State()
	if len(state.Ports) != 1 || !state.Ports[0].Other || state.Ports[0].Port.Port != 11111 || state.Ports[0].Interface != "port0.100" {
		t.Fatalf("ports %+v", state.Ports)
	}
	if len(state.Forwards) != 1 || !state.Forwards[0].Other || state.Forwards[0].InternalPort != 22 {
		t.Fatalf("forwards %+v", state.Forwards)
	}
	if len(state.Networks) != 2 || state.Networks[0].Prefix != "10.61.30.0/24" {
		t.Fatalf("networks %+v", state.Networks)
	}
}

func hasRule(rules []acl_types.ACLRule, match func(acl_types.ACLRule) bool) int {
	for i, r := range rules {
		if match(r) {
			return i
		}
	}
	return -1
}

func is6(p ip_types.Prefix) bool { return p.Address.Af == ip_types.ADDRESS_IP6 }

func TestIPv6FirewallACLs(t *testing.T) {
	f := newFake()
	f.wireguard(11111)
	// Someone else's ACL on the WAN stays, ahead of ours.
	f.acls = append(f.acls, aclEntry{Index: 0, Tag: "other", Rules: []acl_types.ACLRule{anyRule(acl_types.ACL_ACTION_API_PERMIT, false)}})
	f.nextACL = 1
	f.lists[2] = aclList{Input: []uint32{0}}
	s := newTestService(t, f)
	if _, err := s.AddIPv6Rule(IPv6Rule{Protocol: "tcp", Address: "2001:db8:73::10", Port: 443}, "admin"); err != nil {
		t.Fatal(err)
	}
	if f.aclByTag(aclInTag) != nil {
		t.Fatal("an IPv6 rule alone applied an ACL")
	}
	state, err := s.SetIPv6Firewall(true, "admin")
	if err != nil {
		t.Fatal(err)
	}
	in, out := f.aclByTag(aclInTag), f.aclByTag(aclOutTag)
	if in == nil || out == nil || !state.ACLApplied {
		t.Fatalf("acls %+v", f.acls)
	}
	if l := f.lists[2]; !slices.Equal(l.Input, []uint32{0, in.Index}) || !slices.Equal(l.Output, []uint32{out.Index}) {
		t.Fatalf("WAN list %+v", l)
	}
	if _, ok := f.lists[1]; ok {
		t.Fatal("ACL applied on the LAN")
	}
	rules := in.Rules
	last := rules[len(rules)-1]
	if last.IsPermit != acl_types.ACL_ACTION_API_DENY || !is6(last.DstPrefix) || last.DstPrefix.Len != 0 {
		t.Fatalf("last rule %+v", last)
	}
	if i := hasRule(rules, func(r acl_types.ACLRule) bool {
		return !is6(r.SrcPrefix) && r.IsPermit == acl_types.ACL_ACTION_API_PERMIT && r.Proto == 0
	}); i < 0 {
		t.Fatal("IPv4 is not passed to NAT")
	}
	wgRule := hasRule(rules, func(r acl_types.ACLRule) bool {
		return r.Proto == protoUDP && r.DstportOrIcmpcodeFirst == 11111 && r.DstPrefix.Len == 128 &&
			netip.AddrFrom16(r.DstPrefix.Address.Un.GetIP6()) == netip.MustParseAddr("2001:db8:70::23")
	})
	if wgRule < 0 {
		t.Fatal("WireGuard's port is not open on the WAN's IPv6 address")
	}
	if hasRule(rules, func(r acl_types.ACLRule) bool {
		return r.DstPrefix.Len == 128 && netip.AddrFrom16(r.DstPrefix.Address.Un.GetIP6()).IsLinkLocalUnicast()
	}) >= 0 {
		t.Fatal("a port is open on a link-local address")
	}
	if hasRule(rules, func(r acl_types.ACLRule) bool { return r.Proto == protoTCP && r.DstportOrIcmpcodeFirst == 443 }) < 0 {
		t.Fatal("the IPv6 rule is missing")
	}
	for _, typ := range []uint16{135, 136, 128} {
		if hasRule(rules, func(r acl_types.ACLRule) bool {
			return r.Proto == protoICMPv6 && r.IsPermit == acl_types.ACL_ACTION_API_PERMIT && r.SrcportOrIcmptypeFirst <= typ && typ <= r.SrcportOrIcmptypeLast
		}) < 0 {
			t.Fatalf("ICMPv6 type %d is not let in", typ)
		}
	}
	if out.Rules[1].IsPermit != acl_types.ACL_ACTION_API_PERMIT_REFLECT || !is6(out.Rules[1].SrcPrefix) {
		t.Fatalf("outbound %+v", out.Rules)
	}

	// Nothing changes, nothing is written.
	calls := f.calls
	s.mu.Lock()
	if err := s.reconcileNow(false); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	if f.calls != calls {
		t.Fatalf("a reconcile with nothing to do made %d calls", f.calls-calls)
	}

	if _, err := s.SetIPv6Firewall(false, "admin"); err != nil {
		t.Fatal(err)
	}
	if f.aclByTag(aclInTag) != nil || f.aclByTag(aclOutTag) != nil || !slices.Equal(f.lists[2].Input, []uint32{0}) {
		t.Fatalf("after turning off: acls %+v lists %+v", f.acls, f.lists)
	}
}

func TestBlockPingAlone(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	if _, err := s.SetPing(false, "admin"); err != nil {
		t.Fatal(err)
	}
	in := f.aclByTag(aclInTag)
	if in == nil || f.aclByTag(aclOutTag) != nil {
		t.Fatalf("acls %+v", f.acls)
	}
	r := in.Rules
	if len(r) != 4 || r[0].IsPermit != acl_types.ACL_ACTION_API_DENY || r[0].Proto != protoICMP || r[0].SrcportOrIcmptypeFirst != 8 ||
		r[1].Proto != protoICMPv6 || r[1].SrcportOrIcmptypeFirst != 128 || r[3].IsPermit != acl_types.ACL_ACTION_API_PERMIT || !is6(r[3].SrcPrefix) {
		t.Fatalf("rules %+v", r)
	}
	if _, err := s.SetPing(false, "admin"); err == nil {
		t.Fatal("an unchanged setting was accepted")
	}
	if _, err := s.SetPing(true, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(f.acls) != 0 || len(f.lists) != 0 {
		t.Fatalf("left %+v %+v", f.acls, f.lists)
	}
}

func TestNoACLPlugin(t *testing.T) {
	f := newFake()
	f.noACL = true
	s := newTestService(t, f)
	if _, err := s.SetIPv6Firewall(true, "admin"); err == nil || !strings.Contains(err.Error(), "acl") {
		t.Fatalf("got %v", err)
	}
}

func TestRestoreAfterVPPRestart(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	if _, err := s.AddForward(Forward{Protocol: "tcp", ExternalPort: 8080, InternalIP: "10.61.30.10", InternalPort: 80}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPort(Port{Protocol: "udp", Port: 51820}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetIPv6Firewall(true, "admin"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	s.tick(now) // records the run
	f.restart()
	s.stamp = func(string) (fileStamp, error) { return fileStamp{Ino: 2, Ctime: 2}, nil }
	active := false
	s.unitActive = func(string) bool { return active }
	s.tick(now.Add(2 * time.Second))
	if len(f.mappings) != 0 {
		t.Fatal("restored before VPP's unit was active")
	}
	active = true
	s.tick(now.Add(4 * time.Second))
	if len(f.ours()) != 2 || f.aclByTag(aclInTag) == nil || len(f.lists[2].Input) != 1 {
		t.Fatalf("after restart: mappings %+v acls %+v", f.mappings, f.acls)
	}
	// The ACL opens the router port on IPv6 too.
	if hasRule(f.aclByTag(aclInTag).Rules, func(r acl_types.ACLRule) bool { return r.DstportOrIcmpcodeFirst == 51820 }) < 0 {
		t.Fatal("router port is not open on IPv6")
	}
}

func TestWANAddressChangeRebuildsACL(t *testing.T) {
	f := newFake()
	f.wireguard(11111)
	s := newTestService(t, f)
	if _, err := s.SetIPv6Firewall(true, "admin"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	s.tick(now)
	f.ifaces[1].Addrs[1] = netip.MustParsePrefix("2001:db8:99::23/64")
	s.tick(now.Add(2 * time.Second))
	newAddr := func() bool {
		return hasRule(f.aclByTag(aclInTag).Rules, func(r acl_types.ACLRule) bool {
			return r.DstPrefix.Len == 128 && netip.AddrFrom16(r.DstPrefix.Address.Un.GetIP6()) == netip.MustParseAddr("2001:db8:99::23")
		}) >= 0
	}
	if newAddr() {
		t.Fatal("checked again before checkEvery")
	}
	s.tick(now.Add(checkEvery + time.Second))
	if !newAddr() {
		t.Fatal("ACL does not follow the WAN's new address")
	}
}

func TestFailedChangeIsUndone(t *testing.T) {
	f := newFake()
	f.failAdd = func(m mapping) bool { return m.Proto == protoUDP }
	s := newTestService(t, f)
	if _, err := s.AddForward(Forward{Protocol: "both", ExternalPort: 8080, InternalIP: "10.61.30.10"}, "admin"); err == nil {
		t.Fatal("a refused mapping was reported as applied")
	}
	if len(f.mappings) != 0 {
		t.Fatalf("half a change left in VPP: %+v", f.mappings)
	}
	if _, err := os.Stat(s.opts.ConfigFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed change was written")
	}
}

func TestConfigSurvivesServiceRestart(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	if _, err := s.AddIPv6Rule(IPv6Rule{Protocol: "any", Address: "2001:db8:73::/64", Port: 99}, "admin"); err != nil {
		t.Fatal(err)
	}
	again, err := NewService(s.opts, s.dial)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.cfg.IPv6Rules) != 1 || again.cfg.IPv6Rules[0].Port != 0 || again.cfg.NextID <= again.cfg.IPv6Rules[0].ID {
		t.Fatalf("reloaded %+v", again.cfg)
	}
}

func TestHandler(t *testing.T) {
	f := newFake()
	s := newTestService(t, f)
	handler := s.Handler()
	post := func(path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("X-Panel-User", "admin")
		handler.ServeHTTP(w, r)
		return w
	}
	if w := post("/firewall/forward", `{"protocol":"tcp","external_port":443,"internal_ip":"10.61.30.10"}`); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := post("/firewall/forward", `{"protocol":"tcp","external_port":443,"internal_ip":"10.61.30.11"}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "443") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := post("/firewall/ping", `not json`); w.Code != http.StatusBadRequest {
		t.Fatalf("%d", w.Code)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/firewall", nil))
	var state State
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil || len(state.Forwards) != 1 || state.Forwards[0].InternalPort != 443 || !state.AllowPing {
		t.Fatalf("%v %s", err, w.Body)
	}
}
