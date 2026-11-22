package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"go.fd.io/govpp/binapi/acl_types"
	"go.fd.io/govpp/binapi/ip_types"
)

// The LAN meter counts each device's traffic where all of it passes: the ports the devices
// are on, which are the members of the LAN bridge other than its BVI and the TAP to Linux.
// Not the gateway interface: a proxy on Linux answers devices through that TAP, bridged
// past the gateway, and another ACL on the gateway (the firewall's) would match first. Two
// ACLs on each port permit everything. Rules for local peers come first, then one rule per
// device address: as L2 input by source (upload), as L2 output by destination (download). VPP
// counts bytes per rule in the stats segment, which vpp-monitor reads without stopping the
// workers. Without a bridge the gateway interface itself is used.
//
// Each packet on those ports costs an ACL lookup: on the R6S's little core, saturated with
// 64-byte packets, 1–2.5% of forwarding with the rules alone and 3–5% with the counters,
// however many devices (it is a hash lookup), so it is a switch, off by default.

const (
	meterTagIn  = "lan-meter-in"
	meterTagOut = "lan-meter-out"
	noACL       = ^uint32(0)
	meterEvery  = time.Minute
)

// MeterOptions configures the LAN meter.
type MeterOptions struct {
	State     string // whether it is on, and what it changed, kept across restarts
	Published string // the rules in order, for vpp-monitor
}

// meterState is kept in MeterOptions.State.
type meterState struct {
	Enabled bool `json:"enabled"`
	// CountersBefore is whether the ACL counters were on before the meter turned them on.
	CountersBefore *bool    `json:"counters_before,omitempty"`
	In             uint32   `json:"acl_in"`
	Out            uint32   `json:"acl_out"`
	Ports          []uint32 `json:"ports"` // where the ACLs are attached
	// Before 2026-11-22 the ACLs went on the gateway interface alone.
	OldInterface uint32 `json:"interface,omitempty"`
	OldAttached  bool   `json:"attached,omitempty"`
}

// MeterRule is one counted address, after the local-prefix rules in each ACL.
type MeterRule struct {
	Address string `json:"address"`
	MAC     string `json:"mac"`
}

// MeterStatus is what is published for vpp-monitor and shown on the panel.
type MeterStatus struct {
	Enabled       bool           `json:"enabled"`
	Generation    int64          `json:"generation"`          // changes whenever the rules, and so the counters, start over
	Interface     string         `json:"interface,omitempty"` // the ports, comma separated
	ACLIn         uint32         `json:"acl_in"`
	ACLOut        uint32         `json:"acl_out"`
	LocalPrefixes []netip.Prefix `json:"local_prefixes,omitempty"` // one leading rule per prefix, excluded from device totals
	Rules         []MeterRule    `json:"rules"`
	Updated       time.Time      `json:"updated"`
	Error         string         `json:"error,omitempty"`
}

// Meter keeps the ACLs in line with the devices.
type Meter struct {
	opts    MeterOptions
	vpp     meterVPP
	dhcp    *DHCP
	live    func() (*liveState, error)
	hostTap string // the Linux name of the TAP to the router itself, left out
	now     func() time.Time

	mu   sync.Mutex
	st   meterState
	pub  MeterStatus
	kick chan struct{}
}

func NewMeter(opts MeterOptions, vpp meterVPP, dhcp *DHCP, live func() (*liveState, error), hostTap string) (*Meter, error) {
	m := &Meter{opts: opts, vpp: vpp, dhcp: dhcp, live: live, hostTap: hostTap, now: time.Now, kick: make(chan struct{}, 1),
		st: meterState{In: noACL, Out: noACL}}
	data, err := os.ReadFile(opts.State)
	if err == nil {
		if err := json.Unmarshal(data, &m.st); err != nil {
			return nil, fmt.Errorf("%s: %w", opts.State, err)
		}
		if m.st.OldAttached {
			m.st.Ports, m.st.OldInterface, m.st.OldAttached = []uint32{m.st.OldInterface}, 0, false
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	m.pub = MeterStatus{Enabled: m.st.Enabled, ACLIn: noACL, ACLOut: noACL, Rules: []MeterRule{}, Generation: m.now().UnixNano()}
	return m, nil
}

// Run keeps the ACLs up to date: every minute, when kicked, and after VPP restarts (the
// ACLs are gone then and are made again).
func (m *Meter) Run() {
	m.Reconcile()
	ticker := time.NewTicker(meterEvery)
	for {
		select {
		case <-ticker.C:
		case <-m.kick:
		}
		m.Reconcile()
	}
}

// Kick asks for a reconcile soon, as after a DHCP change.
func (m *Meter) Kick() {
	if m == nil {
		return
	}
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *Meter) Status() MeterStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	pub := m.pub
	pub.Rules = slices.Clone(pub.Rules)
	pub.LocalPrefixes = slices.Clone(pub.LocalPrefixes)
	return pub
}

// Set turns the meter on or off now.
func (m *Meter) Set(on bool, user string) (MeterStatus, error) {
	m.mu.Lock()
	m.st.Enabled = on
	err := m.save()
	m.mu.Unlock()
	if err != nil {
		return m.Status(), err
	}
	log.Printf("audit: 按设备统计流量%s，由 %s 修改", map[bool]string{true: "开启", false: "关闭"}[on], user)
	m.Reconcile()
	status := m.Status()
	if status.Error != "" {
		return status, errors.New(status.Error)
	}
	return status, nil
}

func (m *Meter) Reconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.reconcileLocked()
	m.pub.Enabled = m.st.Enabled
	m.pub.Updated = m.now()
	m.pub.Error = ""
	if err != nil {
		m.pub.Error = err.Error()
		log.Printf("LAN meter: %v", err)
	}
	if err := m.save(); err != nil {
		log.Printf("LAN meter: %v", err)
	}
	m.publish()
}

func (m *Meter) reconcileLocked() error {
	if !m.st.Enabled {
		return m.teardownLocked()
	}
	router, leases, err := m.dhcp.meterSources()
	if err != nil {
		return err
	}
	live, err := m.live()
	if err != nil {
		return fmt.Errorf("读取 VPP 失败：%w", err)
	}
	var lan *liveInterface
	for _, iface := range live.Interfaces {
		if slices.ContainsFunc(iface.Addresses, func(p netip.Prefix) bool { return p.Addr() == router }) {
			lan = iface
		}
	}
	if lan == nil {
		return fmt.Errorf("VPP 里没有地址为局域网网关 %s 的接口", router)
	}
	ports, err := m.ports(live, lan)
	if err != nil {
		return err
	}
	neighbors, err := m.vpp.neighbors(lan.Index)
	if err != nil {
		return err
	}
	rules := meterRules(leases, neighbors)
	local := meterLocalPrefixes(live, lan)
	changed := !slices.Equal(rules, m.pub.Rules) || !slices.Equal(local, m.pub.LocalPrefixes)
	fresh := false
	for _, a := range []struct {
		index *uint32
		tag   string
		input bool
	}{{&m.st.In, meterTagIn, true}, {&m.st.Out, meterTagOut, false}} {
		made, err := m.ensureACL(a.index, a.tag, aclRules(local, rules, a.input), changed)
		if err != nil {
			return err
		}
		fresh = fresh || made
	}
	if fresh {
		m.pub.Generation = m.now().UnixNano()
	}
	var names []string
	for _, p := range ports {
		names = append(names, p.Name)
	}
	m.pub.Rules, m.pub.ACLIn, m.pub.ACLOut, m.pub.Interface = rules, m.st.In, m.st.Out, strings.Join(names, ", ")
	m.pub.LocalPrefixes = local
	// Off the ports that are no longer device ports, then onto the ones that are.
	want := make([]uint32, len(ports))
	for i, p := range ports {
		want[i] = p.Index
	}
	for _, sw := range m.st.Ports {
		if !slices.Contains(want, sw) {
			m.detach(sw)
		}
	}
	m.st.Ports = slices.DeleteFunc(m.st.Ports, func(sw uint32) bool { return !slices.Contains(want, sw) })
	for _, p := range ports {
		in, out, err := m.vpp.interfaceACLs(p.Index)
		if err != nil {
			return err
		}
		if !slices.Contains(m.st.Ports, p.Index) {
			m.st.Ports = append(m.st.Ports, p.Index)
		}
		if !slices.Contains(in, m.st.In) {
			if err := m.vpp.attachACL(p.Index, m.st.In, true, true); err != nil {
				return fmt.Errorf("把计数 ACL 挂到 %s 入方向失败：%w", p.Name, err)
			}
		}
		if !slices.Contains(out, m.st.Out) {
			if err := m.vpp.attachACL(p.Index, m.st.Out, false, true); err != nil {
				return fmt.Errorf("把计数 ACL 挂到 %s 出方向失败：%w", p.Name, err)
			}
		}
	}
	on, err := m.vpp.countersEnabled()
	if err != nil {
		return err
	}
	if m.st.CountersBefore == nil {
		m.st.CountersBefore = &on
	}
	if !on {
		return m.vpp.enableCounters(true)
	}
	return nil
}

// ensureACL makes sure the ACL at *index is ours, with these rules: it replaces the rules
// when they changed, and makes the ACL again when VPP no longer has it (after a restart its
// index may even belong to someone else). It reports whether the counters start over.
func (m *Meter) ensureACL(index *uint32, tag string, rules []acl_types.ACLRule, changed bool) (bool, error) {
	ours := false
	if *index != noACL {
		got, exists, err := m.vpp.aclTag(*index)
		if err != nil {
			return false, err
		}
		ours = exists && got == tag
	}
	if ours && !changed {
		return false, nil
	}
	target := *index
	if !ours {
		target = noACL
	}
	made, err := m.vpp.replaceACL(target, tag, rules)
	if err != nil {
		return false, err
	}
	*index = made
	return true, nil
}

// ports are where the devices are: the members of the gateway's bridge other than the BVI
// and the TAP to Linux; the gateway interface itself when it is not a bridge's BVI.
func (m *Meter) ports(live *liveState, lan *liveInterface) ([]*liveInterface, error) {
	if !lan.BVI || lan.Bridge == 0 {
		return []*liveInterface{lan}, nil
	}
	taps := map[uint32]string{}
	if m.hostTap != "" {
		var err error
		if taps, err = m.vpp.tapHosts(); err != nil {
			return nil, err
		}
	}
	var out []*liveInterface
	for _, iface := range live.Interfaces {
		if iface.Bridge == lan.Bridge && !iface.BVI && (m.hostTap == "" || taps[iface.Index] != m.hostTap) {
			out = append(out, iface)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("网桥 %d 里除了网关和 Linux 管理口没有别的成员", lan.Bridge)
	}
	return out, nil
}

func (m *Meter) detach(sw uint32) {
	for _, a := range []struct {
		index uint32
		input bool
	}{{m.st.In, true}, {m.st.Out, false}} {
		if a.index != noACL {
			m.vpp.attachACL(sw, a.index, a.input, false)
		}
	}
}

// teardownLocked takes the ACLs away and puts the counter switch back as it was.
func (m *Meter) teardownLocked() error {
	var problems []error
	for _, sw := range m.st.Ports {
		m.detach(sw)
	}
	m.st.Ports = nil
	for _, a := range []struct {
		index *uint32
		tag   string
	}{{&m.st.In, meterTagIn}, {&m.st.Out, meterTagOut}} {
		if *a.index == noACL {
			continue
		}
		tag, exists, err := m.vpp.aclTag(*a.index)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		if exists && tag == a.tag {
			if err := m.vpp.deleteACL(*a.index); err != nil {
				problems = append(problems, err)
				continue
			}
		}
		*a.index = noACL
	}
	if m.st.CountersBefore != nil {
		if !*m.st.CountersBefore {
			if err := m.vpp.enableCounters(false); err != nil {
				problems = append(problems, err)
			}
		}
		if len(problems) == 0 {
			m.st.CountersBefore = nil
		}
	}
	m.pub = MeterStatus{Enabled: false, ACLIn: noACL, ACLOut: noACL, Rules: []MeterRule{}, Generation: m.pub.Generation}
	return errors.Join(problems...)
}

// meterRules lists the addresses to count, in a stable order: each lease or static host's
// IPv4 address, and every global address VPP has a neighbour entry for on the LAN (which is
// how a phone's own IPv6 addresses are found).
func meterRules(leases, neighbors []neighbor) []MeterRule {
	byAddr := map[netip.Addr]string{}
	for _, n := range neighbors {
		if n.IP.IsValid() && !n.IP.IsLinkLocalUnicast() && !n.IP.IsMulticast() {
			byAddr[n.IP] = n.MAC
		}
	}
	for _, l := range leases {
		byAddr[l.IP] = l.MAC
	}
	addrs := make([]netip.Addr, 0, len(byAddr))
	for a := range byAddr {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	rules := make([]MeterRule, len(addrs))
	for i, a := range addrs {
		rules[i] = MeterRule{Address: a.String(), MAC: byAddr[a]}
	}
	return rules
}

// meterLocalPrefixes includes the device LAN and any other routed LAN bridges. Link-local
// traffic, broadcast and multicast likewise stay out of the device counters.
func meterLocalPrefixes(live *liveState, lan *liveInterface) []netip.Prefix {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
	for _, iface := range live.Interfaces {
		if iface != lan && !iface.BVI {
			continue
		}
		for _, prefix := range iface.Addresses {
			if prefix.IsValid() && prefix.Bits() > 0 {
				prefixes = append(prefixes, prefix.Masked())
			}
		}
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
			return cmp
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(prefixes)
}

// aclRules permits local peers before the device-specific rules, then permits everything else of each
// family so that the meter never drops a packet.
func aclRules(local []netip.Prefix, rules []MeterRule, input bool) []acl_types.ACLRule {
	any4 := ip_types.Prefix{Address: ip_types.Address{Af: ip_types.ADDRESS_IP4}}
	any6 := ip_types.Prefix{Address: ip_types.Address{Af: ip_types.ADDRESS_IP6}}
	permit := func(src, dst ip_types.Prefix) acl_types.ACLRule {
		return acl_types.ACLRule{IsPermit: acl_types.ACL_ACTION_API_PERMIT, SrcPrefix: src, DstPrefix: dst,
			SrcportOrIcmptypeLast: 65535, DstportOrIcmpcodeLast: 65535}
	}
	var out []acl_types.ACLRule
	for _, prefix := range local {
		peer, _ := ip_types.ParsePrefix(prefix.String())
		anyOf := any6
		if prefix.Addr().Is4() {
			anyOf = any4
		}
		if input {
			out = append(out, permit(anyOf, peer))
		} else {
			out = append(out, permit(peer, anyOf))
		}
	}
	for _, r := range rules {
		addr := netip.MustParseAddr(r.Address)
		host, _ := ip_types.ParsePrefix(netip.PrefixFrom(addr, addr.BitLen()).String())
		anyOf := any4
		if addr.Is6() {
			anyOf = any6
		}
		if input {
			out = append(out, permit(host, anyOf))
		} else {
			out = append(out, permit(anyOf, host))
		}
	}
	return append(out, permit(any4, any4), permit(any6, any6))
}

func (m *Meter) save() error {
	data, err := marshalIndent(m.st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.opts.State), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(m.opts.State, data, 0o600)
}

func (m *Meter) publish() {
	if m.opts.Published == "" {
		return
	}
	data, err := marshalIndent(m.pub)
	if err == nil {
		err = os.MkdirAll(filepath.Dir(m.opts.Published), 0o755)
	}
	if err == nil {
		err = writeFileAtomic(m.opts.Published, data, 0o644)
	}
	if err != nil {
		log.Printf("LAN meter: publishing: %v", err)
	}
}
