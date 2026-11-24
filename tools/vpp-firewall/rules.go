package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"go.fd.io/govpp/binapi/acl_types"
	"go.fd.io/govpp/binapi/ip_types"
)

// What the service puts in VPP carries these tags, so it is found again after the service or
// VPP restarts, and nothing else is touched.
const (
	natTag    = "vpp-firewall"
	aclInTag  = "vpp-firewall-in"
	aclOutTag = "vpp-firewall-out"
)

// wan returns the WAN interfaces present in VPP, and the configured ones it lacks.
func wan(cfg *Config, st *vppState) (present []*iface, missing []string) {
	if len(cfg.WANInterfaces) > 0 {
		for _, name := range cfg.WANInterfaces {
			if in := st.byName(name); in != nil {
				present = append(present, in)
			} else {
				missing = append(missing, name)
			}
		}
		return present, missing
	}
	for _, index := range st.NATOutside {
		if in := st.byIndex(index); in != nil {
			present = append(present, in)
		}
	}
	return present, nil
}

// wantedAddresses says which interfaces' addresses a reading needs when not all of them.
func wantedAddresses(cfg *Config) func(string, bool) bool {
	return func(name string, outside bool) bool {
		if len(cfg.WANInterfaces) > 0 {
			return slices.Contains(cfg.WANInterfaces, name)
		}
		return outside
	}
}

func isWAN(list []*iface, index uint32) bool {
	for _, in := range list {
		if in.Index == index {
			return true
		}
	}
	return false
}

// natKey identifies a mapping made on an interface.
type natKey struct {
	identity  bool
	proto     uint8
	port      uint16
	sw        uint32
	localIP   netip.Addr
	localPort uint16
}

func keyOf(m mapping) natKey {
	return natKey{m.Identity, m.Proto, m.ExternalPort, m.ExternalIf, m.LocalIP, m.LocalPort}
}

// desiredMappings are the NAT mappings the configuration asks for, with a problem for each
// rule that cannot be applied now (its interface is gone).
func desiredMappings(cfg *Config, st *vppState) ([]mapping, map[int]string) {
	var out []mapping
	problems := map[int]string{}
	wanList, _ := wan(cfg, st)
	for _, f := range cfg.Forwards {
		in := st.byName(f.Interface)
		if in == nil || !isWAN(wanList, in.Index) {
			problems[f.ID] = "接口 " + f.Interface + " 不在或不是 WAN，规则暂不生效"
			continue
		}
		protos, _ := protocols(f.Protocol, false)
		count, _ := portRange(f.ExternalPort, f.LastPort, rangeLimit)
		local, _ := netip.ParseAddr(f.InternalIP)
		for _, proto := range protos {
			for i := 0; i < count; i++ {
				out = append(out, mapping{Proto: proto, ExternalPort: uint16(f.ExternalPort + i), ExternalIf: in.Index,
					LocalIP: local, LocalPort: uint16(f.InternalPort + i), Tag: natTag})
			}
		}
	}
	for _, p := range cfg.Ports {
		in := st.byName(p.Interface)
		if in == nil || !isWAN(wanList, in.Index) {
			problems[p.ID] = "接口 " + p.Interface + " 不在或不是 WAN，规则暂不生效"
			continue
		}
		protos, _ := protocols(p.Protocol, false)
		count, _ := portRange(p.Port, p.LastPort, rangeLimit)
		for _, proto := range protos {
			for i := 0; i < count; i++ {
				out = append(out, mapping{Identity: true, Proto: proto, ExternalPort: uint16(p.Port + i), ExternalIf: in.Index, Tag: natTag})
			}
		}
	}
	return out, problems
}

// mappingInterface is the interface a mapping is on: named, or owning its external address.
func mappingInterface(st *vppState, m mapping) *iface {
	if m.ExternalIf != noIndex {
		return st.byIndex(m.ExternalIf)
	}
	for i := range st.Interfaces {
		for _, a := range st.Interfaces[i].Addrs {
			if a.Addr() == m.ExternalIP {
				return &st.Interfaces[i]
			}
		}
	}
	return nil
}

// routerPorts are the ports open to VPP itself on the WAN: every identity mapping there,
// whoever made it, so IPv6 opens what IPv4 has open. This service's own are taken from what
// it is about to apply, not from the reading, which may predate the change.
func routerPorts(st *vppState, wanList []*iface, desired []mapping) map[[2]uint16]bool {
	ours := map[mapping]bool{}
	for _, m := range desired {
		if m.Identity {
			ours[m] = true
		}
	}
	ports := map[[2]uint16]bool{}
	for _, m := range append(slices.Clone(desired), st.Mappings...) {
		if !m.Identity || m.ExternalPort == 0 || (m.Tag == natTag && !ours[m]) {
			continue
		}
		if in := mappingInterface(st, m); in != nil && isWAN(wanList, in.Index) {
			ports[[2]uint16{uint16(m.Proto), m.ExternalPort}] = true
		}
	}
	return ports
}

// portRun is first..last of one protocol.
type portRun struct{ proto, first, last uint16 }

// runs joins consecutive ports of a protocol, in order, so a range is one ACL rule.
func runs(ports map[[2]uint16]bool) []portRun {
	keys := make([][2]uint16, 0, len(ports))
	for key := range ports {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b [2]uint16) int { return int(a[0])<<16 + int(a[1]) - int(b[0])<<16 - int(b[1]) })
	var out []portRun
	for _, key := range keys {
		if n := len(out); n > 0 && out[n-1].proto == key[0] && out[n-1].last+1 == key[1] {
			out[n-1].last = key[1]
			continue
		}
		out = append(out, portRun{key[0], key[1], key[1]})
	}
	return out
}

// The ACL plugin keeps ports in the source and destination fields, and ICMP type and code there.
func anyPrefix(is6 bool) ip_types.Prefix {
	if is6 {
		return ip_types.Prefix{Address: ip_types.Address{Af: ip_types.ADDRESS_IP6}}
	}
	return ip_types.Prefix{Address: ip_types.Address{Af: ip_types.ADDRESS_IP4}}
}

func hostPrefix(p netip.Prefix) ip_types.Prefix {
	prefix := ip_types.Prefix{Len: uint8(p.Bits())}
	if p.Addr().Is4() {
		prefix.Address = ip_types.Address{Af: ip_types.ADDRESS_IP4, Un: ip_types.AddressUnionIP4(p.Addr().As4())}
	} else {
		prefix.Address = ip_types.Address{Af: ip_types.ADDRESS_IP6, Un: ip_types.AddressUnionIP6(p.Addr().As16())}
	}
	return prefix
}

func anyRule(action acl_types.ACLAction, is6 bool) acl_types.ACLRule {
	return acl_types.ACLRule{IsPermit: action, SrcPrefix: anyPrefix(is6), DstPrefix: anyPrefix(is6),
		SrcportOrIcmptypeLast: 65535, DstportOrIcmpcodeLast: 65535}
}

func icmpRule(action acl_types.ACLAction, is6 bool, first, last uint16) acl_types.ACLRule {
	proto := ip_types.IPProto(protoICMP)
	if is6 {
		proto = protoICMPv6
	}
	return acl_types.ACLRule{IsPermit: action, SrcPrefix: anyPrefix(is6), DstPrefix: anyPrefix(is6), Proto: proto,
		SrcportOrIcmptypeFirst: first, SrcportOrIcmptypeLast: last, DstportOrIcmpcodeLast: 255}
}

func portRule(dst ip_types.Prefix, is6 bool, proto uint8, first, last uint16) acl_types.ACLRule {
	rule := acl_types.ACLRule{IsPermit: acl_types.ACL_ACTION_API_PERMIT, SrcPrefix: anyPrefix(is6), DstPrefix: dst, Proto: ip_types.IPProto(proto),
		SrcportOrIcmptypeLast: 65535, DstportOrIcmpcodeFirst: first, DstportOrIcmpcodeLast: last}
	if proto != protoTCP && proto != protoUDP {
		rule.DstportOrIcmpcodeFirst, rule.DstportOrIcmpcodeLast = 0, 65535
	}
	return rule
}

// ICMPv6 that IPv6 needs to work (RFC 4890): errors, echo replies, and neighbor discovery.
var icmp6Needed = [][2]uint16{{1, 4}, {129, 129}, {133, 137}}

// inboundRules is the ACL on the WAN's input, or nil when none is needed. NAT44 already
// stops IPv4 nobody asked for, so IPv4 passes to it, apart from ping when that is off.
func inboundRules(cfg *Config, st *vppState, wanList []*iface, desired []mapping) []acl_types.ACLRule {
	if !cfg.IPv6Firewall && !cfg.BlockPing && !cfg.restrictedForwards() {
		return nil
	}
	var rules []acl_types.ACLRule
	for _, f := range cfg.Forwards {
		if len(f.Sources) == 0 {
			continue
		}
		in := st.byName(f.Interface)
		if in == nil || !isWAN(wanList, in.Index) {
			continue
		}
		protos, _ := protocols(f.Protocol, false)
		last := f.LastPort
		if last == 0 {
			last = f.ExternalPort
		}
		for _, addr := range in.Addrs {
			if !addr.Addr().Is4() {
				continue
			}
			for _, proto := range protos {
				r := portRule(hostPrefix(netip.PrefixFrom(addr.Addr(), 32)), false, proto, uint16(f.ExternalPort), uint16(last))
				for _, source := range f.Sources {
					p, _ := netip.ParsePrefix(source)
					allow := r
					allow.SrcPrefix = hostPrefix(p)
					rules = append(rules, allow)
				}
				r.IsPermit = acl_types.ACL_ACTION_API_DENY
				rules = append(rules, r)
			}
		}
	}
	if cfg.BlockPing {
		rules = append(rules, icmpRule(acl_types.ACL_ACTION_API_DENY, false, 8, 8), icmpRule(acl_types.ACL_ACTION_API_DENY, true, 128, 128))
	}
	rules = append(rules, anyRule(acl_types.ACL_ACTION_API_PERMIT, false))
	if !cfg.IPv6Firewall {
		return append(rules, anyRule(acl_types.ACL_ACTION_API_PERMIT, true))
	}
	for _, r := range icmp6Needed {
		rules = append(rules, icmpRule(acl_types.ACL_ACTION_API_PERMIT, true, r[0], r[1]))
	}
	if !cfg.BlockPing {
		rules = append(rules, icmpRule(acl_types.ACL_ACTION_API_PERMIT, true, 128, 128))
	}
	// DHCPv6 replies to VPP's own client, which can come before any session exists.
	dhcp := portRule(anyPrefix(true), true, protoUDP, 546, 546)
	dhcp.SrcportOrIcmptypeFirst, dhcp.SrcportOrIcmptypeLast = 547, 547
	rules = append(rules, dhcp)

	ports := routerPorts(st, wanList, desired)
	open := runs(ports)
	for _, in := range wanList {
		for _, a := range in.Addrs {
			if !a.Addr().Is6() || a.Addr().IsLinkLocalUnicast() {
				continue
			}
			dst := hostPrefix(netip.PrefixFrom(a.Addr(), 128))
			for _, r := range open {
				rules = append(rules, portRule(dst, true, uint8(r.proto), r.first, r.last))
			}
			// IKE on 500 means an IPsec server, which also needs ESP without NAT traversal.
			if ports[[2]uint16{protoUDP, 500}] {
				rules = append(rules, portRule(dst, true, protoESP, 0, 0))
			}
		}
	}
	for _, r := range cfg.IPv6Rules {
		prefix, err := parseIPv6Target(r.Address)
		if err != nil {
			continue
		}
		protos, _ := protocols(r.Protocol, true)
		last := r.LastPort
		if last == 0 {
			last = r.Port
		}
		for _, proto := range protos {
			rules = append(rules, portRule(hostPrefix(prefix), true, proto, uint16(r.Port), uint16(last)))
		}
	}
	return append(rules, anyRule(acl_types.ACL_ACTION_API_DENY, true))
}

// outboundRules lets the replies to what leaves by the WAN back in: IPv6 is reflected into a
// session the input ACL then accepts.
func outboundRules(cfg *Config) []acl_types.ACLRule {
	if !cfg.IPv6Firewall {
		return nil
	}
	return []acl_types.ACLRule{anyRule(acl_types.ACL_ACTION_API_PERMIT, false), anyRule(acl_types.ACL_ACTION_API_PERMIT_REFLECT, true)}
}

// sameRules compares rules as VPP returns them: an IPv4 prefix comes back with the rest of
// the address union zeroed, which is how they are built here too.
func sameRules(a, b []acl_types.ACLRule) bool {
	return len(a) == len(b) && (len(a) == 0 || reflect.DeepEqual(a, b))
}

// reconcile makes VPP match cfg. It touches only what carries this service's tags, and
// keeps other ACLs on the interfaces where they were, ahead of this service's.
func reconcile(v vppAPI, cfg *Config, st *vppState) error {
	var errs []string
	fail := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	// A configured WAN that is gone is reported by the state, not retried as a failure.
	wanList, _ := wan(cfg, st)

	desired, _ := desiredMappings(cfg, st)
	if len(desired) > 0 && !st.NAT {
		errs = append(errs, "VPP 没有 NAT44，端口转发和本机端口不能生效")
		desired = nil
	}
	if !st.Statics {
		// A periodic check reads only identity mappings: static mappings change only by this
		// service's changes and VPP restarts, which read everything.
		desired = slices.DeleteFunc(slices.Clone(desired), func(m mapping) bool { return !m.Identity })
	}
	want := map[natKey]mapping{}
	for _, m := range desired {
		want[keyOf(m)] = m
	}
	// Only the difference is applied, so adding a forward to a thousand others makes as many
	// calls as it has ports. A range that VPP refuses fails port by port: report the first
	// refusal and how many more there were, not a message per port.
	refused := func(what string) func(error) {
		var first error
		n := 0
		return func(err error) {
			if err == nil {
				if first != nil {
					if n > 1 {
						first = fmt.Errorf("%w（共 %d 个%s失败）", first, n, what)
					}
					fail(first)
				}
				return
			}
			if first == nil {
				first = err
			}
			n++
		}
	}
	have := map[natKey]bool{}
	removeFailed := refused("映射删除")
	for _, m := range st.Mappings {
		if m.Tag != natTag || m.ExternalIf == noIndex {
			continue
		}
		key := keyOf(m)
		if _, ok := want[key]; ok {
			have[key] = true
			continue
		}
		if err := v.Mapping(m, false); err != nil {
			removeFailed(err)
		}
	}
	removeFailed(nil)
	addFailed := refused("映射添加")
	for _, m := range desired {
		if !have[keyOf(m)] {
			if err := v.Mapping(m, true); err != nil {
				addFailed(err)
			}
		}
	}
	addFailed(nil)

	in, out := inboundRules(cfg, st, wanList, desired), outboundRules(cfg)
	if (in != nil || out != nil) && !st.ACL {
		return errors.New(strings.Join(append(errs, "VPP 没有 acl 插件，不能过滤入站"), "；"))
	}
	current := map[string]aclEntry{}
	for _, entry := range st.ACLs {
		if entry.Tag == aclInTag || entry.Tag == aclOutTag {
			if _, dup := current[entry.Tag]; dup {
				// A second copy, left by a crash between create and record: drop it once unused.
				continue
			}
			current[entry.Tag] = entry
		}
	}
	ensure := func(tag string, rules []acl_types.ACLRule) (uint32, bool) {
		entry, ok := current[tag]
		if rules == nil {
			return noIndex, false
		}
		if ok && sameRules(entry.Rules, rules) {
			return entry.Index, true
		}
		index := noIndex
		if ok {
			index = entry.Index
		}
		got, err := v.ReplaceACL(index, tag, rules)
		if err != nil {
			fail(err)
			return noIndex, false
		}
		log.Printf("wrote ACL %d (%s, %d rules)", got, tag, len(rules))
		return got, true
	}
	inIndex, inOK := ensure(aclInTag, in)
	outIndex, outOK := ensure(aclOutTag, out)

	ours := func(index uint32) bool {
		for _, entry := range st.ACLs {
			if entry.Index == index && (entry.Tag == aclInTag || entry.Tag == aclOutTag) {
				return true
			}
		}
		return (inOK && index == inIndex) || (outOK && index == outIndex)
	}
	if st.ACL {
		for _, in := range st.Interfaces {
			old := st.Lists[in.Index]
			next := aclList{}
			for _, index := range old.Input {
				if !ours(index) {
					next.Input = append(next.Input, index)
				}
			}
			for _, index := range old.Output {
				if !ours(index) {
					next.Output = append(next.Output, index)
				}
			}
			if isWAN(wanList, in.Index) {
				if inOK {
					next.Input = append(next.Input, inIndex)
				}
				if outOK {
					next.Output = append(next.Output, outIndex)
				}
			}
			if !slices.Equal(old.Input, next.Input) || !slices.Equal(old.Output, next.Output) {
				fail(v.SetACLList(in.Index, next))
			}
		}
		// Only once nothing uses them: VPP refuses to delete an ACL that is applied.
		for _, entry := range st.ACLs {
			if entry.Tag != aclInTag && entry.Tag != aclOutTag {
				continue
			}
			if (inOK && entry.Index == inIndex) || (outOK && entry.Index == outIndex) {
				continue
			}
			fail(v.DeleteACL(entry.Index))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "；"))
	}
	return reconcileLAN(v, cfg, st)
}

// conflicts says what already uses each port on an interface, by protocol and port, from
// VPP's mappings: built once, a range of a thousand ports is not checked against every one.
func conflicts(st *vppState, in *iface) map[[2]int]string {
	out := map[[2]int]string{}
	for _, m := range st.Mappings {
		key := [2]int{int(m.Proto), int(m.ExternalPort)}
		if _, seen := out[key]; seen {
			continue
		}
		if at := mappingInterface(st, m); at != nil && at.Index == in.Index {
			if m.Identity {
				out[key] = fmt.Sprintf("%s %d 已经开放给路由器本机%s", protoName(m.Proto), m.ExternalPort, owner(m))
			} else {
				out[key] = fmt.Sprintf("%s %d 已经转发到 %s:%d%s", protoName(m.Proto), m.ExternalPort, m.LocalIP, m.LocalPort, owner(m))
			}
		}
	}
	return out
}

func owner(m mapping) string {
	if m.Tag == natTag {
		return ""
	}
	return "（其他程序添加的）"
}
