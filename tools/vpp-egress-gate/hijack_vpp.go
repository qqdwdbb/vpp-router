package gate

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"

	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/abf"
	"go.fd.io/govpp/binapi/acl"
	"go.fd.io/govpp/binapi/acl_types"
	"go.fd.io/govpp/binapi/fib_types"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip_types"
)

// The nft redirect only sees queries that reach Linux. A client that asks a public resolver
// goes straight through VPP, so VPP sends port 53 from the client networks to Linux first,
// whatever the destination, and the redirect takes it from there. Conntrack puts the
// original address back on the answer.

const (
	vppHijackTagPrefix = "gate-dns-"
	vppHijackFirstID   = 5300
)

// errVPPHijackUnsupported means VPP lacks the acl or abf plugin.
var errVPPHijackUnsupported = errors.New("VPP has no usable acl and abf plugins")

// HijackVPPEntry sends DNS from Sources, arriving on a VPP interface, to Linux at Via.
type HijackVPPEntry struct {
	Interface    string
	ViaInterface string
	Via          []netip.Addr
	Sources      []netip.Prefix
}

func parseHijackVPP(v any) ([]HijackVPPEntry, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("hijack_vpp must be a list")
	}
	var entries []HijackVPPEntry
	for _, item := range items {
		doc, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("hijack_vpp must be a list of objects")
		}
		for key := range doc {
			if key != "interface" && key != "via_interface" && key != "via" && key != "sources" {
				return nil, fmt.Errorf("hijack_vpp: unknown field %q", key)
			}
		}
		var entry HijackVPPEntry
		entry.Interface, _ = doc["interface"].(string)
		if value, present := doc["via_interface"]; present {
			entry.ViaInterface, _ = value.(string)
			if !nameRe.MatchString(entry.ViaInterface) {
				return nil, fmt.Errorf("hijack_vpp: invalid via_interface")
			}
		}
		if !nameRe.MatchString(entry.Interface) {
			return nil, fmt.Errorf("hijack_vpp: invalid interface %q", entry.Interface)
		}
		vias, _ := doc["via"].([]any)
		sources, _ := doc["sources"].([]any)
		if len(vias) == 0 || len(sources) == 0 {
			return nil, fmt.Errorf("hijack_vpp %s needs via and sources as lists", entry.Interface)
		}
		has := map[bool]bool{}
		for _, value := range vias {
			text, _ := value.(string)
			addr, err := parseAddr(text)
			if err != nil {
				return nil, fmt.Errorf("hijack_vpp %s: invalid via %v", entry.Interface, value)
			}
			if has[addr.Is6()] {
				return nil, fmt.Errorf("hijack_vpp %s: one via per address family", entry.Interface)
			}
			has[addr.Is6()] = true
			entry.Via = append(entry.Via, addr)
		}
		for _, value := range sources {
			text, _ := value.(string)
			prefix, err := parsePrefixStrict(text)
			if err != nil {
				return nil, fmt.Errorf("hijack_vpp %s: invalid source %v", entry.Interface, value)
			}
			if !has[prefix.Addr().Is6()] {
				return nil, fmt.Errorf("hijack_vpp %s: source %s has no via of its family", entry.Interface, prefix)
			}
			entry.Sources = append(entry.Sources, prefix)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// vppHijackPolicy is what one entry needs for one address family.
type vppHijackPolicy struct {
	ID           uint32
	Tag          string
	Interface    string
	ViaInterface string
	Via          netip.Addr
	Rules        []acl_types.ACLRule
}

func anyPrefix(is6 bool) ip_types.Prefix {
	text := "0.0.0.0/0"
	if is6 {
		text = "::/0"
	}
	prefix, _ := ip_types.ParsePrefix(text)
	return prefix
}

func mustACLPrefix(text string) ip_types.Prefix {
	prefix, err := ip_types.ParsePrefix(text)
	if err != nil {
		panic(err)
	}
	return prefix
}

// vppHijackRules leaves this machine's own queries alone, as a resolver here may reach the
// internet through VPP and would otherwise get its own queries back. Multicast DNS-like
// traffic stays on the link.
func vppHijackRules(entry HijackVPPEntry, via netip.Addr, listen []Upstream) []acl_types.ACLRule {
	is6 := via.Is6()
	skip := func(src, dst ip_types.Prefix) acl_types.ACLRule {
		return acl_types.ACLRule{IsPermit: acl_types.ACL_ACTION_API_DENY, SrcPrefix: src, DstPrefix: dst, SrcportOrIcmptypeLast: 65535, DstportOrIcmpcodeLast: 65535}
	}
	own := map[netip.Addr]bool{via: true}
	for _, address := range listen {
		if addr, err := parseAddr(address.Host); err == nil && addr.Is6() == is6 && !addr.IsLoopback() {
			own[addr] = true
		}
	}
	var rules []acl_types.ACLRule
	for addr := range own {
		rules = append(rules, skip(mustACLPrefix(netip.PrefixFrom(addr, addr.BitLen()).String()), anyPrefix(is6)))
	}
	// Map order would otherwise reorder equal rules, which is harmless but hard to read.
	sortACLRules(rules)
	local := []string{"224.0.0.0/4", "255.255.255.255/32"}
	if is6 {
		local = []string{"ff00::/8", "fe80::/10"}
	}
	for _, text := range local {
		rules = append(rules, skip(anyPrefix(is6), mustACLPrefix(text)))
	}
	for _, source := range entry.Sources {
		if source.Addr().Is6() != is6 {
			continue
		}
		for _, proto := range []ip_types.IPProto{ip_types.IP_API_PROTO_UDP, ip_types.IP_API_PROTO_TCP} {
			rules = append(rules, acl_types.ACLRule{
				IsPermit: acl_types.ACL_ACTION_API_PERMIT, SrcPrefix: mustACLPrefix(source.String()), DstPrefix: anyPrefix(is6), Proto: proto,
				SrcportOrIcmptypeLast: 65535, DstportOrIcmpcodeFirst: 53, DstportOrIcmpcodeLast: 53,
			})
		}
	}
	return rules
}

func sortACLRules(rules []acl_types.ACLRule) {
	key := func(r acl_types.ACLRule) string { return r.SrcPrefix.String() }
	for i := 1; i < len(rules); i++ {
		for j := i; j > 0 && key(rules[j]) < key(rules[j-1]); j-- {
			rules[j], rules[j-1] = rules[j-1], rules[j]
		}
	}
}

func vppHijackPolicies(g *GateFile) []vppHijackPolicy {
	var policies []vppHijackPolicy
	for i, entry := range g.HijackVPP {
		for _, via := range entry.Via {
			id := uint32(vppHijackFirstID + 2*i)
			if via.Is6() {
				id++
			}
			policies = append(policies, vppHijackPolicy{
				ID: id, Tag: fmt.Sprintf("%s%d", vppHijackTagPrefix, id), Interface: entry.Interface, ViaInterface: entry.ViaInterface, Via: via,
				Rules: vppHijackRules(entry, via, g.Listen),
			})
		}
	}
	return policies
}

func (s *vppAPISession) vppHijackSupported() error {
	if err := s.ch.CheckCompatiblity(
		(*acl.ACLAddReplace)(nil), (*acl.ACLDel)(nil), (*acl.ACLDump)(nil), (*acl.ACLDetails)(nil),
		(*abf.AbfPolicyAddDel)(nil), (*abf.AbfPolicyDump)(nil), (*abf.AbfPolicyDetails)(nil),
		(*abf.AbfItfAttachAddDel)(nil), (*abf.AbfItfAttachDump)(nil), (*abf.AbfItfAttachDetails)(nil),
	); err != nil {
		return fmt.Errorf("%w: %s", errVPPHijackUnsupported, err)
	}
	return nil
}

func dumpAll[T any](ch api.Channel, request api.Message, details func() (*T, api.Message)) ([]*T, error) {
	req := ch.SendMultiRequest(request)
	var out []*T
	for {
		item, message := details()
		last, err := req.ReceiveReply(message)
		if err != nil {
			return nil, err
		}
		if last {
			return out, nil
		}
		out = append(out, item)
	}
}

func checkRetval(what string, retval int32, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if retval != 0 {
		return fmt.Errorf("%s failed (%d)", what, retval)
	}
	return nil
}

func (s *vppAPISession) dumpVPPHijack() (map[string]uint32, []abf.AbfPolicy, []abf.AbfItfAttach, error) {
	acls, err := dumpAll(s.ch, &acl.ACLDump{ACLIndex: ^uint32(0)}, func() (*acl.ACLDetails, api.Message) {
		d := &acl.ACLDetails{}
		return d, d
	})
	if err != nil {
		return nil, nil, nil, err
	}
	tags := map[string]uint32{}
	for _, d := range acls {
		tags[strings.TrimRight(d.Tag, "\x00")] = d.ACLIndex
	}
	policyDetails, err := dumpAll(s.ch, &abf.AbfPolicyDump{}, func() (*abf.AbfPolicyDetails, api.Message) {
		d := &abf.AbfPolicyDetails{}
		return d, d
	})
	if err != nil {
		return nil, nil, nil, err
	}
	var policies []abf.AbfPolicy
	for _, d := range policyDetails {
		policies = append(policies, d.Policy)
	}
	attachDetails, err := dumpAll(s.ch, &abf.AbfItfAttachDump{}, func() (*abf.AbfItfAttachDetails, api.Message) {
		d := &abf.AbfItfAttachDetails{}
		return d, d
	})
	if err != nil {
		return nil, nil, nil, err
	}
	var attachments []abf.AbfItfAttach
	for _, d := range attachDetails {
		attachments = append(attachments, d.Attach)
	}
	return tags, policies, attachments, nil
}

func (s *vppAPISession) removeVPPHijackPolicy(policy abf.AbfPolicy, attachments []abf.AbfItfAttach) error {
	for _, attach := range attachments {
		if attach.PolicyID != policy.PolicyID {
			continue
		}
		reply := &abf.AbfItfAttachAddDelReply{}
		err := s.ch.SendRequest(&abf.AbfItfAttachAddDel{Attach: attach}).ReceiveReply(reply)
		if err := checkRetval("ABF detach", reply.Retval, err); err != nil {
			return err
		}
	}
	reply := &abf.AbfPolicyAddDelReply{}
	err := s.ch.SendRequest(&abf.AbfPolicyAddDel{Policy: policy}).ReceiveReply(reply)
	return checkRetval("ABF policy delete", reply.Retval, err)
}

// syncVPPHijack makes VPP hold exactly these policies among its own, found by their tag.
// It rebuilds what it finds, which is fine for something that runs once per VPP instance.
func (s *vppAPISession) syncVPPHijack(wanted []vppHijackPolicy) error {
	if err := s.vppHijackSupported(); err != nil {
		if len(wanted) == 0 {
			return nil
		}
		return err
	}
	tags, policies, attachments, err := s.dumpVPPHijack()
	if err != nil {
		return err
	}
	owned := map[uint32]bool{}
	for tag, index := range tags {
		if strings.HasPrefix(tag, vppHijackTagPrefix) {
			owned[index] = true
		}
	}
	ids := map[uint32]bool{}
	for _, policy := range wanted {
		ids[policy.ID] = true
	}
	for _, policy := range policies {
		if owned[policy.ACLIndex] {
			if err := s.removeVPPHijackPolicy(policy, attachments); err != nil {
				return err
			}
		} else if ids[policy.PolicyID] {
			return fmt.Errorf("ABF policy %d belongs to something else", policy.PolicyID)
		}
	}
	kept := map[string]bool{}
	for _, policy := range wanted {
		kept[policy.Tag] = true
	}
	for tag, index := range tags {
		if strings.HasPrefix(tag, vppHijackTagPrefix) && !kept[tag] {
			reply := &acl.ACLDelReply{}
			err := s.ch.SendRequest(&acl.ACLDel{ACLIndex: index}).ReceiveReply(reply)
			if err := checkRetval("ACL delete", reply.Retval, err); err != nil {
				return err
			}
		}
	}
	for _, policy := range wanted {
		if err := s.addVPPHijackPolicy(policy, tags); err != nil {
			return err
		}
	}
	return nil
}

func (s *vppAPISession) addVPPHijackPolicy(policy vppHijackPolicy, tags map[string]uint32) error {
	ifaces, err := s.dumpInterfaces()
	if err != nil {
		return err
	}
	s.ifaces = ifaces
	index, ok := ifaces[policy.Interface]
	if !ok {
		return fmt.Errorf("%w: %s", errVPPInterfaceMissing, policy.Interface)
	}
	viaIndex, err := hijackViaIndex(policy, ifaces)
	if err != nil {
		return err
	}
	aclIndex, exists := tags[policy.Tag]
	if !exists {
		aclIndex = ^uint32(0)
	}
	aclReply := &acl.ACLAddReplaceReply{}
	err = s.ch.SendRequest(&acl.ACLAddReplace{ACLIndex: aclIndex, Tag: policy.Tag, Count: uint32(len(policy.Rules)), R: policy.Rules}).ReceiveReply(aclReply)
	if err := checkRetval("ACL update", aclReply.Retval, err); err != nil {
		return err
	}
	proto := fib_types.FIB_API_PATH_NH_PROTO_IP4
	if policy.Via.Is6() {
		proto = fib_types.FIB_API_PATH_NH_PROTO_IP6
	}
	nh := ip_types.NewAddress(net.IP(policy.Via.AsSlice()))
	policyReply := &abf.AbfPolicyAddDelReply{}
	err = s.ch.SendRequest(&abf.AbfPolicyAddDel{IsAdd: true, Policy: abf.AbfPolicy{
		PolicyID: policy.ID, ACLIndex: aclReply.ACLIndex, NPaths: 1,
		Paths: []fib_types.FibPath{{SwIfIndex: viaIndex, Weight: 1, Proto: proto, Nh: fib_types.FibPathNh{Address: nh.Un}}},
	}}).ReceiveReply(policyReply)
	if err := checkRetval("ABF policy add", policyReply.Retval, err); err != nil {
		return err
	}
	attachReply := &abf.AbfItfAttachAddDelReply{}
	err = s.ch.SendRequest(&abf.AbfItfAttachAddDel{IsAdd: true, Attach: abf.AbfItfAttach{
		PolicyID: policy.ID, SwIfIndex: interface_types.InterfaceIndex(index), IsIPv6: policy.Via.Is6(),
	}}).ReceiveReply(attachReply)
	return checkRetval("ABF attach", attachReply.Retval, err)
}

func hijackViaIndex(policy vppHijackPolicy, ifaces map[string]uint32) (uint32, error) {
	name := policy.ViaInterface
	if name == "" {
		name = policy.Interface
	}
	index, ok := ifaces[name]
	if !ok {
		return 0, fmt.Errorf("%w: %s", errVPPInterfaceMissing, name)
	}
	return index, nil
}

func applyVPPHijack(cfg *Config, wanted []vppHijackPolicy) error {
	apiMu <- struct{}{}
	defer func() { <-apiMu }()
	sess, err := vppAPI(cfg)
	if err != nil {
		dropAPICache()
		return err
	}
	if err := sess.syncVPPHijack(wanted); err != nil {
		if !errors.Is(err, errVPPHijackUnsupported) && !errors.Is(err, errVPPInterfaceMissing) {
			dropAPICache()
		}
		return err
	}
	return nil
}

// natRunsBeforeABF reads show interface features. NAT44 on an inside interface rewrites the
// source before ABF sees it, so the client networks in the ACL never match. VPP does not
// let this be reordered; NAT as an output feature on the WAN runs after ABF instead.
func natRunsBeforeABF(features string) bool {
	nat, inArc := false, false
	for _, line := range strings.Split(features, "\n") {
		name := strings.TrimSpace(line)
		switch {
		case name == "ip4-unicast:":
			inArc = true
		case !inArc:
		case name == "" || strings.HasSuffix(name, ":"):
			return false
		case strings.Contains(name, "in2out"):
			nat = true
		case name == "abf-input-ip4":
			return nat
		}
	}
	return false
}

// vppHijackKeeper applies the policies once per VPP instance, as VPP forgets them when it
// restarts. A failure costs interception of some queries, not DNS, so it never stops Gate.
type vppHijackKeeper struct {
	apply      func() error
	check      func() []string
	generation func() (string, error)
	done       string
	problems   failureLog
}

func newVPPHijackKeeper(cfg *Config, g *GateFile, backend Backend) *vppHijackKeeper {
	wanted := vppHijackPolicies(g)
	return &vppHijackKeeper{
		apply: func() error { return applyVPPHijack(cfg, wanted) },
		check: func() []string {
			var problems []string
			for _, entry := range g.HijackVPP {
				features, err := backend.CLI("show interface features " + entry.Interface)
				if err == nil && natRunsBeforeABF(features) {
					problems = append(problems, fmt.Sprintf("NAT on %s runs before ABF, so IPv4 clients are not intercepted; "+
						"use NAT as an output feature on the WAN (set interface nat44 ei out WAN output-feature)", entry.Interface))
				}
			}
			return problems
		},
		generation: backend.Generation,
		problems:   failureLog{what: "DNS sent elsewhere is not going through Gate"},
	}
}

func (k *vppHijackKeeper) ensure() {
	generation, err := k.generation()
	if err != nil || generation == k.done {
		return
	}
	if err := k.apply(); err != nil {
		k.problems.failed(err)
		return
	}
	k.done = generation
	k.problems.recovered("VPP now sends DNS to Linux")
	if k.check != nil {
		for _, problem := range k.check() {
			log.Printf("%s: %s", k.problems.what, problem)
		}
	}
}

// clearVPPHijack runs as Gate stops: with nothing to answer, a query VPP sends to Linux is lost.
func clearVPPHijack(cfg *Config) {
	if err := applyVPPHijack(cfg, nil); err != nil {
		log.Printf("VPP DNS interception not removed: %s", err)
	}
}
