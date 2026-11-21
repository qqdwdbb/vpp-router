package main

import (
	"fmt"
	"go.fd.io/govpp/binapi/acl_types"
	"go.fd.io/govpp/binapi/ip_types"
	"net/netip"
	"slices"
	"strings"
)

// LANDenyRule blocks a destination before LAN traffic is routed. Other traffic passes.
type LANDenyRule struct {
	Interface   string `json:"interface"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
}

func (c *Config) restrictedForwards() bool {
	for _, f := range c.Forwards {
		if len(f.Sources) > 0 {
			return true
		}
	}
	return false
}
func (c *Config) hasFilters() bool {
	return c.IPv6Firewall || c.BlockPing || c.restrictedForwards() || len(c.LANDeny) > 0
}
func validateFilters(c *Config) error {
	for _, f := range c.Forwards {
		for _, source := range f.Sources {
			p, err := netip.ParsePrefix(source)
			if err != nil || !p.Addr().Is4() || p != p.Masked() {
				return fmt.Errorf("invalid IPv4 forward source: %s", source)
			}
		}
	}
	for _, rule := range c.LANDeny {
		p, err := netip.ParsePrefix(rule.Destination)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("invalid LAN destination: %s", rule.Destination)
		}
		if rule.Interface == "" || len(rule.Interface) > 40 || strings.ContainsAny(rule.Interface, " \t\n/") {
			return fmt.Errorf("invalid LAN interface")
		}
		if _, err := protocols(rule.Protocol, true); err != nil {
			return err
		}
	}
	return nil
}

const lanTag = "vpp-firewall-lan:"

func reconcileLAN(v vppAPI, cfg *Config, previous *vppState) error {
	needed := len(cfg.LANDeny) > 0
	for _, a := range previous.ACLs {
		needed = needed || strings.HasPrefix(a.Tag, lanTag)
	}
	if !needed {
		return nil
	}
	// Read again: WAN reconciliation may have changed ACL lists on this connection.
	st, err := v.Read(true, false, func(string, bool) bool { return true })
	if err != nil {
		return err
	}
	existing := map[string]aclEntry{}
	for _, a := range st.ACLs {
		if strings.HasPrefix(a.Tag, lanTag) {
			existing[a.Tag] = a
		}
	}
	if len(cfg.LANDeny) == 0 && len(existing) == 0 {
		return nil
	}
	if !st.ACL {
		return fmt.Errorf("LAN filtering needs the ACL plugin")
	}
	wanted := map[string][]acl_types.ACLRule{}
	wanList, _ := wan(cfg, st)
	for _, rule := range cfg.LANDeny {
		in := st.byName(rule.Interface)
		if in == nil {
			continue
		}
		if isWAN(wanList, in.Index) {
			return fmt.Errorf("LAN filter interface %s is a WAN", rule.Interface)
		}
		p, _ := netip.ParsePrefix(rule.Destination)
		protos, _ := protocols(rule.Protocol, true)
		for _, proto := range protos {
			r := anyRule(acl_types.ACL_ACTION_API_DENY, p.Addr().Is6())
			r.DstPrefix = hostPrefix(p)
			r.Proto = ip_types.IPProto(proto)
			wanted[in.Name] = append(wanted[in.Name], r)
		}
	}
	indexes := map[string]uint32{}
	for name, rules := range wanted {
		rules = append(rules, anyRule(acl_types.ACL_ACTION_API_PERMIT, false), anyRule(acl_types.ACL_ACTION_API_PERMIT, true))
		tag := lanTag + name
		a, ok := existing[tag]
		index := noIndex
		if ok {
			index = a.Index
		}
		if !ok || !sameRules(a.Rules, rules) {
			index, err = v.ReplaceACL(index, tag, rules)
			if err != nil {
				return err
			}
		}
		indexes[name] = index
	}
	owned := func(index uint32) bool {
		for _, a := range existing {
			if a.Index == index {
				return true
			}
		}
		return false
	}
	for _, in := range st.Interfaces {
		old := st.Lists[in.Index]
		next := aclList{Output: slices.Clone(old.Output)}
		if index, ok := indexes[in.Name]; ok {
			next.Input = append(next.Input, index)
		}
		for _, index := range old.Input {
			if !owned(index) {
				next.Input = append(next.Input, index)
			}
		}
		if !slices.Equal(old.Input, next.Input) {
			if err = v.SetACLList(in.Index, next); err != nil {
				return err
			}
		}
	}
	for tag, a := range existing {
		if _, ok := indexes[strings.TrimPrefix(tag, lanTag)]; !ok {
			if err = v.DeleteACL(a.Index); err != nil {
				return err
			}
		}
	}
	return nil
}
