package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Exits set by hand: a VPP interface and the next hop to send to through it, which may be any
// address the interface reaches, not only its gateway. They are configuration, kept in their
// own file, and take precedence over what other programs offer and what rules used before.
// Changing one changes the rules that use the exit with it.
//
// An exit is named after its interface unless it is given a name of its own. A name lets one
// interface carry several exits, each with its own next hops; the rules on such an exit say
// which one in exitNameField, as the interface no longer does.

// customExit is one line of the exits file.
type customExit struct {
	// Name is empty, or the interface's name, for the exit the interface stands for.
	Name      string   `json:"name,omitempty"`
	Interface string   `json:"interface"`
	Via       []string `json:"via,omitempty"`
	Port      int      `json:"tproxy_port,omitempty"`
	DNS       string   `json:"dns,omitempty"`
	Pools     []string `json:"fakeip_range,omitempty"`
	IPv6      bool     `json:"ipv6,omitempty"`
	// DHCP takes the IPv4 next hop from VPP's lease on the interface; such an exit can carry
	// only the default route.
	DHCP bool `json:"dhcp,omitempty"`
}

// key is the exit's name, which rules and the panel use.
func (e customExit) key() string {
	if e.Name != "" {
		return e.Name
	}
	return e.Interface
}

func (e customExit) profile() map[string]any {
	if e.Port > 0 {
		p := map[string]any{"tproxy_exit": e.Interface, "tproxy_port": float64(e.Port), "ipv6": e.IPv6}
		if dns, _ := parseDNS(e.DNS); dns != nil {
			p["dns_upstream"] = dns
		}
		if len(e.Pools) > 0 {
			pools := make([]any, len(e.Pools))
			for i, pool := range e.Pools {
				pools[i] = pool
			}
			p["fakeip_range"] = pools
		}
		return p
	}
	profile := map[string]any{"interface": e.Interface, "fib_table": float64(0)}
	if e.key() != e.Interface {
		profile[exitNameField] = e.key()
	}
	if len(e.Via) == 1 {
		profile["via"] = e.Via[0]
	} else if len(e.Via) > 1 {
		via := make([]any, len(e.Via))
		for i, v := range e.Via {
			via[i] = v
		}
		profile["via"] = via
	}
	if e.DHCP {
		profile[dhcpGatewayField] = true
	}
	return profile
}

// SetTProxyExit saves a local listener for rules; Gate provisions its transit device.
func (a *Admin) SetTProxyExit(name string, port int, dns string, pools []string, ipv6 bool, user string) (*AdminState, error) {
	if !ruleNameRe.MatchString(name) || port < 1 || port > 65535 {
		return nil, errors.New("TPROXY 名称或端口无效")
	}
	upstream, err := parseDNS(dns)
	if err != nil {
		return nil, err
	}
	if len(pools) > 0 && upstream == nil {
		return nil, errors.New("Fake-IP 出口必须填写 DNS")
	}
	seen := map[bool]bool{}
	for _, pool := range pools {
		p, err := netip.ParsePrefix(pool)
		if err != nil || p != p.Masked() || p.Bits() == 0 || p.Bits() == p.Addr().BitLen() || seen[p.Addr().Is6()] {
			return nil, errors.New("Fake-IP 地址池须为每个地址族至多一个有效 CIDR")
		}
		seen[p.Addr().Is6()] = true
	}
	wanted := customExit{Interface: name, Port: port, DNS: dns, Pools: pools, IPv6: ipv6}
	return a.changeExits("设置 TPROXY 出口 "+name, user, func(exits []customExit, loaded *adminRules) ([]customExit, error) {
		for _, profile := range a.allProfiles(loaded.rules) {
			if ruleExit(profile) == name && profile["tproxy_exit"] == nil {
				return nil, errors.New("名称已被其他出口使用")
			}
		}
		// Rules keep the DNS they chose; one that used this exit's Fake-IP DNS gets its new one.
		before := a.fakeIPOffers(exits)
		var kept []customExit
		for _, e := range exits {
			if e.key() != name {
				kept = append(kept, e)
			}
		}
		after := a.fakeIPOffers(append(kept, wanted))
		for _, rule := range loaded.rules {
			if ruleExit(rule) != name {
				continue
			}
			dns := ruleDNS(rule)
			if old, ok := before[name]; ok && sameDNS(dns, old.dns) {
				dns = nil
				if next, ok := after[name]; ok {
					dns = next.dns
				}
			}
			for key := range ruleAttributes(rule) {
				delete(rule, key)
			}
			for key, value := range wanted.profile() {
				rule[key] = value
			}
			if err := setRuleDNS(rule, dns); err != nil {
				return nil, err
			}
		}
		return append(kept, wanted), nil
	})
}

func (a *Admin) customExits() ([]customExit, error) {
	if a.opts.CustomExits == "" {
		return nil, nil
	}
	data, err := os.ReadFile(a.opts.CustomExits)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var exits []customExit
	if err := json.Unmarshal(data, &exits); err != nil {
		return nil, fmt.Errorf("%s: %w", a.opts.CustomExits, err)
	}
	return exits, nil
}

func renderCustomExits(exits []customExit) ([]byte, error) {
	sort.Slice(exits, func(i, j int) bool { return exits[i].key() < exits[j].key() })
	data, err := json.MarshalIndent(exits, "", "  ")
	return append(data, '\n'), err
}

// parseExitVia checks the next hops: at most one per family, DHCP only in place of IPv4.
func parseExitVia(via4, via6 string, dhcp bool) ([]string, error) {
	var via []string
	via4, via6 = strings.TrimSpace(via4), strings.TrimSpace(via6)
	if via4 != "" {
		if dhcp {
			return nil, errors.New("IPv4 下一跳要么填地址，要么用 DHCP 网关")
		}
		address, err := netip.ParseAddr(via4)
		if err != nil || !address.Is4() {
			return nil, fmt.Errorf("IPv4 下一跳 %q 不是 IPv4 地址", via4)
		}
		via = append(via, address.String())
	}
	if via6 != "" {
		address, err := netip.ParseAddr(via6)
		if err != nil || !address.Is6() || address.Is4In6() || address.Zone() != "" {
			return nil, fmt.Errorf("IPv6 下一跳 %q 不是 IPv6 地址", via6)
		}
		via = append(via, address.String())
	}
	if len(via) == 0 && !dhcp {
		return nil, errors.New("至少要有一个下一跳")
	}
	return via, nil
}

// fixedExit says whether a profile is a VPP interface with next hops of its own, which is
// what can be set here; Linux exits and proxies have theirs generated by Gate's device sync.
func fixedExit(profile map[string]any) bool {
	_, hasInterface := profile["interface"].(string)
	return hasInterface && profile["linux_exit"] == nil && profile["fakeip_range"] == nil && profile["tproxy_port"] == nil && profile["fake_dns"] == nil
}

// SetExit sets the next hops of an exit, and of every rule that uses it. An empty name is the
// interface's own exit; another name adds an exit on the interface beside it, or moves the
// named one, and its rules, to the interface given.
func (a *Admin) SetExit(name, iface, via4, via6 string, dhcp bool, user string) (*AdminState, error) {
	iface, name = strings.TrimSpace(iface), strings.TrimSpace(name)
	if !offeredInterface.MatchString(iface) {
		return nil, fmt.Errorf("接口名 %q 不对", iface)
	}
	if name == "" {
		name = iface
	}
	if name != iface && !ruleNameRe.MatchString(name) {
		return nil, fmt.Errorf("出口名 %q 不对：只能用字母、数字、_ 和 -", name)
	}
	via, err := parseExitVia(via4, via6, dhcp)
	if err != nil {
		return nil, err
	}
	wanted := customExit{Interface: iface, Via: via, DHCP: dhcp}
	if name != iface {
		wanted.Name = name
	}
	description := fmt.Sprintf("把出口 %s 的下一跳设为 %s", name, exitViaText(wanted))
	if name != iface {
		description = fmt.Sprintf("把出口 %s 设为经 %s 到 %s", name, iface, exitViaText(wanted))
	}
	return a.changeExits(description, user, func(exits []customExit, loaded *adminRules) ([]customExit, error) {
		for _, profile := range a.allProfiles(loaded.rules) {
			exit := ruleExit(profile)
			if exit == name && !fixedExit(profile) {
				return nil, fmt.Errorf("%s 的下一跳由 Gate 的设备配置决定，不能在这里改", name)
			}
			// The exit of the interface by that name would be mistaken for this one.
			if other, _ := profile["interface"].(string); name != iface && other == name {
				return nil, fmt.Errorf("出口名 %s 是一个接口的名字，换一个", name)
			}
			if exit == name && profile["interface"] != iface && name == iface {
				return nil, fmt.Errorf("出口名 %s 已被其他接口上的出口使用", name)
			}
		}
		kept := exits[:0]
		for _, exit := range exits {
			if exit.key() != name {
				kept = append(kept, exit)
			}
		}
		if err := retargetRules(loaded.rules, wanted); err != nil {
			return nil, err
		}
		return append(kept, wanted), nil
	})
}

// DeleteExit forgets an exit set by hand. Rules keep the next hops they have.
func (a *Admin) DeleteExit(name, user string) (*AdminState, error) {
	return a.changeExits("删除手动设置的出口 "+name, user, func(exits []customExit, _ *adminRules) ([]customExit, error) {
		kept := exits[:0]
		for _, exit := range exits {
			if exit.key() != name {
				kept = append(kept, exit)
			}
		}
		if len(kept) == len(exits) {
			return nil, fmt.Errorf("没有手动设置的出口 %s", name)
		}
		return kept, nil
	})
}

func exitViaText(e customExit) string {
	parts := append([]string{}, e.Via...)
	if e.DHCP {
		parts = append([]string{"DHCP 网关"}, parts...)
	}
	return strings.Join(parts, "、")
}

// retargetRules gives every rule on the exit the new next hops, for the families it routes.
// A rule left without a next hop for one of its families stops the change.
func retargetRules(rules []map[string]any, exit customExit) error {
	byFamily := map[int]string{}
	for _, via := range exit.Via {
		if address, err := netip.ParseAddr(via); err == nil {
			if address.Is4() {
				byFamily[4] = via
			} else {
				byFamily[6] = via
			}
		}
	}
	for _, rule := range rules {
		if ruleExit(rule) != exit.key() || !fixedExit(rule) {
			continue
		}
		var via []any
		dhcp := false
		for _, family := range ruleFamilies(rule) {
			switch {
			case byFamily[family] != "":
				via = append(via, byFamily[family])
			case family == 4 && exit.DHCP && isCarrier(rule):
				dhcp = true
			case family == 4 && exit.DHCP:
				return fmt.Errorf("规则 %s 走 %s，DHCP 网关只能用于默认出口，先给它填一个 IPv4 下一跳", ruleName(rule), exit.key())
			default:
				return fmt.Errorf("规则 %s 用 IPv%d 走 %s，出口要有 IPv%d 下一跳", ruleName(rule), family, exit.key(), family)
			}
		}
		delete(rule, "via")
		delete(rule, dhcpGatewayField)
		delete(rule, exitNameField)
		rule["interface"] = exit.Interface
		if exit.key() != exit.Interface {
			rule[exitNameField] = exit.key()
		}
		switch len(via) {
		case 0:
		case 1:
			rule["via"] = via[0]
		default:
			rule["via"] = via
		}
		if dhcp {
			rule[dhcpGatewayField] = true
		}
	}
	return nil
}

// changeExits writes the exits file, and the rules with it when they change. A change to rules
// restarts Gate and waits for confirmation like any other; one that leaves them as they were
// is saved at once, as Gate does not read the file.
func (a *Admin) changeExits(description, user string, mutate func([]customExit, *adminRules) ([]customExit, error)) (*AdminState, error) {
	if a.opts.CustomExits == "" {
		return nil, errors.New("管理服务没有设置 --custom-exits")
	}
	loaded, err := a.loadRules()
	if err != nil {
		return nil, err
	}
	before, err := renderRules(loaded.doc)
	if err != nil {
		return nil, err
	}
	exits, err := a.customExits()
	if err != nil {
		return nil, err
	}
	probe, err := mutate(append([]customExit{}, exits...), loaded)
	if err != nil {
		return nil, err
	}
	after, err := renderRules(loaded.doc)
	if err != nil {
		return nil, err
	}
	if string(before) == string(after) {
		a.mu.Lock()
		if a.pending != nil {
			a.mu.Unlock()
			return nil, errors.New("a change is waiting for confirmation")
		}
		data, err := renderCustomExits(probe)
		if err == nil {
			err = writeFileAtomic(a.opts.CustomExits, data, 0o644)
		}
		if err != nil {
			a.mu.Unlock()
			return nil, err
		}
		log.Printf("audit: %s: by %s", description, user)
		a.finish(description, "applied", "", 0)
		a.mu.Unlock()
		return a.State()
	}
	return a.change(description, user, func(loaded *adminRules) (map[string][]byte, error) {
		exits, err := a.customExits()
		if err != nil {
			return nil, err
		}
		next, err := mutate(exits, loaded)
		if err != nil {
			return nil, err
		}
		loaded.custom, loaded.customSet = next, true
		rules, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		list, err := renderCustomExits(next)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{loaded.path: rules, a.opts.CustomExits: list}, nil
	})
}

// describeExits lists every exit, with the next hops a rule sent there gets, in the order the
// profiles name them.
func (a *Admin) describeExits(rules, ruleProfiles []map[string]any) []AdminExit {
	custom := map[string]bool{}
	if exits, err := a.customExits(); err == nil {
		for _, exit := range exits {
			custom[exit.key()] = true
		}
	}
	usable := map[string]bool{}
	for _, profile := range ruleProfiles {
		usable[ruleExit(profile)] = true
	}
	byName := map[string]*AdminExit{}
	var order []string
	for _, profile := range a.allProfiles(rules) {
		name := ruleExit(profile)
		if name == "" {
			continue
		}
		exit := byName[name]
		if exit == nil {
			exit = &AdminExit{Name: name, Families: []int{}, Rules: usable[name], Custom: custom[name], Editable: true}
			byName[name] = exit
			order = append(order, name)
		}
		exit.Editable = exit.Editable && fixedExit(profile)
		if iface, _ := profile["interface"].(string); exit.Interface == "" && iface != "" {
			exit.Interface = iface
		}
		if port, err := asInt(profile["tproxy_port"]); err == nil && port > 0 && exit.TProxyPort == 0 {
			exit.TProxyPort = port
			exit.Pools = anyStrings(profile["fakeip_range"])
		}
		if dhcp, _ := profile[dhcpGatewayField].(bool); dhcp && exit.Via4 == "" {
			exit.DHCP = true
		}
		for _, via := range anyStrings(profile["via"]) {
			if address, err := netip.ParseAddr(via); err == nil {
				if address.Is4() && exit.Via4 == "" && !exit.DHCP {
					exit.Via4 = via
				} else if address.Is6() && exit.Via6 == "" {
					exit.Via6 = via
				}
			}
		}
	}
	list := make([]AdminExit, 0, len(order))
	for _, name := range order {
		exit := byName[name]
		families := map[int]bool{}
		for _, profile := range ruleProfiles {
			if ruleExit(profile) == name {
				for _, family := range ruleFamilies(profile) {
					families[family] = true
				}
			}
		}
		if !exit.Rules {
			// Only the default route can go there; say what it would carry.
			families[4] = exit.DHCP || exit.Via4 != ""
			families[6] = exit.Via6 != ""
		}
		for _, family := range []int{4, 6} {
			if families[family] {
				exit.Families = append(exit.Families, family)
			}
		}
		exit.DNS = exitDNS(ruleProfiles, name)
		list = append(list, *exit)
	}
	return list
}
