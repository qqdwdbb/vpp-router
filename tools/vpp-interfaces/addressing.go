package main

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// How an interface gets its addresses, per family. IPv4 is static or DHCP; IPv6 is static,
// SLAAC or DHCPv6. DHCPv6 gives addresses only, so it runs with router advertisements for
// the default route, as SLAAC does; a prefix the router marks autonomous then also gets an
// address, as on any host.
const (
	modeNone   = "none"
	modeStatic = "static"
	modeDHCP   = "dhcp"
	modeSLAAC  = "slaac"
	modeDHCP6  = "dhcpv6"
	// modePPPoE is the IPv4 of a PPPoX interface, which its creating line gives it; see pppoe.go.
	modePPPoE = "pppoe"
)

// Family is one family's addressing, as the file has it and as a change asks for it.
type Family struct {
	Mode      string   `json:"mode"`
	Addresses []string `json:"addresses"` // static only
	Gateway   string   `json:"gateway"`   // static only; the default route through this interface
	Hostname  string   `json:"hostname"`  // IPv4 DHCP only
}

// familyKinds are the kinds of line that hold a family's addressing.
func familyKinds(v6 bool) []lineKind {
	if v6 {
		return []lineKind{lineAddress, lineSLAAC, lineDHCP6, lineGateway}
	}
	return []lineKind{lineAddress, lineDHCP4, lineGateway, linePPPoE}
}

// familyLines are the indexes of iface's lines for one family.
func familyLines(file *cliFile, iface string, v6 bool) []int {
	var found []int
	for _, i := range file.own(iface, familyKinds(v6)...) {
		line := file.lines[i]
		switch line.kind {
		case lineAddress:
			if line.prefix.Addr().Is6() != v6 {
				continue
			}
		case lineGateway:
			if line.via.Is6() != v6 {
				continue
			}
		}
		found = append(found, i)
	}
	return found
}

type familyConfig struct {
	mode      string
	addresses []netip.Prefix
	gateway   netip.Addr
	hostname  string
}

func (c familyConfig) equal(o familyConfig) bool {
	return c.mode == o.mode && slices.Equal(c.addresses, o.addresses) && c.gateway == o.gateway && c.hostname == o.hostname
}

func (c familyConfig) view() Family {
	f := Family{Mode: c.mode, Addresses: prefixStrings(c.addresses), Hostname: c.hostname}
	if c.gateway.IsValid() {
		f.Gateway = c.gateway.String()
	}
	return f
}

// fileFamily reads one family's addressing of iface from the file.
func fileFamily(file *cliFile, iface string, v6 bool) familyConfig {
	c := familyConfig{mode: modeNone}
	var dhcp4, slaac, dhcp6, pppoe bool
	for _, i := range familyLines(file, iface, v6) {
		line := file.lines[i]
		switch line.kind {
		case lineAddress:
			c.addresses = append(c.addresses, line.prefix)
		case lineGateway:
			c.gateway = line.via
		case lineDHCP4:
			dhcp4, c.hostname = true, line.host
		case lineSLAAC:
			slaac = true
		case lineDHCP6:
			dhcp6 = true
		case linePPPoE:
			pppoe = true
		}
	}
	switch {
	case pppoe:
		c.mode = modePPPoE
	case dhcp4:
		c.mode = modeDHCP
	case dhcp6:
		c.mode = modeDHCP6
	case slaac:
		c.mode = modeSLAAC
	case len(c.addresses) > 0:
		c.mode = modeStatic
	}
	return c
}

// dynamic tells whether a family's addresses come from the network.
func (c familyConfig) dynamic() bool {
	return c.mode == modeDHCP || c.mode == modeSLAAC || c.mode == modeDHCP6 || c.mode == modePPPoE
}

// addressed tells whether the file gives iface any addressing.
func addressed(file *cliFile, iface string) bool {
	return fileFamily(file, iface, false).mode != modeNone || fileFamily(file, iface, true).mode != modeNone
}

var hostnameText = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

var modeNames = map[string]string{modeNone: "不配置", modeStatic: "静态", modeDHCP: "DHCP", modeSLAAC: "SLAAC", modeDHCP6: "DHCPv6", modePPPoE: "PPPoE"}

// parseFamily checks what a change asks for one family.
func parseFamily(request Family, v6 bool) (familyConfig, error) {
	c := familyConfig{mode: request.Mode}
	family := "IPv4"
	if v6 {
		family = "IPv6"
	}
	switch c.mode {
	case modeNone:
	case modeStatic:
		addresses, err := parsePrefixes(request.Addresses)
		if err != nil {
			return c, err
		}
		if len(addresses) == 0 {
			return c, errors.New("静态方式至少要有一个地址")
		}
		for _, prefix := range addresses {
			if prefix.Addr().Is6() != v6 {
				return c, fmt.Errorf("%s 不是 %s 地址", prefix, family)
			}
		}
		c.addresses = addresses
		if text := strings.TrimSpace(request.Gateway); text != "" {
			gateway, err := netip.ParseAddr(text)
			if err != nil || gateway.Is6() != v6 || gateway.Is4In6() {
				return c, fmt.Errorf("网关 %q 不是 %s 地址", text, family)
			}
			if slices.ContainsFunc(addresses, func(p netip.Prefix) bool { return p.Addr() == gateway }) {
				return c, fmt.Errorf("网关 %s 是接口自己的地址", gateway)
			}
			// An IPv6 router is often reached by its link-local address.
			if !(v6 && gateway.IsLinkLocalUnicast()) && !slices.ContainsFunc(addresses, func(p netip.Prefix) bool { return p.Masked().Contains(gateway) }) {
				return c, fmt.Errorf("网关 %s 不在接口的任何网段里", gateway)
			}
			c.gateway = gateway
		}
	case modeDHCP:
		if v6 {
			return c, errors.New("IPv6 用 SLAAC 或 DHCPv6")
		}
		if host := strings.TrimSpace(request.Hostname); host != "" {
			if !hostnameText.MatchString(host) {
				return c, fmt.Errorf("主机名 %q 只能用字母、数字和连字符", host)
			}
			c.hostname = host
		}
	case modeSLAAC, modeDHCP6:
		if !v6 {
			return c, errors.New("SLAAC 和 DHCPv6 只用于 IPv6")
		}
	case modePPPoE:
		return c, errors.New("PPPoE 拨号在“新建接口”里选 PPPoE，在以太网口或 VLAN 子接口上新建拨号接口")
	default:
		return c, fmt.Errorf("不认识的方式 %q", c.mode)
	}
	return c, nil
}

// SetFamily sets how an interface gets its addresses in one family.
func (s *Service) SetFamily(name string, v6 bool, request Family, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		wanted, err := parseFamily(request, v6)
		if err != nil {
			return nil, err
		}
		family := "IPv4"
		if v6 {
			family = "IPv6"
		}
		bd, bvi := fileBridge(file, name)
		if wanted.mode != modeNone && ((iface.Bridge != 0 && !iface.BVI) || (bd != 0 && !bvi)) {
			return nil, fmt.Errorf("%s 在网桥里，二层接口不能有地址，先把它移出网桥", name)
		}
		if wanted.dynamic() && kindOf(iface) == "loopback" {
			return nil, fmt.Errorf("%s 是 loopback，没有链路，不能用 %s", name, modeNames[wanted.mode])
		}
		for _, other := range live.Interfaces {
			if other.Name == name {
				continue
			}
			for _, theirs := range other.Addresses {
				for _, mine := range wanted.addresses {
					if theirs.Overlaps(mine) {
						return nil, fmt.Errorf("%s 和 %s 的地址 %s 重叠", mine, other.Name, theirs)
					}
				}
			}
		}
		old := fileFamily(file, name, v6)
		if old.mode == modePPPoE {
			return nil, fmt.Errorf("%s 的 IPv4 由 PPPoE 拨号获得；改账号在 PPPoE 一栏，不用了就删除这个接口", name)
		}
		if old.equal(wanted) {
			return nil, fmt.Errorf("%s 没有变化", family)
		}
		c := &change{file: file, steps: familySteps(name, v6, old, wanted, iface.Addresses)}

		var lines []string
		switch wanted.mode {
		case modeStatic:
			for _, prefix := range wanted.addresses {
				lines = append(lines, addressCommand(name, prefix, false))
			}
			if wanted.gateway.IsValid() {
				lines = append(lines, gatewayCommand(name, wanted.gateway, false))
			}
		case modeDHCP:
			lines = append(lines, dhcp4Command(name, wanted.hostname, false))
		case modeSLAAC:
			lines = append(lines, slaacCommand(name, false))
		case modeDHCP6:
			lines = append(lines, slaacCommand(name, false), dhcp6Command(name, false))
		}
		at := -1
		if previous := familyLines(file, name, v6); len(previous) > 0 {
			at = previous[0]
			file.remove(previous...)
		} else {
			at = file.insertionPoint(name)
		}
		file.insert(at, lines...)

		c.description = fmt.Sprintf("把 %s 的 %s 改成 %s", name, family, modeNames[wanted.mode])
		if wanted.mode == modeStatic {
			c.description += " " + strings.Join(prefixStrings(wanted.addresses), "、")
			if wanted.gateway.IsValid() {
				c.description += "，网关 " + wanted.gateway.String()
			}
		}
		if wanted.mode == modeDHCP && wanted.hostname != "" {
			c.description += "，主机名 " + wanted.hostname
		}
		return c, nil
	})
}

// familySteps are the live commands taking one family from old to wanted: the old way is
// taken down first, then the new one is set up, and parts that stay the same are left alone.
// live is what the interface has now, so addresses it does not have are not deleted.
func familySteps(name string, v6 bool, old, wanted familyConfig, live []netip.Prefix) []step {
	var steps []step
	ra := func(c familyConfig) bool { return c.mode == modeSLAAC || c.mode == modeDHCP6 }
	// Down.
	if old.mode == modeDHCP && (wanted.mode != modeDHCP || wanted.hostname != old.hostname) {
		steps = append(steps, step{dhcp4Command(name, "", true), dhcp4Command(name, old.hostname, false)})
	}
	if old.mode == modeDHCP6 && wanted.mode != modeDHCP6 {
		steps = append(steps, step{dhcp6Command(name, true), dhcp6Command(name, false)})
	}
	if ra(old) && !ra(wanted) {
		steps = append(steps, step{slaacCommand(name, true), slaacCommand(name, false)})
	}
	if old.mode == modeStatic {
		if old.gateway.IsValid() && (wanted.mode != modeStatic || wanted.gateway != old.gateway) {
			steps = append(steps, step{gatewayCommand(name, old.gateway, true), gatewayCommand(name, old.gateway, false)})
		}
		for _, prefix := range old.addresses {
			if (wanted.mode != modeStatic || !slices.Contains(wanted.addresses, prefix)) && slices.Contains(live, prefix) {
				steps = append(steps, step{addressCommand(name, prefix, true), addressCommand(name, prefix, false)})
			}
		}
	}
	// Up. Taking a dynamic way down removes the addresses it got, even one the new static
	// configuration asks for, so those are not there any more.
	if old.dynamic() {
		live = slices.DeleteFunc(slices.Clone(live), func(p netip.Prefix) bool { return p.Addr().Is6() == v6 })
	}
	switch wanted.mode {
	case modeStatic:
		for _, prefix := range wanted.addresses {
			if !slices.Contains(live, prefix) {
				steps = append(steps, step{addressCommand(name, prefix, false), addressCommand(name, prefix, true)})
			}
		}
		if wanted.gateway.IsValid() && (old.mode != modeStatic || old.gateway != wanted.gateway) {
			steps = append(steps, step{gatewayCommand(name, wanted.gateway, false), gatewayCommand(name, wanted.gateway, true)})
		}
	case modeDHCP:
		if old.mode != modeDHCP || old.hostname != wanted.hostname {
			steps = append(steps, step{dhcp4Command(name, wanted.hostname, false), dhcp4Command(name, "", true)})
		}
	case modeSLAAC, modeDHCP6:
		if !ra(old) {
			steps = append(steps, step{slaacCommand(name, false), slaacCommand(name, true)})
		}
		if wanted.mode == modeDHCP6 && old.mode != modeDHCP6 {
			steps = append(steps, step{dhcp6Command(name, false), dhcp6Command(name, true)})
		}
	}
	return steps
}
