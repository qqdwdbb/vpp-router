package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

// WireGuardDNS enables forwarding to the DNS Gate configured for this router.
// The other fields are resolved from Gate and VPP at start time; they are never
// accepted as panel input.
//
// A query to the tunnel's own address on port 53 is punted by VPP and redirected to
// Linux through VPPInterface, the L3 interface on the Gate listeners' link: the TAP
// itself, or the BVI of the bridge the TAP is in. Linux DNATs it to Gate and routes
// the answer back to the tunnel through VPPIPv4/VPPIPv6, VPP's own address there.
type WireGuardDNS struct {
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	VPPInterface  string `json:"vpp_interface,omitempty"`
	HostInterface string `json:"host_interface,omitempty"`
	VPPIPv4       string `json:"vpp_ipv4,omitempty"`
	VPPIPv6       string `json:"vpp_ipv6,omitempty"`
}

// complete says the forwarding was resolved by this version, so stopping can undo it
// without asking Gate and VPP again.
func (d *WireGuardDNS) complete() bool {
	return d.VPPInterface != "" && d.HostInterface != "" && (d.IPv4 != "" || d.IPv6 != "") &&
		(d.IPv4 == "") == (d.VPPIPv4 == "") && (d.IPv6 == "") == (d.VPPIPv6 == "")
}

var wgDNSInterface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,63}$`)
var wgTAPInterfaceLine = regexp.MustCompile(`^\s*Interface:\s+(tap[0-9]+)\b`)
var wgTAPNameLine = regexp.MustCompile(`^\s*name\s+"([^"]+)"\s*$`)
var wgAddrInterfaceLine = regexp.MustCompile(`^(\S+) \((?:up|dn|down)\):`)
var wgAddrL3Line = regexp.MustCompile(`^\s+L3 (\S+)`)

type wgGateFile struct {
	Listen           [][]json.RawMessage `json:"listen"`
	HijackDNS        bool                `json:"hijack_dns"`
	HijackInterfaces json.RawMessage     `json:"hijack_interfaces"`
}

type wgGateDNS struct {
	IPv4           string
	IPv6           string
	HostInterfaces []string
	HostInterface  string
}

func (a *Service) loadGateDNS() (*wgGateDNS, error) {
	path := a.opts.GateConfig
	if path == "" {
		return nil, errors.New("未配置 DNS Gate 文件")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 DNS Gate 配置失败：%w", err)
	}
	var file wgGateFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("解析 DNS Gate 配置失败：%w", err)
	}
	if !file.HijackDNS {
		return nil, errors.New("DNS Gate 未启用 DNS 劫持")
	}
	var hosts []string
	if len(file.HijackInterfaces) > 0 && string(file.HijackInterfaces) != "null" {
		if err := json.Unmarshal(file.HijackInterfaces, &hosts); err != nil {
			var host string
			if err := json.Unmarshal(file.HijackInterfaces, &host); err != nil {
				return nil, errors.New("DNS Gate 的 hijack_interfaces 无效")
			}
			hosts = []string{host}
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("DNS Gate 没有监听接口")
	}
	port := 0
	for _, item := range file.Listen {
		if len(item) != 2 {
			return nil, errors.New("DNS Gate 的 listen 项无效")
		}
		var host string
		var itemPort int
		if err := json.Unmarshal(item[0], &host); err != nil || json.Unmarshal(item[1], &itemPort) != nil || itemPort < 1 || itemPort > 65535 {
			return nil, errors.New("DNS Gate 的 listen 项无效")
		}
		if port == 0 {
			port = itemPort
		} else if port != itemPort {
			return nil, errors.New("DNS Gate 的监听端口不一致")
		}
	}
	gate := &wgGateDNS{}
	for _, item := range file.Listen {
		if len(item) != 2 {
			continue
		}
		var host string
		var itemPort int
		if json.Unmarshal(item[0], &host) != nil || json.Unmarshal(item[1], &itemPort) != nil {
			continue
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.IsUnspecified() || addr.IsLoopback() || addr.Zone() != "" {
			continue
		}
		endpoint := net.JoinHostPort(addr.String(), fmt.Sprint(itemPort))
		if addr.Is4() && gate.IPv4 == "" {
			gate.IPv4 = endpoint
		} else if addr.Is6() && gate.IPv6 == "" {
			gate.IPv6 = endpoint
		}
	}
	if gate.IPv4 == "" && gate.IPv6 == "" {
		return nil, errors.New("DNS Gate 没有可由 TAP 到达的具体监听地址")
	}
	gate.HostInterfaces = hosts
	if len(hosts) == 1 {
		gate.HostInterface = hosts[0]
	}
	return gate, nil
}

func (a *Service) resolveWGDNS() (*WireGuardDNS, error) {
	gate, err := a.loadGateDNS()
	if err != nil {
		return nil, err
	}
	output, err := a.sys.vppCLI("show tap")
	if err != nil {
		return nil, fmt.Errorf("读取 VPP TAP 对失败：%w", err)
	}
	var vppInterface string
	var hostInterface string
	currentTAP := ""
	for _, line := range strings.Split(output, "\n") {
		if match := wgTAPInterfaceLine.FindStringSubmatch(line); match != nil {
			currentTAP = match[1]
			continue
		}
		if match := wgTAPNameLine.FindStringSubmatch(strings.TrimSuffix(line, "\r")); match != nil && currentTAP != "" {
			if containsString(gate.HostInterfaces, match[1]) {
				if vppInterface != "" {
					return nil, errors.New("DNS Gate 的多个监听接口都对应 VPP TAP，无法自动选择")
				}
				vppInterface = currentTAP
				hostInterface = match[1]
			}
			currentTAP = ""
		}
	}
	if vppInterface == "" {
		return nil, fmt.Errorf("找不到与 DNS Gate 监听接口成对的 VPP TAP（%s）", strings.Join(gate.HostInterfaces, ", "))
	}
	addrs, err := a.sys.vppCLI("show interface address")
	if err != nil {
		return nil, fmt.Errorf("读取 VPP 接口地址失败：%w", err)
	}
	dns := &WireGuardDNS{IPv4: gate.IPv4, IPv6: gate.IPv6, HostInterface: hostInterface}
	for _, family := range []struct {
		listener string
		via      *string
	}{{gate.IPv4, &dns.VPPIPv4}, {gate.IPv6, &dns.VPPIPv6}} {
		if family.listener == "" {
			continue
		}
		listener, _ := netip.ParseAddrPort(family.listener)
		iface, own, err := wgLinkAddress(addrs, listener.Addr(), vppInterface)
		if err != nil {
			return nil, err
		}
		if dns.VPPInterface != "" && dns.VPPInterface != iface {
			return nil, fmt.Errorf("DNS Gate 的 IPv4 和 IPv6 监听地址在 VPP 的不同接口上（%s、%s）", dns.VPPInterface, iface)
		}
		dns.VPPInterface = iface
		*family.via = own.String()
	}
	return dns, nil
}

// wgLinkAddress finds the VPP interface whose subnet holds a Gate listener, and VPP's
// address there. A bridged TAP has no address of its own, so this is then the bridge's
// BVI, which is also what can resolve the listener's neighbour. The TAP wins a tie.
func wgLinkAddress(output string, listener netip.Addr, tap string) (string, netip.Addr, error) {
	var found []string
	var addrs []netip.Addr
	current := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if match := wgAddrInterfaceLine.FindStringSubmatch(line); match != nil {
			current = match[1]
			continue
		}
		match := wgAddrL3Line.FindStringSubmatch(line)
		if match == nil || current == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(match[1])
		if err != nil || prefix.Addr() == listener || !prefix.Masked().Contains(listener) {
			continue
		}
		if current == tap {
			return current, prefix.Addr(), nil
		}
		if !containsString(found, current) {
			found = append(found, current)
			addrs = append(addrs, prefix.Addr())
		}
	}
	switch len(found) {
	case 0:
		return "", netip.Addr{}, fmt.Errorf("VPP 没有与 DNS Gate 监听地址 %s 同网段的接口地址", listener)
	case 1:
		return found[0], addrs[0], nil
	}
	return "", netip.Addr{}, fmt.Errorf("VPP 的多个接口（%s）都与 DNS Gate 监听地址 %s 同网段，无法自动选择", strings.Join(found, ", "), listener)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func checkWGDNS(dns *WireGuardDNS) error {
	if dns == nil {
		return nil
	}
	if dns.VPPInterface == "" && dns.HostInterface == "" && dns.IPv4 == "" && dns.IPv6 == "" {
		return nil
	}
	if !wgDNSInterface.MatchString(dns.VPPInterface) || !wgDNSInterface.MatchString(dns.HostInterface) || len(dns.HostInterface) > 15 {
		return errors.New("DNS Gate 的 TAP 接口名称无效")
	}
	return nil
}

func (a *Service) UpdateWireGuardDNS(iface string, dns *WireGuardDNS, user string) (*WireGuardState, error) {
	a.mu.Lock()
	err := a.updateWireGuardDNSLocked(iface, dns, user)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

func (a *Service) updateWireGuardDNSLocked(iface string, dns *WireGuardDNS, user string) error {
	store, err := a.loadWGStore()
	if err != nil {
		return err
	}
	c := wgFindConfig(store, iface)
	if c == nil {
		return fmt.Errorf("没有配置 %q", iface)
	}
	if c.Enabled {
		return errors.New("请先停止配置，再修改 DNS 转发")
	}
	if dns != nil {
		// The panel only enables the feature. Gate listeners and the TAP pair are
		// discovered internally when the tunnel starts.
		dns = &WireGuardDNS{}
	}
	if err := checkWGDNS(dns); err != nil {
		return err
	}
	c.DNS = dns
	if err := a.saveWGStore(store); err != nil {
		return fmt.Errorf("保存 DNS 配置失败：%w", err)
	}
	log.Printf("audit: wireguard: updated DNS of %s, by %s", iface, user)
	return nil
}

// Each tunnel owns one chain. Replacing it is atomic and never flushes another
// tunnel or Gate's rules. Run before the legacy DNS frontend (priority -101).
func wgDNSBatch(c *wgStored, dns *WireGuardDNS, enabled bool) string {
	chain := c.iface()
	var batch strings.Builder
	fmt.Fprintf(&batch, "add table inet vpp_wireguard_dns\nadd chain inet vpp_wireguard_dns %s { type nat hook prerouting priority -102; policy accept; }\nflush chain inet vpp_wireguard_dns %s\n", chain, chain)
	if enabled {
		for _, own := range c.subnets() {
			family, target := "ip", dns.IPv4
			if !own.Addr().Is4() {
				family, target = "ip6", dns.IPv6
			}
			if target != "" {
				fmt.Fprintf(&batch, "add rule inet vpp_wireguard_dns %s iifname %q %s daddr %s udp dport 53 counter dnat %s to %s\n", chain, dns.HostInterface, family, own.Addr(), family, target)
			}
		}
	}
	return batch.String()
}

func wgDNSRedirects(c *wgStored, dns *WireGuardDNS, remove bool) []string {
	var commands []string
	for _, family := range []struct{ ip, target string }{{"ip", dns.IPv4}, {"ip6", dns.IPv6}} {
		if family.target == "" {
			continue
		}
		target, _ := netip.ParseAddrPort(family.target)
		del := ""
		if remove {
			del = " del"
		}
		commands = append(commands, fmt.Sprintf("%s punt redirect%s rx %s via %s %s", family.ip, del, c.iface(), target.Addr(), dns.VPPInterface))
	}
	return commands
}

// wgDNSPunts registers UDP port 53 for punting. Without it VPP answers UDP to its own
// addresses with port unreachable, so the queries never reach the punt redirect. Only
// plain UDP queries are forwarded. The registration is global and other tunnels or
// configurations may rely on it, so stopping leaves it: unclaimed UDP 53 is then
// dropped instead of refused.
func wgDNSPunts(dns *WireGuardDNS) []string {
	var commands []string
	if dns.IPv4 != "" {
		commands = append(commands, "set punt udp 53")
	}
	if dns.IPv6 != "" {
		commands = append(commands, "set punt ipv6 udp 53")
	}
	return commands
}

// wgDNSRoutes sends Linux's answers for the tunnel's subnets back to VPP. Linux may have
// its default route elsewhere, and the answers would then never reach the tunnel.
func wgDNSRoutes(c *wgStored, dns *WireGuardDNS, verb string) [][]string {
	var routes [][]string
	for _, own := range c.subnets() {
		via := dns.VPPIPv4
		if !own.Addr().Is4() {
			via = dns.VPPIPv6
		}
		if via == "" || own.IsSingleIP() {
			continue
		}
		routes = append(routes, []string{"route", verb, own.Masked().String(), "via", via, "dev", dns.HostInterface})
	}
	return routes
}

func (a *Service) startWGDNS(c *wgStored) error {
	if c.DNS == nil {
		return nil
	}
	dns, err := a.resolveWGDNS()
	if err != nil {
		return err
	}
	c.DNS = dns
	if err := a.sys.nft(wgDNSBatch(c, dns, true)); err != nil {
		return err
	}
	for _, command := range append(wgDNSPunts(dns), wgDNSRedirects(c, dns, false)...) {
		if _, err := a.sys.vppCLI(command); err != nil {
			return fmt.Errorf("设置 DNS punt 失败（%s）：%w", command, err)
		}
	}
	for _, route := range wgDNSRoutes(c, dns, "replace") {
		if err := a.sys.ip(route...); err != nil {
			return fmt.Errorf("设置 DNS 回程路由失败：%w", err)
		}
	}
	return nil
}

func (a *Service) stopWGDNS(c *wgStored) error {
	if c.DNS == nil {
		return nil
	}
	dns := c.DNS
	if !dns.complete() {
		resolved, err := a.resolveWGDNS()
		if err != nil {
			return fmt.Errorf("解析 DNS Gate 失败：%w", err)
		}
		dns = resolved
	}
	for _, route := range wgDNSRoutes(c, dns, "del") {
		if err := a.sys.ip(route...); err != nil {
			log.Printf("wireguard: removing DNS route of %s: %v", c.iface(), err)
		}
	}
	if err := a.sys.nft(wgDNSBatch(c, dns, false)); err != nil {
		return fmt.Errorf("清理 DNS 转发失败：%w", err)
	}
	for _, command := range wgDNSRedirects(c, dns, true) {
		if _, err := a.sys.vppCLI(command); err != nil {
			log.Printf("wireguard: removing DNS punt of %s: %v", c.iface(), err)
		}
	}
	return nil
}
