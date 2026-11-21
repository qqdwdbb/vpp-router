package gate

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

var (
	fibTableRe = regexp.MustCompile(`ipv[46]-VRF:(\d+)\b`)
	fibSplitRe = regexp.MustCompile(`(?m)^([0-9a-fA-F:.]+/\d+)(?:[^\n]*)\n`)
	fibViaRe   = regexp.MustCompile(`(?m)^    \[\d+\] \[@\d+\]: ipv[46][^\n]*?\bvia (\S+) ([^\s:]+)`)
)

func parseFIB(text string, table uint32) (map[RouteKey]PathSet, error) {
	if !regexp.MustCompile(`ipv[46]-VRF:` + fmt.Sprint(table) + `\b`).MatchString(text) {
		return nil, fmt.Errorf("VPP table %d was not returned", table)
	}
	result := map[RouteKey]PathSet{}
	indexes := fibSplitRe.FindAllStringSubmatchIndex(text, -1)
	for i, loc := range indexes {
		prefix := text[loc[2]:loc[3]]
		n, err := parsePrefixStrict(prefix)
		if err != nil {
			continue
		}
		end := len(text)
		if i+1 < len(indexes) {
			end = indexes[i+1][0]
		}
		body := text[loc[1]:end]
		paths := PathSet{}
		for _, m := range fibViaRe.FindAllStringSubmatch(body, -1) {
			via, err := parseAddr(m[1])
			if err != nil {
				continue
			}
			paths[Path{via.String(), m[2]}] = struct{}{}
		}
		key := RouteKey{table, prefixString(n)}
		if len(paths) == 0 && isKnownDrop(key) {
			continue
		}
		result[key] = paths
	}
	return result, nil
}

func usesTProxy(cfg *Config) bool {
	for _, m := range cfg.Mappings {
		if m.Enabled && m.TProxyPort > 0 {
			return true
		}
	}
	return false
}

// TProxyListen intercepts a pool or all real addresses arriving on a dedicated interface.
type TProxyListen struct {
	Interface string
	Prefix    netip.Prefix
	Port      int
	// Address is where the proxy listens; unset means any local address.
	Address netip.Addr
}

func tproxyPortRules(cfg *Config) []TProxyListen {
	var out []TProxyListen
	seen := map[string]struct{}{}
	for _, m := range cfg.Mappings {
		if !m.Enabled || m.TProxyPort == 0 {
			continue
		}
		pools := m.EachFakeIP()
		if m.RealAddresses {
			for _, family := range []int{4, 6} {
				if m.ViaFor(family) != "" {
					pool := "0.0.0.0/0"
					if family == 6 {
						pool = "::/0"
					}
					pools = append(pools, pool)
				}
			}
		}
		for _, pool := range pools {
			prefix, err := parsePrefixStrict(pool)
			if err != nil {
				continue
			}
			var address netip.Addr
			for _, a := range m.TProxyAddress {
				if a.Is6() == prefix.Addr().Is6() {
					address = a
				}
			}
			key := m.TProxyInterface + "|" + prefixString(prefix) + "|" + fmt.Sprint(m.TProxyPort) + "|" + address.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, TProxyListen{Interface: m.TProxyInterface, Prefix: prefix, Port: m.TProxyPort, Address: address})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Prefix.Bits() == 0) != (out[j].Prefix.Bits() == 0) {
			return out[i].Prefix.Bits() != 0
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return prefixString(out[i].Prefix) < prefixString(out[j].Prefix)
	})
	return out
}

func tproxyPortClearScript() []string {
	return []string{
		"flush chain inet egress_gate gate_tproxy",
		"delete chain inet egress_gate gate_tproxy",
	}
}

func tproxyPortNftScript(rules []TProxyListen) []string {
	if len(rules) == 0 {
		return tproxyPortClearScript()
	}
	var b strings.Builder
	b.WriteString("table inet egress_gate {\n")
	b.WriteString("  chain gate_tproxy {\n")
	b.WriteString("    type filter hook prerouting priority mangle - 1; policy accept;\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	b.WriteString("flush chain inet egress_gate gate_tproxy\n")
	b.WriteString("table inet egress_gate {\n")
	b.WriteString("  chain gate_tproxy {\n")
	b.WriteString("    fib daddr type local return\n")
	for _, rule := range rules {
		fam := "ip"
		if rule.Prefix.Addr().Is6() {
			fam = "ip6"
		}
		iif := ""
		if rule.Interface != "" {
			iif = fmt.Sprintf("iifname %q ", rule.Interface)
		}
		to := fmt.Sprintf(":%d", rule.Port)
		if rule.Address.IsValid() {
			to = netip.AddrPortFrom(rule.Address, uint16(rule.Port)).String()
		}
		fmt.Fprintf(&b, "    %s%s daddr %s meta l4proto { tcp, udp } tproxy %s to %s meta mark set 1 ct mark set 1 accept\n",
			iif, fam, prefixString(rule.Prefix), fam, to)
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return []string{strings.TrimSuffix(b.String(), "\n")}
}

func dnsHijackNftScript(ifaces []string, port int) []string {
	if len(ifaces) == 0 || port < 1 {
		return nil
	}
	quoted := make([]string, len(ifaces))
	for i, name := range ifaces {
		quoted[i] = fmt.Sprintf("%q", name)
	}
	iif := quoted[0]
	if len(quoted) > 1 {
		iif = "{ " + strings.Join(quoted, ", ") + " }"
	}
	var b strings.Builder
	b.WriteString("table inet egress_gate {\n")
	b.WriteString("  chain hijack {\n")
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	fmt.Fprintf(&b, "    iifname %s meta l4proto { tcp, udp } th dport 53 redirect to :%d\n", iif, port)
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return []string{strings.TrimSuffix(b.String(), "\n")}
}

func dnsHijackClearScript() []string {
	return []string{
		"flush chain inet egress_gate hijack",
		"delete chain inet egress_gate hijack",
	}
}

func syncDNSHijack(g *GateFile) error {
	if g == nil || !g.HijackDNS {
		return clearDNSHijack()
	}
	return applyNft(dnsHijackNftScript(g.HijackInterfaces, g.Listen[0].Port), "DNS hijack")
}

func clearDNSHijack() error {
	return clearNftChain(context.Background(), "hijack", dnsHijackClearScript(), "DNS hijack")
}
