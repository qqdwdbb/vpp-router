package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// NAT44-EI keys a mapping by the inside FIB, not by the exit, so this project's multi-exit
// setups give each exit its own pool with the nat_ei_context plugin: "nat44 ei context IF LOOP"
// makes traffic leaving IF look as if it came in through LOOP, whose VRF N has the exit's pool,
// "nat44 ei add address A tenant-vrf N". "nat44 ei output-chain IF" goes on along the output arc
// after EI, which otherwise sends packets straight out, and "nat44 ei pool receive A IF" (patch
// 0008) pins A's receive route to IF. NAT44-ED needs none of them: it takes the pool address bound
// to the exit (patch 0034 binds an address to the outside interface that has it), goes on along
// the output arc, and each exit's own address is received by its interface. Checked on a test
// router with a WAN, a bridged loopback exit and a WireGuard exit, the RK3588 board's layout: every client
// left every exit with that exit's address, with the same MSS clamping, also after the WireGuard
// exit was restarted.
//
// So a switch to ED keeps those lines as comments marked eiOnlyMark, and a context VRF's pool
// address gets its ED line, without tenant-vrf, right after its comment. Switching back restores
// the commented lines and drops the ED line that follows one, so EI to ED to EI gives the files
// back as they were. It holds only when each exit's pool is the exit's own address, which a
// switch to ED checks.
const eiOnlyMark = "#ei-only: "

// isEIOnly is whether a NAT44 command is one of the multi-exit commands NAT44-ED does without.
func isEIOnly(f []string) bool {
	return hasWords(f, "nat44", "ei", "context") || hasWords(f, "nat44", "ei", "output-chain") ||
		hasWords(f, "nat44", "ei", "pool", "receive")
}

// tenantVRF is the VRF of an "add address ... tenant-vrf N" command, empty for none.
func tenantVRF(f []string) string {
	if !hasWords(f, "nat44", "ei", "add", "address") && !hasWords(f, "nat44", "add", "address") {
		return ""
	}
	if i := slices.Index(f, "tenant-vrf"); i > 0 && i+1 < len(f) {
		return f[i+1]
	}
	return ""
}

// withoutTenantVRF is an "add address" command without its tenant-vrf.
func withoutTenantVRF(f []string) []string {
	out := slices.Clone(f)
	if i := slices.Index(out, "tenant-vrf"); i > 0 && i+1 < len(out) {
		out = slices.Delete(out, i, i+2)
	}
	return out
}

// multiExit is the multi-exit setup of all the files and WireGuard configurations a switch looks at.
type multiExit struct {
	tables   map[string]string          // interface: its VRF, from "set interface ip table"
	contexts [][2]string                // exit interface and loopback, from "nat44 ei context"
	own      map[string]map[string]bool // interface: its IPv4 addresses
	synced   map[string]bool            // interfaces whose address is a pool address ("add interface address")
}

func newMultiExit() *multiExit {
	return &multiExit{tables: map[string]string{}, own: map[string]map[string]bool{}, synced: map[string]bool{}}
}

func (m *multiExit) addOwn(iface, prefix string) {
	p, err := netip.ParsePrefix(prefix)
	if err != nil || !p.Addr().Is4() {
		return
	}
	if m.own[iface] == nil {
		m.own[iface] = map[string]bool{}
	}
	m.own[iface][p.Addr().String()] = true
}

func (m *multiExit) scan(commands []string) {
	for _, command := range commands {
		f := cliFields(command)
		if slices.Contains(f, "del") {
			continue
		}
		switch {
		case len(f) == 6 && hasWords(f, "set", "interface", "ip", "table"):
			m.tables[f[4]] = f[5]
		case len(f) == 6 && hasWords(f, "set", "interface", "ip", "address"):
			m.addOwn(f[4], f[5])
		case len(f) == 5 && hasWords(f, "nat44", "ei", "context"):
			m.contexts = append(m.contexts, [2]string{f[3], f[4]})
		case len(f) == 6 && hasWords(f, "nat44", "ei", "add", "interface", "address"):
			m.synced[f[5]] = true
		case len(f) == 5 && hasWords(f, "nat44", "add", "interface", "address"):
			m.synced[f[4]] = true
		}
	}
}

// exitOf is the exit interface whose context VRF vrf is.
func (m *multiExit) exitOf(vrf string) (string, bool) {
	for _, c := range m.contexts {
		if table, ok := m.tables[c[1]]; ok && table == vrf {
			return c[0], true
		}
	}
	return "", false
}

// edProblem is why a NAT44-EI command cannot become NAT44-ED's way, empty when it can.
func (m *multiExit) edProblem(f []string) string {
	switch {
	case hasWords(f, "nat44", "ei", "context"):
		if len(f) >= 5 {
			if _, ok := m.tables[f[4]]; !ok {
				return fmt.Sprintf("找不到 %s 的路由表（set interface ip table），不知道哪个地址池属于 %s", f[4], f[3])
			}
		}
	case hasWords(f, "nat44", "ei", "pool", "receive"):
		if len(f) >= 6 && !m.own[f[5]][f[4]] && !m.synced[f[5]] {
			return fmt.Sprintf("%s 不是 %s 自己的地址；NAT44-ED 只认出口自己的地址", f[4], f[5])
		}
	default:
		if vrf := tenantVRF(f); vrf != "" {
			if exit, ok := m.exitOf(vrf); ok && len(f) > 4 && !m.own[exit][f[4]] {
				return fmt.Sprintf("%s 不是出口 %s 自己的地址；NAT44-ED 按出口自己的地址选择", f[4], exit)
			}
		}
	}
	return ""
}

// toED is a NAT44-EI command's lines in NAT44-ED's way: an EI-only command becomes a marked
// comment, and a context VRF's pool address its marked line and its plain ED line.
func (m *multiExit) toED(line string, f []string) ([]string, bool) {
	indent := leadingSpace.FindString(line)
	if isEIOnly(f) {
		return []string{indent + eiOnlyMark + strings.Join(f, " ")}, true
	}
	if vrf := tenantVRF(f); vrf != "" {
		if _, ok := m.exitOf(vrf); ok {
			plain, ok := translateNAT(withoutTenantVRF(f), natED)
			if !ok {
				return nil, false
			}
			return []string{indent + eiOnlyMark + strings.Join(f, " "), indent + strings.Join(plain, " ")}, true
		}
	}
	translated, ok := translateNAT(f, natED)
	if !ok {
		return nil, false
	}
	return []string{indent + strings.Join(translated, " ")}, true
}

// restoredEI is the command a marked comment keeps, and the ED line that came with it, if any.
func restoredEI(line string) (restored string, edLine []string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, eiOnlyMark) {
		return "", nil, false
	}
	command := strings.TrimSpace(strings.TrimPrefix(trimmed, eiOnlyMark))
	f := cliFields(command)
	if tenantVRF(f) != "" {
		edLine, _ = translateNAT(withoutTenantVRF(f), natED)
	}
	return leadingSpace.FindString(line) + command, edLine, true
}
