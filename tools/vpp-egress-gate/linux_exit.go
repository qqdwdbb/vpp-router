package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// LinuxExit describes an administratively dedicated policy table and rule. Each exit
// has its own input device, a TAP or a TUN: the VPP route picks the device, and the
// device picks the exit, so Linux holds no per-destination state. Gate treats both
// kinds alike. Devices, addresses, forwarding sysctls and return routes are provisioned externally.
type LinuxExit struct {
	InputInterface string `json:"input_interface"`
	Interface      string `json:"interface"`
	Table          uint32 `json:"table"`
	Mark           uint32 `json:"mark"`
	Priority       uint32 `json:"priority"`
	Gateway        string `json:"gateway,omitempty"`
	Gateway6       string `json:"gateway6,omitempty"`
	Masquerade     bool   `json:"masquerade,omitempty"`
	// BlockInput is opt-in because it can cut remote management or a tunnel listener on the exit.
	BlockInput bool `json:"block_input,omitempty"`
	// DNSDirect keeps the route's dns upstream on the main table, for a resolver that is not behind the exit.
	DNSDirect bool `json:"dns_direct,omitempty"`
}

func validateLinuxExits(cfg *Config) error {
	marks, tables, priorities := map[uint32]bool{}, map[uint32]bool{}, map[uint32]bool{}
	for i := range cfg.Mappings {
		m := &cfg.Mappings[i]
		e := m.LinuxExit
		if e == nil {
			continue
		}
		if !ifaceRe.MatchString(e.Interface) || !ifaceRe.MatchString(e.InputInterface) || e.Interface == e.InputInterface {
			return fmt.Errorf("linux_exit requires distinct valid Linux input_interface and interface")
		}
		if e.Table < 256 || e.Mark < 2 || e.Priority == 0 || e.Priority >= 32766 || marks[e.Mark] || tables[e.Table] || priorities[e.Priority] {
			return fmt.Errorf("linux_exit requires unique table >= 256, mark >= 2 and priority in 1..32765")
		}
		marks[e.Mark], tables[e.Table], priorities[e.Priority] = true, true, true
		if m.HasFakeIP() || m.TProxyPort != 0 {
			return fmt.Errorf("linux_exit cannot be combined with Fake-IP or TPROXY")
		}
		for family, gateway := range map[int]string{4: e.Gateway, 6: e.Gateway6} {
			if gateway != "" && (viaFamily(gateway) != family || m.ViaFor(family) == "") {
				return fmt.Errorf("linux_exit gateway family must match via")
			}
		}
		for _, other := range cfg.Mappings {
			if other.Key() == m.Key() {
				continue
			}
			// Several gateways of one Linux interface may share a TAP. Each enters
			// Linux on a macvlan of its own, so the input interface still tells them apart.
			sharedTAP := other.LinuxExit != nil && other.LinuxExit.Interface == e.Interface && other.LinuxExit.InputInterface != e.InputInterface
			if other.Interface == m.Interface && !sharedTAP {
				return fmt.Errorf("linux_exit requires its own VPP interface, %s has other routes", m.Interface)
			}
			if other.LinuxExit != nil && (other.LinuxExit.InputInterface == e.InputInterface || other.LinuxExit.Interface == e.InputInterface) {
				return fmt.Errorf("linux_exit requires its own Linux input interface, %s is used by another exit", e.InputInterface)
			}
			if other.TProxyInterface == e.InputInterface {
				return fmt.Errorf("Linux forwarding device must be separate from TPROXY device")
			}
		}
	}
	return nil
}

func hasLinuxExits(cfg *Config) bool {
	for _, m := range cfg.Mappings {
		if m.Enabled && m.LinuxExit != nil {
			return true
		}
	}
	return false
}

// Replacing only our table in one nft transaction preserves external firewall objects.
func linuxExitNftScript(cfg *Config, mtus map[string]int) string {
	var b strings.Builder
	b.WriteString("add table inet egress_gate_linux\ndelete table inet egress_gate_linux\ntable inet egress_gate_linux {\n")
	b.WriteString(" chain classify { type filter hook prerouting priority mangle - 2; policy accept;\n fib daddr type local return\n")
	for _, m := range cfg.Mappings {
		if !m.Enabled || m.LinuxExit == nil {
			continue
		}
		e := m.LinuxExit
		for _, family := range []int{4, 6} {
			if m.ViaFor(family) == "" {
				continue
			}
			nfproto := "ipv4"
			if family == 6 {
				nfproto = "ipv6"
			}
			fmt.Fprintf(&b, " iifname %q meta nfproto %s meta mark set %d return\n", e.InputInterface, nfproto, e.Mark)
		}
		// A family without a next hop has no policy rule, so it must not carry the mark.
		fmt.Fprintf(&b, " iifname %q meta mark set 0\n", e.InputInterface)
	}
	b.WriteString(" }\n chain forward { type filter hook forward priority filter; policy accept;\n")
	// Clamp before any accept. "rt mtu" follows the policy route towards the exit,
	// but for replies it sees only the TAP and the main table, so those need the exit's MTU.
	for _, m := range cfg.Mappings {
		if !m.Enabled || m.LinuxExit == nil {
			continue
		}
		e := m.LinuxExit
		fmt.Fprintf(&b, " iifname %q oifname %q meta mark %d %s set rt mtu\n", e.InputInterface, e.Interface, e.Mark, linuxExitMSSMatch)
		for _, family := range []int{4, 6} {
			if m.ViaFor(family) == "" {
				continue
			}
			nfproto, headers := "ipv4", 40
			if family == 6 {
				nfproto, headers = "ipv6", 60
			}
			if mss := mtus[e.Interface] - headers; mss > 0 {
				fmt.Fprintf(&b, " iifname %q oifname %q meta nfproto %s %s set %d\n", e.Interface, e.InputInterface, nfproto, linuxExitMSSMatch, mss)
			}
		}
	}
	for _, m := range cfg.Mappings {
		if !m.Enabled || m.LinuxExit == nil {
			continue
		}
		e := m.LinuxExit
		fmt.Fprintf(&b, " iifname %q oifname %q meta mark %d accept\n", e.InputInterface, e.Interface, e.Mark)
	}
	// Exits often face a public network: forward only replies and explicit DNAT from them.
	forwarded := map[string]bool{}
	for _, m := range cfg.Mappings {
		if !m.Enabled || m.LinuxExit == nil || forwarded[m.LinuxExit.Interface] {
			continue
		}
		forwarded[m.LinuxExit.Interface] = true
		name := m.LinuxExit.Interface
		fmt.Fprintf(&b, " iifname %q ct state established,related accept\n iifname %q ct status dnat accept\n iifname %q drop\n", name, name, name)
	}
	for _, m := range cfg.Mappings {
		if m.Enabled && m.LinuxExit != nil {
			fmt.Fprintf(&b, " iifname %q drop\n", m.LinuxExit.InputInterface)
		}
	}
	var input strings.Builder
	blocked := map[string]bool{}
	for _, m := range cfg.Mappings {
		if !m.Enabled || m.LinuxExit == nil || !m.LinuxExit.BlockInput || blocked[m.LinuxExit.Interface] {
			continue
		}
		blocked[m.LinuxExit.Interface] = true
		name := m.LinuxExit.Interface
		// Neighbor discovery is untracked, so it must be allowed before the final drop.
		fmt.Fprintf(&input, " iifname %q ct state established,related accept\n iifname %q ct status dnat accept\n iifname %q icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept\n iifname %q drop\n", name, name, name, name)
	}
	// A marked DNS socket must never leave elsewhere, such as while its policy rule is
	// missing. Transit traffic with these marks does not pass this hook.
	var output strings.Builder
	for _, m := range cfg.Mappings {
		if m.Enabled && m.LinuxExit != nil {
			fmt.Fprintf(&output, " meta mark %d oifname != %q oifname != \"lo\" drop\n", m.LinuxExit.Mark, m.LinuxExit.Interface)
		}
	}
	if output.Len() > 0 {
		b.WriteString(" }\n chain output { type filter hook output priority filter; policy accept;\n")
		b.WriteString(output.String())
	}
	if input.Len() > 0 {
		b.WriteString(" }\n chain input { type filter hook input priority filter; policy accept;\n")
		b.WriteString(input.String())
	}
	b.WriteString(" }\n chain nat { type nat hook postrouting priority srcnat; policy accept;\n")
	for _, m := range cfg.Mappings {
		if !m.Enabled || m.LinuxExit == nil || !m.LinuxExit.Masquerade {
			continue
		}
		e := m.LinuxExit
		fmt.Fprintf(&b, " iifname %q oifname %q meta mark %d masquerade\n", e.InputInterface, e.Interface, e.Mark)
	}
	b.WriteString(" }\n}\n")
	return b.String()
}

type linuxExitState struct {
	ready  bool
	status map[string]string
	mtus   map[string]int
}

var linuxExitMu sync.Mutex
var linuxExitStates = map[string]*linuxExitState{}

const (
	linuxExitRouteMetric    = 100
	linuxExitFallbackMetric = 32767
	// Matches both SYN and SYN-ACK. The kernel only ever lowers the option.
	linuxExitMSSMatch = "tcp flags & (syn|rst) == syn tcp option maxseg size"
)

func parseLinuxNumber(raw json.RawMessage) uint64 {
	s := strings.Trim(string(raw), "\"")
	base := 10
	if strings.HasPrefix(s, "0x") {
		base = 0
	}
	n, _ := strconv.ParseUint(s, base, 64)
	return n
}

// linuxExitRulesPresent reports which of this exit's two rules exist: transit
// traffic from the TAP, and local DNS sockets ("iif lo"). Another rule at the
// priority, or another rule reading the table, means they are not dedicated.
func linuxExitRulesPresent(text string, e *LinuxExit, family int) (transit, local bool, err error) {
	var rules []struct {
		Priority uint32          `json:"priority"`
		Mark     json.RawMessage `json:"fwmark"`
		Mask     json.RawMessage `json:"fwmask"`
		Table    json.RawMessage `json:"table"`
		IIF      string          `json:"iif"`
	}
	if strings.TrimSpace(text) != "" {
		if err := json.Unmarshal([]byte(text), &rules); err != nil {
			return false, false, err
		}
	}
	for _, r := range rules {
		if r.Priority != e.Priority {
			if parseLinuxNumber(r.Table) == uint64(e.Table) {
				return false, false, fmt.Errorf("Linux IPv%d table %d is occupied by rule priority %d", family, e.Table, r.Priority)
			}
			continue
		}
		if parseLinuxNumber(r.Mark) != uint64(e.Mark) || parseLinuxNumber(r.Table) != uint64(e.Table) || (len(r.Mask) > 0 && parseLinuxNumber(r.Mask) != 0xffffffff) || (r.IIF != e.InputInterface && r.IIF != "lo") {
			return false, false, fmt.Errorf("Linux IPv%d rule priority %d is occupied", family, e.Priority)
		}
		if r.IIF == "lo" {
			local = true
		} else {
			transit = true
		}
	}
	return transit, local, nil
}

// checkLinuxExitTable accepts only the two default routes this exit installs.
// A lower-metric foreign route would otherwise silently win the policy lookup.
func checkLinuxExitTable(text string, e *LinuxExit, family int) error {
	var routes []struct {
		Type   string `json:"type"`
		Dst    string `json:"dst"`
		Dev    string `json:"dev"`
		Metric uint32 `json:"metric"`
	}
	if strings.TrimSpace(text) != "" {
		if err := json.Unmarshal([]byte(text), &routes); err != nil {
			return err
		}
	}
	for _, r := range routes {
		isDefault := r.Dst == "default" || r.Dst == "0.0.0.0/0" || r.Dst == "::/0"
		fallback := r.Type == "unreachable" && r.Metric == linuxExitFallbackMetric
		exit := (r.Type == "" || r.Type == "unicast") && r.Metric == linuxExitRouteMetric && r.Dev == e.Interface
		if !isDefault || (!fallback && !exit) {
			return fmt.Errorf("Linux IPv%d table %d is occupied by route %s dev %s metric %d", family, e.Table, r.Dst, r.Dev, r.Metric)
		}
	}
	return nil
}

// exitRouteListed says whether a table listing holds the exit's own default route.
func exitRouteListed(text string) bool {
	var routes []struct {
		Type   string `json:"type"`
		Dst    string `json:"dst"`
		Metric uint32 `json:"metric"`
	}
	if !decodeListing(text, &routes) {
		return true
	}
	for _, r := range routes {
		if (r.Type == "" || r.Type == "unicast") && r.Metric == linuxExitRouteMetric {
			return true
		}
	}
	return false
}

// linuxIPv6Router is the next hop of the main table's IPv6 default route on an interface,
// usually learned from router advertisements, or "" when it has none.
func linuxIPv6Router(ctx context.Context, iface string) (string, error) {
	text, err := runCmdContext(ctx, "ip", "-j", "-6", "route", "show", "default", "dev", iface)
	if err != nil {
		if linkMissing(ctx, iface) {
			return "", nil
		}
		return "", err
	}
	var routes []struct {
		Type    string `json:"type"`
		Gateway string `json:"gateway"`
		Metric  uint32 `json:"metric"`
	}
	if !decodeListing(text, &routes) {
		return "", fmt.Errorf("cannot read the IPv6 default routes of %s", iface)
	}
	best, metric := "", uint32(0)
	for _, r := range routes {
		if (r.Type == "" || r.Type == "unicast") && r.Gateway != "" && (best == "" || r.Metric < metric) {
			best, metric = r.Gateway, r.Metric
		}
	}
	return best, nil
}

// linuxExitHasIPv6 says whether a Linux exit can carry IPv6 now: it has a global IPv6
// address and, when it is reached through a gateway, an IPv6 router or gateway6.
// Replaced by tests, which must not read the host's interfaces.
var linuxExitHasIPv6 = linuxExitHasIPv6Real

func linuxExitHasIPv6Real(ctx context.Context, iface string, gateway bool, gateway6 string) bool {
	if gateway6 != "" {
		return true
	}
	text, err := runCmdContext(ctx, "ip", "-j", "-6", "address", "show", "dev", iface, "scope", "global")
	if err != nil {
		return false
	}
	var links []struct {
		Addresses []struct {
			Local  string `json:"local"`
			Failed bool   `json:"dadfailed"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(text), &links) != nil {
		return false
	}
	found := false
	for _, link := range links {
		for _, a := range link.Addresses {
			if address, err := netip.ParseAddr(a.Local); err == nil && address.Is6() && !a.Failed {
				found = true
			}
		}
	}
	if !found || !gateway {
		return found
	}
	router, err := linuxIPv6Router(ctx, iface)
	return err == nil && router != ""
}

// Replaced by tests, which must never touch the host's sysctls.
var linuxSysctlRoot = "/proc/sys"

// ensureLinuxExitRPFilter disables IPv4 reverse path filtering on the exit's
// interfaces. Replies arrive on the exit without a mark, so the check would use the
// main table rather than the exit's policy table and could drop them. It must run
// repeatedly: a new link inherits its value, and distributions set globs on link
// creation. The kernel applies the larger of "all" and the interface value, and
// "all" is host-wide, so that is reported, not changed. The result is a status note.
func ensureLinuxExitRPFilter(m Mapping) string {
	if m.ViaFor(4) == "" {
		return ""
	}
	conf := filepath.Join(linuxSysctlRoot, "net/ipv4/conf")
	var notes []string
	for _, name := range []string{m.LinuxExit.InputInterface, m.LinuxExit.Interface} {
		path := filepath.Join(conf, name, "rp_filter")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err == nil && strings.TrimSpace(string(data)) == "0" {
			continue
		}
		if err == nil {
			err = recordHostSetting(filepath.Join("net/ipv4/conf", name, "rp_filter"), strings.TrimSpace(string(data)), "0")
		}
		if err == nil {
			err = os.WriteFile(path, []byte("0\n"), 0o644)
		}
		if err != nil {
			notes = append(notes, fmt.Sprintf("cannot disable rp_filter on %s: %s", name, err))
			continue
		}
		log.Printf("Linux exit: disabled rp_filter on %s (was %s)", name, strings.TrimSpace(string(data)))
	}
	if data, err := os.ReadFile(filepath.Join(conf, "all", "rp_filter")); err == nil && strings.TrimSpace(string(data)) != "0" {
		notes = append(notes, fmt.Sprintf("net.ipv4.conf.all.rp_filter=%s overrides the interface setting and can drop exit replies", strings.TrimSpace(string(data))))
	}
	return strings.Join(notes, "; ")
}

// ensureLinuxExitIptables keeps a default-drop iptables FORWARD chain from stopping
// what nftables accepts. Traffic must pass both, so nftables still decides; towards
// the TAP only replies are opened. It must run repeatedly: firewall tools often
// restore their saved rules after the TAP appears. The result is a status note.
func ensureLinuxExitIptables(ctx context.Context, input string, tool string) string {
	if _, err := exec.LookPath(tool); err != nil {
		return ""
	}
	rules := [][]string{
		{"-i", input, "-j", "ACCEPT"},
		{"-o", input, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
	for i, rule := range rules {
		if _, err := runCmdContext(ctx, tool, append([]string{"-w", "2", "-C", "FORWARD"}, rule...)...); err == nil {
			continue
		}
		args := append([]string{"-w", "2", "-I", "FORWARD", strconv.Itoa(i + 1)}, rule...)
		if _, err := runCmdContext(ctx, tool, args...); err != nil {
			return fmt.Sprintf("cannot allow %s in %s FORWARD, a default-drop chain would stop its traffic: %s", input, tool, err)
		}
	}
	return ""
}

// linuxLinkInfo distinguishes an unavailable exit from a failed probe.
func linuxLinkInfo(ctx context.Context, name string) (up bool, mtu int, err error) {
	text, err := runCmdContext(ctx, "ip", "-j", "link", "show", "dev", name)
	if err != nil {
		if linkMissing(ctx, name) {
			return false, 0, nil
		}
		return false, 0, err
	}
	var links []struct {
		Flags []string `json:"flags"`
		MTU   int      `json:"mtu"`
	}
	if err := json.Unmarshal([]byte(text), &links); err != nil {
		return false, 0, err
	}
	for _, link := range links {
		for _, flag := range link.Flags {
			if flag == "UP" {
				return true, link.MTU, nil
			}
		}
	}
	return false, 0, nil
}

// checkLinuxExitVia catches a next hop no Linux address answers for, which VPP
// could only resolve into a silent black hole. An absent TAP is checked once it returns.
func checkLinuxExitVia(ctx context.Context, e *LinuxExit, via string, family int) error {
	text, err := runCmdContext(ctx, "ip", "-j", "-"+strconv.Itoa(family), "addr", "show", "dev", e.InputInterface)
	if err != nil {
		if linkMissing(ctx, e.InputInterface) {
			return nil
		}
		return err
	}
	var links []struct {
		Addresses []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(text), &links); err != nil {
		return err
	}
	want, err := netip.ParseAddr(via)
	if err != nil {
		return err
	}
	for _, link := range links {
		for _, address := range link.Addresses {
			if have, err := netip.ParseAddr(address.Local); err == nil && have == want {
				return nil
			}
		}
	}
	return fmt.Errorf("Linux exit next hop %s is not configured on %s", via, e.InputInterface)
}

// prepareLinuxExit fails closed: an absent or down exit still gets the fallback
// route and policy rule, and reports up=false so that other exits keep working.
// Occupancy is checked first, so a foreign rule or route is never replaced.
func prepareLinuxExit(ctx context.Context, m Mapping) (up bool, err error) {
	e := m.LinuxExit
	up, _, err = linuxLinkInfo(ctx, e.Interface)
	if err != nil {
		return false, err
	}
	table := fmt.Sprint(e.Table)
	for _, family := range []int{4, 6} {
		if m.ViaFor(family) == "" {
			continue
		}
		if err := checkLinuxExitVia(ctx, e, m.ViaFor(family), family); err != nil {
			return false, err
		}
		flag := "-" + strconv.Itoa(family)
		text, err := runCmdContext(ctx, "ip", "-N", "-j", flag, "rule", "show")
		if err != nil {
			return false, err
		}
		transit, local, err := linuxExitRulesPresent(text, e, family)
		if err != nil {
			return false, err
		}
		// Not -N, which would print route types as numbers.
		text, err = runCmdContext(ctx, "ip", "-j", flag, "route", "show", "table", table)
		if err != nil {
			// Some kernels report a table without routes as an error.
			if !tableEmpty(ctx, family, table) {
				return false, err
			}
			text = ""
		}
		if err := checkLinuxExitTable(text, e, family); err != nil {
			return false, err
		}
		// A terminal fallback prevents marked traffic leaking through the main table if the link goes down.
		if _, err := runCmdContext(ctx, "ip", flag, "route", "replace", "unreachable", "default", "table", table, "metric", fmt.Sprint(linuxExitFallbackMetric)); err != nil {
			return false, err
		}
		if up {
			args := []string{flag, "route", "replace", "table", table, "default", "metric", fmt.Sprint(linuxExitRouteMetric)}
			gateway := e.Gateway
			if family == 6 {
				gateway = e.Gateway6
			}
			// An exit reached through a gateway needs an IPv6 one too. Without gateway6 it is
			// the router the interface learned from advertisements, which may change.
			learned := family == 6 && gateway == "" && e.Gateway != ""
			if learned {
				if gateway, err = linuxIPv6Router(ctx, e.Interface); err != nil {
					return false, err
				}
			}
			if gateway != "" {
				args = append(args, "via", gateway, "onlink")
			}
			args = append(args, "dev", e.Interface)
			if learned && gateway == "" {
				// Without a router the fallback rejects the traffic until one is back.
				if exitRouteListed(text) {
					if _, err := runCmdContext(ctx, "ip", flag, "route", "del", "table", table, "default", "metric", fmt.Sprint(linuxExitRouteMetric)); err != nil {
						return false, err
					}
				}
			} else if _, err := runCmdContext(ctx, "ip", args...); err != nil {
				// The link can disappear between the probe and the route change.
				still, _, probeErr := linuxLinkInfo(ctx, e.Interface)
				if probeErr != nil || still {
					return false, err
				}
				up = false
			}
		}
		for iif, present := range map[string]bool{e.InputInterface: transit, "lo": local} {
			if present {
				continue
			}
			if _, err := runCmdContext(ctx, "ip", flag, "rule", "add", "priority", fmt.Sprint(e.Priority), "iif", iif, "fwmark", fmt.Sprint(e.Mark), "lookup", table); err != nil {
				return false, err
			}
		}
	}
	return up, nil
}

// prepareLinuxExits isolates exits from each other. Startup still rejects errors
// such as an occupied table, while a later failure must not stop reconciliation.
func (b *VPPBackend) prepareLinuxExits(state *linuxExitState) error {
	checked := map[string]bool{}
	for _, m := range b.Config.Mappings {
		if !m.Enabled || m.LinuxExit == nil || checked[m.LinuxExit.InputInterface] {
			continue
		}
		checked[m.LinuxExit.InputInterface] = true
		note := ensureLinuxExitIptables(b.context(), m.LinuxExit.InputInterface, "iptables")
		if m.ViaFor(6) != "" {
			if more := ensureLinuxExitIptables(b.context(), m.LinuxExit.InputInterface, "ip6tables"); more != "" {
				note = strings.TrimPrefix(note+"; "+more, "; ")
			}
		}
		key := "iptables/" + m.LinuxExit.InputInterface
		if note != state.status[key] {
			if note != "" {
				log.Printf("Linux exit: %s", note)
			}
			if state.status == nil {
				state.status = map[string]string{}
			}
			state.status[key] = note
		}
	}
	for _, m := range b.Config.Mappings {
		if !m.Enabled || m.LinuxExit == nil {
			continue
		}
		up, err := prepareLinuxExit(b.context(), m)
		status := "available"
		if err != nil {
			if !state.ready || ctxErr(b.context()) != nil {
				return err
			}
			status = err.Error()
		} else if !up {
			status = "unavailable; its traffic is rejected until the interface is up"
		}
		if err == nil {
			if note := ensureLinuxExitRPFilter(m); note != "" {
				status += "; " + note
			}
		}
		key := fmt.Sprintf("%s/%d", m.LinuxExit.Interface, m.LinuxExit.Table)
		previous, known := state.status[key]
		if previous != status && (known || status != "available") {
			log.Printf("Linux exit %s table %d: %s", m.LinuxExit.Interface, m.LinuxExit.Table, status)
		}
		if state.status == nil {
			state.status = map[string]string{}
		}
		state.status[key] = status
		if err != nil {
			continue
		}
		if state.mtus == nil {
			state.mtus = map[string]int{}
		}
		delete(state.mtus, m.LinuxExit.Interface)
		if up {
			if _, mtu, err := linuxLinkInfo(b.context(), m.LinuxExit.Interface); err == nil && mtu > 0 {
				state.mtus[m.LinuxExit.Interface] = mtu
			}
		}
	}
	return nil
}

// linuxExitUnderlay returns tunnel endpoints of an exit as host prefixes. Sending
// one of them back into the same exit would encapsulate the tunnel in itself.
// present=false means the interface is absent and its last known endpoints stand.
func linuxExitUnderlay(ctx context.Context, name string) (prefixes []string, present bool, err error) {
	text, err := runCmdContext(ctx, "ip", "-d", "-j", "link", "show", "dev", name)
	if err != nil {
		if linkMissing(ctx, name) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var links []struct {
		Info struct {
			Kind string `json:"info_kind"`
			Data struct {
				Remote string `json:"remote"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal([]byte(text), &links); err != nil {
		return nil, false, err
	}
	for _, link := range links {
		if link.Info.Kind == "wireguard" {
			if _, err := exec.LookPath("wg"); err != nil {
				return nil, true, fmt.Errorf("cannot read WireGuard endpoints of %s: wg command not found", name)
			}
			text, err := runCmdContext(ctx, "wg", "show", name, "endpoints")
			if err != nil {
				return nil, true, err
			}
			prefixes = append(prefixes, parseWireGuardEndpoints(text)...)
			continue
		}
		if addr, err := netip.ParseAddr(link.Info.Data.Remote); err == nil && !addr.IsUnspecified() {
			prefixes = append(prefixes, addrHostPrefix(addr))
		}
	}
	return prefixes, true, nil
}

func addrHostPrefix(addr netip.Addr) string {
	addr = addr.Unmap().WithZone("")
	return netip.PrefixFrom(addr, addr.BitLen()).String()
}

func parseWireGuardEndpoints(text string) []string {
	var prefixes []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if endpoint, err := netip.ParseAddrPort(fields[1]); err == nil {
			prefixes = append(prefixes, addrHostPrefix(endpoint.Addr()))
		}
	}
	return prefixes
}

func removeLinuxExit(ctx context.Context, m Mapping) error {
	if m.LinuxExit == nil {
		return fmt.Errorf("invalid Linux exit ownership journal")
	}
	e := m.LinuxExit
	for _, family := range []int{4, 6} {
		if m.ViaFor(family) == "" {
			continue
		}
		flag := "-" + strconv.Itoa(family)
		ruleGone := func(iif string) func() bool {
			return func() bool { return ruleMissing(ctx, family, e.Priority, iif) }
		}
		routeGone := func(matches func(deviceRoute) bool) func() bool {
			return func() bool { return routeMissing(ctx, family, e.Table, matches) }
		}
		commands := []struct {
			missing func() bool
			args    []string
		}{
			{ruleGone(e.InputInterface), []string{flag, "rule", "del", "priority", fmt.Sprint(e.Priority), "iif", e.InputInterface, "fwmark", fmt.Sprint(e.Mark), "lookup", fmt.Sprint(e.Table)}},
			{ruleGone("lo"), []string{flag, "rule", "del", "priority", fmt.Sprint(e.Priority), "iif", "lo", "fwmark", fmt.Sprint(e.Mark), "lookup", fmt.Sprint(e.Table)}},
			{routeGone(func(r deviceRoute) bool { return r.Dst == "default" && r.Dev == e.Interface && r.Metric == 100 }),
				[]string{flag, "route", "del", "table", fmt.Sprint(e.Table), "default", "metric", "100", "dev", e.Interface}},
			{routeGone(func(r deviceRoute) bool { return r.Type == "unreachable" && r.Dst == "default" }),
				[]string{flag, "route", "del", "unreachable", "default", "table", fmt.Sprint(e.Table), "metric", "32767"}},
		}
		for _, command := range commands {
			if err := ipDelete(ctx, command.missing, command.args...); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *VPPBackend) syncLinuxExits(replace bool) error {
	linuxExitMu.Lock()
	defer linuxExitMu.Unlock()
	state := linuxExitStates[b.Config.StateFile]
	manifest := b.Config.StateFile + ".linux-exits.json"
	var previous []Mapping
	var current []Mapping
	if state == nil || !state.ready {
		data, err := os.ReadFile(manifest)
		if err == nil {
			if err := json.Unmarshal(data, &previous); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if !hasLinuxExits(b.Config) && len(previous) == 0 {
		return nil
	}
	if state == nil {
		state = &linuxExitState{}
		linuxExitStates[b.Config.StateFile] = state
	}
	if !state.ready {
		for _, m := range b.Config.Mappings {
			if m.Enabled && m.LinuxExit != nil {
				current = append(current, m)
			}
		}
		// Save ownership before changing kernel state, including partially applied configurations.
		if err := durableJSON(manifest, append(append([]Mapping{}, previous...), current...)); err != nil {
			return err
		}
		for _, old := range previous {
			if old.LinuxExit == nil {
				return fmt.Errorf("invalid Linux exit ownership journal")
			}
			keep := false
			for _, m := range current {
				if *old.LinuxExit == *m.LinuxExit && old.ViaFor(4) == m.ViaFor(4) && old.ViaFor(6) == m.ViaFor(6) {
					keep = true
					break
				}
			}
			if !keep {
				if err := removeLinuxExit(b.context(), old); err != nil {
					return err
				}
			}
		}
		if !hasLinuxExits(b.Config) {
			if err := b.applyNft([]string{"add table inet egress_gate_linux\ndelete table inet egress_gate_linux"}); err != nil {
				return err
			}
			delete(linuxExitStates, b.Config.StateFile)
			return durableJSON(manifest, current)
		}
	}
	if !state.ready || replace {
		if err := b.prepareLinuxExits(state); err != nil {
			return err
		}
	}
	if state.ready && !replace {
		return nil
	}
	if err := b.applyNft([]string{linuxExitNftScript(b.Config, state.mtus)}); err != nil {
		return fmt.Errorf("Linux exit firewall: %w", err)
	}
	if !state.ready {
		if err := durableJSON(manifest, current); err != nil {
			return err
		}
	}
	state.ready = true
	return nil
}

// EnsureLinuxExits runs at the route barrier. Only the first call has work to do:
// the rules do not depend on destinations, so DNS answers never wait for nftables.
func (b *VPPBackend) EnsureLinuxExits() error {
	if !hasLinuxExits(b.Config) {
		return nil
	}
	return b.syncLinuxExits(false)
}
