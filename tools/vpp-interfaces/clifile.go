package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The CLI file VPP runs at startup is the configuration. Only the commands below are
// understood; every other line, comments and blank lines included, is kept as it is.
type lineKind int

const (
	lineOther      lineKind = iota
	lineComment             // comment or blank
	lineSubif               // create sub-interface BASE ID dot1q VLAN [exact-match]
	lineBridgeDom           // create bridge-domain N ...
	lineLoopback            // create loopback interface [mac M] instance N
	lineAddress             // set interface ip address IF PREFIX
	lineBridge              // set interface l2 bridge IF BD [bvi]
	lineTagRewrite          // set interface l2 tag-rewrite IF pop 1
	lineState               // set interface state IF up|down
	lineMTU                 // set interface mtu packet N IF
	lineDHCP4               // set dhcp client intfc IF [hostname H]
	lineSLAAC               // ip6 nd address autoconfig IF [default-route]
	lineDHCP6               // dhcp6 client IF
	lineGateway             // ip route add 0.0.0.0/0|::/0 via GW IF
	lineNATEnable           // nat44 ei plugin enable ... | nat44 plugin enable ...
	lineNATAddress          // nat44 [ei] add interface address IF
	lineNATOutput           // set interface nat44 [ei] out IF output-feature
	lineNATHairpin          // set interface nat44 [ei] hairpinning IF
	lineCreate              // create tap|vxlan tunnel|gre tunnel|ipip tunnel|host-interface, see device
	linePPPoE               // create pppoe client BASE host-uniq N name IF ..., see pppoe.go
)

type cliLine struct {
	text  string
	kind  lineKind
	iface string // the interface the line configures; for lineOther, empty

	base   string // lineSubif
	subID  uint32
	vlan   uint16
	exact  bool
	bd     uint32 // lineBridgeDom, lineBridge
	bvi    bool
	prefix netip.Prefix // lineAddress
	up     bool         // lineState
	mtu    uint32       // lineMTU
	host   string       // lineDHCP4
	via    netip.Addr   // lineGateway
	device string       // lineCreate: tap, vxlan, gre, ipip or af_packet
	nat    natMode      // lineNATEnable, lineNATAddress, lineNATOutput, lineNATHairpin: which NAT44 plugin's command
	pppoe  *pppoeConfig // linePPPoE; base is the interface it dials on
	words  []string     // lineOther, to find the interfaces it refers to
}

// keyword accepts VPP's abbreviations of a command word, such as "int" for "interface".
func keyword(word, full string) bool {
	if word == full {
		return true
	}
	return len(word) >= 3 && strings.HasPrefix(full, word)
}

func words(fields []string, full ...string) bool {
	if len(fields) < len(full) {
		return false
	}
	for i, word := range full {
		if !keyword(fields[i], word) {
			return false
		}
	}
	return true
}

func parseLine(text string) *cliLine {
	line := &cliLine{text: text}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		line.kind = lineComment
		return line
	}
	f := strings.Fields(trimmed)
	line.words = f
	switch {
	case words(f, "create", "sub-interfaces") && (len(f) == 6 || len(f) == 7) && f[4] == "dot1q":
		id, err1 := strconv.ParseUint(f[3], 10, 32)
		vlan, err2 := strconv.ParseUint(f[5], 10, 12)
		if err1 != nil || err2 != nil || vlan == 0 || (len(f) == 7 && f[6] != "exact-match") {
			return line
		}
		line.kind, line.base, line.subID, line.vlan, line.exact = lineSubif, f[2], uint32(id), uint16(vlan), len(f) == 7
		line.iface = fmt.Sprintf("%s.%d", f[2], id)
	case words(f, "create", "bridge-domain") && len(f) >= 3:
		id, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			return line
		}
		line.kind, line.bd = lineBridgeDom, uint32(id)
	case words(f, "create", "loopback", "interface"):
		for i := 3; i+1 < len(f); i += 2 {
			switch f[i] {
			case "mac":
			case "instance":
				n, err := strconv.ParseUint(f[i+1], 10, 32)
				if err != nil {
					return line
				}
				line.iface = fmt.Sprintf("loop%d", n)
			default:
				return line
			}
		}
		if line.iface != "" && len(f)%2 == 1 {
			line.kind = lineLoopback
		} else {
			line.iface = ""
		}
	case words(f, "set", "interface", "ip", "address") && len(f) == 6:
		prefix, err := netip.ParsePrefix(f[5])
		if err != nil {
			return line
		}
		line.kind, line.iface, line.prefix = lineAddress, f[4], prefix
	case words(f, "set", "interface", "l2", "bridge") && (len(f) == 6 || len(f) == 7):
		id, err := strconv.ParseUint(f[5], 10, 32)
		if err != nil || (len(f) == 7 && f[6] != "bvi") {
			return line
		}
		line.kind, line.iface, line.bd, line.bvi = lineBridge, f[4], uint32(id), len(f) == 7
	case words(f, "set", "interface", "l2", "tag-rewrite") && len(f) == 7 && f[5] == "pop" && f[6] == "1":
		line.kind, line.iface = lineTagRewrite, f[4]
	case words(f, "set", "interface", "state") && len(f) == 5 && (f[4] == "up" || f[4] == "down"):
		line.kind, line.iface, line.up = lineState, f[3], f[4] == "up"
	case words(f, "set", "interface", "mtu", "packet") && len(f) == 6:
		mtu, err := strconv.ParseUint(f[4], 10, 32)
		if err != nil {
			return line
		}
		line.kind, line.iface, line.mtu = lineMTU, f[5], uint32(mtu)
	case words(f, "set", "dhcp", "client") && len(f) >= 5 && f[3] == "intfc" && (len(f) == 5 || (len(f) == 7 && f[5] == "hostname")):
		line.kind, line.iface = lineDHCP4, f[4]
		if len(f) == 7 {
			line.host = f[6]
		}
	case words(f, "ip6", "nd", "address", "autoconfig") && (len(f) == 5 || (len(f) == 6 && f[5] == "default-route")):
		line.kind, line.iface = lineSLAAC, f[4]
	case f[0] == "dhcp6" && len(f) == 3 && keyword(f[1], "client"):
		line.kind, line.iface = lineDHCP6, f[2]
	case f[0] == "ip" && len(f) == 7 && keyword(f[1], "route") && f[2] == "add" && (f[3] == "0.0.0.0/0" || f[3] == "::/0") && f[4] == "via":
		via, err := netip.ParseAddr(f[5])
		if err != nil || via.Is4() != (f[3] == "0.0.0.0/0") {
			return line
		}
		line.kind, line.iface, line.via = lineGateway, f[6], via
	case words(f, "create", "tap"):
		if id, ok := option(f, "id"); ok && !slices.Contains(f, "del") {
			line.kind, line.device, line.iface = lineCreate, "tap", "tap"+id
			if name, ok := option(f, "if-name"); ok {
				line.iface = name
			}
		}
	case words(f, "create", "vxlan", "tunnel"), words(f, "create", "gre", "tunnel"), words(f, "create", "ipip", "tunnel"):
		// Without an instance VPP picks the name, which the file then cannot be matched with.
		if instance, ok := option(f, "instance"); ok && !slices.Contains(f, "del") {
			line.kind, line.device = lineCreate, f[1]
			line.iface = map[string]string{"vxlan": "vxlan_tunnel", "gre": "gre", "ipip": "ipip"}[f[1]] + instance
		}
	case words(f, "create", "pppoe", "client"):
		// Without a name the plugin calls it pppoxN by the order of creation, which the file
		// cannot be matched with; such a line, and a deletion, stay other lines.
		if c, ok := parsePPPoE(f); ok {
			line.kind, line.iface, line.base, line.pppoe = linePPPoE, c.name, c.base, c
		}
	case words(f, "create", "host-interface"):
		if name, ok := option(f, "name"); ok {
			line.kind, line.device, line.iface = lineCreate, "af_packet", "host-"+name
		}
	case len(f) >= 4 && f[0] == "nat44" && f[1] == "ei" && keyword(f[2], "plugin") && f[3] == "enable":
		line.kind, line.nat = lineNATEnable, natEI
	case len(f) >= 3 && f[0] == "nat44" && keyword(f[1], "plugin") && f[2] == "enable":
		line.kind, line.nat = lineNATEnable, natED
	case len(f) == 6 && f[0] == "nat44" && f[1] == "ei" && f[2] == "add" && keyword(f[3], "interface") && keyword(f[4], "address"):
		line.kind, line.iface, line.nat = lineNATAddress, f[5], natEI
	case len(f) == 5 && f[0] == "nat44" && f[1] == "add" && keyword(f[2], "interface") && keyword(f[3], "address"):
		line.kind, line.iface, line.nat = lineNATAddress, f[4], natED
	case len(f) == 7 && words(f, "set", "interface", "nat44", "ei", "out") && f[6] == "output-feature":
		line.kind, line.iface, line.nat = lineNATOutput, f[5], natEI
	case len(f) == 6 && words(f, "set", "interface", "nat44", "out") && f[5] == "output-feature":
		line.kind, line.iface, line.nat = lineNATOutput, f[4], natED
	case len(f) == 6 && words(f, "set", "interface", "nat44", "ei", "hairpinning"):
		line.kind, line.iface, line.nat = lineNATHairpin, f[5], natEI
	case len(f) == 5 && words(f, "set", "interface", "nat44", "hairpinning"):
		line.kind, line.iface, line.nat = lineNATHairpin, f[4], natED
	}
	return line
}

// option returns the word after key, as in "instance 3".
func option(f []string, key string) (string, bool) {
	for i := 0; i+1 < len(f); i++ {
		if f[i] == key {
			return f[i+1], true
		}
	}
	return "", false
}

// refersTo tells whether a line names an interface without being one of the lines that
// configure it, such as a NAT, route or DHCP command.
func (l *cliLine) refersTo(iface string) bool {
	if (l.kind == lineSubif || l.kind == linePPPoE) && l.base == iface {
		return true
	}
	if l.kind != lineOther {
		return false
	}
	for _, word := range l.words {
		if word == iface {
			return true
		}
	}
	return false
}

type cliFile struct {
	lines []*cliLine
	// trailing newline of the original, kept on write
	newline bool
}

func parseCLI(data string) *cliFile {
	file := &cliFile{newline: strings.HasSuffix(data, "\n") || data == ""}
	data = strings.TrimSuffix(data, "\n")
	if data == "" {
		return file
	}
	for _, text := range strings.Split(data, "\n") {
		file.lines = append(file.lines, parseLine(strings.TrimSuffix(text, "\r")))
	}
	return file
}

func (f *cliFile) String() string {
	texts := make([]string, len(f.lines))
	for i, line := range f.lines {
		texts[i] = line.text
	}
	text := strings.Join(texts, "\n")
	if f.newline && text != "" {
		text += "\n"
	}
	return text
}

func (f *cliFile) clone() *cliFile {
	return parseCLI(f.String())
}

// own returns the indexes of the lines configuring iface, of the given kinds or all kinds.
func (f *cliFile) own(iface string, kinds ...lineKind) []int {
	var found []int
	for i, line := range f.lines {
		if line.iface != iface || line.kind == lineOther || line.kind == lineComment {
			continue
		}
		if len(kinds) == 0 {
			found = append(found, i)
			continue
		}
		for _, kind := range kinds {
			if line.kind == kind {
				found = append(found, i)
				break
			}
		}
	}
	return found
}

// references returns the lines that name iface but are not its own.
func (f *cliFile) references(iface string) []*cliLine {
	var found []*cliLine
	for _, line := range f.lines {
		if line.refersTo(iface) {
			found = append(found, line)
		}
	}
	return found
}

// find returns the lines of the given kinds, whatever interface they are for.
func (f *cliFile) find(kinds ...lineKind) []int {
	var found []int
	for i, line := range f.lines {
		if slices.Contains(kinds, line.kind) {
			found = append(found, i)
		}
	}
	return found
}

// mentions tells whether the file says anything about iface.
func (f *cliFile) mentions(iface string) bool {
	return len(f.own(iface)) > 0 || len(f.references(iface)) > 0
}

func (f *cliFile) bridgeDomainLine(bd uint32) int {
	for i, line := range f.lines {
		if line.kind == lineBridgeDom && line.bd == bd {
			return i
		}
	}
	return -1
}

// firstReference is where the first line naming iface without configuring it is, or -1.
func (f *cliFile) firstReference(iface string) int {
	for i, line := range f.lines {
		if line.refersTo(iface) && line.kind == lineOther {
			return i
		}
	}
	return -1
}

// insertionPoint is where a new line for iface goes: after its own lines and after the
// lines it depends on, or at the end when the file says nothing about it.
func (f *cliFile) insertionPoint(iface string, after ...int) int {
	at := -1
	for _, i := range f.own(iface) {
		// NAT lines go after the plugin is enabled, often at the end; others keep their place.
		if kind := f.lines[i].kind; kind != lineNATAddress && kind != lineNATOutput && kind != lineNATHairpin {
			at = max(at, i)
		}
	}
	for _, i := range after {
		at = max(at, i)
	}
	if at < 0 {
		return len(f.lines)
	}
	return at + 1
}

func (f *cliFile) insert(at int, texts ...string) {
	added := make([]*cliLine, len(texts))
	for i, text := range texts {
		added[i] = parseLine(text)
	}
	f.lines = append(f.lines[:at], append(added, f.lines[at:]...)...)
}

func (f *cliFile) remove(indexes ...int) {
	drop := map[int]bool{}
	for _, i := range indexes {
		drop[i] = true
	}
	kept := f.lines[:0]
	for i, line := range f.lines {
		if !drop[i] {
			kept = append(kept, line)
		}
	}
	f.lines = kept
}

func (f *cliFile) replace(at int, text string) {
	f.lines[at] = parseLine(text)
}

// set replaces the lines of one kind for iface with texts: in place of the first, or at
// the insertion point when there were none.
func (f *cliFile) set(iface string, kind lineKind, texts []string, after ...int) {
	old := f.own(iface, kind)
	at := -1
	if len(old) > 0 {
		at = old[0]
		f.remove(old...)
	} else {
		at = f.insertionPoint(iface, after...)
	}
	f.insert(at, texts...)
}

// cliFileFromConfig finds the startup-config or exec file in a VPP startup file.
var startupCLI = regexp.MustCompile(`(?:^|[\s{])(?:exec|startup-config)\s+([^\s}]+)`)
var startupComment = regexp.MustCompile(`(?m)#.*$`)

func cliFileFromConfig(text string) string {
	match := startupCLI.FindStringSubmatch(startupComment.ReplaceAllString(text, ""))
	if match == nil {
		return ""
	}
	return match[1]
}

func addressCommand(iface string, prefix netip.Prefix, del bool) string {
	if del {
		return fmt.Sprintf("set interface ip address del %s %s", iface, prefix)
	}
	return fmt.Sprintf("set interface ip address %s %s", iface, prefix)
}

func bridgeCommand(iface string, bd uint32, bvi bool) string {
	if bvi {
		return fmt.Sprintf("set interface l2 bridge %s %d bvi", iface, bd)
	}
	return fmt.Sprintf("set interface l2 bridge %s %d", iface, bd)
}

func stateCommand(iface string, up bool) string {
	if up {
		return "set interface state " + iface + " up"
	}
	return "set interface state " + iface + " down"
}

func mtuCommand(iface string, mtu uint32) string {
	return fmt.Sprintf("set interface mtu packet %d %s", mtu, iface)
}

func subifCommand(base string, id uint32, vlan uint16) string {
	return fmt.Sprintf("create sub-interface %s %d dot1q %d exact-match", base, id, vlan)
}

func tagPopCommand(iface string) string { return "set interface l2 tag-rewrite " + iface + " pop 1" }

func dhcp4Command(iface, host string, del bool) string {
	switch {
	case del:
		return "set dhcp client del intfc " + iface
	case host != "":
		return "set dhcp client intfc " + iface + " hostname " + host
	}
	return "set dhcp client intfc " + iface
}

func slaacCommand(iface string, disable bool) string {
	if disable {
		return "ip6 nd address autoconfig " + iface + " disable"
	}
	return "ip6 nd address autoconfig " + iface + " default-route"
}

func dhcp6Command(iface string, disable bool) string {
	if disable {
		return "dhcp6 client " + iface + " disable"
	}
	return "dhcp6 client " + iface
}

// natMode is which NAT44 plugin VPP runs: NAT44-EI (nat44_ei_plugin.so) or NAT44-ED
// (nat_plugin.so). Their commands differ only by the "ei" word, apart from the enable and
// timeout lines.
type natMode string

const (
	natEI natMode = "ei"
	natED natMode = "ed"
)

func (m natMode) String() string {
	if m == natED {
		return "NAT44-ED"
	}
	return "NAT44-EI"
}

// word is the command word after "nat44" (and after "set interface nat44"): "ei " or nothing.
func (m natMode) word() string {
	if m == natED {
		return ""
	}
	return "ei "
}

// The NAT an exit gets, as the installer writes it: translate what leaves by the interface to
// its own address, whatever that is at the time, DHCP included. The TCP timeouts are the
// installer's too.
func natEnableCommand(m natMode) string {
	if m == natED {
		return "nat44 plugin enable sessions 65536"
	}
	return "nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384"
}

func natDisableCommand(m natMode) string { return "nat44 " + m.word() + "plugin disable" }

func natTimeoutCommand(m natMode) string {
	if m == natED {
		return "set nat timeout tcp-established 1800 tcp-transitory 120"
	}
	return "set nat44 ei timeout tcp-established 1800 tcp-transitory 120"
}

func natAddressCommand(m natMode, iface string, del bool) string {
	if del {
		return "nat44 " + m.word() + "add interface address " + iface + " del"
	}
	return "nat44 " + m.word() + "add interface address " + iface
}

func natOutputCommand(m natMode, iface string, del bool) string {
	if del {
		return "set interface nat44 " + m.word() + "out " + iface + " output-feature del"
	}
	return "set interface nat44 " + m.word() + "out " + iface + " output-feature"
}

// natHairpinCommand turns hairpinning on or off for a LAN-side interface (VPP patches 0043 and
// 0044): its packets to an address and port the NAT maps to an inside host, such as a port
// forward on the exit's address, are translated and sent back inside instead of out.
func natHairpinCommand(m natMode, iface string, del bool) string {
	if del {
		return "set interface nat44 " + m.word() + "hairpinning " + iface + " del"
	}
	return "set interface nat44 " + m.word() + "hairpinning " + iface
}

func gatewayCommand(iface string, via netip.Addr, del bool) string {
	prefix, verb := "0.0.0.0/0", "add"
	if via.Is6() {
		prefix = "::/0"
	}
	if del {
		verb = "del"
	}
	return fmt.Sprintf("ip route %s %s via %s %s", verb, prefix, via, iface)
}
