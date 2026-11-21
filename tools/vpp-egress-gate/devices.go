package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Devices are persistent TAP interfaces that Linux owns and VPP attaches to. A TAP, not a
// TUN: it moved about twice the upload on the test machine, and only a MAC can tell the
// next hops of a shared device apart.
// They outlive VPP, so their addresses, routes and rules need no repair when it restarts.
//
// Two modes share the journal. --sync-devices applies the user's read-only JSON: it
// allocates numbers, which stay with a device name so that changing one rule never
// renumbers another, sets up Linux, rewrites VPP's static CLI and adds what a running
// VPP lacks. --setup-links runs at boot and sets up Linux from the journal alone, so
// a half-edited JSON cannot affect a boot. It may run before or after VPP: whichever
// comes first creates the device. Only Gate must wait for it, because Gate's routes
// are what send traffic into a device, and a device without its rules must carry none.

// Replaced by tests.
var deviceStateDir = "/var/lib/vpp-egress-gate"

const (
	deviceHostMTU    = 1500
	deviceMaxExits   = 64
	deviceExitNet    = "172.30.10.0/24"
	deviceProxyNet   = "172.30.20.0/24"
	deviceExitNet6   = "fd67:7465:6500::/64"
	deviceProxyNet6  = "fd67:7465:6501::/64"
	deviceProxyHost  = "gate-tproxy"
	deviceProxyID    = 2081
	deviceFirstExit  = 2100
	deviceProxyTable = 1002
	deviceProxyPrio  = 11002
	deviceProxyPort  = 2082
	// Linux allows 15 characters in the name of an interface, which a device must also fit.
	deviceNameMax    = 15
	deviceExitPrefix = "tap-"
	// Several gateways on one interface share a TAP and take a macvlan each.
	deviceSharedPrefix  = "gw-"
	deviceGatewayPrefix = "gm-"
)

var deviceExitNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// DeviceEntry is one allocation. Slot is the /30 of an exit; the TPROXY device has none.
type DeviceEntry struct {
	Host           string `json:"host"`
	ID             int    `json:"id"`
	Slot           int    `json:"slot"`
	Exit           string `json:"exit,omitempty"`
	Table          uint32 `json:"table,omitempty"`
	Mark           uint32 `json:"mark,omitempty"`
	Priority       uint32 `json:"priority,omitempty"`
	ReturnTable    uint32 `json:"return_table,omitempty"`
	ReturnPriority uint32 `json:"return_priority,omitempty"`
	// SharedTAP marks the TAP that several gateways of one interface share. It carries no
	// traffic of its own. Parent is that TAP, on the macvlan entry of each gateway.
	SharedTAP bool   `json:"shared_tap,omitempty"`
	Parent    string `json:"parent,omitempty"`
	// IPv6 also gives the device a transit address, return routes and a next hop.
	IPv6 bool `json:"ipv6,omitempty"`
	// IPv6Found is IPv6 that Gate turned on because the exit had it, the rule saying nothing.
	IPv6Found bool `json:"ipv6_found,omitempty"`
	// Retired devices have left the JSON. VPP may hold them until it restarts.
	Retired bool `json:"retired,omitempty"`
}

func (d DeviceEntry) isProxy() bool        { return d.Host == deviceProxyHost }
func (d DeviceEntry) vppInterface() string { return "tap" + strconv.Itoa(d.ID) }

func deviceHostInNet(cidr string, offset int) netip.Addr {
	addr := netip.MustParsePrefix(cidr).Addr()
	bytes := addr.As4()
	return netip.AddrFrom4([4]byte{bytes[0], bytes[1], bytes[2], bytes[3] + byte(offset)})
}

func (d DeviceEntry) vppAddress() netip.Addr {
	if d.isProxy() {
		return deviceHostInNet(deviceProxyNet, 1)
	}
	return deviceHostInNet(deviceExitNet, 4*d.Slot+1)
}

func (d DeviceEntry) linuxAddress() netip.Addr {
	if d.isProxy() {
		return deviceHostInNet(deviceProxyNet, 2)
	}
	return deviceHostInNet(deviceExitNet, 4*d.Slot+2)
}

func deviceHostInNet6(cidr string, offset int) netip.Addr {
	bytes := netip.MustParsePrefix(cidr).Addr().As16()
	bytes[14], bytes[15] = byte(offset>>8), byte(offset)
	return netip.AddrFrom16(bytes)
}

func (d DeviceEntry) vppAddress6() netip.Addr {
	if d.isProxy() {
		return deviceHostInNet6(deviceProxyNet6, 1)
	}
	return deviceHostInNet6(deviceExitNet6, 4*d.Slot+1)
}

func (d DeviceEntry) linuxAddress6() netip.Addr {
	if d.isProxy() {
		return deviceHostInNet6(deviceProxyNet6, 2)
	}
	return deviceHostInNet6(deviceExitNet6, 4*d.Slot+2)
}

func (d DeviceEntry) prefixLen6() int {
	if d.isProxy() {
		return 64
	}
	return 126
}

// via is what Gate reads: a list as soon as the device has both families.
func (d DeviceEntry) via() any {
	if d.IPv6 {
		return []any{d.linuxAddress().String(), d.linuxAddress6().String()}
	}
	return d.linuxAddress().String()
}

// lansOf picks one family from the client networks.
func lansOf(lans []string, family int) []string {
	var out []string
	for _, text := range lans {
		if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Addr().Is4() == (family == 4) {
			out = append(out, text)
		}
	}
	return out
}

func (d DeviceEntry) prefixLen() int {
	if d.isProxy() {
		return 24
	}
	return 30
}

// A TAP keeps its MACs across VPP restarts, or Linux would hold a stale neighbor.
func (d DeviceEntry) gatewayMAC() string {
	return fmt.Sprintf("02:67:6d:00:%02x:02", d.Slot&0xff)
}

func (d DeviceEntry) mac(end byte) string {
	return fmt.Sprintf("02:67:74:%02x:%02x:%02x", d.ID>>8&0xff, d.ID&0xff, end)
}

// DeviceState is the allocation journal.
type DeviceState struct {
	Devices map[string]*DeviceEntry `json:"devices"`
	// Active devices in rule order; the first holds the main table routes.
	Order []string `json:"order,omitempty"`
	LANs  []string `json:"lan_prefixes,omitempty"`
	// LANInterfaces add the IPv6 prefixes Gate finds on them while it runs.
	LANInterfaces []string `json:"lan_interfaces,omitempty"`
}

// DevicePlan is everything a sync applies, computed without touching the system.
type DevicePlan struct {
	Devices   []DeviceEntry `json:"devices"`
	Retired   []DeviceEntry `json:"retired"`
	LANs      []string      `json:"lan_prefixes"`
	LANIfaces []string      `json:"lan_interfaces,omitempty"`
	VPPSocket string        `json:"vpp_socket"`
	Fixed     string        `json:"fixed_nft"`
	CLI       string        `json:"vpp_cli"`
	Effective string        `json:"gate_config"`
}

func readJSONObject(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

func linkedJSON(entry map[string]any, key string) (string, map[string]any, error) {
	value, ok := entry[key].(string)
	if !ok || value == "" {
		return "", nil, nil
	}
	if !filepath.IsAbs(value) {
		return "", nil, fmt.Errorf("%s must be an absolute path", key)
	}
	doc, err := readJSONObject(value)
	return value, doc, err
}

func parseLANPrefixes(entry map[string]any) ([]netip.Prefix, error) {
	raw, ok := entry["lan_prefixes"].([]any)
	if !ok || len(raw) == 0 {
		return nil, fmt.Errorf("the configuration needs lan_prefixes: the client networks behind VPP")
	}
	reserved := []netip.Prefix{netip.MustParsePrefix(deviceExitNet), netip.MustParsePrefix(deviceProxyNet), netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix(deviceExitNet6), netip.MustParsePrefix(deviceProxyNet6)}
	var lans []netip.Prefix
	for _, item := range raw {
		text, _ := item.(string)
		lan, err := netip.ParsePrefix(text)
		if err != nil || lan.Masked() != lan || lan.Bits() == 0 || lan.Addr().IsLinkLocalUnicast() || lan.Addr().IsMulticast() {
			return nil, fmt.Errorf("invalid lan_prefixes entry %v: a network is required", item)
		}
		for _, other := range reserved {
			if lan.Overlaps(other) {
				return nil, fmt.Errorf("lan_prefixes entry %s overlaps transit or Fake-IP networks", lan)
			}
		}
		for _, other := range lans {
			if lan.Overlaps(other) {
				return nil, fmt.Errorf("lan_prefixes entries overlap: %s", lan)
			}
		}
		lans = append(lans, lan)
	}
	return lans, nil
}

func defaultExcludePrefixes(lans []netip.Prefix) []any {
	base := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}
	var out []any
	for _, lan := range lans {
		private := false
		for _, text := range base {
			if parent := netip.MustParsePrefix(text); parent.Addr().Is4() == lan.Addr().Is4() && parent.Bits() <= lan.Bits() && parent.Contains(lan.Addr()) {
				private = true
			}
		}
		if !private {
			out = append(out, lan.String())
		}
	}
	for _, text := range base {
		out = append(out, text)
	}
	return out
}

// deviceAllocator hands out values that neither the JSON nor another device holds.
type deviceAllocator struct {
	ids, slots, tables, marks, priorities map[int]bool
}

func (a *deviceAllocator) pick(pool map[int]bool, previous, start int) int {
	if previous > 0 && !pool[previous] {
		pool[previous] = true
		return previous
	}
	for value := start; ; value++ {
		if !pool[value] {
			pool[value] = true
			return value
		}
	}
}

func (a *deviceAllocator) reserve(d DeviceEntry) {
	// A gateway on a shared TAP holds no VPP interface of its own: the id is the TAP's.
	if d.Parent == "" {
		a.ids[d.ID] = true
	}
	a.slots[d.Slot+1] = true
	a.tables[int(d.Table)] = true
	a.tables[int(d.ReturnTable)] = true
	a.marks[int(d.Mark)] = true
	a.priorities[int(d.Priority)] = true
	a.priorities[int(d.ReturnPriority)] = true
}

var deviceInterfaceRe = regexp.MustCompile(`^(?:tap|tun)([0-9]+)$`)

func newDeviceAllocator(routes []map[string]any, state *DeviceState, active map[string]bool) (*deviceAllocator, error) {
	a := &deviceAllocator{ids: map[int]bool{}, slots: map[int]bool{}, tables: map[int]bool{deviceProxyTable: true},
		marks: map[int]bool{1: true}, priorities: map[int]bool{deviceProxyPrio: true}}
	for _, route := range routes {
		if iface, _ := route["interface"].(string); iface != "" {
			if match := deviceInterfaceRe.FindStringSubmatch(iface); match != nil {
				id, _ := strconv.Atoi(match[1])
				a.ids[id] = true
			}
		}
		exit, ok := route["linux_exit"].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []struct {
			name string
			pool map[int]bool
		}{{"table", a.tables}, {"mark", a.marks}, {"priority", a.priorities}} {
			if value, present := exit[field.name].(float64); present {
				if field.pool[int(value)] {
					return nil, fmt.Errorf("linux_exit %s %d is already used", field.name, int(value))
				}
				field.pool[int(value)] = true
			}
		}
	}
	// A retired device may still hold its VPP interface.
	for _, d := range state.Devices {
		if !active[d.Host] {
			a.reserve(*d)
		}
	}
	return a, nil
}

// deviceName keeps the name it is given when that fits, so that the devices of a short
// name are obvious. A longer name keeps its start and gets a tag from all of it, as
// interfaces with long names often differ only at the end. Two names with the same tag
// ask for the same device, and the sync refuses that.
func deviceName(prefix, name string) string {
	if len(prefix)+len(name) <= deviceNameMax {
		return prefix + name
	}
	sum := sha256.Sum256([]byte(name))
	tag := hex.EncodeToString(sum[:2])
	return prefix + name[:deviceNameMax-len(prefix)-len(tag)-1] + "-" + tag
}

// logDeviceName says which device a name became when the device does not show it.
func logDeviceName(prefix, name string) {
	if host := deviceName(prefix, name); host != prefix+name {
		log.Printf("devices: %s uses device %s", name, host)
	}
}

// deviceHostFor says which device a rule without an interface asks for, if any.
func deviceHostFor(route map[string]any) (host string, err error) {
	name, _ := route["name"].(string)
	if exit, ok := route["linux_exit"].(map[string]any); ok {
		iface, _ := exit["interface"].(string)
		if len(iface) > deviceNameMax || !deviceExitNameRe.MatchString(iface) {
			return "", fmt.Errorf("invalid Linux exit interface %q: at most %d characters", iface, deviceNameMax)
		}
		label := "linux_exit " + iface
		if _, present := exit["input_interface"]; present {
			return "", fmt.Errorf("%s: input_interface requires interface; omit both to have a device created", label)
		}
		if _, present := route["via"]; present {
			return "", fmt.Errorf("%s: via requires interface; omit both to have a device created", label)
		}
		return deviceName(deviceExitPrefix, iface), nil
	}
	_, fakeRange := route["fakeip_range"]
	_, fakeDNS := route["fake_dns"]
	if !fakeRange && !fakeDNS && route["tproxy_port"] == nil {
		return "", fmt.Errorf("rule %q needs interface and via", name)
	}
	label := "Fake-IP rule " + name
	if _, present := route["via"]; present {
		return "", fmt.Errorf("%s: via requires interface; omit both to have a device created", label)
	}
	return deviceProxyHost, nil
}

// completeDeviceRoutes fills in the rules without an interface and returns their devices.
// sharedExits finds interfaces that several rules ask for, and holds those rules to what
// the shared TAP needs: a name for the macvlan, and a gateway of their own to tell apart.
func sharedExits(routes []map[string]any, state *DeviceState) (map[string]bool, error) {
	counts := map[string]int{}
	for _, route := range routes {
		if exit, ok := route["linux_exit"].(map[string]any); ok {
			name, _ := exit["interface"].(string)
			counts[name]++
		}
	}
	shared := map[string]bool{}
	gateways := map[string]bool{}
	for _, route := range routes {
		exit, ok := route["linux_exit"].(map[string]any)
		if !ok {
			continue
		}
		iface, _ := exit["interface"].(string)
		if counts[iface] < 2 {
			// The last gateway keeps its macvlan. Moving it to a device of its own would
			// disturb a working exit just because another one left.
			name, _ := route["name"].(string)
			parent, gateway := state.Devices[deviceName(deviceSharedPrefix, iface)], state.Devices[deviceName(deviceGatewayPrefix, name)]
			if parent == nil || parent.Retired || gateway == nil || gateway.Retired || gateway.Parent != parent.Host {
				continue
			}
		}
		shared[iface] = true
		label := "linux_exit " + iface
		if _, explicit := route["interface"]; explicit {
			return nil, fmt.Errorf("%s: rules sharing an interface cannot name a device", label)
		}
		gateway, _ := exit["gateway"].(string)
		gateway6, _ := exit["gateway6"].(string)
		if gateway == "" && gateway6 == "" {
			return nil, fmt.Errorf("%s has several rules, so each needs its own gateway", iface)
		}
		if key := iface + "|" + gateway + "|" + gateway6; gateways[key] {
			return nil, fmt.Errorf("%s has several rules, so each needs its own gateway", iface)
		} else {
			gateways[key] = true
		}
		name, _ := route["name"].(string)
		if name == "" || !deviceExitNameRe.MatchString(name) {
			return nil, fmt.Errorf("%s has several rules, so each needs a name", iface)
		}
	}
	return shared, nil
}

// completeDeviceRoutes fills in the rules without an interface and returns their devices.
func completeDeviceRoutes(routes []map[string]any, state *DeviceState, lanIPv6 bool) ([]DeviceEntry, error) {
	type request struct {
		route        map[string]any
		host, parent string
	}
	shared, err := sharedExits(routes, state)
	if err != nil {
		return nil, err
	}
	var requests []request
	active := map[string]bool{}
	exits := map[string]bool{}
	parents := map[string]bool{}
	for _, route := range routes {
		exit, isExit := route["linux_exit"].(map[string]any)
		iface := ""
		if isExit {
			iface, _ = exit["interface"].(string)
			exits[iface] = true
		}
		if _, explicit := route["interface"]; explicit {
			continue
		}
		host, err := deviceHostFor(route)
		if err != nil {
			return nil, err
		}
		parent := ""
		if shared[iface] {
			name, _ := route["name"].(string)
			host, parent = deviceName(deviceGatewayPrefix, name), deviceName(deviceSharedPrefix, iface)
			if !parents[parent] {
				logDeviceName(deviceSharedPrefix, iface)
			}
			logDeviceName(deviceGatewayPrefix, name)
			parents[parent] = true
			active[parent] = true
		} else if isExit {
			logDeviceName(deviceExitPrefix, iface)
		}
		if active[host] {
			if host == deviceProxyHost {
				requests = append(requests, request{route, host, parent})
				continue
			}
			return nil, fmt.Errorf("two rules ask for device %s", host)
		}
		active[host] = true
		requests = append(requests, request{route, host, parent})
	}
	alloc, err := newDeviceAllocator(routes, state, active)
	if err != nil {
		return nil, err
	}
	// Devices that stay go first, so that a new rule cannot take their numbers.
	assigned := map[string]DeviceEntry{}
	for _, keep := range []bool{true, false} {
		for parent := range parents {
			previous := state.Devices[parent]
			if _, done := assigned[parent]; done || (previous != nil) != keep {
				continue
			}
			before := 0
			if previous != nil {
				before = previous.ID
			}
			assigned[parent] = DeviceEntry{Host: parent, Slot: -1, SharedTAP: true, ID: alloc.pick(alloc.ids, before, deviceFirstExit)}
		}
		for _, req := range requests {
			previous := state.Devices[req.host]
			if _, done := assigned[req.host]; done || (previous != nil) != keep {
				continue
			}
			if req.parent != "" {
				if _, ready := assigned[req.parent]; !ready {
					continue
				}
			}
			_, stated := req.route["ipv6"]
			d, err := assignDevice(alloc, req.route, req.host, previous, assigned[req.parent])
			if err != nil {
				return nil, err
			}
			if d.IPv6, err = routeWantsIPv6(req.route, lanIPv6); err != nil {
				return nil, err
			}
			if exit, ok := req.route["linux_exit"].(map[string]any); ok && !stated && lanIPv6 {
				// Unsaid, IPv6 follows the exit: on once it has IPv6, so that the device does
				// not stay without it. Turned on this way it stays on when the exit loses IPv6
				// for a while, as a tunnel does when its link goes down; "ipv6": false turns it off.
				iface, _ := exit["interface"].(string)
				gateway, _ := exit["gateway"].(string)
				gateway6, _ := exit["gateway6"].(string)
				d.IPv6 = (previous != nil && previous.IPv6Found) || linuxExitHasIPv6(context.Background(), iface, gateway != "", gateway6)
				d.IPv6Found = d.IPv6
			}
			req.route["via"] = d.via()
			assigned[req.host] = d
		}
	}
	var devices []DeviceEntry
	placed := map[string]bool{}
	// Proxy rules share the transit device; nftables selects their listener by family/pool.
	for _, req := range requests {
		if req.host != deviceProxyHost {
			continue
		}
		d := assigned[req.host]
		ipv6, err := routeWantsIPv6(req.route, lanIPv6)
		if err != nil {
			return nil, err
		}
		d.IPv6 = d.IPv6 || ipv6
		assigned[req.host] = d
	}
	for _, req := range requests {
		if req.host == deviceProxyHost {
			d := assigned[req.host]
			d.IPv6, _ = routeWantsIPv6(req.route, lanIPv6)
			req.route["interface"], req.route["via"] = d.vppInterface(), d.via()
			delete(req.route, "ipv6")
			req.route["tproxy_interface"] = deviceProxyHost
			if req.route["tproxy_port"] == nil {
				req.route["tproxy_port"] = deviceProxyPort
			}
			if placed[req.host] {
				continue
			}
			placed[req.host] = true
		}
		// A shared TAP comes before its gateways: VPP creates it first.
		if req.parent != "" && !placed[req.parent] {
			placed[req.parent] = true
			devices = append(devices, assigned[req.parent])
		}
		devices = append(devices, assigned[req.host])
	}
	names := map[string]bool{}
	for _, route := range routes {
		name, _ := route["name"].(string)
		if names[name] {
			return nil, fmt.Errorf("route names must be unique: %s", name)
		}
		names[name] = true
	}
	for _, d := range devices {
		if exits[d.Host] {
			return nil, fmt.Errorf("a Linux exit has the name of a generated device: %s", d.Host)
		}
	}
	return devices, nil
}

// routeWantsIPv6 asks the rule, not the LAN: an exit without IPv6 connectivity must
// leave AAAA empty, so that clients fall back to IPv4 instead of into a dead path.
// A Fake-IP rule says so with its pool.
func routeWantsIPv6(route map[string]any, lanIPv6 bool) (bool, error) {
	wanted := false
	if route["tproxy_exit"] != nil && route["fakeip_range"] == nil {
		wanted, _ = route["ipv6"].(bool)
	}
	if _, isExit := route["linux_exit"]; isExit {
		if value, present := route["ipv6"]; present {
			enabled, ok := value.(bool)
			if !ok {
				return false, fmt.Errorf("%s: ipv6 must be true or false", routeLabel(route))
			}
			wanted = enabled
		}
	} else {
		pools, _ := route["fakeip_range"].([]any)
		if text, ok := route["fakeip_range"].(string); ok {
			pools = []any{text}
		}
		for _, pool := range pools {
			text, _ := pool.(string)
			if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Addr().Is6() {
				wanted = true
			}
		}
	}
	if route["tproxy_exit"] == nil {
		delete(route, "ipv6")
	}
	if wanted && !lanIPv6 {
		return false, fmt.Errorf("%s: IPv6 needs an IPv6 entry in lan_prefixes, or lan_interfaces", routeLabel(route))
	}
	return wanted, nil
}

func assignDevice(alloc *deviceAllocator, route map[string]any, host string, previous *DeviceEntry, parent DeviceEntry) (DeviceEntry, error) {
	if previous == nil {
		previous = &DeviceEntry{Slot: -1}
	}
	d := DeviceEntry{Host: host, Slot: -1}
	if host == deviceProxyHost {
		d.ID = alloc.pick(alloc.ids, previous.ID, deviceProxyID)
		route["interface"] = d.vppInterface()
		route["via"] = d.linuxAddress().String()
		if _, present := route["tproxy_port"]; !present {
			route["tproxy_port"] = deviceProxyPort
		}
		route["tproxy_interface"] = deviceProxyHost
		return d, nil
	}
	exit := route["linux_exit"].(map[string]any)
	d.Exit, _ = exit["interface"].(string)
	if parent.Host != "" {
		// The gateways share the TAP, and each has a /30 of its own on it.
		d.ID, d.Parent = parent.ID, parent.Host
	} else {
		d.ID = alloc.pick(alloc.ids, previous.ID, deviceFirstExit)
	}
	// The pool holds slot+1, because pick treats zero as no previous value.
	d.Slot = alloc.pick(alloc.slots, previous.Slot+1, 1) - 1
	if d.Slot >= deviceMaxExits {
		return d, fmt.Errorf("too many Linux exits: at most %d", deviceMaxExits)
	}
	// Values the user chose stand, and were reserved before any allocation.
	for _, field := range []struct {
		name            string
		pool            map[int]bool
		previous, start int
		out             *uint32
	}{
		{"table", alloc.tables, int(previous.Table), 1101, &d.Table},
		{"mark", alloc.marks, int(previous.Mark), 101, &d.Mark},
		{"priority", alloc.priorities, int(previous.Priority), 11101, &d.Priority},
	} {
		value, chosen := exit[field.name].(float64)
		if !chosen {
			value = float64(alloc.pick(field.pool, field.previous, field.start))
		}
		*field.out = uint32(value)
		exit[field.name] = uint32(value)
	}
	d.ReturnTable = uint32(alloc.pick(alloc.tables, int(previous.ReturnTable), 2101))
	d.ReturnPriority = uint32(alloc.pick(alloc.priorities, int(previous.ReturnPriority), 12101))
	exit["input_interface"] = host
	route["interface"] = d.vppInterface()
	route["via"] = d.linuxAddress().String()
	if _, named := route["name"]; !named {
		// Gate's route names do not allow the dot of a VLAN interface.
		route["name"] = strings.ReplaceAll(d.Exit, ".", "_")
	}
	return d, nil
}

// checkRouteOwner holds a rule to what it says: "host" means a Linux interface, which
// traffic reaches through a device, and "vpp" means one inside VPP, which needs nothing
// from Linux. Without the field, the rule's shape decides. A wrong rule stops the sync
// even while it is empty, so a typo cannot wait for the day its domains are added.
func checkRouteOwner(route map[string]any) error {
	value, present := route["owner"]
	if !present {
		return nil
	}
	owner, _ := value.(string)
	_, hasExit := route["linux_exit"]
	_, hasInterface := route["interface"]
	_, hasVia := route["via"]
	_, fakeRange := route["fakeip_range"]
	_, fakeDNS := route["fake_dns"]
	switch owner {
	case "vpp":
		if hasExit {
			return fmt.Errorf("%s: owner vpp cannot have linux_exit", routeLabel(route))
		}
		if !hasInterface || !hasVia {
			return fmt.Errorf("%s: owner vpp needs interface and via", routeLabel(route))
		}
	case "host":
		if !hasExit && !fakeRange && !fakeDNS && !hasInterface && route["tproxy_port"] == nil {
			return fmt.Errorf("%s: owner host needs linux_exit", routeLabel(route))
		}
	default:
		return fmt.Errorf("%s: owner must be host or vpp", routeLabel(route))
	}
	return nil
}

func routeLabel(route map[string]any) string {
	if exit, ok := route["linux_exit"].(map[string]any); ok {
		if name, ok := exit["interface"].(string); ok {
			return "linux_exit " + name
		}
	}
	name, _ := route["name"].(string)
	return "rule " + name
}

// routeHasRules reads source files as Gate does. A file it cannot read counts as
// content, so that the rule stays and Gate's loader reports the real problem.
func routeHasRules(route map[string]any) bool {
	if carries, _ := route["default_route"].(bool); carries {
		return true // the default route is something to divert, with or without lists
	}
	for _, key := range []string{"domains", "domain_keywords"} {
		if list, ok := route[key].([]any); ok && len(list) > 0 {
			return true
		}
	}
	for _, key := range []string{"domain_files", "ip_range_files"} {
		var files []any
		switch value := route[key].(type) {
		case string:
			files = []any{value}
		case []any:
			files = value
		}
		for _, item := range files {
			name, _ := item.(string)
			text, err := os.ReadFile(name)
			if err != nil {
				return true
			}
			for _, line := range strings.Split(string(text), "\n") {
				if strings.TrimSpace(strings.SplitN(line, "#", 2)[0]) != "" {
					return true
				}
			}
		}
	}
	return false
}

// A rule's file names become paths here, so that the rest of the sync reads the same files as Gate.
func absoluteRouteFiles(route map[string]any) error {
	for _, key := range []string{"domain_files", "ip_range_files"} {
		absolute := func(value any) (any, error) {
			if text, ok := value.(string); ok {
				return resolveListFile(key, text)
			}
			return value, nil
		}
		var err error
		switch value := route[key].(type) {
		case string:
			route[key], err = absolute(value)
		case []any:
			for i := 0; i < len(value) && err == nil; i++ {
				value[i], err = absolute(value[i])
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func deviceFixedRules(devices, retired []DeviceEntry) string {
	var b strings.Builder
	// Replacing the table keeps a reload idempotent. The guard is what remains when a
	// reload removes Gate's own table: only traffic Gate has classified may pass.
	b.WriteString("add table inet gate_fixed\ndelete table inet gate_fixed\ntable inet gate_fixed {\n")
	b.WriteString(" chain guard { type filter hook forward priority filter; policy accept;\n")
	for _, d := range devices {
		if d.isProxy() || d.SharedTAP {
			fmt.Fprintf(&b, "  iifname %q drop\n", d.Host)
		} else {
			fmt.Fprintf(&b, "  iifname %q meta mark 0 drop\n", d.Host)
		}
	}
	for _, d := range retired {
		fmt.Fprintf(&b, "  iifname %q drop\n", d.Host)
	}
	b.WriteString(" }\n}\n")
	return b.String()
}

func deviceAddressLines(d DeviceEntry) []string {
	name := d.vppInterface()
	lines := []string{fmt.Sprintf("set interface ip address %s %s/%d", name, d.vppAddress(), d.prefixLen())}
	if d.IPv6 {
		lines = append(lines, fmt.Sprintf("set interface ip address %s %s/%d", name, d.vppAddress6(), d.prefixLen6()))
	}
	return lines
}

func deviceCLILines(d DeviceEntry) []string {
	// A gateway on a shared TAP adds only its addresses.
	if d.Parent != "" {
		return deviceAddressLines(d)
	}
	create := fmt.Sprintf("create tap id %d host-if-name %s hw-addr %s host-mac-addr %s", d.ID, d.Host, d.mac(1), d.mac(2))
	// attach alone clears the persistent flag, so VPP's exit would destroy the device.
	create += fmt.Sprintf(" host-mtu-size %d attach persist", deviceHostMTU)
	name := d.vppInterface()
	lines := []string{
		create,
		// host-mtu-size sets only the Linux side; VPP would otherwise keep 9000.
		fmt.Sprintf("set interface mtu packet %d %s", deviceHostMTU, name),
	}
	if !d.SharedTAP {
		lines = append(lines, deviceAddressLines(d)...)
	}
	return append(lines, fmt.Sprintf("set interface state %s up", name), fmt.Sprintf("set interface rx-mode %s interrupt", name))
}

func deviceCLI(devices []DeviceEntry) string {
	var b strings.Builder
	b.WriteString("# Generated by vpp-egress-gate --sync-devices. Do not edit.\n")
	for _, d := range devices {
		b.WriteString(strings.Join(deviceCLILines(d), "\n") + "\n")
	}
	return b.String()
}

func loadDeviceState() (*DeviceState, error) {
	state := &DeviceState{Devices: map[string]*DeviceEntry{}}
	raw, err := os.ReadFile(filepath.Join(deviceStateDir, "devices.json"))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, fmt.Errorf("device journal: %w", err)
	}
	if state.Devices == nil {
		state.Devices = map[string]*DeviceEntry{}
	}
	return state, nil
}

// PlanDevices turns the user's JSON into the devices and the configuration Gate reads.
func PlanDevices(configPath string, state *DeviceState) (*DevicePlan, error) {
	entry, err := readJSONObject(configPath)
	if err != nil {
		return nil, err
	}
	if err := refuseUnknownFields(configPath); err != nil {
		return nil, err
	}
	if _, present := entry["upstream"]; !present {
		return nil, fmt.Errorf("the configuration needs upstream")
	}
	lans, err := parseLANPrefixes(entry)
	if err != nil {
		return nil, err
	}
	var lanInterfaces []string
	if v, ok := entry["lan_interfaces"]; ok && v != nil {
		if lanInterfaces, err = parseNameList(v, "lan_interfaces"); err != nil {
			return nil, err
		}
	}
	routesPath, routesDoc, err := linkedJSON(entry, "domain_routes_file")
	if err != nil {
		return nil, err
	}
	if routesDoc == nil {
		routesPath, routesDoc = configPath, entry
	}
	_, runtime, err := linkedJSON(entry, "route_config")
	if err != nil {
		return nil, err
	}
	if runtime == nil {
		runtime = entry
		for key, value := range map[string]any{
			"listen":           []any{[]any{"127.0.0.1", 1053}},
			"state_file":       "/var/lib/vpp-egress-gate/state.json",
			"lease_file":       "/var/lib/vpp-egress-gate/leases.json",
			"overlap_policy":   "first",
			"exclude_prefixes": defaultExcludePrefixes(lans),
		} {
			if _, present := entry[key]; !present {
				entry[key] = value
			}
		}
	}
	rawRoutes, ok := routesDoc["routes"].([]any)
	if !ok {
		return nil, fmt.Errorf("%s needs routes", routesPath)
	}
	routes := make([]map[string]any, 0, len(rawRoutes))
	activeRoutes := make([]any, 0, len(rawRoutes))
	for _, item := range rawRoutes {
		route, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("routes must be a list of rules")
		}
		// Refused rather than ignored, so that nobody believes they still have a TUN.
		if _, present := route["device"]; present {
			return nil, fmt.Errorf("%s: device is no longer an option, VPP and Linux always meet on a TAP", routeLabel(route))
		}
		if err := checkRouteOwner(route); err != nil {
			return nil, err
		}
		delete(route, "owner")
		if err := absoluteRouteFiles(route); err != nil {
			return nil, err
		}
		// A device changes how its exit forwards even with no rules behind it, so a rule
		// takes effect only once it has something to divert. Gate refuses an empty one.
		if _, explicit := route["interface"]; explicit {
			if _, present := route["ipv6"]; present {
				return nil, fmt.Errorf("%s: ipv6 is for generated devices; write both next hops in via", routeLabel(route))
			}
		}
		if !routeHasRules(route) {
			log.Printf("devices: skipping %s, it has no domains or IP ranges yet", routeLabel(route))
			continue
		}
		routes = append(routes, route)
		activeRoutes = append(activeRoutes, route)
	}
	// An interface's prefixes count before they are seen: a delegated one may come later.
	devices, err := completeDeviceRoutes(routes, state, len(lansOfPrefixes(lans, 6)) > 0 || len(lanInterfaces) > 0)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route["tproxy_exit"] != nil {
			routesDoc["overlap_policy"] = "first"
			break
		}
	}
	for _, d := range devices {
		if d.isProxy() && routesDoc["overlap_policy"] != "first" && runtime["overlap_policy"] != "first" {
			return nil, fmt.Errorf("a Fake-IP rule with TPROXY requires overlap_policy first")
		}
	}
	// One generated file holds everything, whichever way the user split theirs.
	if routesPath != configPath {
		for key, value := range routesDoc {
			if _, present := entry[key]; !present {
				entry[key] = value
			}
		}
		delete(entry, "domain_routes_file")
	}
	entry["routes"] = activeRoutes
	delete(entry, "lan_prefixes")
	effective, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return nil, err
	}
	plan := &DevicePlan{Devices: devices, Effective: string(effective) + "\n", LANIfaces: lanInterfaces}
	for _, lan := range lans {
		plan.LANs = append(plan.LANs, lan.String())
	}
	active := map[string]bool{}
	for _, d := range devices {
		active[d.Host] = true
	}
	var retiredNames []string
	for host := range state.Devices {
		if !active[host] {
			retiredNames = append(retiredNames, host)
		}
	}
	sort.Strings(retiredNames)
	for _, host := range retiredNames {
		d := *state.Devices[host]
		d.Retired = true
		plan.Retired = append(plan.Retired, d)
	}
	plan.VPPSocket, _ = runtime["vpp_socket"].(string)
	if plan.VPPSocket == "" {
		plan.VPPSocket = "/run/vpp/cli.sock"
	}
	plan.Fixed = deviceFixedRules(devices, plan.Retired)
	plan.CLI = deviceCLI(devices)
	return plan, nil
}

// validateEffective runs Gate's own loaders, so a bad file fails before anything changes.
func lansOfPrefixes(lans []netip.Prefix, family int) []netip.Prefix {
	var out []netip.Prefix
	for _, lan := range lans {
		if lan.Addr().Is4() == (family == 4) {
			out = append(out, lan)
		}
	}
	return out
}

// syncIgnoresListProblems is set by the sync before Gate starts, which treats a list file
// as Gate will. A plain sync is how to check one, so it refuses what is wrong.
var syncIgnoresListProblems bool

func validateEffective(plan *DevicePlan) error {
	directory, err := os.MkdirTemp("", "gate-config-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "gate.json")
	if err := os.WriteFile(path, []byte(plan.Effective), 0o600); err != nil {
		return err
	}
	g, err := LoadGateFile(path)
	if err != nil {
		return err
	}
	routePath := g.RouteConfig
	if routePath == "" {
		routePath = path
	}
	cfg, err := LoadConfig(routePath)
	if err != nil {
		return err
	}
	cfg.IgnoreListProblems = syncIgnoresListProblems
	if _, err := DomainRoutesFromFile(path, cfg); err != nil {
		return err
	}
	return validateLinuxExits(cfg)
}

type deviceLink struct {
	Link string `json:"link"`
	Info struct {
		Kind string `json:"info_kind"`
		Data struct {
			Type       string `json:"type"`
			MultiQueue bool   `json:"multi_queue"`
			Persist    bool   `json:"persist"`
			NumQueues  int    `json:"numqueues"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

func readDeviceLink(ctx context.Context, host string) (*deviceLink, error) {
	text, err := runCmdContext(ctx, "ip", "-d", "-j", "link", "show", "dev", host)
	if err != nil {
		if linkMissing(ctx, host) {
			return nil, nil
		}
		return nil, err
	}
	var links []deviceLink
	if err := json.Unmarshal([]byte(text), &links); err != nil {
		return nil, err
	}
	if len(links) == 0 {
		return nil, nil
	}
	return &links[0], nil
}

// ensureDeviceLink creates the device, and never takes over an interface it did not make.
func ensureDeviceLink(ctx context.Context, d DeviceEntry) error {
	link, err := readDeviceLink(ctx, d.Host)
	if err != nil {
		return err
	}
	if link != nil {
		data := link.Info.Data
		if link.Info.Kind != "tun" || data.Type != "tap" || !data.Persist || !data.MultiQueue {
			return fmt.Errorf("Linux interface %s exists and is not a device of this kind; refusing to take it over", d.Host)
		}
		return nil
	}
	// VPP opens the device with IFF_MULTI_QUEUE, which the kernel refuses to mix.
	if _, err := runCmdContext(ctx, "ip", "tuntap", "add", "mode", "tap", "multi_queue", "name", d.Host); err != nil {
		return err
	}
	_, err = runCmdContext(ctx, "ip", "link", "set", "dev", d.Host, "address", d.mac(2))
	return err
}

// ensureGatewayLink makes the macvlan of one gateway on a shared TAP.
func ensureGatewayLink(ctx context.Context, d DeviceEntry) error {
	link, err := readDeviceLink(ctx, d.Host)
	if err != nil {
		return err
	}
	if link != nil {
		if link.Info.Kind != "macvlan" {
			return fmt.Errorf("Linux interface %s exists and is not a device of this kind; refusing to take it over", d.Host)
		}
		if link.Link == d.Parent {
			return nil
		}
		if _, err := runCmdContext(ctx, "ip", "link", "delete", "dev", d.Host); err != nil {
			return err
		}
	}
	_, err = runCmdContext(ctx, "ip", "link", "add", d.Host, "link", d.Parent, "address", d.gatewayMAC(), "type", "macvlan", "mode", "bridge")
	return err
}

// configureSharedTAP readies the TAP under the macvlans. Frames for other MACs reach them,
// and the TAP itself answers nothing, so that each next hop resolves to its own macvlan.
func configureSharedTAP(ctx context.Context, d DeviceEntry) error {
	if err := setSysctl(filepath.Join("net/ipv4/conf", d.Host, "arp_ignore"), "8"); err != nil {
		return err
	}
	if err := setSysctl(filepath.Join("net/ipv6/conf", d.Host, "disable_ipv6"), "1"); err != nil {
		return err
	}
	_, err := runCmdContext(ctx, "ip", "link", "set", "dev", d.Host, "up")
	return err
}

type deviceRoute struct {
	Type     string `json:"type"`
	Dst      string `json:"dst"`
	Dev      string `json:"dev"`
	Protocol string `json:"protocol"`
	Metric   uint32 `json:"metric"`
}

func familyFlag(family int) string { return "-" + strconv.Itoa(family) }

func listDeviceRoutes(ctx context.Context, family int, args ...string) ([]deviceRoute, error) {
	text, err := runCmdContext(ctx, "ip", append([]string{"-j", familyFlag(family), "route", "show"}, args...)...)
	if err != nil {
		// Some kernels report a table without routes as an error.
		if len(args) == 2 && args[0] == "table" && tableEmpty(ctx, family, args[1]) {
			return nil, nil
		}
		return nil, err
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	var routes []deviceRoute
	if err := json.Unmarshal([]byte(text), &routes); err != nil {
		return nil, err
	}
	return routes, nil
}

// ensureRule adds a policy rule once. Adding it twice would leave two rules, and a
// foreign rule at the priority stops the sync. It works for an interface that does not
// exist yet: the rule waits for the name.
func ensureRule(ctx context.Context, family int, priority uint32, iif string, table uint32, match ...string) error {
	text, err := runCmdContext(ctx, "ip", "-N", "-j", familyFlag(family), "rule", "show")
	if err != nil {
		return err
	}
	var rules []struct {
		Priority uint32          `json:"priority"`
		IIF      string          `json:"iif"`
		Table    json.RawMessage `json:"table"`
	}
	if strings.TrimSpace(text) != "" {
		if err := json.Unmarshal([]byte(text), &rules); err != nil {
			return err
		}
	}
	for _, rule := range rules {
		if rule.Priority != priority {
			continue
		}
		if rule.IIF == iif && parseLinuxNumber(rule.Table) == uint64(table) {
			return nil
		}
		return fmt.Errorf("policy rule priority %d is occupied", priority)
	}
	args := append([]string{familyFlag(family), "rule", "add", "priority", fmt.Sprint(priority), "iif", iif}, match...)
	_, err = runCmdContext(ctx, "ip", append(args, "lookup", fmt.Sprint(table))...)
	return err
}

func ensureProxyRoutes(ctx context.Context, d DeviceEntry) error {
	if _, err := runCmdContext(ctx, "ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", fmt.Sprint(deviceProxyTable)); err != nil {
		return err
	}
	if err := ensureRule(ctx, 4, deviceProxyPrio, deviceProxyHost, deviceProxyTable, "fwmark", "1"); err != nil {
		return err
	}
	if !d.IPv6 {
		return nil
	}
	if _, err := runCmdContext(ctx, "ip", "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", fmt.Sprint(deviceProxyTable)); err != nil {
		return err
	}
	return ensureRule(ctx, 6, deviceProxyPrio, deviceProxyHost, deviceProxyTable, "fwmark", "1")
}

// syncReturnRoutes keeps one family of a device's return table equal to the client networks.
func syncReturnRoutes(ctx context.Context, d DeviceEntry, family int, gateway string, lans []string) error {
	table := fmt.Sprint(d.ReturnTable)
	existing, err := listDeviceRoutes(ctx, family, "table", table)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, lan := range lans {
		wanted[lan] = true
	}
	for _, route := range existing {
		if route.Dev != d.Host {
			return fmt.Errorf("routing table %s is occupied by route %s dev %s", table, route.Dst, route.Dev)
		}
		if !wanted[route.Dst] {
			if _, err := runCmdContext(ctx, "ip", familyFlag(family), "route", "del", route.Dst, "table", table); err != nil {
				return err
			}
		}
	}
	for _, lan := range lans {
		if _, err := runCmdContext(ctx, "ip", familyFlag(family), "route", "replace", lan, "via", gateway, "dev", d.Host, "table", table); err != nil {
			return err
		}
	}
	return ensureRule(ctx, family, d.ReturnPriority, d.Exit, d.ReturnTable)
}

// configureDevice is safe to repeat. It leaves other people's routes and rules alone.
func configureDevice(ctx context.Context, d DeviceEntry, lans []string) error {
	if d.Parent != "" {
		// Each answers only for its own address, or a next hop could resolve to the wrong one.
		for name, value := range map[string]string{"arp_ignore": "1", "arp_announce": "2"} {
			if err := setSysctl(filepath.Join("net/ipv4/conf", d.Host, name), value); err != nil {
				return err
			}
		}
	}
	if d.IPv6 {
		// The address is fixed, and a router advertisement must not add another.
		for _, name := range []string{"accept_ra", "autoconf"} {
			if err := setSysctl(filepath.Join("net/ipv6/conf", d.Host, name), "0"); err != nil {
				return err
			}
		}
	}
	if _, err := runCmdContext(ctx, "ip", "link", "set", "dev", d.Host, "up"); err != nil {
		return err
	}
	if _, err := runCmdContext(ctx, "ip", "address", "replace", fmt.Sprintf("%s/%d", d.linuxAddress(), d.prefixLen()), "dev", d.Host); err != nil {
		return err
	}
	if d.IPv6 {
		// nodad: a tentative address could not serve as a next hop, and Gate checks that it exists.
		address := fmt.Sprintf("%s/%d", d.linuxAddress6(), d.prefixLen6())
		if _, err := runCmdContext(ctx, "ip", "-6", "address", "replace", address, "dev", d.Host, "nodad"); err != nil {
			return err
		}
	}
	if !d.IPv6 {
		// A rule can turn IPv6 off while its device stays.
		address := fmt.Sprintf("%s/%d", d.linuxAddress6(), d.prefixLen6())
		if err := ipDelete(ctx, func() bool { return addressMissing(ctx, 6, d.Host, address) }, "-6", "address", "del", address, "dev", d.Host); err != nil {
			return err
		}
		if err := clearFamily(ctx, d, 6); err != nil {
			return err
		}
	}
	if d.isProxy() {
		return ensureProxyRoutes(ctx, d)
	}
	if err := syncReturnRoutes(ctx, d, 4, d.vppAddress().String(), lansOf(lans, 4)); err != nil {
		return err
	}
	if d.IPv6 {
		return syncReturnRoutes(ctx, d, 6, d.vppAddress6().String(), lansOf(lans, 6))
	}
	return nil
}

// syncMainRoutes keeps one main table route per client network, for what Linux itself
// sends to clients: proxy replies and ICMP errors. A route through anything else is
// the host's own way to that network, and it stands. Each family has its own holder,
// the first device that has that family.
func syncMainRoutes(ctx context.Context, devices, retired []DeviceEntry, lans []string) error {
	ours := map[string]bool{}
	for _, d := range append(append([]DeviceEntry{}, devices...), retired...) {
		ours[d.Host] = true
	}
	if len(devices) == 0 {
		return nil
	}
	for _, family := range []int{4, 6} {
		var holder *DeviceEntry
		for i := range devices {
			if !devices[i].SharedTAP && (family == 4 || devices[i].IPv6) {
				holder = &devices[i]
				break
			}
		}
		wanted := map[string]bool{}
		if holder != nil {
			gateway := holder.vppAddress().String()
			if family == 6 {
				gateway = holder.vppAddress6().String()
			}
			for _, lan := range lansOf(lans, family) {
				existing, err := listDeviceRoutes(ctx, family, "exact", lan)
				if err != nil {
					return err
				}
				foreign := false
				for _, route := range existing {
					foreign = foreign || !ours[route.Dev]
				}
				if foreign {
					log.Printf("devices: main table already has a route to %s, leaving it", lan)
					continue
				}
				wanted[holder.Host+"|"+lan] = true
				if _, err := runCmdContext(ctx, "ip", familyFlag(family), "route", "replace", lan, "via", gateway, "dev", holder.Host); err != nil {
					return err
				}
			}
		}
		for _, d := range devices {
			if d.SharedTAP {
				continue
			}
			routes, err := listDeviceRoutes(ctx, family, "dev", d.Host)
			if err != nil {
				return err
			}
			for _, route := range routes {
				if route.Protocol != "kernel" && !wanted[d.Host+"|"+route.Dst] {
					if _, err := runCmdContext(ctx, "ip", familyFlag(family), "route", "del", route.Dst, "dev", d.Host); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// clearFamily removes one family's return routes, rules and TPROXY table of a device.
func clearFamily(ctx context.Context, d DeviceEntry, family int) error {
	flag := familyFlag(family)
	if d.Exit != "" {
		missing := func() bool { return ruleMissing(ctx, family, d.ReturnPriority, d.Exit) }
		if err := ipDelete(ctx, missing, flag, "rule", "del", "priority", fmt.Sprint(d.ReturnPriority), "iif", d.Exit, "lookup", fmt.Sprint(d.ReturnTable)); err != nil {
			return err
		}
		routes, err := listDeviceRoutes(ctx, family, "table", fmt.Sprint(d.ReturnTable))
		if err != nil {
			return err
		}
		for _, route := range routes {
			if _, err := runCmdContext(ctx, "ip", flag, "route", "del", route.Dst, "table", fmt.Sprint(d.ReturnTable)); err != nil {
				return err
			}
		}
		return nil
	}
	missing := func() bool { return ruleMissing(ctx, family, deviceProxyPrio, deviceProxyHost) }
	if err := ipDelete(ctx, missing, flag, "rule", "del", "priority", fmt.Sprint(deviceProxyPrio), "iif", deviceProxyHost, "fwmark", "1", "lookup", fmt.Sprint(deviceProxyTable)); err != nil {
		return err
	}
	local := "0.0.0.0/0"
	if family == 6 {
		local = "::/0"
	}
	routeGone := func() bool {
		return routeMissing(ctx, family, deviceProxyTable, func(r deviceRoute) bool { return r.Type == "local" && r.Dst == "default" })
	}
	return ipDelete(ctx, routeGone, flag, "route", "del", "local", local, "dev", "lo", "table", fmt.Sprint(deviceProxyTable))
}

// retireDevice removes what steers traffic into the device at once. The device goes
// when VPP has let go of it, which a boot guarantees, so VPP never loses it in use.
func retireDevice(ctx context.Context, d DeviceEntry) (gone bool, err error) {
	for _, family := range []int{4, 6} {
		if d.SharedTAP {
			break
		}
		if err := clearFamily(ctx, d, family); err != nil {
			return false, err
		}
	}
	link, err := readDeviceLink(ctx, d.Host)
	if err != nil {
		return false, err
	}
	if link == nil {
		return true, nil
	}
	if link.Info.Data.NumQueues > 0 {
		log.Printf("devices: %s has left the configuration; it goes once VPP restarts", d.Host)
		return false, nil
	}
	if _, err := runCmdContext(ctx, "ip", "link", "delete", "dev", d.Host); err != nil {
		return false, err
	}
	return true, nil
}

// attachRunningVPP gives a running VPP the devices it lacks, so that adding one does
// not need a restart. At boot VPP has not started, and the startup CLI does the work.
func attachRunningVPP(ctx context.Context, plan *DevicePlan) error {
	if _, err := os.Stat(plan.VPPSocket); err != nil {
		return nil
	}
	current, err := runCmdContext(ctx, "vppctl", "-s", plan.VPPSocket, "show", "interface")
	if err != nil {
		log.Printf("devices: VPP not reachable, its startup CLI will attach the devices: %s", err)
		return nil
	}
	addresses, err := runCmdContext(ctx, "vppctl", "-s", plan.VPPSocket, "show", "interface", "addr")
	if err != nil {
		return err
	}
	run := func(line string) error {
		out, err := runCmdContext(ctx, "vppctl", append([]string{"-s", plan.VPPSocket}, strings.Fields(line)...)...)
		if err != nil {
			return err
		}
		lower := strings.ToLower(out)
		if strings.Contains(lower, "unknown input") || strings.Contains(lower, "error") || strings.Contains(lower, "failed") {
			return fmt.Errorf("vppctl %s: %s", line, strings.TrimSpace(out))
		}
		return nil
	}
	// A gateway that left a shared TAP gives its addresses back, as the TAP stays.
	for _, d := range plan.Retired {
		if d.Parent == "" {
			continue
		}
		for _, address := range []string{fmt.Sprintf("%s/%d", d.vppAddress(), d.prefixLen()), fmt.Sprintf("%s/%d", d.vppAddress6(), d.prefixLen6())} {
			if vppInterfaceHasAddress(addresses, d.vppInterface(), address) {
				if err := run(fmt.Sprintf("set interface ip address del %s %s", d.vppInterface(), address)); err != nil {
					return err
				}
			}
		}
	}
	for _, d := range plan.Devices {
		if d.Parent != "" {
			for _, line := range deviceAddressLines(d) {
				fields := strings.Fields(line)
				if !vppInterfaceHasAddress(addresses, d.vppInterface(), fields[len(fields)-1]) {
					if err := run(line); err != nil {
						return err
					}
				}
			}
			if !d.IPv6 {
				address := fmt.Sprintf("%s/%d", d.vppAddress6(), d.prefixLen6())
				if vppInterfaceHasAddress(addresses, d.vppInterface(), address) {
					if err := run(fmt.Sprintf("set interface ip address del %s %s", d.vppInterface(), address)); err != nil {
						return err
					}
				}
			}
			continue
		}
		if regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(d.vppInterface()) + `\s`).MatchString(current) {
			if d.SharedTAP {
				continue
			}
			// A rule can turn IPv6 on or off while VPP holds the device.
			address := fmt.Sprintf("%s/%d", d.vppAddress6(), d.prefixLen6())
			present := vppInterfaceHasAddress(addresses, d.vppInterface(), address)
			if d.IPv6 && !present {
				if err := run(fmt.Sprintf("set interface ip address %s %s", d.vppInterface(), address)); err != nil {
					return err
				}
			}
			if !d.IPv6 && present {
				if err := run(fmt.Sprintf("set interface ip address del %s %s", d.vppInterface(), address)); err != nil {
					return err
				}
			}
			continue
		}
		for _, line := range deviceCLILines(d) {
			if err := run(line); err != nil {
				return err
			}
		}
	}
	return nil
}

func vppInterfaceHasAddress(output, name, address string) bool {
	current := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, " \r")
		if line != "" && line[0] != ' ' {
			current = strings.Fields(line)[0]
		} else if current == name && strings.TrimSpace(line) == "L3 "+address {
			return true
		}
	}
	return false
}

func writeDeviceFile(path, text string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(text), mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func (s *DeviceState) active() []DeviceEntry {
	var devices []DeviceEntry
	for _, host := range s.Order {
		if d := s.Devices[host]; d != nil && !d.Retired {
			devices = append(devices, *d)
		}
	}
	return devices
}

func (s *DeviceState) retired() []DeviceEntry {
	var devices []DeviceEntry
	for _, d := range s.Devices {
		if d.Retired {
			devices = append(devices, *d)
		}
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Host < devices[j].Host })
	return devices
}

func loadFixedRules(ctx context.Context, state *DeviceState) error {
	path := filepath.Join(deviceStateDir, "fixed.nft")
	if err := writeDeviceFile(path, deviceFixedRules(state.active(), state.retired()), 0o644); err != nil {
		return err
	}
	_, err := runCmdContext(ctx, "nft", "-f", path)
	return err
}

func setSysctl(name, value string) error {
	path := filepath.Join(linuxSysctlRoot, name)
	current, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err == nil && strings.TrimSpace(string(current)) == value {
		return nil
	}
	if err == nil {
		err = recordHostSetting(name, strings.TrimSpace(string(current)), value)
	}
	if err == nil {
		err = os.WriteFile(path, []byte(value+"\n"), 0o644)
	}
	if err != nil {
		return fmt.Errorf("cannot set %s: %w", name, err)
	}
	log.Printf("devices: set %s to %s for Linux exits", name, value)
	return nil
}

// keepRouterAdvertisements stops IPv6 forwarding from costing the host its addresses:
// by default an interface ignores router advertisements once forwarding is on, and
// accept_ra 2 is how it keeps them.
func keepRouterAdvertisements() error {
	paths, err := filepath.Glob(filepath.Join(linuxSysctlRoot, "net/ipv6/conf/*/accept_ra"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		name, _ := filepath.Rel(linuxSysctlRoot, path)
		if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) == "1" {
			if err := setSysctl(name, "2"); err != nil {
				return err
			}
		}
	}
	return nil
}

// enableIPv6Forwarding touches nothing when forwarding is on already, in any form:
// 2 also means on, and it is the host's own choice.
func enableIPv6Forwarding(ctx context.Context) error {
	const name = "net/ipv6/conf/all/forwarding"
	current, err := os.ReadFile(filepath.Join(linuxSysctlRoot, name))
	if err != nil || strings.TrimSpace(string(current)) != "0" {
		return nil
	}
	if err := keepRouterAdvertisements(); err != nil {
		return err
	}
	if err := setSysctl(name, "1"); err != nil {
		return err
	}
	warnIfForwardingIsOpen(ctx, 6)
	return nil
}

// enableExitForwarding changes host-wide settings, so it waits for the first exit in
// use. The kernel applies the larger of "all" and an interface's rp_filter, and replies
// arrive on an exit without a mark, so a strict "all" would drop them.
func enableExitForwarding(devices []DeviceEntry) error {
	ctx := context.Background()
	was, _ := os.ReadFile(filepath.Join(linuxSysctlRoot, "net/ipv4/ip_forward"))
	if err := setSysctl("net/ipv4/ip_forward", "1"); err != nil {
		return err
	}
	if strings.TrimSpace(string(was)) == "0" {
		warnIfForwardingIsOpen(ctx, 4)
	}
	if err := setSysctl("net/ipv4/conf/all/rp_filter", "0"); err != nil {
		return err
	}
	for _, d := range devices {
		if d.IPv6 && !d.isProxy() {
			return enableIPv6Forwarding(ctx)
		}
	}
	return nil
}

// applyLinks makes Linux match the journal. It never talks to VPP.
func applyLinks(ctx context.Context, state *DeviceState) error {
	// The guard comes first, so that no device can carry traffic without it.
	if err := loadFixedRules(ctx, state); err != nil {
		return err
	}
	devices := state.active()
	// What the running Gate found on the LAN interfaces stays, or a sync would drop it.
	lans := state.clientNetworks(readLearnedLANs())
	if len(devices) > 0 {
		if err := enableExitForwarding(devices); err != nil {
			return err
		}
	}
	for _, d := range devices {
		if d.SharedTAP {
			if err := ensureDeviceLink(ctx, d); err != nil {
				return err
			}
			if err := configureSharedTAP(ctx, d); err != nil {
				return fmt.Errorf("%s: %w", d.Host, err)
			}
			continue
		}
		if d.Parent != "" {
			if err := ensureGatewayLink(ctx, d); err != nil {
				return err
			}
		} else if err := ensureDeviceLink(ctx, d); err != nil {
			return err
		}
		if err := configureDevice(ctx, d, lans); err != nil {
			return fmt.Errorf("%s: %w", d.Host, err)
		}
	}
	if err := syncMainRoutes(ctx, devices, state.retired(), lans); err != nil {
		return err
	}
	removed := false
	for _, d := range state.retired() {
		gone, err := retireDevice(ctx, d)
		if err != nil {
			return fmt.Errorf("%s: %w", d.Host, err)
		}
		if gone {
			delete(state.Devices, d.Host)
			removed = true
		}
	}
	if !removed {
		return nil
	}
	if err := durableJSON(filepath.Join(deviceStateDir, "devices.json"), state); err != nil {
		return err
	}
	return loadFixedRules(ctx, state)
}

// SetupLinks is the --setup-links mode: restore Linux from the last successful sync.
func SetupLinks() error {
	state, err := loadDeviceState()
	if err != nil {
		return err
	}
	if len(state.Devices) == 0 {
		log.Printf("devices: nothing recorded yet, run --sync-devices first")
		return nil
	}
	return applyLinks(context.Background(), state)
}

// SyncDevices is the --sync-devices mode: apply the user's JSON, and exit.
func SyncDevices(configPath string, dryRun bool) error {
	ctx := context.Background()
	state, err := loadDeviceState()
	if err != nil {
		return err
	}
	plan, err := PlanDevices(configPath, state)
	if err != nil {
		return err
	}
	if err := validateEffective(plan); err != nil {
		return fmt.Errorf("generated configuration: %w", err)
	}
	if dryRun {
		out, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	next := &DeviceState{Devices: map[string]*DeviceEntry{}, LANs: plan.LANs, LANInterfaces: plan.LANIfaces}
	for i := range plan.Devices {
		d := &plan.Devices[i]
		next.Devices[d.Host] = d
		next.Order = append(next.Order, d.Host)
	}
	for i := range plan.Retired {
		next.Devices[plan.Retired[i].Host] = &plan.Retired[i]
	}
	// Record ownership before changing anything, so a partial run can be cleaned up.
	if err := durableJSON(filepath.Join(deviceStateDir, "devices.json"), next); err != nil {
		return err
	}
	if err := applyLinks(ctx, next); err != nil {
		return err
	}
	if err := writeDeviceFile(filepath.Join(deviceStateDir, "vpp-devices.cli"), plan.CLI, 0o644); err != nil {
		return err
	}
	if err := writeDeviceFile(filepath.Join(deviceStateDir, "gate.json"), plan.Effective, 0o600); err != nil {
		return err
	}
	return attachRunningVPP(ctx, plan)
}
