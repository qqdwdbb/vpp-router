package gate

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/dhcp"
	"go.fd.io/govpp/binapi/fib"
	"go.fd.io/govpp/binapi/fib_types"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip"
	"go.fd.io/govpp/binapi/ip_types"
	"go.fd.io/govpp/binapi/wireguard"
)

// A rule with default_route also carries what no rule and no more specific route claims.
//
// The exit takes the two halves of the address space, 0.0.0.0/1 and 128.0.0.0/1 (::/1 and
// 8000::/1), and leaves 0.0.0.0/0 to whoever set it: DHCP, SLAAC or the startup CLI. That
// route stays readable and in place, so removing the halves is all a fallback takes.
//
// Some traffic must keep using that route, or the exit would carry itself:
//   - WireGuard endpoints in VPP. A tunnel used as the exit would otherwise send its own
//     packets into itself, and a WireGuard server would answer its clients through the exit.
//   - exclude_prefixes, which already hold the endpoints of Linux exit tunnels and the
//     networks Gate never routes (private, loopback and link-local by default). Without an
//     exit chosen they follow 0.0.0.0/0, and so they still do.
//
// These are pinned with copies of 0.0.0.0/0's paths. Everything here has a FIB source of its
// own, ranked below the sources that install routes, so any other route on the same prefix
// wins, and an entry can be removed whole without naming its paths.
//
// The halves are only in place while the exit can carry traffic: its VPP interface exists
// and is up, and for a Linux exit, so is the Linux interface. Otherwise traffic falls back to
// 0.0.0.0/0. Whether the far end answers is not something an interface says, so a tunnel that
// is up but dead is not noticed.
const (
	defaultSourceName     = "vpp-egress-gate-default"
	defaultSourcePriority = 240 // below CLI, API, DHCP and adjacency, above Gate's drop routes
	defaultCheckTicks     = 5   // ticks between checks when nothing else asks for one
)

var defaultHalves = map[int][]string{4: {"0.0.0.0/1", "128.0.0.0/1"}, 6: {"::/1", "8000::/1"}}

// defaultExit is where one family's default route goes.
type defaultExit struct {
	Table     uint32
	Interface string
	Via       string // empty when DHCP gives it
	DHCP      bool   // the IPv4 next hop is the router in VPP's DHCP lease on Interface
	LinuxExit string // the Linux interface behind a Linux exit's device
}

// defaultVia is a mapping's next hop for the default route, with "dhcp" for one the lease gives.
func defaultVia(m Mapping, family int) string {
	if family == 4 && m.DHCPGateway {
		return "dhcp"
	}
	return m.ViaFor(family)
}

// validateDefaultRoutes allows one exit per family. Several rules may say so as long as they
// name the same one, like the IPv4 and IPv6 rules of a group.
func validateDefaultRoutes(mappings []Mapping) error {
	chosen := map[int]Mapping{}
	for _, m := range mappings {
		if !m.Enabled || !m.Default {
			continue
		}
		for _, family := range []int{4, 6} {
			via := defaultVia(m, family)
			if via == "" {
				continue
			}
			if other, ok := chosen[family]; ok && (other.FibTable != m.FibTable || other.Interface != m.Interface || defaultVia(other, family) != via) {
				return fmt.Errorf("rules %s and %s both carry the IPv%d default route through different exits", other.Set, m.Set, family)
			}
			chosen[family] = m
		}
	}
	return nil
}

// defaultExits returns the exit of each family that has one.
func defaultExits(cfg *Config) map[int]defaultExit {
	exits := map[int]defaultExit{}
	if cfg == nil {
		return exits
	}
	for _, m := range cfg.Mappings {
		if !m.Enabled || !m.Default {
			continue
		}
		for _, family := range []int{4, 6} {
			if via := defaultVia(m, family); via != "" {
				exit := defaultExit{Table: m.FibTable, Interface: m.Interface, Via: via}
				if via == "dhcp" {
					exit.Via, exit.DHCP = "", true
				}
				if m.LinuxExit != nil {
					exit.LinuxExit = m.LinuxExit.Interface
				}
				exits[family] = exit
			}
		}
	}
	return exits
}

// defaultPath is one FIB path, in a form that can be compared and stored.
type defaultPath struct {
	SwIfIndex uint32
	Table     uint32
	Type      fib_types.FibPathType
	Proto     fib_types.FibPathNhProto
	Next      netip.Addr // invalid for a path with no next hop
	Weight    uint8
	Pref      uint8
}

func (p defaultPath) String() string {
	next := "-"
	if p.Next.IsValid() {
		next = p.Next.String()
	}
	return fmt.Sprintf("%d/%d/%d/%d/%s/%d/%d", p.SwIfIndex, p.Table, p.Type, p.Proto, next, p.Weight, p.Pref)
}

// defaultRoute is one route Gate wants under its default source.
type defaultRoute struct {
	Table  uint32
	Prefix string
	Paths  []defaultPath
}

func (r defaultRoute) Key() RouteKey { return RouteKey{r.Table, r.Prefix} }

// signature tells whether a route already in place is still the one wanted.
func (r defaultRoute) signature() string {
	parts := make([]string, len(r.Paths))
	for i, p := range r.Paths {
		parts[i] = p.String()
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// defaultObservation is what VPP says, for the tables the exits use.
type defaultObservation struct {
	Interfaces map[string]vppInterfaceState
	Fallback   map[RouteKey][]defaultPath // 0.0.0.0/0 and ::/0 per table, best source's usable paths
	Endpoints  []defaultEndpoint          // WireGuard peers
	Leases     map[string]netip.Addr      // router of each bound DHCP lease, by interface
}

type vppInterfaceState struct {
	Index uint32
	Up    bool // admin and link
}

type defaultEndpoint struct {
	Table   uint32
	Address netip.Addr
}

func familyDefault(family int) string {
	if family == 4 {
		return "0.0.0.0/0"
	}
	return "::/0"
}

// DefaultRouteStatus is what the state socket reports about the default route.
type DefaultRouteStatus struct {
	Interface string `json:"interface,omitempty"`
	Families  []int  `json:"families"` // configured
	Active    []int  `json:"active"`   // the exit carries them now
	Problem   string `json:"problem,omitempty"`
}

// planDefaultRoutes lists the routes wanted now, and says what is in use.
func planDefaultRoutes(exits map[int]defaultExit, excludes []string, obs defaultObservation, linuxUp func(string) bool) (map[RouteKey]defaultRoute, DefaultRouteStatus) {
	desired := map[RouteKey]defaultRoute{}
	status := DefaultRouteStatus{Families: []int{}, Active: []int{}}
	var problems []string
	for _, family := range []int{4, 6} {
		exit, ok := exits[family]
		if !ok {
			continue
		}
		status.Interface = exit.Interface
		status.Families = append(status.Families, family)
		state, present := obs.Interfaces[exit.Interface]
		switch {
		case !present:
			problems = append(problems, fmt.Sprintf("%s is not in VPP", exit.Interface))
			continue
		case !state.Up:
			problems = append(problems, fmt.Sprintf("%s is down", exit.Interface))
			continue
		case exit.LinuxExit != "" && !linuxUp(exit.LinuxExit):
			problems = append(problems, fmt.Sprintf("Linux interface %s is missing or down", exit.LinuxExit))
			continue
		}
		var next netip.Addr
		if exit.DHCP {
			if next = obs.Leases[exit.Interface]; !next.IsValid() {
				problems = append(problems, fmt.Sprintf("%s has no DHCP lease with a router", exit.Interface))
				continue
			}
		} else if parsed, err := netip.ParseAddr(exit.Via); err == nil {
			next = parsed
		} else {
			continue
		}
		proto := fib_types.FIB_API_PATH_NH_PROTO_IP4
		if family == 6 {
			proto = fib_types.FIB_API_PATH_NH_PROTO_IP6
		}
		through := []defaultPath{{SwIfIndex: state.Index, Type: fib_types.FIB_API_PATH_TYPE_NORMAL, Proto: proto, Next: next, Weight: 1}}
		for _, half := range defaultHalves[family] {
			route := defaultRoute{Table: exit.Table, Prefix: half, Paths: through}
			desired[route.Key()] = route
		}
		status.Active = append(status.Active, family)

		fallback := obs.Fallback[RouteKey{exit.Table, familyDefault(family)}]
		if len(fallback) == 0 {
			continue // nothing to keep reachable the old way
		}
		loops := false
		for _, path := range fallback {
			loops = loops || path.SwIfIndex == state.Index
		}
		if loops {
			continue // 0.0.0.0/0 already goes through the exit
		}
		pin := func(prefix netip.Prefix) {
			key := RouteKey{exit.Table, prefixString(prefix)}
			if _, taken := desired[key]; !taken {
				desired[key] = defaultRoute{Table: exit.Table, Prefix: key.Prefix, Paths: fallback}
			}
		}
		for _, text := range excludes {
			if prefix, err := parsePrefixStrict(text); err == nil && (family == 4) == prefix.Addr().Is4() && prefix.Bits() > 0 {
				pin(prefix)
			}
		}
		for _, endpoint := range obs.Endpoints {
			if endpoint.Table == exit.Table && (family == 4) == endpoint.Address.Is4() && !endpoint.Address.IsUnspecified() {
				pin(netip.PrefixFrom(endpoint.Address, endpoint.Address.BitLen()))
			}
		}
	}
	status.Problem = strings.Join(problems, "; ")
	return desired, status
}

// defaultRouteAPI is the part of VPP the keeper uses.
type defaultRouteAPI interface {
	generation() (string, error)
	observe(tables []uint32) (defaultObservation, error)
	add(route defaultRoute) error
	remove(key RouteKey) error
}

// defaultRouteKeeper keeps VPP's routes matching the plan. A failure costs the choice of
// exit, not DNS, so it never stops Gate.
type defaultRouteKeeper struct {
	config    func() *Config
	api       defaultRouteAPI
	linuxUp   func(string) bool
	statePath string

	generation string
	current    map[RouteKey]string // signatures of what is in place
	wait       int
	problems   failureLog

	mu     sync.Mutex
	status DefaultRouteStatus
	logged string
}

func newDefaultRouteKeeper(config func() *Config, api defaultRouteAPI) *defaultRouteKeeper {
	cfg := config()
	return &defaultRouteKeeper{
		config:    config,
		api:       api,
		linuxUp:   linuxInterfaceUp,
		statePath: defaultStatePath(cfg),
		current:   map[RouteKey]string{},
		problems:  failureLog{what: "default route not updated"},
		status:    DefaultRouteStatus{Families: []int{}, Active: []int{}},
	}
}

func defaultStatePath(cfg *Config) string { return cfg.StateFile + ".default" }

// Status is safe to call from any goroutine.
func (k *defaultRouteKeeper) Status() DefaultRouteStatus {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.status
}

// tick checks every few calls, or at once when forced.
func (k *defaultRouteKeeper) tick(force bool) {
	if k.wait++; !force && k.wait < defaultCheckTicks {
		return
	}
	k.wait = 0
	k.ensure()
}

func (k *defaultRouteKeeper) ensure() {
	generation, err := k.api.generation()
	if err != nil {
		return // VPP is restarting; the next tick looks again
	}
	if generation != k.generation {
		// Routes from an earlier VPP run went with it.
		k.generation, k.current = generation, readDefaultState(k.statePath, generation)
	}
	cfg := k.config()
	exits := defaultExits(cfg)
	if len(exits) == 0 && len(k.current) == 0 {
		k.setStatus(DefaultRouteStatus{Families: []int{}, Active: []int{}})
		return // nothing chosen and nothing to undo: VPP is not asked anything
	}
	tables := map[uint32]bool{}
	for _, exit := range exits {
		tables[exit.Table] = true
	}
	list := make([]uint32, 0, len(tables))
	for table := range tables {
		list = append(list, table)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	obs, err := k.api.observe(list)
	if err != nil {
		k.problems.failed(err)
		return
	}
	desired, status := planDefaultRoutes(exits, cfg.ExcludePrefixes, obs, k.linuxUp)
	if err := k.apply(desired); err != nil {
		k.problems.failed(err)
		status.Problem = strings.TrimPrefix(status.Problem+"; "+err.Error(), "; ")
		k.setStatus(status)
		return
	}
	k.problems.recovered("default route updated")
	k.setStatus(status)
}

func (k *defaultRouteKeeper) setStatus(status DefaultRouteStatus) {
	k.mu.Lock()
	k.status = status
	k.mu.Unlock()
	text := describeDefaultStatus(status)
	if text != k.logged {
		k.logged = text
		log.Print(text)
	}
}

func describeDefaultStatus(status DefaultRouteStatus) string {
	if len(status.Families) == 0 {
		return "default route: the system's"
	}
	var parts []string
	for _, family := range status.Families {
		active := false
		for _, f := range status.Active {
			active = active || f == family
		}
		if active {
			parts = append(parts, fmt.Sprintf("IPv%d through %s", family, status.Interface))
		} else {
			parts = append(parts, fmt.Sprintf("IPv%d falls back to the system's", family))
		}
	}
	text := "default route: " + strings.Join(parts, ", ")
	if status.Problem != "" {
		text += " (" + status.Problem + ")"
	}
	return text
}

// apply removes what is no longer wanted and adds what is missing. What is added is
// recorded first, so that it can always be removed, also by a later Gate or a flush.
func (k *defaultRouteKeeper) apply(desired map[RouteKey]defaultRoute) error {
	var first error
	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	changed := false
	for _, key := range sortedRouteKeys(k.current) {
		route, wanted := desired[key]
		if wanted && route.signature() == k.current[key] {
			continue
		}
		if err := k.api.remove(key); err != nil {
			note(err)
			continue
		}
		delete(k.current, key)
		changed = true
	}
	var added []defaultRoute
	for key, route := range desired {
		if _, present := k.current[key]; !present {
			added = append(added, route)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Key().less(added[j].Key()) })
	if len(added) > 0 {
		recorded := make(map[RouteKey]string, len(k.current)+len(added))
		for key, signature := range k.current {
			recorded[key] = signature
		}
		for _, route := range added {
			recorded[route.Key()] = "" // removable, not yet known to be in place
		}
		if err := saveDefaultState(k.statePath, k.generation, recorded); err != nil {
			return fmt.Errorf("saving %s, nothing added: %w", k.statePath, err)
		}
		// The halves go last: the pins must be in place before traffic moves.
		sort.SliceStable(added, func(i, j int) bool { return !isDefaultHalf(added[i].Prefix) && isDefaultHalf(added[j].Prefix) })
		for _, route := range added {
			if err := k.api.add(route); err != nil {
				note(err)
				k.current[route.Key()] = "" // recorded, and retried as changed next time
				continue
			}
			k.current[route.Key()] = route.signature()
		}
		changed = true
	}
	if changed {
		note(saveDefaultState(k.statePath, k.generation, k.current))
	}
	return first
}

func isDefaultHalf(prefix string) bool {
	for _, halves := range defaultHalves {
		for _, half := range halves {
			if half == prefix {
				return true
			}
		}
	}
	return false
}

func (a RouteKey) less(b RouteKey) bool {
	if a.Table != b.Table {
		return a.Table < b.Table
	}
	return a.Prefix < b.Prefix
}

func sortedRouteKeys(set map[RouteKey]string) []RouteKey {
	keys := make([]RouteKey, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].less(keys[j]) })
	return keys
}

func readDefaultState(path, generation string) map[RouteKey]string {
	current := map[RouteKey]string{}
	state, _ := ReadJSON(path, map[string]any{}).(map[string]any)
	if g, _ := state["generation"].(string); g != generation {
		return current
	}
	items, _ := state["routes"].([]any)
	for _, item := range items {
		fields, _ := item.(map[string]any)
		prefix, _ := fields["prefix"].(string)
		table, err := asInt(fields["table"])
		signature, _ := fields["paths"].(string)
		if prefix != "" && err == nil {
			current[RouteKey{uint32(table), prefix}] = signature
		}
	}
	return current
}

func saveDefaultState(path, generation string, set map[RouteKey]string) error {
	routes := make([]map[string]any, 0, len(set))
	for _, key := range sortedRouteKeys(set) {
		routes = append(routes, map[string]any{"table": key.Table, "prefix": key.Prefix, "paths": set[key]})
	}
	return AtomicJSON(path, map[string]any{"generation": generation, "routes": routes})
}

func linuxInterfaceUp(name string) bool {
	link, err := net.InterfaceByName(name)
	return err == nil && link.Flags&net.FlagUp != 0 && link.Flags&net.FlagRunning != 0
}

// vppDefaultRouteAPI reaches VPP through Gate's shared API session.
type vppDefaultRouteAPI struct {
	cfg     *Config
	backend Backend
}

func (v vppDefaultRouteAPI) generation() (string, error) { return v.backend.Generation() }

func (v vppDefaultRouteAPI) session(do func(*vppAPISession) error) error {
	apiMu <- struct{}{}
	defer func() { <-apiMu }()
	sess, err := vppAPI(v.cfg)
	if err != nil {
		dropAPICache()
		return err
	}
	if err := do(sess); err != nil {
		var failure api.VPPApiError
		if !errors.As(err, &failure) {
			dropAPICache() // a broken connection, not a refusal
		}
		return err
	}
	return nil
}

func (v vppDefaultRouteAPI) observe(tables []uint32) (defaultObservation, error) {
	obs := defaultObservation{Fallback: map[RouteKey][]defaultPath{}}
	err := v.session(func(s *vppAPISession) error {
		var err error
		if obs.Interfaces, err = s.dumpInterfaceStates(); err != nil {
			return err
		}
		for _, table := range tables {
			for _, family := range []int{4, 6} {
				paths, err := s.lookupExact(table, familyDefault(family))
				if err != nil {
					return err
				}
				obs.Fallback[RouteKey{table, familyDefault(family)}] = paths
			}
		}
		if obs.Endpoints, err = s.wireguardEndpoints(); err != nil {
			return err
		}
		obs.Leases, err = s.dhcpRouters(obs.Interfaces)
		return err
	})
	return obs, err
}

func (v vppDefaultRouteAPI) add(route defaultRoute) error {
	return v.session(func(s *vppAPISession) error { return s.defaultRouteAddDel(true, route) })
}

func (v vppDefaultRouteAPI) remove(key RouteKey) error {
	return v.session(func(s *vppAPISession) error {
		return s.defaultRouteAddDel(false, defaultRoute{Table: key.Table, Prefix: key.Prefix})
	})
}

// defaultSource finds Gate's default source, registering it the first time this VPP run needs it.
func (s *vppAPISession) defaultSource() (uint8, error) {
	if s.defaultSrc != 0 {
		return s.defaultSrc, nil
	}
	sources, err := dumpAll(s.ch, &fib.FibSourceDump{}, func() (*fib.FibSourceDetails, api.Message) {
		details := &fib.FibSourceDetails{}
		return details, details
	})
	if err != nil {
		return 0, err
	}
	for _, details := range sources {
		if strings.TrimRight(details.Src.Name, "\x00") == defaultSourceName {
			s.defaultSrc = details.Src.ID
			return s.defaultSrc, nil
		}
	}
	reply := &fib.FibSourceAddReply{}
	err = s.ch.SendRequest(&fib.FibSourceAdd{Src: fib.FibSource{Priority: defaultSourcePriority, Name: defaultSourceName}}).ReceiveReply(reply)
	if err := checkRetval("VPP FIB source add", reply.Retval, err); err != nil {
		return 0, err
	}
	s.defaultSrc = reply.ID
	return s.defaultSrc, nil
}

func (s *vppAPISession) dumpInterfaceStates() (map[string]vppInterfaceState, error) {
	details, err := dumpAll(s.ch, &interfaces.SwInterfaceDump{SwIfIndex: ^interface_types.InterfaceIndex(0)}, func() (*interfaces.SwInterfaceDetails, api.Message) {
		d := &interfaces.SwInterfaceDetails{}
		return d, d
	})
	if err != nil {
		return nil, err
	}
	states := make(map[string]vppInterfaceState, len(details))
	names := make(map[string]uint32, len(details))
	const up = interface_types.IF_STATUS_API_FLAG_ADMIN_UP | interface_types.IF_STATUS_API_FLAG_LINK_UP
	for _, d := range details {
		name := strings.TrimRight(d.InterfaceName, "\x00")
		if name == "" {
			continue
		}
		states[name] = vppInterfaceState{Index: uint32(d.SwIfIndex), Up: d.Flags&up == up}
		names[name] = uint32(d.SwIfIndex)
	}
	s.ifaces = names
	return states, nil
}

// lookupExact returns the usable paths of a prefix's best source. A table that does not exist,
// or a prefix with only a drop, has none.
func (s *vppAPISession) lookupExact(table uint32, text string) ([]defaultPath, error) {
	prefix, err := ip_types.ParsePrefix(text)
	if err != nil {
		return nil, err
	}
	reply := &ip.IPRouteLookupV2Reply{}
	if err := s.ch.SendRequest(&ip.IPRouteLookupV2{TableID: table, Exact: 1, Prefix: prefix}).ReceiveReply(reply); err != nil {
		var failure api.VPPApiError
		if errors.As(err, &failure) {
			return nil, nil
		}
		return nil, err
	}
	if reply.Retval != 0 {
		return nil, nil
	}
	var paths []defaultPath
	for _, p := range reply.Route.Paths {
		if path, ok := usablePath(p); ok {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

// usablePath keeps paths that forward somewhere: not drops, not local delivery.
func usablePath(p fib_types.FibPath) (defaultPath, bool) {
	switch p.Type {
	case fib_types.FIB_API_PATH_TYPE_NORMAL:
	default:
		return defaultPath{}, false
	}
	path := defaultPath{SwIfIndex: p.SwIfIndex, Table: p.TableID, Type: p.Type, Proto: p.Proto, Weight: p.Weight, Pref: p.Preference}
	var next netip.Addr
	switch p.Proto {
	case fib_types.FIB_API_PATH_NH_PROTO_IP4:
		ip4 := p.Nh.Address.GetIP4()
		next = netip.AddrFrom4([4]byte(ip4))
	case fib_types.FIB_API_PATH_NH_PROTO_IP6:
		ip6 := p.Nh.Address.GetIP6()
		next = netip.AddrFrom16([16]byte(ip6))
	default:
		return defaultPath{}, false
	}
	if !next.IsUnspecified() {
		path.Next = next
	}
	if p.SwIfIndex == ^uint32(0) && !path.Next.IsValid() {
		return defaultPath{}, false // neither an interface nor a next hop: nowhere to go
	}
	if path.Weight == 0 {
		path.Weight = 1
	}
	return path, true
}

// dhcpRouters lists the router of every bound IPv4 lease. VPP without the plugin has none.
func (s *vppAPISession) dhcpRouters(states map[string]vppInterfaceState) (map[string]netip.Addr, error) {
	if s.dhcp == 0 {
		s.dhcp = -1
		if s.ch.CheckCompatiblity((*dhcp.DHCPClientDump)(nil), (*dhcp.DHCPClientDetails)(nil)) == nil {
			s.dhcp = 1
		}
	}
	if s.dhcp < 0 {
		return nil, nil
	}
	clients, err := dumpAll(s.ch, &dhcp.DHCPClientDump{}, func() (*dhcp.DHCPClientDetails, api.Message) {
		d := &dhcp.DHCPClientDetails{}
		return d, d
	})
	if err != nil {
		return nil, err
	}
	names := make(map[uint32]string, len(states))
	for name, state := range states {
		names[state.Index] = name
	}
	routers := map[string]netip.Addr{}
	for _, client := range clients {
		lease := client.Lease
		if lease.IsIPv6 || lease.State != dhcp.DHCP_CLIENT_STATE_API_BOUND {
			continue
		}
		router, ok := netip.AddrFromSlice(lease.RouterAddress.ToIP().To4())
		name := names[uint32(lease.SwIfIndex)]
		if ok && name != "" && !router.IsUnspecified() {
			routers[name] = router
		}
	}
	return routers, nil
}

// wireguardEndpoints lists the peers' endpoints. VPP without the plugin has none.
func (s *vppAPISession) wireguardEndpoints() ([]defaultEndpoint, error) {
	if s.wireguard == 0 {
		s.wireguard = -1
		if s.ch.CheckCompatiblity((*wireguard.WireguardPeersDump)(nil), (*wireguard.WireguardPeersDetails)(nil)) == nil {
			s.wireguard = 1
		}
	}
	if s.wireguard < 0 {
		return nil, nil
	}
	peers, err := dumpAll(s.ch, &wireguard.WireguardPeersDump{PeerIndex: ^uint32(0)}, func() (*wireguard.WireguardPeersDetails, api.Message) {
		d := &wireguard.WireguardPeersDetails{}
		return d, d
	})
	if err != nil {
		return nil, err
	}
	var endpoints []defaultEndpoint
	for _, peer := range peers {
		if address, ok := netip.AddrFromSlice(peer.Peer.Endpoint.ToIP()); ok {
			endpoints = append(endpoints, defaultEndpoint{Table: peer.Peer.TableID, Address: address.Unmap()})
		}
	}
	return endpoints, nil
}

func (s *vppAPISession) defaultRouteAddDel(add bool, route defaultRoute) error {
	source, err := s.defaultSource()
	if err != nil {
		return err
	}
	prefix, err := ip_types.ParsePrefix(route.Prefix)
	if err != nil {
		return err
	}
	// A delete without paths removes everything this source holds for the prefix; marked
	// multipath, VPP would read it as removing one empty path and refuse.
	req := &ip.IPRouteAddDelV2{IsAdd: add, IsMultipath: add, Route: ip.IPRouteV2{TableID: route.Table, Prefix: prefix, Src: source}}
	if add {
		for _, p := range route.Paths {
			path := fib_types.FibPath{SwIfIndex: p.SwIfIndex, TableID: p.Table, Weight: p.Weight, Preference: p.Pref, Type: p.Type, Proto: p.Proto}
			if p.Next.IsValid() {
				path.Nh = fib_types.FibPathNh{Address: ip_types.NewAddress(net.IP(p.Next.AsSlice())).Un}
			}
			req.Route.Paths = append(req.Route.Paths, path)
		}
		req.Route.NPaths = uint8(len(req.Route.Paths))
	}
	reply := &ip.IPRouteAddDelV2Reply{}
	err = s.ch.SendRequest(req).ReceiveReply(reply)
	return checkRetval("VPP route "+route.Prefix, reply.Retval, err)
}

// flushDefaultRoutes removes what the default route keeper recorded for this VPP run.
func flushDefaultRoutes(ctx context.Context, cfg *Config, backend Backend, dryRun bool) error {
	generation, err := backend.Generation()
	if err != nil {
		return err
	}
	path := defaultStatePath(cfg)
	current := readDefaultState(path, generation)
	api := vppDefaultRouteAPI{cfg: cfg, backend: backend}
	var first error
	for _, key := range sortedRouteKeys(current) {
		if dryRun {
			fmt.Printf("ip route del %s table %d (source %s)\n", key.Prefix, key.Table, defaultSourceName)
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := api.remove(key); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		delete(current, key)
	}
	if dryRun {
		return first
	}
	if err := saveDefaultState(path, generation, current); err != nil && first == nil {
		first = err
	}
	return first
}
