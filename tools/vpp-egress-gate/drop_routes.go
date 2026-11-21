package gate

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"go.fd.io/govpp/binapi/fib"
	"go.fd.io/govpp/binapi/fib_types"
	"go.fd.io/govpp/binapi/ip"
	"go.fd.io/govpp/binapi/ip_types"
)

// Every prefix a rule sends to an exit has a drop route underneath the real one. VPP uses the
// entry's best source, so traffic follows the real route while it exists and is discarded when
// it does not: a missing exit can never send traffic out by the default route. The drop routes
// have a FIB source of their own, ranked below every source that installs routes, so they
// never mix with a real path and nothing has to change when an exit comes or goes.
//
// They are recorded next to the ledger so that a prefix no longer wanted can be removed, also
// by a later Gate.
const (
	dropSourceName     = "vpp-egress-gate-drop"
	dropSourcePriority = 245 // below CLI, API and adjacency; lower numbers win
)

// knownDrops is what this process has as drop routes. A FIB entry holding only one of them is
// free for a real route, where any other entry with no usable path belongs to someone else.
var knownDrops = struct {
	sync.RWMutex
	keys map[RouteKey]bool
}{keys: map[RouteKey]bool{}}

func rememberDrops(set map[DropRoute]bool) {
	keys := make(map[RouteKey]bool, len(set))
	for route := range set {
		keys[RouteKey{route.Table, route.Prefix}] = true
	}
	knownDrops.Lock()
	knownDrops.keys = keys
	knownDrops.Unlock()
}

func isKnownDrop(key RouteKey) bool {
	knownDrops.RLock()
	defer knownDrops.RUnlock()
	return knownDrops.keys[key]
}

// DropRoute is a prefix VPP discards.
type DropRoute struct {
	Table  uint32 `json:"table"`
	Prefix string `json:"prefix"`
}

func (r DropRoute) command(verb string) string {
	return fmt.Sprintf("ip route %s %s table %d via drop", verb, r.Prefix, r.Table)
}

func dropStatePath(cfg *Config) string { return cfg.StateFile + ".drops" }

// readDrops returns what this VPP run holds. Routes from an earlier run went with it.
func readDrops(cfg *Config, generation string) map[DropRoute]bool {
	current := map[DropRoute]bool{}
	state, _ := ReadJSON(dropStatePath(cfg), map[string]any{}).(map[string]any)
	if g, _ := state["generation"].(string); g != generation {
		return current
	}
	items, _ := state["routes"].([]any)
	for _, item := range items {
		fields, _ := item.(map[string]any)
		prefix, _ := fields["prefix"].(string)
		table, err := asInt(fields["table"])
		if prefix != "" && err == nil {
			current[DropRoute{uint32(table), prefix}] = true
		}
	}
	return current
}

func sortedDrops(set map[DropRoute]bool) []DropRoute {
	routes := make([]DropRoute, 0, len(set))
	for route := range set {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Table != routes[j].Table {
			return routes[i].Table < routes[j].Table
		}
		return routes[i].Prefix < routes[j].Prefix
	})
	return routes
}

func saveDrops(cfg *Config, generation string, set map[DropRoute]bool) error {
	return AtomicJSON(dropStatePath(cfg), map[string]any{"generation": generation, "routes": sortedDrops(set)})
}

// desiredDrops lists every prefix a rule routes, except those Gate may not touch.
func desiredDrops(cfg *Config, prefixes map[MappingKey]map[string]struct{}) map[DropRoute]bool {
	desired := map[DropRoute]bool{}
	for _, mapping := range cfg.Mappings {
		if !mapping.Enabled {
			continue
		}
		for text := range prefixes[mapping.Key()] {
			prefix, err := parsePrefixStrict(text)
			if err != nil {
				continue
			}
			family := 6
			if prefix.Addr().Is4() {
				family = 4
			}
			if mapping.ViaFor(family) != "" && !prefixExcluded(cfg, prefix) {
				desired[DropRoute{mapping.FibTable, text}] = true
			}
		}
	}
	return desired
}

// syncDrops makes the drop routes match, before any real route changes: one going away must
// not outlive the real route above it, and a new one must be in place before it is needed.
// A failure is logged and not returned, as real routes must still go in.
func syncDrops(cfg *Config, backend Backend, generation string, desired map[DropRoute]bool) {
	current := readDrops(cfg, generation)
	stale, added := map[DropRoute]bool{}, map[DropRoute]bool{}
	for route := range current {
		if !desired[route] {
			stale[route] = true
			delete(current, route)
		}
	}
	for route := range desired {
		if !current[route] {
			added[route] = true
			current[route] = true // recorded first, so that it can always be removed
		}
	}
	rememberDrops(current)
	if len(stale) == 0 && len(added) == 0 {
		return
	}
	if len(stale) > 0 {
		if err := backend.ApplyDrops(false, sortedDrops(stale)); err != nil {
			log.Printf("removing drop routes: %v", err)
		}
	}
	if err := saveDrops(cfg, generation, current); err != nil {
		log.Printf("saving drop routes, none added: %v", err)
		return
	}
	if len(added) > 0 {
		if err := backend.ApplyDrops(true, sortedDrops(added)); err != nil {
			log.Printf("adding drop routes: %v", err)
		}
	}
}

// dropSource finds the FIB source, registering it the first time this VPP run needs it.
func (s *vppAPISession) dropSource() (uint8, error) {
	if s.dropSrc != 0 {
		return s.dropSrc, nil
	}
	req := s.ch.SendMultiRequest(&fib.FibSourceDump{})
	for {
		details := &fib.FibSourceDetails{}
		last, err := req.ReceiveReply(details)
		if err != nil {
			return 0, err
		}
		if last {
			break
		}
		if strings.TrimRight(details.Src.Name, "\x00") == dropSourceName {
			s.dropSrc = details.Src.ID
		}
	}
	if s.dropSrc != 0 {
		return s.dropSrc, nil
	}
	reply := &fib.FibSourceAddReply{}
	err := s.ch.SendRequest(&fib.FibSourceAdd{Src: fib.FibSource{Priority: dropSourcePriority, Name: dropSourceName}}).ReceiveReply(reply)
	if err != nil {
		return 0, err
	}
	if reply.Retval != 0 {
		return 0, fmt.Errorf("VPP FIB source add failed (%d)", reply.Retval)
	}
	s.dropSrc = reply.ID
	return s.dropSrc, nil
}

func (s *vppAPISession) routeDrop(add bool, route DropRoute) error {
	source, err := s.dropSource()
	if err != nil {
		return err
	}
	prefix, err := ip_types.ParsePrefix(route.Prefix)
	if err != nil {
		return err
	}
	proto := fib_types.FIB_API_PATH_NH_PROTO_IP4
	if parsed, err := netip.ParsePrefix(route.Prefix); err == nil && parsed.Addr().Is6() {
		proto = fib_types.FIB_API_PATH_NH_PROTO_IP6
	}
	req := &ip.IPRouteAddDelV2{
		IsAdd:       add,
		IsMultipath: true,
		Route: ip.IPRouteV2{
			TableID: route.Table,
			Prefix:  prefix,
			NPaths:  1,
			Src:     source,
			Paths: []fib_types.FibPath{{
				SwIfIndex: ^uint32(0),
				Weight:    1,
				Proto:     proto,
				Type:      fib_types.FIB_API_PATH_TYPE_DROP,
				Nh:        fib_types.FibPathNh{Address: ip_types.NewAddress(net.IPv4zero).Un},
			}},
		},
	}
	reply := &ip.IPRouteAddDelV2Reply{}
	if err := s.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return err
	}
	if reply.Retval != 0 {
		return fmt.Errorf("VPP route API failed (%d): %s", reply.Retval, route.Prefix)
	}
	return nil
}

// routeDeleteEntry removes everything Gate's source holds for a prefix. A path through a
// deleted interface can only go this way: it has no name left to be named by, and VPP treats
// adding the same path again as done, leaving it unresolved even once the interface is back.
func (s *vppAPISession) routeDeleteEntry(route Route) error {
	prefix, err := ip_types.ParsePrefix(route.Prefix)
	if err != nil {
		return err
	}
	reply := &ip.IPRouteAddDelV2Reply{}
	req := &ip.IPRouteAddDelV2{Route: ip.IPRouteV2{TableID: route.Table, Prefix: prefix, Src: s.cliSrc}}
	if err := s.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return err
	}
	if reply.Retval != 0 {
		return fmt.Errorf("VPP route API failed (%d): %s", reply.Retval, route.Prefix)
	}
	return nil
}

func applyVPPDrops(ctx context.Context, cfg *Config, add bool, routes []DropRoute) error {
	select {
	case apiMu <- struct{}{}:
		defer func() { <-apiMu }()
	case <-ctx.Done():
		return ctx.Err()
	}
	sess, err := vppAPI(cfg)
	if err != nil {
		dropAPICache()
		return err
	}
	var first error
	for _, route := range routes {
		// Keep going: one prefix VPP refuses says nothing about the others.
		if err := sess.routeDrop(add, route); err != nil && first == nil {
			first = err
		}
	}
	return first
}
