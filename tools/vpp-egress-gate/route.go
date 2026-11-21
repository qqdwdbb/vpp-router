package gate

import (
	"fmt"
	"net/netip"
	"sort"
)

// Route is a FIB path owned by the gate.
type Route struct {
	Table     uint32
	Prefix    string
	Via       string
	Interface string
}

type RouteKey struct {
	Table  uint32
	Prefix string
}

func (r Route) Key() RouteKey { return RouteKey{r.Table, r.Prefix} }

func (r Route) Command(action string) string {
	return fmt.Sprintf("ip route %s %s table %d via %s %s", action, r.Prefix, r.Table, r.Via, r.Interface)
}

func (r Route) PrefixNet() netip.Prefix {
	p, err := parsePrefixStrict(r.Prefix)
	if err != nil {
		p, _ = netip.ParsePrefix(r.Prefix)
	}
	return p
}

func (r Route) less(other Route) bool {
	if r.Table != other.Table {
		return r.Table < other.Table
	}
	if r.Prefix != other.Prefix {
		return r.Prefix < other.Prefix
	}
	if r.Via != other.Via {
		return r.Via < other.Via
	}
	return r.Interface < other.Interface
}

func sortRoutes(routes []Route) {
	sort.Slice(routes, func(i, j int) bool { return routes[i].less(routes[j]) })
}

type Path struct {
	Via, Interface string
}

type PathSet map[Path]struct{}

func pathSetOf(via, iface string) PathSet {
	return PathSet{Path{via, iface}: {}}
}

func pathSetEqual(a, b PathSet) bool {
	if len(a) != len(b) {
		return false
	}
	for p := range a {
		if _, ok := b[p]; !ok {
			return false
		}
	}
	return true
}

func Matches(route Route, live map[RouteKey]PathSet) bool {
	return pathSetEqual(live[route.Key()], pathSetOf(route.Via, route.Interface))
}

type addrInt struct{ hi, lo uint64 }

func addrToInt(addr netip.Addr) addrInt {
	if addr.Is4() {
		return addrInt{0, uint64(binaryUint32(addr.As4()))}
	}
	b := addr.As16()
	return addrInt{binaryUint64(b[0:8]), binaryUint64(b[8:16])}
}

func binaryUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func binaryUint64(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func (a addrInt) shiftRight(n int) addrInt {
	if n <= 0 {
		return a
	}
	if n >= 128 {
		return addrInt{}
	}
	if n >= 64 {
		return addrInt{0, a.hi >> uint(n-64)}
	}
	return addrInt{a.hi >> uint(n), a.lo>>uint(n) | a.hi<<uint(64-n)}
}

func (a addrInt) shiftLeft(n int) addrInt {
	if n <= 0 {
		return a
	}
	if n >= 128 {
		return addrInt{}
	}
	if n >= 64 {
		return addrInt{a.lo << uint(n-64), 0}
	}
	return addrInt{a.hi<<uint(n) | a.lo>>uint(64-n), a.lo << uint(n)}
}

// PrefixIndex maps prefix lengths to integer network addresses.
type PrefixIndex struct {
	groups map[[2]int]map[int]map[addrInt][]any
}

func NewPrefixIndex() *PrefixIndex {
	return &PrefixIndex{groups: map[[2]int]map[int]map[addrInt][]any{}}
}

func (p *PrefixIndex) Add(network netip.Prefix, value any, table uint32) {
	key := [2]int{int(table), network.Addr().BitLen()}
	lengths := p.groups[key]
	if lengths == nil {
		lengths = map[int]map[addrInt][]any{}
		p.groups[key] = lengths
	}
	addresses := lengths[network.Bits()]
	if addresses == nil {
		addresses = map[addrInt][]any{}
		lengths[network.Bits()] = addresses
	}
	n := addrToInt(network.Masked().Addr())
	list := addresses[n]
	for _, existing := range list {
		if existing == value {
			return
		}
	}
	addresses[n] = append(list, value)
}

func (p *PrefixIndex) Covering(network netip.Prefix, table uint32) []any {
	key := [2]int{int(table), network.Addr().BitLen()}
	lengths := p.groups[key]
	if lengths == nil {
		return nil
	}
	address := addrToInt(network.Masked().Addr())
	bits := network.Addr().BitLen()
	var out []any
	for length, addresses := range lengths {
		if length <= network.Bits() {
			shift := bits - length
			n := address.shiftRight(shift).shiftLeft(shift)
			out = append(out, addresses[n]...)
		}
	}
	return out
}

func staticPrefixIndex(cfg *Config) *PrefixIndex {
	if cfg.staticIndex != nil {
		return cfg.staticIndex
	}
	index := NewPrefixIndex()
	for key, prefixes := range cfg.StaticPrefixes {
		for prefix := range prefixes {
			n, err := parsePrefixStrict(prefix)
			if err != nil {
				continue
			}
			index.Add(n, [2]any{key, prefix}, 0)
		}
	}
	cfg.staticIndex = index
	return index
}

func exclusionIndex(cfg *Config) (*PrefixIndex, []netip.Prefix) {
	if cfg.exclusionIndex != nil {
		return cfg.exclusionIndex, cfg.exclusionNets
	}
	nets := make([]netip.Prefix, 0, len(cfg.ExcludePrefixes))
	index := NewPrefixIndex()
	for _, prefix := range cfg.ExcludePrefixes {
		n, err := parsePrefixStrict(prefix)
		if err != nil {
			continue
		}
		nets = append(nets, n)
		index.Add(n, true, 0)
	}
	cfg.exclusionIndex, cfg.exclusionNets = index, nets
	return index, nets
}

func isExcluded(network netip.Prefix, protected []netip.Prefix, exclusions []netip.Prefix) bool {
	for _, p := range protected {
		if p.Addr().BitLen() == network.Addr().BitLen() && prefixSubnetOf(p, network) {
			return true
		}
	}
	for _, n := range exclusions {
		if prefixesOverlap(n, network) {
			return true
		}
	}
	return false
}

func prefixExcluded(cfg *Config, network netip.Prefix) bool {
	index, networks := exclusionIndex(cfg)
	if network.Addr().Is4() && network.Bits() == 32 || network.Addr().Is6() && network.Bits() == 128 {
		return len(index.Covering(network, 0)) > 0
	}
	return isExcluded(network, nil, networks)
}

func plan(desired map[RouteKey]Route, owned []Route, live map[RouteKey]PathSet) (remove, add, current, conflicts []Route) {
	currentMap := map[RouteKey]Route{}
	for _, r := range owned {
		if Matches(r, live) {
			currentMap[r.Key()] = r
		}
	}
	for key, r := range currentMap {
		if desired[key] != r {
			remove = append(remove, r)
		}
	}
	for key, route := range desired {
		if currentMap[key] == route {
			continue
		}
		if _, present := live[key]; !present || func() bool { _, ok := currentMap[key]; return ok }() {
			add = append(add, route)
		} else {
			conflicts = append(conflicts, route)
		}
	}
	for _, r := range currentMap {
		current = append(current, r)
	}
	sortRoutes(remove)
	sortRoutes(add)
	sortRoutes(current)
	sortRoutes(conflicts)
	return
}

func collectDesired(mappings []Mapping, prefixSets map[MappingKey]map[string]struct{}, protected []netip.Prefix, exclusions []netip.Prefix, overlapPolicy string) (map[RouteKey]Route, int, error) {
	desired := map[RouteKey]Route{}
	excluded := 0
	priorRanges := map[[2]int][]netip.Prefix{}
	priorHosts := map[[2]int][]netip.Prefix{}
	rangeIndex := NewPrefixIndex()
	excludedIndex := NewPrefixIndex()
	for _, network := range exclusions {
		excludedIndex.Add(network, true, 0)
	}
	protectedSet := map[netip.Addr]struct{}{}
	for _, p := range protected {
		protectedSet[p.Addr()] = struct{}{}
	}
	for _, mapping := range mappings {
		key := mapping.Key()
		var accepted []netip.Prefix
		for prefix := range prefixSets[key] {
			network, err := parsePrefixStrict(prefix)
			if err != nil {
				return nil, 0, err
			}
			family := 4
			if network.Addr().Is6() {
				family = 6
			}
			via := mapping.ViaFor(family)
			if via == "" {
				return nil, 0, fmt.Errorf("address family mismatch for set %s", mapping.Set)
			}
			host := network.Bits() == network.Addr().BitLen()
			var blocked bool
			if host {
				_, inProtected := protectedSet[network.Addr()]
				blocked = inProtected || len(excludedIndex.Covering(network, 0)) > 0
			} else {
				blocked = isExcluded(network, protected, exclusions)
			}
			if blocked {
				excluded++
				continue
			}
			group := [2]int{int(mapping.FibTable), network.Addr().BitLen()}
			parts := []netip.Prefix{network}
			if overlapPolicy == "first" {
				if host {
					if len(rangeIndex.Covering(network, mapping.FibTable)) > 0 {
						parts = nil
					}
				} else {
					for _, covered := range append(append([]netip.Prefix{}, priorRanges[group]...), priorHosts[group]...) {
						parts = subtractPrefix(parts, covered)
					}
				}
			}
			for _, part := range parts {
				route := Route{mapping.FibTable, prefixString(part), via, mapping.Interface}
				if existing, ok := desired[route.Key()]; ok && existing != route {
					if overlapPolicy == "first" {
						continue
					}
					return nil, 0, fmt.Errorf("conflicting mappings for %s; refusing partial reconciliation", prefix)
				}
				desired[route.Key()] = route
			}
			accepted = append(accepted, network)
		}
		if overlapPolicy == "first" {
			for _, network := range accepted {
				prior := priorHosts
				if network.Bits() != network.Addr().BitLen() {
					prior = priorRanges
					rangeIndex.Add(network, true, mapping.FibTable)
				}
				g := [2]int{int(mapping.FibTable), network.Addr().BitLen()}
				prior[g] = append(prior[g], network)
			}
		}
	}
	return desired, excluded, nil
}

func coveringRoutes(desired map[RouteKey]Route, required []Route) ([]Route, error) {
	result := map[Route]struct{}{}
	for _, request := range required {
		network := request.PrefixNet()
		remaining := []netip.Prefix{network}
		for _, route := range desired {
			prefix := route.PrefixNet()
			if route.Table == request.Table && prefix.Addr().BitLen() == network.Addr().BitLen() && prefixesOverlap(prefix, network) {
				result[route] = struct{}{}
				remaining = subtractPrefix(remaining, prefix)
			}
		}
		if len(remaining) > 0 {
			return nil, fmt.Errorf("ordered route barrier rejected an excluded or missing prefix")
		}
	}
	out := make([]Route, 0, len(result))
	for route := range result {
		out = append(out, route)
	}
	sortRoutes(out)
	return out, nil
}
