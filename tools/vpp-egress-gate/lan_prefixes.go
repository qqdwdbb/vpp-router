package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip"
)

// Client networks that come and go. lan_prefixes is fixed when the devices are synced, but
// an IPv6 prefix delegated by the ISP changes with the lease, and a renumbered LAN would
// lose the routes that take replies from Linux (proxies, Linux exits) back to its clients.
// lan_interfaces names the VPP interfaces such a prefix is set on: the running Gate reads
// their IPv6 prefixes and keeps those routes equal to them, beside the fixed ones.
//
// What it found is written to lanPrefixFile, under /run: a device sync or a restart reads
// it, so that the routes stay while Gate is away, and a reboot starts from the fixed ones.

var lanPrefixFile = "/run/vpp-egress-gate/lan-prefixes.json"

// learnedLANs is what the running Gate last found on its LAN interfaces.
type learnedLANs struct {
	Interfaces []string `json:"interfaces"`
	Prefixes   []string `json:"prefixes"`
}

func readLearnedLANs() learnedLANs {
	var learned learnedLANs
	raw, err := os.ReadFile(lanPrefixFile)
	if err != nil {
		return learned
	}
	if err := json.Unmarshal(raw, &learned); err != nil {
		log.Printf("devices: %s: %v; using lan_prefixes alone", lanPrefixFile, err)
		return learnedLANs{}
	}
	return learned
}

func writeLearnedLANs(learned learnedLANs) error {
	data, err := json.MarshalIndent(learned, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(lanPrefixFile), 0o755); err != nil {
		return err
	}
	tmp := lanPrefixFile + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, lanPrefixFile)
}

// clientNetworks is lan_prefixes with what was learned on the same LAN interfaces. A record
// made for other interfaces belongs to an earlier configuration and is left out.
func (s *DeviceState) clientNetworks(learned learnedLANs) []string {
	lans := append([]string{}, s.LANs...)
	if len(s.LANInterfaces) == 0 || !slices.Equal(sortedCopy(learned.Interfaces), sortedCopy(s.LANInterfaces)) {
		return lans
	}
	var fixed []netip.Prefix
	for _, text := range s.LANs {
		if prefix, err := netip.ParsePrefix(text); err == nil {
			fixed = append(fixed, prefix)
		}
	}
	for _, text := range learned.Prefixes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !usableLANPrefix(prefix, fixed) {
			continue
		}
		fixed = append(fixed, prefix)
		lans = append(lans, prefix.String())
	}
	return lans
}

func sortedCopy(names []string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	return out
}

// usableLANPrefix keeps a found prefix that a client can have: global or unique local, not
// a transit or Fake-IP network, and not one already listed or covering one.
func usableLANPrefix(prefix netip.Prefix, others []netip.Prefix) bool {
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() == 0 || prefix.Bits() > 64 ||
		prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() || prefix.Addr().IsUnspecified() {
		return false
	}
	for _, text := range []string{deviceExitNet6, deviceProxyNet6} {
		if prefix.Overlaps(netip.MustParsePrefix(text)) {
			return false
		}
	}
	for _, other := range others {
		if prefix.Overlaps(other) {
			return false
		}
	}
	return true
}

// interfacePrefixes6 returns the IPv6 networks of the addresses on the interfaces that VPP
// has, and the names it does not have.
func (s *vppAPISession) interfacePrefixes6(names []string) ([]netip.Prefix, []string, error) {
	if err := s.ch.CheckCompatiblity((*ip.IPAddressDump)(nil), (*ip.IPAddressDetails)(nil)); err != nil {
		return nil, nil, err
	}
	ifaces, err := s.dumpInterfaces()
	if err != nil {
		return nil, nil, err
	}
	var found []netip.Prefix
	var missing []string
	for _, name := range names {
		index, ok := ifaces[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		req := s.ch.SendMultiRequest(&ip.IPAddressDump{SwIfIndex: interface_types.InterfaceIndex(index), IsIPv6: true})
		for {
			details := &ip.IPAddressDetails{}
			last, err := req.ReceiveReply(details)
			if err != nil {
				return nil, nil, err
			}
			if last {
				break
			}
			prefix := details.Prefix.ToIPNet()
			address, ok := netip.AddrFromSlice(prefix.IP)
			if !ok {
				continue
			}
			bits, _ := prefix.Mask.Size()
			found = append(found, netip.PrefixFrom(address.Unmap(), bits).Masked())
		}
	}
	return found, missing, nil
}

// lanPrefixKeeper follows the LAN interfaces for the running Gate.
type lanPrefixKeeper struct {
	interfaces []string
	// read asks VPP for the interfaces' prefixes, and apply makes Linux route to the client
	// networks; tests replace both.
	read    func() ([]netip.Prefix, []string, error)
	apply   func(ctx context.Context, state *DeviceState, lans []string) error
	applied string // the prefixes last applied, or empty before the first time
	missing string
	failure failureLog
}

func newLANPrefixKeeper(interfaces []string, session func(func(*vppAPISession) error) error) *lanPrefixKeeper {
	k := &lanPrefixKeeper{interfaces: interfaces, apply: applyClientNetworks,
		failure: failureLog{what: "following the LAN interfaces' IPv6 prefixes failed"}}
	k.read = func() (found []netip.Prefix, missing []string, err error) {
		err = session(func(s *vppAPISession) error {
			found, missing, err = s.interfacePrefixes6(interfaces)
			return err
		})
		return found, missing, err
	}
	return k
}

// tick reads the prefixes and, when they changed, the routes follow. While VPP cannot be
// asked, the routes stay as they are: a VPP restart does not renumber the LAN.
func (k *lanPrefixKeeper) tick() {
	if k == nil || len(k.interfaces) == 0 {
		return
	}
	found, missing, err := k.read()
	if err != nil {
		k.failure.failed(err)
		return
	}
	if text := strings.Join(missing, ", "); text != k.missing {
		k.missing = text
		if text != "" {
			log.Printf("lan_interfaces: VPP has no interface %s", text)
		}
	}
	state, err := loadDeviceState()
	if err != nil {
		k.failure.failed(err)
		return
	}
	var fixed []netip.Prefix
	for _, text := range state.LANs {
		if prefix, err := netip.ParsePrefix(text); err == nil {
			fixed = append(fixed, prefix)
		}
	}
	learned := learnedLANs{Interfaces: sortedCopy(k.interfaces), Prefixes: []string{}}
	sort.Slice(found, func(i, j int) bool { return found[i].String() < found[j].String() })
	for _, prefix := range found {
		if usableLANPrefix(prefix, fixed) {
			fixed = append(fixed, prefix)
			learned.Prefixes = append(learned.Prefixes, prefix.String())
		}
	}
	signature := strings.Join(learned.Prefixes, " ") + "|"
	if signature == k.applied {
		return
	}
	// The device journal must name the same interfaces, or a sync would not keep these.
	if !slices.Equal(sortedCopy(state.LANInterfaces), learned.Interfaces) {
		k.failure.failed(fmt.Errorf("the device journal has lan_interfaces %v, not %v: run --sync-devices", state.LANInterfaces, k.interfaces))
		return
	}
	if err := writeLearnedLANs(learned); err != nil {
		k.failure.failed(err)
		return
	}
	if err := k.apply(context.Background(), state, state.clientNetworks(learned)); err != nil {
		k.failure.failed(err)
		return
	}
	k.failure.recovered("following the LAN interfaces' IPv6 prefixes recovered")
	if len(learned.Prefixes) == 0 {
		log.Printf("lan_interfaces: no IPv6 prefix on %s", strings.Join(k.interfaces, ", "))
	} else {
		log.Printf("lan_interfaces: IPv6 client networks %s", strings.Join(learned.Prefixes, ", "))
	}
	k.applied = signature
}

// applyClientNetworks routes Linux's replies to the client networks: each device's return
// table and the main table, as a sync would.
func applyClientNetworks(ctx context.Context, state *DeviceState, lans []string) error {
	devices := state.active()
	for _, d := range devices {
		if d.SharedTAP || d.isProxy() {
			continue
		}
		if err := syncReturnRoutes(ctx, d, 4, d.vppAddress().String(), lansOf(lans, 4)); err != nil {
			return fmt.Errorf("%s: %w", d.Host, err)
		}
		if d.IPv6 {
			if err := syncReturnRoutes(ctx, d, 6, d.vppAddress6().String(), lansOf(lans, 6)); err != nil {
				return fmt.Errorf("%s: %w", d.Host, err)
			}
		}
	}
	return syncMainRoutes(ctx, devices, state.retired(), lans)
}
