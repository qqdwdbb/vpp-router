package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/dhcp"
	"go.fd.io/govpp/binapi/fib_types"
	vppif "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip"
	"go.fd.io/govpp/binapi/ip_types"
	"go.fd.io/govpp/binapi/l2"
	"go.fd.io/govpp/binapi/nat44_ed"
	"go.fd.io/govpp/binapi/nat44_ei"
	"go.fd.io/govpp/binapi/vlib"
	"go.fd.io/govpp/core"
)

// liveInterface is what VPP says about an interface now.
type liveInterface struct {
	Index     uint32
	Name      string
	Parent    string // the interface a sub-interface is on
	Sub       bool
	SubID     uint32
	VLAN      uint16
	Exact     bool
	Plain     bool // a sub-interface with one dot1q tag and nothing else
	Hardware  bool
	Up, Link  bool
	MTU       uint32
	Addresses []netip.Prefix
	Bridge    uint32
	BVI       bool
	// DHCPRouter is the router of the interface's bound IPv4 lease, if any.
	DHCPRouter netip.Addr
	// IPv6Router is ::/0's next hop through the interface: from router advertisements, or static.
	IPv6Router netip.Addr
}

type liveState struct {
	Interfaces []*liveInterface
	Bridges    map[uint32]bool
	// NAT is the NAT44 plugin VPP has loaded, empty for none.
	NAT natMode
	// HairpinCLI is whether that plugin has "set interface nat44 [ei] hairpinning" (patches
	// 0043/0044); Hairpin are the interfaces it is on for.
	HairpinCLI bool
	Hairpin    map[string]bool
}

func (s *liveState) find(name string) *liveInterface {
	for _, iface := range s.Interfaces {
		if iface.Name == name {
			return iface
		}
	}
	return nil
}

// system is what a change does to the machine.
type system interface {
	cli(command string) (string, error)
	read() (*liveState, error)
	restart(unit string) error
	// ready waits until the unit is active and a new VPP, one whose API socket is not
	// the one stamped before, answers on it.
	ready(unit string, before fileStamp) error
	stamp() (fileStamp, error)
}

type realSystem struct{ apiSocket string }

func (s *realSystem) connect() (*core.Connection, api.Channel, error) {
	conn, err := govpp.Connect(s.apiSocket)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to the VPP API: %w", err)
	}
	channel, err := conn.NewAPIChannel()
	if err != nil {
		conn.Disconnect()
		return nil, nil, err
	}
	channel.SetReplyTimeout(5 * time.Second)
	return conn, channel, nil
}

// cliError recognises VPP's report of a failed command, which comes back as text: the
// command's path, a colon and the reason, or "unknown input".
var cliError = regexp.MustCompile(`(?m)^(?:set|create|delete|ip|ip6|dhcp6|enable)\b[^:\n]*: |unknown input`)

func (s *realSystem) cli(command string) (string, error) {
	conn, channel, err := s.connect()
	if err != nil {
		return "", err
	}
	defer conn.Disconnect()
	defer channel.Close()
	reply := &vlib.CliInbandReply{}
	if err := channel.SendRequest(&vlib.CliInband{Cmd: command}).ReceiveReply(reply); err != nil {
		return "", fmt.Errorf("%s: %w", command, err)
	}
	if cliError.MatchString(reply.Reply) {
		return reply.Reply, fmt.Errorf("%s: %s", command, strings.TrimSpace(reply.Reply))
	}
	return reply.Reply, nil
}

// readHairpin asks the NAT plugin which interfaces hairpin. A plugin without the patches does not
// know the command.
func readHairpin(ch api.Channel, mode natMode) (bool, map[string]bool) {
	reply := &vlib.CliInbandReply{}
	if ch.SendRequest(&vlib.CliInband{Cmd: "show nat44 " + mode.word() + "hairpinning interfaces"}).ReceiveReply(reply) != nil || reply.Retval != 0 || cliError.MatchString(reply.Reply) {
		return false, nil
	}
	on := map[string]bool{}
	for _, name := range strings.Fields(reply.Reply) {
		on[name] = true
	}
	return true, on
}

func (s *realSystem) read() (*liveState, error) {
	conn, ch, err := s.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Disconnect()
	defer ch.Close()
	all := interface_types.InterfaceIndex(^uint32(0))
	state := &liveState{Bridges: map[uint32]bool{}}
	byIndex := map[uint32]*liveInterface{}
	parents := map[uint32]uint32{}
	request := ch.SendMultiRequest(&vppif.SwInterfaceDump{SwIfIndex: all})
	for {
		var reply vppif.SwInterfaceDetails
		stop, err := request.ReceiveReply(&reply)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		iface := &liveInterface{
			Index:    uint32(reply.SwIfIndex),
			Name:     strings.TrimRight(reply.InterfaceName, "\x00"),
			Sub:      reply.Type == interface_types.IF_API_TYPE_SUB,
			Hardware: reply.Type == interface_types.IF_API_TYPE_HARDWARE,
			Up:       reply.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0,
			Link:     reply.Flags&interface_types.IF_STATUS_API_FLAG_LINK_UP != 0,
		}
		if len(reply.Mtu) > 0 {
			iface.MTU = reply.Mtu[0]
		}
		if iface.Sub {
			iface.SubID = reply.SubID
			iface.VLAN = reply.SubOuterVlanID
			iface.Exact = reply.SubIfFlags&interface_types.SUB_IF_API_FLAG_EXACT_MATCH != 0
			iface.Plain = reply.SubNumberOfTags == 1 && reply.SubIfFlags&(interface_types.SUB_IF_API_FLAG_DOT1AD|interface_types.SUB_IF_API_FLAG_DEFAULT|interface_types.SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY) == 0
			parents[iface.Index] = reply.SupSwIfIndex
		}
		byIndex[iface.Index] = iface
		state.Interfaces = append(state.Interfaces, iface)
	}
	for index, parent := range parents {
		if p := byIndex[parent]; p != nil {
			byIndex[index].Parent = p.Name
		}
	}
	for _, iface := range state.Interfaces {
		for _, ipv6 := range []bool{false, true} {
			request := ch.SendMultiRequest(&ip.IPAddressDump{SwIfIndex: interface_types.InterfaceIndex(iface.Index), IsIPv6: ipv6})
			for {
				var reply ip.IPAddressDetails
				stop, err := request.ReceiveReply(&reply)
				if err != nil {
					return nil, err
				}
				if stop {
					break
				}
				address, err := netip.ParseAddr(reply.Prefix.Address.String())
				if err != nil || address.IsLinkLocalUnicast() {
					continue
				}
				iface.Addresses = append(iface.Addresses, netip.PrefixFrom(address, int(reply.Prefix.Len)))
			}
		}
	}
	bridges := ch.SendMultiRequest(&l2.BridgeDomainDump{BdID: ^uint32(0), SwIfIndex: all})
	for {
		var reply l2.BridgeDomainDetails
		stop, err := bridges.ReceiveReply(&reply)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		if reply.BdID == 0 {
			continue
		}
		state.Bridges[reply.BdID] = true
		for _, member := range reply.SwIfDetails {
			if iface := byIndex[uint32(member.SwIfIndex)]; iface != nil {
				iface.Bridge = reply.BdID
			}
		}
		if reply.BviSwIfIndex != all {
			if iface := byIndex[uint32(reply.BviSwIfIndex)]; iface != nil {
				iface.Bridge, iface.BVI = reply.BdID, true
			}
		}
	}
	// ::/0's paths name the IPv6 router of each interface that has one. Only a detail too.
	if prefix, err := ip_types.ParsePrefix("::/0"); err == nil {
		var reply ip.IPRouteLookupV2Reply
		if ch.SendRequest(&ip.IPRouteLookupV2{Exact: 1, Prefix: prefix}).ReceiveReply(&reply) == nil {
			for _, path := range reply.Route.Paths {
				router := netip.AddrFrom16([16]byte(path.Nh.Address.GetIP6()))
				if iface := byIndex[path.SwIfIndex]; iface != nil && path.Proto == fib_types.FIB_API_PATH_NH_PROTO_IP6 && !router.IsUnspecified() && !iface.IPv6Router.IsValid() {
					iface.IPv6Router = router
				}
			}
		}
	}
	// Only the loaded plugins' messages are in VPP's table.
	switch {
	case ch.CheckCompatiblity((*nat44_ed.Nat44ShowRunningConfig)(nil), (*nat44_ed.Nat44ShowRunningConfigReply)(nil)) == nil:
		state.NAT = natED
	case ch.CheckCompatiblity((*nat44_ei.Nat44EiShowRunningConfig)(nil), (*nat44_ei.Nat44EiShowRunningConfigReply)(nil)) == nil:
		state.NAT = natEI
	}
	if state.NAT != "" {
		state.HairpinCLI, state.Hairpin = readHairpin(ch, state.NAT)
	}
	// Leases only add a detail, so VPP without the DHCP plugin is no error.
	if ch.CheckCompatiblity((*dhcp.DHCPClientDump)(nil), (*dhcp.DHCPClientDetails)(nil)) == nil {
		clients := ch.SendMultiRequest(&dhcp.DHCPClientDump{})
		for {
			var reply dhcp.DHCPClientDetails
			stop, err := clients.ReceiveReply(&reply)
			if err != nil || stop {
				break
			}
			lease := reply.Lease
			router, ok := netip.AddrFromSlice(lease.RouterAddress.ToIP().To4())
			if iface := byIndex[uint32(lease.SwIfIndex)]; iface != nil && ok && !lease.IsIPv6 && lease.State == dhcp.DHCP_CLIENT_STATE_API_BOUND && !router.IsUnspecified() {
				iface.DHCPRouter = router
			}
		}
	}
	return state, nil
}

func (s *realSystem) restart(unit string) error {
	output, err := exec.Command("systemctl", "restart", "--no-block", unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %v: %s", unit, err, strings.TrimSpace(string(output)))
	}
	return nil
}

const readyTimeout = 90 * time.Second

func (s *realSystem) ready(unit string, before fileStamp) error {
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		if stamp, err := s.stamp(); err != nil || stamp == before {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil {
			if _, err := s.read(); err == nil {
				return nil
			}
		} else if exec.Command("systemctl", "is-failed", "--quiet", unit).Run() == nil {
			return errors.New(unit + " failed to start")
		}
		time.Sleep(time.Second)
	}
	return errors.New(unit + " did not come back in " + strconv.Itoa(int(readyTimeout.Seconds())) + " seconds")
}

func (s *realSystem) stamp() (fileStamp, error) { return stampOf(s.apiSocket) }
