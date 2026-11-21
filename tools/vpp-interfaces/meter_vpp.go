package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"go.fd.io/govpp/binapi/acl"
	"go.fd.io/govpp/binapi/acl_types"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip_neighbor"
	"go.fd.io/govpp/binapi/ip_types"
)

// The VPP calls the LAN meter makes. They are main-thread API calls, but few and small: a
// handful of ACL messages when the devices change, and one neighbour dump a minute.
type meterVPP interface {
	aclTag(index uint32) (tag string, exists bool, err error)
	replaceACL(index uint32, tag string, rules []acl_types.ACLRule) (uint32, error)
	deleteACL(index uint32) error
	interfaceACLs(sw uint32) (in, out []uint32, err error)
	attachACL(sw, index uint32, input, add bool) error
	countersEnabled() (bool, error)
	enableCounters(on bool) error
	neighbors(sw uint32) ([]neighbor, error)
}

type neighbor struct {
	IP  netip.Addr
	MAC string
}

func (s *realSystem) aclTag(index uint32) (string, bool, error) {
	conn, ch, err := s.connect()
	if err != nil {
		return "", false, err
	}
	defer conn.Disconnect()
	defer ch.Close()
	request := ch.SendMultiRequest(&acl.ACLDump{ACLIndex: index})
	for {
		var reply acl.ACLDetails
		stop, err := request.ReceiveReply(&reply)
		if err != nil {
			return "", false, err
		}
		if stop {
			return "", false, nil
		}
		if reply.ACLIndex == index {
			return strings.TrimRight(reply.Tag, "\x00"), true, nil
		}
	}
}

func (s *realSystem) replaceACL(index uint32, tag string, rules []acl_types.ACLRule) (uint32, error) {
	conn, ch, err := s.connect()
	if err != nil {
		return 0, err
	}
	defer conn.Disconnect()
	defer ch.Close()
	reply := &acl.ACLAddReplaceReply{}
	if err := ch.SendRequest(&acl.ACLAddReplace{ACLIndex: index, Tag: tag, Count: uint32(len(rules)), R: rules}).ReceiveReply(reply); err != nil {
		return 0, fmt.Errorf("acl_add_replace: %w", err)
	}
	return reply.ACLIndex, nil
}

func (s *realSystem) deleteACL(index uint32) error {
	conn, ch, err := s.connect()
	if err != nil {
		return err
	}
	defer conn.Disconnect()
	defer ch.Close()
	return ch.SendRequest(&acl.ACLDel{ACLIndex: index}).ReceiveReply(&acl.ACLDelReply{})
}

func (s *realSystem) interfaceACLs(sw uint32) ([]uint32, []uint32, error) {
	conn, ch, err := s.connect()
	if err != nil {
		return nil, nil, err
	}
	defer conn.Disconnect()
	defer ch.Close()
	request := ch.SendMultiRequest(&acl.ACLInterfaceListDump{SwIfIndex: interface_types.InterfaceIndex(sw)})
	var in, out []uint32
	for {
		var reply acl.ACLInterfaceListDetails
		stop, err := request.ReceiveReply(&reply)
		if err != nil {
			return nil, nil, err
		}
		if stop {
			return in, out, nil
		}
		if uint32(reply.SwIfIndex) == sw && int(reply.NInput) <= len(reply.Acls) {
			in, out = append(in, reply.Acls[:reply.NInput]...), append(out, reply.Acls[reply.NInput:]...)
		}
	}
}

func (s *realSystem) attachACL(sw, index uint32, input, add bool) error {
	conn, ch, err := s.connect()
	if err != nil {
		return err
	}
	defer conn.Disconnect()
	defer ch.Close()
	return ch.SendRequest(&acl.ACLInterfaceAddDel{IsAdd: add, IsInput: input, SwIfIndex: interface_types.InterfaceIndex(sw), ACLIndex: index}).
		ReceiveReply(&acl.ACLInterfaceAddDelReply{})
}

var countersLine = regexp.MustCompile(`Stats counters enabled for interface ACLs: (\d)`)

// countersEnabled has no API of its own; the ACL plugin prints it.
func (s *realSystem) countersEnabled() (bool, error) {
	out, err := s.cli("show acl-plugin tables mask")
	if err != nil {
		return false, err
	}
	m := countersLine.FindStringSubmatch(out)
	if m == nil {
		return false, fmt.Errorf("the ACL plugin does not say whether its counters are on")
	}
	return m[1] == "1", nil
}

func (s *realSystem) enableCounters(on bool) error {
	conn, ch, err := s.connect()
	if err != nil {
		return err
	}
	// VPP 26.06 answers this request with an acl_del_reply (REPLY_MACRO (VL_API_ACL_DEL_REPLY)
	// in the handler in acl.c), so the reply is read as that. Whatever comes back, the switch
	// is read again afterwards, which also works once VPP answers with the right message.
	sendErr := ch.SendRequest(&acl.ACLStatsIntfCountersEnable{Enable: on}).ReceiveReply(&acl.ACLDelReply{})
	ch.Close()
	conn.Disconnect()
	got, err := s.countersEnabled()
	switch {
	case err == nil && got == on:
		return nil
	case sendErr != nil:
		return fmt.Errorf("acl_stats_intf_counters_enable: %w", sendErr)
	case err != nil:
		return err
	default:
		return fmt.Errorf("the ACL counters are still %v", got)
	}
}

func (s *realSystem) neighbors(sw uint32) ([]neighbor, error) {
	conn, ch, err := s.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Disconnect()
	defer ch.Close()
	var out []neighbor
	for _, af := range []ip_types.AddressFamily{ip_types.ADDRESS_IP4, ip_types.ADDRESS_IP6} {
		request := ch.SendMultiRequest(&ip_neighbor.IPNeighborDump{SwIfIndex: interface_types.InterfaceIndex(sw), Af: af})
		for {
			var reply ip_neighbor.IPNeighborDetails
			stop, err := request.ReceiveReply(&reply)
			if err != nil {
				return nil, err
			}
			if stop {
				break
			}
			n := reply.Neighbor
			if ip, ok := netip.AddrFromSlice(n.IPAddress.ToIP()); ok {
				out = append(out, neighbor{IP: ip.Unmap(), MAC: strings.ToLower(n.MacAddress.String())})
			}
		}
	}
	return out, nil
}
