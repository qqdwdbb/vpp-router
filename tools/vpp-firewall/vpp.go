package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/acl"
	"go.fd.io/govpp/binapi/acl_types"
	vppif "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip"
	"go.fd.io/govpp/binapi/ip_types"
	"go.fd.io/govpp/binapi/nat44_ei"
	"go.fd.io/govpp/core"
)

// noIndex is VPP's ~0: no interface, or a new ACL.
const noIndex = ^uint32(0)

// iface is a VPP interface and its addresses. Addresses are read only for the interfaces
// a reading asks for.
type iface struct {
	Index uint32
	Name  string
	Addrs []netip.Prefix
}

// mapping is a NAT44-EI static or identity mapping. One made on an interface shows twice in
// VPP's dumps: as the request on the interface (ExternalIf set) and, once the interface has
// an address, as the mapping on that address (ExternalIf is noIndex).
type mapping struct {
	Identity     bool
	Proto        uint8
	ExternalPort uint16
	ExternalIf   uint32
	ExternalIP   netip.Addr
	LocalIP      netip.Addr
	LocalPort    uint16
	Tag          string
}

type aclEntry struct {
	Index uint32
	Tag   string
	Rules []acl_types.ACLRule
}

// aclList is what an interface has applied, in order, for each direction.
type aclList struct{ Input, Output []uint32 }

// vppState is one reading of what the firewall depends on.
type vppState struct {
	Interfaces []iface
	// NATOutside are the interfaces NAT44-EI translates traffic leaving by (output feature).
	NATOutside []uint32
	NAT        bool // the NAT44-EI API is there
	ACL        bool // the ACL API is there
	// Statics says Mappings has the static mappings too, not only the identity mappings.
	Statics  bool
	Mappings []mapping
	ACLs     []aclEntry
	Lists    map[uint32]aclList
}

func (s *vppState) byName(name string) *iface {
	for i := range s.Interfaces {
		if s.Interfaces[i].Name == name {
			return &s.Interfaces[i]
		}
	}
	return nil
}

func (s *vppState) byIndex(index uint32) *iface {
	for i := range s.Interfaces {
		if s.Interfaces[i].Index == index {
			return &s.Interfaces[i]
		}
	}
	return nil
}

// vppAPI is what the service does to VPP. One value is one connection.
type vppAPI interface {
	// Read reads the state; addresses for every interface when all, else for wanted only.
	// Static mappings only when statics: NAT44-EI's dump holds VPP's worker barrier while it
	// lists them all, thousands with large ranges.
	Read(all, statics bool, wanted func(name string, natOutside bool) bool) (*vppState, error)
	Mapping(m mapping, add bool) error
	// ReplaceACL creates an ACL when index is noIndex, else replaces it in place.
	ReplaceACL(index uint32, tag string, rules []acl_types.ACLRule) (uint32, error)
	DeleteACL(index uint32) error
	SetACLList(sw uint32, list aclList) error
	Close()
}

type realVPP struct {
	conn *core.Connection
	ch   api.Channel
}

func dialVPP(socket string) (vppAPI, error) {
	conn, err := govpp.Connect(socket)
	if err != nil {
		return nil, err
	}
	ch, err := conn.NewAPIChannel()
	if err != nil {
		conn.Disconnect()
		return nil, err
	}
	ch.SetReplyTimeout(5 * time.Second)
	return &realVPP{conn: conn, ch: ch}, nil
}

func (v *realVPP) Close() {
	v.ch.Close()
	v.conn.Disconnect()
}

func dumpAll[T any](ch api.Channel, request api.Message, details func() (*T, api.Message)) ([]*T, error) {
	req := ch.SendMultiRequest(request)
	var out []*T
	for {
		item, message := details()
		last, err := req.ReceiveReply(message)
		if err != nil {
			return nil, err
		}
		if last {
			return out, nil
		}
		out = append(out, item)
	}
}

func checkRetval(what string, retval int32, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if retval != 0 {
		return fmt.Errorf("%s: VPP 返回错误 %d", what, retval)
	}
	return nil
}

func prefixOf(p ip_types.AddressWithPrefix) (netip.Prefix, bool) {
	var addr netip.Addr
	if p.Address.Af == ip_types.ADDRESS_IP6 {
		addr = netip.AddrFrom16(p.Address.Un.GetIP6())
	} else {
		addr = netip.AddrFrom4(p.Address.Un.GetIP4())
	}
	// The interface's own address with its length, not the network.
	prefix := netip.PrefixFrom(addr, int(p.Len))
	return prefix, prefix.IsValid()
}

func (v *realVPP) Read(all, statics bool, wanted func(string, bool) bool) (*vppState, error) {
	st := &vppState{Lists: map[uint32]aclList{}, Statics: statics}
	ifaces, err := dumpAll(v.ch, &vppif.SwInterfaceDump{SwIfIndex: interface_types.InterfaceIndex(noIndex)}, func() (*vppif.SwInterfaceDetails, api.Message) {
		d := &vppif.SwInterfaceDetails{}
		return d, d
	})
	if err != nil {
		return nil, fmt.Errorf("读取接口：%w", err)
	}
	for _, d := range ifaces {
		st.Interfaces = append(st.Interfaces, iface{Index: uint32(d.SwIfIndex), Name: strings.TrimRight(d.InterfaceName, "\x00")})
	}

	st.NAT = v.ch.CheckCompatiblity((*nat44_ei.Nat44EiAddDelStaticMapping)(nil), (*nat44_ei.Nat44EiAddDelIdentityMapping)(nil),
		(*nat44_ei.Nat44EiStaticMappingDump)(nil), (*nat44_ei.Nat44EiStaticMappingDetails)(nil),
		(*nat44_ei.Nat44EiIdentityMappingDump)(nil), (*nat44_ei.Nat44EiIdentityMappingDetails)(nil)) == nil
	if st.NAT {
		if st.NATOutside, err = v.natOutside(); err != nil {
			return nil, err
		}
		if st.Mappings, err = v.mappings(statics); err != nil {
			return nil, err
		}
	}
	for i := range st.Interfaces {
		in := &st.Interfaces[i]
		outside := false
		for _, index := range st.NATOutside {
			outside = outside || index == in.Index
		}
		if !all && !wanted(in.Name, outside) {
			continue
		}
		for _, is6 := range []bool{false, true} {
			addrs, err := dumpAll(v.ch, &ip.IPAddressDump{SwIfIndex: interface_types.InterfaceIndex(in.Index), IsIPv6: is6}, func() (*ip.IPAddressDetails, api.Message) {
				d := &ip.IPAddressDetails{}
				return d, d
			})
			if err != nil {
				return nil, fmt.Errorf("读取 %s 的地址：%w", in.Name, err)
			}
			for _, a := range addrs {
				if prefix, ok := prefixOf(a.Prefix); ok {
					in.Addrs = append(in.Addrs, prefix)
				}
			}
		}
	}

	st.ACL = v.ch.CheckCompatiblity((*acl.ACLAddReplace)(nil), (*acl.ACLDel)(nil), (*acl.ACLDump)(nil), (*acl.ACLDetails)(nil),
		(*acl.ACLInterfaceSetACLList)(nil), (*acl.ACLInterfaceListDump)(nil), (*acl.ACLInterfaceListDetails)(nil)) == nil
	if st.ACL {
		acls, err := dumpAll(v.ch, &acl.ACLDump{ACLIndex: noIndex}, func() (*acl.ACLDetails, api.Message) {
			d := &acl.ACLDetails{}
			return d, d
		})
		if err != nil {
			return nil, fmt.Errorf("读取 ACL：%w", err)
		}
		for _, d := range acls {
			st.ACLs = append(st.ACLs, aclEntry{Index: d.ACLIndex, Tag: strings.TrimRight(d.Tag, "\x00"), Rules: d.R})
		}
		lists, err := dumpAll(v.ch, &acl.ACLInterfaceListDump{SwIfIndex: interface_types.InterfaceIndex(noIndex)}, func() (*acl.ACLInterfaceListDetails, api.Message) {
			d := &acl.ACLInterfaceListDetails{}
			return d, d
		})
		if err != nil {
			return nil, fmt.Errorf("读取接口的 ACL：%w", err)
		}
		for _, d := range lists {
			n := min(int(d.NInput), len(d.Acls))
			if len(d.Acls) > 0 {
				st.Lists[uint32(d.SwIfIndex)] = aclList{Input: append([]uint32(nil), d.Acls[:n]...), Output: append([]uint32(nil), d.Acls[n:]...)}
			}
		}
	}
	return st, nil
}

// natOutside reads the output-feature interfaces. VPP 23.10 and later list them with a
// cursor get; older ones with a dump.
func (v *realVPP) natOutside() ([]uint32, error) {
	var out []uint32
	if v.ch.CheckCompatiblity((*nat44_ei.Nat44EiOutputInterfaceGet)(nil), (*nat44_ei.Nat44EiOutputInterfaceGetReply)(nil), (*nat44_ei.Nat44EiOutputInterfaceDetails)(nil)) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := v.conn.NewStream(ctx)
		if err != nil {
			return nil, err
		}
		defer stream.Close()
		cursor := uint32(0)
		for round := 0; round < 64; round++ {
			if err := stream.SendMsg(&nat44_ei.Nat44EiOutputInterfaceGet{Cursor: cursor}); err != nil {
				return nil, fmt.Errorf("读取 NAT 出口：%w", err)
			}
			for {
				msg, err := stream.RecvMsg()
				if err != nil {
					return nil, fmt.Errorf("读取 NAT 出口：%w", err)
				}
				if d, ok := msg.(*nat44_ei.Nat44EiOutputInterfaceDetails); ok {
					out = append(out, uint32(d.SwIfIndex))
					continue
				}
				reply, ok := msg.(*nat44_ei.Nat44EiOutputInterfaceGetReply)
				if !ok {
					return nil, fmt.Errorf("读取 NAT 出口：意外的消息 %s", msg.GetMessageName())
				}
				// EAGAIN: the reply queue filled; continue from the cursor.
				if reply.Retval == -165 && reply.Cursor != noIndex {
					cursor = reply.Cursor
					break
				}
				return out, nil
			}
		}
		return out, nil
	}
	details, err := dumpAll(v.ch, &nat44_ei.Nat44EiInterfaceOutputFeatureDump{}, func() (*nat44_ei.Nat44EiInterfaceOutputFeatureDetails, api.Message) {
		d := &nat44_ei.Nat44EiInterfaceOutputFeatureDetails{}
		return d, d
	})
	if err != nil {
		return nil, fmt.Errorf("读取 NAT 出口：%w", err)
	}
	for _, d := range details {
		out = append(out, uint32(d.SwIfIndex))
	}
	return out, nil
}

func (v *realVPP) mappings(withStatics bool) ([]mapping, error) {
	var out []mapping
	var statics []*nat44_ei.Nat44EiStaticMappingDetails
	var err error
	if withStatics {
		statics, err = dumpAll(v.ch, &nat44_ei.Nat44EiStaticMappingDump{}, func() (*nat44_ei.Nat44EiStaticMappingDetails, api.Message) {
			d := &nat44_ei.Nat44EiStaticMappingDetails{}
			return d, d
		})
	}
	if err != nil {
		return nil, fmt.Errorf("读取 NAT 静态映射：%w", err)
	}
	for _, d := range statics {
		m := mapping{Proto: d.Protocol, ExternalPort: d.ExternalPort, ExternalIf: uint32(d.ExternalSwIfIndex),
			LocalIP: netip.AddrFrom4(d.LocalIPAddress), LocalPort: d.LocalPort, Tag: strings.TrimRight(d.Tag, "\x00")}
		if m.ExternalIf == noIndex {
			m.ExternalIP = netip.AddrFrom4(d.ExternalIPAddress)
		}
		out = append(out, m)
	}
	identities, err := dumpAll(v.ch, &nat44_ei.Nat44EiIdentityMappingDump{}, func() (*nat44_ei.Nat44EiIdentityMappingDetails, api.Message) {
		d := &nat44_ei.Nat44EiIdentityMappingDetails{}
		return d, d
	})
	if err != nil {
		return nil, fmt.Errorf("读取 NAT identity mapping：%w", err)
	}
	for _, d := range identities {
		m := mapping{Identity: true, Proto: d.Protocol, ExternalPort: d.Port, ExternalIf: uint32(d.SwIfIndex), Tag: strings.TrimRight(d.Tag, "\x00")}
		if m.ExternalIf == noIndex {
			m.ExternalIP = netip.AddrFrom4(d.IPAddress)
		}
		out = append(out, m)
	}
	return out, nil
}

func ip4(addr netip.Addr) ip_types.IP4Address {
	if !addr.Is4() {
		return ip_types.IP4Address{}
	}
	return addr.As4()
}

func (v *realVPP) Mapping(m mapping, add bool) error {
	if m.Identity {
		reply := &nat44_ei.Nat44EiAddDelIdentityMappingReply{}
		err := v.ch.SendRequest(&nat44_ei.Nat44EiAddDelIdentityMapping{IsAdd: add, Protocol: m.Proto, Port: m.ExternalPort,
			SwIfIndex: interface_types.InterfaceIndex(m.ExternalIf), VrfID: noIndex, Tag: m.Tag}).ReceiveReply(reply)
		return checkRetval("NAT identity mapping", reply.Retval, err)
	}
	reply := &nat44_ei.Nat44EiAddDelStaticMappingReply{}
	err := v.ch.SendRequest(&nat44_ei.Nat44EiAddDelStaticMapping{IsAdd: add, LocalIPAddress: ip4(m.LocalIP), Protocol: m.Proto,
		LocalPort: m.LocalPort, ExternalPort: m.ExternalPort, ExternalSwIfIndex: interface_types.InterfaceIndex(m.ExternalIf),
		VrfID: noIndex, Tag: m.Tag}).ReceiveReply(reply)
	// GoVPP reports a non-zero retval as err too, so test the reply itself.
	if add && reply.Retval == retvalNoSuchEntry {
		// nat44_ei_reserve_port: the external port is taken, by a dynamic session's translation
		// on a single WAN address that hands out ports from the whole range above 1024.
		return fmt.Errorf("%s %d 正被动态 NAT 会话占用，等这些连接结束后再试，或改用其他端口", protoName(m.Proto), m.ExternalPort)
	}
	return checkRetval(fmt.Sprintf("NAT 静态映射 %s %d", protoName(m.Proto), m.ExternalPort), reply.Retval, err)
}

// retvalNoSuchEntry is VNET_API_ERROR_NO_SUCH_ENTRY.
const retvalNoSuchEntry = -6

func (v *realVPP) ReplaceACL(index uint32, tag string, rules []acl_types.ACLRule) (uint32, error) {
	reply := &acl.ACLAddReplaceReply{}
	err := v.ch.SendRequest(&acl.ACLAddReplace{ACLIndex: index, Tag: tag, Count: uint32(len(rules)), R: rules}).ReceiveReply(reply)
	return reply.ACLIndex, checkRetval("写入 ACL "+tag, reply.Retval, err)
}

func (v *realVPP) DeleteACL(index uint32) error {
	reply := &acl.ACLDelReply{}
	err := v.ch.SendRequest(&acl.ACLDel{ACLIndex: index}).ReceiveReply(reply)
	return checkRetval("删除 ACL", reply.Retval, err)
}

func (v *realVPP) SetACLList(sw uint32, list aclList) error {
	acls := append(append([]uint32(nil), list.Input...), list.Output...)
	if len(acls) > 255 || len(list.Input) > 255 {
		return errors.New("接口上的 ACL 太多")
	}
	reply := &acl.ACLInterfaceSetACLListReply{}
	err := v.ch.SendRequest(&acl.ACLInterfaceSetACLList{SwIfIndex: interface_types.InterfaceIndex(sw), Count: uint8(len(acls)),
		NInput: uint8(len(list.Input)), Acls: acls}).ReceiveReply(reply)
	return checkRetval("给接口挂 ACL", reply.Retval, err)
}
