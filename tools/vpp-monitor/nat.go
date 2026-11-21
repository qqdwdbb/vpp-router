package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	vppif "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip"
	"go.fd.io/govpp/binapi/ip_types"
	"go.fd.io/govpp/binapi/nat44_ei"
	"go.fd.io/govpp/core"
)

// Connections per exit come from the NAT sessions: every exit uses NAT, a session already
// counts its traffic, and reading it adds nothing to forwarding. The external address needs
// patches/vpp/0012, without which VPP reports it as zero and it is left blank. IPv6 is left
// out: its translation is 1:1 and keeps no per-connection state worth counting.
//
// Individual NAT sessions are not in the stats segment, only behind VPP's binary API, whose
// handlers normally run with the workers held at a barrier. So nothing here runs unless a
// viewer has the sessions open, reads are rate limited whatever the number of viewers, and
// the amount read in one go is bounded.
const (
	natMinInterval = 5 * time.Second
	natIdleClose   = 30 * time.Second
	natMaxRead     = 5000
	natMaxRows     = 300
)

// natUser is one inside address known to NAT.
type natUser struct {
	Address string
	VRF     uint32
	Dynamic uint32
	Static  uint32
}

type natSession struct {
	Protocol uint16
	Inside   string
	Outside  string
	External string
	Static   bool
	Idle     float64
	Bytes    uint64
	Packets  uint64
}

// natLocal is what VPP's interfaces say about addresses: which exit holds an address, and
// which networks are local.
type natLocal struct {
	Names    map[string]string
	Prefixes []netip.Prefix
}

// The kinds of address in the client columns.
const (
	clientKindClient = "client"
	clientKindSelf   = "self"
	clientKindReturn = "return"
)

func (l *natLocal) inLocalNetwork(address netip.Addr) bool {
	for _, prefix := range l.Prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// classifyClient tells a real client from the router's own traffic and from packets heading
// back in. A packet from a public host to a private or local address that still leaves
// through an exit has lost its way: typically a reply to a VPN client that has disconnected,
// where NAT then takes the remote server for an inside host.
func classifyClient(client, external netip.Addr, local *natLocal) string {
	if !client.IsValid() || local == nil {
		return clientKindClient
	}
	if _, own := local.Names[client.String()]; own {
		return clientKindSelf
	}
	if !client.IsGlobalUnicast() || client.IsPrivate() || local.inLocalNetwork(client) {
		return clientKindClient
	}
	if external.IsValid() && (external.IsPrivate() || local.inLocalNetwork(external)) {
		return clientKindReturn
	}
	return clientKindClient
}

// endpointAddress reads the address out of "ip:port", "[ip]:port" or "ip".
func endpointAddress(text string) netip.Addr {
	if endpoint, err := netip.ParseAddrPort(text); err == nil {
		return endpoint.Addr()
	}
	address, _ := netip.ParseAddr(text)
	return address
}

// natAPI is the part of VPP's API the sessions view needs.
type natAPI interface {
	exits() (*natLocal, error)
	users() ([]natUser, error)
	sessions(natUser) ([]natSession, error)
	close()
}

type NATSessionRow struct {
	Exit     string  `json:"exit"`
	Protocol string  `json:"protocol"`
	Inside   string  `json:"inside"`
	Outside  string  `json:"outside"`
	External string  `json:"external"`
	User     string  `json:"user"`
	Static   bool    `json:"static"`
	Bps      float64 `json:"bps"`
	Pps      float64 `json:"pps"`
	Kind     string  `json:"kind"`
	Bytes    uint64  `json:"bytes"`
	Packets  uint64  `json:"packets"`
	Idle     float64 `json:"idle_seconds"`
}

// NATUserRow is one client. VPP keeps a user per address and VRF, and a router with a NAT
// domain per exit has several for one device, so the report adds them up by address.
type NATUserRow struct {
	Address string   `json:"address"`
	Exits   []string `json:"exits"`
	Kind    string   `json:"kind"`
	Dynamic uint32   `json:"dynamic"`
	Static  uint32   `json:"static"`
	Read    bool     `json:"read"`
	Bps     float64  `json:"bps"`
	Pps     float64  `json:"pps"`
}

// NATExitRow totals the sessions leaving through one exit.
type NATExitRow struct {
	Name     string  `json:"name"`
	Bps      float64 `json:"bps"`
	Pps      float64 `json:"pps"`
	Sessions int     `json:"sessions"`
}

// NATReport is one reading of the sessions, busiest first.
type NATReport struct {
	Available     bool            `json:"available"`
	Reason        string          `json:"reason"`
	Time          int64           `json:"time"`
	RatesReady    bool            `json:"rates_ready"`
	TotalSessions uint64          `json:"total_sessions"`
	ReadSessions  int             `json:"read_sessions"`
	Truncated     bool            `json:"truncated"`
	Bps           float64         `json:"bps"`
	Pps           float64         `json:"pps"`
	Exits         []NATExitRow    `json:"exits"`
	Users         []NATUserRow    `json:"users"`
	Sessions      []NATSessionRow `json:"sessions"`
}

type natKey struct {
	protocol                  uint16
	inside, outside, external string
}

type natCounters struct{ bytes, packets uint64 }

// NATService reads sessions on demand and keeps the connection only while they are viewed.
type NATService struct {
	dial func() (natAPI, error)
	now  func() time.Time

	mu       sync.Mutex
	api      natAPI
	cached   *NATReport
	cachedAt time.Time
	previous map[natKey]natCounters
	lastRead time.Time
	idle     *time.Timer
	exits    *natLocal
}

func NewNATService(dial func() (natAPI, error)) *NATService {
	return &NATService{dial: dial, now: time.Now}
}

// Report returns a reading no older than natMinInterval.
func (s *NATService) Report() *NATReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.idle != nil {
		s.idle.Stop()
	}
	s.idle = time.AfterFunc(natIdleClose, s.closeIdle)
	if s.cached != nil && now.Sub(s.cachedAt) < natMinInterval {
		return s.cached
	}
	s.cached, s.cachedAt = s.read(now), now
	return s.cached
}

func (s *NATService) closeIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.api != nil && s.now().Sub(s.cachedAt) >= natIdleClose {
		s.closeLocked()
	}
}

// closeLocked also forgets the counters: rates over a long absence would mean little.
func (s *NATService) closeLocked() {
	if s.api != nil {
		s.api.close()
		s.api = nil
	}
	s.previous, s.lastRead, s.exits = nil, time.Time{}, nil
}

func (s *NATService) unavailable(now time.Time, err error) *NATReport {
	s.closeLocked()
	return &NATReport{Reason: err.Error(), Time: now.Unix()}
}

func (s *NATService) read(now time.Time) *NATReport {
	if s.api == nil {
		api, err := s.dial()
		if err != nil {
			return s.unavailable(now, err)
		}
		s.api = api
	}
	if s.exits == nil {
		exits, err := s.api.exits()
		if err != nil {
			return s.unavailable(now, err)
		}
		s.exits = exits
	}
	users, err := s.api.users()
	if err != nil {
		return s.unavailable(now, err)
	}
	sort.Slice(users, func(i, j int) bool {
		a, b := users[i].Dynamic+users[i].Static, users[j].Dynamic+users[j].Static
		if a != b {
			return a > b
		}
		return users[i].Address < users[j].Address
	})
	report := &NATReport{Available: true, Time: now.Unix(), Users: make([]NATUserRow, 0, len(users))}
	dt := now.Sub(s.lastRead).Seconds()
	report.RatesReady = !s.lastRead.IsZero() && dt > 0
	current := make(map[natKey]natCounters)
	exits := make(map[string]*NATExitRow)
	var rows []NATSessionRow
	budget := natMaxRead
	for _, user := range users {
		row := NATUserRow{Address: user.Address, Dynamic: user.Dynamic, Static: user.Static}
		count := int(user.Dynamic + user.Static)
		report.TotalSessions += uint64(count)
		// A user that does not fit is left out rather than cut off partway: one dump
		// cannot be stopped early, and the busiest users are visited first.
		if count > budget {
			report.Truncated = true
			report.Users = append(report.Users, row)
			continue
		}
		sessions, err := s.api.sessions(user)
		if err != nil {
			return s.unavailable(now, err)
		}
		row.Read = true
		budget -= len(sessions)
		report.ReadSessions += len(sessions)
		for _, session := range sessions {
			one := NATSessionRow{
				Exit: s.exitOf(session.Outside), Protocol: protocolName(session.Protocol), Inside: session.Inside, Outside: session.Outside,
				External: session.External, User: user.Address, Static: session.Static,
				Kind:  classifyClient(endpointAddress(session.Inside), endpointAddress(session.External), s.exits),
				Bytes: session.Bytes, Packets: session.Packets, Idle: session.Idle,
			}
			key := natKey{session.Protocol, session.Inside, session.Outside, session.External}
			current[key] = natCounters{session.Bytes, session.Packets}
			if before, ok := s.previous[key]; ok && report.RatesReady && session.Bytes >= before.bytes && session.Packets >= before.packets {
				one.Bps = float64(session.Bytes-before.bytes) * 8 / dt
				one.Pps = float64(session.Packets-before.packets) / dt
			}
			row.Bps += one.Bps
			row.Pps += one.Pps
			exit := exits[one.Exit]
			if exit == nil {
				exit = &NATExitRow{Name: one.Exit}
				exits[one.Exit] = exit
			}
			exit.Bps += one.Bps
			exit.Pps += one.Pps
			exit.Sessions++
			rows = append(rows, one)
		}
		report.Bps += row.Bps
		report.Pps += row.Pps
		report.Users = append(report.Users, row)
	}
	// Before the list is cut to what the page shows: every client needs its exits and kind.
	report.Users = mergeUsers(report.Users, rows)
	s.previous, s.lastRead = current, now
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Bps != rows[j].Bps {
			return rows[i].Bps > rows[j].Bps
		}
		return rows[i].Bytes > rows[j].Bytes
	})
	if len(rows) > natMaxRows {
		rows = rows[:natMaxRows]
	}
	report.Sessions = rows
	for _, name := range sortedKeys(exits) {
		report.Exits = append(report.Exits, *exits[name])
	}
	sort.SliceStable(report.Exits, func(i, j int) bool { return report.Exits[i].Bps > report.Exits[j].Bps })
	sort.SliceStable(report.Users, func(i, j int) bool { return report.Users[i].Bps > report.Users[j].Bps })
	return report
}

// externalAddress returns nothing for the zero address, which is what VPP reports when it
// did not record the far end of a session.
func externalAddress(protocol uint16, address string, port uint16) string {
	if address == "0.0.0.0" {
		return ""
	}
	if protocol == 1 {
		return address // an ICMP session's "port" is its identifier
	}
	return fmt.Sprintf("%s:%d", address, port)
}

// exitOf names the interface holding a session's translated address. An address that no
// interface holds, such as a pool address reached by routing, is shown as it is.
func (s *NATService) exitOf(outside string) string {
	address, _, _ := strings.Cut(outside, ":")
	if name, ok := s.exits.Names[address]; ok {
		return name
	}
	return address
}

// mergeUsers adds up the rows of each client and lists the exits its connections use.
func mergeUsers(users []NATUserRow, sessions []NATSessionRow) []NATUserRow {
	exits := make(map[string]map[string]bool)
	kinds := make(map[string]map[string]bool)
	for _, session := range sessions {
		if exits[session.User] == nil {
			exits[session.User] = make(map[string]bool)
			kinds[session.User] = make(map[string]bool)
		}
		exits[session.User][session.Exit] = true
		kinds[session.User][session.Kind] = true
	}
	// A client with any ordinary connection stays a client.
	kindOf := func(address string) string {
		if len(kinds[address]) == 1 {
			for kind := range kinds[address] {
				return kind
			}
		}
		return clientKindClient
	}
	merged := make([]NATUserRow, 0, len(users))
	index := make(map[string]int, len(users))
	for _, user := range users {
		at, seen := index[user.Address]
		if !seen {
			index[user.Address] = len(merged)
			user.Exits = sortedKeys(exits[user.Address])
			user.Kind = kindOf(user.Address)
			merged = append(merged, user)
			continue
		}
		row := &merged[at]
		row.Dynamic += user.Dynamic
		row.Static += user.Static
		row.Bps += user.Bps
		row.Pps += user.Pps
		row.Read = row.Read || user.Read
	}
	return merged
}

func protocolName(protocol uint16) string {
	switch protocol {
	case 58:
		return "ICMPv6"
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	}
	return fmt.Sprintf("%d", protocol)
}

// vppNAT reads NAT44-EI sessions over VPP's API socket.
type vppNAT struct {
	conn   *core.Connection
	ch     api.Channel
	names  map[uint32]string
	labels *InterfaceLabels
}

func dialVPPNAT(socket string, labels *InterfaceLabels) (natAPI, error) {
	conn, err := govpp.Connect(socket)
	if err != nil {
		return nil, fmt.Errorf("connecting to the VPP API: %w", err)
	}
	ch, err := conn.NewAPIChannel()
	if err != nil {
		conn.Disconnect()
		return nil, err
	}
	ch.SetReplyTimeout(3 * time.Second)
	if err := ch.CheckCompatiblity(&nat44_ei.Nat44EiUserDump{}, &nat44_ei.Nat44EiUserDetails{},
		&nat44_ei.Nat44EiUserSessionV2Dump{}, &nat44_ei.Nat44EiUserSessionV2Details{},
		&vppif.SwInterfaceDump{}, &vppif.SwInterfaceDetails{}, &ip.IPAddressDump{}, &ip.IPAddressDetails{}); err != nil {
		ch.Close()
		conn.Disconnect()
		return nil, fmt.Errorf("this VPP has no compatible NAT44-EI API: %w", err)
	}
	return &vppNAT{conn: conn, ch: ch, labels: labels}, nil
}

func (v *vppNAT) close() {
	v.ch.Close()
	v.conn.Disconnect()
}

// exits maps each interface address to the interface's name.
func (v *vppNAT) exits() (*natLocal, error) {
	names := make(map[interface_types.InterfaceIndex]string)
	v.names = make(map[uint32]string)
	request := v.ch.SendMultiRequest(&vppif.SwInterfaceDump{SwIfIndex: interface_types.InterfaceIndex(^uint32(0))})
	for {
		var reply vppif.SwInterfaceDetails
		stop, err := request.ReceiveReply(&reply)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		names[reply.SwIfIndex] = strings.TrimRight(reply.InterfaceName, "\x00")
		v.names[uint32(reply.SwIfIndex)] = v.labels.Name(names[reply.SwIfIndex])
	}
	local := &natLocal{Names: make(map[string]string)}
	for index, name := range names {
		for _, ipv6 := range []bool{false, true} {
			request := v.ch.SendMultiRequest(&ip.IPAddressDump{SwIfIndex: index, IsIPv6: ipv6})
			for {
				var reply ip.IPAddressDetails
				stop, err := request.ReceiveReply(&reply)
				if err != nil {
					return nil, err
				}
				if stop {
					break
				}
				local.Names[reply.Prefix.Address.String()] = v.labels.Name(name)
				if prefix, err := netip.ParsePrefix(reply.Prefix.String()); err == nil {
					local.Prefixes = append(local.Prefixes, prefix.Masked())
				}
			}
		}
	}
	return local, nil
}

func (v *vppNAT) users() ([]natUser, error) {
	var users []natUser
	request := v.ch.SendMultiRequest(&nat44_ei.Nat44EiUserDump{})
	for {
		var reply nat44_ei.Nat44EiUserDetails
		stop, err := request.ReceiveReply(&reply)
		if err != nil {
			return nil, err
		}
		if stop {
			return users, nil
		}
		users = append(users, natUser{Address: reply.IPAddress.String(), VRF: reply.VrfID, Dynamic: reply.Nsessions, Static: reply.Nstaticsessions})
	}
}

func (v *vppNAT) sessions(user natUser) ([]natSession, error) {
	address, err := ip_types.ParseIP4Address(user.Address)
	if err != nil {
		return nil, err
	}
	var sessions []natSession
	request := v.ch.SendMultiRequest(&nat44_ei.Nat44EiUserSessionV2Dump{IPAddress: address, VrfID: user.VRF})
	for {
		var reply nat44_ei.Nat44EiUserSessionV2Details
		stop, err := request.ReceiveReply(&reply)
		if err != nil {
			return nil, err
		}
		if stop {
			return sessions, nil
		}
		sessions = append(sessions, natSession{
			Protocol: reply.Protocol,
			Inside:   fmt.Sprintf("%s:%d", reply.InsideIPAddress, reply.InsidePort),
			Outside:  fmt.Sprintf("%s:%d", reply.OutsideIPAddress, reply.OutsidePort),
			External: externalAddress(reply.Protocol, reply.ExtHostAddress.String(), reply.ExtHostPort),
			Static:   reply.Flags&nat44_ei.NAT44_EI_STATIC_MAPPING != 0,
			Idle:     float64(reply.TimeSinceLastHeard),
			Bytes:    reply.TotalBytes,
			Packets:  uint64(reply.TotalPkts),
		})
	}
}
