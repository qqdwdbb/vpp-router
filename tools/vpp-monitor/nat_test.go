package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fakeNAT struct {
	list     []natUser
	byUser   map[string][]natSession
	reads    int
	dumped   []string
	usersErr error
	closed   int
}

func (f *fakeNAT) exits() (*natLocal, error) {
	return testLocal(), nil
}

func testLocal() *natLocal {
	return &natLocal{
		Names:    map[string]string{"1.1.1.1": "wan", "2001:db8:1::1": "wan"},
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.61.20.0/24"), netip.MustParsePrefix("2001:db8:2::/64"), netip.MustParsePrefix("2001:db8:1::/64")},
	}
}
func (f *fakeNAT) users() ([]natUser, error) {
	f.reads++
	return f.list, f.usersErr
}
func (f *fakeNAT) sessions(user natUser) ([]natSession, error) {
	f.dumped = append(f.dumped, user.Address)
	return f.byUser[user.Address], nil
}
func (f *fakeNAT) close() { f.closed++ }

func tcp(inside string, bytes, packets uint64) natSession {
	return natSession{Protocol: 6, Inside: inside, Outside: "1.1.1.1:5", External: "8.8.8.8:443", Bytes: bytes, Packets: packets, Idle: 2}
}

func natService(f *fakeNAT) (*NATService, *time.Time) {
	now := time.Unix(1000, 0)
	s := NewNATService(func() (natAPI, error) { return f, nil })
	s.now = func() time.Time { return now }
	return s, &now
}

func TestNATRatesComeFromTwoReadings(t *testing.T) {
	f := &fakeNAT{
		list:   []natUser{{Address: "10.0.0.1", Dynamic: 2}},
		byUser: map[string][]natSession{"10.0.0.1": {tcp("10.0.0.1:1", 1000, 10), tcp("10.0.0.1:2", 500, 5)}},
	}
	s, now := natService(f)
	first := s.Report()
	if first.RatesReady || first.Sessions[0].Bps != 0 || !first.Available {
		t.Fatalf("first = %+v", first)
	}
	f.byUser["10.0.0.1"] = []natSession{tcp("10.0.0.1:1", 1000, 10), tcp("10.0.0.1:2", 500+1250, 5+50)}
	*now = now.Add(5 * time.Second)
	second := s.Report()
	if !second.RatesReady || second.Sessions[0].Inside != "10.0.0.1:2" {
		t.Fatalf("second = %+v", second)
	}
	top := second.Sessions[0]
	if top.Bps != 2000 || top.Pps != 10 || top.Protocol != "TCP" || top.User != "10.0.0.1" {
		t.Fatalf("top = %+v", top)
	}
	if second.Bps != 2000 || second.Users[0].Bps != 2000 || second.Users[0].Pps != 10 {
		t.Fatalf("totals = %+v", second)
	}
}

func TestNATReadsAreRateLimited(t *testing.T) {
	f := &fakeNAT{list: []natUser{{Address: "10.0.0.1", Dynamic: 1}}, byUser: map[string][]natSession{"10.0.0.1": {tcp("a", 1, 1)}}}
	s, now := natService(f)
	s.Report()
	*now = now.Add(natMinInterval - time.Second)
	s.Report()
	s.Report()
	if f.reads != 1 {
		t.Fatalf("%d reads inside the minimum interval", f.reads)
	}
	*now = now.Add(time.Second)
	s.Report()
	if f.reads != 2 {
		t.Fatalf("%d reads after the interval", f.reads)
	}
}

func TestNATReadIsBoundedAndBusiestFirst(t *testing.T) {
	f := &fakeNAT{
		list: []natUser{
			{Address: "10.0.0.1", Dynamic: 10},
			{Address: "10.0.0.2", Dynamic: natMaxRead + 1},
			{Address: "10.0.0.3", Dynamic: natMaxRead - 5},
			{Address: "10.0.0.4", Dynamic: 3},
		},
		byUser: map[string][]natSession{},
	}
	for _, user := range f.list {
		for i := 0; i < int(user.Dynamic) && user.Dynamic <= natMaxRead; i++ {
			f.byUser[user.Address] = append(f.byUser[user.Address], tcp(fmt.Sprintf("%s:%d", user.Address, i), 1, 1))
		}
	}
	s, _ := natService(f)
	report := s.Report()
	if !report.Truncated || report.TotalSessions != natMaxRead*2+9 {
		t.Fatalf("report: truncated %v total %d", report.Truncated, report.TotalSessions)
	}
	if strings.Join(f.dumped, ",") != "10.0.0.3,10.0.0.4" {
		t.Fatalf("dumped %v", f.dumped)
	}
	if report.ReadSessions != natMaxRead-2 || len(report.Sessions) != natMaxRows {
		t.Fatalf("read %d rows %d", report.ReadSessions, len(report.Sessions))
	}
	if report.Users[0].Read || report.Users[0].Address != "10.0.0.2" || !report.Users[1].Read {
		t.Fatalf("users = %+v", report.Users[:2])
	}
}

func TestNATErrorReportsAndReconnects(t *testing.T) {
	f := &fakeNAT{list: []natUser{}, usersErr: errors.New("vpp went away")}
	dials := 0
	now := time.Unix(1000, 0)
	s := NewNATService(func() (natAPI, error) { dials++; return f, nil })
	s.now = func() time.Time { return now }
	report := s.Report()
	if report.Available || report.Reason != "vpp went away" || f.closed != 1 {
		t.Fatalf("report = %+v, closed %d", report, f.closed)
	}
	f.usersErr = nil
	now = now.Add(natMinInterval)
	if report = s.Report(); !report.Available || dials != 2 {
		t.Fatalf("report = %+v, dials %d", report, dials)
	}
}

func TestNATDialFailureIsReported(t *testing.T) {
	s := NewNATService(func() (natAPI, error) { return nil, errors.New("no NAT plugin") })
	if report := s.Report(); report.Available || report.Reason != "no NAT plugin" {
		t.Fatalf("report = %+v", report)
	}
}

func TestNATConnectionClosesWhenIdle(t *testing.T) {
	f := &fakeNAT{list: []natUser{{Address: "10.0.0.1"}}, byUser: map[string][]natSession{}}
	s, now := natService(f)
	s.Report()
	s.idle.Stop()
	*now = now.Add(natIdleClose - time.Second)
	s.closeIdle()
	if f.closed != 0 {
		t.Fatal("closed while still in use")
	}
	*now = now.Add(time.Second)
	s.closeIdle()
	if f.closed != 1 || s.api != nil || s.previous != nil {
		t.Fatalf("closed %d, api %v", f.closed, s.api)
	}
}

func TestNATEndpoint(t *testing.T) {
	f := &fakeNAT{list: []natUser{{Address: "10.0.0.1", Dynamic: 1}}, byUser: map[string][]natSession{"10.0.0.1": {tcp("10.0.0.1:1", 1, 1)}}}
	nat, _ := natService(f)
	c, _ := newTestCollector(&fakeStats{})
	w := httptest.NewRecorder()
	NewHandler(c, c.store, nat, NewVPNService(&fakeVPN{}, nil)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/nat", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"inside":"10.0.0.1:1"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestProtocolNames(t *testing.T) {
	for protocol, want := range map[uint16]string{1: "ICMP", 6: "TCP", 17: "UDP", 47: "47", 58: "ICMPv6"} {
		if got := protocolName(protocol); got != want {
			t.Errorf("%d: %s", protocol, got)
		}
	}
}

func TestUnrecordedExternalAddressIsEmpty(t *testing.T) {
	if got := externalAddress(6, "0.0.0.0", 0); got != "" {
		t.Errorf("zero address = %q", got)
	}
	if got := externalAddress(17, "8.8.8.8", 53); got != "8.8.8.8:53" {
		t.Errorf("address = %q", got)
	}
	if got := externalAddress(1, "8.8.8.8", 51043); got != "8.8.8.8" {
		t.Errorf("ICMP address = %q", got)
	}
}

func TestSessionsAreGroupedByExit(t *testing.T) {
	second := natSession{Protocol: 6, Inside: "10.0.0.2:9", Outside: "2.2.2.2:7", External: "9.9.9.9:80", Bytes: 500, Packets: 5}
	f := &fakeNAT{
		list:   []natUser{{Address: "10.0.0.1", Dynamic: 1}, {Address: "10.0.0.2", Dynamic: 1}},
		byUser: map[string][]natSession{"10.0.0.1": {tcp("10.0.0.1:1", 1000, 10)}, "10.0.0.2": {second}},
	}
	s, now := natService(f)
	s.Report()
	f.byUser["10.0.0.1"] = []natSession{tcp("10.0.0.1:1", 2250, 60)}
	*now = now.Add(5 * time.Second)
	report := s.Report()
	if report.Sessions[0].Exit != "wan" || report.Sessions[1].Exit != "2.2.2.2" {
		t.Fatalf("sessions = %+v", report.Sessions)
	}
	if len(report.Exits) != 2 || report.Exits[0].Name != "wan" || report.Exits[0].Bps != 2000 || report.Exits[0].Sessions != 1 {
		t.Fatalf("exits = %+v", report.Exits)
	}
	if report.Exits[1].Name != "2.2.2.2" || report.Exits[1].Sessions != 1 {
		t.Fatalf("exits = %+v", report.Exits)
	}
}

func TestOneClientInSeveralVRFsIsOneRow(t *testing.T) {
	wan := natSession{Protocol: 6, Inside: "10.0.0.1:1", Outside: "1.1.1.1:5", External: "8.8.8.8:443", Bytes: 1000, Packets: 10}
	vpn := natSession{Protocol: 6, Inside: "10.0.0.1:2", Outside: "2.2.2.2:6", External: "9.9.9.9:443", Bytes: 2000, Packets: 20}
	f := &vrfNAT{fakeNAT: fakeNAT{list: []natUser{
		{Address: "10.0.0.1", VRF: 0, Dynamic: 1},
		{Address: "10.0.0.1", VRF: 102, Dynamic: 1},
		{Address: "10.0.0.2", VRF: 0, Static: 1},
	}, byUser: map[string][]natSession{"10.0.0.2": {tcp("10.0.0.2:1", 1, 1)}}}, byVRF: map[uint32][]natSession{0: {wan}, 102: {vpn}}}
	now := time.Unix(1000, 0)
	s := NewNATService(func() (natAPI, error) { return f, nil })
	s.now = func() time.Time { return now }
	s.Report()
	f.byVRF[0][0].Bytes += 625
	f.byVRF[102][0].Bytes += 1250
	now = now.Add(5 * time.Second)
	report := s.Report()
	if len(report.Users) != 2 {
		t.Fatalf("users = %+v", report.Users)
	}
	user := report.Users[0]
	if user.Address != "10.0.0.1" || user.Dynamic != 2 || user.Bps != 3000 || strings.Join(user.Exits, ",") != "2.2.2.2,wan" {
		t.Fatalf("user = %+v", user)
	}
	if report.TotalSessions != 3 || len(report.Sessions) != 3 {
		t.Fatalf("report = %+v", report)
	}
}

// vrfNAT returns a client's sessions by VRF, as a router with several NAT domains does.
type vrfNAT struct {
	fakeNAT
	byVRF map[uint32][]natSession
}

func (f *vrfNAT) sessions(user natUser) ([]natSession, error) {
	if sessions, ok := f.byVRF[user.VRF]; ok && user.Address == "10.0.0.1" {
		return sessions, nil
	}
	return f.fakeNAT.sessions(user)
}

func TestClassifyClient(t *testing.T) {
	local := testLocal()
	cases := []struct {
		name             string
		client, external string
		want             string
	}{
		{"LAN client", "10.61.20.90", "8.8.8.8", clientKindClient},
		{"VPN client in a private pool", "10.62.50.1", "8.8.8.8", clientKindClient},
		{"delegated IPv6 client", "2001:db8:2::5", "2600::1", clientKindClient},
		{"VPN client in a public pool", "2001:db8:3::100", "2600::1", clientKindClient},
		{"the router itself", "1.1.1.1", "8.8.8.8", clientKindSelf},
		{"the router's IPv6", "2001:db8:1::1", "2600::1", clientKindSelf},
		{"reply to a gone VPN client", "203.0.113.35", "10.62.50.1", clientKindReturn},
		{"reply to a local IPv6 address", "2600::23", "2001:db8:2::100", clientKindReturn},
		{"public source, no destination known", "203.0.113.35", "", clientKindClient},
	}
	for _, tc := range cases {
		external, _ := netip.ParseAddr(tc.external)
		if got := classifyClient(netip.MustParseAddr(tc.client), external, local); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestEndpointAddress(t *testing.T) {
	for text, want := range map[string]string{"10.0.0.1:53": "10.0.0.1", "[2001:db8::1]:443": "2001:db8::1", "8.8.8.8": "8.8.8.8", "2001:db8::2": "2001:db8::2"} {
		if got := endpointAddress(text).String(); got != want {
			t.Errorf("%s: %s", text, got)
		}
	}
	if endpointAddress("").IsValid() {
		t.Error("an empty endpoint has no address")
	}
}

func TestReturnTrafficIsNotCountedAsAClient(t *testing.T) {
	stray := natSession{Protocol: 6, Inside: "203.0.113.35:2002", Outside: "1.1.1.1:9", External: "10.62.50.1:44490", Bytes: 300, Packets: 5}
	own := natSession{Protocol: 6, Inside: "1.1.1.1:5000", Outside: "1.1.1.1:5000", External: "8.8.8.8:53", Bytes: 1, Packets: 1}
	f := &fakeNAT{
		list:   []natUser{{Address: "203.0.113.35", Dynamic: 1}, {Address: "1.1.1.1", Dynamic: 1}, {Address: "10.61.20.90", Dynamic: 1}},
		byUser: map[string][]natSession{"203.0.113.35": {stray}, "1.1.1.1": {own}, "10.61.20.90": {tcp("10.61.20.90:1", 1, 1)}},
	}
	s, _ := natService(f)
	report := s.Report()
	kinds := map[string]string{}
	for _, user := range report.Users {
		kinds[user.Address] = user.Kind
	}
	if kinds["203.0.113.35"] != clientKindReturn || kinds["1.1.1.1"] != clientKindSelf || kinds["10.61.20.90"] != clientKindClient {
		t.Fatalf("kinds = %v", kinds)
	}
	for _, session := range report.Sessions {
		if session.User == "203.0.113.35" && session.Kind != clientKindReturn {
			t.Fatalf("session = %+v", session)
		}
	}
}

func TestClientsBeyondTheDisplayedRowsKeepKindAndExits(t *testing.T) {
	busy := make([]natSession, 0, natMaxRows+5)
	for i := 0; i < natMaxRows+5; i++ {
		busy = append(busy, tcp(fmt.Sprintf("10.61.20.5:%d", i+1), 1000, 10))
	}
	stray := natSession{Protocol: 6, Inside: "203.0.113.35:2002", Outside: "1.1.1.1:9", External: "10.62.50.1:44490", Bytes: 1, Packets: 1}
	f := &fakeNAT{
		list:   []natUser{{Address: "10.61.20.5", Dynamic: uint32(len(busy))}, {Address: "203.0.113.35", Dynamic: 1}},
		byUser: map[string][]natSession{"10.61.20.5": busy, "203.0.113.35": {stray}},
	}
	s, _ := natService(f)
	report := s.Report()
	if len(report.Sessions) != natMaxRows {
		t.Fatalf("%d rows", len(report.Sessions))
	}
	for _, user := range report.Users {
		if user.Address == "203.0.113.35" && (user.Kind != clientKindReturn || len(user.Exits) != 1 || user.Exits[0] != "wan") {
			t.Fatalf("user = %+v", user)
		}
	}
}
