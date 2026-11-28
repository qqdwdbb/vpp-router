package main

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParsePPPoELine(t *testing.T) {
	line := parseLine("create pppoe client eth0.100 host-uniq 1 name pppoe0 username u@isp password s3cret use-peer-dns add-default-route4 mtu 1480")
	if line.kind != linePPPoE || line.iface != "pppoe0" || line.base != "eth0.100" {
		t.Fatalf("line %+v", line)
	}
	c := line.pppoe
	if c.hostUniq != 1 || c.username != "u@isp" || c.password != "s3cret" || !slices.Equal(c.rest, []string{"use-peer-dns", "add-default-route4", "mtu", "1480"}) {
		t.Fatalf("config %+v", c)
	}
	if c.command() != "create pppoe client eth0.100 host-uniq 1 name pppoe0 username u@isp password s3cret use-peer-dns add-default-route4 mtu 1480" {
		t.Fatalf("command %q", c.command())
	}
	if c.deleteCommand() != "create pppoe client eth0.100 host-uniq 1 del" {
		t.Fatalf("delete %q", c.deleteCommand())
	}
	if got := line.shownText(); strings.Contains(got, "s3cret") || !strings.Contains(got, "password ******") {
		t.Fatalf("shown %q", got)
	}
	// Lines the panel cannot match with an interface stay other lines.
	for _, text := range []string{
		"create pppoe client eth0.100 host-uniq 1 username u password p", // no name
		"create pppoe client eth0.100 host-uniq 1 del",
		"create pppoe client sw-if-index 2 host-uniq 1 name pppoe0",
		"create pppoe client eth0.100 host-uniq 1 name pppoe0 frobnicate",
	} {
		if parseLine(text).kind != lineOther {
			t.Fatalf("%q read as %v", text, parseLine(text).kind)
		}
	}
}

func TestRedact(t *testing.T) {
	text := "create pppoe client: unknown input `password hunter2 use-peer-dns'"
	if got := redact(text); strings.Contains(got, "hunter2") {
		t.Fatalf("redact %q", got)
	}
}

const pppoeFile = installerFile + "create pppoe client eth0.100 host-uniq 1 name pppoe0 username u@isp password s3cret use-peer-dns add-default-route4\n"

func pppoeLive() *liveState {
	live := installerLive()
	live.Interfaces = append(live.Interfaces, &liveInterface{Index: 6, Name: "pppoe0", Hardware: true, Up: true, Link: true, MTU: 1492,
		Addresses: []netip.Prefix{pfx("100.64.1.2/32")}, PPPoE: &livePPPoE{State: "session", Session: 7, ACMAC: "02:00:00:00:00:09"}})
	return live
}

func TestCreatePPPoEOnAnExit(t *testing.T) {
	s, sys, path := setup(t, installerFile, "")
	state, err := s.CreateDevice(DeviceRequest{Kind: "pppoe", Parent: "eth0.100", Username: "u@isp", Password: "s3cret"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	create := "create pppoe client eth0.100 host-uniq 1 name pppoe0 username u@isp password s3cret use-peer-dns add-default-route4"
	want := []string{create, "nat44 ei add interface address pppoe0", "set interface nat44 ei out pppoe0 output-feature"}
	if !slices.Equal(sys.commands, want) {
		t.Fatalf("commands %q", sys.commands)
	}
	text := read(t, path)
	if !strings.Contains(text, "ip route add 0.0.0.0/0 via 10.61.10.1 eth0.100\n"+create+"\n") {
		t.Fatalf("the client does not follow its interface:\n%s", text)
	}
	if !strings.Contains(text, "user-sessions 16384\nnat44 ei add interface address pppoe0\nset interface nat44 ei out pppoe0 output-feature\n") {
		t.Fatalf("exit lines:\n%s", text)
	}
	// The page sees neither the password nor the undo commands, which have it.
	data, _ := json.Marshal(state)
	if strings.Contains(string(data), "s3cret") {
		t.Fatalf("password in the state: %s", data)
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"set interface nat44 ei out pppoe0 output-feature del", "nat44 ei add interface address pppoe0 del", "create pppoe client eth0.100 host-uniq 1 del"}) {
		t.Fatalf("undo %q", sys.commands)
	}
	if read(t, path) != installerFile {
		t.Fatalf("rollback left\n%s", read(t, path))
	}
}

func TestCreatePPPoERefusals(t *testing.T) {
	s, _, _ := setup(t, pppoeFile, "")
	s.sys.(*fakeSystem).live = pppoeLive()
	for name, q := range map[string]DeviceRequest{
		"no password":       {Kind: "pppoe", Parent: "eth1", Username: "u"},
		"space in password": {Kind: "pppoe", Parent: "eth1", Username: "u", Password: "a b"},
		"bridged":           {Kind: "pppoe", Parent: "eth0", Username: "u", Password: "p"},
		"loopback":          {Kind: "pppoe", Parent: "loop0", Username: "u", Password: "p"},
		"second client":     {Kind: "pppoe", Parent: "eth0.100", Username: "u", Password: "p"},
		"other program's":   {Kind: "pppoe", Parent: "wg0", Username: "u", Password: "p"},
	} {
		if _, err := s.CreateDevice(q, "admin"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// A second port gets the next name and Host-Uniq.
	q := DeviceRequest{Kind: "pppoe", Parent: "eth1", Username: "v", Password: "w"}
	file := parseCLI(pppoeFile)
	c, err := pppoeCreate(file, pppoeLive(), q)
	if err != nil || c.name != "pppoe1" || c.hostUniq != 2 {
		t.Fatalf("second client %+v, %v", c, err)
	}
}

func TestPPPoEView(t *testing.T) {
	s, sys, _ := setup(t, pppoeFile, "")
	sys.live = pppoeLive()
	state := s.State()
	for _, v := range state.Interfaces {
		switch v.Name {
		case "pppoe0":
			if v.Kind != "pppoe" || v.IPv4.Mode != modePPPoE || v.PPPoE == nil || v.PPPoE.Username != "u@isp" || !v.PPPoE.Password || v.PPPoE.State != "session" || v.NATReason != "" || v.Reason != "" {
				t.Fatalf("view %+v %+v", v, v.PPPoE)
			}
			if v.DeleteReason != "" {
				t.Fatalf("pppoe0 cannot be deleted: %s", v.DeleteReason)
			}
		case "eth0.100":
			if v.PPPoEReason == "" || v.BridgeReason == "" || v.DeleteReason == "" {
				t.Fatalf("eth0.100 %+v", v)
			}
			for _, ref := range v.References {
				if strings.Contains(ref, "s3cret") {
					t.Fatalf("password in a reference: %q", ref)
				}
			}
		case "eth1":
			if v.PPPoEReason != "" {
				t.Fatalf("eth1 cannot dial: %s", v.PPPoEReason)
			}
		}
	}
	data, _ := json.Marshal(state)
	if strings.Contains(string(data), "s3cret") {
		t.Fatalf("password in the state: %s", data)
	}
}

func TestSetPPPoEAccount(t *testing.T) {
	s, sys, path := setup(t, pppoeFile, "")
	sys.live = pppoeLive()
	if _, err := s.SetPPPoE(PPPoERequest{Interface: "pppoe0", Username: "u@isp"}, "admin"); err == nil {
		t.Fatal("no change accepted")
	}
	if _, err := s.SetPPPoE(PPPoERequest{Interface: "pppoe0", Username: "x y"}, "admin"); err == nil {
		t.Fatal("bad account accepted")
	}
	if _, err := s.SetPPPoE(PPPoERequest{Interface: "pppoe0", Username: "new@isp"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"set pppoe client pppoe0 username new@isp password s3cret", "pppoe client restart pppoe0"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if !strings.Contains(read(t, path), "name pppoe0 username new@isp password s3cret use-peer-dns add-default-route4\n") {
		t.Fatalf("file\n%s", read(t, path))
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"set pppoe client pppoe0 username u@isp password s3cret", "pppoe client restart pppoe0"}) {
		t.Fatalf("undo %q", sys.commands)
	}
	if read(t, path) != pppoeFile {
		t.Fatalf("rollback left\n%s", read(t, path))
	}
	// IPv4 stays the client's; IPv6 can be set on the PPPoX interface.
	if _, err := s.SetFamily("pppoe0", false, Family{Mode: modeDHCP}, "admin"); err == nil {
		t.Fatal("IPv4 of pppoe0 changed")
	}
	if _, err := s.SetFamily("pppoe0", true, Family{Mode: modeSLAAC}, "admin"); err != nil {
		t.Fatal(err)
	}
	s.Rollback("admin")
}

func TestDeletePPPoE(t *testing.T) {
	file := pppoeFile + "nat44 ei add interface address pppoe0\nset interface nat44 ei out pppoe0 output-feature\n"
	s, sys, path := setup(t, file, "")
	sys.live = pppoeLive()
	if _, err := s.DeleteDevice("pppoe0", "admin"); err == nil {
		t.Fatal("deleted an exit")
	}
	if _, err := s.SetBridge("eth0.100", 1, false, "admin"); err == nil {
		t.Fatal("the access interface joined a bridge")
	}
	s, sys, path = setup(t, pppoeFile, "")
	sys.live = pppoeLive()
	if _, err := s.DeleteDevice("pppoe0", "admin"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sys.commands, []string{"create pppoe client eth0.100 host-uniq 1 del"}) {
		t.Fatalf("commands %q", sys.commands)
	}
	if read(t, path) != installerFile {
		t.Fatalf("left\n%s", read(t, path))
	}
	sys.commands = nil
	s.Rollback("admin")
	if !slices.Equal(sys.commands, []string{"create pppoe client eth0.100 host-uniq 1 name pppoe0 username u@isp password s3cret use-peer-dns add-default-route4"}) {
		t.Fatalf("undo %q", sys.commands)
	}
}

func TestParsePPPoEStatus(t *testing.T) {
	clients := parsePPPoEClients("[0] sw-if-index 2 host-uniq 1 pppox-sw-if-index 6 state PPPOE_CLIENT_SESSION session-id 7 ac-mac-address 02:00:00:00:00:09\n" +
		"[1] sw-if-index 5 host-uniq 2 pppox-sw-if-index 8 state PPPOE_CLIENT_DISCOVERY session-id 0 ac-mac-address 00:00:00:00:00:00\n")
	if c := clients[6]; c == nil || c.State != "session" || c.Session != 7 || c.ACMAC != "02:00:00:00:00:09" {
		t.Fatalf("client 6 %+v", c)
	}
	c := clients[8]
	if c == nil || c.State != "discovery" || c.ACMAC != "" {
		t.Fatalf("client 8 %+v", c)
	}
	parsePPPoEDebug("[1] access-interface eth1 host-uniq 2\n    pppoe state PPPOE_CLIENT_DISCOVERY session-id 0 pppox-sw-if-index 8\n    reconnects 3 last-disconnect auth-fail next-discovery 25.0s\n    auth-failures 2\n", c)
	if c.Reconnects != 3 || c.Last != "auth-fail" || c.AuthFails != 2 {
		t.Fatalf("debug %+v", c)
	}
}
