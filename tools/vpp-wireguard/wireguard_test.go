package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeSystem struct {
	commands   []string
	peers      string
	peersOnAdd string
	cliFail    string
	ifaces     string
	taps       string
	ifacesErr  error
	unitOff    bool
	nftBatches []string
	nftErr     error
	addrs      string
	ipCommands []string
	ipFail     string
}

func (f *fakeSystem) ip(args ...string) error {
	command := strings.Join(args, " ")
	f.ipCommands = append(f.ipCommands, command)
	if f.ipFail != "" && strings.HasPrefix(command, f.ipFail) {
		return errors.New("rejected")
	}
	return nil
}

func (f *fakeSystem) nft(batch string) error {
	f.nftBatches = append(f.nftBatches, batch)
	return f.nftErr
}

func (f *fakeSystem) unitActive(string) bool { return !f.unitOff }

func (f *fakeSystem) vppCLI(command string) (string, error) {
	f.commands = append(f.commands, command)
	if strings.HasPrefix(command, "wireguard peer add") {
		f.peers = f.peersOnAdd
	}
	if command == "show wireguard peer" {
		return f.peers, nil
	}
	if command == "show interface" {
		return f.ifaces, f.ifacesErr
	}
	if command == "show tap" {
		return f.taps, nil
	}
	if command == "show interface address" {
		return f.addrs, nil
	}
	if f.cliFail != "" && strings.HasPrefix(command, f.cliFail) {
		return "", errors.New("rejected")
	}
	return "", nil
}

const (
	wgClientKey   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	wgUpstreamKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
	wgNewKey      = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="
	wg0Line       = "wg0                               11     up          1420/0/0/0\n"
)

type fixture struct {
	dir, namesFile string
	sys            *fakeSystem
	admin          *Service
	opts           Options
}

// newFixture has wg0 running, with a client and an upstream peer.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{dir: dir, namesFile: filepath.Join(dir, "config", "names.json"), sys: &fakeSystem{ifaces: wg0Line, taps: "Interface: tap0 (ifindex 3)\n  name \"vpp-host\"\n", addrs: testVPPAddrs}}
	gateFile := filepath.Join(dir, "egress-gate.json")
	if err := os.WriteFile(gateFile, []byte(`{"listen":[["10.61.20.2",1053],["fd00::2",1053]],"hijack_dns":true,"hijack_interfaces":["vpp-host"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f.opts = Options{ConfigDir: filepath.Join(dir, "config"), Names: f.namesFile, GateConfig: gateFile}
	admin, err := NewService(f.opts, f.sys)
	if err != nil {
		t.Fatal(err)
	}
	f.admin = admin
	err = admin.saveWGStore(&wgStore{Configs: []*wgStored{{
		Name: "boot", Instance: 0, Enabled: true, PrivateKey: wgPrivateKey, Source: "10.61.10.2", ListenPort: 51820, MTU: 1420,
		Addresses: []string{"10.0.0.1/24", "fd42:1111:2222:90::1/64"},
		Peers: []wgStoredPeer{
			{PublicKey: wgClientKey, AllowedIPs: []string{"10.0.0.2/32", "fd42:1111:2222:90::2/128"}},
			{PublicKey: wgUpstreamKey, AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: "1.2.3.4", Port: 51820, Keepalive: 25},
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) store(t *testing.T) *wgStore {
	t.Helper()
	store, err := f.admin.loadWGStore()
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStateListsClientsAndHidesSecrets(t *testing.T) {
	f := newFixture(t)
	state, err := f.admin.WireGuard()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(state)
	if strings.Contains(string(data), wgPrivateKey) {
		t.Fatalf("private key reached the reply: %s", data)
	}
	if len(state.Peers) != 1 || state.Peers[0].PublicKey != wgClientKey {
		t.Fatalf("the upstream peer must not be listed: %+v", state.Peers)
	}
}

func TestAddPeerOnARunningConfig(t *testing.T) {
	f := newFixture(t)
	if _, err := f.admin.AddWireGuardPeer("wg0", wgNewKey, " 手机 ", []string{"10.0.0.3", "fd42:1111:2222:90::3/128"}, "admin"); err != nil {
		t.Fatal(err)
	}
	peerLine := "wireguard peer add wg0 public-key " + wgNewKey + " endpoint 0.0.0.0 dst-port 0 allowed-ip 10.0.0.3/32 allowed-ip fd42:1111:2222:90::3/128 persistent-keepalive 0"
	want := peerLine + "\nip route add 10.0.0.3/32 via 10.0.0.3 wg0\nip route add fd42:1111:2222:90::3/128 via fd42:1111:2222:90::3 wg0"
	if got := strings.Join(onlyChanges(f.sys.commands), "\n"); got != want {
		t.Fatalf("commands:\n%s", got)
	}
	if peers := f.store(t).Configs[0].Peers; len(peers) != 3 || peers[2].PublicKey != wgNewKey {
		t.Fatalf("%+v", peers)
	}
	names, _ := os.ReadFile(f.namesFile)
	if !strings.Contains(string(names), "手机") {
		t.Fatalf("names: %s", names)
	}
}

func TestAddPeerRefusals(t *testing.T) {
	f := newFixture(t)
	for name, attempt := range map[string]struct {
		iface, key string
		addresses  []string
	}{
		"key":       {"wg0", "not a key\nip route del 0.0.0.0/0", []string{"10.0.0.3"}},
		"short key": {"wg0", "AAAA", []string{"10.0.0.3"}},
		"interface": {"wg1", wgNewKey, []string{"10.0.0.3"}},
		"injection": {"wg0", wgNewKey, []string{"10.0.0.3 allowed-ip 0.0.0.0/0"}},
		"duplicate": {"wg0", wgClientKey, []string{"10.0.0.3"}},
		"none":      {"wg0", wgNewKey, nil},
		"wide":      {"wg0", wgNewKey, []string{"10.0.0.0/24"}},
		"default":   {"wg0", wgNewKey, []string{"0.0.0.0/0"}},
		"outside":   {"wg0", wgNewKey, []string{"10.61.70.5"}},
		"router":    {"wg0", wgNewKey, []string{"10.0.0.1"}},
		"taken":     {"wg0", wgNewKey, []string{"10.0.0.2"}},
		"taken v6":  {"wg0", wgNewKey, []string{"fd42:1111:2222:90::2"}},
		"repeated":  {"wg0", wgNewKey, []string{"10.0.0.3", "10.0.0.3/32"}},
	} {
		if _, err := f.admin.AddWireGuardPeer(attempt.iface, attempt.key, "", attempt.addresses, "admin"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(onlyChanges(f.sys.commands)) != 0 {
		t.Errorf("a refused peer reached VPP: %v", f.sys.commands)
	}
	if len(f.store(t).Configs[0].Peers) != 2 {
		t.Fatal("a refused peer was stored")
	}
}

func TestAddPeerUndoesWhenVPPRefusesTheRoute(t *testing.T) {
	f := newFixture(t)
	f.sys.cliFail = "ip route add"
	f.sys.peersOnAdd = "[7] endpoint:[0.0.0.0:0->0.0.0.0:0] wg0 keep-alive:0\n  key:" + wgNewKey + "\n  allowed-ips:\n"
	if _, err := f.admin.AddWireGuardPeer("wg0", wgNewKey, "", []string{"10.0.0.3"}, "admin"); err == nil {
		t.Fatal("accepted")
	}
	if !strings.Contains(strings.Join(f.sys.commands, "\n"), "wireguard peer remove 7") {
		t.Fatalf("not undone:\n%s", strings.Join(f.sys.commands, "\n"))
	}
	if len(f.store(t).Configs[0].Peers) != 2 {
		t.Fatal("stored")
	}
}

func TestDeletePeer(t *testing.T) {
	f := newFixture(t)
	os.WriteFile(f.namesFile, []byte(`{"`+wgClientKey+`":"phone","other":"laptop"}`), 0o600)
	f.sys.peers = "[0] endpoint:[0.0.0.0:0->0.0.0.0:0] wg0 keep-alive:0\n  key:" + wgUpstreamKey + "\n[3] endpoint:[0.0.0.0:0->0.0.0.0:0] wg0 keep-alive:0\n  key:" + wgClientKey + "\n  allowed-ips:\n"
	state, err := f.admin.DeleteWireGuardPeer("wg0", wgClientKey, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Peers) != 0 {
		t.Fatalf("still listed: %+v", state.Peers)
	}
	want := "wireguard peer remove 3\nip route del 10.0.0.2/32 via 10.0.0.2 wg0\nip route del fd42:1111:2222:90::2/128 via fd42:1111:2222:90::2 wg0"
	if got := strings.Join(onlyChanges(f.sys.commands), "\n"); got != want {
		t.Fatalf("commands:\n%s", got)
	}
	names, _ := os.ReadFile(f.namesFile)
	if strings.Contains(string(names), wgClientKey) || !strings.Contains(string(names), "laptop") {
		t.Fatalf("names: %s", names)
	}
}

func TestDeletePeerRefusesUpstreamAndUnknown(t *testing.T) {
	f := newFixture(t)
	for _, key := range []string{wgUpstreamKey, wgNewKey} {
		if _, err := f.admin.DeleteWireGuardPeer("wg0", key, "admin"); err == nil {
			t.Errorf("%s: deleted", key)
		}
	}
	if len(onlyChanges(f.sys.commands)) != 0 {
		t.Fatalf("reached VPP: %v", f.sys.commands)
	}
}

func TestDeletePeerKeepsItWhenVPPRefuses(t *testing.T) {
	f := newFixture(t)
	f.sys.peers = "[3] endpoint:[0.0.0.0:0->0.0.0.0:0] wg0 keep-alive:0\n  key:" + wgClientKey + "\n"
	f.sys.cliFail = "wireguard peer remove"
	if _, err := f.admin.DeleteWireGuardPeer("wg0", wgClientKey, "admin"); err == nil {
		t.Fatal("deleted")
	}
	if len(f.store(t).Configs[0].Peers) != 2 {
		t.Fatal("the peer left the store although VPP kept it")
	}
}

const (
	wgPrivateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	wgPSK        = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDA="
)

var wgConf = `# a comment
[Interface]
PrivateKey = ` + wgPrivateKey + `
Address = 10.9.0.1/24, fd09::1/64
ListenPort = 51900
MTU = 1400
DNS = 1.1.1.1
PostUp = rm -rf /

[Peer]
PublicKey = ` + wgNewKey + `
PresharedKey = ` + wgPSK + `
AllowedIPs = 10.9.0.2/32, 192.168.77.0/24
Endpoint = 1.2.3.4:51821
PersistentKeepalive = 25

[Peer]
PublicKey = EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA=
AllowedIPs = 0.0.0.0/0
`

func addWGConfig(t *testing.T, f *fixture) WireGuardConfig {
	t.Helper()
	state, err := f.admin.AddWireGuardConfig("home", "10.61.10.2", wgConf, "", "", "", false, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return state.Configs[len(state.Configs)-1]
}

func wgStartCommands() []string {
	return []string{
		"wireguard create instance 100 listen-port 51900 private-key " + wgPrivateKey + " src 10.61.10.2",
		"set interface mtu packet 1400 wg100",
		"set interface ip address wg100 10.9.0.1/24",
		"set interface ip address wg100 fd09::1/64",
		"wireguard peer add wg100 public-key " + wgNewKey + " preshared-key " + wgPSK + " endpoint 1.2.3.4 dst-port 51821 allowed-ip 10.9.0.2/32 allowed-ip 192.168.77.0/24 persistent-keepalive 25",
		"ip route add 10.9.0.2/32 via 10.9.0.2 wg100",
		"wireguard peer add wg100 public-key EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA= endpoint 0.0.0.0 dst-port 0 allowed-ip 0.0.0.0/0 persistent-keepalive 0",
		"set interface state wg100 up",
	}
}

func onlyChanges(commands []string) []string {
	var kept []string
	for _, command := range commands {
		if !strings.HasPrefix(command, "show ") {
			kept = append(kept, command)
		}
	}
	return kept
}

func TestWireGuardConfigIsStoredStoppedAndHidesSecrets(t *testing.T) {
	f := newFixture(t)
	config := addWGConfig(t, f)
	if config.Interface != "wg100" || config.Enabled || config.Running || config.Peers != 2 || config.ListenPort != 51900 {
		t.Fatalf("%+v", config)
	}
	if len(config.PublicKey) != 44 || config.PublicKey == wgPrivateKey {
		t.Fatalf("public key %q", config.PublicKey)
	}
	if len(onlyChanges(f.sys.commands)) != 0 {
		t.Fatalf("saving reached VPP: %v", f.sys.commands)
	}
	w := httptest.NewRecorder()
	f.admin.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/wireguard", nil))
	if body := w.Body.String(); strings.Contains(body, wgPrivateKey) || strings.Contains(body, wgPSK) || !strings.Contains(body, "wg100") {
		t.Fatalf("reply: %s", body)
	}
	info, err := os.Stat(filepath.Join(f.opts.ConfigDir, wgStoreFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("store: %v %v", info, err)
	}
	if !strings.Contains(w.Body.String(), `"default_source":"10.61.10.2"`) {
		t.Fatalf("no default source: %s", w.Body.String())
	}
}

func TestWireGuardConfigRefusalsDoNotQuoteTheConfig(t *testing.T) {
	f := newFixture(t)
	valid := "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.9.0.1/24\n[Peer]\nPublicKey = " + wgNewKey + "\nAllowedIPs = 10.9.0.2/32\n"
	for name, text := range map[string]string{
		"empty":        "",
		"no interface": "[Peer]\nPublicKey = " + wgNewKey + "\nAllowedIPs = 10.9.0.2/32\n",
		"bad key":      strings.Replace(valid, wgPrivateKey, "SECRETSECRET", 1),
		"no peer":      "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.9.0.1/24\n",
		"no address":   strings.Replace(valid, "Address = 10.9.0.1/24\n", "", 1),
		"unknown":      valid + "Mystery = SECRETSECRET\n",
		"garbage":      valid + "SECRETSECRET\n",
		"no allowed":   strings.Replace(valid, "AllowedIPs = 10.9.0.2/32\n", "", 1),
		"bad port":     strings.Replace(valid, "Address", "ListenPort = 0\nAddress", 1),
		"duplicate":    valid + "[Peer]\nPublicKey = " + wgNewKey + "\nAllowedIPs = 10.9.0.3/32\n",
		"v6 endpoint":  valid + "Endpoint = [fd00::1]:51820\n",
	} {
		_, err := f.admin.AddWireGuardConfig(name, "10.61.10.2", text, "", "", "", false, "admin")
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "SECRETSECRET") || strings.Contains(err.Error(), wgPrivateKey) {
			t.Errorf("%s quoted the configuration: %v", name, err)
		}
	}
	if _, err := f.admin.AddWireGuardConfig("x", "not an address", valid, "", "", "", false, "admin"); err == nil {
		t.Error("a bad source was accepted")
	}
	if _, err := f.admin.AddWireGuardConfig("", "10.61.10.2", valid, "", "", "", false, "admin"); err == nil {
		t.Error("an empty name was accepted")
	}
	state, _ := f.admin.WireGuard()
	if len(state.Configs) != 1 {
		t.Fatalf("stored: %+v", state.Configs)
	}
}

// What the WireGuard apps and VPN providers export: a byte order mark, CRLF, repeated
// Address and AllowedIPs lines, bare addresses, DNS and no ListenPort.
func TestWireGuardConfigReadsExportedFiles(t *testing.T) {
	text := "\ufeff# exported\r\n[Interface]\r\nPrivateKey = " + wgPrivateKey + "\r\nAddress = 10.66.0.2\r\nAddress = fd66::2/128\r\n" +
		"DNS = 10.66.0.1\r\nDNS = fd66::1\r\nMTU = 1380\r\nPostUp = echo SECRETSECRET\r\nPostUp = true\r\n\r\n[Peer]\r\nPublicKey = " + wgNewKey +
		"\r\nPresharedKey = " + wgPSK + "\r\nAllowedIPs = 0.0.0.0/0\r\nAllowedIPs = ::/0, 10.66.0.1 # gateway\r\nEndpoint = 1.2.3.4:51820\r\nPersistentKeepalive = 25\r\n"
	stored, peers, err := parseWireGuardConf(text)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(stored.Addresses, " "); got != "10.66.0.2/32 fd66::2/128" {
		t.Errorf("addresses: %s", got)
	}
	if stored.MTU != 1380 || stored.ListenPort != 0 || len(peers) != 1 {
		t.Errorf("parsed: %+v %d peers", stored, len(peers))
	}
	if got := strings.Join(peers[0].AllowedIPs, " "); got != "0.0.0.0/0 ::/0 10.66.0.1/32" {
		t.Errorf("allowed: %s", got)
	}
	if peers[0].host != "1.2.3.4" || peers[0].Port != 51820 || peers[0].Keepalive != 25 || peers[0].PresharedKey != wgPSK {
		t.Errorf("peer: %+v", peers[0])
	}
	for name, bad := range map[string]string{
		"repeated key":  strings.Replace(text, "MTU = 1380", "PrivateKey = "+wgPrivateKey, 1),
		"repeated peer": strings.Replace(text, "PersistentKeepalive = 25", "PublicKey = "+wgNewKey, 1),
		"zoned address": strings.Replace(text, "10.66.0.2", "fe80::1%eth0", 1),
	} {
		if _, _, err := parseWireGuardConf(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWireGuardConfigChoosesFreeInstanceAndPort(t *testing.T) {
	f := newFixture(t)
	text := "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.9.0.1/24\n[Peer]\nPublicKey = " + wgNewKey + "\nAllowedIPs = 10.9.0.2/32\n"
	first, err := f.admin.AddWireGuardConfig("a", "10.61.10.2", text, "", "", "", false, "admin")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.admin.AddWireGuardConfig("b", "10.61.10.2", text, "", "", "", false, "admin")
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.Configs[1], second.Configs[2]
	if a.Interface != "wg100" || b.Interface != "wg101" || a.ListenPort == b.ListenPort || a.ListenPort != 51821 {
		t.Fatalf("%+v %+v", a, b)
	}
	if _, err := f.admin.AddWireGuardConfig("a", "10.61.10.2", text, "", "", "", false, "admin"); err == nil {
		t.Fatal("a repeated name was accepted")
	}
}

func TestWireGuardConfigStartAndStop(t *testing.T) {
	f := newFixture(t)
	f.admin.opts.NATInterface = "eth0"
	addWGConfig(t, f)
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	want := wgStartCommands()
	want = append(want[:len(want)-1], "nat44 ei add identity mapping external eth0 udp 51900", want[len(want)-1])
	if got := onlyChanges(f.sys.commands); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	for _, command := range onlyChanges(f.sys.commands) {
		if strings.Contains(command, "ip route") && strings.Contains(command, "0.0.0.0/0") {
			t.Fatalf("a default route reached the FIB: %s", command)
		}
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1400/0/0/0\n"
	state, _ := f.admin.WireGuard()
	if !state.Configs[1].Enabled || !state.Configs[1].Running {
		t.Fatalf("%+v", state.Configs[1])
	}
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err == nil {
		t.Fatal("started twice")
	}
	f.sys.commands = nil
	if _, err := f.admin.StopWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	wantStop := "nat44 ei add identity mapping external eth0 udp 51900 del\nip route del 10.9.0.2/32 via 10.9.0.2 wg100\nwireguard delete wg100"
	if got := strings.Join(onlyChanges(f.sys.commands), "\n"); got != wantStop {
		t.Fatalf("commands:\n%s", got)
	}
	f.sys.ifaces = wg0Line
	state, _ = f.admin.WireGuard()
	if state.Configs[1].Enabled || state.Configs[1].Running {
		t.Fatalf("%+v", state.Configs[1])
	}
}

func TestStopRemovesAllInterfacePeersBeforeDeletingInterface(t *testing.T) {
	f := newFixture(t)
	addWGConfig(t, f)
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.ifaces += "wg100 12 up 1400/0/0/0\n"
	// Enough peers to exercise the multi-peer case, including another interface
	// using the same key. The snapshot must target only this interface.
	f.sys.peers = "[90] endpoint:[x] wg1000 keep-alive:0\n  public key:" + wgNewKey + "\n"
	for i := 0; i < 28; i++ {
		f.sys.peers += fmt.Sprintf("[%d] endpoint:[x] wg100 keep-alive:25\n  public key:%s\n", i, wgNewKey)
	}
	f.sys.commands = nil
	if _, err := f.admin.StopWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	changes := onlyChanges(f.sys.commands)
	for i := 0; i < 28; i++ {
		if changes[i] != fmt.Sprintf("wireguard peer remove %d", i) {
			t.Fatalf("peer %d was not removed before deletion: %v", i, changes)
		}
	}
	if changes[len(changes)-1] != "wireguard delete wg100" || len(changes) != 30 {
		t.Fatalf("unexpected cleanup: %v", changes)
	}
	f.sys.ifaces, f.sys.peers = wg0Line, ""
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatalf("restart failed: %v", err)
	}
}

func TestStopKeepsInterfaceAndEnabledStateWhenPeerRemovalFails(t *testing.T) {
	f := newFixture(t)
	addWGConfig(t, f)
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.ifaces += "wg100 12 up 1400/0/0/0\n"
	f.sys.peers = "[21] endpoint:[x] wg100 keep-alive:25\n"
	f.sys.cliFail, f.sys.commands = "wireguard peer remove", nil
	if _, err := f.admin.StopWireGuardConfig("wg100", "admin"); err == nil {
		t.Fatal("stop succeeded despite failed peer removal")
	}
	for _, command := range f.sys.commands {
		if command == "wireguard delete wg100" {
			t.Fatal("deleted interface with remaining peers")
		}
	}
	store, _ := f.admin.loadWGStore()
	if !wgFindConfig(store, "wg100").Enabled {
		t.Fatal("failed stop disabled configuration")
	}
}

func TestUpdateWireGuardSource(t *testing.T) {
	f := newFixture(t)
	addWGConfig(t, f)
	request := httptest.NewRequest("POST", "/wireguard/config/source", strings.NewReader(`{"interface":"wg100","source":"10.61.10.3"}`))
	response := httptest.NewRecorder()
	f.admin.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update: %d %s", response.Code, response.Body)
	}
	store, _ := f.admin.loadWGStore()
	c := wgFindConfig(store, "wg100")
	if c.Source != "10.61.10.3" || c.PrivateKey != wgPrivateKey || len(c.Peers) != 2 || c.Enabled {
		t.Fatal("source update changed other configuration")
	}
	for _, source := range []string{"bad", "0.0.0.0", "::", "2001:db8::1"} {
		if _, err := f.admin.UpdateWireGuardSource("wg100", source, "admin"); err == nil {
			t.Errorf("accepted invalid or mismatched source %q", source)
		}
	}
	if _, err := f.admin.UpdateWireGuardSource("wg999", "10.61.10.3", "admin"); err == nil {
		t.Fatal("updated missing configuration")
	}
	f.sys.commands = nil
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(onlyChanges(f.sys.commands)[0], "src 10.61.10.3") {
		t.Fatal("start did not use saved source")
	}
	if _, err := f.admin.UpdateWireGuardSource("wg100", "10.61.10.4", "admin"); err == nil {
		t.Fatal("updated enabled configuration")
	}
}

func TestWireGuardConfigStartUndoesAndStaysStopped(t *testing.T) {
	f := newFixture(t)
	addWGConfig(t, f)
	f.sys.cliFail = "ip route add"
	_, err := f.admin.StartWireGuardConfig("wg100", "admin")
	if err == nil {
		t.Fatal("started")
	}
	if strings.Contains(err.Error(), wgPrivateKey) {
		t.Fatalf("the error quoted the key: %v", err)
	}
	if !strings.Contains(strings.Join(f.sys.commands, "\n"), "wireguard delete wg100") {
		t.Fatalf("not undone:\n%s", strings.Join(f.sys.commands, "\n"))
	}
	state, _ := f.admin.WireGuard()
	if state.Configs[1].Enabled {
		t.Fatal("a failed start was remembered")
	}
}

func TestWireGuardConfigConflictsAreRefusedBeforeVPP(t *testing.T) {
	f := newFixture(t)
	for name, text := range map[string]string{
		"address": "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.0.0.9/24\n[Peer]\nPublicKey = " + wgNewKey + "\nAllowedIPs = 10.0.0.2/32\n",
	} {
		state, err := f.admin.AddWireGuardConfig(name, "10.61.10.2", text, "", "", "", false, "admin")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		f.sys.commands = nil
		if _, err := f.admin.StartWireGuardConfig(state.Configs[len(state.Configs)-1].Interface, "admin"); err == nil {
			t.Errorf("%s: started", name)
		}
		if len(onlyChanges(f.sys.commands)) != 0 {
			t.Errorf("%s reached VPP: %v", name, f.sys.commands)
		}
	}
	if _, err := f.admin.AddWireGuardConfig("port", "10.61.10.2", strings.Replace(wgConf, "ListenPort = 51900", "ListenPort = 51820", 1), "", "", "", false, "admin"); err == nil {
		t.Error("a port in use by a startup file was accepted")
	}
}

func TestWireGuardConfigDeleteStopsAndForgets(t *testing.T) {
	f := newFixture(t)
	namesFile := f.namesFile
	os.WriteFile(namesFile, []byte(`{"`+wgNewKey+`":"phone","other":"laptop"}`), 0o600)
	addWGConfig(t, f)
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1400/0/0/0\n"
	f.sys.commands = nil
	state, err := f.admin.DeleteWireGuardConfig("wg100", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Configs) != 1 || !strings.Contains(strings.Join(f.sys.commands, "\n"), "wireguard delete wg100") {
		t.Fatalf("%+v %v", state.Configs, f.sys.commands)
	}
	stored := f.store(t)
	if len(stored.Configs) != 1 || stored.Configs[0].Instance != 0 {
		t.Fatalf("the configuration stayed on disk: %+v", stored.Configs)
	}
	names, _ := os.ReadFile(namesFile)
	if strings.Contains(string(names), wgNewKey) || !strings.Contains(string(names), "laptop") {
		t.Fatalf("names: %s", names)
	}
}

func TestWireGuardRestoreWaitsForVPPThenOncePerRun(t *testing.T) {
	f := newFixture(t)
	addWGConfig(t, f)
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	started := time.Unix(5000, 0)
	stamp := fileStamp{Ino: 7, Ctime: started.UnixNano()}
	f.admin.stamp = func(string) (fileStamp, error) { return stamp, nil }

	f.sys.commands = nil
	f.admin.wireGuardTick(started.Add(wgSettle - time.Second))
	if len(f.sys.commands) != 0 {
		t.Fatalf("too early: %v", f.sys.commands)
	}
	f.admin.wireGuardTick(started.Add(wgSettle))
	if got, want := onlyChanges(f.sys.commands), wgStartCommands(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	f.sys.commands = nil
	f.admin.wireGuardTick(started.Add(wgSettle + time.Hour))
	if len(f.sys.commands) != 0 {
		t.Fatalf("VPP was asked again in the same run: %v", f.sys.commands)
	}

	// A new run: a failed restore is retried, and is visible until it works.
	restarted := started.Add(2 * time.Hour)
	stamp = fileStamp{Ino: 8, Ctime: restarted.UnixNano()}
	f.sys.cliFail = "wireguard create"
	f.admin.wireGuardTick(restarted.Add(wgSettle))
	state, _ := f.admin.WireGuard()
	if state.Configs[1].Error == "" || !state.Configs[1].Enabled || state.Configs[1].Running {
		t.Fatalf("%+v", state.Configs[1])
	}
	if strings.Contains(state.Configs[1].Error, wgPrivateKey) {
		t.Fatalf("the error quoted the key: %s", state.Configs[1].Error)
	}
	f.sys.cliFail, f.sys.commands = "", nil
	f.admin.wireGuardTick(restarted.Add(wgSettle + time.Second))
	if len(onlyChanges(f.sys.commands)) != 0 {
		t.Fatalf("retried too soon: %v", f.sys.commands)
	}
	f.admin.wireGuardTick(restarted.Add(wgSettle + wgRetryEvery))
	if len(onlyChanges(f.sys.commands)) == 0 {
		t.Fatal("not retried")
	}
	state, _ = f.admin.WireGuard()
	if state.Configs[1].Error != "" {
		t.Fatalf("error stayed: %s", state.Configs[1].Error)
	}
}

func TestWireGuardRestoreSkipsWhatVPPHasAndWhatIsStopped(t *testing.T) {
	f := newFixture(t)
	addWGConfig(t, f)
	if !f.admin.reconcileWireGuard() {
		t.Fatal("nothing started, nothing to do")
	}
	if len(onlyChanges(f.sys.commands)) != 0 {
		t.Fatalf("a stopped configuration reached VPP: %v", f.sys.commands)
	}
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1400/0/0/0\n"
	f.sys.commands = nil
	if !f.admin.reconcileWireGuard() || len(onlyChanges(f.sys.commands)) != 0 {
		t.Fatalf("recreated: %v", f.sys.commands)
	}
}

func TestStoredConfigPeersFollowTheConfig(t *testing.T) {
	f := newFixture(t)
	addWGConfig(t, f)
	key := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA="

	// Stopped: only stored.
	if _, err := f.admin.AddWireGuardPeer("wg100", key, "", []string{"10.9.0.3"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(onlyChanges(f.sys.commands)) != 0 {
		t.Fatalf("a stopped configuration reached VPP: %v", f.sys.commands)
	}
	if _, err := f.admin.DeleteWireGuardPeer("wg100", key, "admin"); err != nil {
		t.Fatal(err)
	}

	// Running: VPP too.
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1400/0/0/0\n"
	f.sys.commands = nil
	if _, err := f.admin.AddWireGuardPeer("wg100", key, "", []string{"10.9.0.3"}, "admin"); err != nil {
		t.Fatal(err)
	}
	want := "wireguard peer add wg100 public-key " + key + " endpoint 0.0.0.0 dst-port 0 allowed-ip 10.9.0.3/32 persistent-keepalive 0\nip route add 10.9.0.3/32 via 10.9.0.3 wg100"
	if got := strings.Join(onlyChanges(f.sys.commands), "\n"); got != want {
		t.Fatalf("commands:\n%s", got)
	}
	f.sys.commands = nil
	f.sys.peers = "[4] endpoint:[0.0.0.0:0->0.0.0.0:0] wg100 keep-alive:0\n  public key:" + key + " x\n"
	if _, err := f.admin.DeleteWireGuardPeer("wg100", key, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(onlyChanges(f.sys.commands), "\n"); got != "wireguard peer remove 4\nip route del 10.9.0.3/32 via 10.9.0.3 wg100" {
		t.Fatalf("commands:\n%s", got)
	}
}

func TestWireGuardEndpointNameIsResolvedInTheTunnelFamily(t *testing.T) {
	f := newFixture(t)
	var asked string
	f.admin.lookup = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		asked = network + " " + host
		return []netip.Addr{netip.MustParseAddr("5.6.7.8")}, nil
	}
	text := strings.Replace(wgConf, "1.2.3.4:51821", "vpn.example.com:51821", 1)
	if _, err := f.admin.AddWireGuardConfig("named", "10.61.10.2", text, "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if asked != "ip4 vpn.example.com" {
		t.Fatalf("asked %q", asked)
	}
	store, _ := f.admin.loadWGStore()
	if store.Configs[1].Peers[0].Endpoint != "5.6.7.8" {
		t.Fatalf("%+v", store.Configs[1].Peers[0])
	}
}

func TestCommandsRunAfterUpAndBeforeDown(t *testing.T) {
	f := newFixture(t)
	if _, err := f.admin.AddWireGuardConfig("home", "10.61.10.2", wgConf, "# comment\nset interface nat66 in wg100\n\nip punt redirect rx wg100 via 10.61.20.2 loop200\n", "set interface nat66 in wg100 del\n", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	want := append(wgStartCommands(), "set interface nat66 in wg100", "ip punt redirect rx wg100 via 10.61.20.2 loop200")
	if got := onlyChanges(f.sys.commands); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1400/0/0/0\n"
	f.sys.commands = nil
	if _, err := f.admin.StopWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	got := onlyChanges(f.sys.commands)
	if len(got) == 0 || got[0] != "set interface nat66 in wg100 del" || got[len(got)-1] != "wireguard delete wg100" {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
}

func TestACommandThatFailsUndoesTheStart(t *testing.T) {
	f := newFixture(t)
	if _, err := f.admin.AddWireGuardConfig("home", "10.61.10.2", wgConf, "abf attach ip4 policy 620 wg100", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.cliFail = "abf attach"
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err == nil {
		t.Fatal("started")
	}
	if !strings.Contains(strings.Join(f.sys.commands, "\n"), "wireguard delete wg100") {
		t.Fatalf("not undone:\n%s", strings.Join(f.sys.commands, "\n"))
	}
}

func TestCommandsAreVPPOnly(t *testing.T) {
	for _, text := range []string{"exec /tmp/x", "unix cli-listen /tmp/y", strings.Repeat("x", wgCommandLength+1), strings.Repeat("show version\n", wgCommandLimit+1)} {
		if _, err := cleanCommands(text); err == nil {
			t.Errorf("accepted %.20q", text)
		}
	}
}

func TestRestoreWaitsForTheUnitNamed(t *testing.T) {
	f := newFixture(t)
	f.admin.opts.VPPUnit = "vpp.service"
	addWGConfig(t, f)
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(5000, 0)
	f.admin.stamp = func(string) (fileStamp, error) { return fileStamp{Ino: 7, Ctime: now.UnixNano()}, nil }
	f.sys.unitOff, f.sys.commands = true, nil
	f.admin.wireGuardTick(now.Add(time.Hour))
	if len(f.sys.commands) != 0 {
		t.Fatalf("restored before the unit was active: %v", f.sys.commands)
	}
	f.sys.unitOff = false
	f.admin.wireGuardTick(now.Add(time.Second)) // well inside the fixed wait
	if got := onlyChanges(f.sys.commands); len(got) == 0 || !strings.HasPrefix(got[0], "wireguard create instance 100") {
		t.Fatalf("commands: %v", got)
	}
}

func vppFile(extra string) string {
	return "wireguard create instance 8 listen-port 22222 private-key " + wgPrivateKey + " src 10.61.10.2\n" +
		"set interface mtu packet 1280 wg8\n" +
		"set interface ip address wg8 10.62.40.1/24\n" +
		"set interface ip address wg8 fd42:1111:2222:70::1/64\n" +
		"wireguard peer add wg8 public-key " + wgNewKey + " endpoint 0.0.0.0 dst-port 0 allowed-ip 10.62.40.2/32 allowed-ip fd42:1111:2222:70::2/128 persistent-keepalive 25\n" +
		"ip route add 10.62.40.2/32 via 10.62.40.2 wg8\n" +
		"ip route add fd42:1111:2222:70::2/128 via fd42:1111:2222:70::2 wg8\n" + extra +
		"set interface state wg8 up\n"
}

func TestImportKeepsTheInterfaceAndItsCommands(t *testing.T) {
	dir := t.TempDir()
	file, up, down := filepath.Join(dir, "sg.vpp"), filepath.Join(dir, "up"), filepath.Join(dir, "down")
	os.WriteFile(file, []byte("# generated\n"+vppFile("")), 0o600)
	os.WriteFile(up, []byte("abf attach ip4 policy 620 wg8\n"), 0o600)
	os.WriteFile(down, []byte("abf attach ip4 policy 620 wg8 del\n"), 0o600)
	config := filepath.Join(dir, "config")
	stored, err := importConfig(config, "sg", file, up, down, true)
	if err != nil {
		t.Fatal(err)
	}
	if stored.iface() != "wg8" || !stored.Enabled || !stored.SkipNATOpen || len(stored.AfterUp) != 1 || len(stored.BeforeDown) != 1 {
		t.Fatalf("%+v", stored)
	}
	f := &fixture{sys: &fakeSystem{ifaces: "wg8                               15     up          1280/0/0/0\n"}}
	f.opts = Options{ConfigDir: config, NATInterface: "eth0"}
	service, err := NewService(f.opts, f.sys)
	if err != nil {
		t.Fatal(err)
	}
	if !service.reconcileWireGuard() || len(onlyChanges(f.sys.commands)) != 0 {
		t.Fatalf("a live imported interface was touched: %v", f.sys.commands)
	}
	f.sys.ifaces = ""
	if !service.reconcileWireGuard() {
		t.Fatal("restore failed")
	}
	got := strings.Join(onlyChanges(f.sys.commands), "\n")
	if !strings.HasPrefix(got+"\n", strings.TrimRight(vppFile(""), "")) || strings.Contains(got, "nat44") || !strings.HasSuffix(got, "abf attach ip4 policy 620 wg8") {
		t.Fatalf("restore differs from the file:\n%s", got)
	}
	data, _ := os.ReadFile(filepath.Join(config, wgStoreFile))
	if !strings.Contains(string(data), wgPrivateKey) {
		t.Fatal("the key was not stored")
	}
}

func TestImportRefusesWhatItCannotExpress(t *testing.T) {
	for name, text := range map[string]string{
		"extra line": vppFile("ip route add 192.168.50.0/24 via 192.168.50.1 wg8\n"),
		"changed":    strings.Replace(vppFile(""), "ip route add 10.62.40.2/32 via 10.62.40.2", "ip route add 10.62.40.2/32 via 10.62.40.9", 1),
		"empty":      "set interface state wg8 up\n",
		"bad key":    strings.Replace(vppFile(""), wgPrivateKey, "SECRETSECRET", 1),
	} {
		dir := t.TempDir()
		file := filepath.Join(dir, "x.vpp")
		os.WriteFile(file, []byte(text), 0o600)
		_, err := importConfig(filepath.Join(dir, "c"), "x", file, "", "", true)
		if err == nil {
			t.Errorf("%s: imported", name)
		} else if strings.Contains(err.Error(), "SECRETSECRET") || strings.Contains(err.Error(), wgPrivateKey) {
			t.Errorf("%s quoted the file: %v", name, err)
		}
	}
}

func TestImportRefusesADuplicate(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "x.vpp")
	os.WriteFile(file, []byte(vppFile("")), 0o600)
	config := filepath.Join(dir, "c")
	if _, err := importConfig(config, "x", file, "", "", true); err != nil {
		t.Fatal(err)
	}
	if _, err := importConfig(config, "y", file, "", "", true); err == nil {
		t.Fatal("imported the same interface twice")
	}
}

// sharedKeyConf is a configuration with the same client as wg0, as a real router has.
func sharedKeyConf() string {
	return "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.8.0.1/24\nListenPort = 51900\n[Peer]\nPublicKey = " + wgClientKey + "\nAllowedIPs = 10.8.0.2/32\n"
}

func startSharedKey(t *testing.T, f *fixture) {
	t.Helper()
	if _, err := f.admin.AddWireGuardConfig("shared", "10.61.10.2", sharedKeyConf(), "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatalf("a key shared with another interface stopped the start: %v", err)
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1420/0/0/0\n"
	f.sys.commands = nil
}

const sharedPeers = "[0] endpoint:[0.0.0.0:0->0.0.0.0:0] wg0 keep-alive:0\n  public key:" + wgClientKey + " x\n" +
	"[9] endpoint:[0.0.0.0:0->0.0.0.0:0] wg100 keep-alive:0\n  public key:" + wgClientKey + " y\n"

func TestDeletingASharedKeyRemovesOnlyThatInterfacesPeer(t *testing.T) {
	f := newFixture(t)
	startSharedKey(t, f)
	f.sys.peers = sharedPeers
	if _, err := f.admin.DeleteWireGuardPeer("wg100", wgClientKey, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(onlyChanges(f.sys.commands), "\n"); !strings.HasPrefix(got, "wireguard peer remove 9\n") {
		t.Fatalf("commands:\n%s", got)
	}
	store := f.store(t)
	if len(store.Configs[0].Peers) != 2 || len(store.Configs[1].Peers) != 0 {
		t.Fatalf("%+v", store.Configs)
	}
}

func TestASharedKeysNameStaysUntilItsLastPeerGoes(t *testing.T) {
	f := newFixture(t)
	startSharedKey(t, f)
	os.WriteFile(f.namesFile, []byte(`{"`+wgClientKey+`":"phone"}`), 0o600)
	f.sys.peers = sharedPeers
	if _, err := f.admin.DeleteWireGuardPeer("wg100", wgClientKey, "admin"); err != nil {
		t.Fatal(err)
	}
	if names, _ := os.ReadFile(f.namesFile); !strings.Contains(string(names), "phone") {
		t.Fatalf("the name went while wg0 still has the peer: %s", names)
	}
	if _, err := f.admin.DeleteWireGuardPeer("wg0", wgClientKey, "admin"); err != nil {
		t.Fatal(err)
	}
	if names, _ := os.ReadFile(f.namesFile); strings.Contains(string(names), "phone") {
		t.Fatalf("the name outlived the last peer: %s", names)
	}
}

func TestAKeyMayBeAddedToASecondInterface(t *testing.T) {
	f := newFixture(t)
	if _, err := f.admin.AddWireGuardConfig("other", "10.61.10.2", strings.Replace(sharedKeyConf(), wgClientKey, wgUpstreamKey, 1), "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.AddWireGuardPeer("wg100", wgClientKey, "", []string{"10.8.0.9"}, "admin"); err != nil {
		t.Fatalf("a key on another interface was refused: %v", err)
	}
	if _, err := f.admin.AddWireGuardPeer("wg100", wgClientKey, "", []string{"10.8.0.10"}, "admin"); err == nil {
		t.Fatal("the same key was added twice to one interface")
	}
}

func TestImportAcceptsAKeySharedWithAnotherInterface(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "a.vpp"), filepath.Join(dir, "b.vpp")
	os.WriteFile(first, []byte(vppFile("")), 0o600)
	other := strings.NewReplacer("instance 8", "instance 9", "22222", "22223", "wg8", "wg9", "10.62.40.", "10.1.9.", "fd42:1111:2222:70::", "fc09::").Replace(vppFile(""))
	os.WriteFile(second, []byte(other), 0o600)
	config := filepath.Join(dir, "c")
	if _, err := importConfig(config, "a", first, "", "", true); err != nil {
		t.Fatal(err)
	}
	if _, err := importConfig(config, "b", second, "", "", true); err != nil {
		t.Fatalf("a shared key was refused: %v", err)
	}
}

func tableOffConf() string {
	return "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.9.0.1/24\nListenPort = 51900\nTable = off\n[Peer]\nPublicKey = " + wgNewKey + "\nAllowedIPs = 0.0.0.0/0, 10.9.0.2/32\nEndpoint = 1.2.3.4:51821\n"
}

func TestTableOffInstallsNoRoutes(t *testing.T) {
	f := newFixture(t)
	if _, err := f.admin.AddWireGuardConfig("exit", "10.61.10.2", tableOffConf(), "ip route add 172.16.0.0/16 via 10.9.0.2 wg100", "ip route del 172.16.0.0/16 via 10.9.0.2 wg100", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(onlyChanges(f.sys.commands), "\n")
	if !strings.Contains(got, "allowed-ip 0.0.0.0/0 allowed-ip 10.9.0.2/32") {
		t.Fatalf("the peer lost its AllowedIPs:\n%s", got)
	}
	if strings.Contains(strings.ReplaceAll(got, "ip route add 172.16.0.0/16 via 10.9.0.2 wg100", ""), "ip route") {
		t.Fatalf("Table = off still routed:\n%s", got)
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1420/0/0/0\n"
	f.sys.commands = nil
	if _, err := f.admin.StopWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(onlyChanges(f.sys.commands), "\n"); got != "ip route del 172.16.0.0/16 via 10.9.0.2 wg100\nwireguard delete wg100" {
		t.Fatalf("commands:\n%s", got)
	}
}

func TestTableOffPeerGetsNoRouteEither(t *testing.T) {
	f := newFixture(t)
	if _, err := f.admin.AddWireGuardConfig("exit", "10.61.10.2", tableOffConf(), "", "", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1420/0/0/0\n"
	f.sys.commands = nil
	key := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA="
	if _, err := f.admin.AddWireGuardPeer("wg100", key, "", []string{"10.9.0.3"}, "admin"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(onlyChanges(f.sys.commands), "\n")
	if strings.Contains(got, "ip route") || !strings.Contains(got, "allowed-ip 10.9.0.3/32") {
		t.Fatalf("commands:\n%s", got)
	}
}

func TestOtherTableValuesKeepTheDefaultRoutes(t *testing.T) {
	stored, _, err := parseWireGuardConf(strings.Replace(tableOffConf(), "Table = off", "Table = auto", 1))
	if err != nil || stored.NoRoutes {
		t.Fatalf("%v %+v", err, stored)
	}
}

func readExits(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestStartedConfigsAreOfferedAsExits(t *testing.T) {
	f := newFixture(t)
	f.admin.opts.ExitsFile = filepath.Join(f.dir, "run", "exits.json")
	if _, err := f.admin.AddWireGuardConfig("exit", "10.61.10.2", tableOffConf(), "", "", "10.9.0.2", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := readExits(t, f.admin.opts.ExitsFile); got != "[]" {
		t.Fatalf("offered before it started: %s", got)
	}
	if _, err := f.admin.StartWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := readExits(t, f.admin.opts.ExitsFile); got != `[{"interface":"wg100","via":"10.9.0.2"}]` {
		t.Fatalf("offered: %s", got)
	}
	f.sys.ifaces = wg0Line + "wg100                             12     up          1420/0/0/0\n"
	if _, err := f.admin.StopWireGuardConfig("wg100", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := readExits(t, f.admin.opts.ExitsFile); got != "[]" {
		t.Fatalf("still offered once stopped: %s", got)
	}
}

func TestExitViaIsChecked(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.9.0.1/24, fd09::1/64\n[Peer]\nPublicKey = " + wgNewKey + "\nAllowedIPs = 10.9.0.0/24\n"
	f := newFixture(t)
	for name, via := range map[string]string{
		"not an address":  "gateway",
		"two of a family": "10.9.0.2 10.9.0.3",
		"own address":     "10.9.0.1",
		"no such family":  "fd42:1111:2222:90::9",
		"no peer holds":   "10.8.0.2",
	} {
		if _, err := f.admin.AddWireGuardConfig("x", "10.61.10.2", conf, "", "", via, false, "admin"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := f.admin.AddWireGuardConfig("x", "10.61.10.2", conf, "", "", "10.9.0.2", false, "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestExitsArePublishedOnStartAndHoldNoSecrets(t *testing.T) {
	f := newFixture(t)
	store := f.store(t)
	store.Configs[0].ExitVia = []string{"10.0.0.2"}
	if err := f.admin.saveWGStore(store); err != nil {
		t.Fatal(err)
	}
	f.opts.ExitsFile = filepath.Join(f.dir, "exits.json")
	if _, err := NewService(f.opts, f.sys); err != nil {
		t.Fatal(err)
	}
	if got := readExits(t, f.opts.ExitsFile); got != `[{"interface":"wg0","via":"10.0.0.2"}]` || strings.Contains(got, wgPrivateKey) {
		t.Fatalf("offered: %s", got)
	}
}
