package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.fd.io/govpp/api"
)

// The format of `vppctl wg show` as printed by a real router, with shortened keys.
const wgSample = `interface: wg0
	public key: SERVERKEY=
	listening port: 11111
	peer: AAAA=
		endpoint: 203.0.113.121:8237
		allowed ips:
			10.62.10.21/32
			fd42:1111:2222:90::15/128
		latest handshake: 12 seconds ago
		transfer: 171.12 MB received, 720.31 MB sent
		persistent keepalive: every 25 seconds

	peer: BBBB=
		endpoint: 203.0.113.9:28098
		allowed ips:
			10.62.10.11/32
		latest handshake: 1 h, 1 minute, 44 seconds ago
		transfer: 48 KB received, 1.30 GB sent

	peer: CCCC=
		endpoint: 0.0.0.0:0
		allowed ips:
			10.62.10.3/32
		latest handshake: never
		transfer: 0 B received, 0 B sent

interface: wg8
	public key: OTHER=
	private key: MUSTNOTAPPEAR=
	peer: DDDD=
		allowed ips:
			10.62.40.2/32
		latest handshake: 2 minutes, 59 seconds ago
		transfer: 1 B received, 2 B sent
`

func TestParseAgo(t *testing.T) {
	for text, want := range map[string]int64{
		"12 seconds":                       12,
		"2 minutes, 59 seconds":            179,
		"1 h, 0 minutes, 0 seconds":        3600,
		"1 day, 2 h, 3 minutes, 4 seconds": 93784,
		"3 hours":                          10800,
	} {
		if got, ok := parseAgo(text); !ok || got != want {
			t.Errorf("parseAgo(%q) = %d, %v; want %d", text, got, ok, want)
		}
	}
	if _, ok := parseAgo("1 fortnight"); ok {
		t.Error("an unknown unit was accepted")
	}
}

func TestParseWireGuard(t *testing.T) {
	peers, err := parseWireGuard(wgSample)
	if err != nil || len(peers) != 4 {
		t.Fatalf("%d peers, %v", len(peers), err)
	}
	first := peers[0]
	if first.Interface != "wg0" || first.PublicKey != "AAAA=" || first.Endpoint != "203.0.113.121:8237" || strings.Join(first.AllowedIPs, ",") != "10.62.10.21/32,fd42:1111:2222:90::15/128" {
		t.Fatalf("first = %+v", first)
	}
	if first.HandshakeSeconds != 12 || !first.Online {
		t.Fatalf("first = %+v", first)
	}
	received, sent := 171.12, 720.31
	if first.RxBytes != uint64(received*(1<<20)) || first.TxBytes != uint64(sent*(1<<20)) {
		t.Fatalf("transfer = %d %d", first.RxBytes, first.TxBytes)
	}
	second := peers[1]
	if second.HandshakeSeconds != 3704 || second.Online || second.RxBytes != 48<<10 {
		t.Fatalf("second = %+v", second)
	}
	if never := peers[2]; never.HandshakeSeconds != -1 || never.Online {
		t.Fatalf("never = %+v", never)
	}
	if last := peers[3]; last.Interface != "wg8" || !last.Online {
		t.Fatalf("online just under the limit: %+v", last)
	}
}

func TestPrivateKeysCannotReachTheReport(t *testing.T) {
	service := NewVPNService(&fakeVPN{wg: wgSample}, nil)
	w := httptest.NewRecorder()
	serveVPN(service).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/vpn", nil))
	if strings.Contains(w.Body.String(), "MUSTNOTAPPEAR") || strings.Contains(w.Body.String(), "private") {
		t.Fatalf("leaked: %s", w.Body)
	}
	if !strings.Contains(w.Body.String(), `"public_key":"AAAA="`) {
		t.Fatalf("body = %s", w.Body)
	}
}

func TestDefaultRoutePeerIsAnUpstreamNotAClient(t *testing.T) {
	peers, err := parseWireGuard("interface: wg1\n\tpeer: UP=\n\t\tallowed ips:\n\t\t\t0.0.0.0/0\n\tpeer: V6=\n\t\tallowed ips:\n\t\t\t::/0\n\tpeer: CLIENT=\n\t\tallowed ips:\n\t\t\t10.0.0.2/32\n")
	if err != nil || len(peers) != 3 || !peers[0].Upstream || !peers[1].Upstream || peers[2].Upstream {
		t.Fatalf("%+v %v", peers, err)
	}
}

func TestStockVPPWithoutWgShow(t *testing.T) {
	if _, err := parseWireGuard("unknown input `wg show'"); err == nil || !strings.Contains(err.Error(), "0002") {
		t.Fatalf("err = %v", err)
	}
}

// The layout strongSwan documents for `ipsec statusall`.
const ipsecSample = `Status of IKE charon daemon (strongSwan 5.9.8, Linux 6.1.57, aarch64):
Connections:
        cert:  %any...%any  IKEv2, dpddelay=30s
Security Associations (2 up, 0 connecting):
        cert[3]: ESTABLISHED 12 minutes ago, 192.0.2.1[ddns.example]...203.0.113.5[C=CN, O=Example, CN=client1]
        cert[3]: IKEv2 SPIs: 1234_i 5678_r*, public key reauthentication in 2 hours
        cert{5}:  INSTALLED, TUNNEL, reqid 5, ESP in UDP SPIs: c1f0_i cf01_o
        cert{5}:  AES_GCM_16_256, 1234 bytes_i (12 pkts, 3s ago), 5678 bytes_o (34 pkts, 3s ago), rekeying in 48 minutes
        cert{5}:   0.0.0.0/0 ::/0 === 10.62.50.1/32 2001:db8::100/128
eap-mschapv2[4]: ESTABLISHED 3 hours ago, 192.0.2.1[ddns.example]...198.51.100.7[198.51.100.7]
eap-mschapv2[4]: Remote EAP identity: alice
eap-mschapv2{6}:  INSTALLED, TUNNEL, reqid 6, ESP SPIs: aa_i bb_o
eap-mschapv2{6}:  AES_CBC_256/HMAC_SHA2_256_128, rekeying in 30 minutes
eap-mschapv2{6}:   10.0.0.0/8 === 10.62.20.9/32
`

func TestParseIPsec(t *testing.T) {
	clients := parseIPsec(ipsecSample)
	if len(clients) != 2 {
		t.Fatalf("clients = %+v", clients)
	}
	first := clients[0]
	if first.Connection != "cert" || first.Identity != "C=CN, O=Example, CN=client1" || first.Remote != "203.0.113.5" || first.EstablishedSeconds != 720 {
		t.Fatalf("first = %+v", first)
	}
	if strings.Join(first.VirtualIPs, ",") != "10.62.50.1/32,2001:db8::100/128" || !first.HasCounters || first.BytesIn != 1234 || first.BytesOut != 5678 {
		t.Fatalf("first = %+v", first)
	}
	second := clients[1]
	if second.EAPIdentity != "alice" || second.HasCounters || strings.Join(second.VirtualIPs, ",") != "10.62.20.9/32" || second.EstablishedSeconds != 10800 {
		t.Fatalf("second = %+v", second)
	}
}

func TestParseIPsecWithNoSessions(t *testing.T) {
	if clients := parseIPsec("Connections:\n cert: x\nSecurity Associations (0 up, 0 connecting):\n  none\n"); len(clients) != 0 {
		t.Fatalf("clients = %+v", clients)
	}
}

type fakeVPN struct {
	wg, ipsec       string
	wgErr, ipsecErr error
	reads           int
}

func (f *fakeVPN) wireGuardStatus() (string, error) { f.reads++; return f.wg, f.wgErr }
func (f *fakeVPN) ipsecStatus() (string, error)     { return f.ipsec, f.ipsecErr }

func TestVPNReportCachesAndNamesPeers(t *testing.T) {
	source := &fakeVPN{wg: wgSample, ipsec: ipsecSample}
	service := NewVPNService(source, map[string]string{"BBBB=": "laptop"})
	now := time.Unix(1000, 0)
	service.now = func() time.Time { return now }
	report := service.Report()
	if len(report.WireGuard) != 4 || len(report.IPsec) != 2 || report.WireGuardError != "" {
		t.Fatalf("report = %+v", report)
	}
	if report.WireGuard[0].PublicKey != "AAAA=" || report.WireGuard[3].PublicKey != "CCCC=" {
		t.Fatalf("sorting: %+v", report.WireGuard)
	}
	named := false
	for _, peer := range report.WireGuard {
		named = named || (peer.PublicKey == "BBBB=" && peer.Name == "laptop")
	}
	if !named {
		t.Fatalf("no name: %+v", report.WireGuard)
	}
	service.Report()
	if source.reads != 1 {
		t.Fatalf("%d reads inside the interval", source.reads)
	}
	now = now.Add(vpnMinInterval)
	service.Report()
	if source.reads != 2 {
		t.Fatalf("%d reads after the interval", source.reads)
	}
}

func TestOneFailedSourceKeepsTheOther(t *testing.T) {
	service := NewVPNService(&fakeVPN{wg: wgSample, ipsecErr: errors.New("no strongSwan")}, nil)
	report := service.Report()
	if report.IPsecError != "no strongSwan" || len(report.WireGuard) != 4 {
		t.Fatalf("report = %+v", report)
	}
	service = NewVPNService(&fakeVPN{wgErr: errors.New("no VPP"), ipsec: ipsecSample}, nil)
	report = service.Report()
	if report.WireGuardError != "no VPP" || len(report.IPsec) != 2 {
		t.Fatalf("report = %+v", report)
	}
}

func TestVPNNamesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "names.json")
	os.WriteFile(path, []byte(`{"AAAA=":"phone"}`), 0o644)
	names, err := LoadVPNNames(path)
	if err != nil || names["AAAA="] != "phone" {
		t.Fatalf("%v %v", names, err)
	}
	if names, err := LoadVPNNames(""); names != nil || err != nil {
		t.Fatalf("%v %v", names, err)
	}
	os.WriteFile(path, []byte(`not json`), 0o644)
	if _, err := LoadVPNNames(path); err == nil {
		t.Fatal("a broken file was accepted")
	}
}

func TestStrokeConfig(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	path, err := writeStrokeConfig("unix:///run/rk3588-strongswan/charon.ctl")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "socket = unix:///run/rk3588-strongswan/charon.ctl") {
		t.Fatalf("config = %s", data)
	}
	for _, bad := range []string{"tcp://1.1.1.1", "unix:///x\n}", "unix:///a b"} {
		if _, err := writeStrokeConfig(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUnknownCLICommandIsRecognised(t *testing.T) {
	if !cliUnsupported(fmt.Errorf("wrapped: %w", api.VPPApiError(-1))) {
		t.Fatal("-1 not recognised")
	}
	if cliUnsupported(api.VPPApiError(-2)) || cliUnsupported(errors.New("timeout")) || cliUnsupported(nil) {
		t.Fatal("another failure was taken for a missing command")
	}
}

func TestUpstreamTunnelsComeFirst(t *testing.T) {
	peers := []WireGuardPeer{
		{PublicKey: "never", HandshakeSeconds: -1},
		{PublicKey: "recent", HandshakeSeconds: 5},
		{PublicKey: "up-old", HandshakeSeconds: 900, Upstream: true},
		{PublicKey: "up-new", HandshakeSeconds: 20, Upstream: true},
		{PublicKey: "up-never", HandshakeSeconds: -1, Upstream: true},
	}
	sortWireGuard(peers)
	var order []string
	for _, peer := range peers {
		order = append(order, peer.PublicKey)
	}
	if got := strings.Join(order, ","); got != "up-new,up-old,up-never,recent,never" {
		t.Fatalf("order = %s", got)
	}
}

func TestVPNNamesFollowTheFileAndInvalidateRereads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "names.json")
	source := &fakeVPN{wg: wgSample}
	service := NewVPNService(source, nil)
	service.namesFile = path
	key := service.Report().WireGuard[0].PublicKey
	if name := service.Report().WireGuard[0].Name; name != "" {
		t.Fatalf("a missing file named a peer: %q", name)
	}
	os.WriteFile(path, []byte(`{"`+key+`":"phone"}`), 0o644)
	if name := service.Report().WireGuard[0].Name; name != "" {
		t.Fatalf("the cached reading should still be used: %q", name)
	}
	service.Invalidate()
	if name := service.Report().WireGuard[0].Name; name != "phone" {
		t.Fatalf("name after invalidate: %q", name)
	}
}

func TestParsePlainPeersFromStockVPP(t *testing.T) {
	text := `[0] endpoint:[10.61.10.2:11111->203.0.113.30:45865] wg0 keep-alive:25 flags: 2, api-clients count: 0
  adj: 31 32
  public key:AAAA= 6cfd
  allowed-ips: 10.62.10.2/32 fd42:1111:2222:90::2/128
[1] endpoint:[10.61.10.2:11111->0.0.0.0:0] wg1 keep-alive:25 flags: 0
  key:BBBB= 5f29
  allowed-ips: 0.0.0.0/0
`
	peers, err := parseWireGuard(text)
	if err != nil || len(peers) != 2 {
		t.Fatalf("%v %v", peers, err)
	}
	first := peers[0]
	if first.Interface != "wg0" || first.PublicKey != "AAAA=" || first.Endpoint != "203.0.113.30:45865" || len(first.AllowedIPs) != 2 || !first.Limited || first.Online || first.HandshakeSeconds != -1 || first.Upstream {
		t.Fatalf("%+v", first)
	}
	if second := peers[1]; second.Interface != "wg1" || second.PublicKey != "BBBB=" || !second.Upstream {
		t.Fatalf("%+v", second)
	}
}
