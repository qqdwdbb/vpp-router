package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
const wgKey = "ERERERERERERERERERERERERERERERERERERERERERE="
const wgPeer = "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4="

func outbound(t *testing.T, p Profile) map[string]any {
	t.Helper()
	doc, err := p.Upstream()
	if err != nil {
		t.Fatalf("%+v: %v", p, err)
	}
	list := asList(toAny(doc)["outbounds"])
	if len(list) != 1 {
		t.Fatalf("outbounds %v", doc)
	}
	return list[0].(map[string]any)
}

// toAny round-trips through JSON, so maps read as they would from a file.
func toAny(value any) map[string]any {
	data, _ := json.Marshal(value)
	var out map[string]any
	json.Unmarshal(data, &out)
	return out
}

func get(m map[string]any, path string) any {
	var value any = m
	for _, key := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[key]
	}
	return value
}

func TestProfilesBecomeOutbounds(t *testing.T) {
	for _, c := range []struct {
		p    Profile
		want map[string]any
	}{
		{Profile{Type: "socks", Server: "1.2.3.4", Port: 1080, Username: "u", Password: "p"},
			map[string]any{"type": "socks", "version": "5", "username": "u", "password": "p", "tag": "proxy", "tls": nil}},
		{Profile{Type: "http", Server: "h.example", Port: 443, TLS: TLS{Enabled: true, ServerName: "h.example"}},
			map[string]any{"type": "http", "tls.enabled": true, "tls.server_name": "h.example"}},
		{Profile{Type: "shadowsocks", Server: "s", Port: 8388, Method: "2022-blake3-aes-128-gcm", Password: "k", TLS: TLS{Enabled: true}},
			map[string]any{"method": "2022-blake3-aes-128-gcm", "password": "k", "tls": nil}},
		{Profile{Type: "vmess", Server: "v", Port: 443, UUID: testUUID, TLS: TLS{Enabled: true}, Transport: Transport{Type: "ws", Path: "/ray", Host: "cdn.example"}},
			map[string]any{"uuid": testUUID, "security": "auto", "transport.type": "ws", "transport.path": "/ray", "transport.headers.Host": "cdn.example"}},
		{Profile{Type: "vless", Server: "r", Port: 443, UUID: testUUID, Flow: "xtls-rprx-vision", TLS: TLS{Enabled: true, ServerName: "www.example.com", Reality: true, PublicKey: "pk", ShortID: "ab"}},
			map[string]any{"flow": "xtls-rprx-vision", "tls.reality.enabled": true, "tls.reality.public_key": "pk", "tls.reality.short_id": "ab", "tls.utls.fingerprint": "chrome"}},
		{Profile{Type: "trojan", Server: "t", Port: 443, Password: "p", Transport: Transport{Type: "grpc", ServiceName: "svc"}},
			map[string]any{"tls.enabled": true, "transport.service_name": "svc"}},
		{Profile{Type: "hysteria2", Server: "h", Port: 443, Password: "p", Obfs: "o", UpMbps: 50, DownMbps: 200},
			map[string]any{"obfs.type": "salamander", "obfs.password": "o", "up_mbps": float64(50), "tls.enabled": true}},
		{Profile{Type: "tuic", Server: "q", Port: 443, UUID: testUUID, Password: "p", TLS: TLS{ALPN: []string{"h3"}}},
			map[string]any{"congestion_control": "bbr", "tls.enabled": true, "tls.alpn": []any{"h3"}}},
		{Profile{Type: "anytls", Server: "a", Port: 443, Password: "p", TLS: TLS{Insecure: true}},
			map[string]any{"password": "p", "tls.insecure": true}},
	} {
		out := outbound(t, c.p)
		for path, want := range c.want {
			if got := get(out, path); !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s = %v, want %v (%v)", c.p.Type, path, got, want, out)
			}
		}
	}
}

func TestWireGuardBecomesAnEndpoint(t *testing.T) {
	p := Profile{Type: "wireguard", Server: "192.0.2.1", Port: 51820, Address: []string{"10.0.0.2/32"}, PrivateKey: wgKey, PeerKey: wgPeer}
	doc, err := p.Upstream()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := asList(toAny(doc)["endpoints"])[0].(map[string]any)
	peer := asList(endpoint["peers"])[0].(map[string]any)
	if endpoint["tag"] != "proxy" || peer["public_key"] != wgPeer || len(asList(peer["allowed_ips"])) != 2 {
		t.Fatalf("endpoint %v", endpoint)
	}
}

func TestValidationRefusals(t *testing.T) {
	for _, p := range []Profile{
		{Type: "nope", Server: "x", Port: 1},
		{Type: "socks", Server: "", Port: 1080},
		{Type: "socks", Server: "a b", Port: 1080},
		{Type: "socks", Server: "x", Port: 70000},
		{Type: "socks", Server: "x", Port: 1, Password: "p"},
		{Type: "shadowsocks", Server: "x", Port: 1, Method: "rc4", Password: "p"},
		{Type: "vmess", Server: "x", Port: 1, UUID: "not-a-uuid"},
		{Type: "trojan", Server: "x", Port: 1},
		{Type: "trojan", Server: "x", Port: 1, Password: "p", TLS: TLS{Reality: true, PublicKey: "k"}},
		{Type: "vless", Server: "x", Port: 1, UUID: testUUID, TLS: TLS{Enabled: true, Reality: true}},
		{Type: "vless", Server: "x", Port: 1, UUID: testUUID, Transport: Transport{Type: "grpc"}},
		{Type: "wireguard", Server: "x", Port: 1, Address: []string{"10.0.0.2"}, PrivateKey: wgKey, PeerKey: wgPeer},
		{Type: "wireguard", Server: "x", Port: 1, Address: []string{"10.0.0.2/32"}, PrivateKey: "short", PeerKey: wgPeer},
	} {
		if _, err := p.Upstream(); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

func TestShareLinks(t *testing.T) {
	b64 := func(text string) string { return base64.StdEncoding.EncodeToString([]byte(text)) }
	vmess := b64(`{"v":"2","ps":"hk","add":"v.example","port":"443","id":"` + testUUID + `","aid":"0","scy":"auto","net":"ws","path":"/ray","host":"cdn.example","tls":"tls","sni":"cdn.example"}`)
	for link, want := range map[string]Profile{
		"socks5://u:p@1.2.3.4:1080#home": {Type: "socks", Name: "home", Server: "1.2.3.4", Port: 1080, Username: "u", Password: "p"},
		"socks://" + base64.RawURLEncoding.EncodeToString([]byte("u:p")) + "@1.2.3.4:1080":              {Type: "socks", Server: "1.2.3.4", Port: 1080, Username: "u", Password: "p"},
		"https://u:p@h.example:443?sni=h.example":                                                       {Type: "http", Server: "h.example", Port: 443, Username: "u", Password: "p", TLS: TLS{Enabled: true, ServerName: "h.example"}},
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@s.example:8388#jp": {Type: "shadowsocks", Name: "jp", Server: "s.example", Port: 8388, Method: "aes-256-gcm", Password: "pw"},
		"ss://2022-blake3-aes-128-gcm:a%2Bb%3D@[2001:db8::1]:8388":                                      {Type: "shadowsocks", Server: "2001:db8::1", Port: 8388, Method: "2022-blake3-aes-128-gcm", Password: "a+b="},
		"ss://" + b64("chacha20-ietf-poly1305:pw@s.example:8388") + "#old":                              {Type: "shadowsocks", Name: "old", Server: "s.example", Port: 8388, Method: "chacha20-ietf-poly1305", Password: "pw"},
		"vmess://" + vmess: {Type: "vmess", Name: "hk", Server: "v.example", Port: 443, UUID: testUUID, Security: "auto",
			TLS: TLS{Enabled: true, ServerName: "cdn.example"}, Transport: Transport{Type: "ws", Path: "/ray", Host: "cdn.example"}},
		"vless://" + testUUID + "@r.example:443?security=reality&sni=www.example.com&fp=chrome&pbk=PK&sid=ab&flow=xtls-rprx-vision&type=tcp#us": {Type: "vless", Name: "us", Server: "r.example", Port: 443, UUID: testUUID, Flow: "xtls-rprx-vision",
			TLS: TLS{Enabled: true, ServerName: "www.example.com", Fingerprint: "chrome", Reality: true, PublicKey: "PK", ShortID: "ab"}},
		"trojan://pw@t.example:443?sni=t.example&type=grpc&serviceName=svc&allowInsecure=1": {Type: "trojan", Server: "t.example", Port: 443, Password: "pw",
			TLS: TLS{Enabled: true, ServerName: "t.example", Insecure: true}, Transport: Transport{Type: "grpc", ServiceName: "svc"}},
		"hy2://pw@h.example:443?sni=h.example&obfs=salamander&obfs-password=ob&insecure=1": {Type: "hysteria2", Server: "h.example", Port: 443, Password: "pw", Obfs: "ob",
			TLS: TLS{Enabled: true, ServerName: "h.example", Insecure: true}},
		"tuic://" + testUUID + ":pw@q.example:443?congestion_control=cubic&alpn=h3&sni=q.example": {Type: "tuic", Server: "q.example", Port: 443, UUID: testUUID, Password: "pw", Congestion: "cubic",
			TLS: TLS{Enabled: true, ServerName: "q.example", ALPN: []string{"h3"}}},
		"anytls://pw@a.example:443?sni=a.example": {Type: "anytls", Server: "a.example", Port: 443, Password: "pw", TLS: TLS{Enabled: true, ServerName: "a.example"}},
	} {
		got, err := ParseLink(link)
		if err != nil {
			t.Errorf("%s: %v", link, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", link, got, want)
		}
		if _, err := got.Upstream(); err != nil && got.Type != "vless" {
			t.Errorf("%s does not make an outbound: %v", link, err)
		}
	}
	nodes, err := ParseLinks("not a link\nfoo://x@y:1\nsocks5://1.2.3.4:1080\n")
	if err != nil || len(nodes) != 2 || len(nodes[0].Ignored) == 0 || nodes[1].Type != "socks" {
		t.Fatalf("mixed lines: %+v %v", nodes, err)
	}
	if got, _ := ParseLink("ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@s:1/?plugin=obfs-local"); len(got.Ignored) != 1 {
		t.Fatalf("plugin not reported: %+v", got)
	}
}

const clientConfig = `{
  "log": {"level": "info"},
  "outbounds": [
    {"type": "selector", "tag": "select", "outbounds": ["hk", "jp"]},
    {"type": "urltest", "tag": "auto", "outbounds": ["hk", "jp"]},
    {"type": "trojan", "tag": "hk", "server": "hk.example", "server_port": 443, "password": "pw",
     "tls": {"enabled": true, "server_name": "hk.example", "utls": {"enabled": true, "fingerprint": "chrome"}},
     "multiplex": {"enabled": true}},
    {"type": "vless", "tag": "jp", "server": "jp.example", "server_port": 443, "uuid": "` + testUUID + `",
     "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example"}}, "tls": {"enabled": true}},
    {"type": "direct", "tag": "direct"}
  ],
  "endpoints": [{"type": "wireguard", "tag": "wg", "address": ["10.0.0.2/32"], "private_key": "` + wgKey + `",
    "peers": [{"address": "192.0.2.1", "port": 51820, "public_key": "` + wgPeer + `", "allowed_ips": ["0.0.0.0/0"]}]}]
}`

func TestSingBoxConfigurationNodes(t *testing.T) {
	nodes, err := ParseSingBox(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 || nodes[0].Name != "hk" || nodes[1].Name != "jp" || nodes[2].Type != "wireguard" {
		t.Fatalf("nodes %+v", nodes)
	}
	if !reflect.DeepEqual(nodes[0].Ignored, []string{"multiplex"}) || nodes[0].TLS.Fingerprint != "chrome" {
		t.Fatalf("hk %+v", nodes[0])
	}
	if nodes[1].Transport.Host != "cdn.example" || nodes[1].Ignored != nil {
		t.Fatalf("jp %+v", nodes[1])
	}
	if nodes[2].PeerKey != wgPeer || nodes[2].Server != "192.0.2.1" {
		t.Fatalf("wg %+v", nodes[2])
	}
	// What the wizard makes reads back the same.
	for _, node := range nodes {
		doc, err := node.Upstream()
		if err != nil {
			t.Fatalf("%s: %v", node.Name, err)
		}
		again, err := ParseSingBox(string(must(json.Marshal(doc))))
		if err != nil || again[0].Server != node.Server || again[0].Type != node.Type {
			t.Fatalf("%s round trip: %+v %v", node.Name, again, err)
		}
	}
	if _, err := ParseSingBox(`{"outbounds":[{"type":"direct"}]}`); err == nil {
		t.Fatal("no nodes accepted")
	}
}

func must(data []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return data
}

func TestSubscriptionBodies(t *testing.T) {
	links := "trojan://pw@t.example:443#a\nsocks5://1.2.3.4:1080#b\n"
	for name, body := range map[string]string{
		"base64": base64.StdEncoding.EncodeToString([]byte(links)),
		"plain":  links,
		"json":   clientConfig,
	} {
		nodes, err := ParseSubscription(body)
		if err != nil || len(nodes) < 2 {
			t.Errorf("%s: %+v %v", name, nodes, err)
		}
	}
}

type fakeSystem struct {
	checkErr  error
	actives   []bool
	units     []string
	probeCode int
	probeErr  error
	probed    map[string]any
	body      string
}

func (f *fakeSystem) check(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "entry.json")); err != nil {
		return err
	}
	return f.checkErr
}
func (f *fakeSystem) version() string { return "1.14.3" }
func (f *fakeSystem) unit(action string) error {
	f.units = append(f.units, action)
	return nil
}
func (f *fakeSystem) active() bool {
	if len(f.actives) == 0 {
		return true
	}
	value := f.actives[0]
	f.actives = f.actives[1:]
	return value
}
func (f *fakeSystem) probe(upstream map[string]any, url string) (int, time.Duration, error) {
	f.probed = upstream
	return f.probeCode, 120 * time.Millisecond, f.probeErr
}
func (f *fakeSystem) fetch(string) (string, error) { return f.body, nil }

const placeholderUpstream = `{"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"rules":[{"inbound":["tproxy","lan-socks"],"action":"reject"}]}}`

func setup(t *testing.T) (*Service, *fakeSystem, string) {
	t.Helper()
	dir := t.TempDir()
	box := filepath.Join(dir, "sing-box")
	os.MkdirAll(box, 0o700)
	os.WriteFile(filepath.Join(box, "entry.json"), []byte(`{"inbounds":[{"type":"socks","tag":"lan-socks","listen":"10.61.30.2","listen_port":1080}]}`), 0o600)
	os.WriteFile(filepath.Join(box, "upstream.json"), []byte(placeholderUpstream), 0o600)
	sys := &fakeSystem{probeCode: 204}
	s, err := NewService(Options{SingBoxDir: box, ConfigDir: filepath.Join(dir, "proxy"), StateDir: filepath.Join(dir, "state"), TestURL: "https://test.example/204"}, sys)
	if err != nil {
		t.Fatal(err)
	}
	s.sleep = func(time.Duration) {}
	return s, sys, box
}

func TestApplyWritesAndRestarts(t *testing.T) {
	s, sys, box := setup(t)
	if state := s.State(); state.Upstream != "none" || !state.Installed || len(state.Inbounds) != 1 {
		t.Fatalf("before: %+v", state)
	}
	p := Profile{Type: "trojan", Server: "t.example", Port: 443, Password: "secret-pw", Name: "hk"}
	state, err := s.Apply(p, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Upstream != "wizard" || state.Profile.Server != "t.example" || state.Profile.Password != "" || !reflect.DeepEqual(state.SecretsSet, []string{"password"}) {
		t.Fatalf("state %+v", state)
	}
	if data, _ := json.Marshal(state); strings.Contains(string(data), "secret-pw") {
		t.Fatal("the password left the service")
	}
	if !reflect.DeepEqual(sys.units, []string{"restart"}) {
		t.Fatalf("units %v", sys.units)
	}
	if backup, _ := os.ReadFile(filepath.Join(box, "upstream.json.bak")); string(backup) != placeholderUpstream {
		t.Fatal("the previous upstream was not kept")
	}
	if info, _ := os.Stat(filepath.Join(box, "upstream.json")); info.Mode().Perm() != 0o600 {
		t.Fatal("upstream.json readable by others")
	}
	// An empty password keeps the saved one.
	p.Password = ""
	p.Name = "renamed"
	if _, err := s.Apply(p, "admin"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(box, "upstream.json")); !strings.Contains(string(data), "secret-pw") {
		t.Fatalf("password lost:\n%s", data)
	}
	// Edited by hand: shown as custom.
	os.WriteFile(filepath.Join(box, "upstream.json"), []byte(`{"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"s.example"}]}`), 0o600)
	if state := s.State(); state.Upstream != "custom" || state.Profile != nil || !strings.Contains(state.Custom[0], "shadowsocks s.example") {
		t.Fatalf("custom: %+v", state)
	}
}

func TestApplyRefusedOrNotComingBack(t *testing.T) {
	s, sys, box := setup(t)
	sys.checkErr = errors.New("bad")
	if _, err := s.Apply(Profile{Type: "socks", Server: "1.2.3.4", Port: 1080}, "admin"); err == nil {
		t.Fatal("accepted what sing-box refused")
	}
	if data, _ := os.ReadFile(filepath.Join(box, "upstream.json")); string(data) != placeholderUpstream || len(sys.units) != 0 {
		t.Fatal("a refused change did something")
	}
	sys.checkErr = nil
	sys.actives = []bool{true, false}
	if _, err := s.Apply(Profile{Type: "socks", Server: "1.2.3.4", Port: 1080}, "admin"); err == nil {
		t.Fatal("no error when sing-box did not stay up")
	}
	if data, _ := os.ReadFile(filepath.Join(box, "upstream.json")); string(data) != placeholderUpstream {
		t.Fatalf("not restored:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(s.opts.ConfigDir, "profile.json")); !os.IsNotExist(err) {
		t.Fatal("profile kept after the restore")
	}
	if !reflect.DeepEqual(sys.units, []string{"restart", "restart"}) {
		t.Fatalf("units %v", sys.units)
	}
}

func TestTests(t *testing.T) {
	s, sys, _ := setup(t)
	if _, err := s.Test(nil, ""); err == nil {
		t.Fatal("tested the placeholder")
	}
	result, err := s.Test(&Profile{Type: "socks", Server: "1.2.3.4", Port: 1080}, "")
	if err != nil || !result.OK || result.URL != "https://test.example/204" {
		t.Fatalf("result %+v %v", result, err)
	}
	if get(asList(sys.probed["outbounds"])[0].(map[string]any), "server") != "1.2.3.4" {
		t.Fatalf("probed %v", sys.probed)
	}
	sys.probeErr = errors.New("timeout")
	if result, _ := s.Test(&Profile{Type: "socks", Server: "1.2.3.4", Port: 1080}, ""); result.OK || result.Message != "timeout" {
		t.Fatalf("failure %+v", result)
	}
	if _, err := s.Test(nil, "ftp://x"); err == nil {
		t.Fatal("ftp test URL accepted")
	}
}

func TestSubscriptionFlow(t *testing.T) {
	s, sys, box := setup(t)
	sys.body = base64.StdEncoding.EncodeToString([]byte("trojan://pw1@a.example:443#A\ntrojan://pw2@b.example:443#B\n"))
	state, err := s.Subscribe("https://sub.example/x")
	if err != nil || len(state.Subscription.Nodes) != 2 || state.Subscription.Nodes[0].Password != "" {
		t.Fatalf("subscribe %+v %v", state, err)
	}
	if state, err = s.UseSubscriptionNode(1, "admin"); err != nil || state.Subscription.Using != "B" || state.Profile.Server != "b.example" {
		t.Fatalf("use %+v %v", state, err)
	}
	// The provider changes B's server; updating applies it.
	sys.body = "trojan://pw3@c.example:443#B\n"
	if state, err = s.UpdateSubscription("admin"); err != nil || state.Profile.Server != "c.example" {
		t.Fatalf("update %+v %v", state, err)
	}
	if data, _ := os.ReadFile(filepath.Join(box, "upstream.json")); !strings.Contains(string(data), "pw3") {
		t.Fatal("updated node not applied")
	}
	sys.body = "trojan://pw@d.example:443#D\n"
	if _, err := s.UpdateSubscription("admin"); err == nil {
		t.Fatal("no error when the node in use is gone")
	}
}

// TestRealSingBoxAccepts runs sing-box check on what the wizard makes for every protocol, with
// SINGBOX set to a sing-box binary, as on a router: SINGBOX=/usr/local/bin/sing-box.
func TestRealSingBoxAccepts(t *testing.T) {
	binary := os.Getenv("SINGBOX")
	if binary == "" {
		t.Skip("SINGBOX not set")
	}
	sys := &realSystem{opts: Options{Binary: binary}}
	entry := `{"inbounds":[{"type":"socks","tag":"lan-socks","listen":"127.0.0.1","listen_port":1080}],
		"dns":{"servers":[{"type":"local","tag":"system"}]},"route":{"final":"proxy","default_domain_resolver":"system"}}`
	profiles := []Profile{
		{Type: "socks", Server: "1.2.3.4", Port: 1080, Username: "u", Password: "p"},
		{Type: "http", Server: "h.example", Port: 443, Username: "u", Password: "p", TLS: TLS{Enabled: true, ServerName: "h.example", Fingerprint: "firefox"}},
		{Type: "shadowsocks", Server: "s.example", Port: 8388, Method: "2022-blake3-aes-128-gcm", Password: "8JCsPssfgS8tiRwiMlhARg=="},
		{Type: "vmess", Server: "v.example", Port: 443, UUID: testUUID, TLS: TLS{Enabled: true, ALPN: []string{"h2", "http/1.1"}}, Transport: Transport{Type: "ws", Path: "/ray", Host: "cdn.example"}},
		{Type: "vless", Server: "r.example", Port: 443, UUID: testUUID, Flow: "xtls-rprx-vision", TLS: TLS{Enabled: true, ServerName: "www.microsoft.com", Reality: true, PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", ShortID: "0123456789abcdef"}},
		{Type: "vless", Server: "g.example", Port: 443, UUID: testUUID, TLS: TLS{Enabled: true}, Transport: Transport{Type: "grpc", ServiceName: "svc"}},
		{Type: "vless", Server: "u.example", Port: 80, UUID: testUUID, Transport: Transport{Type: "httpupgrade", Path: "/up", Host: "u.example"}},
		{Type: "trojan", Server: "t.example", Port: 443, Password: "pw", TLS: TLS{ServerName: "t.example", Insecure: true}, Transport: Transport{Type: "http", Path: "/h2", Host: "t.example"}},
		{Type: "hysteria2", Server: "h.example", Port: 443, Password: "pw", Obfs: "ob", UpMbps: 50, DownMbps: 200},
		{Type: "tuic", Server: "q.example", Port: 443, UUID: testUUID, Password: "pw", TLS: TLS{ALPN: []string{"h3"}}},
		{Type: "anytls", Server: "a.example", Port: 443, Password: "pw"},
		{Type: "wireguard", Server: "192.0.2.1", Port: 51820, Address: []string{"10.0.0.2/32", "fd00::2/128"}, PrivateKey: wgKey, PeerKey: wgPeer, PreSharedKey: wgKey, MTU: 1408},
	}
	for _, p := range profiles {
		doc, err := p.Upstream()
		if err != nil {
			t.Fatalf("%s: %v", p.Type, err)
		}
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "entry.json"), []byte(entry), 0o600)
		os.WriteFile(filepath.Join(dir, "upstream.json"), must(json.Marshal(doc)), 0o600)
		if err := sys.check(dir); err != nil {
			t.Errorf("%s %s: %v", p.Type, p.Transport.Type, err)
		}
	}
}

func TestClearAndDeleteSubscription(t *testing.T) {
	s, sys, box := setup(t)
	sys.body = "trojan://pw1@a.example:443#A\n"
	if _, err := s.Subscribe("https://sub.example/x"); err != nil {
		t.Fatal(err)
	}
	if state, err := s.UseSubscriptionNode(0, "admin"); err != nil || state.Subscription.Using != "A" {
		t.Fatalf("use %+v %v", state, err)
	}
	state, err := s.Clear("admin")
	if err != nil || state.Upstream != "none" || state.Profile != nil || state.Subscription.Using != "" {
		t.Fatalf("clear %+v %v", state, err)
	}
	if _, err := os.Stat(filepath.Join(s.opts.ConfigDir, "profile.json")); !os.IsNotExist(err) {
		t.Fatal("profile kept after clearing")
	}
	if backup, _ := os.ReadFile(filepath.Join(box, "upstream.json.bak")); !strings.Contains(string(backup), "pw1") {
		t.Fatal("the cleared upstream was not kept")
	}
	if !reflect.DeepEqual(sys.units, []string{"restart", "restart"}) {
		t.Fatalf("units %v", sys.units)
	}
	// A wizard apply is not a subscription node.
	if _, err := s.UseSubscriptionNode(0, "admin"); err != nil {
		t.Fatal(err)
	}
	if state, _ := s.Apply(Profile{Type: "socks", Server: "1.2.3.4", Port: 1080}, "admin"); state.Subscription.Using != "" {
		t.Fatalf("still using %q", state.Subscription.Using)
	}
	if state, err := s.DeleteSubscription("admin"); err != nil || state.Subscription != nil || state.Upstream != "wizard" {
		t.Fatalf("delete %+v %v", state, err)
	}
	if _, err := s.DeleteSubscription("admin"); err != nil {
		t.Fatal(err)
	}
}

func TestClearRefused(t *testing.T) {
	s, sys, box := setup(t)
	if _, err := s.Apply(Profile{Type: "socks", Server: "1.2.3.4", Port: 1080}, "admin"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(box, "upstream.json"))
	sys.actives = []bool{false}
	if _, err := s.Clear("admin"); err == nil {
		t.Fatal("no error when sing-box did not stay up")
	}
	if data, _ := os.ReadFile(filepath.Join(box, "upstream.json")); string(data) != string(before) || s.State().Upstream != "wizard" {
		t.Fatal("not restored")
	}
}
