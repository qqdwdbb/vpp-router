package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var dhcpNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

type dhcpFixture struct {
	d        *DHCP
	dir      string
	conf     string
	hosts    string
	leases   string
	commands []string
	fail     string // a command that fails
}

func newDHCPFixture(t *testing.T) *dhcpFixture {
	t.Helper()
	dir := t.TempDir()
	f := &dhcpFixture{dir: dir, conf: filepath.Join(dir, "dnsmasq.conf"), hosts: filepath.Join(dir, "dhcp-hosts"),
		leases: filepath.Join(dir, "dnsmasq.leases")}
	write(t, f.conf, "# managed lines and mine\ninterface=vpp-host\nbind-interfaces\nlisten-address=10.61.30.2\n"+
		"dhcp-range=10.61.30.100,10.61.30.200,255.255.255.0,12h\ndhcp-option=option:router,10.61.30.1\n"+
		"dhcp-option=option:dns-server,10.61.30.2\ndhcp-leasefile="+f.leases+"\ndhcp-hostsfile="+f.hosts+"\nlocal=/lan/\n")
	write(t, f.hosts, "# static\n02:00:00:00:30:01,10.61.30.20,nas\nid:01:02,10.61.30.30\n")
	expired, active := dhcpNow.Add(-time.Hour).Unix(), dhcpNow.Add(time.Hour).Unix()
	write(t, f.leases, fmt.Sprintf("%d 02:00:00:00:30:02 10.61.30.101 laptop 01:02:00:00:00:30:02\n"+
		"%d 02:00:00:00:30:03 10.61.30.102 * *\n0 02:00:00:00:30:04 10.61.30.103 tv *\n"+
		"duid 00:01:00:01:aa\n", active, expired))
	f.d = NewDHCP(DHCPOptions{Conf: f.conf, Unit: "vpp-router-dnsmasq.service",
		Devices: filepath.Join(dir, "devices.json"), Clients: filepath.Join(dir, "clients.json")})
	f.d.now = func() time.Time { return dhcpNow }
	f.d.run = func(name string, args ...string) error {
		command := strings.Join(append([]string{filepath.Base(name)}, args...), " ")
		f.commands = append(f.commands, command)
		if f.fail != "" && strings.HasPrefix(command, f.fail) {
			return errors.New("failed")
		}
		return nil
	}
	return f
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDHCPStateReadsTheConfigurationHostsAndLeases(t *testing.T) {
	f := newDHCPFixture(t)
	state, err := f.d.State()
	if err != nil {
		t.Fatal(err)
	}
	if state.Network != "10.61.30.0/24" || state.Router != "10.61.30.1" || state.Server != "10.61.30.2" {
		t.Fatalf("network %+v", state)
	}
	if state.Range != (DHCPRange{Start: "10.61.30.100", End: "10.61.30.200", Lease: "12h"}) {
		t.Fatalf("range %+v", state.Range)
	}
	if len(state.Hosts) != 1 || state.Hosts[0] != (StaticHost{MAC: "02:00:00:00:30:01", IP: "10.61.30.20", Name: "nas"}) {
		t.Fatalf("hosts %+v", state.Hosts)
	}
	if !slices.Equal(state.OtherHosts, []string{"id:01:02,10.61.30.30"}) {
		t.Fatalf("other hosts %v", state.OtherHosts)
	}
	if len(state.Leases) != 3 || state.Leases[0].Hostname != "laptop" || state.Leases[0].ClientID == "" ||
		state.Leases[1].Hostname != "" || state.Leases[2].Expires != nil {
		t.Fatalf("leases %+v", state.Leases)
	}
	// The expired lease makes no device; the static host and the active leases do.
	var labels []string
	for _, d := range state.Devices {
		labels = append(labels, d.Label)
	}
	slices.Sort(labels)
	if !slices.Equal(labels, []string{"laptop", "nas", "tv"}) {
		t.Fatalf("devices %v", labels)
	}
}

func TestDHCPIsOffWithoutItsConfiguration(t *testing.T) {
	var off *DHCP
	if _, err := off.State(); !errors.Is(err, errDHCPOff) {
		t.Fatal(err)
	}
	f := newDHCPFixture(t)
	os.Remove(f.conf)
	if _, err := f.d.State(); !errors.Is(err, errDHCPOff) {
		t.Fatal(err)
	}
}

func TestDHCPRangeIsCheckedAndChangedInPlace(t *testing.T) {
	f := newDHCPFixture(t)
	for _, bad := range []struct {
		r    DHCPRange
		want string
	}{
		{DHCPRange{Start: "10.61.31.10", End: "10.61.30.20"}, "10.61.30.0/24"},
		{DHCPRange{Start: "10.61.30.90", End: "10.61.30.80"}, "大于"},
		{DHCPRange{Start: "10.61.30.1", End: "10.61.30.50"}, "10.61.30.1"},
		{DHCPRange{Start: "10.61.30.100", End: "10.61.30.255"}, "10.61.30.255"},
		{DHCPRange{Start: "10.61.30.100", End: "10.61.30.200", Lease: "soon"}, "租期"},
		{DHCPRange{Start: "10.61.30.100", End: "10.61.30.200", Lease: "30s"}, "2 分钟"},
	} {
		if _, err := f.d.SetRange(bad.r, "admin"); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%+v: %v", bad.r, err)
		}
	}
	before := read(t, f.conf)
	state, err := f.d.SetRange(DHCPRange{Start: "10.61.30.50", End: "10.61.30.99"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Range != (DHCPRange{Start: "10.61.30.50", End: "10.61.30.99", Lease: "12h"}) {
		t.Fatalf("range %+v", state.Range)
	}
	after := read(t, f.conf)
	if strings.Replace(before, "dhcp-range=10.61.30.100,10.61.30.200,", "dhcp-range=10.61.30.50,10.61.30.99,", 1) != after {
		t.Fatalf("only the range line may change:\n%s", after)
	}
	if !slices.Contains(f.commands, "systemctl restart vpp-router-dnsmasq.service") {
		t.Fatalf("commands %v", f.commands)
	}
	// dnsmasq failing on the new range gets the old one back.
	f.fail = "systemctl restart"
	if _, err := f.d.SetRange(DHCPRange{Start: "10.61.30.60", End: "10.61.30.70", Lease: "1h"}, "admin"); err == nil {
		t.Fatal("a failed restart was not reported")
	}
	if read(t, f.conf) != after {
		t.Fatal("the range was not put back")
	}
}

func TestStaticHostsAreAddedReplacedAndDeleted(t *testing.T) {
	f := newDHCPFixture(t)
	for _, bad := range []struct {
		h    StaticHost
		want string
	}{
		{StaticHost{MAC: "nope", IP: "10.61.30.40"}, "MAC"},
		{StaticHost{MAC: "01:00:5e:00:00:01", IP: "10.61.30.40"}, "组播"},
		{StaticHost{MAC: "02:00:00:00:30:09", IP: "10.61.29.40"}, "10.61.30.0/24"},
		{StaticHost{MAC: "02:00:00:00:30:09", IP: "10.61.30.2"}, "网关"},
		{StaticHost{MAC: "02:00:00:00:30:09", IP: "10.61.30.20"}, "已经分配"},
		{StaticHost{MAC: "02:00:00:00:30:09", IP: "10.61.30.101"}, "正在被"},
		{StaticHost{MAC: "02:00:00:00:30:09", IP: "10.61.30.40", Name: "my printer"}, "名字"},
	} {
		if _, err := f.d.SetHost(bad.h, "admin"); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%+v: %v", bad.h, err)
		}
	}
	// The expired lease's address is free.
	if _, err := f.d.SetHost(StaticHost{MAC: "02-00-00-00-30-09", IP: "10.61.30.102", Name: "printer"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.SetHost(StaticHost{MAC: "02:00:00:00:30:01", IP: "10.61.30.21"}, "admin"); err != nil {
		t.Fatal(err)
	}
	want := "# static\n02:00:00:00:30:01,10.61.30.21\nid:01:02,10.61.30.30\n02:00:00:00:30:09,10.61.30.102,printer\n"
	if got := read(t, f.hosts); got != want {
		t.Fatalf("hosts:\n%s", got)
	}
	if _, err := f.d.DeleteHost("02:00:00:00:30:09", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.DeleteHost("02:00:00:00:30:09", "admin"); err == nil {
		t.Fatal("deleted twice")
	}
	if got := read(t, f.hosts); got != "# static\n02:00:00:00:30:01,10.61.30.21\nid:01:02,10.61.30.30\n" {
		t.Fatalf("hosts:\n%s", got)
	}
	if n := strings.Count(strings.Join(f.commands, "\n"), "systemctl reload vpp-router-dnsmasq.service"); n != 3 {
		t.Fatalf("reloads %d: %v", n, f.commands)
	}
	if slices.ContainsFunc(f.commands, func(c string) bool { return strings.HasPrefix(c, "systemctl restart") }) {
		t.Fatal("static hosts must not restart dnsmasq")
	}
}

func event(t *testing.T, path string, now time.Time, env map[string]string, args ...string) {
	t.Helper()
	getenv := func(key string) string {
		if key == "VPP_INTERFACES_CLIENTS" {
			return path
		}
		return env[key]
	}
	if code := dhcpEvent(args, getenv, now); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestDHCPScriptRecordsWhatClientsSay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	phone := map[string]string{"DNSMASQ_SUPPLIED_HOSTNAME": "Pixel-8", "DNSMASQ_VENDOR_CLASS": "android-dhcp-14",
		"DNSMASQ_REQUESTED_OPTIONS": "1,3,6,15,26,28,51,58,59,43,114,108", "DNSMASQ_CLIENT_ID": "01:da:00:00:00:00:01"}
	event(t, path, dhcpNow, phone, "add", "DA:00:00:00:00:01", "10.61.30.150")
	event(t, path, dhcpNow.Add(time.Hour), map[string]string{}, "old", "da:00:00:00:00:01", "10.61.30.151")
	event(t, path, dhcpNow.Add(2*time.Hour), map[string]string{}, "del", "da:00:00:00:00:01", "10.61.30.151")
	event(t, path, dhcpNow, phone, "add", "00:01:00:01:aa:bb:cc", "fd00::5") // DHCPv6
	event(t, path, dhcpNow, phone, "tftp", "1000", "10.61.30.150", "/boot")
	clients, err := readClients(path)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := clients["da:00:00:00:00:01"]
	if len(clients) != 1 || !ok {
		t.Fatalf("clients %+v", clients)
	}
	if c.Hostname != "Pixel-8" || c.Vendor != "android-dhcp-14" || c.Params == "" || c.IP != "10.61.30.151" ||
		!c.First.Equal(dhcpNow) || !c.Last.Equal(dhcpNow.Add(2*time.Hour)) {
		t.Fatalf("client %+v", c)
	}
}

func deviceOf(state *DHCPState, mac string) *DeviceView {
	for i, d := range state.Devices {
		for _, m := range d.MACs {
			if m.MAC == mac {
				return &state.Devices[i]
			}
		}
	}
	return nil
}

func TestRandomMACsJoinTheirDeviceOnlyWhenCertain(t *testing.T) {
	f := newDHCPFixture(t)
	phone := map[string]string{"DNSMASQ_SUPPLIED_HOSTNAME": "Pixel-8", "DNSMASQ_VENDOR_CLASS": "android-dhcp-14",
		"DNSMASQ_REQUESTED_OPTIONS": "1,3,6,15,26,28,51,58,59"}
	other := map[string]string{"DNSMASQ_SUPPLIED_HOSTNAME": "iPhone", "DNSMASQ_REQUESTED_OPTIONS": "1,121,3,6,15,108,114,119,252"}
	event(t, f.d.opts.Clients, dhcpNow.Add(-48*time.Hour), phone, "add", "da:00:00:00:00:01", "10.61.30.150")
	event(t, f.d.opts.Clients, dhcpNow.Add(-24*time.Hour), phone, "add", "fa:00:00:00:00:02", "10.61.30.151")
	// A universal MAC never joins by the rule, even with the same name and fingerprint.
	event(t, f.d.opts.Clients, dhcpNow.Add(-23*time.Hour), phone, "add", "00:1a:00:00:00:03", "10.61.30.152")
	event(t, f.d.opts.Clients, dhcpNow.Add(-22*time.Hour), other, "add", "da:00:00:00:00:10", "10.61.30.160")
	event(t, f.d.opts.Clients, dhcpNow.Add(-21*time.Hour), other, "add", "da:00:00:00:00:11", "10.61.30.161")
	state, err := f.d.State()
	if err != nil {
		t.Fatal(err)
	}
	pixel := deviceOf(state, "da:00:00:00:00:01")
	if pixel.ID != deviceOf(state, "fa:00:00:00:00:02").ID || len(pixel.MACs) != 2 || !pixel.MACs[1].Auto || pixel.Label != "Pixel-8" {
		t.Fatalf("pixel %+v", pixel)
	}
	if deviceOf(state, "00:1a:00:00:00:03").ID == pixel.ID {
		t.Fatal("a universal MAC joined by the rule")
	}
	// Now two devices go by Pixel-8 (the universal MAC's too), so the next random MAC only
	// suggests both.
	universal := deviceOf(state, "00:1a:00:00:00:03")
	event(t, f.d.opts.Clients, dhcpNow.Add(-time.Hour), phone, "add", "da:00:00:00:00:04", "10.61.30.153")
	state, _ = f.d.State()
	fourth := deviceOf(state, "da:00:00:00:00:04")
	if fourth.ID == pixel.ID || !slices.Equal(fourth.Suggest, []string{pixel.ID, universal.ID}) {
		t.Fatalf("fourth %+v", fourth)
	}
	// Two iPhones: the second one joined the first, as nothing told them apart; split it.
	iphone := deviceOf(state, "da:00:00:00:00:10")
	if iphone.ID != deviceOf(state, "da:00:00:00:00:11").ID {
		t.Fatal("same name and fingerprint, only one device of that name: should have joined")
	}
	state, err = f.d.SplitMAC("da:00:00:00:00:11", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if deviceOf(state, "da:00:00:00:00:11").ID == deviceOf(state, "da:00:00:00:00:10").ID {
		t.Fatal("not split")
	}
	if _, err := f.d.SplitMAC("da:00:00:00:00:11", "admin"); err == nil {
		t.Fatal("split a device of one MAC")
	}
	// Merge the suggested one by hand, and name the result.
	state, err = f.d.MergeDevices(pixel.ID, fourth.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	merged := deviceOf(state, "da:00:00:00:00:04")
	if merged.ID != pixel.ID || len(merged.MACs) != 3 || merged.MACs[2].Auto {
		t.Fatalf("merged %+v", merged)
	}
	if _, err := f.d.NameDevice(pixel.ID, strings.Repeat("长", 33), "admin"); err == nil {
		t.Fatal("long name accepted")
	}
	state, err = f.d.NameDevice(pixel.ID, " 小明的手机 ", "admin")
	if err != nil || deviceOf(state, "da:00:00:00:00:01").Label != "小明的手机" {
		t.Fatalf("named %v %+v", err, deviceOf(state, "da:00:00:00:00:01"))
	}
}

func TestSuggestionsAndForgetting(t *testing.T) {
	f := newDHCPFixture(t)
	phone := map[string]string{"DNSMASQ_SUPPLIED_HOSTNAME": "phone", "DNSMASQ_REQUESTED_OPTIONS": "1,3,6"}
	event(t, f.d.opts.Clients, dhcpNow.Add(-3*time.Hour), phone, "add", "da:00:00:00:00:01", "10.61.30.150")
	event(t, f.d.opts.Clients, dhcpNow.Add(-2*time.Hour), phone, "add", "00:1a:00:00:00:02", "10.61.30.151")
	event(t, f.d.opts.Clients, dhcpNow.Add(-time.Hour), phone, "add", "da:00:00:00:00:03", "10.61.30.152")
	state, err := f.d.State()
	if err != nil {
		t.Fatal(err)
	}
	// A universal MAC goes by the same name, so the random one is only suggested, with both.
	third := deviceOf(state, "da:00:00:00:00:03")
	if len(third.Suggest) != 2 {
		t.Fatalf("suggest %+v", third)
	}
	state, err = f.d.DismissSuggestion(third.ID, "admin")
	if err != nil || len(deviceOf(state, "da:00:00:00:00:03").Suggest) != 0 {
		t.Fatalf("dismissed %v", err)
	}
	// A device with a static host or an active lease stays.
	if _, err := f.d.ForgetDevice(deviceOf(state, "02:00:00:00:30:01").ID, "admin"); err == nil || !strings.Contains(err.Error(), "静态") {
		t.Fatal(err)
	}
	if _, err := f.d.ForgetDevice(deviceOf(state, "02:00:00:00:30:02").ID, "admin"); err == nil || !strings.Contains(err.Error(), "租约") {
		t.Fatal(err)
	}
	state, err = f.d.ForgetDevice(third.ID, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if deviceOf(state, "da:00:00:00:00:03") != nil {
		t.Fatal("forgotten device came back")
	}
	clients, _ := readClients(f.d.opts.Clients)
	if _, ok := clients["da:00:00:00:00:03"]; ok {
		t.Fatal("its client record stayed")
	}
}

func TestDHCPOverTheAPI(t *testing.T) {
	f := newDHCPFixture(t)
	dir := t.TempDir()
	cli := filepath.Join(dir, "router.vpp")
	write(t, cli, "")
	s, err := NewService(Options{CLIFile: cli, StateDir: filepath.Join(dir, "state"), DHCP: f.d.opts}, &fakeSystem{live: installerLive()})
	if err != nil {
		t.Fatal(err)
	}
	s.dhcp = f.d
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	post := func(path, body string) (int, string) {
		response, err := http.Post(server.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}
	response, err := http.Get(server.URL + "/interfaces/dhcp")
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("GET: %v %v", err, response.Status)
	}
	response.Body.Close()
	if code, body := post("/interfaces/dhcp/host", `{"mac":"02:00:00:00:30:09","ip":"10.61.30.40","name":"cam"}`); code != 200 || !strings.Contains(body, `"cam"`) {
		t.Fatalf("host: %d %s", code, body)
	}
	if code, body := post("/interfaces/dhcp/range", `{"start":"10.61.30.1","end":"10.61.30.9"}`); code != 409 || !strings.Contains(body, "10.61.30.1") {
		t.Fatalf("range: %d %s", code, body)
	}
	// Without DHCP the routes answer with the reason.
	s.dhcp = nil
	if code, body := post("/interfaces/dhcp/device/name", `{"id":"d1","name":"x"}`); code != 409 || !strings.Contains(body, "DHCP") {
		t.Fatalf("off: %d %s", code, body)
	}
}

func gatewaySetup(t *testing.T) (*Service, *dhcpFixture, string, *[]string) {
	t.Helper()
	s, _, _ := setup(t, installerFile, "")
	f := newDHCPFixture(t)
	s.dhcp = f.d
	env := filepath.Join(f.dir, "router.env")
	write(t, env, "# vpp-router-ctl\nHOST_TAP=vpp-host\nHOST_CIDR=10.61.30.2/24\nHOST_GW=10.61.30.1\nHOST_DEFAULT=1\n")
	s.opts.RouterEnv = env
	s.linkExists = func(string) bool { return true }
	ran := &[]string{}
	s.run = func(name string, args ...string) error {
		*ran = append(*ran, name+" "+strings.Join(args, " "))
		return nil
	}
	return s, f, env, ran
}

func TestLANGatewayMoveIsFollowedAndUndone(t *testing.T) {
	s, f, env, ran := gatewaySetup(t)
	for _, bad := range []struct{ address, want string }{
		{"10.61.30.150/24", "地址池"}, {"10.61.30.20/24", "静态分配"}, {"10.61.30.2/24", "Linux 管理口"},
	} {
		if _, err := s.SetAddresses("loop0", []string{bad.address}, "admin"); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%s: %v", bad.address, err)
		}
	}
	confBefore, envBefore := read(t, f.conf), read(t, env)
	state, err := s.SetAddresses("loop0", []string{"10.61.30.254/24"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state.Pending.Description, "跟着改成 10.61.30.254") {
		t.Fatalf("description %q", state.Pending.Description)
	}
	if !strings.Contains(read(t, f.conf), "dhcp-option=option:router,10.61.30.254\n") || !strings.Contains(read(t, env), "HOST_GW=10.61.30.254\n") {
		t.Fatalf("not followed:\n%s\n%s", read(t, f.conf), read(t, env))
	}
	if !slices.Contains(*ran, "ip -4 route replace default via 10.61.30.254 dev vpp-host") ||
		!slices.Contains(f.commands, "systemctl restart vpp-router-dnsmasq.service") {
		t.Fatalf("commands %v %v", *ran, f.commands)
	}
	if pending := read(t, filepath.Join(s.opts.StateDir, pendingFile)); !strings.Contains(pending, `"follow"`) {
		t.Fatalf("the follow was not saved for a rollback after a restart: %s", pending)
	}
	if _, err := s.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if read(t, f.conf) != confBefore || read(t, env) != envBefore {
		t.Fatalf("not undone:\n%s\n%s", read(t, f.conf), read(t, env))
	}
	if (*ran)[len(*ran)-1] != "ip -4 route replace default via 10.61.30.1 dev vpp-host" {
		t.Fatalf("route not put back: %v", *ran)
	}
	// Another network is renumbering, which nothing follows yet.
	*ran = nil
	if _, err := s.SetAddresses("loop0", []string{"192.168.9.1/24"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if read(t, f.conf) != confBefore || read(t, env) != envBefore || len(*ran) != 0 {
		t.Fatal("a move to another network was followed")
	}
	s.Rollback("admin")
}

func TestLANGatewayMoveThatCannotFollowIsUndone(t *testing.T) {
	s, f, env, _ := gatewaySetup(t)
	confBefore, envBefore := read(t, f.conf), read(t, env)
	f.fail = "systemctl restart"
	if _, err := s.SetAddresses("loop0", []string{"10.61.30.254/24"}, "admin"); err == nil || !strings.Contains(err.Error(), "已恢复") {
		t.Fatal(err)
	}
	if s.pending != nil {
		t.Fatal("left pending")
	}
	if read(t, f.conf) != confBefore || read(t, env) != envBefore {
		t.Fatal("dnsmasq or router.env changed")
	}
	if !strings.Contains(read(t, s.opts.CLIFile), "set interface ip address loop0 10.61.30.1/24") {
		t.Fatal("the CLI file was not put back")
	}
}
