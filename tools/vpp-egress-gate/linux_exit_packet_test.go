package gate

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A client and server for real traffic. TCP_MAXSEG shows the MSS each side was told.
const packetHelper = `
import socket, sys, threading
mode = sys.argv[1]
def echo(c):
    try:
        while True:
            data = c.recv(65536)
            if not data:
                break
            c.sendall(data)
    except OSError:
        pass
    c.close()
if mode == 'tcp':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[2], int(sys.argv[3])))
    s.listen(16)
    print('ready', flush=True)
    while True:
        c, peer = s.accept()
        print('tcp', peer[0], c.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG), flush=True)
        threading.Thread(target=echo, args=(c,), daemon=True).start()
elif mode == 'udp':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((sys.argv[2], int(sys.argv[3])))
    print('ready', flush=True)
    while True:
        data, peer = s.recvfrom(4096)
        print('udp', peer[0], flush=True)
        s.sendto(data, peer)
elif mode == 'connect':
    source, target, port, size = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(sys.argv[6]))
    try:
        s.bind((source, 0))
        s.connect((target, port))
        mss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        payload = bytes(i % 251 for i in range(size))
        threading.Thread(target=s.sendall, args=(payload,), daemon=True).start()
        received = bytearray()
        while len(received) < size:
            data = s.recv(65536)
            if not data:
                break
            received += data
        print('ok', mss) if bytes(received) == payload else print('fail corrupted', len(received))
    except OSError as error:
        print('fail', type(error).__name__)
`

type packetLab struct {
	t       *testing.T
	script  string
	cfg     *Config
	backend *VPPBackend
}

const (
	labLAN, labFarWG, labFarPPP, labWAN = "gt-lan", "gt-far-wg", "gt-far-ppp", "gt-wan"
	labClient                           = "10.64.30.2"
	labNeighbor, labNeighborAddress     = "gt-nbr", "10.99.4.2"
	labWGHost, labPPPHost               = "203.0.113.7", "203.0.113.8"
)

func (l *packetLab) run(ns string, args ...string) string {
	l.t.Helper()
	out, err := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...).CombinedOutput()
	if err != nil {
		l.t.Fatalf("%s %v: %v\n%s", ns, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (l *packetLab) host(args ...string) string {
	l.t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		l.t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// labServer records what a helper server in a namespace reports.
type labServer struct {
	mu    sync.Mutex
	lines []string
}

func (s *labServer) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.lines
	s.lines = nil
	return out
}

func (l *packetLab) serve(ns, kind, address string, port int) *labServer {
	l.t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, "python3", "-u", l.script, kind, address, fmt.Sprint(port))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	server := &labServer{}
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "ready" {
				close(ready)
				continue
			}
			server.mu.Lock()
			server.lines = append(server.lines, scanner.Text())
			server.mu.Unlock()
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		l.t.Fatalf("server in %s did not start", ns)
	}
	return server
}

func (l *packetLab) connect(ns, source, target string, port, size int) string {
	l.t.Helper()
	return l.run(ns, "python3", l.script, "connect", source, target, fmt.Sprint(port), fmt.Sprint(size), "2")
}

func (l *packetLab) expectOK(ns, source, target string, port int) string {
	l.t.Helper()
	result := l.connect(ns, source, target, port, 200000)
	if !strings.HasPrefix(result, "ok") {
		l.t.Fatalf("%s -> %s:%d: %s", source, target, port, result)
	}
	return result
}

func (l *packetLab) expectBlocked(ns, source, target string, port int) string {
	l.t.Helper()
	result := l.connect(ns, source, target, port, 100)
	if !strings.HasPrefix(result, "fail") {
		l.t.Fatalf("%s -> %s:%d should be blocked: %s", source, target, port, result)
	}
	return result
}

func (l *packetLab) expectNothing(name string, server *labServer) {
	l.t.Helper()
	if lines := server.take(); len(lines) != 0 {
		l.t.Fatalf("traffic reached %s: %v", name, lines)
	}
}

func (l *packetLab) veth(inner, outer, ns string) {
	l.t.Helper()
	l.host("ip", "link", "add", inner, "type", "veth", "peer", "name", outer)
	l.host("ip", "link", "set", outer, "netns", ns)
	l.host("ip", "link", "set", inner, "up")
	l.run(ns, "ip", "link", "set", outer, "up")
}

func newPacketLab(t *testing.T) *packetLab {
	t.Helper()
	if os.Getenv("GATE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	l := &packetLab{t: t, script: filepath.Join(dir, "helper.py")}
	if err := os.WriteFile(l.script, []byte(packetHelper), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{labLAN, labFarWG, labFarPPP, labWAN, labNeighbor} {
		l.host("ip", "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		l.run(ns, "ip", "link", "set", "lo", "up")
		l.run(ns, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")
	}
	l.host("ip", "link", "set", "lo", "up")
	l.host("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0")

	// LAN side, standing in for VPP: its routes pick the device, and so the exit.
	l.veth("tap-gate-wg", "lan0", labLAN)
	l.veth("tap-gate-ppp", "lan1", labLAN)
	l.run(labLAN, "ip", "addr", "add", "172.30.10.1/30", "dev", "lan0")
	l.run(labLAN, "ip", "addr", "add", "172.30.10.5/30", "dev", "lan1")
	l.run(labLAN, "ip", "addr", "add", labClient+"/32", "dev", "lo")
	l.run(labLAN, "ip", "route", "add", "default", "via", "172.30.10.2")
	l.run(labLAN, "ip", "route", "add", labPPPHost+"/32", "via", "172.30.10.6")

	// Exits. The WireGuard-like one has a smaller MTU than its far side, so only a clamp limits MSS.
	l.veth("gate-wg", "far0", labFarWG)
	l.host("ip", "link", "set", "gate-wg", "mtu", "1400")
	l.host("ip", "addr", "add", "10.99.1.1/30", "dev", "gate-wg")
	l.run(labFarWG, "ip", "addr", "add", "10.99.1.2/30", "dev", "far0")
	l.run(labFarWG, "ip", "addr", "add", labWGHost+"/32", "dev", "lo")
	l.run(labFarWG, "ip", "route", "add", "default", "via", "10.99.1.1")

	l.veth("gate-ppp", "far1", labFarPPP)
	l.host("ip", "addr", "add", "10.99.2.1/30", "dev", "gate-ppp")
	l.run(labFarPPP, "ip", "addr", "add", "10.99.2.2/30", "dev", "far1")
	l.run(labFarPPP, "ip", "addr", "add", labPPPHost+"/32", "dev", "lo")
	l.run(labFarPPP, "ip", "route", "add", "default", "via", "10.99.2.1")

	// The main table's way out holds the same addresses, so any leak connects here.
	l.veth("gate-main", "wan0", labWAN)
	l.host("ip", "addr", "add", "10.99.3.1/30", "dev", "gate-main")
	l.host("ip", "route", "add", "default", "via", "10.99.3.2")
	l.run(labWAN, "ip", "addr", "add", "10.99.3.2/30", "dev", "wan0")
	for _, address := range []string{labWGHost, labPPPHost, "198.51.100.9"} {
		l.run(labWAN, "ip", "addr", "add", address+"/32", "dev", "lo")
	}
	l.run(labWAN, "ip", "route", "add", "default", "via", "10.99.3.1")

	// A machine on some other interface of the host, which Gate's rules do not cover.
	l.veth("gate-nbr", "nbr0", labNeighbor)
	l.host("ip", "addr", "add", "10.99.4.1/30", "dev", "gate-nbr")
	l.run(labNeighbor, "ip", "addr", "add", labNeighborAddress+"/30", "dev", "nbr0")
	l.run(labNeighbor, "ip", "route", "add", "default", "via", "10.99.4.1")

	// Everything from here comes from the device plan, as it would on a router. Veths stand
	// in for the persistent devices, which pass nothing here without VPP attached.
	source := filepath.Join(dir, "source.json")
	writeJSON(t, source, map[string]any{"upstream": []any{"127.0.0.1", 53}, "lan_prefixes": []any{"10.64.30.0/24", "10.62.0.0/16"}, "routes": []any{
		map[string]any{"domains": []any{"wg.example"}, "linux_exit": map[string]any{"interface": "gate-wg", "masquerade": true, "gateway": "10.99.1.2"}},
		map[string]any{"domains": []any{"ppp.example"}, "linux_exit": map[string]any{"interface": "gate-ppp", "block_input": true, "gateway": "10.99.2.2"}},
		map[string]any{"name": "proxy", "domains": []any{"proxy.example"}, "fake_dns": []any{"127.0.0.1", 5354}, "fakeip_range": "198.18.0.0/15"},
	}})
	plan, err := PlanDevices(source, &DeviceState{Devices: map[string]*DeviceEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEffective(plan); err != nil {
		t.Fatal(err)
	}
	fixed := filepath.Join(dir, "fixed.nft")
	if err := os.WriteFile(fixed, []byte(plan.Fixed), 0o644); err != nil {
		t.Fatal(err)
	}
	l.host("ip", "link", "add", "gate-tproxy", "type", "dummy")
	// Hosts with a default-drop iptables FORWARD chain must work too; Gate opens only the TAP.
	if _, err := exec.LookPath("iptables"); err == nil {
		l.host("iptables", "-P", "FORWARD", "DROP")
	}
	// Run twice, as two syncs would.
	for range 2 {
		l.host("nft", "-f", fixed)
		for _, d := range plan.Devices {
			if err := configureDevice(context.Background(), d, plan.LANs); err != nil {
				t.Fatal(err)
			}
		}
		if err := syncMainRoutes(context.Background(), plan.Devices, plan.Retired, plan.LANs); err != nil {
			t.Fatal(err)
		}
	}
	if rules := l.host("ip", "-4", "rule", "show"); strings.Count(rules, "lookup 1002") != 1 {
		t.Fatalf("setup is not idempotent:\n%s", rules)
	}
	if rules := l.host("ip", "-4", "rule", "show"); strings.Count(rules, "iif gate-wg") != 1 || strings.Count(rules, "iif gate-ppp") != 1 {
		t.Fatalf("return rules are not idempotent:\n%s", rules)
	}
	if routes := l.host("ip", "-4", "route", "show", "table", "1002"); !strings.Contains(routes, "local default dev lo") {
		t.Fatalf("TPROXY table: %s", routes)
	}
	if rules := l.host("nft", "list", "table", "inet", "gate_fixed"); strings.Count(rules, `iifname "tap-gate-wg" meta mark`) != 1 {
		t.Fatalf("reload duplicated the guard:\n%s", rules)
	}

	path := filepath.Join(dir, "gate.json")
	if err := os.WriteFile(path, []byte(plan.Effective), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DomainRoutesFromFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.StateFile = filepath.Join(dir, "state.json")
	l.cfg, l.backend = cfg, &VPPBackend{Config: cfg}
	t.Cleanup(func() { delete(linuxExitStates, cfg.StateFile) })
	if err := l.backend.EnsureLinuxExits(); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *packetLab) state() *linuxExitState { return linuxExitStates[l.cfg.StateFile] }

// repair runs the steps of a background pass that do not need VPP.
func (l *packetLab) repair() {
	l.t.Helper()
	state := l.state()
	if err := l.backend.prepareLinuxExits(state); err != nil {
		l.t.Fatal(err)
	}
	if err := applyNft([]string{linuxExitNftScript(l.cfg, state.mtus)}, "repair"); err != nil {
		l.t.Fatal(err)
	}
}

func TestLinuxExitPackets(t *testing.T) {
	l := newPacketLab(t)
	const port = 8080
	farWG := l.serve(labFarWG, "tcp", "0.0.0.0", port)
	farPPP := l.serve(labFarPPP, "tcp", "0.0.0.0", port)
	wan := l.serve(labWAN, "tcp", "0.0.0.0", port)
	lan := l.serve(labLAN, "tcp", "0.0.0.0", port)
	local := l.serve(labFarWG, "udp", labWGHost, 5353)
	wanUDP := l.serve(labWAN, "udp", labWGHost, 5353)
	reset := func() {
		for _, s := range []*labServer{farWG, farPPP, wan, lan, local, wanUDP} {
			s.take()
		}
	}
	step := func(name string, body func(t *testing.T)) {
		reset()
		t.Run(name, func(t *testing.T) {
			l.t = t
			body(t)
		})
		if t.Failed() {
			l.t = t
			for _, args := range [][]string{{"nft", "list", "ruleset"}, {"ip", "rule"}, {"ip", "route", "show", "table", "all"}, {"ip", "-br", "addr"}, {"ip", "neigh"}, {"sysctl", "net.ipv4.ip_forward", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.gate-wg.rp_filter", "net.ipv4.conf.tap-gate-wg.rp_filter"}} {
				out, _ := exec.Command(args[0], args[1:]...).CombinedOutput()
				t.Logf("%v:\n%s", args, out)
			}
			t.FailNow()
		}
	}

	step("traffic_uses_its_exit_and_masquerades", func(t *testing.T) {
		result := l.expectOK(labLAN, labClient, labWGHost, port)
		lines := farWG.take()
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "tcp 10.99.1.1 ") {
			t.Fatalf("far side saw %v, client %s", lines, result)
		}
		l.expectNothing("main table exit", wan)
	})
	step("exit_without_masquerade_keeps_client_address", func(t *testing.T) {
		l.expectOK(labLAN, labClient, labPPPHost, port)
		lines := farPPP.take()
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "tcp "+labClient+" ") {
			t.Fatalf("far side saw %v", lines)
		}
		l.expectNothing("main table exit", wan)
	})
	step("mss_is_clamped_in_both_directions", func(t *testing.T) {
		// Earlier traffic taught both ends the path MTU, which would hide a missing clamp.
		l.run(labLAN, "ip", "route", "flush", "cache")
		l.run(labFarWG, "ip", "route", "flush", "cache")
		// TCP_MAXSEG excludes the 12 bytes of timestamps: a clamp to 1360 reads 1348, none reads 1448.
		client := l.expectOK(labLAN, labClient, labWGHost, port)
		if client != "ok 1348" {
			t.Fatalf("client MSS (reply clamp): %s", client)
		}
		if lines := farWG.take(); len(lines) != 1 || !strings.HasSuffix(lines[0], " 1348") {
			t.Fatalf("server MSS (forward clamp): %v", lines)
		}
		// The other exit's MTU is 1500, so its traffic must not be lowered by this one's.
		if client := l.expectOK(labLAN, labClient, labPPPHost, port); client != "ok 1448" {
			t.Fatalf("other exit MSS: %s", client)
		}
	})
	step("reply_returns_through_the_device_of_its_exit", func(t *testing.T) {
		for _, tc := range []struct{ exit, device string }{{"gate-wg", "tap-gate-wg"}, {"gate-ppp", "tap-gate-ppp"}} {
			out := l.host("ip", "route", "get", labClient, "from", "203.0.113.7", "iif", tc.exit)
			if !strings.Contains(out, "dev "+tc.device) {
				t.Fatalf("reply from %s: %s", tc.exit, out)
			}
		}
	})
	step("destination_beyond_the_exit_does_not_leak", func(t *testing.T) {
		l.expectBlocked(labLAN, labClient, "198.51.100.9", port)
		l.expectNothing("main table exit", wan)
	})
	step("exit_cannot_open_connections_to_lan", func(t *testing.T) {
		l.expectBlocked(labFarWG, labWGHost, labClient, port)
		l.expectBlocked(labFarPPP, labPPPHost, labClient, port)
		l.expectNothing("LAN", lan)
	})
	step("block_input_applies_only_to_its_exit", func(t *testing.T) {
		// This process is in the Gate namespace, so its listeners are Linux's local services.
		ln, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					buf := make([]byte, 65536)
					for {
						n, err := conn.Read(buf)
						if err != nil {
							return
						}
						if _, err := conn.Write(buf[:n]); err != nil {
							return
						}
					}
				}()
			}
		}()
		service := ln.Addr().(*net.TCPAddr).Port
		l.expectOK(labFarWG, "10.99.1.2", "10.99.1.1", service)
		l.expectBlocked(labFarPPP, "10.99.2.2", "10.99.2.1", service)
		// Replies to Linux's own connections still arrive through the blocked exit.
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort("10.99.2.2", fmt.Sprint(port)), 2*time.Second)
		if err != nil {
			t.Fatalf("outgoing connection through block_input exit: %v", err)
		}
		conn.Close()
	})
	step("a_neighbor_needs_the_hosts_firewall_to_stop_it", func(t *testing.T) {
		if _, err := exec.LookPath("iptables"); err != nil {
			t.Skip("iptables not available")
		}
		const farWGAddress = "10.99.1.2"
		// The lab's default-drop FORWARD chain is what the warning asks for.
		if !forwardingIsFiltered(context.Background(), 4) {
			t.Fatal("the default drop was not detected")
		}
		l.expectBlocked(labNeighbor, labNeighborAddress, "198.51.100.9", port)
		l.expectBlocked(labNeighbor, labNeighborAddress, farWGAddress, port)
		l.expectNothing("WAN", wan)
		l.expectNothing("far side of the exit", farWG)
		l.host("iptables", "-P", "FORWARD", "ACCEPT")
		defer l.host("iptables", "-P", "FORWARD", "DROP")
		if forwardingIsFiltered(context.Background(), 4) {
			t.Fatal("an open chain counted as filtered")
		}
		// Gate's own rules do not stop these, which is what the warning is about. A small
		// payload is enough to show the path, and Gate clamps no MSS for this traffic.
		for _, target := range []string{"198.51.100.9", farWGAddress} {
			if result := l.connect(labNeighbor, labNeighborAddress, target, port, 100); !strings.HasPrefix(result, "ok") {
				t.Fatalf("%s -> %s: %s", labNeighborAddress, target, result)
			}
		}
		// The exit's own guard still stands: nothing new reaches the client side.
		l.expectBlocked(labFarWG, "10.99.1.2", labClient, port)
	})
	step("rp_filter_on_exit_is_repaired", func(t *testing.T) {
		const path = "/proc/sys/net/ipv4/conf/gate-wg/rp_filter"
		// Control: strict filtering does drop replies here, so the repair below is what fixes them.
		if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		l.expectBlocked(labLAN, labClient, labWGHost, port)
		l.repair()
		if data, _ := os.ReadFile(path); strings.TrimSpace(string(data)) != "0" {
			t.Fatalf("rp_filter %q", data)
		}
		l.expectOK(labLAN, labClient, labWGHost, port)
	})
	step("dns_query_leaves_through_the_exit", func(t *testing.T) {
		query := func(mark uint32) error {
			dialer := net.Dialer{Timeout: time.Second}
			if mark != 0 {
				dialer.Control = markedDialControl(mark)
			}
			conn, err := dialer.Dial("udp4", net.JoinHostPort(labWGHost, "5353"))
			if err != nil {
				return err
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("q")); err != nil {
				return err
			}
			_, err = conn.Read(make([]byte, 16))
			return err
		}
		// Control: an unmarked socket follows the main table, as the query did before the fix.
		if err := query(0); err != nil {
			t.Fatal(err)
		}
		if lines := wanUDP.take(); len(lines) != 1 {
			t.Fatalf("control query did not use the main table: %v", lines)
		}
		l.expectNothing("exit", local)
		if err := query(101); err != nil {
			t.Fatal(err)
		}
		if lines := local.take(); len(lines) != 1 || lines[0] != "udp 10.99.1.1" {
			t.Fatalf("exit saw %v", lines)
		}
		l.expectNothing("main table exit", wanUDP)

		// A lost policy rule must not send the marked query out of the main table.
		l.host("ip", "rule", "del", "priority", "11101", "iif", "lo", "fwmark", "101", "lookup", "1101")
		if err := query(101); err == nil {
			t.Fatal("query succeeded without its policy rule")
		}
		l.expectNothing("main table exit", wanUDP)
		l.repair()
		if err := query(101); err != nil {
			t.Fatalf("query after repair: %v", err)
		}
	})
	step("down_exit_fails_closed_and_recovers", func(t *testing.T) {
		l.host("ip", "link", "set", "gate-wg", "down")
		l.repair()
		if status := l.state().status["gate-wg/1101"]; !strings.Contains(status, "unavailable") {
			t.Fatalf("status %q", status)
		}
		// Unreachable is rejected at once rather than timing out.
		if result := l.expectBlocked(labLAN, labClient, labWGHost, port); !strings.Contains(result, "OSError") && !strings.Contains(result, "Unreachable") && !strings.Contains(result, "timeout") {
			t.Fatalf("result %s", result)
		}
		l.expectNothing("main table exit", wan)
		// The other exit is unaffected.
		l.expectOK(labLAN, labClient, labPPPHost, port)

		dialer := net.Dialer{Control: markedDialControl(101)}
		if conn, err := dialer.Dial("udp4", net.JoinHostPort(labWGHost, "5353")); err == nil {
			conn.Close()
			t.Fatal("marked DNS socket routed while its exit is down")
		}

		l.host("ip", "link", "set", "gate-wg", "up")
		l.repair()
		if status := l.state().status["gate-wg/1101"]; status != "available" {
			t.Fatalf("status %q", status)
		}
		if result := l.expectOK(labLAN, labClient, labWGHost, port); result != "ok 1348" {
			t.Fatalf("after recovery: %s", result)
		}
	})
	step("missing_exit_does_not_stop_a_restart", func(t *testing.T) {
		// Moving the link away looks like an interface that has not been created yet.
		l.host("ip", "link", "set", "gate-ppp", "netns", labWAN)
		delete(linuxExitStates, l.cfg.StateFile)
		if err := l.backend.EnsureLinuxExits(); err != nil {
			t.Fatalf("restart with a missing exit: %v", err)
		}
		l.expectOK(labLAN, labClient, labWGHost, port)
		l.expectBlocked(labLAN, labClient, labPPPHost, port)
		l.expectNothing("main table exit", wan)
		l.run(labWAN, "ip", "link", "set", "gate-ppp", "netns", "1")
	})
	step("restart_is_idempotent_and_occupied_table_is_refused", func(t *testing.T) {
		delete(linuxExitStates, l.cfg.StateFile)
		if err := l.backend.EnsureLinuxExits(); err != nil {
			t.Fatalf("restart: %v", err)
		}
		l.expectOK(labLAN, labClient, labWGHost, port)
		rules := l.host("ip", "-4", "rule", "show", "priority", "11101")
		if strings.Count(rules, "lookup 1101") != 2 {
			t.Fatalf("rules after restart:\n%s", rules)
		}
		l.host("ip", "route", "add", "local", "10.77.0.0/16", "dev", "lo", "table", "1101")
		delete(linuxExitStates, l.cfg.StateFile)
		err := l.backend.EnsureLinuxExits()
		if err == nil || !strings.Contains(err.Error(), "occupied") {
			t.Fatalf("occupied table accepted: %v", err)
		}
		l.host("ip", "route", "del", "local", "10.77.0.0/16", "dev", "lo", "table", "1101")
		if err := l.backend.EnsureLinuxExits(); err != nil {
			t.Fatalf("restart after clearing: %v", err)
		}
	})
	step("iptables_restore_is_repaired", func(t *testing.T) {
		if _, err := exec.LookPath("iptables"); err != nil {
			t.Skip("iptables not available")
		}
		if rules := l.host("iptables", "-S", "FORWARD"); strings.Count(rules, "tap-gate-wg") != 2 {
			t.Fatalf("iptables rules:\n%s", rules)
		}
		// What a firewall tool restoring saved rules does.
		l.host("iptables", "-F", "FORWARD")
		l.expectBlocked(labLAN, labClient, labWGHost, port)
		l.repair()
		l.repair()
		if rules := l.host("iptables", "-S", "FORWARD"); strings.Count(rules, "tap-gate-wg") != 2 {
			t.Fatalf("iptables rules after repair:\n%s", rules)
		}
		l.expectOK(labLAN, labClient, labWGHost, port)
	})
	step("firewall_reload_fails_closed_and_recovers", func(t *testing.T) {
		l.host("nft", "delete", "table", "inet", "egress_gate_linux")
		l.expectBlocked(labLAN, labClient, labWGHost, port)
		l.expectNothing("main table exit", wan)
		// Control: without the installer's guard the same reload does leak. This proves the check can see one.
		l.host("nft", "delete", "table", "inet", "gate_fixed")
		l.expectOK(labLAN, labClient, labWGHost, port)
		if lines := wan.take(); len(lines) == 0 {
			t.Fatal("control did not reach the main table exit")
		}
		reset()
		// The next background pass rebuilds Gate's table.
		l.repair()
		l.expectOK(labLAN, labClient, labWGHost, port)
		if lines := farWG.take(); len(lines) != 1 {
			t.Fatalf("exit saw %v", lines)
		}
		l.expectNothing("main table exit", wan)
	})
}

// Reads a real WireGuard device rather than relying on the documented output format.
func TestLinuxExitUnderlayKernel(t *testing.T) {
	if os.Getenv("GATE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wg not available")
	}
	ctx := context.Background()
	if _, err := runCmdContext(ctx, "ip", "link", "add", "gate-wgreal", "type", "wireguard"); err != nil {
		t.Skipf("WireGuard unavailable: %v", err)
	}
	defer func() { _, _ = runCmdContext(ctx, "ip", "link", "del", "gate-wgreal") }()
	key := filepath.Join(t.TempDir(), "key")
	private, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, private, 0o600); err != nil {
		t.Fatal(err)
	}
	// A device silently ignores a peer with its own key, so the peer needs a different one.
	peer, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		t.Fatal(err)
	}
	genpub := exec.Command("wg", "pubkey")
	genpub.Stdin = strings.NewReader(string(peer))
	public, err := genpub.Output()
	if err != nil {
		t.Fatal(err)
	}
	if prefixes, present, err := linuxExitUnderlay(ctx, "gate-wgreal"); err != nil || !present || len(prefixes) != 0 {
		t.Fatalf("no peers: %v %v %v", prefixes, present, err)
	}
	if out, err := exec.Command("wg", "set", "gate-wgreal", "private-key", key, "peer", strings.TrimSpace(string(public)), "endpoint", "203.0.113.50:51820", "allowed-ips", "0.0.0.0/0").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	prefixes, present, err := linuxExitUnderlay(ctx, "gate-wgreal")
	if err != nil || !present || len(prefixes) != 1 || prefixes[0] != "203.0.113.50/32" {
		t.Fatalf("endpoint: %v %v %v", prefixes, present, err)
	}
	if _, err := runCmdContext(ctx, "ip", "link", "add", "gate-gre", "type", "gre", "remote", "203.0.113.51", "local", "192.0.2.9"); err == nil {
		defer func() { _, _ = runCmdContext(ctx, "ip", "link", "del", "gate-gre") }()
		if prefixes, _, err := linuxExitUnderlay(ctx, "gate-gre"); err != nil || len(prefixes) != 1 || prefixes[0] != "203.0.113.51/32" {
			t.Fatalf("gre remote: %v %v", prefixes, err)
		}
	}
	if _, present, err := linuxExitUnderlay(ctx, "gate-absent"); err != nil || present {
		t.Fatalf("absent: %v %v", present, err)
	}
}
