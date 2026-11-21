package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const installerConf = `# 由 vpp-router-install.sh 生成
unix {
  nodaemon
  runtime-dir /run/vpp
  cli-listen /run/vpp/cli.sock
  startup-config /etc/vpp/router.vpp
}
socksvr { socket-name /run/vpp/api.sock }
memory { main-heap-size 1G }
buffers { buffers-per-numa 16384 }
cpu { main-core 1 corelist-workers 2-3 }
plugins {
  path /usr/local/lib/vpp-router/vpp_plugins
  plugin default { disable }
  plugin dpdk_plugin.so { enable }
}
dpdk {
  uio-driver vfio-pci
  dev 0000:01:00.0 { name port0 num-rx-queues 2 }
  dev 0000:02:00.0 { name port1 }
}
`

// Hand-written, in the shape of the RK3588 board's startup.conf.
const handConf = `unix {
  nodaemon
  startup-config /etc/vpp/topology.vpp # the CLI file
}
cpu {
  main-core 0
  corelist-workers 4
  # skip-cores 2
  relative
}
dpdk {
  dev default {
    num-rx-queues 1
  }
  dev 0000:01:00.0
  dev 0001:01:00.0 {
    name eth2-dpdk
  }
}
`

const routerVPP = `# 由 vpp-router-install.sh 生成
set interface state port0 up

# NAT44-EI：只翻译从 WAN 发出的流量
nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384
set nat44 ei timeout tcp-established 1800 tcp-transitory 120
nat44 ei add interface address port0
set interface nat44 ei out port0 output-feature
`

func TestStartConfCPU(t *testing.T) {
	conf, err := parseStartConf(installerConf)
	if err != nil {
		t.Fatal(err)
	}
	cpu, err := conf.cpu()
	if err != nil {
		t.Fatal(err)
	}
	if *cpu.MainCore != 1 || !slices.Equal(cpu.Workers, []int{2, 3}) {
		t.Fatalf("cpu %+v", cpu)
	}
	devs := conf.dpdkDevs()
	if len(devs) != 2 || devs[0].Name != "port0" || devs[0].Queues != 2 || devs[1].Queues != 0 {
		t.Fatalf("devs %+v", devs)
	}
	main := 0
	text, err := conf.withThreads(&cpuConf{MainCore: &main, Workers: []int{1, 2, 3}, Policy: "fifo", Priority: new(int)}, map[string]int{"0000:01:00.0": 3, "0000:02:00.0": 3})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.NewReplacer(
		"cpu { main-core 1 corelist-workers 2-3 }", "cpu { main-core 0 corelist-workers 1-3 scheduler-policy fifo scheduler-priority 0 }",
		"name port0 num-rx-queues 2 }", "name port0 num-rx-queues 3 }",
		"{ name port1 }", "{ num-rx-queues 3 name port1 }",
	).Replace(installerConf)
	if text != want {
		t.Fatalf("got\n%s\nwant\n%s", text, want)
	}
}

func TestStartConfHandWritten(t *testing.T) {
	conf, err := parseStartConf(handConf)
	if err != nil {
		t.Fatal(err)
	}
	cpu, err := conf.cpu()
	if err != nil {
		t.Fatal(err)
	}
	if *cpu.MainCore != 0 || !slices.Equal(cpu.Workers, []int{4}) || !slices.Equal(cpu.Other, []string{"relative"}) {
		t.Fatalf("cpu %+v", cpu)
	}
	devs := conf.dpdkDevs()
	if len(devs) != 3 || devs[0].Address != "default" || devs[0].Queues != 1 || devs[2].Name != "eth2-dpdk" {
		t.Fatalf("devs %+v", devs)
	}
	main := 0
	cpu.MainCore, cpu.Workers = &main, []int{4, 5}
	text, err := conf.withThreads(cpu, map[string]int{"0000:01:00.0": 2, "1:1:0.0": 2})
	if err != nil {
		t.Fatal(err)
	}
	want := `unix {
  nodaemon
  startup-config /etc/vpp/topology.vpp # the CLI file
}
cpu { main-core 0 corelist-workers 4-5 relative }
dpdk {
  dev default {
    num-rx-queues 1
  }
  dev 0000:01:00.0 { num-rx-queues 2 }
  dev 0001:01:00.0 { num-rx-queues 2
    name eth2-dpdk
  }
}
`
	if text != want {
		t.Fatalf("got\n%s", text)
	}
	if _, err := parseStartConf(text); err != nil {
		t.Fatal(err)
	}
	if cliFileFromConfig(handConf) != "/etc/vpp/topology.vpp" {
		t.Fatal("cli file")
	}
}

func TestStartConfNoCPU(t *testing.T) {
	conf, _ := parseStartConf("unix { nodaemon }")
	main := 2
	text, _ := conf.withThreads(&cpuConf{MainCore: &main}, nil)
	if text != "unix { nodaemon }\ncpu { main-core 2 }\n" {
		t.Fatalf("%q", text)
	}
	for _, bad := range []string{"unix { nodaemon", "unix } {", "{ x }"} {
		if _, err := parseStartConf(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestCoreList(t *testing.T) {
	list, err := parseCoreList("1,3-5,4")
	if err != nil || !slices.Equal(list, []int{1, 3, 4, 5}) || formatCoreList(list) != "1,3-5" {
		t.Fatal(list, err)
	}
	if list, _ := parseCoreMask("0x1c"); !slices.Equal(list, []int{2, 3, 4}) {
		t.Fatal(list)
	}
	for _, bad := range []string{"", "a", "3-1", "-1"} {
		if _, err := parseCoreList(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestCLIFileNAT(t *testing.T) {
	file := parseCLI(routerVPP)
	size, ok := file.natSize()
	if !ok || size != (natSize{65536, 4096, 16384}) {
		t.Fatal(size, ok)
	}
	if got := file.timeouts(); got != (natTimeouts{UDP: 300, TCPEstablished: 1800, TCPTransitory: 120, ICMP: 60}) {
		t.Fatal(got)
	}
	file.setNATSize(natSize{131072, 8192, 32768})
	file.setTimeouts(natTimeouts{600, 3600, 60, 30})
	want := strings.NewReplacer(
		"sessions 65536 users 4096 user-sessions 16384", "sessions 131072 users 8192 user-sessions 32768",
		"timeout tcp-established 1800 tcp-transitory 120", "timeout udp 600 tcp-established 3600 tcp-transitory 60 icmp 30",
	).Replace(routerVPP)
	if file.String() != want {
		t.Fatalf("got\n%s", file.String())
	}

	file = parseCLI("nat44 ei plugin enable static-mapping-only\nset nat44 ei timeout udp 100\nset nat44 ei timeout icmp 5\n")
	file.setTimeouts(natTimeouts{1, 2, 3, 4})
	file.setNATSize(natSize{2048, 10, 100})
	if file.String() != "nat44 ei plugin enable static-mapping-only sessions 2048 users 10 user-sessions 100\nset nat44 ei timeout udp 1 tcp-established 2 tcp-transitory 3 icmp 4\n" {
		t.Fatalf("%q", file.String())
	}
	file = parseCLI("set int state port0 up\n")
	if file.setTimeouts(defaultTimeouts) || file.setNATSize(defaultSize) {
		t.Fatal("changed a file without NAT")
	}
}

func TestParseHardware(t *testing.T) {
	text := `              Name                Idx   Link  Hardware
port0                              1     up   port0
  Link speed: 2500 Mbps
  RX Queues:
    queue thread         mode
    0     vpp_wk_0 (1)   polling
  Ethernet address 00:11:22:33:44:55
  Realtek RTL8125
    carrier up full duplex max-frame-size 9014
    rx: queues 1 (max 4), desc 1024 (min 32 max 4096 align 8)
    tx: queues 2 (max 4), desc 1024 (min 32 max 4096 align 8)
    pci: device 10ec:8125 subsystem 10ec:0123 address 0000:01:00.00 numa 0
tap0                               2     up   tap0
  Ethernet address 02:fe:00:00:00:01
`
	hw := parseHardware(text)
	if len(hw) != 2 || hw[0] != (hardware{Name: "port0", PCI: "0000:01:00.0", Queues: 1, MaxQueues: 4}) || hw[1].Name != "tap0" {
		t.Fatalf("%+v", hw)
	}
}

// fakeVPP runs what the files say each time it is restarted.
type fakeVPP struct {
	t           *testing.T
	dir         string
	run         int
	down        bool
	threads     []thread
	queues      []rxQueue
	nat         *natRunning
	noInterrupt map[string]bool // interfaces that stay polling
	calls       []string
	hw          string          // what show hardware-interfaces says
	broken      map[string]bool // PCI addresses no PMD takes
	stops       int
}

func (f *fakeVPP) start() {
	f.run++
	f.down = false
	conf, err := parseStartConf(readFile(f.t, filepath.Join(f.dir, "router.conf")))
	if err != nil {
		f.down = true
		return
	}
	cpu, _ := conf.cpu()
	f.hw = "port0  1  up  port0\n    rx: queues 2 (max 4), desc 1024\n    pci: device 1:1 address 0000:01:00.00 numa 0\n"
	for _, d := range conf.dpdkDevs() {
		if a, _ := pciAddress(d.Address); a != "0000:01:00.0" && !f.broken[a] {
			for _, name := range d.names() {
				if name != "" {
					f.hw += name + "  9  down  " + name + "\n    pci: device 8086:1533 address " + a + " numa 0\n"
				}
			}
		}
	}
	f.threads = []thread{{Index: 0, Name: "vpp_main", CPU: *cpu.MainCore}}
	for i, w := range cpu.Workers {
		f.threads = append(f.threads, thread{Index: uint32(i + 1), Name: "vpp_wk", Type: "workers", CPU: w})
	}
	f.queues = []rxQueue{{Index: 1, Interface: "port0", Queue: 0, Mode: "polling"}, {Index: 1, Interface: "port0", Queue: 1, Mode: "polling"}, {Index: 2, Interface: "tap0", Queue: 0, Mode: "interrupt"}}
	if len(cpu.Workers) > 0 {
		for i := range f.queues {
			f.queues[i].Thread = 1
		}
	}
	file := parseCLI(readFile(f.t, filepath.Join(f.dir, "router.vpp")))
	size, _ := file.natSize()
	f.nat = &natRunning{Size: size, Timeouts: file.timeouts()}
	if size.Sessions > 1<<20 {
		f.nat.Size = defaultSize // the plugin could not enable
	}
}

func (f *fakeVPP) Threads() ([]thread, error) {
	if f.down {
		return nil, errors.New("down")
	}
	return slices.Clone(f.threads), nil
}
func (f *fakeVPP) RxQueues() ([]rxQueue, error) { return slices.Clone(f.queues), nil }
func (f *fakeVPP) SetRxMode(index uint32, mode string) error {
	f.calls = append(f.calls, "mode "+mode)
	for i := range f.queues {
		if f.queues[i].Index == index && !(mode != "polling" && f.noInterrupt[f.queues[i].Interface]) {
			f.queues[i].Mode = mode
		}
	}
	return nil
}
func (f *fakeVPP) SetRxPlacement(index, queue, thread uint32) error {
	f.calls = append(f.calls, "placement")
	for i := range f.queues {
		if f.queues[i].Index == index && f.queues[i].Queue == queue {
			f.queues[i].Thread = thread
		}
	}
	return nil
}
func (f *fakeVPP) NAT() (*natRunning, error) { return f.nat, nil }
func (f *fakeVPP) SetNATTimeouts(t natTimeouts) error {
	f.nat.Timeouts = t
	return nil
}
func (f *fakeVPP) CLI(string) (string, error) { return f.hw, nil }
func (f *fakeVPP) Close()                     {}

func readFile(t *testing.T, path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeTestFile(t *testing.T, path, text string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// clock moves on only when something sleeps.
type clock struct{ t time.Time }

func newTestService(t *testing.T) (*Service, *fakeVPP, *clock) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "router.conf"), installerConf)
	writeTestFile(t, filepath.Join(dir, "router.vpp"), routerVPP)
	sys := filepath.Join(dir, "sys/devices/system/cpu")
	writeTestFile(t, filepath.Join(sys, "online"), "0-3\n")
	for i, p := range []struct{ cpus, governor string }{{"0 1", "ondemand"}, {"2 3", "performance"}} {
		policy := filepath.Join(sys, "cpufreq", "policy"+[]string{"0", "2"}[i])
		writeTestFile(t, filepath.Join(policy, "related_cpus"), p.cpus+"\n")
		writeTestFile(t, filepath.Join(policy, "scaling_governor"), p.governor+"\n")
		writeTestFile(t, filepath.Join(policy, "scaling_available_governors"), "ondemand performance schedutil \n")
		writeTestFile(t, filepath.Join(policy, "cpuinfo_max_freq"), []string{"1800000", "2400000"}[i])
	}
	fake := &fakeVPP{t: t, dir: dir, noInterrupt: map[string]bool{}, broken: map[string]bool{}}
	fake.start()
	opts := Options{
		StartConf: filepath.Join(dir, "router.conf"), CLIFile: filepath.Join(dir, "router.vpp"), ConfigFile: filepath.Join(dir, "system.json"),
		VPPUnit: "vpp-router.service", StateDir: filepath.Join(dir, "state"), Confirm: time.Minute, MaxWorkers: -1,
		OtherPending: filepath.Join(dir, "interfaces-pending.json"), Sysfs: filepath.Join(dir, "sys"),
	}
	s, err := NewService(opts, func() (vppAPI, error) {
		if fake.down {
			return nil, errors.New("no VPP")
		}
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{time.Unix(1_800_000_000, 0)}
	s.now = func() time.Time { return c.t }
	s.sleep = func(d time.Duration) { c.t = c.t.Add(d) }
	s.stamp = func() (fileStamp, error) { return fileStamp{Ino: uint64(fake.run)}, nil }
	s.restart = func(string) error { fake.start(); return nil }
	s.stop = func(string) error { fake.stops++; fake.down = true; return nil }
	s.host.proc = filepath.Join(dir, "proc")
	s.host.addrs = func(string) []string { return nil }
	s.host.channels = func(string) int { return 0 }
	s.unitActive = func(string) bool { return !fake.down }
	s.unitFailed = func(string) bool { return fake.down }
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	return s, fake, c
}

func TestThreadsConfirm(t *testing.T) {
	s, fake, _ := newTestService(t)
	state, err := s.SetThreads(ThreadsRequest{MainCore: 0, Workers: []int{1, 2, 3}, RxQueues: map[string]int{"0000:01:00.0": 3}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || fake.run != 2 || len(fake.threads) != 4 {
		t.Fatalf("pending %+v run %d threads %v", state.Pending, fake.run, fake.threads)
	}
	if !strings.Contains(readFile(t, s.opts.StartConf), "cpu { main-core 0 corelist-workers 1-3 }") || !strings.Contains(readFile(t, s.opts.StartConf), "num-rx-queues 3") {
		t.Fatal(readFile(t, s.opts.StartConf))
	}
	if _, err := s.SetNATTimeouts(defaultTimeouts, "admin"); err == nil {
		t.Fatal("a second change while one is pending")
	}
	if _, err := s.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if s.pending != nil || s.last.Outcome != "confirmed" {
		t.Fatal(s.last)
	}
	if _, err := os.Stat(filepath.Join(s.opts.StateDir, pendingFile)); err == nil {
		t.Fatal("pending file left")
	}
}

func TestThreadsExpire(t *testing.T) {
	s, fake, c := newTestService(t)
	if _, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: []int{2}}, "admin"); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(2 * time.Minute)
	s.expire()
	if s.last.Outcome != "rolled-back" || readFile(t, s.opts.StartConf) != installerConf || fake.run != 3 || len(fake.threads) != 3 {
		t.Fatalf("%+v run %d", s.last, fake.run)
	}
}

func TestThreadsChecks(t *testing.T) {
	s, _, _ := newTestService(t)
	for _, q := range []ThreadsRequest{
		{MainCore: 4},
		{MainCore: 1, Workers: []int{1}},
		{MainCore: 1, Workers: []int{2, 9}},
		{MainCore: 1, Workers: []int{2, 3}}, // no change
		{MainCore: 1, Workers: []int{2}, Policy: "deadline"},
		{MainCore: 1, Workers: []int{2}, Policy: "batch", Priority: new(int)},
		{MainCore: 1, Workers: []int{2}, RxQueues: map[string]int{"0000:01:00.0": 5}},
		{MainCore: 1, Workers: []int{2}, RxQueues: map[string]int{"0000:09:00.0": 1}},
	} {
		if _, err := s.SetThreads(q, "admin"); err == nil {
			t.Errorf("%+v accepted", q)
		}
	}
	s.opts.MaxWorkers = 0
	if _, err := s.SetThreads(ThreadsRequest{MainCore: 1, Workers: []int{2}}, "admin"); err == nil || !strings.Contains(err.Error(), "单线程") {
		t.Fatal(err)
	}
	if _, err := s.SetThreads(ThreadsRequest{MainCore: 0}, "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestNATSizeFailsAndRollsBack(t *testing.T) {
	s, fake, _ := newTestService(t)
	if _, err := s.SetNATSize(natSize{1 << 22, 4096, 16384}, "admin"); err == nil {
		t.Fatal("accepted a table VPP did not take")
	}
	if readFile(t, s.opts.CLIFile) != routerVPP || s.pending != nil || s.last.Outcome != "rolled-back" || fake.nat.Size.Sessions != 65536 {
		t.Fatalf("%+v %+v", s.last, fake.nat)
	}
	if _, err := s.SetNATSize(natSize{131072, 4096, 16384}, "admin"); err != nil {
		t.Fatal(err)
	}
	if fake.nat.Size.Sessions != 131072 || s.pending == nil {
		t.Fatal(fake.nat)
	}
}

func TestPendingSurvivesRestart(t *testing.T) {
	s, fake, c := newTestService(t)
	if _, err := s.SetNATSize(natSize{131072, 4096, 16384}, "admin"); err != nil {
		t.Fatal(err)
	}
	// A new run of the service, past the deadline, rolls back.
	again, err := NewService(s.opts, s.dial)
	if err != nil {
		t.Fatal(err)
	}
	again.now, again.sleep, again.stamp, again.restart, again.unitActive, again.unitFailed = s.now, s.sleep, s.stamp, s.restart, s.unitActive, s.unitFailed
	c.t = c.t.Add(time.Hour)
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	if again.last == nil || again.last.Outcome != "rolled-back" || readFile(t, s.opts.CLIFile) != routerVPP || fake.nat.Size.Sessions != 65536 {
		t.Fatalf("%+v", again.last)
	}
}

func TestNATTimeouts(t *testing.T) {
	s, fake, _ := newTestService(t)
	want := natTimeouts{UDP: 120, TCPEstablished: 3600, TCPTransitory: 60, ICMP: 30}
	if _, err := s.SetNATTimeouts(want, "admin"); err != nil {
		t.Fatal(err)
	}
	if fake.nat.Timeouts != want || parseCLI(readFile(t, s.opts.CLIFile)).timeouts() != want || fake.run != 1 {
		t.Fatal(fake.nat.Timeouts)
	}
	if _, err := s.SetNATTimeouts(natTimeouts{UDP: 5, TCPEstablished: 60, TCPTransitory: 60, ICMP: 60}, "admin"); err == nil {
		t.Fatal("5 s accepted")
	}
	writeTestFile(t, s.opts.OtherPending, "{}")
	if _, err := s.SetNATTimeouts(defaultTimeouts, "admin"); err == nil || !strings.Contains(err.Error(), "接口页") {
		t.Fatal(err)
	}
	if !s.State().OtherPending {
		t.Fatal("other pending not shown")
	}
}

func TestRxModeAndPlacement(t *testing.T) {
	s, fake, _ := newTestService(t)
	if _, err := s.SetRxMode("port0", "adaptive", "admin"); err != nil {
		t.Fatal(err)
	}
	fake.noInterrupt["tap0"] = true
	fake.queues[2].Mode = "polling"
	if _, err := s.SetRxMode("tap0", "interrupt", "admin"); err == nil || !strings.Contains(err.Error(), "不支持") {
		t.Fatal(err)
	}
	if _, err := s.SetRxPlacement("port0", 1, 2, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRxPlacement("port0", 1, 5, "admin"); err == nil {
		t.Fatal("no such worker accepted")
	}
	cfg, _ := loadConfig(s.opts.ConfigFile)
	if cfg.RxModes["port0"] != "adaptive" || cfg.RxModes["tap0"] != "" || cfg.RxPlacement["port0"][1] != 2 {
		t.Fatalf("%+v", cfg)
	}

	// After VPP restarts, both come back.
	fake.start()
	s.tick(s.now())
	if fake.queues[0].Mode != "adaptive" || fake.queues[1].Mode != "adaptive" || fake.queues[1].Thread != 2 || len(s.warnings) != 0 {
		t.Fatalf("%+v %v", fake.queues, s.warnings)
	}
	calls := len(fake.calls)
	s.tick(s.now())
	if len(fake.calls) != calls {
		t.Fatal("reapplied to the same VPP run")
	}

	// With fewer workers, the placement is skipped and reported.
	writeTestFile(t, s.opts.StartConf, strings.Replace(installerConf, "corelist-workers 2-3", "corelist-workers 2", 1))
	fake.start()
	s.tick(s.now())
	if len(s.warnings) != 1 || !strings.Contains(s.warnings[0], "worker 1") {
		t.Fatal(s.warnings)
	}
	state := s.State()
	if len(state.Interfaces) != 2 || state.Interfaces[0].Setting != "adaptive" || *state.Interfaces[0].Queues[1].Setting != 2 {
		t.Fatalf("%+v", state.Interfaces)
	}
	if _, err := s.SetRxMode("port0", "default", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRxPlacement("port0", 1, -1, "admin"); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadConfig(s.opts.ConfigFile)
	if len(cfg.RxModes) != 0 || len(cfg.RxPlacement) != 0 {
		t.Fatalf("%+v", cfg)
	}
}

func TestGovernors(t *testing.T) {
	s, _, _ := newTestService(t)
	state, err := s.SetGovernor("policy2", "schedutil", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Governors[1].Governor != "schedutil" || state.GovernorSettings["policy2"] != "schedutil" {
		t.Fatalf("%+v", state.Governors)
	}
	if _, err := s.SetGovernor("policy2", "turbo", "admin"); err == nil {
		t.Fatal("unknown governor accepted")
	}
	if _, err := s.SetGovernor("../policy2", "ondemand", "admin"); err == nil {
		t.Fatal("bad policy accepted")
	}
	if len(state.CPUs) != 4 || state.CPUs[0].Big || !state.CPUs[2].Big || state.CPUs[3].Policy != "policy2" {
		t.Fatalf("%+v", state.CPUs)
	}
	// At boot the setting comes back.
	writeTestFile(t, filepath.Join(s.opts.Sysfs, "devices/system/cpu/cpufreq/policy2/scaling_governor"), "performance\n")
	again, _ := NewService(s.opts, s.dial)
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	if again.host.policies()[1].Governor != "schedutil" {
		t.Fatal("governor not set at start")
	}
}

func TestStateJSON(t *testing.T) {
	s, _, _ := newTestService(t)
	writeTestFile(t, s.opts.StartConf, "cpu { main-core 1 }\n")
	data, err := json.Marshal(s.State())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"devices":[]`, `"running":{"size":{"sessions":65536`, `"timeouts":{"udp":300`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("state has no %s: %s", want, data)
		}
	}
}
