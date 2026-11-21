package main

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const testRouterEnv = `# vpp-router-ctl 读取的设置，由 vpp-router-install.sh 生成
PREFIX=/usr/local
UIO=vfio-pci
NOIOMMU=0
# 角色 PCI 内核接口名 接入方式 VPP接口名
NICS=(
  "wan 0000:01:00.0 eth0 dpdk port0"
  "lan 0000:02:00.0 eth1 dpdk port1"
)
`

// pciFixture is a card in the test's sysfs.
type pciFixture struct {
	address, class, id, driver, netdev string
	group                              []string // other devices in its IOMMU group
	more                               []string // more ports' interfaces, dev_port 1 on
}

func addPCI(t *testing.T, sys string, c pciFixture) {
	dir := filepath.Join(sys, "bus/pci/devices", c.address)
	vendor, device, _ := strings.Cut(c.id, ":")
	writeTestFile(t, filepath.Join(dir, "class"), "0x"+c.class+"\n")
	writeTestFile(t, filepath.Join(dir, "vendor"), "0x"+vendor+"\n")
	writeTestFile(t, filepath.Join(dir, "device"), "0x"+device+"\n")
	writeTestFile(t, filepath.Join(dir, "driver_override"), "(null)\n")
	if c.driver != "" {
		drv := filepath.Join(sys, "bus/pci/drivers", c.driver)
		writeTestFile(t, filepath.Join(drv, "bind"), "")
		writeTestFile(t, filepath.Join(drv, "unbind"), "")
		if err := os.Symlink(drv, filepath.Join(dir, "driver")); err != nil {
			t.Fatal(err)
		}
	}
	for port, name := range append([]string{c.netdev}, c.more...) {
		if name == "" {
			continue
		}
		writeTestFile(t, filepath.Join(dir, "net", name, "dev_port"), strconv.Itoa(port)+"\n")
		writeTestFile(t, filepath.Join(sys, "class/net", name, "carrier"), "1\n")
		writeTestFile(t, filepath.Join(sys, "class/net", name, "speed"), "10000\n")
	}
	for _, other := range append([]string{c.address}, c.group...) {
		class := readTrim(filepath.Join(sys, "bus/pci/devices", other, "class"))
		writeTestFile(t, filepath.Join(dir, "iommu_group/devices", other, "class"), class+"\n")
	}
}

func newNICService(t *testing.T) (*Service, *fakeVPP) {
	s, fake, _ := newTestService(t)
	dir := filepath.Dir(s.opts.StartConf)
	sys := s.opts.Sysfs
	s.opts.RouterEnv = filepath.Join(dir, "router.env")
	s.opts.NICsOrig = filepath.Join(dir, "state-router/nics.orig")
	s.opts.PCIIDs = filepath.Join(dir, "dpdk-pci-ids")
	s.opts.UnitFile = filepath.Join(dir, "vpp-router.service")
	writeTestFile(t, s.opts.RouterEnv, testRouterEnv)
	writeTestFile(t, s.opts.NICsOrig, "0000:01:00.0 igb eth0\n")
	writeTestFile(t, s.opts.PCIIDs, "8086 1533 e1000\n8086 1539 e1000\n15b3 1003 mlx4\n")
	writeTestFile(t, s.opts.UnitFile, "[Service]\nExecStartPre=/usr/local/sbin/vpp-router-ctl prep\n")
	addPCI(t, sys, pciFixture{address: "0000:01:00.0", class: "020000", id: "8086:1533", driver: "vfio-pci"})
	addPCI(t, sys, pciFixture{address: "0000:00:1c.0", class: "060400", id: "8086:a33c", driver: "pcieport"})
	addPCI(t, sys, pciFixture{address: "0000:03:00.0", class: "020000", id: "8086:1533", driver: "igb", netdev: "enp3s0", group: []string{"0000:00:1c.0"}})
	addPCI(t, sys, pciFixture{address: "0000:04:00.0", class: "020000", id: "1234:5678", driver: "foo", netdev: "enp4s0"})
	addPCI(t, sys, pciFixture{address: "0000:05:00.1", class: "0c0330", id: "8086:15b5", driver: "xhci_hcd"})
	addPCI(t, sys, pciFixture{address: "0000:05:00.0", class: "020000", id: "8086:1539", driver: "igb", netdev: "enp5s0", group: []string{"0000:05:00.1"}})
	addPCI(t, sys, pciFixture{address: "0000:06:00.0", class: "020000", id: "8086:1539", driver: "igb", netdev: "enp6s0"})
	addPCI(t, sys, pciFixture{address: "0000:07:00.0", class: "028000", id: "8086:2723", driver: "iwlwifi", netdev: "wlp7s0"})
	writeTestFile(t, filepath.Join(sys, "bus/pci/devices/0000:07:00.0/net/wlp7s0/wireless/x"), "")
	writeTestFile(t, filepath.Join(s.host.proc, "net/route"), "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"+
		"enp6s0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
		"enp3s0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
	return s, fake
}

func cardOf(t *testing.T, view NICsView, address string) NICView {
	i := slices.IndexFunc(view.Cards, func(c NICView) bool { return c.Address == address })
	if i < 0 {
		t.Fatalf("no card %s in %+v", address, view.Cards)
	}
	return view.Cards[i]
}

func TestNICsView(t *testing.T) {
	s, _ := newNICService(t)
	view := s.State().NICs
	if view.Reason != "" || view.UIO != "vfio-pci" || view.Queues != 2 || view.SuggestedName != "lan0" {
		t.Fatalf("%+v", view)
	}
	var addresses []string
	for _, c := range view.Cards {
		addresses = append(addresses, c.Address)
	}
	// In use, and the Wi-Fi card, are left out.
	if !slices.Equal(addresses, []string{"0000:03:00.0", "0000:04:00.0", "0000:05:00.0", "0000:06:00.0"}) {
		t.Fatal(addresses)
	}
	if c := cardOf(t, view, "0000:03:00.0"); len(c.Problems) != 0 || c.PMD != "e1000" || c.Kind != "dpdk" || c.Link != "up 10000M" || c.Interface != "enp3s0" {
		t.Fatalf("%+v", c)
	}
	for address, want := range map[string]string{"0000:04:00.0": "PCI ID 表", "0000:05:00.0": "0000:05:00.1（xhci_hcd）", "0000:06:00.0": "默认路由"} {
		if c := cardOf(t, view, address); len(c.Problems) != 1 || !strings.Contains(c.Problems[0], want) {
			t.Errorf("%s: %v", address, c.Problems)
		}
	}

	writeTestFile(t, s.opts.UnitFile, "ExecStartPre=/usr/bin/python3 /usr/local/lib/vpp-router/rtl8125-init.py --pci 0000:01:00.0\n")
	writeTestFile(t, s.opts.PCIIDs, "8086 ffff r8169\n")
	if c := cardOf(t, s.State().NICs, "0000:03:00.0"); len(c.Problems) != 1 || !strings.Contains(c.Problems[0], "RTL8125") {
		t.Fatalf("%v", c.Problems)
	}

	for text, want := range map[string]string{
		strings.Replace(installerConf, "  uio-driver vfio-pci\n", "  no-pci\n", 1): "--config-only",
		"cpu { main-core 1 }\n": "--config-only",
	} {
		writeTestFile(t, s.opts.StartConf, text)
		if reason := s.State().NICs.Reason; !strings.Contains(reason, want) {
			t.Errorf("reason %q", reason)
		}
	}
	os.Remove(s.opts.RouterEnv)
	if reason := s.State().NICs.Reason; !strings.Contains(reason, "router.env") {
		t.Fatal(reason)
	}
}

func TestAddNICAndRollback(t *testing.T) {
	s, fake := newNICService(t)
	state, err := s.AddNIC(AddNICRequest{Address: "03:00.0", Name: "lan0"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || state.Pending.Device == nil || state.Pending.Device.Driver != "igb" || fake.run != 2 {
		t.Fatalf("%+v run %d", state.Pending, fake.run)
	}
	conf := readFile(t, s.opts.StartConf)
	if want := "  dev 0000:02:00.0 { name port1 }\n  dev 0000:03:00.0 { name lan0 num-rx-queues 2 }\n}\n"; !strings.HasSuffix(conf, want) {
		t.Fatalf("%s", conf)
	}
	if env := readFile(t, s.opts.RouterEnv); !strings.Contains(env, "  \"lan 0000:02:00.0 eth1 dpdk port1\"\n  \"lan 0000:03:00.0 enp3s0 dpdk lan0\"\n)\n") {
		t.Fatalf("%s", env)
	}
	if orig := readFile(t, s.opts.NICsOrig); orig != "0000:01:00.0 igb eth0\n0000:03:00.0 igb enp3s0\n" {
		t.Fatalf("%q", orig)
	}
	if !strings.Contains(state.Pending.Description, "lan0") {
		t.Fatal(state.Pending.Description)
	}
	// The card is in VPP now, so no longer offered.
	if slices.ContainsFunc(state.NICs.Cards, func(c NICView) bool { return c.Address == "0000:03:00.0" }) {
		t.Fatal("added card still offered")
	}

	if _, err := s.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if s.last.Outcome != "rolled-back" || fake.stops != 1 || fake.run != 3 || fake.down {
		t.Fatalf("%+v stops %d run %d", s.last, fake.stops, fake.run)
	}
	if readFile(t, s.opts.StartConf) != installerConf || readFile(t, s.opts.RouterEnv) != testRouterEnv {
		t.Fatal("files not restored")
	}
	if got := readFile(t, filepath.Join(s.opts.Sysfs, "bus/pci/devices/0000:03:00.0/driver_override")); got != "\n" {
		t.Fatalf("driver_override %q", got)
	}
	// nics.orig keeps the first driver seen, as the installer does.
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:03:00.0", Name: "lan0"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if orig := readFile(t, s.opts.NICsOrig); strings.Count(orig, "0000:03:00.0") != 1 {
		t.Fatalf("%q", orig)
	}
	if _, err := s.Confirm("admin"); err != nil || s.last.Outcome != "confirmed" {
		t.Fatal(err, s.last)
	}
}

func TestAddNICNotTakenRollsBack(t *testing.T) {
	s, fake := newNICService(t)
	fake.broken["0000:03:00.0"] = true
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:03:00.0", Name: "lan0"}, "admin"); err == nil || !strings.Contains(err.Error(), "没有出现 lan0") {
		t.Fatal(err)
	}
	if s.pending != nil || s.last.Outcome != "rolled-back" || fake.stops != 1 || readFile(t, s.opts.StartConf) != installerConf || readFile(t, s.opts.RouterEnv) != testRouterEnv {
		t.Fatalf("%+v", s.last)
	}
}

func TestAddNICChecks(t *testing.T) {
	s, _ := newNICService(t)
	for _, q := range []AddNICRequest{
		{Address: "0000:03:00.0", Name: "port0"}, // taken
		{Address: "0000:03:00.0", Name: "tap1"},  // a virtual interface's name
		{Address: "0000:03:00.0", Name: "1lan"},  // not a name
		{Address: "0000:03:00.0", Name: "lan.1"}, // looks like a sub-interface
		{Address: "0000:01:00.0", Name: "lan0"},  // already in VPP
		{Address: "0000:05:00.0", Name: "lan0"},  // IOMMU group busy
		{Address: "0000:06:00.0", Name: "lan0"},  // Linux's default route
		{Address: "0000:09:00.0", Name: "lan0"},  // no such card
		{Address: "nonsense", Name: "lan0"},
	} {
		if _, err := s.AddNIC(q, "admin"); err == nil {
			t.Errorf("%+v accepted", q)
		}
	}
	s.host.addrs = func(name string) []string {
		if name == "enp3s0" {
			return []string{"192.168.5.2/24"}
		}
		return nil
	}
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:03:00.0", Name: "lan0"}, "admin"); err == nil || !strings.Contains(err.Error(), "192.168.5.2/24") {
		t.Fatal(err)
	}
	s.host.channels = func(string) int { return 1 }
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:03:00.0", Name: "lan0", Accept: true}, "admin"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, s.opts.StartConf), "name lan0 num-rx-queues 1 }") {
		t.Fatal("queues not capped by the driver's channels")
	}
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:04:00.0", Name: "lan1"}, "admin"); err == nil {
		t.Fatal("a second change while one is pending")
	}
}

func TestPendingNICSurvivesRestart(t *testing.T) {
	s, fake := newNICService(t)
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:03:00.0", Name: "lan0"}, "admin"); err != nil {
		t.Fatal(err)
	}
	again, err := NewService(s.opts, s.dial)
	if err != nil {
		t.Fatal(err)
	}
	again.now, again.sleep, again.stamp, again.restart, again.stop, again.unitActive, again.unitFailed = s.now, s.sleep, s.stamp, s.restart, s.stop, s.unitActive, s.unitFailed
	again.host = s.host
	s.sleep(2 * s.opts.Confirm)
	if err := again.Start(); err != nil {
		t.Fatal(err)
	}
	if again.last == nil || again.last.Outcome != "rolled-back" || fake.stops != 1 || readFile(t, s.opts.RouterEnv) != testRouterEnv {
		t.Fatalf("%+v", again.last)
	}
}

func TestGiveBack(t *testing.T) {
	sys := t.TempDir()
	h := host{sysfs: sys}
	addPCI(t, sys, pciFixture{address: "0000:03:00.0", class: "020000", id: "8086:1533", driver: "vfio-pci"})
	writeTestFile(t, filepath.Join(sys, "bus/pci/drivers/igb/bind"), "")
	err := h.giveBack(&AddedNIC{Address: "0000:03:00.0", Driver: "igb", Kind: "dpdk"})
	// The test's sysfs does not move the driver link, so the check after says so.
	if err == nil || !strings.Contains(err.Error(), "vfio-pci") {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(sys, "bus/pci/drivers/vfio-pci/unbind")) != "0000:03:00.0" || readFile(t, filepath.Join(sys, "bus/pci/drivers/igb/bind")) != "0000:03:00.0" {
		t.Fatal("not unbound and bound")
	}
	if err := h.giveBack(&AddedNIC{Address: "0000:03:00.0", Driver: "mlx4_core", Kind: "mlx"}); err != nil {
		t.Fatal(err)
	}
}

func TestWithDev(t *testing.T) {
	conf, _ := parseStartConf("dpdk { uio-driver vfio-pci dev 0000:01:00.0 }\n")
	text, err := conf.withDev("0000:03:00.0", "lan0", 1, []string{"no-multi-seg"})
	if err != nil || text != "dpdk { uio-driver vfio-pci dev 0000:01:00.0 no-multi-seg dev 0000:03:00.0 { name lan0 num-rx-queues 1 } }\n" {
		t.Fatalf("%q %v", text, err)
	}
	conf, _ = parseStartConf(handConf)
	text, _ = conf.withDev("0000:03:00.0", "lan0", 2, nil)
	if !strings.HasSuffix(text, "    name eth2-dpdk\n  }\n  dev 0000:03:00.0 { name lan0 num-rx-queues 2 }\n}\n") {
		t.Fatalf("%s", text)
	}
	if _, err := parseStartConf(text); err != nil {
		t.Fatal(err)
	}
	env := parseRouterEnv(testRouterEnv)
	if env.vars["UIO"] != "vfio-pci" || len(env.nics) != 2 || env.nics[1].Name != "port1" || !env.has("2:0.0") {
		t.Fatalf("%+v", env)
	}
}

// A ConnectX-3: two ports on one PCI function, the first already VPP's mx0.
func newMLXService(t *testing.T) (*Service, *fakeVPP) {
	s, fake := newNICService(t)
	conf := strings.Replace(installerConf, "  dev 0000:02:00.0 { name port1 }\n", "  dev 0000:02:00.0 { name port1 }\n  dev 0000:08:00.0 { name mx0 num-rx-queues 2 num-rx-desc 2048 }\n", 1)
	writeTestFile(t, s.opts.StartConf, conf)
	writeTestFile(t, s.opts.RouterEnv, strings.Replace(testRouterEnv, "port1\"\n", "port1\"\n  \"lan 0000:08:00.0 ens8 mlx mx0\"\n", 1))
	writeTestFile(t, s.opts.PCIIDs, "8086 1533 e1000\n15b3 1003 mlx4\n")
	addPCI(t, s.opts.Sysfs, pciFixture{address: "0000:08:00.0", class: "020000", id: "15b3:1003", driver: "mlx4_core", netdev: "ens8", more: []string{"ens8d1"}})
	writeTestFile(t, filepath.Join(s.opts.Sysfs, "module/mlx4_core/parameters/log_num_mgm_entry_size"), "-1\n")
	writeTestFile(t, s.opts.NICsOrig, "0000:01:00.0 igb eth0\n0000:08:00.0 mlx4_core ens8\n")
	s.opts.DPDKPlugin = filepath.Join(filepath.Dir(s.opts.StartConf), "dpdk_plugin.so")
	writeTestFile(t, s.opts.DPDKPlugin, "\x7fELF... port %u of device %s has no name in '%v'. Skipping...")
	fake.start()
	return s, fake
}

func TestAddSecondPort(t *testing.T) {
	s, fake := newMLXService(t)
	view := s.State().NICs
	i := slices.IndexFunc(view.Cards, func(c NICView) bool { return c.Address == "0000:08:00.0" })
	if i < 0 || view.Cards[i].Port != 1 || view.Cards[i].Interface != "ens8d1" || len(view.Cards[i].Problems) != 0 || !slices.Equal(view.Cards[i].Shares, []string{"mx0"}) {
		t.Fatalf("%+v", view.Cards)
	}
	if slices.ContainsFunc(view.Cards, func(c NICView) bool { return c.Interface == "ens8" }) {
		t.Fatal("the port in use is offered")
	}
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:08:00.0", Port: 0, Name: "lan0"}, "admin"); err == nil {
		t.Fatal("port 0 is in use")
	}
	state, err := s.AddNIC(AddNICRequest{Address: "0000:08:00.0", Port: 1, Name: "lan0"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	conf := readFile(t, s.opts.StartConf)
	if !strings.Contains(conf, "  dev 0000:08:00.0 { name mx0,lan0 num-rx-queues 2 num-rx-desc 2048 }\n}") || strings.Contains(conf, "no-multi-seg") {
		t.Fatalf("%s", conf)
	}
	if !strings.Contains(readFile(t, s.opts.RouterEnv), "  \"lan 0000:08:00.0 ens8d1 mlx lan0\"\n)") {
		t.Fatal(readFile(t, s.opts.RouterEnv))
	}
	if !strings.Contains(state.Pending.Description, "口 1（ens8d1）") || !strings.Contains(state.Pending.Description, "2 个收包队列") {
		t.Fatal(state.Pending.Description)
	}
	if strings.Count(readFile(t, s.opts.NICsOrig), "0000:08:00.0") != 1 {
		t.Fatal(readFile(t, s.opts.NICsOrig))
	}
	if _, err := s.Rollback("admin"); err != nil || s.last.Outcome != "rolled-back" || fake.stops != 1 {
		t.Fatal(err, s.last)
	}
	if strings.Contains(readFile(t, s.opts.StartConf), "lan0") {
		t.Fatal("not restored")
	}
	// mlx keeps its driver: nothing is written to sysfs.
	if got := readFile(t, filepath.Join(s.opts.Sysfs, "bus/pci/devices/0000:08:00.0/driver_override")); got != "(null)\n" {
		t.Fatalf("%q", got)
	}
}

func TestSecondPortNeedsPatchedPlugin(t *testing.T) {
	s, _ := newMLXService(t)
	writeTestFile(t, s.opts.DPDKPlugin, "\x7fELF stock")
	c := cardOf(t, s.State().NICs, "0000:08:00.0")
	if len(c.Problems) != 1 || !strings.Contains(c.Problems[0], "0031") {
		t.Fatal(c.Problems)
	}
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:08:00.0", Port: 1, Name: "lan0"}, "admin"); err == nil {
		t.Fatal("accepted without the patch")
	}
}

func TestNewCardSecondPortOnly(t *testing.T) {
	s, _ := newMLXService(t)
	// A ConnectX-3 VPP does not use: its second port alone leaves the first out of the list.
	addPCI(t, s.opts.Sysfs, pciFixture{address: "0000:09:00.0", class: "020000", id: "15b3:1003", driver: "mlx4_core", netdev: "ens9", more: []string{"ens9d1"}})
	if n := len(slices.DeleteFunc(s.State().NICs.Cards, func(c NICView) bool { return c.Address != "0000:09:00.0" })); n != 2 {
		t.Fatalf("%d ports", n)
	}
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:09:00.0", Port: 1, Name: "lan0"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, s.opts.StartConf), "  dev 0000:09:00.0 { name ,lan0 num-rx-queues 2 }\n}") {
		t.Fatal(readFile(t, s.opts.StartConf))
	}
}

func TestPluginFromStartConf(t *testing.T) {
	s, _ := newMLXService(t)
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "b/dpdk_plugin.so"), "has no name in '%v'")
	s.opts.DPDKPlugin = ""
	conf, _ := parseStartConf("plugins { path " + filepath.Join(dir, "a") + ":" + filepath.Join(dir, "b") + " }")
	if !s.pluginNamesPorts(conf) {
		t.Fatal("plugin not found on the path")
	}
}

// port1 (0000:02:00.0) is a LAN card the installer gave VPP, from igb.
func newRetireService(t *testing.T, driverNow string) (*Service, *fakeVPP) {
	s, fake := newNICService(t)
	writeTestFile(t, s.opts.NICsOrig, "0000:01:00.0 igb eth0\n0000:02:00.0 igb eth1\n")
	addPCI(t, s.opts.Sysfs, pciFixture{address: "0000:02:00.0", class: "020000", id: "8086:1533", driver: driverNow})
	writeTestFile(t, filepath.Join(s.opts.Sysfs, "bus/pci/drivers/igb/bind"), "")
	return s, fake
}

func activeOf(t *testing.T, s *Service, name string) ActiveNIC {
	list := s.State().NICs.Active
	i := slices.IndexFunc(list, func(a ActiveNIC) bool { return a.Name == name })
	if i < 0 {
		t.Fatalf("no %s in %+v", name, list)
	}
	return list[i]
}

func TestRetireNIC(t *testing.T) {
	s, fake := newRetireService(t, "igb") // the test's sysfs cannot rebind, so it starts where it ends
	if a := activeOf(t, s, "port1"); len(a.Problems) != 0 || a.Driver != "igb" || a.Role != "lan" || a.Interface != "eth1" {
		t.Fatalf("%+v", a)
	}
	if a := activeOf(t, s, "port0"); len(a.Problems) != 2 || !strings.Contains(a.Problems[0], "WAN") || !strings.Contains(a.Problems[1], "set interface state port0 up") {
		t.Fatalf("%v", a.Problems)
	}
	s.cfg.RxModes = map[string]string{"port1": "adaptive", "port0": "adaptive"}
	state, err := s.RetireNIC("port1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil || state.Pending.Retired == nil || fake.stops != 1 || fake.run != 2 || fake.down {
		t.Fatalf("%+v stops %d run %d", state.Pending, fake.stops, fake.run)
	}
	if got := readFile(t, s.opts.StartConf); got != strings.Replace(installerConf, "  dev 0000:02:00.0 { name port1 }\n", "", 1) {
		t.Fatalf("%s", got)
	}
	if got := readFile(t, s.opts.RouterEnv); got != strings.Replace(testRouterEnv, "  \"lan 0000:02:00.0 eth1 dpdk port1\"\n", "", 1) {
		t.Fatalf("%s", got)
	}
	if !strings.Contains(state.Pending.Description, "交还 igb") {
		t.Fatal(state.Pending.Description)
	}
	if got := readFile(t, filepath.Join(s.opts.Sysfs, "bus/pci/devices/0000:02:00.0/driver_override")); got != "\n" {
		t.Fatalf("driver_override %q", got)
	}
	// The card is free now, so it is offered again.
	if !slices.ContainsFunc(state.NICs.Cards, func(c NICView) bool { return c.Address == "0000:02:00.0" }) {
		t.Fatal("retired card not offered")
	}
	if _, err := s.Rollback("admin"); err != nil || s.last.Outcome != "rolled-back" {
		t.Fatal(err, s.last)
	}
	if readFile(t, s.opts.StartConf) != installerConf || readFile(t, s.opts.RouterEnv) != testRouterEnv || s.cfg.RxModes["port1"] != "adaptive" {
		t.Fatal("not put back")
	}
	if _, err := s.RetireNIC("port1", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.cfg.RxModes["port1"]; ok || s.cfg.RxModes["port0"] != "adaptive" {
		t.Fatalf("%v", s.cfg.RxModes)
	}
	// port0 is now the last card.
	if a := activeOf(t, s, "port0"); !strings.Contains(strings.Join(a.Problems, ""), "最后一块") {
		t.Fatalf("%v", a.Problems)
	}
}

func TestRetireGiveBackFails(t *testing.T) {
	s, fake := newRetireService(t, "vfio-pci")
	if _, err := s.RetireNIC("port1", "admin"); err == nil || !strings.Contains(err.Error(), "原驱动") {
		t.Fatal(err)
	}
	if s.pending != nil || s.last.Outcome != "rolled-back" || readFile(t, s.opts.StartConf) != installerConf || readFile(t, s.opts.RouterEnv) != testRouterEnv || fake.down {
		t.Fatalf("%+v", s.last)
	}
}

func TestRetireChecks(t *testing.T) {
	s, _ := newRetireService(t, "igb")
	writeTestFile(t, s.opts.CLIFile, routerVPP+"create sub-interface port1 100\n# port1 in a comment is fine\n")
	for _, name := range []string{"port0", "port1", "nonesuch", "tap0"} {
		if _, err := s.RetireNIC(name, "admin"); err == nil {
			t.Errorf("%s retired", name)
		}
	}
	if uses := cliUses("set int ip address port1.100 10.0.0.1/24\nset interface state port10 up\n", "port1"); len(uses) != 1 {
		t.Fatal(uses)
	}
	writeTestFile(t, s.opts.CLIFile, routerVPP+strings.Repeat("set interface state port1 up\n", 5))
	if p := activeOf(t, s, "port1").Problems; len(p) != 1 || !strings.HasSuffix(p[0], " 等 5 行") || strings.Count(p[0], "port1 up") != 3 {
		t.Fatal(p)
	}
}

func TestRetireSharedPort(t *testing.T) {
	s, fake := newMLXService(t)
	if _, err := s.AddNIC(AddNICRequest{Address: "0000:08:00.0", Port: 1, Name: "lan0"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
	if a := activeOf(t, s, "lan0"); a.Port != 1 || !slices.Equal(a.Shares, []string{"mx0"}) || len(a.Problems) != 0 {
		t.Fatalf("%+v", a)
	}
	state, err := s.RetireNIC("mx0", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, s.opts.StartConf), "dev 0000:08:00.0 { name ,lan0 num-rx-queues 2") || state.Pending.Retired.Kind != "shared" {
		t.Fatal(readFile(t, s.opts.StartConf))
	}
	if _, err := s.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RetireNIC("lan0", "admin"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, s.opts.StartConf), "dev 0000:08:00.0 { name mx0 num-rx-queues 2") || strings.Contains(readFile(t, s.opts.RouterEnv), "lan0") || fake.down {
		t.Fatal(readFile(t, s.opts.StartConf))
	}
}

func TestWithoutDev(t *testing.T) {
	conf, _ := parseStartConf("dpdk { uio-driver vfio-pci dev 0000:01:00.0 { name a } dev 0000:02:00.0 }\n")
	if text, _ := conf.withoutDev("0000:01:00.0"); text != "dpdk { uio-driver vfio-pci dev 0000:02:00.0 }\n" {
		t.Fatalf("%q", text)
	}
	if text, _ := conf.withoutDev("2:0.0"); text != "dpdk { uio-driver vfio-pci dev 0000:01:00.0 { name a } }\n" {
		t.Fatalf("%q", text)
	}
	conf, _ = parseStartConf(handConf)
	text, _ := conf.withoutDev("0001:01:00.0")
	if !strings.HasSuffix(text, "  dev 0000:01:00.0\n}\n") {
		t.Fatalf("%s", text)
	}
}
