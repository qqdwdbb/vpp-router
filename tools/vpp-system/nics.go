package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Adding a PCI network card to VPP through DPDK, as the installer does for the cards chosen when
// it ran: the card goes into the dpdk section of VPP's startup file and into router.env's NICS,
// which vpp-router-ctl reads to bind it before VPP starts; VPP restarts, and the change is undone
// unless confirmed, giving the card back to the driver it had.

// AddedNIC is the card a pending change added, so a rollback can give it back.
type AddedNIC struct {
	Address   string `json:"address"`
	Driver    string `json:"driver"`         // the driver it had, "none" for none
	Interface string `json:"interface"`      // Linux's name for it, "-" for none
	Kind      string `json:"kind"`           // dpdk (bound to the UIO driver) or mlx (keeps its driver)
	Name      string `json:"name,omitempty"` // the VPP interface
}

// NICView is a PCI network card, or one port of a card with several (mlx4 drives both ports of
// a ConnectX-3 through one PCI function), that VPP does not use.
type NICView struct {
	Address string `json:"address"`
	// Port is the port on the PCI function, Linux's dev_port; 0 for most cards.
	Port int `json:"port"`
	// Shares is the VPP interfaces already on this PCI function, for a port of a card VPP uses.
	Shares    []string `json:"shares"`
	ID        string   `json:"id"` // vendor:device
	PMD       string   `json:"pmd"`
	Kind      string   `json:"kind"`
	Driver    string   `json:"driver"`
	Interface string   `json:"interface"`
	Link      string   `json:"link"`
	Addresses []string `json:"addresses"`
	// Problems keep it from being added; Warnings are for the user to accept.
	Problems []string `json:"problems"`
	Warnings []string `json:"warnings"`
}

// ActiveNIC is a card or port that router.env gives VPP through DPDK.
type ActiveNIC struct {
	Name      string   `json:"name"`
	Address   string   `json:"address"`
	Port      int      `json:"port"`
	Shares    []string `json:"shares"` // the other VPP interfaces on this PCI function
	Interface string   `json:"interface"`
	Kind      string   `json:"kind"`
	Role      string   `json:"role"`
	Driver    string   `json:"driver"`  // what it goes back to, from nics.orig; "" when not noted
	Running   bool     `json:"running"` // VPP has it now
	// Problems keep it in VPP, such as lines of the CLI file that use it.
	Problems []string `json:"problems"`
}

type NICsView struct {
	// Reason is why no card can be added on this deployment, empty when they can.
	Reason        string      `json:"reason"`
	UIO           string      `json:"uio"`
	Queues        int         `json:"queues"`
	SuggestedName string      `json:"suggested_name"`
	Cards         []NICView   `json:"cards"`
	Active        []ActiveNIC `json:"active"`
}

type AddNICRequest struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Name    string `json:"name"`
	// Accept says the user has seen the card's warnings, such as its Linux addresses going.
	Accept bool `json:"accept"`
}

// router.env, written by the installer and sourced by vpp-router-ctl.

type routerEnv struct {
	text  string
	vars  map[string]string
	nics  []envNIC
	close int // offset of the line closing NICS=(, -1 when there is none
}

type envNIC struct {
	Role, Address, Interface, Kind, Name string
	start, end                           int // the line's offsets
}

func parseRouterEnv(text string) *routerEnv {
	env := &routerEnv{text: text, vars: map[string]string{}, close: -1}
	inNICS := false
	offset := 0
	for _, line := range strings.SplitAfter(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case inNICS && trimmed == ")":
			env.close = offset
			inNICS = false
		case inNICS:
			fields := strings.Fields(strings.Trim(trimmed, `"'`))
			if len(fields) >= 4 {
				nic := envNIC{Role: fields[0], Address: fields[1], Interface: fields[2], Kind: fields[3], start: offset, end: offset + len(line)}
				if len(fields) > 4 {
					nic.Name = fields[4]
				}
				env.nics = append(env.nics, nic)
			}
		case trimmed == "NICS=(":
			inNICS = true
		default:
			if name, value, ok := strings.Cut(trimmed, "="); ok && !strings.HasPrefix(trimmed, "#") {
				env.vars[name] = strings.Trim(value, `"'`)
			}
		}
		offset += len(line)
	}
	return env
}

// withNIC is the file with one more card at the end of NICS.
func (e *routerEnv) withNIC(nic envNIC) string {
	line := fmt.Sprintf("  \"%s %s %s %s %s\"\n", nic.Role, nic.Address, nic.Interface, nic.Kind, nic.Name)
	return e.text[:e.close] + line + e.text[e.close:]
}

// withoutNIC is the file without that card's line.
func (e *routerEnv) withoutNIC(nic envNIC) string { return e.text[:nic.start] + e.text[nic.end:] }

func (e *routerEnv) has(address string) bool {
	return slices.ContainsFunc(e.nics, func(n envNIC) bool { return sameAddress(n.Address, address) })
}

// The startup file's dpdk section.

// dpdkWords are the words directly in the dpdk section, such as uio-driver and its value.
func (c *startConf) dpdkWords() []string { return c.sectionWords("dpdk") }

// sectionWords are the words directly in a section, nil when there is no such section.
func (c *startConf) sectionWords(name string) []string {
	s := c.section(name)
	if s == nil {
		return nil
	}
	var words []string
	for _, it := range s.body {
		words = append(words, it.word.text)
	}
	return words
}

// withDev is the file with a dev block added at the end of the dpdk section, and the words
// added before it.
func (c *startConf) withDev(address, name string, queues int, words []string) (string, error) {
	s := c.section("dpdk")
	if s == nil {
		return "", errors.New("启动文件里没有 dpdk 段")
	}
	closing := s.shut - 1 // the "}"
	lineStart := strings.LastIndexByte(c.text[:closing], '\n') + 1
	lines := append(slices.Clone(words), fmt.Sprintf("dev %s { name %s num-rx-queues %d }", address, name, queues))
	if strings.TrimSpace(c.text[lineStart:closing]) == "" && lineStart > s.open {
		// "}" on a line of its own: a line per entry, indented as the section's first entry.
		indent := "  "
		if len(s.body) > 0 {
			first := s.body[0].word.start
			if from := strings.LastIndexByte(c.text[:first], '\n') + 1; strings.TrimSpace(c.text[from:first]) == "" {
				indent = c.text[from:first]
			}
		}
		text := ""
		for _, l := range lines {
			text += indent + l + "\n"
		}
		return c.text[:lineStart] + text + c.text[lineStart:], nil
	}
	return c.text[:closing] + strings.Join(lines, " ") + " " + c.text[closing:], nil
}

// withDevName is the file with a dev block's name replaced, such as "port0" by "port0,lan0".
func (c *startConf) withDevName(address, name string) (string, error) {
	for _, d := range c.dpdkDevs() {
		if sameAddress(d.Address, address) {
			if d.nameTok == nil {
				return "", fmt.Errorf("dpdk 里的 dev %s 没有 name", address)
			}
			return applyEdits(c.text, []edit{{d.nameTok.start, d.nameTok.end, name}}), nil
		}
	}
	return "", fmt.Errorf("dpdk 里没有 dev %s", address)
}

// withoutDev is the file without a dev block: its line when the block has a line of its own.
func (c *startConf) withoutDev(address string) (string, error) {
	for _, d := range c.dpdkDevs() {
		if !sameAddress(d.Address, address) {
			continue
		}
		start, end := d.devWord.start, d.item.word.end
		if d.item.section {
			end = d.item.shut
		}
		lineStart := strings.LastIndexByte(c.text[:start], '\n') + 1
		lineEnd := len(c.text)
		if i := strings.IndexByte(c.text[end:], '\n'); i >= 0 {
			lineEnd = end + i + 1
		}
		if strings.TrimSpace(c.text[lineStart:start]) == "" && strings.TrimSpace(c.text[end:lineEnd]) == "" {
			return c.text[:lineStart] + c.text[lineEnd:], nil
		}
		for start > 0 && (c.text[start-1] == ' ' || c.text[start-1] == '\t') {
			start--
		}
		return c.text[:start] + c.text[end:], nil
	}
	return "", fmt.Errorf("dpdk 里没有 dev %s", address)
}

// names is the dev block's name split into one name a port, "" for a port it leaves out.
func (d dpdkDev) names() []string {
	if d.Name == "" {
		return nil
	}
	return strings.Split(d.Name, ",")
}

// The host's PCI network cards.

// pciIDs is DPDK's table of the PCI IDs each PMD drives, which the installer writes from the build.
type pciIDs map[string]string // "vvvv:dddd" or "vvvv:ffff" to the PMD's name

func loadPCIIDs(path string) (pciIDs, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	ids := pciIDs{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) == 3 {
			key := strings.ToLower(f[0] + ":" + f[1])
			if _, ok := ids[key]; !ok {
				ids[key] = f[2]
			}
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%s 是空的", path)
	}
	return ids, scanner.Err()
}

func (ids pciIDs) pmd(id string) string {
	if pmd, ok := ids[id]; ok {
		return pmd
	}
	vendor, _, _ := strings.Cut(id, ":")
	return ids[vendor+":ffff"]
}

func (h host) pciDir(address string) string {
	return filepath.Join(h.sysfs, "bus/pci/devices", address)
}

func (h host) pciDriver(address string) string {
	target, err := os.Readlink(filepath.Join(h.pciDir(address), "driver"))
	if err != nil {
		return "none"
	}
	return filepath.Base(target)
}

func hexID(path string) string {
	return strings.TrimPrefix(strings.ToLower(readTrim(path)), "0x")
}

// pciCard is what sysfs says about one card.
type pciCard struct {
	Address, ID, Class, Driver string
	Netdevs                    []netdev // Linux's interfaces for it, by port
	Wireless                   bool
}

type netdev struct {
	Name string
	Port int // dev_port
}

func (h host) pciCards() []pciCard {
	dirs, _ := filepath.Glob(filepath.Join(h.sysfs, "bus/pci/devices/*"))
	var cards []pciCard
	for _, dir := range dirs {
		class := hexID(filepath.Join(dir, "class"))
		if !strings.HasPrefix(class, "02") {
			continue
		}
		address := filepath.Base(dir)
		card := pciCard{Address: address, Class: class, Driver: h.pciDriver(address),
			ID: hexID(filepath.Join(dir, "vendor")) + ":" + hexID(filepath.Join(dir, "device"))}
		nets, _ := filepath.Glob(filepath.Join(dir, "net/*"))
		for _, n := range nets {
			card.Netdevs = append(card.Netdevs, netdev{Name: filepath.Base(n), Port: readInt(filepath.Join(n, "dev_port"))})
			_, err1 := os.Stat(filepath.Join(n, "wireless"))
			_, err2 := os.Stat(filepath.Join(n, "phy80211"))
			card.Wireless = card.Wireless || err1 == nil || err2 == nil
		}
		slices.SortFunc(card.Netdevs, func(a, b netdev) int { return a.Port - b.Port })
		cards = append(cards, card)
	}
	return cards
}

// iommuBusy is the other devices in the card's IOMMU group that a kernel driver still has,
// which keep VFIO from taking the group. Bridges do not count.
func (h host) iommuBusy(address string) (busy []string, hasGroup bool) {
	members, _ := filepath.Glob(filepath.Join(h.pciDir(address), "iommu_group/devices/*"))
	for _, m := range members {
		other := filepath.Base(m)
		if other == address || strings.HasPrefix(hexID(filepath.Join(m, "class")), "06") {
			continue
		}
		if drv := h.pciDriver(other); drv != "none" && drv != "vfio-pci" {
			busy = append(busy, other+"（"+drv+"）")
		}
	}
	return busy, len(members) > 0
}

// defaultRouteDevs is the interfaces Linux's default routes leave by.
func (h host) defaultRouteDevs() map[string]bool {
	devs := map[string]bool{}
	for _, line := range strings.Split(readTrim(filepath.Join(h.proc, "net/route")), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 7 && f[1] == "00000000" && f[7] == "00000000" {
			devs[f[0]] = true
		}
	}
	for _, line := range strings.Split(readTrim(filepath.Join(h.proc, "net/ipv6_route")), "\n") {
		f := strings.Fields(line)
		if len(f) == 10 && strings.Trim(f[0], "0") == "" && f[1] == "00" && f[9] != "lo" {
			devs[f[9]] = true
		}
	}
	return devs
}

func (h host) netdevMaster(ifname string) string {
	target, err := os.Readlink(filepath.Join(h.sysfs, "class/net", ifname, "master"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func (h host) link(ifname string) string {
	dir := filepath.Join(h.sysfs, "class/net", ifname)
	if readTrim(filepath.Join(dir, "carrier")) != "1" {
		return "down"
	}
	if speed := readInt(filepath.Join(dir, "speed")); speed > 0 {
		return fmt.Sprintf("up %dM", speed)
	}
	return "up"
}

// hostAddrs is an interface's addresses, link-local ones left out.
func hostAddrs(ifname string) []string {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil
	}
	addrs, _ := iface.Addrs()
	var list []string
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
			list = append(list, n.String())
		}
	}
	return list
}

var ethtoolMax = regexp.MustCompile(`^(Combined|RX):\s+(\d+)`)

// hostChannels is the most receive queues the driver offers, from ethtool, 0 when unknown.
func hostChannels(ifname string) int {
	output, err := exec.Command("ethtool", "-l", ifname).Output()
	if err != nil {
		return 0
	}
	most := 0
	for _, part := range strings.SplitN(string(output), "Current hardware settings", 2)[:1] {
		for _, line := range strings.Split(part, "\n") {
			if m := ethtoolMax.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				n, _ := strconv.Atoi(m[2])
				most = max(most, n)
			}
		}
	}
	return most
}

// giveBack returns a card VPP no longer uses to the driver it had, as vpp-router-ctl restore does.
func (h host) giveBack(nic *AddedNIC) error {
	if nic.Kind != "dpdk" {
		return nil
	}
	dir := h.pciDir(nic.Address)
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	os.WriteFile(filepath.Join(dir, "driver_override"), []byte("\n"), 0o200)
	current := h.pciDriver(nic.Address)
	if current == nic.Driver {
		return nil
	}
	if current != "none" {
		if err := os.WriteFile(filepath.Join(dir, "driver/unbind"), []byte(nic.Address), 0o200); err != nil {
			return fmt.Errorf("从 %s 解绑：%w", current, err)
		}
	}
	probe := filepath.Join(h.sysfs, "bus/pci/drivers_probe")
	if nic.Driver != "none" && nic.Driver != "" {
		if err := os.WriteFile(filepath.Join(h.sysfs, "bus/pci/drivers", nic.Driver, "bind"), []byte(nic.Address), 0o200); err != nil {
			os.WriteFile(probe, []byte(nic.Address), 0o200)
		}
	} else {
		os.WriteFile(probe, []byte(nic.Address), 0o200)
	}
	if now := h.pciDriver(nic.Address); nic.Driver != "none" && now != nic.Driver {
		return fmt.Errorf("%s 现在的驱动是 %s，不是原来的 %s", nic.Address, now, nic.Driver)
	}
	return nil
}

// The service.

var nicName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

// virtualPrefixes are the names the interfaces page takes for virtual interfaces.
var virtualPrefixes = []string{"tap", "tun", "wg", "loop", "ipip", "gre", "vxlan", "memif", "pg", "ipsec", "lcp", "pipe", "geneve", "gtpu", "srv6", "lisp", "nat", "mpls", "host-", "local", "vpp"}

// nicContext is what the checks of a card need, read once.
type nicContext struct {
	conf        *startConf
	env         *routerEnv
	ids         pciIDs
	uio         string
	noIOMMU     bool
	queues      int
	names       map[string]bool // taken interface names
	routes      map[string]bool
	platformRTL bool
	// multiPort says VPP's dpdk plugin takes "name a,b" for the ports of one device (patch 0031).
	multiPort bool
}

// nicSetup reads what adding a card needs, or says why this deployment cannot.
func (s *Service) nicSetup(hw []hardware) (*nicContext, string) {
	if s.opts.RouterEnv == "" {
		return nil, "管理服务没有设置 --router-env"
	}
	data, err := os.ReadFile(s.opts.RouterEnv)
	if err != nil {
		return nil, "读不到安装器的 " + s.opts.RouterEnv + "，只有安装器部署的 VPP 能在这里加网卡"
	}
	ctx := &nicContext{env: parseRouterEnv(string(data)), names: map[string]bool{}}
	if ctx.env.close < 0 {
		return nil, s.opts.RouterEnv + " 里没有 NICS=( … )"
	}
	if ctx.conf, err = s.loadStartConf(); err != nil {
		return nil, err.Error()
	}
	words := ctx.conf.dpdkWords()
	if words == nil || slices.Contains(words, "no-pci") {
		return nil, "安装时没有选 PCI 的 DPDK 网卡，VPP 没有接管 PCI 设备；用安装器的 --config-only 重新选择网卡"
	}
	if i := slices.Index(words, "uio-driver"); i >= 0 && i+1 < len(words) {
		ctx.uio = words[i+1]
	}
	if ctx.uio == "" {
		ctx.uio = ctx.env.vars["UIO"]
	}
	if ctx.uio == "" {
		return nil, "启动文件的 dpdk 段和 router.env 都没有 UIO 驱动"
	}
	ctx.noIOMMU = ctx.env.vars["NOIOMMU"] == "1"
	if ctx.ids, err = loadPCIIDs(s.opts.PCIIDs); err != nil {
		return nil, "读不到 DPDK 的 PCI ID 表（" + err.Error() + "），无法确认网卡是否受支持"
	}
	if s.opts.VPPUnit == "" {
		return nil, "加网卡要重启 VPP，但管理服务没有设置 --vpp-unit"
	}
	cpu, _ := ctx.conf.cpu()
	ctx.queues = 1
	if cpu != nil {
		ctx.queues = max(1, len(cpu.Workers), cpu.AutoWorkers)
	}
	for _, d := range ctx.conf.dpdkDevs() {
		for _, name := range d.names() {
			ctx.names[name] = true
		}
	}
	for _, n := range ctx.env.nics {
		ctx.names[n.Name] = true
	}
	for _, h := range hw {
		ctx.names[h.Name] = true
	}
	delete(ctx.names, "")
	ctx.routes = s.host.defaultRouteDevs()
	if s.opts.UnitFile != "" {
		ctx.platformRTL = strings.Contains(readTrim(s.opts.UnitFile), "rtl8125-init")
	}
	ctx.multiPort = s.pluginNamesPorts(ctx.conf)
	return ctx, ""
}

// multiPortMark is a message only the patched plugin has.
const multiPortMark = "has no name in '"

// pluginNamesPorts says whether VPP's dpdk plugin, from -dpdk-plugin or the startup file's plugin
// path, names each port of a device from "name a,b".
func (s *Service) pluginNamesPorts(conf *startConf) bool {
	paths := []string{s.opts.DPDKPlugin}
	if s.opts.DPDKPlugin == "" {
		paths = nil
		words := conf.sectionWords("plugins")
		if i := slices.Index(words, "path"); i >= 0 && i+1 < len(words) {
			for _, dir := range strings.Split(words[i+1], ":") {
				paths = append(paths, filepath.Join(dir, "dpdk_plugin.so"))
			}
		}
	}
	for _, path := range paths {
		if data, err := os.ReadFile(path); err == nil {
			return strings.Contains(string(data), multiPortMark)
		}
	}
	return false
}

func (ctx *nicContext) dev(address string) *dpdkDev {
	for _, d := range ctx.conf.dpdkDevs() {
		if sameAddress(d.Address, address) {
			return &d
		}
	}
	return nil
}

// portUsed says whether VPP has this port of a card it uses: named in the dev block, or in NICS.
func (ctx *nicContext) portUsed(address string, dev *dpdkDev, nd netdev) bool {
	if slices.ContainsFunc(ctx.env.nics, func(n envNIC) bool { return sameAddress(n.Address, address) && n.Interface == nd.Name }) {
		return true
	}
	names := dev.names()
	return nd.Port < len(names) && names[nd.Port] != ""
}

func (ctx *nicContext) suggestName() string {
	for i := 0; ; i++ {
		if name := fmt.Sprintf("lan%d", i); !ctx.names[name] {
			return name
		}
	}
}

// cards is every PCI network card, or port of one, that VPP does not use, with what keeps it
// from being added.
func (s *Service) cards(ctx *nicContext) []NICView {
	list := []NICView{}
	for _, c := range s.host.pciCards() {
		if c.Wireless {
			continue
		}
		pmd := ctx.ids.pmd(c.ID)
		dev := ctx.dev(c.Address)
		if (pmd == "mlx4" || pmd == "mlx5") && len(c.Netdevs) > 0 {
			// The PMD makes a port for each of Linux's interfaces, each added on its own.
			for _, nd := range c.Netdevs {
				if dev != nil && ctx.portUsed(c.Address, dev, nd) || dev == nil && ctx.env.has(c.Address) && slices.ContainsFunc(ctx.env.nics, func(n envNIC) bool { return n.Interface == nd.Name }) {
					continue
				}
				list = append(list, s.card(ctx, c, pmd, dev, nd))
			}
			continue
		}
		if dev != nil || ctx.env.has(c.Address) {
			continue
		}
		var nd netdev
		if len(c.Netdevs) > 0 {
			nd = c.Netdevs[0]
		}
		list = append(list, s.card(ctx, c, pmd, nil, nd))
	}
	slices.SortFunc(list, func(a, b NICView) int {
		if c := strings.Compare(a.Address, b.Address); c != 0 {
			return c
		}
		return a.Port - b.Port
	})
	return list
}

// card is one card or port, with its problems and warnings. dev is the card's dev block when VPP
// already uses another port of it.
func (s *Service) card(ctx *nicContext, c pciCard, pmd string, dev *dpdkDev, nd netdev) NICView {
	v := NICView{Address: c.Address, Port: nd.Port, ID: c.ID, PMD: pmd, Driver: c.Driver, Interface: nd.Name,
		Shares: []string{}, Problems: []string{}, Warnings: []string{}, Addresses: []string{}}
	switch pmd {
	case "":
		v.Problems = append(v.Problems, "这次编译的 DPDK 不支持它（不在 PCI ID 表里）")
	case "mlx4", "mlx5":
		v.Kind = "mlx"
	default:
		v.Kind = "dpdk"
	}
	if dev != nil {
		for _, name := range dev.names() {
			if name != "" {
				v.Shares = append(v.Shares, name)
			}
		}
		if dev.Name == "" {
			v.Problems = append(v.Problems, "启动文件里 dev "+dev.Address+" 没有 name，先给已有的口起名")
		}
	}
	if (dev != nil || nd.Port > 0) && !ctx.multiPort {
		v.Problems = append(v.Problems, "VPP 的 dpdk 插件不能给同一 PCI 设备的几个口分别命名（要补丁 0031）；用安装器重新编译 VPP 后再加")
	}
	if c.ID == "10ec:8168" && pmd != "" {
		v.Warnings = append(v.Warnings, "RTL8111/8168 只有 8168G 及以后的芯片受 DPDK 支持，旧芯片接入后 VPP 里不会出现这个口，会自动恢复")
	}
	if pmd == "r8169" && ctx.platformRTL {
		v.Problems = append(v.Problems, "这个平台的 RTL8125 要在 VPP 启动前做缓存同步初始化，要用安装器的 --config-only 接入")
	}
	if nd.Name != "" {
		v.Link = s.host.link(nd.Name)
		v.Addresses = append(v.Addresses, s.host.addrs(nd.Name)...)
		if master := s.host.netdevMaster(nd.Name); master != "" {
			v.Problems = append(v.Problems, "它属于 "+master+"（网桥或 bond），先在 Linux 里移出")
		} else if ctx.routes[nd.Name] {
			v.Problems = append(v.Problems, "Linux 的默认路由经过它，接入后 Linux 会断网；先改 Linux 的网络配置")
		}
		if len(v.Addresses) > 0 {
			if v.Kind == "mlx" {
				v.Warnings = append(v.Warnings, "Linux 在它上面有地址 "+strings.Join(v.Addresses, "、")+"，Mellanox 网卡接入后 Linux 网卡还在，但发到这个口的包由 VPP 收，经过这些地址的连接会断")
			} else {
				v.Warnings = append(v.Warnings, "Linux 在它上面有地址 "+strings.Join(v.Addresses, "、")+"，接入后这些地址和经过它的连接都没有了；撤销时网卡交还给 "+c.Driver+"，地址要由系统的网络配置重新设置")
			}
		}
	}
	switch v.Kind {
	case "mlx":
		if nd.Name == "" {
			v.Problems = append(v.Problems, "Mellanox 网卡经内核驱动接入，要有 Linux 网卡（mlx4_en / mlx5_core）")
		}
		if pmd == "mlx4" {
			if mgm := readTrim(filepath.Join(s.host.sysfs, "module/mlx4_core/parameters/log_num_mgm_entry_size")); mgm != "" && mgm != "-1" {
				v.Problems = append(v.Problems, "mlx4_core 的 log_num_mgm_entry_size 是 "+mgm+"，mlx4 PMD 要 -1；用安装器的 --config-only 接入，它会设置并重新加载驱动")
			}
		}
	case "dpdk":
		if ctx.uio == "vfio-pci" {
			busy, group := s.host.iommuBusy(c.Address)
			if len(busy) > 0 {
				v.Problems = append(v.Problems, "IOMMU 组里还有内核驱动在用的设备："+strings.Join(busy, "、")+"，VFIO 不能接管")
			}
			if !group && !ctx.noIOMMU {
				v.Problems = append(v.Problems, "没有 IOMMU 组，vfio-pci 要无 IOMMU 模式，安装时没有选；用安装器的 --config-only 接入")
			}
		}
	}
	return v
}

func (s *Service) nicsView(hw []hardware) NICsView {
	ctx, reason := s.nicSetup(hw)
	if ctx == nil {
		return NICsView{Reason: reason, Cards: []NICView{}, Active: []ActiveNIC{}}
	}
	return NICsView{UIO: ctx.uio, Queues: ctx.queues, SuggestedName: ctx.suggestName(), Cards: s.cards(ctx), Active: s.active(ctx, hw)}
}

// cliUses is the lines of the CLI file that name the interface or one of its sub-interfaces.
func cliUses(text, name string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		for _, f := range cliFields(line) {
			if f == name || strings.HasPrefix(f, name+".") {
				lines = append(lines, strings.TrimSpace(line))
				break
			}
		}
	}
	return lines
}

// originalDriver is the card's driver as nics.orig notes it, "" when it does not.
func (s *Service) originalDriver(address string) string {
	if s.opts.NICsOrig == "" {
		return ""
	}
	for _, line := range strings.Split(readTrim(s.opts.NICsOrig), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && sameAddress(f[0], address) {
			return f[1]
		}
	}
	return ""
}

// active is the cards and ports router.env gives VPP through DPDK, with what keeps each in.
func (s *Service) active(ctx *nicContext, hw []hardware) []ActiveNIC {
	list := []ActiveNIC{}
	cli, cliErr := os.ReadFile(s.opts.CLIFile)
	pciDevs := 0
	for _, d := range ctx.conf.dpdkDevs() {
		if _, ok := pciAddress(d.Address); ok {
			pciDevs++
		}
	}
	for _, n := range ctx.env.nics {
		if n.Kind != "dpdk" && n.Kind != "mlx" || n.Name == "" {
			continue
		}
		address, _ := pciAddress(n.Address)
		a := ActiveNIC{Name: n.Name, Address: address, Interface: n.Interface, Kind: n.Kind, Role: n.Role,
			Driver: s.originalDriver(address), Shares: []string{}, Problems: []string{}}
		if a.Interface == "-" {
			a.Interface = ""
		}
		a.Running = slices.ContainsFunc(hw, func(h hardware) bool { return h.Name == n.Name })
		var names []string
		if dev := ctx.dev(address); dev != nil {
			names = dev.names()
		}
		if i := slices.Index(names, n.Name); i >= 0 {
			a.Port = i
		} else {
			a.Problems = append(a.Problems, "启动文件的 dpdk 段里没有 "+n.Name)
		}
		left := 0
		for _, other := range names {
			if other != "" && other != n.Name {
				a.Shares = append(a.Shares, other)
				left++
			}
		}
		if n.Role == "wan" {
			a.Problems = append(a.Problems, "这是安装时选的 WAN 口，PD 同步、IPsec 等配置也用它；用安装器的 --config-only 重新选择")
		}
		if left == 0 && pciDevs <= 1 {
			a.Problems = append(a.Problems, "这是 dpdk 段里最后一块网卡，没有 dev 时 dpdk 插件会接管所有处于 down 状态的网卡")
		}
		if cliErr != nil {
			a.Problems = append(a.Problems, cliErr.Error())
		} else if uses := cliUses(string(cli), n.Name); len(uses) > 0 {
			shown := strings.Join(uses[:min(3, len(uses))], "；")
			if len(uses) > 3 {
				shown += fmt.Sprintf(" 等 %d 行", len(uses))
			}
			a.Problems = append(a.Problems, "CLI 文件还有命令用它，先在接口页删掉地址、子接口、桥和出口："+shown)
		}
		list = append(list, a)
	}
	return list
}

// RetireNIC takes a card or port out of VPP and gives it back to its driver, restarting VPP;
// unconfirmed, the files are put back and VPP takes the card again.
func (s *Service) RetireNIC(name, user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.otherPending(); err != nil {
		return nil, err
	}
	hw := s.hardware()
	ctx, reason := s.nicSetup(hw)
	if ctx == nil {
		return nil, errors.New(reason)
	}
	active := s.active(ctx, hw)
	i := slices.IndexFunc(active, func(a ActiveNIC) bool { return a.Name == name })
	if i < 0 {
		return nil, fmt.Errorf("router.env 里没有经 DPDK 接入的 %s", name)
	}
	a := active[i]
	if len(a.Problems) > 0 {
		return nil, errors.New(strings.Join(a.Problems, "；"))
	}
	var confText string
	var err error
	if len(a.Shares) > 0 {
		names := ctx.dev(a.Address).names()
		names[a.Port] = ""
		for len(names) > 0 && names[len(names)-1] == "" {
			names = names[:len(names)-1]
		}
		confText, err = ctx.conf.withDevName(a.Address, strings.Join(names, ","))
	} else {
		confText, err = ctx.conf.withoutDev(a.Address)
	}
	if err != nil {
		return nil, err
	}
	j := slices.IndexFunc(ctx.env.nics, func(n envNIC) bool { return n.Name == name })
	envText := ctx.env.withoutNIC(ctx.env.nics[j])
	driver := a.Driver
	if driver == "" || len(a.Shares) > 0 {
		// Not noted: the kernel picks one. A port of a card VPP keeps stays where it is.
		driver = "none"
	}
	retired := &AddedNIC{Address: a.Address, Driver: driver, Interface: a.Interface, Kind: a.Kind, Name: name}
	if len(a.Shares) > 0 {
		retired.Kind = "shared" // the card stays with VPP: nothing to give back
	}
	label := a.Address
	if a.Port > 0 || len(a.Shares) > 0 {
		label += fmt.Sprintf(" 口 %d", a.Port)
	}
	if a.Interface != "" {
		label += "，" + a.Interface
	}
	description := fmt.Sprintf("退出 DPDK 网卡 %s（%s）", name, label)
	if retired.Kind == "dpdk" && driver != "none" {
		description += "，交还 " + driver
	}
	return s.restartChange(user, description, map[string]string{s.opts.StartConf: confText, s.opts.RouterEnv: envText}, nil, retired, func(v vppAPI) error {
		text, err := v.CLI("show hardware-interfaces")
		if err != nil {
			return err
		}
		hw := parseHardware(text)
		if slices.ContainsFunc(hw, func(h hardware) bool { return h.Name == name }) {
			return fmt.Errorf("VPP 里还有 %s", name)
		}
		for _, other := range a.Shares {
			if !slices.ContainsFunc(hw, func(h hardware) bool { return h.Name == other }) {
				return fmt.Errorf("同一块卡上的 %s 没有了", other)
			}
		}
		return nil
	})
}

// AddNIC puts a PCI card into VPP through DPDK, restarting VPP; unconfirmed, the files are put
// back and the card goes back to its driver.
func (s *Service) AddNIC(q AddNICRequest, user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.otherPending(); err != nil {
		return nil, err
	}
	address, ok := pciAddress(q.Address)
	if !ok {
		return nil, fmt.Errorf("PCI 地址 %q 不对", q.Address)
	}
	ctx, reason := s.nicSetup(s.hardware())
	if ctx == nil {
		return nil, errors.New(reason)
	}
	cards := s.cards(ctx)
	i := slices.IndexFunc(cards, func(c NICView) bool { return c.Address == address && c.Port == q.Port })
	if i < 0 {
		return nil, fmt.Errorf("没有可以加入的网卡 %s 口 %d（已经在 VPP 里，或者不是网卡）", address, q.Port)
	}
	card := cards[i]
	if len(card.Problems) > 0 {
		return nil, errors.New(strings.Join(card.Problems, "；"))
	}
	if len(card.Warnings) > 0 && !q.Accept {
		return nil, errors.New(strings.Join(card.Warnings, "；"))
	}
	name := q.Name
	if !nicName.MatchString(name) {
		return nil, errors.New("接口名以字母开头，只用字母、数字、- 和 _，最长 32 个字符")
	}
	if slices.ContainsFunc(virtualPrefixes, func(p string) bool { return strings.HasPrefix(name, p) }) {
		return nil, fmt.Errorf("%s 开头的名字留给虚拟接口，接口页不会把它当物理口", name)
	}
	if ctx.names[name] {
		return nil, fmt.Errorf("已经有接口叫 %s", name)
	}
	// The dev block names the ports in order, "" for a port left out.
	var names []string
	queues := ctx.queues
	var confText string
	var err error
	if dev := ctx.dev(address); dev != nil {
		// Another port of this card is in VPP: the block's other settings apply to this port too.
		names = dev.names()
		for len(names) <= card.Port {
			names = append(names, "")
		}
		names[card.Port] = name
		if dev.Queues > 0 {
			queues = dev.Queues
		}
		confText, err = ctx.conf.withDevName(address, strings.Join(names, ","))
	} else {
		names = make([]string, card.Port+1)
		names[card.Port] = name
		if card.Interface != "" {
			if most := s.host.channels(card.Interface); most > 0 {
				queues = min(queues, most)
			}
		}
		var words []string
		// As the installer: mlx4 with RX scatter takes several descriptors a packet, and receives
		// far fewer packets a second.
		if card.Driver == "mlx4_core" && !slices.Contains(ctx.conf.dpdkWords(), "no-multi-seg") {
			words = append(words, "no-multi-seg")
		}
		confText, err = ctx.conf.withDev(address, strings.Join(names, ","), queues, words)
	}
	if err != nil {
		return nil, err
	}
	ifname := card.Interface
	if ifname == "" {
		ifname = "-"
	}
	envText := ctx.env.withNIC(envNIC{Role: "lan", Address: address, Interface: ifname, Kind: card.Kind, Name: name})
	if err := s.recordOriginal(address, card.Driver, ifname); err != nil {
		return nil, err
	}
	device := &AddedNIC{Address: address, Driver: card.Driver, Interface: ifname, Kind: card.Kind}
	label := address
	if card.Port > 0 || len(card.Shares) > 0 {
		label += fmt.Sprintf(" 口 %d", card.Port)
	}
	if card.Interface != "" {
		label += "（" + card.Interface + "）"
	}
	description := fmt.Sprintf("接入 DPDK 网卡 %s，VPP 接口名 %s，%d 个收包队列", label, name, queues)
	return s.restartChange(user, description, map[string]string{s.opts.StartConf: confText, s.opts.RouterEnv: envText}, device, nil, func(v vppAPI) error {
		text, err := v.CLI("show hardware-interfaces")
		if err != nil {
			return err
		}
		hw := parseHardware(text)
		for _, want := range names {
			if want != "" && !slices.ContainsFunc(hw, func(h hardware) bool { return h.PCI == address && h.Name == want }) {
				return fmt.Errorf("VPP 里没有出现 %s（%s）：PMD 没有接管它，详情看 journalctl -u %s", want, address, s.opts.VPPUnit)
			}
		}
		return nil
	})
}

// recordOriginal notes the card's driver in the installer's nics.orig, which its --restore uses to
// give cards back; the first driver seen stays, as the installer keeps it.
func (s *Service) recordOriginal(address, driver, ifname string) error {
	if s.opts.NICsOrig == "" {
		return nil
	}
	data, err := os.ReadFile(s.opts.NICsOrig)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 0 && sameAddress(f[0], address) {
			return nil
		}
	}
	text := string(data)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += fmt.Sprintf("%s %s %s\n", address, driver, ifname)
	if err := writeFileAtomic(s.opts.NICsOrig, []byte(text), 0o644); err != nil {
		return err
	}
	log.Printf("audit: %s recorded in %s with driver %s", address, s.opts.NICsOrig, driver)
	return nil
}
