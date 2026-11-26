package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pendingFile = "pending.json"
	backupFile  = "backup.vpp"
)

// Options configures the service.
type Options struct {
	CLIFile  string
	VPPUnit  string // restarts VPP for changes that cannot be made live; empty refuses them
	StateDir string
	Confirm  time.Duration
	// ExitsFile is where the interfaces with a default route are published, for gate-admin.
	ExitsFile string
	// OtherPending is vpp-system's pending change. It edits the same CLI file and puts it back
	// on rollback, so neither starts a change while the other waits.
	OtherPending string
	// DHCP is the LAN's dnsmasq; an empty Conf leaves DHCP out.
	DHCP DHCPOptions
	// RouterEnv is the installer's router.env, whose HOST_GW follows the LAN gateway.
	RouterEnv string
	// Meter counts each device's traffic on the LAN gateway, when switched on; needs DHCP.
	Meter MeterOptions
}

// Pending is an applied change waiting for confirmation.
type Pending struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	User        string    `json:"user"`
	Deadline    time.Time `json:"deadline"`
	Restart     bool      `json:"restart"`
	Undo        []string  `json:"undo"`
	Stamp       fileStamp `json:"stamp"`
	Follow      *Follow   `json:"follow,omitempty"` // what followed a gateway move
}

// Result is how the last change ended.
type Result struct {
	Description string    `json:"description"`
	Outcome     string    `json:"outcome"`
	Detail      string    `json:"detail"`
	Time        time.Time `json:"time"`
}

// step is one live command and the one undoing it.
type step struct{ do, undo string }

// change is what an operation does: the new file, and the live commands making VPP match
// it, or a restart when it cannot be made live.
type change struct {
	description string
	file        *cliFile
	steps       []step
	restart     bool
	move        *gatewayChange // the LAN gateway moves, and DHCP and Linux follow
}

// Service applies changes one at a time.
type Service struct {
	opts Options
	sys  system
	now  func() time.Time

	sleep      func(time.Duration)
	linkExists func(string) bool // whether Linux has an interface of this name

	dhcp  *DHCP  // nil without DHCP
	meter *Meter // nil without DHCP
	run  runner // commands outside VPP, such as ip

	mu      sync.Mutex
	pending *Pending
	last    *Result
	timer   *time.Timer
	nextID  int
}

// NewService finishes what a previous run left: an unconfirmed change is rolled back, or
// keeps its deadline if there is still time.
func NewService(opts Options, sys system) (*Service, error) {
	if opts.Confirm <= 0 {
		opts.Confirm = time.Minute
	}
	s := &Service{opts: opts, sys: sys, now: time.Now, sleep: time.Sleep, linkExists: linkExists, run: execRunner}
	if opts.DHCP.Conf != "" {
		s.dhcp = NewDHCP(opts.DHCP)
	}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(opts.StateDir, pendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var pending Pending
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil, fmt.Errorf("%s: %w", pendingFile, err)
	}
	s.pending = &pending
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.now().Before(pending.Deadline) {
		s.rollbackLocked("管理服务重启时改动还没有确认")
		return s, nil
	}
	s.arm()
	return s, nil
}

func (s *Service) arm() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(s.pending.Deadline.Sub(s.now()), s.expire)
}

func (s *Service) expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil && !s.now().Before(s.pending.Deadline) {
		s.rollbackLocked("没有在期限内确认")
	}
}

func (s *Service) finish(description, outcome, detail string) {
	s.last = &Result{Description: description, Outcome: outcome, Detail: detail, Time: s.now()}
	log.Printf("audit: %s: %s %s", description, outcome, detail)
}

func (s *Service) backupPath() string { return filepath.Join(s.opts.StateDir, backupFile) }

func (s *Service) savePending() error {
	data, err := json.Marshal(s.pending)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.opts.StateDir, pendingFile), data, 0o600)
}

func (s *Service) clearPending() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.pending = nil
	os.Remove(filepath.Join(s.opts.StateDir, pendingFile))
	os.Remove(s.backupPath())
}

func (s *Service) fileMode() os.FileMode {
	if info, err := os.Stat(s.opts.CLIFile); err == nil {
		return info.Mode().Perm()
	}
	return 0o644
}

func (s *Service) restoreFile() error {
	data, err := os.ReadFile(s.backupPath())
	if err != nil {
		return err
	}
	return writeFileAtomic(s.opts.CLIFile, data, s.fileMode())
}

const settleTimeout = 60 * time.Second

// restartVPP restarts VPP and waits until it has run the CLI file now on disk.
func (s *Service) restartVPP() error {
	before, _ := s.sys.stamp()
	if err := s.sys.restart(s.opts.VPPUnit); err != nil {
		return err
	}
	if err := s.sys.ready(s.opts.VPPUnit, before); err != nil {
		return err
	}
	return s.settle()
}

// settle waits for VPP to finish its startup file, which it runs after the API is up:
// until the interfaces the file creates exist and two readings a second apart agree.
func (s *Service) settle() error {
	file, err := s.load()
	if err != nil {
		return err
	}
	var created []string
	for _, line := range file.lines {
		if line.kind == lineSubif || line.kind == lineLoopback || line.kind == lineCreate {
			created = append(created, line.iface)
		}
	}
	previous := ""
	for waited := time.Duration(0); waited < settleTimeout; waited += time.Second {
		live, err := s.sys.read()
		if err == nil {
			var names []string
			for _, iface := range live.Interfaces {
				names = append(names, iface.Name)
			}
			missing := slices.ContainsFunc(created, func(name string) bool { return !slices.Contains(names, name) })
			key := strings.Join(names, " ")
			if !missing && key == previous {
				return nil
			}
			previous = key
		}
		s.sleep(time.Second)
	}
	return errors.New("VPP 重启后没有在 60 秒内建好配置文件里的接口")
}

// undo runs undo commands in order, and reports the first failure.
func (s *Service) undo(commands []string) error {
	var first error
	for _, command := range commands {
		command, err := s.resolveIndexes(command)
		if err == nil {
			_, err = s.sys.cli(command)
		}
		if err != nil {
			log.Printf("undo %q: %v", command, err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// rollbackLocked puts the file back, and VPP with it: by the undo commands, or by a restart
// when the change was one or VPP has restarted since and so runs the changed file.
func (s *Service) rollbackLocked(reason string) {
	description := s.pending.Description
	if err := s.restoreFile(); err != nil {
		s.finish(description, "rollback-failed", reason+"：恢复配置文件失败："+err.Error())
		return // the backup stays, for someone to look at
	}
	s.publishExits()
	restart := s.pending.Restart
	if !restart {
		if stamp, err := s.sys.stamp(); err != nil || stamp != s.pending.Stamp {
			restart = true
		}
	}
	var err error
	switch {
	case restart && s.opts.VPPUnit != "":
		err = s.restartVPP()
	case restart:
		err = errors.New("VPP 已经重启过，没有设置 --vpp-unit，配置文件已恢复，要再重启 VPP 才能生效")
	default:
		err = s.undo(s.pending.Undo)
	}
	if f := s.pending.Follow; f != nil {
		if followErr := s.unfollow(f); followErr != nil {
			err = errors.Join(err, followErr)
		}
	}
	if err != nil {
		s.finish(description, "rollback-failed", reason+"："+err.Error())
	} else {
		s.finish(description, "rolled-back", reason)
	}
	s.clearPending()
}

func (s *Service) load() (*cliFile, error) {
	data, err := os.ReadFile(s.opts.CLIFile)
	if err != nil {
		return nil, err
	}
	return parseCLI(string(data)), nil
}

// apply makes a change and leaves it waiting for confirmation.
func (s *Service) apply(user string, build func(*cliFile, *liveState) (*change, error)) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		return nil, errors.New("还有改动等待确认")
	}
	if s.opts.OtherPending != "" {
		if _, err := os.Stat(s.opts.OtherPending); err == nil {
			return nil, errors.New("系统页还有改动等待确认，确认或恢复后再改")
		}
	}
	file, err := s.load()
	if err != nil {
		return nil, err
	}
	original := file.String()
	live, err := s.sys.read()
	if err != nil {
		return nil, fmt.Errorf("读取 VPP 状态失败：%w", err)
	}
	c, err := build(file.clone(), live)
	if err != nil {
		return nil, err
	}
	if c.restart && s.opts.VPPUnit == "" {
		return nil, errors.New("这个改动要重启 VPP，但管理服务没有设置 --vpp-unit")
	}
	if err := writeFileAtomic(s.backupPath(), []byte(original), 0o600); err != nil {
		return nil, err
	}
	var undo []string
	if !c.restart {
		for _, step := range c.steps {
			if _, err := s.sys.cli(step.do); err != nil {
				s.undo(undo)
				os.Remove(s.backupPath())
				return nil, err
			}
			if step.undo != "" {
				undo = append(strings.Split(step.undo, "\n"), undo...)
			}
		}
	}
	if err := writeFileAtomic(s.opts.CLIFile, []byte(c.file.String()), s.fileMode()); err != nil {
		s.undo(undo)
		os.Remove(s.backupPath())
		return nil, err
	}
	s.publishExits()
	s.nextID++
	s.pending = &Pending{
		ID: strconv.FormatInt(s.now().Unix(), 10) + "-" + strconv.Itoa(s.nextID), Description: c.description,
		User: user, Restart: c.restart, Undo: undo,
	}
	log.Printf("audit: %s applied by %s", c.description, user)
	if c.restart {
		if err := s.restartVPP(); err != nil {
			s.rollbackLocked("VPP 没有恢复：" + err.Error())
			return nil, fmt.Errorf("VPP 重启后没有恢复，已恢复旧配置：%w", err)
		}
	}
	if c.move != nil {
		if err := s.follow(*c.move); err != nil {
			s.rollbackLocked("DHCP 和 Linux 的网关没有跟着改好：" + err.Error())
			return nil, fmt.Errorf("DHCP 和 Linux 的网关没有跟着改好，已恢复旧配置：%w", err)
		}
	}
	if stamp, err := s.sys.stamp(); err == nil {
		s.pending.Stamp = stamp
	}
	s.pending.Deadline = s.now().Add(s.opts.Confirm)
	if err := s.savePending(); err != nil {
		s.rollbackLocked("保存待确认状态失败：" + err.Error())
		return nil, err
	}
	s.arm()
	return s.stateLocked(), nil
}

// Confirm keeps the pending change.
func (s *Service) Confirm(user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return nil, errors.New("没有等待确认的改动")
	}
	description := s.pending.Description
	s.clearPending()
	s.finish(description, "confirmed", "由 "+user+" 确认")
	return s.stateLocked(), nil
}

// Rollback undoes the pending change now.
func (s *Service) Rollback(user string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return nil, errors.New("没有等待确认的改动")
	}
	s.rollbackLocked("由 " + user + " 撤销")
	return s.stateLocked(), nil
}

// The panel's view.

type InterfaceView struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"` // physical, sub, loopback, other
	Parent        string   `json:"parent,omitempty"`
	SubID         uint32   `json:"sub_id,omitempty"`
	VLAN          uint16   `json:"vlan,omitempty"`
	Up            bool     `json:"up"`
	Link          bool     `json:"link"`
	MTU           uint32   `json:"mtu"`
	Addresses     []string `json:"addresses"`
	FileAddresses []string `json:"file_addresses"`
	Bridge        uint32   `json:"bridge"`
	BVI           bool     `json:"bvi"`
	// How the file has it get its addresses, per family.
	IPv4 Family `json:"ipv4"`
	IPv6 Family `json:"ipv6"`
	// Why each part cannot be changed; empty when it can.
	Reason        string `json:"reason"`
	AddressReason string `json:"address_reason"`
	BridgeReason  string `json:"bridge_reason"`
	VLANReason    string `json:"vlan_reason"`
	DeleteReason  string `json:"delete_reason"`
	// NAT is whether the interface is an exit: what leaves by it is translated to its address.
	NAT bool `json:"nat"`
	// DHCPGateway is the router of the IPv4 DHCP lease, as VPP has it now.
	DHCPGateway string `json:"dhcp_gateway,omitempty"`
	// IPv6Gateway is ::/0's next hop through the interface, as VPP has it now.
	IPv6Gateway string `json:"ipv6_gateway,omitempty"`
	NATReason   string `json:"nat_reason"` // why it cannot be turned on; turning it off has its own checks
	// Hairpin is whether the file turns NAT hairpinning on for the interface; HairpinLive whether
	// VPP has it on now. HairpinReason is why it cannot be turned on.
	Hairpin       bool     `json:"hairpin"`
	HairpinLive   bool     `json:"hairpin_live"`
	HairpinReason string   `json:"hairpin_reason"`
	References    []string `json:"references"`
}

type BridgeView struct {
	ID      uint32   `json:"id"`
	Members []string `json:"members"`
	BVI     string   `json:"bvi"`
	InFile  bool     `json:"in_file"`
}

type State struct {
	File             string          `json:"file"`
	CanRestart       bool            `json:"can_restart"`
	Error            string          `json:"error"`
	Interfaces       []InterfaceView `json:"interfaces"`
	Bridges          []BridgeView    `json:"bridges"`
	Pending          *Pending        `json:"pending"`
	SecondsRemaining float64         `json:"seconds_remaining"`
	Last             *Result         `json:"last"`
}

func (s *Service) State() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stateLocked()
}

func (s *Service) stateLocked() *State {
	state := &State{File: s.opts.CLIFile, CanRestart: s.opts.VPPUnit != "", Interfaces: []InterfaceView{}, Bridges: []BridgeView{}, Pending: s.pending, Last: s.last}
	if s.pending != nil {
		state.SecondsRemaining = max(0, s.pending.Deadline.Sub(s.now()).Seconds())
	}
	file, err := s.load()
	if err != nil {
		state.Error = "读取配置文件失败：" + err.Error()
		return state
	}
	live, err := s.sys.read()
	if err != nil {
		state.Error = "读取 VPP 状态失败：" + err.Error()
		return state
	}
	for _, iface := range live.Interfaces {
		if iface.Name == "local0" {
			continue
		}
		state.Interfaces = append(state.Interfaces, s.view(file, live, iface))
	}
	state.Bridges = bridgeViews(file, live)
	return state
}

var virtualPrefixes = []string{"tap", "tun", "wg", "loop", "ipip", "gre", "vxlan", "memif", "pg", "ipsec", "lcp", "pipe", "geneve", "gtpu", "srv6", "lisp", "nat", "mpls"}

func kindOf(iface *liveInterface) string {
	switch {
	case iface.Sub:
		return "sub"
	case strings.HasPrefix(iface.Name, "loop"):
		return "loopback"
	case strings.HasPrefix(iface.Name, "vxlan_tunnel"):
		return "vxlan"
	case strings.HasPrefix(iface.Name, "gre"):
		return "gre"
	case strings.HasPrefix(iface.Name, "ipip"):
		return "ipip"
	case strings.HasPrefix(iface.Name, "tap"):
		return "tap"
	case iface.Hardware && !slices.ContainsFunc(virtualPrefixes, func(prefix string) bool { return strings.HasPrefix(iface.Name, prefix) }):
		return "physical"
	}
	return "other"
}

// managed tells whether the panel may change an interface, and why not.
func managed(file *cliFile, iface *liveInterface) string {
	if file.mentions(iface.Name) || kindOf(iface) == "physical" {
		return ""
	}
	return "配置文件里没有这个接口，由其他程序管理"
}

func prefixStrings(prefixes []netip.Prefix) []string {
	texts := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		texts[i] = prefix.String()
	}
	return texts
}

func fileAddresses(file *cliFile, iface string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, i := range file.own(iface, lineAddress) {
		prefixes = append(prefixes, file.lines[i].prefix)
	}
	return prefixes
}

// fileBridge is the bridge the file puts iface in.
func fileBridge(file *cliFile, iface string) (uint32, bool) {
	lines := file.own(iface, lineBridge)
	if len(lines) == 0 {
		return 0, false
	}
	line := file.lines[lines[len(lines)-1]]
	return line.bd, line.bvi
}

func (s *Service) view(file *cliFile, live *liveState, iface *liveInterface) InterfaceView {
	v := InterfaceView{
		Name: iface.Name, Kind: kindOf(iface), Parent: iface.Parent, Up: iface.Up, Link: iface.Link, MTU: iface.MTU,
		Addresses: prefixStrings(iface.Addresses), FileAddresses: prefixStrings(fileAddresses(file, iface.Name)),
		Bridge: iface.Bridge, BVI: iface.BVI, References: []string{},
		IPv4: fileFamily(file, iface.Name, false).view(), IPv6: fileFamily(file, iface.Name, true).view(),
	}
	if iface.Sub {
		v.SubID, v.VLAN = iface.SubID, iface.VLAN
	}
	for _, line := range file.references(iface.Name) {
		v.References = append(v.References, strings.TrimSpace(line.text))
	}
	v.NAT = natEnabled(file, iface.Name)
	v.Hairpin, v.HairpinLive = hairpinEnabled(file, iface.Name), live.Hairpin[iface.Name]
	if iface.DHCPRouter.IsValid() {
		v.DHCPGateway = iface.DHCPRouter.String()
	}
	if iface.IPv6Router.IsValid() {
		v.IPv6Gateway = iface.IPv6Router.String()
	}
	v.Reason = managed(file, iface)
	if v.Reason != "" {
		v.AddressReason, v.BridgeReason, v.VLANReason, v.DeleteReason, v.NATReason, v.HairpinReason = v.Reason, v.Reason, v.Reason, v.Reason, v.Reason, v.Reason
		return v
	}
	v.NATReason = natReason(file, live, iface)
	if !v.Hairpin {
		v.HairpinReason = hairpinReason(file, live, iface)
	}
	bd, bvi := fileBridge(file, iface.Name)
	switch {
	case (iface.Bridge != 0 && !iface.BVI) || (bd != 0 && !bvi):
		v.AddressReason = "接口在网桥里，二层接口不能有地址"
	}
	subLines := file.own(iface.Name, lineSubif)
	switch {
	case !iface.Sub:
		v.VLANReason, v.DeleteReason = "不是 VLAN 子接口", deviceDeleteReason(file, iface)
	case len(subLines) == 0:
		v.VLANReason, v.DeleteReason = "这个子接口不是配置文件创建的", "这个子接口不是配置文件创建的"
	default:
		if !s.opts.canRestart() {
			v.VLANReason = "修改 VLAN ID 要重启 VPP，管理服务没有设置 --vpp-unit"
		}
		if len(v.References) > 0 {
			v.DeleteReason = "配置文件里还有引用它的命令：" + v.References[0]
		}
		if len(file.own(iface.Name, lineNATAddress, lineNATOutput)) > 0 {
			v.DeleteReason = "还是出口（NAT），先取消"
		}
		if hairpinEnabled(file, iface.Name) {
			v.DeleteReason = "开着 NAT 回流，先关闭"
		}
	}
	if len(file.own(iface.Name, lineNATAddress, lineNATOutput)) > 0 && v.BridgeReason == "" {
		v.BridgeReason = "是出口（NAT），先取消才能加入网桥"
	}
	if hairpinEnabled(file, iface.Name) && v.BridgeReason == "" {
		v.BridgeReason = "开着 NAT 回流，先关闭才能改网桥"
	}
	return v
}

func (o Options) canRestart() bool { return o.VPPUnit != "" }

func bridgeViews(file *cliFile, live *liveState) []BridgeView {
	byID := map[uint32]*BridgeView{}
	get := func(id uint32) *BridgeView {
		if byID[id] == nil {
			byID[id] = &BridgeView{ID: id, Members: []string{}}
		}
		return byID[id]
	}
	for id := range live.Bridges {
		get(id)
	}
	for _, line := range file.lines {
		if line.kind == lineBridgeDom || line.kind == lineBridge {
			get(line.bd).InFile = true
		}
	}
	for _, iface := range live.Interfaces {
		if iface.Bridge == 0 {
			continue
		}
		bridge := get(iface.Bridge)
		if iface.BVI {
			bridge.BVI = iface.Name
		} else {
			bridge.Members = append(bridge.Members, iface.Name)
		}
	}
	views := make([]BridgeView, 0, len(byID))
	for _, view := range byID {
		views = append(views, *view)
	}
	slices.SortFunc(views, func(a, b BridgeView) int { return int(a.ID) - int(b.ID) })
	return views
}

// Operations. Each checks against the file and VPP's running state, and changes nothing
// when a check fails.

func editable(file *cliFile, live *liveState, name string) (*liveInterface, error) {
	iface := live.find(name)
	if iface == nil || name == "local0" {
		return nil, fmt.Errorf("VPP 里没有接口 %s", name)
	}
	if reason := managed(file, iface); reason != "" {
		return nil, fmt.Errorf("%s：%s", name, reason)
	}
	return iface, nil
}

func parsePrefixes(texts []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, text := range texts {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("%q 不是“地址/掩码长度”格式，比如 10.61.70.1/24", text)
		}
		address := prefix.Addr()
		if address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("%s 不能用作接口地址", text)
		}
		if (address.Is4() && prefix.Bits() > 32) || prefix.Bits() == 0 {
			return nil, fmt.Errorf("%s 的掩码长度不对", text)
		}
		if address.Is4() && prefix.Bits() < 31 {
			if address == prefix.Masked().Addr() {
				return nil, fmt.Errorf("%s 是网络地址，不能用作接口地址", text)
			}
		}
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes, nil
}

// SetAddresses replaces the addresses the file gives an interface.
func (s *Service) SetAddresses(name string, texts []string, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		wanted, err := parsePrefixes(texts)
		if err != nil {
			return nil, err
		}
		bd, bvi := fileBridge(file, name)
		if len(wanted) > 0 && ((iface.Bridge != 0 && !iface.BVI) || (bd != 0 && !bvi)) {
			return nil, fmt.Errorf("%s 在网桥里，二层接口不能有地址，先把它移出网桥", name)
		}
		if fileFamily(file, name, false).dynamic() || fileFamily(file, name, true).dynamic() || len(file.own(name, lineGateway)) > 0 {
			return nil, fmt.Errorf("%s 用了 DHCP、SLAAC 或网关，按地址族分别设置", name)
		}
		for _, other := range live.Interfaces {
			if other.Name == name {
				continue
			}
			for _, theirs := range other.Addresses {
				for _, mine := range wanted {
					if theirs.Overlaps(mine) {
						return nil, fmt.Errorf("%s 和 %s 的地址 %s 重叠", mine, other.Name, theirs)
					}
				}
			}
		}
		old := fileAddresses(file, name)
		c := &change{file: file}
		for _, prefix := range old {
			if !slices.Contains(wanted, prefix) && slices.Contains(iface.Addresses, prefix) {
				c.steps = append(c.steps, step{addressCommand(name, prefix, true), addressCommand(name, prefix, false)})
			}
		}
		for _, prefix := range wanted {
			if !slices.Contains(iface.Addresses, prefix) {
				c.steps = append(c.steps, step{addressCommand(name, prefix, false), addressCommand(name, prefix, true)})
			}
		}
		lines := make([]string, len(wanted))
		for i, prefix := range wanted {
			lines[i] = addressCommand(name, prefix, false)
		}
		file.set(name, lineAddress, lines, file.own(name, lineSubif, lineLoopback, lineBridge)...)
		// A bridge's gateway is named by its bridge, as the panel shows it.
		what := name + " 的地址"
		if iface.BVI {
			what = fmt.Sprintf("网桥 %d 的网关地址", iface.Bridge)
		}
		if len(wanted) == 0 {
			c.description = "删除 " + what
		} else {
			c.description = fmt.Sprintf("把 %s改成 %s", what, strings.Join(prefixStrings(wanted), "、"))
		}
		if slices.Equal(old, wanted) && len(c.steps) == 0 {
			return nil, errors.New("地址没有变化")
		}
		from, to, moves, err := s.dhcp.gatewayMove(old, wanted)
		if err != nil {
			return nil, err
		}
		if moves {
			c.move = &gatewayChange{from, to}
			c.description += fmt.Sprintf("，DHCP 发的网关和 Linux 管理口的默认路由从 %s 跟着改成 %s", from, to)
		}
		return c, nil
	})
}

// SetBridge moves an interface into a bridge domain, or out of any when bd is 0.
func (s *Service) SetBridge(name string, bd uint32, bvi bool, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		oldBD, oldBVI := iface.Bridge, iface.BVI
		if oldBD == bd && oldBVI == bvi {
			return nil, errors.New("网桥没有变化")
		}
		if bd != 0 && len(file.own(name, lineNATAddress, lineNATOutput)) > 0 {
			return nil, fmt.Errorf("%s 是出口（NAT），先取消才能加入网桥", name)
		}
		if hairpinEnabled(file, name) {
			return nil, fmt.Errorf("%s 开着 NAT 回流，先关闭才能改网桥", name)
		}
		c := &change{file: file}
		pop := iface.Sub && iface.Exact && iface.Plain
		hadPop := len(file.own(name, lineTagRewrite)) > 0
		// Leave the current bridge first.
		if oldBD != 0 {
			// Undo runs in reverse, so the bridge is rejoined before the tag rewrite returns.
			if hadPop {
				c.steps = append(c.steps, step{"set interface l2 tag-rewrite " + name + " disable", tagPopCommand(name)})
			}
			c.steps = append(c.steps, step{"set interface l3 " + name, bridgeCommand(name, oldBD, oldBVI)})
		}
		file.remove(file.own(name, lineTagRewrite)...)
		if bd == 0 {
			file.remove(file.own(name, lineBridge)...)
			c.description = fmt.Sprintf("把 %s 移出网桥 %d", name, oldBD)
			return c, nil
		}
		if bvi {
			if !strings.HasPrefix(name, "loop") {
				return nil, errors.New("只有 loopback 接口可以做 BVI")
			}
			for _, other := range live.Interfaces {
				if other.Bridge == bd && other.BVI && other.Name != name {
					return nil, fmt.Errorf("网桥 %d 已经有 BVI %s", bd, other.Name)
				}
			}
		} else if len(iface.Addresses) > 0 || addressed(file, name) {
			return nil, fmt.Errorf("%s 有地址，加入网桥前要先把 IPv4 和 IPv6 都设为不配置", name)
		}
		if !live.Bridges[bd] && file.bridgeDomainLine(bd) < 0 {
			return nil, fmt.Errorf("网桥 %d 不存在，先新建", bd)
		}
		c.steps = append(c.steps, step{bridgeCommand(name, bd, bvi), "set interface l3 " + name})
		lines := []string{bridgeCommand(name, bd, bvi)}
		if pop && !bvi {
			c.steps = append(c.steps, step{tagPopCommand(name), "set interface l2 tag-rewrite " + name + " disable"})
			lines = append(lines, tagPopCommand(name))
		}
		file.set(name, lineBridge, lines, append(file.own(name, lineSubif, lineLoopback), file.bridgeDomainLine(bd))...)
		if oldBD != 0 {
			c.description = fmt.Sprintf("把 %s 从网桥 %d 移到网桥 %d", name, oldBD, bd)
		} else {
			c.description = fmt.Sprintf("把 %s 加入网桥 %d", name, bd)
		}
		if bvi {
			c.description += "（BVI）"
		}
		return c, nil
	})
}

// SetState sets an interface's administrative state.
func (s *Service) SetState(name string, up bool, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		lines := file.own(name, lineState)
		if iface.Up == up && len(lines) > 0 && file.lines[lines[len(lines)-1]].up == up {
			return nil, errors.New("状态没有变化")
		}
		c := &change{file: file, description: fmt.Sprintf("把 %s 设为 %s", name, map[bool]string{true: "up", false: "down"}[up])}
		if iface.Up != up {
			c.steps = []step{{stateCommand(name, up), stateCommand(name, iface.Up)}}
		}
		file.set(name, lineState, []string{stateCommand(name, up)}, file.own(name)...)
		return c, nil
	})
}

// SetMTU sets an interface's packet MTU.
func (s *Service) SetMTU(name string, mtu uint32, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		if mtu < 576 || mtu > 9216 {
			return nil, errors.New("MTU 要在 576 到 9216 之间")
		}
		if iface.MTU == mtu && len(file.own(name, lineMTU)) > 0 {
			return nil, errors.New("MTU 没有变化")
		}
		c := &change{file: file, description: fmt.Sprintf("把 %s 的 MTU 改成 %d", name, mtu)}
		if iface.MTU != mtu {
			c.steps = []step{{mtuCommand(name, mtu), mtuCommand(name, iface.MTU)}}
		}
		file.set(name, lineMTU, []string{mtuCommand(name, mtu)}, file.own(name, lineSubif, lineLoopback)...)
		return c, nil
	})
}

func vlanInUse(file *cliFile, live *liveState, base string, vlan uint16, except string) string {
	for _, iface := range live.Interfaces {
		if iface.Sub && iface.Parent == base && iface.VLAN == vlan && iface.Name != except {
			return iface.Name
		}
	}
	for _, line := range file.lines {
		if line.kind == lineSubif && line.base == base && line.vlan == vlan && line.iface != except {
			return line.iface
		}
	}
	return ""
}

// CreateSubif creates a dot1q sub-interface, up and with nothing on it.
func (s *Service) CreateSubif(base string, id uint32, vlan uint16, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		parent, err := editable(file, live, base)
		if err != nil {
			return nil, err
		}
		if parent.Sub || kindOf(parent) == "loopback" {
			return nil, fmt.Errorf("%s 上不能建 VLAN 子接口", base)
		}
		if vlan < 1 || vlan > 4094 {
			return nil, errors.New("VLAN ID 要在 1 到 4094 之间")
		}
		if id == 0 {
			id = uint32(vlan)
		}
		name := fmt.Sprintf("%s.%d", base, id)
		if live.find(name) != nil || len(file.own(name, lineSubif)) > 0 {
			return nil, fmt.Errorf("%s 已经存在", name)
		}
		if other := vlanInUse(file, live, base, vlan, ""); other != "" {
			return nil, fmt.Errorf("%s 上的 VLAN %d 已经由 %s 使用", base, vlan, other)
		}
		c := &change{file: file, description: fmt.Sprintf("在 %s 上新建 VLAN %d 子接口 %s", base, vlan, name)}
		c.steps = []step{{subifCommand(base, id, vlan), "delete sub-interface " + name}, {stateCommand(name, true), ""}}
		at := len(file.lines)
		if own := file.own(base); len(own) > 0 {
			at = file.insertionPoint(base)
		}
		file.insert(at, subifCommand(base, id, vlan), stateCommand(name, true))
		return c, nil
	})
}

// DeleteSubif deletes a sub-interface the file created, and its lines.
func (s *Service) DeleteSubif(name string, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		own := file.own(name)
		if !iface.Sub || len(file.own(name, lineSubif)) == 0 {
			return nil, fmt.Errorf("%s 不是配置文件创建的 VLAN 子接口", name)
		}
		if refs := file.references(name); len(refs) > 0 {
			return nil, fmt.Errorf("配置文件里还有引用 %s 的命令，先删掉：%s", name, strings.TrimSpace(refs[0].text))
		}
		if fileFamily(file, name, false).dynamic() || fileFamily(file, name, true).dynamic() || len(file.own(name, lineGateway)) > 0 {
			return nil, fmt.Errorf("%s 还在用 DHCP、SLAAC 或网关，先把 IPv4 和 IPv6 设为不配置", name)
		}
		if len(file.own(name, lineNATAddress, lineNATOutput)) > 0 {
			return nil, fmt.Errorf("%s 还是出口（NAT），先取消", name)
		}
		if hairpinEnabled(file, name) {
			return nil, fmt.Errorf("%s 开着 NAT 回流，先关闭", name)
		}
		c := &change{file: file, description: "删除子接口 " + name}
		// Undo runs in reverse: the interface is recreated from its lines, then gets its
		// addresses back, then rejoins its bridge.
		if iface.Bridge != 0 {
			rejoin := []string{bridgeCommand(name, iface.Bridge, iface.BVI)}
			if len(file.own(name, lineTagRewrite)) > 0 {
				rejoin = append(rejoin, tagPopCommand(name))
			}
			c.steps = append(c.steps, step{"set interface l3 " + name, strings.Join(rejoin, "\n")})
		}
		for _, prefix := range iface.Addresses {
			c.steps = append(c.steps, step{addressCommand(name, prefix, true), addressCommand(name, prefix, false)})
		}
		var recreate []string
		for _, i := range file.own(name, lineSubif, lineState, lineMTU) {
			recreate = append(recreate, strings.TrimSpace(file.lines[i].text))
		}
		c.steps = append(c.steps, step{"delete sub-interface " + name, strings.Join(recreate, "\n")})
		file.remove(own...)
		return c, nil
	})
}

// ChangeVLAN changes the VLAN a sub-interface matches. VPP cannot do that in place, and
// recreating the interface would lose what other programs put on it, so VPP restarts.
func (s *Service) ChangeVLAN(name string, vlan uint16, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		if _, err := editable(file, live, name); err != nil {
			return nil, err
		}
		lines := file.own(name, lineSubif)
		if len(lines) == 0 {
			return nil, fmt.Errorf("%s 不是配置文件创建的 VLAN 子接口", name)
		}
		if vlan < 1 || vlan > 4094 {
			return nil, errors.New("VLAN ID 要在 1 到 4094 之间")
		}
		line := file.lines[lines[0]]
		if line.vlan == vlan {
			return nil, errors.New("VLAN ID 没有变化")
		}
		if other := vlanInUse(file, live, line.base, vlan, name); other != "" {
			return nil, fmt.Errorf("%s 上的 VLAN %d 已经由 %s 使用", line.base, vlan, other)
		}
		text := fmt.Sprintf("create sub-interface %s %d dot1q %d", line.base, line.subID, vlan)
		if line.exact {
			text += " exact-match"
		}
		file.replace(lines[0], text)
		return &change{file: file, restart: true, description: fmt.Sprintf("把 %s 的 VLAN ID 从 %d 改成 %d（重启 VPP）", name, line.vlan, vlan)}, nil
	})
}

// CreateBridge creates a bridge domain, and optionally a loopback as its BVI.
func (s *Service) CreateBridge(bd uint32, bvi bool, addresses []string, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		if bd < 1 || bd > 0xFFFFFF {
			return nil, errors.New("网桥编号要在 1 到 16777215 之间")
		}
		if live.Bridges[bd] || file.bridgeDomainLine(bd) >= 0 {
			return nil, fmt.Errorf("网桥 %d 已经存在", bd)
		}
		wanted, err := parsePrefixes(addresses)
		if err != nil {
			return nil, err
		}
		if len(wanted) > 0 && !bvi {
			return nil, errors.New("只有 BVI 能有地址")
		}
		c := &change{file: file, description: fmt.Sprintf("新建网桥 %d", bd)}
		create := fmt.Sprintf("create bridge-domain %d", bd)
		c.steps = []step{{create, fmt.Sprintf("create bridge-domain %d del", bd)}}
		lines := []string{"", create}
		if bvi {
			instance := bd
			for live.find(fmt.Sprintf("loop%d", instance)) != nil || file.mentions(fmt.Sprintf("loop%d", instance)) {
				instance++
			}
			loop := fmt.Sprintf("loop%d", instance)
			for _, other := range live.Interfaces {
				for _, theirs := range other.Addresses {
					for _, mine := range wanted {
						if theirs.Overlaps(mine) {
							return nil, fmt.Errorf("%s 和 %s 的地址 %s 重叠", mine, other.Name, theirs)
						}
					}
				}
			}
			bviLines := []string{fmt.Sprintf("create loopback interface instance %d", instance), bridgeCommand(loop, bd, true)}
			for _, prefix := range wanted {
				bviLines = append(bviLines, addressCommand(loop, prefix, false))
			}
			bviLines = append(bviLines, stateCommand(loop, true))
			c.steps = append(c.steps, step{bviLines[0], "delete loopback interface intfc " + loop})
			for _, line := range bviLines[1:] {
				c.steps = append(c.steps, step{line, ""})
			}
			lines = append(lines, bviLines...)
			c.description += "，网关 " + loop
			if len(wanted) > 0 {
				c.description += " 地址 " + strings.Join(prefixStrings(wanted), "、")
			}
		}
		file.insert(len(file.lines), lines...)
		return c, nil
	})
}
