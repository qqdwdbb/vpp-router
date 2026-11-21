package main

import (
	"cmp"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	watchEvery = 2 * time.Second
	// checkEvery re-reads VPP while an ACL is applied, for WAN addresses and interfaces that
	// change under it (DHCPv6, SLAAC, a new NAT exit).
	checkEvery = 10 * time.Second
	retryEvery = 10 * time.Second
	// settle is how long VPP's API socket must exist before restoring, without -vpp-unit.
	settle = 30 * time.Second
	// staticsEvery is how long the page reuses VPP's static mappings. Dumping them holds
	// VPP's worker barrier for the whole list (on the N1, 4096 mappings stall forwarding
	// 20-40 ms), and the page reloads every 5 seconds while open. Ours come from the file;
	// only others' show up to this late.
	staticsEvery = time.Minute
)

// Options configures the service.
type Options struct {
	ConfigFile string
	APISocket  string
	VPPUnit    string
}

// Service applies one change at a time, each to VPP and the file together.
type Service struct {
	opts       Options
	dial       func() (vppAPI, error)
	unitActive func(string) bool
	stamp      func(string) (fileStamp, error)
	now        func() time.Time

	mu         sync.Mutex
	cfg        *Config
	applied    fileStamp // the VPP run the configuration was applied to
	checkedAt  time.Time
	retryAt    time.Time
	applyError string
	// statics are VPP's static mappings as last read in full, at staticsAt from the VPP run
	// staticsRun.
	statics    []mapping
	staticsAt  time.Time
	staticsRun fileStamp
}

func NewService(opts Options, dial func() (vppAPI, error)) (*Service, error) {
	cfg, err := loadConfig(opts.ConfigFile)
	if err != nil {
		return nil, err
	}
	return &Service{opts: opts, dial: dial, cfg: cfg, stamp: stampOf, now: time.Now,
		unitActive: func(unit string) bool { return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil }}, nil
}

// WAN is a WAN interface and its addresses.
type WAN struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// ForwardView is a forward, or a static mapping someone else made (ID 0, read only).
type ForwardView struct {
	Forward
	Other   bool   `json:"other,omitempty"`
	Problem string `json:"problem,omitempty"`
}

// PortView is a router port, or an identity mapping someone else made (ID 0, read only).
type PortView struct {
	Port
	Other   bool   `json:"other,omitempty"`
	Problem string `json:"problem,omitempty"`
}

// Network is a LAN network a forward can go to.
type Network struct {
	Interface string `json:"interface"`
	Prefix    string `json:"prefix"`
}

// State is what the firewall page shows.
type State struct {
	WAN          []WAN         `json:"wan"`
	WANMissing   []string      `json:"wan_missing,omitempty"`
	WANFixed     bool          `json:"wan_fixed"` // set in the file, not taken from NAT
	AllowPing    bool          `json:"allow_ping"`
	IPv6Firewall bool          `json:"ipv6_firewall"`
	Forwards     []ForwardView `json:"forwards"`
	Ports        []PortView    `json:"ports"`
	IPv6Rules    []IPv6Rule    `json:"ipv6_rules"`
	LANDeny      []LANDenyRule `json:"lan_deny,omitempty"`
	Networks     []Network     `json:"networks"`
	NAT          bool          `json:"nat"`
	ACL          bool          `json:"acl"`
	ACLApplied   bool          `json:"acl_applied"`
	VPPError     string        `json:"vpp_error,omitempty"`
	ApplyError   string        `json:"apply_error,omitempty"`
	Applied      bool          `json:"applied"`
}

func (s *Service) read(all bool) (vppAPI, *vppState, error) {
	v, err := s.dial()
	if err != nil {
		return nil, nil, fmt.Errorf("连不上 VPP：%w", err)
	}
	st, err := v.Read(all, all, wantedAddresses(s.cfg))
	if err != nil {
		v.Close()
		return nil, nil, err
	}
	s.remember(st)
	return v, st, nil
}

// remember keeps the static mappings of a full reading for the page.
func (s *Service) remember(st *vppState) {
	if !st.Statics {
		return
	}
	s.statics = nil
	for _, m := range st.Mappings {
		if !m.Identity {
			s.statics = append(s.statics, m)
		}
	}
	s.staticsAt = s.now()
	s.staticsRun, _ = s.stamp(s.opts.APISocket)
}

// State reads VPP and describes the firewall.
func (s *Service) State() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, _ := s.stamp(s.opts.APISocket)
	if s.staticsAt.IsZero() || s.now().Sub(s.staticsAt) >= staticsEvery || run != s.staticsRun {
		v, st, err := s.read(true)
		if err != nil {
			return s.view(nil, err)
		}
		v.Close()
		return s.view(st, nil)
	}
	v, err := s.dial()
	if err != nil {
		return s.view(nil, fmt.Errorf("连不上 VPP：%w", err))
	}
	defer v.Close()
	st, err := v.Read(true, false, wantedAddresses(s.cfg))
	if err != nil {
		return s.view(nil, err)
	}
	st.Mappings, st.Statics = append(st.Mappings, s.statics...), true
	return s.view(st, nil)
}

func (s *Service) view(st *vppState, readErr error) *State {
	cfg := s.cfg
	out := &State{AllowPing: !cfg.BlockPing, IPv6Firewall: cfg.IPv6Firewall, WANFixed: len(cfg.WANInterfaces) > 0,
		IPv6Rules: append([]IPv6Rule{}, cfg.IPv6Rules...), Forwards: []ForwardView{}, Ports: []PortView{}, WAN: []WAN{}, Networks: []Network{},
		ApplyError: s.applyError, LANDeny: cfg.LANDeny}
	if stamp, err := s.stamp(s.opts.APISocket); err == nil {
		out.Applied = s.applied != (fileStamp{}) && s.applied == stamp && s.applyError == ""
	}
	if readErr != nil {
		out.VPPError = readErr.Error()
		for _, f := range cfg.Forwards {
			out.Forwards = append(out.Forwards, ForwardView{Forward: f})
		}
		for _, p := range cfg.Ports {
			out.Ports = append(out.Ports, PortView{Port: p})
		}
		return out
	}
	out.NAT, out.ACL = st.NAT, st.ACL
	wanList, missing := wan(cfg, st)
	out.WANMissing = missing
	for _, in := range wanList {
		w := WAN{Name: in.Name, Addresses: []string{}}
		for _, a := range in.Addrs {
			if !a.Addr().IsLinkLocalUnicast() {
				w.Addresses = append(w.Addresses, a.String())
			}
		}
		out.WAN = append(out.WAN, w)
	}
	for _, in := range st.Interfaces {
		if isWAN(wanList, in.Index) {
			continue
		}
		for _, a := range in.Addrs {
			if a.Addr().Is4() && a.Bits() < 32 {
				out.Networks = append(out.Networks, Network{Interface: in.Name, Prefix: a.Masked().String()})
			}
		}
	}
	_, problems := desiredMappings(cfg, st)
	for _, f := range cfg.Forwards {
		out.Forwards = append(out.Forwards, ForwardView{Forward: f, Problem: problems[f.ID]})
	}
	for _, p := range cfg.Ports {
		out.Ports = append(out.Ports, PortView{Port: p, Problem: problems[p.ID]})
	}
	// Others' mappings: one row for each run of consecutive ports, from the record on the
	// interface when there is one. coturn's relay range is a thousand mappings.
	ports, forwards := othersRows(st, wanList)
	out.Ports = append(out.Ports, ports...)
	out.Forwards = append(out.Forwards, forwards...)
	for _, entry := range st.ACLs {
		if entry.Tag != aclInTag {
			continue
		}
		for _, in := range wanList {
			out.ACLApplied = out.ACLApplied || slices.Contains(st.Lists[in.Index].Input, entry.Index)
		}
	}
	return out
}

// othersRows are the mappings other programs made, read only: identity mappings on a WAN and
// static mappings anywhere, consecutive ports to consecutive inside ports joined into a range.
func othersRows(st *vppState, wanList []*iface) ([]PortView, []ForwardView) {
	type row struct {
		m     mapping
		where string
		last  uint16
	}
	seen := map[string]bool{}
	var rows []row
	for _, m := range st.Mappings {
		if m.Tag == natTag {
			continue
		}
		in := mappingInterface(st, m)
		where := m.ExternalIP.String()
		if in != nil {
			where = in.Name
		}
		if m.Identity && (in == nil || !isWAN(wanList, in.Index)) {
			continue
		}
		key := fmt.Sprint(m.Identity, m.Proto, m.ExternalPort, where, m.LocalIP, m.LocalPort)
		if seen[key] {
			continue
		}
		seen[key] = true
		rows = append(rows, row{m, where, m.ExternalPort})
	}
	slices.SortStableFunc(rows, func(a, b row) int {
		return cmp.Or(cmp.Compare(a.m.Tag, b.m.Tag), cmp.Compare(a.where, b.where), boolCompare(a.m.Identity, b.m.Identity),
			cmp.Compare(a.m.Proto, b.m.Proto), a.m.LocalIP.Compare(b.m.LocalIP), cmp.Compare(a.m.ExternalPort, b.m.ExternalPort))
	})
	var joined []row
	for _, r := range rows {
		if n := len(joined); n > 0 {
			p := &joined[n-1]
			if p.m.Tag == r.m.Tag && p.where == r.where && p.m.Identity == r.m.Identity && p.m.Proto == r.m.Proto && p.m.LocalIP == r.m.LocalIP &&
				int(p.last)+1 == int(r.m.ExternalPort) && (r.m.Identity || int(r.m.LocalPort)-int(r.m.ExternalPort) == int(p.m.LocalPort)-int(p.m.ExternalPort)) {
				p.last = r.m.ExternalPort
				continue
			}
		}
		joined = append(joined, r)
	}
	var ports []PortView
	var forwards []ForwardView
	for _, r := range joined {
		last := 0
		if r.last != r.m.ExternalPort {
			last = int(r.last)
		}
		if r.m.Identity {
			ports = append(ports, PortView{Port: Port{Name: r.m.Tag, Protocol: protoName(r.m.Proto), Interface: r.where, Port: int(r.m.ExternalPort), LastPort: last}, Other: true})
		} else {
			forwards = append(forwards, ForwardView{Forward: Forward{Name: r.m.Tag, Protocol: protoName(r.m.Proto), Interface: r.where,
				ExternalPort: int(r.m.ExternalPort), LastPort: last, InternalIP: r.m.LocalIP.String(), InternalPort: int(r.m.LocalPort)}, Other: true})
		}
	}
	return ports, forwards
}

func boolCompare(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// change validates edit against VPP, applies the result, and writes the file. When VPP
// refuses part of it, the old configuration is put back.
func (s *Service) change(user, what string, edit func(cfg *Config, st *vppState) error) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, st, err := s.read(true)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	next := s.cfg.clone()
	if err := edit(next, st); err != nil {
		return nil, err
	}
	if err := reconcile(v, next, st); err != nil {
		s.restore(v, st, what, err)
		return nil, err
	}
	if err := next.save(s.opts.ConfigFile); err != nil {
		s.restore(v, st, what, err)
		return nil, fmt.Errorf("写入 %s：%w", s.opts.ConfigFile, err)
	}
	s.cfg = next
	s.applyError = ""
	log.Printf("audit user=%q change=%q", user, what)
	after, err := v.Read(true, true, wantedAddresses(s.cfg))
	if err != nil {
		return s.view(nil, err), nil
	}
	s.remember(after)
	return s.view(after, nil), nil
}

func (s *Service) restore(v vppAPI, before *vppState, what string, cause error) {
	log.Printf("audit change=%q failed: %v; restoring", what, cause)
	st, err := v.Read(true, true, wantedAddresses(s.cfg))
	if err == nil {
		s.remember(st)
		err = reconcile(v, s.cfg, st)
	}
	if err != nil {
		s.applyError = "恢复原来的规则时出错：" + err.Error()
		log.Printf("restore after failed change: %v", err)
	}
}

func (s *Service) nextID(cfg *Config) int {
	id := cfg.NextID
	cfg.NextID++
	return id
}

func wanByName(cfg *Config, st *vppState, name string) (*iface, error) {
	wanList, _ := wan(cfg, st)
	if len(wanList) == 0 {
		return nil, errors.New("没有 WAN 接口：先在接口页把上行口设为出口（NAT）")
	}
	if name == "" {
		return wanList[0], nil
	}
	for _, in := range wanList {
		if in.Name == name {
			return in, nil
		}
	}
	return nil, fmt.Errorf("%s 不是 WAN 接口", name)
}

// usedPorts are the external ports the configuration's mappings use on an interface.
func usedPorts(cfg *Config, st *vppState, in *iface) map[[2]int]string {
	used := map[[2]int]string{}
	for _, f := range cfg.Forwards {
		if f.Interface != in.Name {
			continue
		}
		protos, _ := protocols(f.Protocol, false)
		count, _ := portRange(f.ExternalPort, f.LastPort, rangeLimit)
		for _, proto := range protos {
			for i := 0; i < count; i++ {
				used[[2]int{int(proto), f.ExternalPort + i}] = fmt.Sprintf("已经转发到 %s:%d", f.InternalIP, f.InternalPort+i)
			}
		}
	}
	for _, p := range cfg.Ports {
		if p.Interface != in.Name {
			continue
		}
		protos, _ := protocols(p.Protocol, false)
		count, _ := portRange(p.Port, p.LastPort, rangeLimit)
		for _, proto := range protos {
			for i := 0; i < count; i++ {
				used[[2]int{int(proto), p.Port + i}] = "已经开放给路由器本机"
			}
		}
	}
	return used
}

// natExit requires an interface NAT44-EI translates for: a mapping on any other never takes
// the interface's address ("External address must be allocated").
func natExit(st *vppState, in *iface) error {
	if !slices.Contains(st.NATOutside, in.Index) {
		return fmt.Errorf("%s 不是 NAT 出口，端口转发和本机端口只能开在 NAT 出口上（接口页“设为出口”）", in.Name)
	}
	return nil
}

// checkLocalFree requires each inside address and port to be forwarded once: NAT44-EI keys a
// static mapping by it too, and refuses a second one, or leaves it unresolved for good when
// the interface has no address yet.
func checkLocalFree(cfg *Config, st *vppState, protos []uint8, local netip.Addr, first, count int) error {
	type inside struct {
		proto uint8
		port  int
	}
	// Each inside port already forwarded to, and the message for it.
	taken := map[inside]string{}
	for _, f := range cfg.Forwards {
		if f.InternalIP != local.String() {
			continue
		}
		fprotos, _ := protocols(f.Protocol, false)
		n, _ := portRange(f.ExternalPort, f.LastPort, rangeLimit)
		for _, proto := range fprotos {
			for i := 0; i < n; i++ {
				taken[inside{proto, f.InternalPort + i}] = fmt.Sprintf("%s:%d（%s）已经有转发（外部端口 %d），NAT44-EI 一个内部地址和端口只能转发一次",
					local, f.InternalPort+i, protoName(proto), f.ExternalPort+i)
			}
		}
	}
	for _, m := range st.Mappings {
		key := inside{m.Proto, int(m.LocalPort)}
		if _, seen := taken[key]; seen || m.Identity || m.Tag == natTag || m.LocalIP != local {
			continue
		}
		taken[key] = fmt.Sprintf("%s:%d（%s）已经有其他程序添加的转发（外部端口 %d），NAT44-EI 一个内部地址和端口只能转发一次",
			local, m.LocalPort, protoName(m.Proto), m.ExternalPort)
	}
	for _, proto := range protos {
		for i := 0; i < count; i++ {
			if what, ok := taken[inside{proto, first + i}]; ok {
				return errors.New(what)
			}
		}
	}
	return nil
}

func checkFree(cfg *Config, st *vppState, in *iface, protos []uint8, first, count int) error {
	used, others := usedPorts(cfg, st, in), conflicts(st, in)
	for _, proto := range protos {
		for i := 0; i < count; i++ {
			key := [2]int{int(proto), first + i}
			if what, ok := used[key]; ok {
				return fmt.Errorf("%s 上的 %s %d %s", in.Name, protoName(proto), first+i, what)
			}
			if what, ok := others[key]; ok {
				return fmt.Errorf("%s 上的 %s", in.Name, what)
			}
		}
	}
	return nil
}

func (s *Service) AddForward(f Forward, user string) (*State, error) {
	if err := validateFilters(&Config{Forwards: []Forward{f}}); err != nil {
		return s.State(), err
	}
	return s.change(user, fmt.Sprintf("端口转发 %s %d → %s:%d", f.Protocol, f.ExternalPort, f.InternalIP, f.InternalPort), func(cfg *Config, st *vppState) error {
		if !st.NAT {
			return errors.New("VPP 没有启用 NAT44-EI，不能做端口转发")
		}
		if len(f.Sources) > 0 && !st.ACL {
			return errors.New("来源限制需要启用 ACL 插件")
		}
		var err error
		if f.Name, err = cleanName(f.Name); err != nil {
			return err
		}
		protos, err := protocols(f.Protocol, false)
		if err != nil {
			return err
		}
		in, err := wanByName(cfg, st, f.Interface)
		if err != nil {
			return err
		}
		if err := natExit(st, in); err != nil {
			return err
		}
		f.Interface = in.Name
		count, err := portRange(f.ExternalPort, f.LastPort, rangeLimit)
		if err != nil {
			return fmt.Errorf("外部%w", err)
		}
		if count == 1 {
			f.LastPort = 0
		}
		if f.InternalPort == 0 {
			f.InternalPort = f.ExternalPort
		}
		if f.InternalPort < 1 || f.InternalPort+count-1 > 65535 {
			return errors.New("内部端口在 1 到 65535 之间，端口段整个要放得下")
		}
		local, err := netip.ParseAddr(strings.TrimSpace(f.InternalIP))
		if err != nil || !local.Is4() {
			return errors.New("内部地址写 IPv4 地址，比如 10.61.70.10；IPv6 用 IPv6 防火墙放行")
		}
		f.InternalIP = local.String()
		if err := checkLocal(st, in, local); err != nil {
			return err
		}
		if err := checkFree(cfg, st, in, protos, f.ExternalPort, count); err != nil {
			return err
		}
		if err := checkLocalFree(cfg, st, protos, local, f.InternalPort, count); err != nil {
			return err
		}
		f.ID = s.nextID(cfg)
		cfg.Forwards = append(cfg.Forwards, f)
		return cfg.checkMappingLimit()
	})
}

// checkLocal requires a host on one of VPP's other networks, and not VPP itself.
func checkLocal(st *vppState, wanIf *iface, local netip.Addr) error {
	for _, in := range st.Interfaces {
		for _, a := range in.Addrs {
			if a.Addr() == local {
				return fmt.Errorf("%s 是 VPP 自己（%s）的地址；开放路由器本机的端口用“本机端口”", local, in.Name)
			}
		}
	}
	for _, in := range st.Interfaces {
		if in.Index == wanIf.Index {
			continue
		}
		for _, a := range in.Addrs {
			if a.Addr().Is4() && a.Bits() < 32 && a.Masked().Contains(local) {
				if p := a.Masked(); local == p.Addr() || (p.Bits() < 31 && local == lastAddr(p)) {
					return fmt.Errorf("%s 是网段 %s 的网络或广播地址", local, p)
				}
				return nil
			}
		}
	}
	return fmt.Errorf("%s 不在 VPP 的任何局域网段里", local)
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (s *Service) AddPort(p Port, user string) (*State, error) {
	return s.change(user, fmt.Sprintf("本机端口 %s %d", p.Protocol, p.Port), func(cfg *Config, st *vppState) error {
		if !st.NAT {
			return errors.New("VPP 没有启用 NAT44-EI；没有 NAT 时 WAN 上的端口本来就不被拦")
		}
		var err error
		if p.Name, err = cleanName(p.Name); err != nil {
			return err
		}
		protos, err := protocols(p.Protocol, false)
		if err != nil {
			return err
		}
		in, err := wanByName(cfg, st, p.Interface)
		if err != nil {
			return err
		}
		if err := natExit(st, in); err != nil {
			return err
		}
		p.Interface = in.Name
		count, err := portRange(p.Port, p.LastPort, rangeLimit)
		if err != nil {
			return err
		}
		if count == 1 {
			p.LastPort = 0
		}
		if err := checkFree(cfg, st, in, protos, p.Port, count); err != nil {
			return err
		}
		p.ID = s.nextID(cfg)
		cfg.Ports = append(cfg.Ports, p)
		return cfg.checkMappingLimit()
	})
}

func (s *Service) AddIPv6Rule(r IPv6Rule, user string) (*State, error) {
	return s.change(user, fmt.Sprintf("IPv6 放行 %s %s %d", r.Protocol, r.Address, r.Port), func(cfg *Config, st *vppState) error {
		var err error
		if r.Name, err = cleanName(r.Name); err != nil {
			return err
		}
		if _, err := protocols(r.Protocol, true); err != nil {
			return err
		}
		prefix, err := parseIPv6Target(r.Address)
		if err != nil {
			return err
		}
		r.Address = prefix.String()
		if prefix.Bits() == 128 {
			r.Address = prefix.Addr().String()
		}
		if r.Protocol == "any" {
			r.Port, r.LastPort = 0, 0
		} else {
			count, err := portRange(r.Port, r.LastPort, 0)
			if err != nil {
				return err
			}
			if count == 1 {
				r.LastPort = 0
			}
		}
		if len(cfg.IPv6Rules) >= ruleLimit {
			return fmt.Errorf("最多 %d 条 IPv6 放行规则", ruleLimit)
		}
		r.ID = s.nextID(cfg)
		cfg.IPv6Rules = append(cfg.IPv6Rules, r)
		return nil
	})
}

// Delete removes a forward, router port or IPv6 rule by its ID.
func (s *Service) Delete(id int, user string) (*State, error) {
	return s.change(user, fmt.Sprintf("删除规则 %d", id), func(cfg *Config, st *vppState) error {
		n := len(cfg.Forwards) + len(cfg.Ports) + len(cfg.IPv6Rules)
		cfg.Forwards = slices.DeleteFunc(cfg.Forwards, func(f Forward) bool { return f.ID == id })
		cfg.Ports = slices.DeleteFunc(cfg.Ports, func(p Port) bool { return p.ID == id })
		cfg.IPv6Rules = slices.DeleteFunc(cfg.IPv6Rules, func(r IPv6Rule) bool { return r.ID == id })
		if n == len(cfg.Forwards)+len(cfg.Ports)+len(cfg.IPv6Rules) {
			return errors.New("没有这条规则，可能已经删除")
		}
		return nil
	})
}

func (s *Service) SetPing(allow bool, user string) (*State, error) {
	return s.change(user, fmt.Sprintf("WAN ping allow=%v", allow), func(cfg *Config, st *vppState) error {
		if cfg.BlockPing == !allow {
			return errors.New("ping 设置没有变化")
		}
		if !allow {
			if err := needACL(cfg, st); err != nil {
				return err
			}
		}
		cfg.BlockPing = !allow
		return nil
	})
}

func (s *Service) SetIPv6Firewall(enable bool, user string) (*State, error) {
	return s.change(user, fmt.Sprintf("IPv6 firewall enable=%v", enable), func(cfg *Config, st *vppState) error {
		if cfg.IPv6Firewall == enable {
			return errors.New("IPv6 防火墙设置没有变化")
		}
		if enable {
			if err := needACL(cfg, st); err != nil {
				return err
			}
		}
		cfg.IPv6Firewall = enable
		return nil
	})
}

func needACL(cfg *Config, st *vppState) error {
	if !st.ACL {
		return errors.New("VPP 没有加载 acl 插件")
	}
	if wanList, _ := wan(cfg, st); len(wanList) == 0 {
		return errors.New("没有 WAN 接口：先在接口页把上行口设为出口（NAT）")
	}
	return nil
}

// tick puts the configuration back after VPP restarts, and while an ACL is applied keeps it
// in step with the WAN's addresses.
func (s *Service) tick(now time.Time) {
	stamp, err := s.stamp(s.opts.APISocket)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	restarted := stamp != s.applied
	if restarted {
		if s.opts.VPPUnit != "" {
			if !s.unitActive(s.opts.VPPUnit) {
				return
			}
		} else if now.Sub(time.Unix(0, stamp.Ctime)) < settle {
			return
		}
		if now.Before(s.retryAt) {
			return
		}
	} else if !s.cfg.hasFilters() || now.Sub(s.checkedAt) < checkEvery {
		return
	}
	s.checkedAt = now
	err = s.reconcileNow(!restarted)
	if err != nil {
		s.applyError = err.Error()
		s.retryAt = now.Add(retryEvery)
		log.Printf("apply: %v", err)
		return
	}
	if restarted {
		log.Printf("applied %d forwards, %d router ports, %d IPv6 rules to VPP", len(s.cfg.Forwards), len(s.cfg.Ports), len(s.cfg.IPv6Rules))
	}
	s.applied = stamp
	s.applyError = ""
}

func (s *Service) reconcileNow(light bool) error {
	v, st, err := s.read(!light)
	if err != nil {
		return err
	}
	defer v.Close()
	return reconcile(v, s.cfg, st)
}

func (s *Service) watch() {
	for range time.Tick(watchEvery) {
		s.tick(s.now())
	}
}
