package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/bits"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The LAN's DHCP is the installer's dnsmasq. Its dnsmasq.conf is changed in place, only on
// the lines the installer manages (here only the IPv4 dhcp-range), and static hosts live in
// the file its dhcp-hostsfile names, which dnsmasq reads again on SIGHUP. None of this needs
// the confirmation interface changes need: it cannot cut the panel off.

// DHCPOptions configures the LAN's DHCP. An empty Conf turns it off.
type DHCPOptions struct {
	Conf    string // dnsmasq.conf
	Unit    string // dnsmasq's unit: restarted for a new range, reloaded for static hosts
	Devices string // which MACs make one device, and the names given
	Clients string // what the dhcp-script records about each client
}

// runner runs a command, returning its output when it fails.
type runner func(name string, args ...string) error

func execRunner(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

// DHCP manages the range, static hosts and devices.
type DHCP struct {
	opts DHCPOptions
	run  runner
	now  func() time.Time
	mu   sync.Mutex
}

func NewDHCP(opts DHCPOptions) *DHCP {
	return &DHCP{opts: opts, run: execRunner, now: time.Now}
}

var (
	macPattern   = regexp.MustCompile(`^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$`)
	leasePattern = regexp.MustCompile(`^(\d+[smhdw]?|infinite)$`)
	namePattern  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

func normalMAC(text string) (string, bool) {
	if !macPattern.MatchString(text) {
		return "", false
	}
	return strings.ToLower(strings.ReplaceAll(text, "-", ":")), true
}

// randomMAC tells a locally administered address, as phones use for Wi-Fi privacy.
func randomMAC(mac string) bool {
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && b&2 != 0
}

// DHCPRange is the dynamic pool.
type DHCPRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
	Lease string `json:"lease"`
}

// dnsmasqConf is what this service reads from dnsmasq.conf.
type dnsmasqConf struct {
	lines     []string
	rangeLine int // the managed dhcp-range line, or -1
	Range     DHCPRange
	Mask      netip.Addr
	Router    netip.Addr
	Server    netip.Addr // listen-address, which the clients are given as DNS server
	Leases    string
	Hosts     string
}

func splitTags(value string) (tags, fields []string) {
	for _, f := range strings.Split(value, ",") {
		f = strings.TrimSpace(f)
		if len(fields) == 0 && (strings.HasPrefix(f, "tag:") || strings.HasPrefix(f, "set:") || strings.HasPrefix(f, "id:")) {
			tags = append(tags, f)
			continue
		}
		fields = append(fields, f)
	}
	return tags, fields
}

func ip4(text string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(text)
	return a, err == nil && a.Is4()
}

// parseRange reads an untagged IPv4 dhcp-range, the kind the installer manages.
func parseRange(value string) (start, end, mask netip.Addr, lease string, ok bool) {
	tags, fields := splitTags(value)
	if len(tags) > 0 || len(fields) < 2 {
		return
	}
	var ok1, ok2 bool
	if start, ok1 = ip4(fields[0]); !ok1 {
		return
	}
	if end, ok2 = ip4(fields[1]); !ok2 {
		return
	}
	for _, f := range fields[2:] {
		if a, isAddr := ip4(f); isAddr && !mask.IsValid() {
			mask = a
		} else if leasePattern.MatchString(f) {
			lease = f
		}
	}
	if lease == "" {
		lease = "1h"
	}
	return start, end, mask, lease, true
}

func readConf(path string) (*dnsmasqConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &dnsmasqConf{lines: strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), rangeLine: -1}
	for i, raw := range c.lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "dhcp-range":
			if start, end, mask, lease, ok := parseRange(value); ok && c.rangeLine < 0 {
				c.rangeLine = i
				c.Range = DHCPRange{Start: start.String(), End: end.String(), Lease: lease}
				c.Mask = mask
			}
		case "dhcp-option", "dhcp-option-force":
			tags, fields := splitTags(value)
			if len(tags) == 0 && len(fields) >= 2 && (fields[0] == "3" || fields[0] == "option:router") {
				c.Router, _ = ip4(fields[1])
			}
		case "listen-address":
			if !c.Server.IsValid() {
				c.Server, _ = ip4(strings.Split(value, ",")[0])
			}
		case "dhcp-leasefile", "dhcp-lease-file":
			c.Leases = value
		case "dhcp-hostsfile":
			c.Hosts = value
		}
	}
	return c, nil
}

// network is the LAN, from the gateway and the range's netmask.
func (c *dnsmasqConf) network() (netip.Prefix, error) {
	if c.rangeLine < 0 {
		return netip.Prefix{}, errors.New("dnsmasq.conf 里没有 IPv4 地址池")
	}
	if !c.Mask.IsValid() || !c.Router.IsValid() {
		return netip.Prefix{}, errors.New("dnsmasq.conf 的地址池没有掩码，或者没有网关选项")
	}
	m := c.Mask.As4()
	n := uint32(m[0])<<24 | uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])
	ones := bits.OnesCount32(n)
	if n != ^uint32(0)<<(32-ones) {
		return netip.Prefix{}, fmt.Errorf("掩码 %s 无效", c.Mask)
	}
	return netip.PrefixFrom(c.Router, ones).Masked(), nil
}

// StaticHost is a static assignment the panel manages: one MAC, one IPv4 address, a name.
type StaticHost struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
}

// parseHost reads "mac,ip[,name]"; other forms (tags, client IDs, several MACs) are left alone.
func parseHost(line string) (StaticHost, bool) {
	fields := strings.Split(strings.TrimSpace(line), ",")
	if len(fields) < 2 || len(fields) > 3 {
		return StaticHost{}, false
	}
	mac, ok := normalMAC(strings.TrimSpace(fields[0]))
	if !ok {
		return StaticHost{}, false
	}
	ip, ok := ip4(strings.TrimSpace(fields[1]))
	if !ok {
		return StaticHost{}, false
	}
	h := StaticHost{MAC: mac, IP: ip.String()}
	if len(fields) == 3 {
		if h.Name = strings.TrimSpace(fields[2]); !namePattern.MatchString(h.Name) {
			return StaticHost{}, false
		}
	}
	return h, true
}

func (h StaticHost) line() string {
	if h.Name != "" {
		return h.MAC + "," + h.IP + "," + h.Name
	}
	return h.MAC + "," + h.IP
}

type hostsFile struct {
	lines []string
	hosts []StaticHost
	at    []int // line of each host
	other []string
}

func readHosts(path string) (*hostsFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &hostsFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	f := &hostsFile{}
	if text := strings.TrimSuffix(string(data), "\n"); text != "" {
		f.lines = strings.Split(text, "\n")
	}
	for i, raw := range f.lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if h, ok := parseHost(line); ok {
			f.hosts = append(f.hosts, h)
			f.at = append(f.at, i)
		} else {
			f.other = append(f.other, line)
		}
	}
	return f, nil
}

// Lease is one line of dnsmasq's lease file.
type Lease struct {
	MAC      string     `json:"mac"`
	IP       string     `json:"ip"`
	Hostname string     `json:"hostname,omitempty"`
	ClientID string     `json:"client_id,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"` // nil: never
}

func (l Lease) active(now time.Time) bool { return l.Expires == nil || l.Expires.After(now) }

func readLeases(path string) ([]Lease, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var leases []Lease
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		mac, ok := normalMAC(f[1])
		if _, isIP := ip4(f[2]); !ok || !isIP {
			continue
		}
		l := Lease{MAC: mac, IP: f[2]}
		if f[3] != "*" {
			l.Hostname = f[3]
		}
		if len(f) > 4 && f[4] != "*" {
			l.ClientID = f[4]
		}
		if seconds, err := strconv.ParseInt(f[0], 10, 64); err == nil && seconds != 0 {
			t := time.Unix(seconds, 0)
			l.Expires = &t
		}
		leases = append(leases, l)
	}
	return leases, nil
}

// DHCPState is what the panel shows.
type DHCPState struct {
	Network    string       `json:"network"`
	Router     string       `json:"router"`
	Server     string       `json:"server"`
	Range      DHCPRange    `json:"range"`
	Hosts      []StaticHost `json:"hosts"`
	OtherHosts []string     `json:"other_hosts"`
	Leases     []Lease      `json:"leases"`
	Devices    []DeviceView `json:"devices"`
}

var errDHCPOff = errors.New("没有启用 LAN 的 DHCP")

// load reads everything; the caller holds mu.
func (d *DHCP) load() (*dnsmasqConf, netip.Prefix, *hostsFile, []Lease, error) {
	if d == nil || d.opts.Conf == "" {
		return nil, netip.Prefix{}, nil, nil, errDHCPOff
	}
	conf, err := readConf(d.opts.Conf)
	if errors.Is(err, os.ErrNotExist) {
		return nil, netip.Prefix{}, nil, nil, errDHCPOff
	}
	if err != nil {
		return nil, netip.Prefix{}, nil, nil, err
	}
	network, err := conf.network()
	if err != nil {
		return nil, netip.Prefix{}, nil, nil, err
	}
	if conf.Hosts == "" || conf.Leases == "" {
		return nil, netip.Prefix{}, nil, nil, errors.New("dnsmasq.conf 里没有 dhcp-hostsfile 或 dhcp-leasefile，重新运行一次安装脚本")
	}
	hosts, err := readHosts(conf.Hosts)
	if err != nil {
		return nil, netip.Prefix{}, nil, nil, err
	}
	leases, err := readLeases(conf.Leases)
	if err != nil {
		return nil, netip.Prefix{}, nil, nil, err
	}
	return conf, network, hosts, leases, nil
}

func (d *DHCP) State() (*DHCPState, error) {
	if d == nil {
		return nil, errDHCPOff
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stateLocked()
}

func (d *DHCP) stateLocked() (*DHCPState, error) {
	conf, network, hosts, leases, err := d.load()
	if err != nil {
		return nil, err
	}
	devices, err := d.devicesLocked(hosts.hosts, leases)
	if err != nil {
		return nil, err
	}
	state := &DHCPState{Network: network.String(), Router: conf.Router.String(), Range: conf.Range,
		Hosts: hosts.hosts, OtherHosts: hosts.other, Leases: leases, Devices: devices}
	if conf.Server.IsValid() {
		state.Server = conf.Server.String()
	}
	if state.Hosts == nil {
		state.Hosts = []StaticHost{}
	}
	if state.OtherHosts == nil {
		state.OtherHosts = []string{}
	}
	if state.Leases == nil {
		state.Leases = []Lease{}
	}
	return state, nil
}

// reserved are the addresses no client may get.
func reserved(conf *dnsmasqConf, network netip.Prefix) []netip.Addr {
	out := []netip.Addr{network.Addr(), broadcast(network), conf.Router}
	if conf.Server.IsValid() {
		out = append(out, conf.Server)
	}
	return out
}

func broadcast(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= ^uint32(0) >> p.Bits()
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

func between(a, start, end netip.Addr) bool { return a.Compare(start) >= 0 && a.Compare(end) <= 0 }

// SetRange changes the dynamic pool and restarts dnsmasq, about a second without DHCP and DNS.
func (d *DHCP) SetRange(r DHCPRange, user string) (*DHCPState, error) {
	if d == nil {
		return nil, errDHCPOff
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	conf, network, _, _, err := d.load()
	if err != nil {
		return nil, err
	}
	start, ok1 := ip4(r.Start)
	end, ok2 := ip4(r.End)
	if !ok1 || !ok2 || !network.Contains(start) || !network.Contains(end) {
		return nil, fmt.Errorf("起始和结束地址要在 %s 内", network)
	}
	if start.Compare(end) > 0 {
		return nil, errors.New("起始地址不能大于结束地址")
	}
	if r.Lease == "" {
		r.Lease = conf.Range.Lease
	}
	if !leasePattern.MatchString(r.Lease) {
		return nil, errors.New("租期写成 12h、30m、7d 或 infinite")
	}
	if seconds, unit := leaseSeconds(r.Lease); unit && seconds < 120 {
		return nil, errors.New("租期至少 2 分钟")
	}
	for _, a := range reserved(conf, network) {
		if between(a, start, end) {
			return nil, fmt.Errorf("地址池不能包含 %s（网关、DNS 或网段本身的地址）", a)
		}
	}
	lines := slices.Clone(conf.lines)
	lines[conf.rangeLine] = fmt.Sprintf("dhcp-range=%s,%s,%s,%s", start, end, conf.Mask, r.Lease)
	before, err := os.ReadFile(d.opts.Conf)
	if err != nil {
		return nil, err
	}
	if err := d.writeTested(lines); err != nil {
		return nil, err
	}
	if err := d.run("systemctl", "restart", d.opts.Unit); err != nil {
		// Put the old range back so dnsmasq keeps serving.
		writeFileAtomic(d.opts.Conf, before, 0o644)
		d.run("systemctl", "restart", d.opts.Unit)
		return nil, fmt.Errorf("dnsmasq 用新的地址池启动失败，已恢复：%w", err)
	}
	log.Printf("audit: DHCP 地址池改为 %s – %s，租期 %s，由 %s 修改", start, end, r.Lease, user)
	return d.stateLocked()
}

// leaseSeconds converts a lease time; the second result is false for "infinite".
func leaseSeconds(lease string) (int64, bool) {
	if lease == "infinite" {
		return 0, false
	}
	unit := map[byte]int64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	last := lease[len(lease)-1]
	mult, ok := unit[last]
	digits := lease
	if ok {
		digits = lease[:len(lease)-1]
	} else {
		mult = 1
	}
	n, _ := strconv.ParseInt(digits, 10, 64)
	return n * mult, true
}

// writeTested writes dnsmasq.conf, and puts the old one back if dnsmasq rejects the new one.
func (d *DHCP) writeTested(lines []string) error {
	before, err := os.ReadFile(d.opts.Conf)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(d.opts.Conf, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	if path, err := exec.LookPath("dnsmasq"); err == nil {
		if err := d.run(path, "--test", "-C", d.opts.Conf); err != nil {
			writeFileAtomic(d.opts.Conf, before, 0o644)
			return fmt.Errorf("dnsmasq 不接受新的配置：%w", err)
		}
	}
	return nil
}

// SetHost adds a static host or changes the one with this MAC; dnsmasq rereads them on SIGHUP.
func (d *DHCP) SetHost(h StaticHost, user string) (*DHCPState, error) {
	if d == nil {
		return nil, errDHCPOff
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	conf, network, hosts, leases, err := d.load()
	if err != nil {
		return nil, err
	}
	mac, ok := normalMAC(strings.TrimSpace(h.MAC))
	if !ok {
		return nil, errors.New("MAC 地址写成 aa:bb:cc:dd:ee:ff")
	}
	if b, _ := strconv.ParseUint(mac[:2], 16, 8); b&1 != 0 {
		return nil, errors.New("这是组播 MAC 地址")
	}
	ip, ok := ip4(strings.TrimSpace(h.IP))
	if !ok || !network.Contains(ip) {
		return nil, fmt.Errorf("地址要在 %s 内", network)
	}
	if slices.Contains(reserved(conf, network), ip) {
		return nil, fmt.Errorf("%s 是网关、DNS 或网段本身的地址", ip)
	}
	h = StaticHost{MAC: mac, IP: ip.String(), Name: strings.TrimSpace(h.Name)}
	if h.Name != "" && !namePattern.MatchString(h.Name) {
		return nil, errors.New("名字只能用字母、数字和连字符，最多 63 个字符，用作 DHCP 主机名")
	}
	for _, other := range hosts.hosts {
		if other.MAC != mac && other.IP == h.IP {
			return nil, fmt.Errorf("%s 已经分配给 %s", h.IP, other.MAC)
		}
	}
	now := d.now()
	for _, l := range leases {
		if l.IP == h.IP && l.MAC != mac && l.active(now) {
			return nil, fmt.Errorf("%s 正在被 %s 使用，等它的租约过期或换个地址", h.IP, l.MAC)
		}
	}
	lines := slices.Clone(hosts.lines)
	replaced := false
	for i, other := range hosts.hosts {
		if other.MAC == mac {
			lines[hosts.at[i]] = h.line()
			replaced = true
		}
	}
	if !replaced {
		lines = append(lines, h.line())
	}
	if err := d.writeHosts(conf.Hosts, lines); err != nil {
		return nil, err
	}
	log.Printf("audit: DHCP 静态分配 %s，由 %s 修改", h.line(), user)
	return d.stateLocked()
}

func (d *DHCP) DeleteHost(mac, user string) (*DHCPState, error) {
	if d == nil {
		return nil, errDHCPOff
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	conf, _, hosts, _, err := d.load()
	if err != nil {
		return nil, err
	}
	mac, _ = normalMAC(strings.TrimSpace(mac))
	var lines []string
	found := false
	for i, line := range hosts.lines {
		if j := slices.Index(hosts.at, i); j >= 0 && hosts.hosts[j].MAC == mac {
			found = true
			continue
		}
		lines = append(lines, line)
	}
	if !found {
		return nil, errors.New("没有这个静态分配")
	}
	if err := d.writeHosts(conf.Hosts, lines); err != nil {
		return nil, err
	}
	log.Printf("audit: DHCP 删除 %s 的静态分配，由 %s 修改", mac, user)
	return d.stateLocked()
}

func (d *DHCP) writeHosts(path string, lines []string) error {
	text := strings.Join(lines, "\n")
	if text != "" {
		text += "\n"
	}
	if err := writeFileAtomic(path, []byte(text), 0o644); err != nil {
		return err
	}
	// A static host takes effect at the client's next request; no restart.
	if err := d.run("systemctl", "reload", d.opts.Unit); err != nil {
		return fmt.Errorf("已保存，但 dnsmasq 没有重新读取：%w", err)
	}
	return nil
}

// marshalIndent is shared by the JSON files kept here.
func marshalIndent(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	return append(data, '\n'), err
}

// gatewayMove tells whether an address change moves the LAN gateway dnsmasq hands out within
// its network: the old gateway goes, and a new address in the same network comes. It checks
// that the new gateway is free in DHCP's eyes. ok is false when DHCP is not concerned.
func (d *DHCP) gatewayMove(old, wanted []netip.Prefix) (from, to netip.Addr, ok bool, err error) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	conf, network, hosts, _, loadErr := d.load()
	if loadErr != nil {
		return // no DHCP to follow
	}
	had := slices.ContainsFunc(old, func(p netip.Prefix) bool { return p.Addr() == conf.Router })
	kept := slices.ContainsFunc(wanted, func(p netip.Prefix) bool { return p.Addr() == conf.Router })
	if !had || kept {
		return
	}
	for _, p := range wanted {
		if p.Addr().Is4() && p.Masked() == network {
			to = p.Addr()
			break
		}
	}
	if !to.IsValid() {
		return // another network: renumbering is not followed
	}
	start, _ := ip4(conf.Range.Start)
	end, _ := ip4(conf.Range.End)
	if between(to, start, end) {
		return from, to, false, fmt.Errorf("新网关 %s 在 DHCP 地址池 %s – %s 里，先在局域网页调整地址池", to, conf.Range.Start, conf.Range.End)
	}
	if conf.Server.IsValid() && to == conf.Server {
		return from, to, false, fmt.Errorf("%s 是 Linux 管理口（DNS）的地址", to)
	}
	for _, h := range hosts.hosts {
		if h.IP == to.String() {
			return from, to, false, fmt.Errorf("%s 已经静态分配给 %s，先在局域网页删除", to, h.MAC)
		}
	}
	return conf.Router, to, true, nil
}

// SetRouter changes the gateway dnsmasq hands out, then restarts it: clients get it when they
// renew their lease.
func (d *DHCP) SetRouter(from, to netip.Addr) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	conf, err := readConf(d.opts.Conf)
	if err != nil {
		return err
	}
	lines := slices.Clone(conf.lines)
	changed := false
	for i, raw := range lines {
		key, value, _ := strings.Cut(strings.TrimSpace(raw), "=")
		key = strings.TrimSpace(key)
		if key != "dhcp-option" && key != "dhcp-option-force" {
			continue
		}
		tags, fields := splitTags(value)
		if len(tags) == 0 && len(fields) >= 2 && (fields[0] == "3" || fields[0] == "option:router") && fields[1] == from.String() {
			lines[i] = key + "=option:router," + to.String()
			changed = true
		}
	}
	if !changed {
		return fmt.Errorf("dnsmasq.conf 里没有网关 %s", from)
	}
	before, err := os.ReadFile(d.opts.Conf)
	if err != nil {
		return err
	}
	if err := d.writeTested(lines); err != nil {
		return err
	}
	if err := d.run("systemctl", "restart", d.opts.Unit); err != nil {
		writeFileAtomic(d.opts.Conf, before, 0o644)
		d.run("systemctl", "restart", d.opts.Unit)
		return fmt.Errorf("dnsmasq 用新网关重启失败：%w", err)
	}
	log.Printf("audit: DHCP 网关 %s 改为 %s", from, to)
	return nil
}

// meterSources is what the LAN meter counts: the gateway dnsmasq hands out, which finds the
// LAN interface, and the IPv4 address of every active lease and static host.
func (d *DHCP) meterSources() (netip.Addr, []neighbor, error) {
	if d == nil {
		return netip.Addr{}, nil, errDHCPOff
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	conf, _, hosts, leases, err := d.load()
	if err != nil {
		return netip.Addr{}, nil, err
	}
	var out []neighbor
	now := d.now()
	for _, l := range leases {
		if ip, ok := ip4(l.IP); ok && l.active(now) {
			out = append(out, neighbor{IP: ip, MAC: l.MAC})
		}
	}
	for _, h := range hosts.hosts {
		if ip, ok := ip4(h.IP); ok {
			out = append(out, neighbor{IP: ip, MAC: h.MAC})
		}
	}
	return conf.Router, out, nil
}
