package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Interfaces the panel creates besides VLAN sub-interfaces: a loopback, a TAP whose other end
// is a Linux interface, VXLAN, GRE and IPIP tunnels, and AF_PACKET, which attaches a Linux
// interface to VPP. Each is one creation line in the file, named by its instance so that the
// file and VPP agree on the name, and comes up with nothing on it.

// DeviceRequest says what to create. Which fields count depends on Kind.
type DeviceRequest struct {
	Kind  string `json:"kind"`  // loopback, tap, vxlan, gre, ipip, af_packet
	Local string `json:"local"` // tunnels: this end, an address VPP has
	Peer  string `json:"peer"`  // tunnels: the other end
	VNI   uint32 `json:"vni"`   // vxlan
	L2    bool   `json:"l2"`    // gre: carry Ethernet (teb), for a bridge
	Host  string `json:"host"`  // tap: the Linux name; af_packet: the Linux interface
	// HostAddresses go on the Linux end of a TAP, at most one per family.
	HostAddresses []string `json:"host_addresses"`
}

var deviceKinds = map[string]string{"loopback": "loopback", "tap": "TAP", "vxlan": "VXLAN", "gre": "GRE", "ipip": "IPIP", "af_packet": "AF_PACKET"}

var linuxName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

// freeInstance is the lowest number from start that gives a name neither VPP nor the file has.
func freeInstance(file *cliFile, live *liveState, start int, name func(int) string) int {
	for n := start; ; n++ {
		if live.find(name(n)) == nil && len(file.own(name(n))) == 0 {
			return n
		}
	}
}

// localAddress checks that a tunnel's two ends are of one family and this end is VPP's.
func localAddress(live *liveState, local, peer string) (netip.Addr, netip.Addr, error) {
	src, err1 := netip.ParseAddr(strings.TrimSpace(local))
	dst, err2 := netip.ParseAddr(strings.TrimSpace(peer))
	if err1 != nil || err2 != nil || src.Zone() != "" || dst.Zone() != "" {
		return src, dst, errors.New("本端和对端要写 IP 地址")
	}
	if src.Is4() != dst.Is4() {
		return src, dst, errors.New("本端和对端要是同一个地址族")
	}
	for _, iface := range live.Interfaces {
		if slices.ContainsFunc(iface.Addresses, func(p netip.Prefix) bool { return p.Addr() == src }) {
			return src, dst, nil
		}
	}
	return src, dst, fmt.Errorf("本端地址 %s 不在 VPP 的任何接口上", src)
}

// deviceCommand returns the creation line and the interface it makes.
func (s *Service) deviceCommand(file *cliFile, live *liveState, q DeviceRequest) (command, name string, err error) {
	switch q.Kind {
	case "loopback":
		n := freeInstance(file, live, 0, func(n int) string { return "loop" + strconv.Itoa(n) })
		return fmt.Sprintf("create loopback interface instance %d", n), "loop" + strconv.Itoa(n), nil
	case "tap":
		host := strings.TrimSpace(q.Host)
		if !linuxName.MatchString(host) {
			return "", "", errors.New("Linux 接口名是字母、数字、_ . -，最多 15 个字符")
		}
		if s.linkExists(host) {
			return "", "", fmt.Errorf("Linux 里已经有接口 %s", host)
		}
		// Gate numbers its devices from 2000; staying below keeps the two apart.
		n := freeInstance(file, live, 1, func(n int) string { return "tap" + strconv.Itoa(n) })
		if n >= 2000 {
			return "", "", errors.New("没有可用的 TAP 编号")
		}
		command = fmt.Sprintf("create tap id %d host-if-name %s", n, host)
		families := map[bool]bool{}
		for _, text := range q.HostAddresses {
			if text = strings.TrimSpace(text); text == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix.Addr().Zone() != "" {
				return "", "", fmt.Errorf("Linux 一侧的地址 %q 要写成 地址/长度", text)
			}
			if families[prefix.Addr().Is6()] {
				return "", "", errors.New("Linux 一侧每个地址族只能有一个地址")
			}
			families[prefix.Addr().Is6()] = true
			if prefix.Addr().Is6() {
				command += " host-ip6-addr " + prefix.String()
			} else {
				command += " host-ip4-addr " + prefix.String()
			}
		}
		return command, "tap" + strconv.Itoa(n), nil
	case "vxlan", "gre", "ipip":
		src, dst, err := localAddress(live, q.Local, q.Peer)
		if err != nil {
			return "", "", err
		}
		prefix := map[string]string{"vxlan": "vxlan_tunnel", "gre": "gre", "ipip": "ipip"}[q.Kind]
		n := freeInstance(file, live, 0, func(n int) string { return prefix + strconv.Itoa(n) })
		command = fmt.Sprintf("create %s tunnel src %s dst %s", q.Kind, src, dst)
		switch q.Kind {
		case "vxlan":
			if q.VNI < 1 || q.VNI > 16777215 {
				return "", "", errors.New("VNI 要在 1 到 16777215 之间")
			}
			command += fmt.Sprintf(" vni %d", q.VNI)
		case "gre":
			if q.L2 {
				command += " teb"
			}
		}
		return command + fmt.Sprintf(" instance %d", n), prefix + strconv.Itoa(n), nil
	case "af_packet":
		host := strings.TrimSpace(q.Host)
		if !linuxName.MatchString(host) || host == "lo" {
			return "", "", errors.New("要写一个 Linux 网卡名")
		}
		if !s.linkExists(host) {
			return "", "", fmt.Errorf("Linux 里没有接口 %s", host)
		}
		name = "host-" + host
		if live.find(name) != nil || len(file.own(name)) > 0 {
			return "", "", fmt.Errorf("%s 已经接入 VPP", host)
		}
		return "create host-interface name " + host, name, nil
	}
	return "", "", fmt.Errorf("不支持的接口类型 %q", q.Kind)
}

// deleteCommand removes what a creation line made, for an interface VPP has now.
func deleteCommand(line *cliLine, iface *liveInterface) string {
	if line.kind == lineLoopback {
		return "delete loopback interface intfc " + line.iface
	}
	switch line.device {
	case "tap":
		return "delete tap " + line.iface
	case "vxlan", "gre":
		return strings.TrimSpace(line.text) + " del"
	case "ipip":
		return "delete ipip tunnel sw_if_index " + strconv.FormatUint(uint64(iface.Index), 10)
	case "af_packet":
		name, _ := option(line.words, "name")
		return "delete host-interface name " + name
	}
	return ""
}

// indexPlaceholder stands for an interface's index in an undo command, read when it runs: an
// IPIP tunnel is deleted by index, which it has only once created.
var indexPlaceholder = regexp.MustCompile(`\{index:([^}]+)\}`)

func (s *Service) resolveIndexes(command string) (string, error) {
	if !indexPlaceholder.MatchString(command) {
		return command, nil
	}
	live, err := s.sys.read()
	if err != nil {
		return "", err
	}
	var missing error
	resolved := indexPlaceholder.ReplaceAllStringFunc(command, func(match string) string {
		name := indexPlaceholder.FindStringSubmatch(match)[1]
		if iface := live.find(name); iface != nil {
			return strconv.FormatUint(uint64(iface.Index), 10)
		}
		missing = fmt.Errorf("VPP 里没有接口 %s", name)
		return match
	})
	return resolved, missing
}

// CreateDevice creates an interface, up and with nothing on it.
func (s *Service) CreateDevice(q DeviceRequest, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		command, name, err := s.deviceCommand(file, live, q)
		if err != nil {
			return nil, err
		}
		if live.find(name) != nil {
			return nil, fmt.Errorf("%s 已经存在", name)
		}
		undo := deleteCommand(parseLine(command), &liveInterface{Name: name})
		if q.Kind == "ipip" {
			undo = "delete ipip tunnel sw_if_index {index:" + name + "}"
		}
		c := &change{file: file, description: fmt.Sprintf("新建 %s 接口 %s", deviceKinds[q.Kind], name)}
		if q.Kind == "tap" {
			c.description += "，Linux 一侧是 " + strings.TrimSpace(q.Host)
		}
		c.steps = []step{{command, undo}, {stateCommand(name, true), ""}}
		// At the end: a tunnel's local address, and anything else it needs, comes first.
		file.insert(len(file.lines), command, stateCommand(name, true))
		return c, nil
	})
}

// createdBy returns the line of the file that created iface, other than a sub-interface's.
func createdBy(file *cliFile, iface string) *cliLine {
	for _, i := range file.own(iface, lineCreate, lineLoopback) {
		return file.lines[i]
	}
	return nil
}

// deviceDeleteReason says why an interface the file created cannot be deleted, or empty.
func deviceDeleteReason(file *cliFile, iface *liveInterface) string {
	name := iface.Name
	bd, bvi := fileBridge(file, name)
	switch {
	case createdBy(file, name) == nil:
		return "这个接口不是配置文件创建的"
	case iface.Bridge != 0 || iface.BVI || bd != 0 || bvi:
		return "接口在网桥里，先移出网桥"
	case fileFamily(file, name, false).dynamic() || fileFamily(file, name, true).dynamic() || len(file.own(name, lineGateway)) > 0:
		return "还在用 DHCP、SLAAC 或网关，先把 IPv4 和 IPv6 设为不配置"
	case len(file.own(name, lineNATAddress, lineNATOutput)) > 0:
		return "还是出口（NAT），先取消"
	}
	if refs := file.references(name); len(refs) > 0 {
		return "配置文件里还有引用它的命令：" + strings.TrimSpace(refs[0].text)
	}
	return ""
}

// DeleteDevice deletes an interface the file created, and its lines.
func (s *Service) DeleteDevice(name string, user string) (*State, error) {
	return s.apply(user, func(file *cliFile, live *liveState) (*change, error) {
		iface, err := editable(file, live, name)
		if err != nil {
			return nil, err
		}
		if iface.Sub {
			return nil, errors.New("VLAN 子接口用删除子接口")
		}
		if reason := deviceDeleteReason(file, iface); reason != "" {
			return nil, fmt.Errorf("%s：%s", name, reason)
		}
		line := createdBy(file, name)
		c := &change{file: file, description: "删除接口 " + name}
		// Undo runs in reverse: the interface is recreated from its lines, then gets its addresses back.
		for _, prefix := range iface.Addresses {
			c.steps = append(c.steps, step{addressCommand(name, prefix, true), addressCommand(name, prefix, false)})
		}
		var recreate []string
		for _, i := range file.own(name, lineCreate, lineLoopback, lineState, lineMTU) {
			recreate = append(recreate, strings.TrimSpace(file.lines[i].text))
		}
		c.steps = append(c.steps, step{deleteCommand(line, iface), strings.Join(recreate, "\n")})
		file.remove(file.own(name)...)
		return c, nil
	})
}

func linkExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}
