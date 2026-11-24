package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// WireGuard configurations made in the panel are stored here, not in VPP, which keeps nothing
// across a restart. The store is the only source: what VPP runs is generated from it, and put
// back after VPP restarts. It holds private keys, so it is private to root and its types are
// never what a reply is encoded from. No command or line of a configuration may reach an
// error or a log, as they contain those keys.
const (
	wgStoreFile     = "wireguard.json"
	wgFirstInstance = 100 // clear of the small numbers startup files use
	wgFirstPort     = 51820
	wgConfigLimit   = 32
	wgDefaultMTU    = 1420
	wgResolveLimit  = 5 * time.Second
	wgWatchEvery    = 2 * time.Second
	wgRetryEvery    = 5 * time.Second // what a restore waits for appears within seconds
	wgCommandLimit  = 64
	wgCommandLength = 512
	// wgSettle is how long VPP's socket must have existed before configurations go back when
	// no unit is named to say that VPP's own configuration has finished.
	wgSettle = 30 * time.Second
)

type wgStoredPeer struct {
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	Endpoint     string   `json:"endpoint,omitempty"` // an address; empty until the peer is heard from
	Port         int      `json:"port,omitempty"`
	Keepalive    int      `json:"keepalive,omitempty"`
}

type wgStored struct {
	Name       string         `json:"name"`
	Instance   int            `json:"instance"`
	Enabled    bool           `json:"enabled"`
	PrivateKey string         `json:"private_key"`
	Source     string         `json:"source"`
	ListenPort int            `json:"listen_port"`
	MTU        int            `json:"mtu"`
	Addresses  []string       `json:"addresses"`
	Peers      []wgStoredPeer `json:"peers"`
	// AfterUp are VPP commands that belong to this interface, run once it is up, and
	// BeforeDown undoes them. They are what lets VPP's startup know nothing about tunnels.
	AfterUp    []string `json:"after_up,omitempty"`
	BeforeDown []string `json:"before_down,omitempty"`
	// ExitVia are next hops inside the tunnel, one per address family, that make a started
	// configuration selectable as an exit for Gate's rules.
	ExitVia []string `json:"exit_via,omitempty"`
	// NoRoutes is wg-quick's Table = off: AllowedIPs only say what the tunnel accepts, and
	// traffic gets into it by the configuration's commands or by rules.
	NoRoutes bool `json:"no_routes,omitempty"`
	// SkipNATOpen is for a port opened by other means, as imported tunnels' ports are.
	SkipNATOpen bool          `json:"skip_nat_open,omitempty"`
	DNS         *WireGuardDNS `json:"dns,omitempty"`
}

type wgStore struct {
	Configs []*wgStored `json:"configs"`
}

// WireGuardConfig is a stored configuration as the panel sees it, without its secrets.
type WireGuardConfig struct {
	DNS        *WireGuardDNS `json:"dns,omitempty"`
	Name       string        `json:"name"`
	Interface  string        `json:"interface"`
	Enabled    bool          `json:"enabled"`
	Running    bool          `json:"running"`
	Addresses  []string      `json:"addresses"`
	ListenPort int           `json:"listen_port"`
	PublicKey  string        `json:"public_key"`
	Source     string        `json:"source"`
	Peers      int           `json:"peers"`
	Commands   int           `json:"commands"`
	Error      string        `json:"error"`
}

func (c *wgStored) iface() string { return "wg" + strconv.Itoa(c.Instance) }

func (a *Service) wgStorePath() string { return filepath.Join(a.opts.ConfigDir, wgStoreFile) }

func (a *Service) loadWGStore() (*wgStore, error) {
	store := &wgStore{}
	data, err := os.ReadFile(a.wgStorePath())
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, fmt.Errorf("%s 无法解析", wgStoreFile) // the decoder's message can quote the file
	}
	return store, nil
}

func (a *Service) saveWGStore(store *wgStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(a.wgStorePath(), append(data, '\n'), 0o600); err != nil {
		return err
	}
	a.publishExits(store)
	return nil
}

// wgExit is one line of the file gate-admin reads to offer exits. Nothing else connects the two.
type wgExit struct {
	Interface string `json:"interface"`
	Via       string `json:"via"`
}

// publishExits lists the started configurations with a next hop. Failing costs only the
// choice of these exits, so it is logged.
func (a *Service) publishExits(store *wgStore) {
	if a.opts.ExitsFile == "" {
		return
	}
	exits := []wgExit{}
	for _, c := range store.Configs {
		if c.Enabled {
			for _, via := range c.ExitVia {
				exits = append(exits, wgExit{c.iface(), via})
			}
		}
	}
	data, err := json.Marshal(exits)
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(a.opts.ExitsFile), 0o700); err == nil {
			err = writeFileAtomic(a.opts.ExitsFile, append(data, '\n'), 0o600)
		}
	}
	if err != nil {
		log.Printf("wireguard: publishing the exits: %v", err)
	}
}

// checkExitVia reads the next hops: at most one per address family, and each must belong to
// a peer, as VPP picks the peer for a packet by what its AllowedIPs contain.
func checkExitVia(text string, c *wgStored) ([]string, error) {
	var via []string
	families := map[bool]bool{}
	for _, item := range wgList(strings.NewReplacer(" ", ",", "，", ",").Replace(text)) {
		address, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("出口下一跳 %q 不是地址", item)
		}
		address = address.Unmap().WithZone("")
		if families[address.Is4()] {
			return nil, errors.New("出口下一跳每个地址族只能有一个")
		}
		families[address.Is4()] = true
		sameFamily := slices.ContainsFunc(c.subnets(), func(own netip.Prefix) bool {
			return own.Addr().Is4() == address.Is4() && own.Addr() != address
		})
		if !sameFamily {
			return nil, fmt.Errorf("出口下一跳 %s 不能用：接口没有这个地址族的地址，或它就是接口自己的地址", address)
		}
		held := slices.ContainsFunc(c.Peers, func(peer wgStoredPeer) bool {
			return slices.ContainsFunc(wgPrefixes(peer.AllowedIPs), func(prefix netip.Prefix) bool { return prefix.Contains(address) })
		})
		if !held {
			return nil, fmt.Errorf("出口下一跳 %s 不在任何节点的 AllowedIPs 内", address)
		}
		via = append(via, address.String())
	}
	return via, nil
}

func wgPublicKey(private string) string {
	decoded, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return ""
	}
	key, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

// Fields wg-quick acts on outside the tunnel. A router has no use for them, and running a
// pasted PostUp would be running anything at all.
var wgIgnoredFields = map[string]bool{
	"dns": true, "fwmark": true, "saveconfig": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
}

// Fields wg-quick lets a section repeat, adding to the earlier lines.
var wgRepeatedFields = map[string]bool{
	"address": true, "allowedips": true, "dns": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
}

// wgPrefix reads an Address or AllowedIPs item. Like wg and wg-quick, a bare address is a
// single host.
func wgPrefix(item string) (netip.Prefix, error) {
	if !strings.Contains(item, "/") {
		address, err := netip.ParseAddr(item)
		if err != nil || address.Zone() != "" {
			return netip.Prefix{}, errors.New("not an address")
		}
		return netip.PrefixFrom(address, address.BitLen()), nil
	}
	return netip.ParsePrefix(item)
}

func wgList(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

type wgParsedPeer struct {
	wgStoredPeer
	host string
}

// parseWireGuardConf reads the wg-quick format, as wg-quick and the WireGuard apps export
// it. Errors name lines, never their content.
func parseWireGuardConf(text string) (*wgStored, []*wgParsedPeer, error) {
	text = strings.TrimPrefix(text, "\ufeff")
	config := &wgStored{MTU: wgDefaultMTU}
	var peers []*wgParsedPeer
	var peer *wgParsedPeer
	section, seen := "", map[string]bool{}
	for index, raw := range strings.Split(text, "\n") {
		line := raw
		if at := strings.IndexByte(line, '#'); at >= 0 {
			line = line[:at]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		bad := func(what string) (*wgStored, []*wgParsedPeer, error) {
			return nil, nil, fmt.Errorf("第 %d 行%s", index+1, what)
		}
		switch strings.ToLower(line) {
		case "[interface]":
			if section != "" {
				return bad("：[Interface] 只能有一个，且要在最前面")
			}
			section, seen = "interface", map[string]bool{}
			continue
		case "[peer]":
			if section == "" {
				return bad("：[Peer] 前要有 [Interface]")
			}
			section, seen = "peer", map[string]bool{}
			peer = &wgParsedPeer{}
			peers = append(peers, peer)
			continue
		}
		name, value, found := strings.Cut(line, "=")
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if !found || section == "" {
			return bad("无法识别")
		}
		if seen[name] && !wgRepeatedFields[name] {
			return bad("的字段重复了")
		}
		seen[name] = true
		number := func(low, high int) (int, bool) {
			parsed, err := strconv.Atoi(value)
			return parsed, err == nil && parsed >= low && parsed <= high
		}
		var ok bool
		switch {
		case section == "interface" && wgIgnoredFields[name]:
		case section == "interface" && name == "table":
			// Other values choose a Linux routing table, which has no meaning here.
			config.NoRoutes = strings.EqualFold(value, "off")
		case section == "interface" && name == "privatekey":
			config.PrivateKey = value
			if !validWireGuardKey(value) {
				return bad("的 PrivateKey 格式不对")
			}
		case section == "interface" && name == "address":
			for _, item := range wgList(value) {
				address, err := wgPrefix(item)
				if err != nil {
					return bad("的 Address 不对，要写成 10.0.0.1/24 这样")
				}
				config.Addresses = append(config.Addresses, address.String())
			}
		case section == "interface" && name == "listenport":
			if config.ListenPort, ok = number(1, 65535); !ok {
				return bad("的 ListenPort 不对")
			}
		case section == "interface" && name == "mtu":
			if config.MTU, ok = number(1280, 9000); !ok {
				return bad("的 MTU 不对，范围是 1280 到 9000")
			}
		case section == "peer" && name == "publickey":
			peer.PublicKey = value
			if !validWireGuardKey(value) {
				return bad("的 PublicKey 格式不对")
			}
		case section == "peer" && name == "presharedkey":
			peer.PresharedKey = value
			if !validWireGuardKey(value) {
				return bad("的 PresharedKey 格式不对")
			}
		case section == "peer" && name == "allowedips":
			for _, item := range wgList(value) {
				prefix, err := wgPrefix(item)
				if err != nil {
					return bad("的 AllowedIPs 不对")
				}
				peer.AllowedIPs = append(peer.AllowedIPs, prefix.Masked().String())
			}
		case section == "peer" && name == "endpoint":
			host, port, err := net.SplitHostPort(value)
			if err != nil {
				return bad("的 Endpoint 要写成 地址:端口")
			}
			peer.host = host
			if peer.Port, err = strconv.Atoi(port); err != nil || peer.Port < 1 || peer.Port > 65535 {
				return bad("的 Endpoint 端口不对")
			}
		case section == "peer" && name == "persistentkeepalive":
			if !strings.EqualFold(value, "off") {
				if peer.Keepalive, ok = number(0, 65535); !ok {
					return bad("的 PersistentKeepalive 不对")
				}
			}
		default:
			return bad("的字段不支持")
		}
	}
	if config.PrivateKey == "" {
		return nil, nil, errors.New("缺少 PrivateKey")
	}
	if len(config.Addresses) == 0 {
		return nil, nil, errors.New("缺少 Address")
	}
	if len(peers) == 0 {
		return nil, nil, errors.New("至少要有一个 [Peer]")
	}
	keys := map[string]bool{}
	for index, item := range peers {
		if item.PublicKey == "" {
			return nil, nil, fmt.Errorf("第 %d 个 [Peer] 缺少 PublicKey", index+1)
		}
		if len(item.AllowedIPs) == 0 {
			return nil, nil, fmt.Errorf("第 %d 个 [Peer] 缺少 AllowedIPs", index+1)
		}
		if keys[item.PublicKey] {
			return nil, nil, fmt.Errorf("第 %d 个 [Peer] 的公钥重复了", index+1)
		}
		keys[item.PublicKey] = true
	}
	return config, peers, nil
}

var wgHostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// resolveWireGuardEndpoint gives the address a peer is reached at, in the family the tunnel
// sends from. A name is resolved once, as VPP takes only addresses.
func (a *Service) resolveWireGuardEndpoint(host string, source netip.Addr) (netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap().WithZone("")
		if address.Is4() != source.Is4() {
			return netip.Addr{}, fmt.Errorf("端点 %s 和源地址不是同一个地址族", host)
		}
		return address, nil
	}
	if !wgHostName.MatchString(host) {
		return netip.Addr{}, fmt.Errorf("端点 %q 不是地址也不是域名", host)
	}
	network := "ip6"
	if source.Is4() {
		network = "ip4"
	}
	ctx, cancel := context.WithTimeout(context.Background(), wgResolveLimit)
	defer cancel()
	addresses, err := a.lookup(ctx, network, host)
	if err != nil || len(addresses) == 0 {
		return netip.Addr{}, fmt.Errorf("解析端点 %s 失败", host)
	}
	return addresses[0].Unmap().WithZone(""), nil
}

func (c *wgStored) subnets() []netip.Prefix {
	var subnets []netip.Prefix
	for _, text := range c.Addresses {
		if address, err := netip.ParsePrefix(text); err == nil {
			subnets = append(subnets, address)
		}
	}
	return subnets
}

// routable keeps the prefixes inside the tunnel's own subnets. Anything wider, above all a
// default route from a pasted client configuration, could take over the router's own routes,
// so WireGuard accepts it but the main table does not get it.
func (c *wgStored) routable(prefixes []netip.Prefix) []netip.Prefix {
	if c.NoRoutes {
		return nil
	}
	var kept []netip.Prefix
	for _, prefix := range prefixes {
		for _, subnet := range c.subnets() {
			if subnet.Bits() <= prefix.Bits() && subnet.Masked().Contains(prefix.Addr()) && !slices.Contains(kept, prefix) {
				kept = append(kept, prefix)
				break
			}
		}
	}
	return kept
}

func wgPrefixes(texts []string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, text := range texts {
		if prefix, err := netip.ParsePrefix(text); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
}

func (c *wgStored) peerLine(peer wgStoredPeer) string {
	endpoint, port := peer.Endpoint, peer.Port
	if endpoint == "" {
		endpoint, port = "0.0.0.0", 0
		if address, err := netip.ParseAddr(c.Source); err == nil && !address.Is4() {
			endpoint = "::"
		}
	}
	line := "wireguard peer add " + c.iface() + " public-key " + peer.PublicKey
	if peer.PresharedKey != "" {
		line += " preshared-key " + peer.PresharedKey
	}
	line += fmt.Sprintf(" endpoint %s dst-port %d", endpoint, port)
	for _, allowed := range peer.AllowedIPs {
		line += " allowed-ip " + allowed
	}
	return line + fmt.Sprintf(" persistent-keepalive %d", peer.Keepalive)
}

func (a *Service) wgNATLine(c *wgStored, suffix string) string {
	address, err := netip.ParseAddr(c.Source)
	if a.opts.NATInterface == "" || c.SkipNATOpen || err != nil || !address.Is4() {
		return ""
	}
	return fmt.Sprintf("nat44 %sadd identity mapping external %s udp %d%s", a.natWord(), a.opts.NATInterface, c.ListenPort, suffix)
}

// natWord is "ei " when VPP runs NAT44-EI and nothing for NAT44-ED, whose commands lack the
// word. Only NAT44-ED has "show nat44 summary".
func (a *Service) natWord() string {
	if output, err := a.sys.vppCLI("show nat44 summary"); err == nil && strings.Contains(output, "translations") {
		return ""
	}
	return "ei "
}

type wgStep struct{ command, what string }

func (a *Service) wgUpSteps(c *wgStored) []wgStep {
	name := c.iface()
	steps := []wgStep{
		{fmt.Sprintf("wireguard create instance %d listen-port %d private-key %s src %s", c.Instance, c.ListenPort, c.PrivateKey, c.Source), "创建接口"},
		{fmt.Sprintf("set interface mtu packet %d %s", c.MTU, name), "设置 MTU"},
	}
	for _, address := range c.Addresses {
		steps = append(steps, wgStep{"set interface ip address " + name + " " + address, "设置地址 " + address})
	}
	for _, peer := range c.Peers {
		steps = append(steps, wgStep{c.peerLine(peer), "添加节点 " + peer.PublicKey})
		for _, prefix := range c.routable(wgPrefixes(peer.AllowedIPs)) {
			steps = append(steps, wgStep{wireGuardRoute("add", prefix, name), "添加路由 " + prefix.String()})
		}
	}
	if line := a.wgNATLine(c, ""); line != "" {
		steps = append(steps, wgStep{line, "放行监听端口"})
	}
	steps = append(steps, wgStep{"set interface state " + name + " up", "启用接口"})
	for _, step := range a.natCommands(c, c.AfterUp) {
		steps = append(steps, wgStep{step.command, fmt.Sprintf("附加命令第 %d 条", step.index+1)})
	}
	return steps
}

// cleanCommands reads a block of VPP commands, one per line. They are VPP CLI only: exec and
// unix would reach files and the host.
func cleanCommands(text string) ([]string, error) {
	var commands []string
	for index, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > wgCommandLength || strings.ContainsFunc(line, unicode.IsControl) {
			return nil, fmt.Errorf("附加命令第 %d 行太长或含控制字符", index+1)
		}
		if first := strings.Fields(line)[0]; first == "exec" || first == "unix" {
			return nil, fmt.Errorf("附加命令第 %d 行：不能用 %s", index+1, first)
		}
		commands = append(commands, line)
	}
	if len(commands) > wgCommandLimit {
		return nil, fmt.Errorf("附加命令最多 %d 条", wgCommandLimit)
	}
	return commands, nil
}

// wgDown removes a configuration from VPP. Routes go before the interface they point at, and
// DNS cleanup failures are reported too, so they can be retried before disabling the config.
func (a *Service) wgDown(c *wgStored) error {
	name := c.iface()
	dnsErr := a.stopWGDNS(c)
	for _, step := range a.natCommands(c, c.BeforeDown) {
		if _, err := a.sys.vppCLI(step.command); err != nil {
			log.Printf("wireguard: a before-down command of %s: %v", name, err)
		}
	}
	// VPP's interface deletion walks and mutates the same peer hash, which can
	// skip peers. Remove a snapshot explicitly while their interface still exists.
	if err := a.removeInterfacePeers(name); err != nil {
		return fmt.Errorf("删除接口节点失败：%w", err)
	}
	if line := a.wgNATLine(c, " del"); line != "" {
		if _, err := a.sys.vppCLI(line); err != nil {
			log.Printf("wireguard: closing the port of %s: %v", name, err)
		}
	}
	for _, peer := range c.Peers {
		for _, prefix := range c.routable(wgPrefixes(peer.AllowedIPs)) {
			if _, err := a.sys.vppCLI(wireGuardRoute("del", prefix, name)); err != nil {
				log.Printf("wireguard: removing the route to %s: %v", prefix, err)
			}
		}
	}
	_, err := a.sys.vppCLI("wireguard delete " + name)
	return errors.Join(dnsErr, err)
}

// UpdateWireGuardSource changes a stopped configuration without exposing its keys.
func (a *Service) UpdateWireGuardSource(iface, source, user string) (*WireGuardState, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(source))
	if err != nil || address.IsUnspecified() {
		return nil, errors.New("源地址不对，要填 VPP 发出隧道包用的地址")
	}
	address = address.Unmap().WithZone("")
	a.mu.Lock()
	err = a.updateWireGuardSourceLocked(iface, address, user)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

// UpdateWireGuardSettings changes the two stopped-configuration settings shown in one editor.
// It validates both before writing the store, so a bad Gate configuration cannot leave only
// half of the edit applied.
func (a *Service) UpdateWireGuardSettings(iface, source string, dns *WireGuardDNS, user string) (*WireGuardState, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(source))
	if err != nil || address.IsUnspecified() {
		return nil, errors.New("源地址不对，要填 VPP 发出隧道包用的地址")
	}
	address = address.Unmap().WithZone("")
	a.mu.Lock()
	store, err := a.loadWGStore()
	if err == nil {
		c := wgFindConfig(store, iface)
		if c == nil {
			err = fmt.Errorf("没有配置 %q", iface)
		} else if c.Enabled {
			err = errors.New("请先停止配置，再编辑")
		} else if err = checkWireGuardSource(address, c); err == nil {
			if dns != nil {
				if _, err = a.loadGateDNS(); err == nil {
					dns = &WireGuardDNS{}
				}
			}
		}
		if err == nil {
			c.Source = address.String()
			c.DNS = dns
			err = a.saveWGStore(store)
			if err == nil {
				log.Printf("audit: wireguard: edited %s, by %s", iface, user)
			}
		}
	}
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

func checkWireGuardSource(address netip.Addr, c *wgStored) error {
	for _, peer := range c.Peers {
		if peer.Endpoint == "" {
			continue
		}
		endpoint, err := netip.ParseAddr(peer.Endpoint)
		if err != nil || endpoint.Unmap().Is4() != address.Is4() {
			return errors.New("源地址和节点端点必须是同一个地址族")
		}
	}
	return nil
}

func (a *Service) updateWireGuardSourceLocked(iface string, address netip.Addr, user string) error {
	store, err := a.loadWGStore()
	if err != nil {
		return err
	}
	c := wgFindConfig(store, iface)
	if c == nil {
		return fmt.Errorf("没有配置 %q", iface)
	}
	if c.Enabled {
		return errors.New("请先停止配置，再修改源地址")
	}
	if err := checkWireGuardSource(address, c); err != nil {
		return err
	}
	c.Source = address.String()
	if err := a.saveWGStore(store); err != nil {
		return fmt.Errorf("保存配置失败：%w", err)
	}
	log.Printf("audit: wireguard: updated source of %s, by %s", iface, user)
	return nil
}

// wgUp creates a configuration in VPP, entirely or not at all.
func (a *Service) wgUp(c *wgStored) error {
	for _, step := range a.wgUpSteps(c) {
		if _, err := a.sys.vppCLI(step.command); err != nil {
			if undoErr := a.wgDown(c); undoErr != nil {
				log.Printf("wireguard: undoing %s: %v", c.iface(), undoErr)
			}
			return fmt.Errorf("VPP 拒绝了：%s（%w）", step.what, err)
		}
	}
	if err := a.startWGDNS(c); err != nil {
		if undoErr := a.wgDown(c); undoErr != nil {
			log.Printf("wireguard: undoing %s: %v", c.iface(), undoErr)
		}
		return fmt.Errorf("启用 DNS 转发失败：%w", err)
	}
	return nil
}

var wgInterfaceLine = regexp.MustCompile(`(?m)^(\S+)\s+\d+\s+(?:up|down)\b`)

// vppInterfaces lists what VPP has. `show wireguard interface` would do but prints private keys.
func (a *Service) vppInterfaces() (map[string]bool, error) {
	output, err := a.sys.vppCLI("show interface")
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, match := range wgInterfaceLine.FindAllStringSubmatch(output, -1) {
		names[match[1]] = true
	}
	return names, nil
}

func (a *Service) wgLive(c *wgStored) (bool, error) {
	if !c.Enabled {
		return false, nil
	}
	names, err := a.vppInterfaces()
	if err != nil {
		return false, err
	}
	return names[c.iface()], nil
}

func wgFindConfig(store *wgStore, iface string) *wgStored {
	for _, c := range store.Configs {
		if c.iface() == iface {
			return c
		}
	}
	return nil
}

// AddWireGuardConfig stores a configuration without starting it.
// With dns, the configuration forwards DNS on its own addresses to Gate once started; Gate
// must be usable already, as when DNS is enabled in the editor.
func (a *Service) AddWireGuardConfig(name, source, text, afterUp, beforeDown, exitVia string, dns bool, user string) (*WireGuardState, error) {
	name, err := cleanWireGuardName(name)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("配置要有名字")
	}
	sourceAddress, err := netip.ParseAddr(strings.TrimSpace(source))
	if err != nil || sourceAddress.IsUnspecified() {
		return nil, errors.New("源地址不对，要填路由器发出隧道包用的地址")
	}
	sourceAddress = sourceAddress.Unmap().WithZone("")
	stored, peers, err := parseWireGuardConf(text)
	if err != nil {
		return nil, err
	}
	stored.Name, stored.Source = name, sourceAddress.String()
	if stored.AfterUp, err = cleanCommands(afterUp); err != nil {
		return nil, err
	}
	if stored.BeforeDown, err = cleanCommands(beforeDown); err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if peer.host != "" {
			address, err := a.resolveWireGuardEndpoint(peer.host, sourceAddress)
			if err != nil {
				return nil, err
			}
			peer.Endpoint = address.String()
		}
		stored.Peers = append(stored.Peers, peer.wgStoredPeer)
	}
	if stored.ExitVia, err = checkExitVia(exitVia, stored); err != nil {
		return nil, err
	}
	if dns {
		if _, err := a.loadGateDNS(); err != nil {
			return nil, err
		}
		stored.DNS = &WireGuardDNS{}
	}
	a.mu.Lock()
	err = a.addWireGuardConfigLocked(stored, user)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

func (a *Service) addWireGuardConfigLocked(stored *wgStored, user string) error {
	config, err := a.readWireGuard()
	if err != nil {
		return err
	}
	if len(config.store.Configs) >= wgConfigLimit {
		return fmt.Errorf("最多保存 %d 份配置", wgConfigLimit)
	}
	instances, ports := map[string]bool{}, map[int]bool{}
	for _, iface := range config.interfaces {
		instances[iface.name], ports[iface.port] = true, true
	}
	for _, other := range config.store.Configs {
		if other.Name == stored.Name {
			return errors.New("这个名字的配置已经存在")
		}
	}
	if stored.ListenPort != 0 && ports[stored.ListenPort] {
		return fmt.Errorf("监听端口 %d 已被其他配置使用", stored.ListenPort)
	}
	for port := wgFirstPort; stored.ListenPort == 0 && port <= 65535; port++ {
		if !ports[port] {
			stored.ListenPort = port
		}
	}
	for stored.Instance = wgFirstInstance; instances[stored.iface()]; stored.Instance++ {
	}
	config.store.Configs = append(config.store.Configs, stored)
	if err := a.saveWGStore(config.store); err != nil {
		return fmt.Errorf("保存配置失败：%w", err)
	}
	log.Printf("audit: wireguard: stored configuration %q as %s, by %s", stored.Name, stored.iface(), user)
	return nil
}

// wgKeyInUse says whether a key is still a peer anywhere: a name belongs to the key.
func wgKeyInUse(store *wgStore, key string) bool {
	return slices.ContainsFunc(store.Configs, func(c *wgStored) bool {
		return slices.ContainsFunc(c.Peers, func(peer wgStoredPeer) bool { return peer.PublicKey == key })
	})
}

// wgConflict says why a configuration cannot run next to what is running. A key shared with
// another interface is no conflict: whether VPP can tell them apart is VPP's to say.
func wgConflict(config *wgConfig, c *wgStored) error {
	for _, other := range config.interfaces {
		if other.stored == c || !other.stored.Enabled {
			continue
		}
		if other.port == c.ListenPort {
			return fmt.Errorf("监听端口 %d 已被 %s 使用", c.ListenPort, other.name)
		}
		for _, own := range c.subnets() {
			for _, address := range other.addresses {
				if own.Overlaps(address) {
					return fmt.Errorf("地址 %s 和 %s 的 %s 重叠", own, other.name, address)
				}
			}
		}
	}
	return nil
}

// StartWireGuardConfig creates the configuration in VPP and restores it after restarts.
func (a *Service) StartWireGuardConfig(iface, user string) (*WireGuardState, error) {
	a.mu.Lock()
	err := a.startWireGuardConfigLocked(iface, user)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

func (a *Service) startWireGuardConfigLocked(iface, user string) error {
	config, err := a.readWireGuard()
	if err != nil {
		return err
	}
	c := wgFindConfig(config.store, iface)
	if c == nil {
		return fmt.Errorf("没有配置 %q", iface)
	}
	if c.Enabled {
		return errors.New("这份配置已经启动了")
	}
	if err := wgConflict(config, c); err != nil {
		return err
	}
	names, err := a.vppInterfaces()
	if err != nil {
		return fmt.Errorf("读取 VPP 接口失败：%w", err)
	}
	if names[iface] {
		return fmt.Errorf("VPP 里已经有接口 %s，不是这份配置创建的", iface)
	}
	if err := a.wgUp(c); err != nil {
		return err
	}
	c.Enabled = true
	if err := a.saveWGStore(config.store); err != nil {
		if undoErr := a.wgDown(c); undoErr != nil {
			log.Printf("wireguard: undoing %s: %v", iface, undoErr)
		}
		return fmt.Errorf("保存配置失败：%w", err)
	}
	delete(a.wgErrors, iface)
	log.Printf("audit: wireguard: started %s, by %s", iface, user)
	return nil
}

// stopLocked takes a configuration out of VPP if it is there, and marks it stopped.
func (a *Service) stopLocked(store *wgStore, c *wgStored) error {
	live, err := a.wgLive(c)
	if err != nil {
		return fmt.Errorf("读取 VPP 接口失败：%w", err)
	}
	if live {
		if err := a.wgDown(c); err != nil {
			return fmt.Errorf("停止配置失败：%w", err)
		}
	} else if err := a.stopWGDNS(c); err != nil {
		return err
	}
	c.Enabled = false
	delete(a.wgErrors, c.iface())
	if err := a.saveWGStore(store); err != nil {
		return fmt.Errorf("接口已停止，但保存配置失败，VPP 重启后它会恢复：%w", err)
	}
	return nil
}

// StopWireGuardConfig removes the configuration from VPP and keeps it stored.
func (a *Service) StopWireGuardConfig(iface, user string) (*WireGuardState, error) {
	a.mu.Lock()
	err := a.stopWireGuardConfigLocked(iface, user)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

func (a *Service) stopWireGuardConfigLocked(iface, user string) error {
	store, err := a.loadWGStore()
	if err != nil {
		return err
	}
	c := wgFindConfig(store, iface)
	if c == nil {
		return fmt.Errorf("没有配置 %q", iface)
	}
	if !c.Enabled {
		return errors.New("这份配置没有启动")
	}
	if err := a.stopLocked(store, c); err != nil {
		return err
	}
	log.Printf("audit: wireguard: stopped %s, by %s", iface, user)
	return nil
}

// DeleteWireGuardConfig stops a configuration if needed and forgets it.
func (a *Service) DeleteWireGuardConfig(iface, user string) (*WireGuardState, error) {
	a.mu.Lock()
	err := a.deleteWireGuardConfigLocked(iface, user)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

func (a *Service) deleteWireGuardConfigLocked(iface, user string) error {
	store, err := a.loadWGStore()
	if err != nil {
		return err
	}
	c := wgFindConfig(store, iface)
	if c == nil {
		return fmt.Errorf("没有配置 %q", iface)
	}
	if c.Enabled {
		if err := a.stopLocked(store, c); err != nil {
			return err
		}
	}
	store.Configs = slices.DeleteFunc(store.Configs, func(item *wgStored) bool { return item == c })
	if err := a.saveWGStore(store); err != nil {
		return fmt.Errorf("保存配置失败：%w", err)
	}
	for _, peer := range c.Peers {
		if !wgKeyInUse(store, peer.PublicKey) {
			a.saveWireGuardName(peer.PublicKey, "")
		}
	}
	log.Printf("audit: wireguard: deleted configuration %s, by %s", iface, user)
	return nil
}

// addStoredPeerLocked adds a client to a stored configuration, and to VPP if it is running.
func (a *Service) addStoredPeerLocked(config *wgConfig, iface *wgInterface, key, name string, hosts []netip.Prefix, user string) error {
	c := iface.stored
	live, err := a.wgLive(c)
	if err != nil {
		return fmt.Errorf("读取 VPP 接口失败：%w", err)
	}
	peer := wgStoredPeer{PublicKey: key}
	for _, host := range hosts {
		peer.AllowedIPs = append(peer.AllowedIPs, host.String())
	}
	hosts = c.routable(hosts) // the routes to add and undo; AllowedIPs are as given
	undo := func() {
		if err := a.removeLive(key, iface.name, hosts); err != nil {
			log.Printf("wireguard: undoing the peer %s: %v", key, err)
		}
	}
	if live {
		if _, found, err := a.peerIndex(iface.name, key); err != nil {
			return fmt.Errorf("读取 VPP 的节点失败：%w", err)
		} else if found {
			return errors.New("这个公钥的节点已经在 VPP 里，但不在配置中")
		}
		if _, err := a.sys.vppCLI(c.peerLine(peer)); err != nil {
			return fmt.Errorf("VPP 没有接受这个节点：%w", err)
		}
		for _, host := range hosts {
			if _, err := a.sys.vppCLI(wireGuardRoute("add", host, iface.name)); err != nil {
				undo()
				return fmt.Errorf("VPP 没有接受节点的路由：%w", err)
			}
		}
	}
	c.Peers = append(c.Peers, peer)
	if err := a.saveWGStore(config.store); err != nil {
		if live {
			undo()
		}
		return fmt.Errorf("保存配置失败：%w", err)
	}
	a.saveWireGuardName(key, name)
	log.Printf("audit: wireguard: added %s on %s, by %s", key, iface.name, user)
	return nil
}

// deleteStoredPeerLocked removes a client from a stored configuration and from VPP.
func (a *Service) deleteStoredPeerLocked(config *wgConfig, peer *wgPeer, user string) error {
	c := peer.stored
	live, err := a.wgLive(c)
	if err != nil {
		return fmt.Errorf("读取 VPP 接口失败：%w", err)
	}
	if live {
		if err := a.removeLive(peer.key, peer.iface, c.routable(peer.allowed)); err != nil {
			return fmt.Errorf("从 VPP 删除节点失败：%w", err)
		}
	}
	c.Peers = slices.DeleteFunc(c.Peers, func(item wgStoredPeer) bool { return item.PublicKey == peer.key })
	if err := a.saveWGStore(config.store); err != nil {
		return fmt.Errorf("节点已从 VPP 删除，但保存配置失败，VPP 重启后它会回来：%w", err)
	}
	if !wgKeyInUse(config.store, peer.key) {
		a.saveWireGuardName(peer.key, "")
	}
	log.Printf("audit: wireguard: removed %s from %s, by %s", peer.key, peer.iface, user)
	return nil
}

// reconcileWireGuard creates every started configuration VPP does not have, and reports
// whether all of them are there now.
func (a *Service) reconcileWireGuard() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	store, err := a.loadWGStore()
	if err != nil {
		log.Printf("wireguard: %v", err)
		return false
	}
	if !slices.ContainsFunc(store.Configs, func(c *wgStored) bool { return c.Enabled }) {
		return true
	}
	names, err := a.vppInterfaces()
	if err != nil {
		return false
	}
	complete := true
	for _, c := range store.Configs {
		if !c.Enabled {
			continue
		}
		var err error
		if names[c.iface()] {
			err = a.startWGDNS(c)
		} else {
			err = a.wgUp(c)
		}
		if err != nil {
			complete = false
			if a.wgErrors[c.iface()] != err.Error() {
				log.Printf("wireguard: restoring %s: %v", c.iface(), err)
			}
			a.wgErrors[c.iface()] = err.Error()
			continue
		}
		delete(a.wgErrors, c.iface())
		log.Printf("wireguard: restored %s", c.iface())
	}
	return complete
}

// wireGuardTick restores the configurations once per VPP run. It looks only at VPP's socket
// file until there is something to do, so a running VPP is not disturbed.
func (a *Service) wireGuardTick(now time.Time) {
	stamp, err := a.stamp(a.opts.APISocket)
	if err != nil {
		return
	}
	if stamp.Ino == a.wgApplied.Ino && stamp.Ctime == a.wgApplied.Ctime {
		return
	}
	if a.opts.VPPUnit != "" {
		if !a.sys.unitActive(a.opts.VPPUnit) {
			return
		}
	} else if now.Sub(time.Unix(0, stamp.Ctime)) < wgSettle {
		return
	}
	if now.Before(a.wgRetryAt) {
		return
	}
	if a.reconcileWireGuard() {
		a.wgApplied = stamp
	} else {
		a.wgRetryAt = now.Add(wgRetryEvery)
	}
}

func (a *Service) watchVPP() {
	for range time.Tick(wgWatchEvery) {
		a.wireGuardTick(a.now())
	}
}
