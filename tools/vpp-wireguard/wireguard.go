package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	wgNameLimit    = 64
	wgAddressLimit = 8
)

// Options configures the service.
type Options struct {
	ConfigDir string
	Names     string
	APISocket string
	// NATInterface is the NAT44 (EI or ED) outside interface on which a configuration's listening
	// port is opened, where VPP would otherwise drop handshakes.
	NATInterface string
	// ExitsFile is where the started configurations usable as exits are published.
	ExitsFile string
	// VPPUnit is the systemd unit that configures VPP; configurations are restored once it
	// is active, as their commands can depend on what it sets up.
	VPPUnit string
	// GateConfig is the Gate entry configuration. DNS forwarding uses only its
	// concrete listeners and hijack interface; the panel cannot override them.
	GateConfig string
}

// Service applies changes one at a time.
type Service struct {
	opts Options
	sys  system
	now  func() time.Time

	mu        sync.Mutex
	lookup    func(context.Context, string, string) ([]netip.Addr, error)
	stamp     func(string) (fileStamp, error)
	wgErrors  map[string]string // why a started configuration could not be restored
	wgApplied fileStamp         // the VPP run the configurations were restored into
	wgRetryAt time.Time
}

// NewService prepares the configuration directory.
func NewService(opts Options, sys system) (*Service, error) {
	if err := os.MkdirAll(opts.ConfigDir, 0o700); err != nil {
		return nil, err
	}
	service := &Service{opts: opts, sys: sys, now: time.Now, lookup: net.DefaultResolver.LookupNetIP, stamp: stampOf, wgErrors: map[string]string{}}
	if store, err := service.loadWGStore(); err == nil {
		service.publishExits(store)
	}
	return service, nil
}

// WireGuardInterface is an interface peers can be added to.
type WireGuardInterface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// WireGuardPeer is a peer the panel may delete. Peers that carry a default route are
// tunnels out of this router and are not listed.
type WireGuardPeer struct {
	PublicKey  string   `json:"public_key"`
	Interface  string   `json:"interface"`
	AllowedIPs []string `json:"allowed_ips"`
}

// WireGuardState is what the VPN page can manage.
type WireGuardState struct {
	Interfaces []WireGuardInterface `json:"interfaces"`
	Peers      []WireGuardPeer      `json:"peers"`
	Configs    []WireGuardConfig    `json:"configs"`
	DNSGate    *WireGuardDNS        `json:"dns_gate,omitempty"`
	// DefaultSource is the address existing tunnels send from, suggested for a new one.
	DefaultSource string `json:"default_source"`
	// VPPError says the running state could not be read, so Running means nothing.
	VPPError string `json:"vpp_error"`
}

type wgInterface struct {
	name      string
	stored    *wgStored
	port      int
	addresses []netip.Prefix
}

type wgPeer struct {
	key, iface string
	stored     *wgStored
	allowed    []netip.Prefix
}

type wgConfig struct {
	interfaces []*wgInterface
	peers      []*wgPeer
	store      *wgStore
}

func (c *wgConfig) iface(name string) *wgInterface {
	for _, candidate := range c.interfaces {
		if candidate.name == name {
			return candidate
		}
	}
	return nil
}

// peer finds a peer on an interface: one key may be a peer of several interfaces.
func (c *wgConfig) peer(iface, key string) *wgPeer {
	for _, candidate := range c.peers {
		if candidate.iface == iface && candidate.key == key {
			return candidate
		}
	}
	return nil
}

func (p *wgPeer) upstream() bool {
	return slices.ContainsFunc(p.allowed, func(prefix netip.Prefix) bool { return prefix.Bits() == 0 })
}

// readWireGuard reads the store into the shapes checks are made on.
func (a *Service) readWireGuard() (*wgConfig, error) {
	store, err := a.loadWGStore()
	if err != nil {
		return nil, err
	}
	config := &wgConfig{store: store}
	for _, c := range store.Configs {
		config.interfaces = append(config.interfaces, &wgInterface{name: c.iface(), stored: c, port: c.ListenPort, addresses: c.subnets()})
		for _, peer := range c.Peers {
			config.peers = append(config.peers, &wgPeer{key: peer.PublicKey, iface: c.iface(), stored: c, allowed: wgPrefixes(peer.AllowedIPs)})
		}
	}
	return config, nil
}

// WireGuard returns the interfaces, peers and configurations the panel can change.
func (a *Service) WireGuard() (*WireGuardState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	config, err := a.readWireGuard()
	if err != nil {
		return nil, err
	}
	result := &WireGuardState{Interfaces: []WireGuardInterface{}, Peers: []WireGuardPeer{}, Configs: []WireGuardConfig{}}
	if gate, gateErr := a.loadGateDNS(); gateErr == nil {
		result.DNSGate = &WireGuardDNS{IPv4: gate.IPv4, IPv6: gate.IPv6, HostInterface: gate.HostInterface}
	}
	if len(config.store.Configs) > 0 {
		result.DefaultSource = config.store.Configs[0].Source
	}
	var running map[string]bool
	if len(config.store.Configs) > 0 {
		if running, err = a.vppInterfaces(); err != nil {
			result.VPPError = "读取 VPP 接口失败"
		}
	}
	for _, c := range config.store.Configs {
		result.Configs = append(result.Configs, WireGuardConfig{
			DNS:  c.DNS,
			Name: c.Name, Interface: c.iface(), Enabled: c.Enabled, Running: c.Enabled && running[c.iface()],
			Addresses: c.Addresses, ListenPort: c.ListenPort, PublicKey: wgPublicKey(c.PrivateKey),
			Source: c.Source, Peers: len(c.Peers), Commands: len(c.AfterUp), Error: a.wgErrors[c.iface()],
		})
	}
	for _, iface := range config.interfaces {
		item := WireGuardInterface{Name: iface.name, Addresses: []string{}}
		for _, address := range iface.addresses {
			item.Addresses = append(item.Addresses, address.String())
		}
		result.Interfaces = append(result.Interfaces, item)
	}
	for _, peer := range config.peers {
		if peer.upstream() {
			continue
		}
		item := WireGuardPeer{PublicKey: peer.key, Interface: peer.iface, AllowedIPs: []string{}}
		for _, prefix := range peer.allowed {
			item.AllowedIPs = append(item.AllowedIPs, prefix.String())
		}
		result.Peers = append(result.Peers, item)
	}
	return result, nil
}

func validWireGuardKey(key string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(key)
	return err == nil && len(decoded) == 32
}

func cleanWireGuardName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if len([]rune(name)) > wgNameLimit {
		return "", fmt.Errorf("名字不能超过 %d 个字符", wgNameLimit)
	}
	if strings.ContainsFunc(name, unicode.IsControl) {
		return "", errors.New("名字里有控制字符")
	}
	return name, nil
}

// wireGuardHost accepts a bare address or its /32 or /128 form. A peer's address is a single
// host: a wider one would claim addresses the router may be routing somewhere else.
func wireGuardHost(text string) (netip.Prefix, error) {
	text = strings.TrimSpace(text)
	if !strings.Contains(text, "/") {
		address, err := netip.ParseAddr(text)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q 不是地址", text)
		}
		return netip.PrefixFrom(address.WithZone(""), address.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q 不是地址", text)
	}
	if !prefix.IsSingleIP() {
		return netip.Prefix{}, fmt.Errorf("%s 不是单个地址，节点地址要用 /32 或 /128", text)
	}
	return prefix, nil
}

// checkWireGuardAddresses returns the peer's addresses, or why one of them cannot be used.
func checkWireGuardAddresses(config *wgConfig, iface *wgInterface, texts []string) ([]netip.Prefix, error) {
	if len(texts) == 0 {
		return nil, errors.New("至少要有一个内网地址")
	}
	if len(texts) > wgAddressLimit {
		return nil, fmt.Errorf("一个节点最多 %d 个地址", wgAddressLimit)
	}
	var hosts []netip.Prefix
	for _, text := range texts {
		host, err := wireGuardHost(text)
		if err != nil {
			return nil, err
		}
		if slices.Contains(hosts, host) {
			return nil, fmt.Errorf("%s 重复了", host)
		}
		inside := false
		for _, own := range iface.addresses {
			if own.Addr() == host.Addr() {
				return nil, fmt.Errorf("%s 是接口 %s 自己的地址", host.Addr(), iface.name)
			}
			inside = inside || own.Masked().Contains(host.Addr())
		}
		if !inside {
			return nil, fmt.Errorf("%s 不在接口 %s 的网段内", host.Addr(), iface.name)
		}
		for _, peer := range config.peers {
			if peer.upstream() {
				continue // a tunnel's default route claims everything and conflicts with nothing
			}
			for _, allowed := range peer.allowed {
				if allowed.Contains(host.Addr()) {
					return nil, fmt.Errorf("%s 已被节点 %s 使用", host.Addr(), peer.key)
				}
			}
		}
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func wireGuardRoute(verb string, host netip.Prefix, iface string) string {
	return fmt.Sprintf("ip route %s %s via %s %s", verb, host, host.Addr(), iface)
}

var wgPeerRecord = regexp.MustCompile(`(?m)^\s*\[(\d+)\]`)

func (a *Service) removeInterfacePeers(iface string) error {
	output, err := a.sys.vppCLI("show wireguard peer")
	if err != nil {
		return err
	}
	starts := wgPeerRecord.FindAllStringSubmatchIndex(output, -1)
	for i, start := range starts {
		end := len(output)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		if !strings.Contains(output[start[0]:end], "] "+iface+" ") {
			continue
		}
		index := output[start[2]:start[3]]
		if _, err := a.sys.vppCLI("wireguard peer remove " + index); err != nil {
			return err
		}
	}
	return nil
}

// peerIndex finds a peer in VPP, which removes peers by index. A record is searched for the
// key and the interface rather than parsed, as one key may be a peer of several interfaces.
func (a *Service) peerIndex(iface, key string) (index int, found bool, err error) {
	output, err := a.sys.vppCLI("show wireguard peer")
	if err != nil {
		return 0, false, err
	}
	starts := wgPeerRecord.FindAllStringSubmatchIndex(output, -1)
	for i, start := range starts {
		end := len(output)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		if record := output[start[0]:end]; strings.Contains(record, key) && strings.Contains(record, "] "+iface+" ") {
			index, err := strconv.Atoi(output[start[2]:start[3]])
			return index, err == nil, err
		}
	}
	return 0, false, nil
}

// removeLive takes a peer out of the running VPP. Its routes go even when the peer is gone.
func (a *Service) removeLive(key, iface string, hosts []netip.Prefix) error {
	index, found, err := a.peerIndex(iface, key)
	if err != nil {
		return err
	}
	if found {
		if _, err := a.sys.vppCLI("wireguard peer remove " + strconv.Itoa(index)); err != nil {
			return err
		}
	}
	for _, host := range hosts {
		if _, err := a.sys.vppCLI(wireGuardRoute("del", host, iface)); err != nil {
			log.Printf("wireguard: removing the route to %s: %v", host, err)
		}
	}
	return nil
}

// saveWireGuardName keeps a peer's name in the file the panel reads names from. A failure
// only costs the name, so it is logged and the peer stays.
func (a *Service) saveWireGuardName(key, name string) {
	path := a.opts.Names
	if path == "" {
		return
	}
	names := map[string]string{}
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &names)
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		log.Printf("wireguard: the names file cannot be read, leaving it alone: %v", err)
		return
	}
	if name == "" {
		if _, ok := names[key]; !ok {
			return
		}
		delete(names, key)
	} else {
		names[key] = name
	}
	encoded, err := json.MarshalIndent(names, "", "  ")
	if err == nil {
		err = writeFileAtomic(path, append(encoded, '\n'), 0o600)
	}
	if err != nil {
		log.Printf("wireguard: saving the names file: %v", err)
	}
}

// AddWireGuardPeer adds a client, identified by the public key it generated for itself.
func (a *Service) AddWireGuardPeer(ifaceName, key, name string, addresses []string, user string) (*WireGuardState, error) {
	if !validWireGuardKey(key) {
		return nil, errors.New("公钥格式不对，应该是 44 个字符的 Base64")
	}
	name, err := cleanWireGuardName(name)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	err = a.addWireGuardPeerLocked(ifaceName, key, name, addresses, user)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

func (a *Service) addWireGuardPeerLocked(ifaceName, key, name string, addresses []string, user string) error {
	config, err := a.readWireGuard()
	if err != nil {
		return err
	}
	iface := config.iface(ifaceName)
	if iface == nil {
		return fmt.Errorf("接口 %q 不能由面板管理", ifaceName)
	}
	if config.peer(ifaceName, key) != nil {
		return errors.New("这个接口上已经有这个公钥的节点")
	}
	hosts, err := checkWireGuardAddresses(config, iface, addresses)
	if err != nil {
		return err
	}
	return a.addStoredPeerLocked(config, iface, key, name, hosts, user)
}

// DeleteWireGuardPeer removes a peer from its configuration and from VPP.
func (a *Service) DeleteWireGuardPeer(iface, key, user string) (*WireGuardState, error) {
	a.mu.Lock()
	err := a.deleteWireGuardPeerLocked(iface, key, user)
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.WireGuard()
}

func (a *Service) deleteWireGuardPeerLocked(iface, key, user string) error {
	config, err := a.readWireGuard()
	if err != nil {
		return err
	}
	peer := config.peer(iface, key)
	if peer == nil {
		return errors.New("这个接口上没有这个节点")
	}
	if peer.upstream() {
		return errors.New("这是上游隧道，不能在这里删除")
	}
	return a.deleteStoredPeerLocked(config, peer, user)
}
