package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	nameLimit  = 64
	rangeLimit = 1024 // ports one forward or router port may span; each is a NAT mapping
	// mappingLimit caps the NAT mappings forwards and router ports make together, TCP and UDP
	// counted apart. Each takes main heap in VPP and an API call to add when VPP restarts.
	mappingLimit = 4096
	ruleLimit    = 256
	protoTCP     = 6
	protoUDP     = 17
	protoICMP    = 1
	protoESP     = 50
	protoICMPv6  = 58
)

// Forward sends connections to ports on a WAN interface's address to a host behind it.
type Forward struct {
	ID           int      `json:"id"`
	Name         string   `json:"name"`
	Protocol     string   `json:"protocol"` // tcp, udp or both
	Interface    string   `json:"interface"`
	ExternalPort int      `json:"external_port"`
	LastPort     int      `json:"last_port,omitempty"` // the range's last external port; 0 for one port
	InternalIP   string   `json:"internal_ip"`
	InternalPort int      `json:"internal_port"`
	Sources      []string `json:"sources,omitempty"`
}

// Port opens a port on a WAN interface to VPP itself.
type Port struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Interface string `json:"interface"`
	Port      int    `json:"port"`
	LastPort  int    `json:"last_port,omitempty"`
}

// IPv6Rule lets connections from the WAN reach hosts behind it over IPv6.
type IPv6Rule struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // tcp, udp, both or any
	Address  string `json:"address"`  // an address or a prefix
	Port     int    `json:"port,omitempty"`
	LastPort int    `json:"last_port,omitempty"`
}

// Config is /etc/vpp/firewall.json.
type Config struct {
	// WANInterfaces overrides the WAN: by default, the interfaces NAT44 translates for.
	WANInterfaces []string      `json:"wan_interfaces,omitempty"`
	BlockPing     bool          `json:"block_ping"`
	IPv6Firewall  bool          `json:"ipv6_firewall"`
	Forwards      []Forward     `json:"forwards"`
	Ports         []Port        `json:"ports"`
	IPv6Rules     []IPv6Rule    `json:"ipv6_rules"`
	NextID        int           `json:"next_id"`
	LANDeny       []LANDenyRule `json:"lan_deny,omitempty"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{NextID: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := validateFilters(cfg); err != nil {
		return nil, err
	}
	if cfg.NextID < 1 {
		cfg.NextID = 1
	}
	for _, id := range cfg.ids() {
		cfg.NextID = max(cfg.NextID, id+1)
	}
	return cfg, nil
}

func (c *Config) ids() []int {
	var ids []int
	for _, f := range c.Forwards {
		ids = append(ids, f.ID)
	}
	for _, p := range c.Ports {
		ids = append(ids, p.ID)
	}
	for _, r := range c.IPv6Rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// mappingCount is how many NAT mappings the forwards and router ports make.
func (c *Config) mappingCount() int {
	n := 0
	for _, f := range c.Forwards {
		protos, _ := protocols(f.Protocol, false)
		count, _ := portRange(f.ExternalPort, f.LastPort, rangeLimit)
		n += len(protos) * count
	}
	for _, p := range c.Ports {
		protos, _ := protocols(p.Protocol, false)
		count, _ := portRange(p.Port, p.LastPort, rangeLimit)
		n += len(protos) * count
	}
	return n
}

// checkMappingLimit refuses a configuration that makes more NAT mappings than mappingLimit.
func (c *Config) checkMappingLimit() error {
	if n := c.mappingCount(); n > mappingLimit {
		return fmt.Errorf("端口转发和本机端口合计最多 %d 个 NAT 映射（TCP、UDP 各算一个），这样改要 %d 个", mappingLimit, n)
	}
	return nil
}

func (c *Config) clone() *Config {
	data, _ := json.Marshal(c)
	out := &Config{}
	json.Unmarshal(data, out)
	return out
}

func (c *Config) save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o644)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".vpp-firewall-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

func protocols(name string, allowAny bool) ([]uint8, error) {
	switch name {
	case "tcp":
		return []uint8{protoTCP}, nil
	case "udp":
		return []uint8{protoUDP}, nil
	case "both":
		return []uint8{protoTCP, protoUDP}, nil
	case "any":
		if allowAny {
			return []uint8{0}, nil
		}
	}
	if allowAny {
		return nil, errors.New("协议只能是 tcp、udp、both 或 any")
	}
	return nil, errors.New("协议只能是 tcp、udp 或 both")
}

func protoName(proto uint8) string {
	switch proto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	case protoICMP:
		return "icmp"
	}
	return fmt.Sprint(proto)
}

func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > nameLimit {
		return "", fmt.Errorf("名称最多 %d 个字", nameLimit)
	}
	if strings.ContainsAny(name, "\r\n\t") {
		return "", errors.New("名称不能有换行")
	}
	return name, nil
}

// portRange checks first..last, last 0 meaning first alone, and returns how many ports it has.
func portRange(first, last, limit int) (int, error) {
	if first < 1 || first > 65535 {
		return 0, errors.New("端口在 1 到 65535 之间")
	}
	if last == 0 {
		return 1, nil
	}
	if last < first || last > 65535 {
		return 0, errors.New("端口段的结束端口要不小于起始端口，且不大于 65535")
	}
	if limit > 0 && last-first+1 > limit {
		return 0, fmt.Errorf("端口段最多 %d 个端口", limit)
	}
	return last - first + 1, nil
}

func parseIPv6Target(text string) (netip.Prefix, error) {
	text = strings.TrimSpace(text)
	var prefix netip.Prefix
	if strings.Contains(text, "/") {
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return prefix, errors.New("地址写成 IPv6 地址或前缀，比如 2001:db8::10 或 2001:db8:1::/64")
		}
		prefix = p.Masked()
	} else {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return prefix, errors.New("地址写成 IPv6 地址或前缀，比如 2001:db8::10 或 2001:db8:1::/64")
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return prefix, errors.New("这里只填 IPv6 地址；IPv4 用端口转发")
	}
	return prefix, nil
}
