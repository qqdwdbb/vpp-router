package gate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultListDir = "/etc/vpp/gate"
	seenPersist    = 60
	migratedDomain = "@legacy"
	defaultIdle    = 7 * 24 * 3600
	exactLookupLim = 16
)

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
	setNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	ifaceRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)
	labelRe   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type MappingKey struct {
	Family, Table, Set string
}

type Mapping struct {
	Enabled         bool
	Family          string
	Table           string
	Set             string
	Interface       string
	Via             string
	Via6            string
	FibTable        uint32
	FakeIP          string
	FakeIP6         string
	TProxyPort      int
	TProxyInterface string
	// TProxyAddress holds at most one address per family; none means any local address.
	TProxyAddress []netip.Addr
	LinuxExit     *LinuxExit
	// Default makes the exit carry everything no rule and no more specific route claims.
	Default bool
	// DHCPGateway takes the IPv4 next hop from VPP's DHCP lease on Interface, at run time.
	DHCPGateway bool
	// RealAddresses: a TPROXY rule that sends real addresses to its listener, because its DNS
	// is not Fake-IP or because it has address ranges. Fake-IP rules send only their pool.
	RealAddresses bool
}

func (m Mapping) Key() MappingKey {
	return MappingKey{m.Family, m.Table, m.Set}
}

func viaFamily(via string) int {
	addr, err := parseAddr(via)
	if err != nil {
		return 0
	}
	if addr.Is4() {
		return 4
	}
	return 6
}

func (m Mapping) ViaFor(family int) string {
	if family == 4 {
		if viaFamily(m.Via) == 4 {
			return m.Via
		}
		return ""
	}
	if m.Via6 != "" {
		return m.Via6
	}
	if viaFamily(m.Via) == 6 {
		return m.Via
	}
	return ""
}

func (m Mapping) FakeIPFor(family int) string {
	if family == 4 {
		if p, err := parsePrefixStrict(m.FakeIP); err == nil && p.Addr().Is4() {
			return m.FakeIP
		}
		return ""
	}
	if m.FakeIP6 != "" {
		return m.FakeIP6
	}
	if p, err := parsePrefixStrict(m.FakeIP); err == nil && p.Addr().Is6() {
		return m.FakeIP
	}
	return ""
}

func (m Mapping) HasFakeIP() bool {
	return m.FakeIP != "" || m.FakeIP6 != ""
}

func (m Mapping) MatchesPath(table uint32, via, iface string) bool {
	if !m.Enabled || m.FibTable != table || m.Interface != iface || via == "" {
		return false
	}
	return via == m.ViaFor(4) || via == m.ViaFor(6)
}

func (m Mapping) EachVia() []string {
	var out []string
	if v := m.ViaFor(4); v != "" {
		out = append(out, v)
	}
	if v := m.ViaFor(6); v != "" {
		out = append(out, v)
	}
	return out
}

func (m Mapping) EachFakeIP() []string {
	var out []string
	if v := m.FakeIPFor(4); v != "" {
		out = append(out, v)
	}
	if v := m.FakeIPFor(6); v != "" {
		out = append(out, v)
	}
	return out
}

type FakeIPPool struct {
	Route    Route
	Upstream *Upstream
	Mapping  MappingKey
}

type Upstream struct {
	Host string
	Port int
}

type Target struct {
	Version *int
	Mapping Mapping
}

type Rule struct {
	Pattern      string
	Targets      []Target
	Upstream     *Upstream
	UpstreamMark uint32
	Match        string
}

type Config struct {
	// IgnoreListProblems is for starting Gate: what is wrong with a list file costs that
	// part of the file, with a warning, and not DNS. A plain sync still refuses it.
	IgnoreListProblems   bool
	IntervalSeconds      float64
	MonitorResyncSeconds float64
	MaxRoutes            int
	IdleSeconds          int
	FibAuditSeconds      float64
	VPPSocket            string
	APISocket            string
	VPPService           string
	StateFile            string
	StateSocket          string
	LockFiles            []string
	ExcludePrefixes      []string
	DNSUpstreamPolicy    string
	OverlapPolicy        string
	Mappings             []Mapping
	FakeIPTTL            int
	StaticPrefixes       map[MappingKey]map[string]struct{}
	IPRangePrefixes      map[MappingKey]map[string]struct{}
	FakeIPPools          map[netip.Prefix]FakeIPPool

	staticIndex    *PrefixIndex
	exclusionIndex *PrefixIndex
	exclusionNets  []netip.Prefix
}

type GateFile struct {
	RouteConfig      string
	DomainRoutesFile string
	LeaseFile        string
	Upstream         Upstream
	Listen           []Upstream
	HasRoutes        bool
	HijackDNS        bool
	HijackInterfaces []string
	HijackVPP        []HijackVPPEntry
	// LANInterfaces are VPP interfaces whose IPv6 prefixes are client networks too, for
	// prefixes that come and go, such as a delegated one. See lan_prefixes.go.
	LANInterfaces []string
}

func LoadGateFile(path string) (*GateFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	g := &GateFile{}
	g.RouteConfig, _ = doc["route_config"].(string)
	g.DomainRoutesFile, _ = doc["domain_routes_file"].(string)
	g.LeaseFile, _ = doc["lease_file"].(string)
	up, err := parseHostPort(doc["upstream"])
	if err != nil {
		return nil, err
	}
	g.Upstream = up
	if listen, ok := doc["listen"].([]any); ok {
		for _, item := range listen {
			hp, err := parseHostPort(item)
			if err != nil {
				return nil, err
			}
			g.Listen = append(g.Listen, hp)
		}
	}
	if v, ok := doc["hijack_dns"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("hijack_dns must be a boolean")
		}
		g.HijackDNS = b
	}
	if v, ok := doc["hijack_interfaces"]; ok && v != nil {
		names, err := parseNameList(v, "hijack_interfaces")
		if err != nil {
			return nil, err
		}
		g.HijackInterfaces = names
	}
	if v, ok := doc["lan_interfaces"]; ok && v != nil {
		names, err := parseNameList(v, "lan_interfaces")
		if err != nil {
			return nil, err
		}
		g.LANInterfaces = names
	}
	if v, ok := doc["hijack_vpp"]; ok && v != nil {
		entries, err := parseHijackVPP(v)
		if err != nil {
			return nil, err
		}
		g.HijackVPP = entries
	}
	if err := g.validateHijack(); err != nil {
		return nil, err
	}
	_, routes, err := linkedJSON(doc, "domain_routes_file")
	if err != nil {
		return nil, err
	}
	if routes == nil {
		routes = doc
	}
	if err := ValidateDNSConfig(doc, routes); err != nil {
		return nil, err
	}
	_, g.HasRoutes = doc["routes"].([]any)
	return g, nil
}

func parseNameList(v any, key string) ([]string, error) {
	var arr []any
	switch t := v.(type) {
	case string:
		arr = []any{t}
	case []any:
		arr = t
	default:
		return nil, fmt.Errorf("%s must be an interface name or a list of names", key)
	}
	seen := map[string]struct{}{}
	var out []string
	for _, item := range arr {
		name, ok := item.(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("%s must be an interface name or a list of names", key)
		}
		if !ifaceRe.MatchString(name) {
			return nil, fmt.Errorf("invalid %s name %q", key, name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

func (g *GateFile) validateHijack() error {
	if !g.HijackDNS {
		if len(g.HijackVPP) > 0 {
			return fmt.Errorf("hijack_vpp requires hijack_dns")
		}
		return nil
	}
	if len(g.HijackInterfaces) == 0 {
		return fmt.Errorf("hijack_dns requires hijack_interfaces")
	}
	if len(g.Listen) == 0 {
		return fmt.Errorf("hijack_dns requires listen")
	}
	port := g.Listen[0].Port
	for _, listen := range g.Listen[1:] {
		if listen.Port != port {
			return fmt.Errorf("hijack_dns requires every listen address to use the same port")
		}
	}
	return nil
}

func parseHostPort(v any) (Upstream, error) {
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 {
		return Upstream{}, fmt.Errorf("host/port must be [IP address, port]")
	}
	host, ok := arr[0].(string)
	if !ok {
		return Upstream{}, fmt.Errorf("host must be a string")
	}
	port, err := asInt(arr[1])
	if err != nil || port < 1 || port > 65535 {
		return Upstream{}, fmt.Errorf("invalid port")
	}
	return Upstream{host, port}, nil
}

func asInt(v any) (int, error) {
	switch t := v.(type) {
	case float64:
		return int(t), nil
	case json.Number:
		return strconv.Atoi(t.String())
	case int:
		return t, nil
	case int32:
		return int(t), nil
	case int64:
		return int(t), nil
	case uint:
		return int(t), nil
	case uint32:
		return int(t), nil
	case uint64:
		return int(t), nil
	default:
		return 0, fmt.Errorf("not an integer")
	}
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	cfg := &Config{
		IntervalSeconds:      2,
		MonitorResyncSeconds: 60,
		MaxRoutes:            10000,
		IdleSeconds:          defaultIdle,
		FibAuditSeconds:      60,
		VPPSocket:            "/run/vpp/cli.sock",
		APISocket:            "/run/vpp/api.sock",
		VPPService:           "vpp",
		StateFile:            "/var/lib/vpp-egress-gate/state.json",
		LockFiles:            []string{"/run/lock/vpp-wireguard-client-import.lock", "/run/lock/vpp-wireguard-import.lock"},
		DNSUpstreamPolicy:    "first-upstream",
		OverlapPolicy:        "error",
		StaticPrefixes:       map[MappingKey]map[string]struct{}{},
		FakeIPPools:          map[netip.Prefix]FakeIPPool{},
	}
	if v, ok := doc["interval_seconds"]; ok {
		cfg.IntervalSeconds, _ = v.(float64)
	}
	if v, ok := doc["monitor_resync_seconds"]; ok {
		cfg.MonitorResyncSeconds, _ = v.(float64)
	}
	if v, ok := doc["max_routes"]; ok {
		n, err := asInt(v)
		if err != nil {
			return nil, fmt.Errorf("max_routes must be between 1 and 1000000")
		}
		cfg.MaxRoutes = n
	}
	if v, ok := doc["idle_seconds"]; ok {
		n, err := asInt(v)
		if err != nil {
			return nil, fmt.Errorf("idle_seconds must be between 0 and 90 days")
		}
		cfg.IdleSeconds = n
	}
	if v, ok := doc["fib_audit_seconds"]; ok {
		switch t := v.(type) {
		case float64:
			cfg.FibAuditSeconds = t
		default:
			n, err := asInt(v)
			if err != nil {
				return nil, fmt.Errorf("fib_audit_seconds must be between 0 and 86400")
			}
			cfg.FibAuditSeconds = float64(n)
		}
	}
	if v, ok := doc["vpp_socket"].(string); ok {
		cfg.VPPSocket = v
	}
	if v, ok := doc["api_socket"].(string); ok {
		cfg.APISocket = v
	}
	if v, ok := doc["vpp_service"].(string); ok {
		cfg.VPPService = v
	}
	if v, ok := doc["state_file"].(string); ok {
		cfg.StateFile = v
	}
	if v, ok := doc["state_socket"].(string); ok {
		cfg.StateSocket = v
	}
	if v, ok := doc["lock_files"].([]any); ok {
		cfg.LockFiles = nil
		for _, item := range v {
			s, _ := item.(string)
			cfg.LockFiles = append(cfg.LockFiles, s)
		}
	}
	if v, ok := doc["exclude_prefixes"].([]any); ok {
		for _, item := range v {
			s, _ := item.(string)
			cfg.ExcludePrefixes = append(cfg.ExcludePrefixes, s)
		}
	}
	if v, ok := doc["dns_upstream_policy"].(string); ok {
		cfg.DNSUpstreamPolicy = v
	}
	if v, ok := doc["overlap_policy"].(string); ok {
		cfg.OverlapPolicy = v
	}
	if cfg.DNSUpstreamPolicy != "first" && cfg.DNSUpstreamPolicy != "first-upstream" {
		return nil, fmt.Errorf("dns_upstream_policy must be first or first-upstream")
	}
	if cfg.OverlapPolicy != "error" && cfg.OverlapPolicy != "first" {
		return nil, fmt.Errorf("overlap_policy must be error or first")
	}
	if cfg.IntervalSeconds < 0.2 || cfg.IntervalSeconds > 3600 {
		return nil, fmt.Errorf("interval_seconds must be between 0.2 and 3600")
	}
	if cfg.MonitorResyncSeconds < 1 || cfg.MonitorResyncSeconds > 3600 {
		return nil, fmt.Errorf("monitor_resync_seconds must be between 1 and 3600")
	}
	if cfg.MaxRoutes < 1 || cfg.MaxRoutes > 1000000 {
		return nil, fmt.Errorf("max_routes must be between 1 and 1000000")
	}
	if cfg.IdleSeconds < 0 || cfg.IdleSeconds > 90*24*3600 {
		return nil, fmt.Errorf("idle_seconds must be between 0 and 90 days")
	}
	if cfg.FibAuditSeconds < 0 || cfg.FibAuditSeconds > 86400 {
		return nil, fmt.Errorf("fib_audit_seconds must be between 0 and 86400")
	}
	if !nameRe.MatchString(cfg.VPPService) {
		return nil, fmt.Errorf("invalid vpp_service")
	}
	for _, prefix := range cfg.ExcludePrefixes {
		if _, err := parsePrefixStrict(prefix); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func dnsUpstreamValue(v any) (*Upstream, error) {
	return namedUpstream("dns_upstream", v)
}

func namedUpstream(field string, v any) (*Upstream, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("%s must be [IP address, port]", field)
	}
	host, ok := arr[0].(string)
	if !ok {
		return nil, fmt.Errorf("%s must be [IP address, port]", field)
	}
	port, err := asInt(arr[1])
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%s must be [IP address, port]", field)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, fmt.Errorf("%s host must be an IP address", field)
	}
	return &Upstream{host, port}, nil
}

func routeUpstream(obj map[string]any) (upstream *Upstream, fake bool, err error) {
	for _, key := range []string{"dns_upstream", "dns", "fake_dns"} {
		raw, ok := obj[key]
		if !ok {
			continue
		}
		up, err := namedUpstream(key, raw)
		if err != nil {
			return nil, false, err
		}
		if upstream != nil && (upstream.Host != up.Host || upstream.Port != up.Port) {
			return nil, false, fmt.Errorf("conflicting DNS upstream fields")
		}
		upstream = up
		if key == "fake_dns" {
			fake = true
		}
	}
	return upstream, fake, nil
}

func parseViaList(v any) (v4, v6 string, err error) {
	if v == nil {
		return "", "", fmt.Errorf("invalid domain route via")
	}
	var items []any
	switch t := v.(type) {
	case string:
		items = []any{t}
	case []any:
		items = t
	default:
		return "", "", fmt.Errorf("via must be an IP address or a list of IP addresses")
	}
	if len(items) == 0 {
		return "", "", fmt.Errorf("via must be an IP address or a list of IP addresses")
	}
	for _, item := range items {
		addr, err := parseAddr(fmt.Sprint(item))
		if err != nil {
			return "", "", err
		}
		if addr.Is4() {
			if v4 != "" {
				return "", "", fmt.Errorf("via lists at most one IPv4 and one IPv6 next hop")
			}
			v4 = addr.String()
			continue
		}
		if v6 != "" {
			return "", "", fmt.Errorf("via lists at most one IPv4 and one IPv6 next hop")
		}
		v6 = addr.String()
	}
	return v4, v6, nil
}

func parsePrefixList(v any) (v4, v6 string, err error) {
	if v == nil {
		return "", "", nil
	}
	var items []any
	switch t := v.(type) {
	case string:
		items = []any{t}
	case []any:
		items = t
	default:
		return "", "", fmt.Errorf("fakeip_range must be a prefix or a list of prefixes")
	}
	for _, item := range items {
		network, err := parsePrefixStrict(fmt.Sprint(item))
		if err != nil {
			return "", "", err
		}
		if network.Bits() == 0 || network.Bits() == network.Addr().BitLen() {
			return "", "", fmt.Errorf("fakeip_range requires an upstream DNS and a matching pool family")
		}
		if network.Addr().Is4() {
			if v4 != "" {
				return "", "", fmt.Errorf("fakeip_range lists at most one IPv4 and one IPv6 pool")
			}
			v4 = prefixString(network)
			continue
		}
		if v6 != "" {
			return "", "", fmt.Errorf("fakeip_range lists at most one IPv4 and one IPv6 pool")
		}
		v6 = prefixString(network)
	}
	return v4, v6, nil
}

// resolveListFile finds a list file named by a rule: an absolute path, or a file name in
// defaultListDir.
func resolveListFile(key, name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("%s %s must be a file name or an absolute path", key, name)
	}
	return filepath.Join(defaultListDir, name), nil
}

func listFiles(item map[string]any, key string) ([]string, error) {
	raw, ok := item[key]
	if !ok || raw == nil {
		return nil, nil
	}
	var arr []any
	switch t := raw.(type) {
	case string:
		arr = []any{t}
	case []any:
		arr = t
	default:
		return nil, fmt.Errorf("%s must be a file path or a list of file paths", key)
	}
	var out []string
	for _, v := range arr {
		name, ok := v.(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("%s must be a file path or a list of file paths", key)
		}
		file, err := resolveListFile(key, name)
		if err != nil {
			return nil, err
		}
		out = append(out, file)
	}
	return out, nil
}

func domainRouteFiles(item map[string]any) ([]string, error) {
	a, err := listFiles(item, "domain_files")
	if err != nil {
		return nil, err
	}
	b, err := listFiles(item, "ip_range_files")
	if err != nil {
		return nil, err
	}
	return append(a, b...), nil
}

func DomainSourceHash(paths []string) (string, error) {
	h := sha256.New()
	for _, path := range paths {
		name := []byte(path)
		// A list file Gate ignored has no content, and hashes as such.
		content, _ := os.ReadFile(path)
		var nlen [4]byte
		binary.BigEndian.PutUint32(nlen[:], uint32(len(name)))
		var clen [8]byte
		binary.BigEndian.PutUint64(clen[:], uint64(len(content)))
		h.Write(nlen[:])
		h.Write(name)
		h.Write(clen[:])
		h.Write(content)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func domainOutletHashes(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	routes, _ := doc["routes"].([]any)
	hashes := map[string]string{}
	for _, item := range routes {
		obj, _ := item.(map[string]any)
		h := sha256.New()
		dump, err := canonicalDump(obj)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(dump))
		files, err := domainRouteFiles(obj)
		if err != nil {
			return nil, err
		}
		for _, filename := range files {
			name := []byte(filename)
			content, _ := os.ReadFile(filename)
			var nlen [4]byte
			binary.BigEndian.PutUint32(nlen[:], uint32(len(name)))
			var clen [8]byte
			binary.BigEndian.PutUint64(clen[:], uint64(len(content)))
			h.Write(nlen[:])
			h.Write(name)
			h.Write(clen[:])
			h.Write(content)
		}
		name, _ := obj["name"].(string)
		hashes[name] = fmt.Sprintf("%x", h.Sum(nil))
	}
	return hashes, nil
}

func canonicalDump(v any) (string, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteString(": ")
			s, err := canonicalDump(t[k])
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		b.WriteByte('}')
		return b.String(), nil
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			s, err := canonicalDump(item)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		b.WriteByte(']')
		return b.String(), nil
	case string:
		out, _ := json.Marshal(t)
		return string(out), nil
	case bool:
		if t {
			return "true", nil
		}
		return "false", nil
	case nil:
		return "null", nil
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), nil
		}
		return strconv.FormatFloat(t, 'g', -1, 64), nil
	default:
		out, err := json.Marshal(t)
		return string(out), err
	}
}

func DomainRoutePaths(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	routes, ok := doc["routes"].([]any)
	if !ok {
		return nil, fmt.Errorf("domain routes must contain a routes array")
	}
	paths := []string{path}
	for _, item := range routes {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid domain route")
		}
		files, err := domainRouteFiles(obj)
		if err != nil {
			return nil, err
		}
		paths = append(paths, files...)
	}
	return paths, nil
}

func checkDomain(rawDomain string) error {
	domain := strings.ToLower(strings.TrimRight(rawDomain, "."))
	if len(domain) > 253 {
		return fmt.Errorf("invalid domain: %s", rawDomain)
	}
	for _, label := range strings.Split(domain, ".") {
		if !labelRe.MatchString(label) {
			return fmt.Errorf("invalid domain: %s", rawDomain)
		}
	}
	return nil
}

func DomainRoutesFromFile(path string, cfg *Config) ([]Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	routesRaw, ok := doc["routes"].([]any)
	if !ok {
		return nil, fmt.Errorf("domain routes must contain a routes array")
	}
	if v, ok := doc["overlap_policy"].(string); ok {
		if v != "error" && v != "first" {
			return nil, fmt.Errorf("overlap_policy must be error or first")
		}
		cfg.OverlapPolicy = v
	}
	if v, ok := doc["dns_upstream_policy"].(string); ok {
		if v != "first" && v != "first-upstream" {
			return nil, fmt.Errorf("dns_upstream_policy must be first or first-upstream")
		}
		cfg.DNSUpstreamPolicy = v
	}
	for _, item := range routesRaw {
		obj, _ := item.(map[string]any)
		if obj == nil {
			continue
		}
		_, hasFake := obj["fakeip_range"]
		_, hasFakeDNS := obj["fake_dns"]
		if hasFake || hasFakeDNS || obj["tproxy_port"] != nil {
			cfg.OverlapPolicy = "first"
			cfg.DNSUpstreamPolicy = "first"
			break
		}
	}
	var mappings []Mapping
	var rules []Rule
	names := map[string]struct{}{}
	pools := map[netip.Prefix]FakeIPPool{}
	ipRangePrefixes := map[MappingKey]map[string]struct{}{}
	for _, item := range routesRaw {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid domain route")
		}
		name, _ := obj["name"].(string)
		if !setNameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid or duplicate domain route name")
		}
		if _, dup := names[name]; dup {
			return nil, fmt.Errorf("invalid or duplicate domain route name")
		}
		names[name] = struct{}{}
		iface, _ := obj["interface"].(string)
		if iface == "" || !nameRe.MatchString(iface) {
			return nil, fmt.Errorf("invalid domain route interface")
		}
		dhcpGateway := false
		if v, ok := obj["dhcp_gateway"]; ok {
			if dhcpGateway, ok = v.(bool); !ok {
				return nil, fmt.Errorf("rule %s: dhcp_gateway must be true or false", name)
			}
		}
		var via4, via6 string
		if _, present := obj["via"]; present || !dhcpGateway {
			if via4, via6, err = parseViaList(obj["via"]); err != nil {
				return nil, err
			}
		}
		if dhcpGateway && via4 != "" {
			return nil, fmt.Errorf("rule %s: dhcp_gateway is the IPv4 next hop, so via can only add an IPv6 one", name)
		}
		fib := 0
		if v, ok := obj["fib_table"]; ok {
			fib, err = asInt(v)
			if err != nil || fib < 0 || fib >= 1<<32 {
				return nil, fmt.Errorf("invalid domain route fib_table")
			}
		}
		var domains []string
		if v, ok := obj["domains"]; ok {
			arr, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("domains must be a list")
			}
			for _, d := range arr {
				s, ok := d.(string)
				if !ok {
					return nil, fmt.Errorf("invalid domain")
				}
				domains = append(domains, s)
			}
		}
		var keywords []string
		if v, ok := obj["domain_keywords"]; ok {
			arr, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("domain_keywords must be a list")
			}
			for _, d := range arr {
				s, ok := d.(string)
				if !ok {
					return nil, fmt.Errorf("invalid domain keyword")
				}
				keywords = append(keywords, s)
			}
		}
		upstream, fakeDNS, err := routeUpstream(obj)
		if err != nil {
			return nil, err
		}
		domainFiles, err := listFiles(obj, "domain_files")
		if err != nil {
			return nil, err
		}
		for _, filename := range domainFiles {
			text, err := os.ReadFile(filename)
			if err != nil {
				if !cfg.IgnoreListProblems {
					return nil, err
				}
				log.Printf("rule %s: list file ignored: %s", name, err)
				continue
			}
			for lineNumber, line := range strings.Split(string(text), "\n") {
				domain := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
				if domain == "" {
					continue
				}
				if cfg.IgnoreListProblems && checkDomain(domain) != nil {
					log.Printf("rule %s: line ignored: %s:%d: invalid domain: %s", name, filename, lineNumber+1, domain)
					continue
				}
				domains = append(domains, domain)
			}
		}
		var ipPrefixes []string
		rangeFiles, err := listFiles(obj, "ip_range_files")
		if err != nil {
			return nil, err
		}
		for _, filename := range rangeFiles {
			text, err := os.ReadFile(filename)
			if err != nil {
				if !cfg.IgnoreListProblems {
					return nil, err
				}
				log.Printf("rule %s: list file ignored: %s", name, err)
				continue
			}
			// A bad line goes on its own: a range that is half right is not installed.
			invalidRange := func(lineNumber int, value string) error {
				err := fmt.Errorf("invalid IP range in %s:%d: %s", filename, lineNumber+1, value)
				if !cfg.IgnoreListProblems {
					return err
				}
				log.Printf("rule %s: line ignored: %s", name, err)
				return nil
			}
			for lineNumber, rawLine := range strings.Split(string(text), "\n") {
				value := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
				if value == "" {
					continue
				}
				var networks []netip.Prefix
				if strings.Contains(value, "-") {
					parts := strings.SplitN(value, "-", 2)
					first, err1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
					last, err2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
					if err1 != nil || err2 != nil || first.BitLen() != last.BitLen() || first.Compare(last) > 0 {
						if err := invalidRange(lineNumber, value); err != nil {
							return nil, err
						}
						continue
					}
					networks, err = summarizeRange(first, last)
					if err != nil {
						if err := invalidRange(lineNumber, value); err != nil {
							return nil, err
						}
						continue
					}
				} else {
					n, err := parsePrefixStrict(value)
					if err != nil {
						if err := invalidRange(lineNumber, value); err != nil {
							return nil, err
						}
						continue
					}
					networks = []netip.Prefix{n}
				}
				usable := true
				for _, network := range networks {
					usable = usable && network.Bits() != 0 && !((network.Addr().Is4() && via4 == "") || (network.Addr().Is6() && via6 == ""))
				}
				if !usable {
					if err := invalidRange(lineNumber, value); err != nil {
						return nil, err
					}
					continue
				}
				for _, network := range networks {
					ipPrefixes = append(ipPrefixes, prefixString(network))
				}
			}
		}
		defaultRoute := false
		if v, ok := obj["default_route"]; ok {
			if defaultRoute, ok = v.(bool); !ok {
				return nil, fmt.Errorf("rule %s: default_route must be true or false", name)
			}
		}
		if len(domains) == 0 && len(keywords) == 0 && len(ipPrefixes) == 0 && !defaultRoute {
			if cfg.IgnoreListProblems && len(domainFiles)+len(rangeFiles) > 0 {
				log.Printf("rule %s is off until restart: its list files have nothing usable, so its names and addresses use the default route", name)
				continue
			}
			return nil, fmt.Errorf("domain route needs domains, domain_keywords, or a nonempty source file")
		}
		primaryVia := via4
		if primaryVia == "" {
			primaryVia = via6
		}
		mapping := Mapping{Enabled: true, Family: "inet", Table: "dns_gate", Set: name,
			Interface: iface, Via: primaryVia, Via6: "", FibTable: uint32(fib), Default: defaultRoute, DHCPGateway: dhcpGateway}
		if via4 != "" && via6 != "" {
			mapping.Via6 = via6
		}
		mappingKey := mapping.Key()
		if len(ipPrefixes) > 0 {
			set := ipRangePrefixes[mappingKey]
			if set == nil {
				set = map[string]struct{}{}
				ipRangePrefixes[mappingKey] = set
			}
			for _, p := range ipPrefixes {
				set[p] = struct{}{}
			}
		}
		pool4, pool6, err := parsePrefixList(obj["fakeip_range"])
		if err != nil {
			return nil, err
		}
		if fakeDNS && pool4 == "" && pool6 == "" {
			return nil, fmt.Errorf("fake_dns requires fakeip_range")
		}
		if pool4 != "" || pool6 != "" {
			if via4 != "" && pool4 == "" || via6 != "" && pool6 == "" {
				return nil, fmt.Errorf("fakeip_range requires an upstream DNS and a matching pool family")
			}
		}
		addPool := func(prefix, via string) error {
			if prefix == "" {
				return nil
			}
			if via == "" || upstream == nil || cfg.DNSUpstreamPolicy != "first" || cfg.OverlapPolicy != "first" {
				return fmt.Errorf("fakeip_range requires an upstream DNS and a matching pool family")
			}
			network, err := parsePrefixStrict(prefix)
			if err != nil {
				return err
			}
			route := Route{uint32(fib), prefix, via, iface}
			for other, entry := range pools {
				if network.Addr().BitLen() == other.Addr().BitLen() && prefixesOverlap(network, other) {
					if network != other || route != entry.Route || (entry.Upstream == nil) != (upstream == nil) ||
						(upstream != nil && *entry.Upstream != *upstream) {
						return fmt.Errorf("overlapping Fake-IP pools have different policies")
					}
				}
			}
			if _, exists := pools[network]; !exists {
				pools[network] = FakeIPPool{Route: route, Upstream: upstream, Mapping: mappingKey}
			}
			return nil
		}
		if err := addPool(pool4, via4); err != nil {
			return nil, err
		}
		if err := addPool(pool6, via6); err != nil {
			return nil, err
		}
		if pool4 != "" {
			mapping.FakeIP = pool4
		} else if pool6 != "" && via4 == "" {
			mapping.FakeIP = pool6
		}
		if pool6 != "" && via4 != "" {
			mapping.FakeIP6 = pool6
		}
		if v, ok := obj["tproxy_port"]; ok {
			n, err := asInt(v)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("tproxy_port must be between 1 and 65535")
			}
			if cfg.OverlapPolicy != "first" {
				return nil, fmt.Errorf("tproxy_port requires ordered reconciliation")
			}
			mapping.TProxyPort = n
			mapping.RealAddresses = !mapping.HasFakeIP() || len(ipPrefixes) > 0
		}
		if v, ok := obj["tproxy_interface"].(string); ok && v != "" {
			if !nameRe.MatchString(v) {
				return nil, fmt.Errorf("invalid tproxy_interface")
			}
			mapping.TProxyInterface = v
		}
		if mapping.TProxyInterface != "" && mapping.TProxyPort == 0 {
			return nil, fmt.Errorf("tproxy_interface requires tproxy_port")
		}
		if mapping.RealAddresses && mapping.TProxyInterface == "" {
			return nil, fmt.Errorf("real-address tproxy_port requires tproxy_interface")
		}
		if dhcpGateway && (!defaultRoute || len(domains) > 0 || len(keywords) > 0 || len(ipPrefixes) > 0 || obj["linux_exit"] != nil) {
			// Routes for rules are installed with their next hop; one that changes with the lease cannot be.
			return nil, fmt.Errorf("rule %s: dhcp_gateway is only for a rule that carries the default route and matches nothing", name)
		}
		if mapping.Default && (mapping.HasFakeIP() || mapping.TProxyPort != 0) {
			// A Fake-IP exit only takes its pool; real addresses sent there would miss the proxy.
			return nil, fmt.Errorf("rule %s: default_route needs an exit for real addresses, not a Fake-IP one", name)
		}
		if v, ok := obj["tproxy_address"]; ok && v != nil {
			addresses, err := parseTProxyAddress(v, mapping)
			if err != nil {
				return nil, err
			}
			mapping.TProxyAddress = addresses
		}
		var upstreamMark uint32
		if raw, ok := obj["linux_exit"]; ok {
			data, err := json.Marshal(raw)
			if err != nil {
				return nil, err
			}
			var exit LinuxExit
			decoder := json.NewDecoder(strings.NewReader(string(data)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&exit); err != nil {
				return nil, fmt.Errorf("linux_exit: %w", err)
			}
			mapping.LinuxExit = &exit
			if upstream != nil && !exit.DNSDirect {
				// Without a route of this family in the exit's table the query would use the main table.
				if mapping.ViaFor(viaFamily(upstream.Host)) == "" {
					return nil, fmt.Errorf("linux_exit DNS upstream %s needs a via of the same family, or dns_direct", upstream.Host)
				}
				upstreamMark = exit.Mark
			}
		}
		mappings = append(mappings, mapping)
		targets := []Target{{Mapping: mapping}}
		for _, rawDomain := range domains {
			domain := strings.ToLower(strings.TrimRight(rawDomain, "."))
			if err := checkDomain(rawDomain); err != nil {
				return nil, err
			}
			rules = append(rules, Rule{Pattern: domain, Targets: append([]Target{}, targets...), Upstream: upstream, UpstreamMark: upstreamMark, Match: "suffix"})
		}
		for _, rawKw := range keywords {
			keyword := strings.ToLower(strings.TrimSpace(rawKw))
			if keyword == "" || strings.ContainsAny(keyword, " \t\n") {
				return nil, fmt.Errorf("invalid domain keyword: %s", rawKw)
			}
			rules = append(rules, Rule{Pattern: keyword, Targets: append([]Target{}, targets...), Upstream: upstream, UpstreamMark: upstreamMark, Match: "contains"})
		}
	}
	// A rule with neither content nor default_route was refused above, so an empty list forwards DNS and diverts nothing.
	cfg.Mappings = mappings
	for i, m := range mappings {
		if !m.RealAddresses {
			continue
		}
		for _, other := range mappings[:i] {
			if !other.RealAddresses || other.TProxyInterface != m.TProxyInterface {
				continue
			}
			if other.TProxyPort != m.TProxyPort || fmt.Sprint(other.TProxyAddress) != fmt.Sprint(m.TProxyAddress) {
				return nil, fmt.Errorf("real-address TPROXY rules sharing %s must use the same listener", m.TProxyInterface)
			}
		}
	}
	if err := validateDefaultRoutes(mappings); err != nil {
		return nil, err
	}
	if err := validateLinuxExits(cfg); err != nil {
		return nil, err
	}
	cfg.FakeIPPools = pools
	cfg.IPRangePrefixes = ipRangePrefixes
	ttl := 604800
	if v, ok := doc["fakeip_ttl"]; ok {
		n, err := asInt(v)
		if err != nil || n < 1 || n > 2147483647 {
			return nil, fmt.Errorf("fakeip_ttl must be an integer between 1 and 2147483647")
		}
		ttl = n
	}
	cfg.FakeIPTTL = ttl
	return rules, nil
}

func RuleMatches(name, pattern, matchType string) bool {
	name = strings.ToLower(strings.TrimRight(name, "."))
	if matchType == "contains" {
		return strings.Contains(name, pattern)
	}
	return name == pattern || strings.HasSuffix(name, "."+pattern)
}

// parseTProxyAddress reads where a proxy listening on one address, such as 127.0.0.1, takes
// TPROXY traffic. Without it the kernel picks an address of the input interface, which
// only a proxy listening on every address accepts. Each pool then needs one of its family.
func parseTProxyAddress(v any, m Mapping) ([]netip.Addr, error) {
	var texts []any
	switch value := v.(type) {
	case string:
		texts = []any{value}
	case []any:
		texts = value
	default:
		return nil, fmt.Errorf("tproxy_address must be an address or a list of addresses")
	}
	if m.TProxyPort == 0 {
		return nil, fmt.Errorf("tproxy_address requires tproxy_port")
	}
	var out []netip.Addr
	has := map[bool]bool{}
	for _, item := range texts {
		text, _ := item.(string)
		addr, err := parseAddr(text)
		if err != nil {
			return nil, fmt.Errorf("invalid tproxy_address %v: leave it out for a proxy listening on every address", item)
		}
		if has[addr.Is6()] {
			return nil, fmt.Errorf("tproxy_address lists at most one IPv4 and one IPv6 address")
		}
		has[addr.Is6()] = true
		out = append(out, addr)
	}
	for _, pool := range m.EachFakeIP() {
		if prefix, err := parsePrefixStrict(pool); err == nil && !has[prefix.Addr().Is6()] {
			return nil, fmt.Errorf("tproxy_address has no address for the Fake-IP pool %s", pool)
		}
	}
	return out, nil
}
