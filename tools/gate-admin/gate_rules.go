package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gate "vpp.local/vpp-egress-gate"
)

// The admin service changes what Gate routes, for the management panel: which exit a rule
// uses and what its domain and address list files hold. It is a process of its own because applying a
// change restarts Gate, and something has to outlive that restart to bring the previous
// configuration back if the change is not confirmed. It uses Gate's own configuration
// checks, so it never accepts what Gate would refuse.
const (
	adminMaxBody       = 4 << 20
	adminDomainLimit   = 200
	adminReadyTimeout  = 30 * time.Second
	adminReadyProbe    = time.Second
	adminCommandLimit  = 2 * time.Minute
	adminLedgerTimeout = time.Second
	pendingFile        = "pending.json"
	exitsFile          = "exits.json"
)

var (
	listFileName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.domains$`)
	rangeFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.ranges$`)
	ruleNameRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// What a managed list file holds.
const (
	kindDomains = "domains"
	kindRanges  = "ranges"
)

var kindLabel = map[string]string{kindDomains: "域名表", kindRanges: "网段表"}

// Fields of a rule that say what it matches; everything else describes where it goes.
// default_route is neither, and is listed so that it stays with the rule and never travels
// with an exit's attributes to another rule. settleDefault decides where it is.
var ruleSourceFields = map[string]bool{
	"name": true, "domain_files": true, "domains": true, "domain_keywords": true, "ip_range_files": true,
	defaultRouteField: true,
}

// defaultRouteField marks the rules whose exit carries the default route. An exit no rule
// uses gets a rule of its own for it, with nothing to match: a carrier.
const defaultRouteField = "default_route"

// dhcpGatewayField marks an exit whose IPv4 next hop Gate takes from VPP's DHCP lease.
const dhcpGatewayField = "dhcp_gateway"

// exitNameField names the exit a rule uses when its interface carries more than one. Gate
// itself routes by interface and next hop and only accepts the field.
const exitNameField = "exit"

// AdminOptions configures the admin service.
type AdminOptions struct {
	ProxySocket string
	ListDir     string
	Socket      string
	Config      string
	Unit        string
	StateDir    string
	Confirm     time.Duration
	// ExitsFile lists further exits, published by the program that owns those interfaces.
	ExitsFile string
	// CustomExits holds the exits set by hand.
	CustomExits string
}

// adminSystem is what applying a change does to the machine.
type adminSystem interface {
	check() error                // validate the configuration on disk without changing anything
	sync() error                 // regenerate what Gate runs from the configuration on disk
	restart() error              // restart Gate
	reload() (bool, error)       // reload collections; reports whether Gate restarted
	ready() error                // wait until Gate answers DNS
	stop() error                 // stop Gate
	flush() error                // undo what a stopped Gate did at run time, with its leases
	start() error                // start Gate
	ledger() (gateLedger, error) // the routes Gate has installed now, and its default route
}

// gateLedger is what the running Gate says about its routes.
type gateLedger struct {
	Owned   []adminRoute             `json:"owned"`
	Default *gate.DefaultRouteStatus `json:"default_route"` // nil from a Gate that does not report it
}

// adminRoute is one route in Gate's ledger.
type adminRoute struct {
	Table     uint32 `json:"table"`
	Prefix    string `json:"prefix"`
	Via       string `json:"via"`
	Interface string `json:"interface"`
}

// AdminExit is a place a rule group can be sent to.
type AdminExit struct {
	TProxyPort int      `json:"tproxy_port,omitempty"`
	Pools      []string `json:"fakeip_range,omitempty"`
	Name       string   `json:"name"`
	Interface  string   `json:"interface,omitempty"` // a VPP exit's interface, which several exits may share
	Families   []int    `json:"families"`
	DNS        string   `json:"dns"` // what a rule sent to this exit asks by default
	Via4       string   `json:"via4"`
	Via6       string   `json:"via6"`
	DHCP       bool     `json:"dhcp"` // the IPv4 next hop is the DHCP lease's router
	// Rules tells whether rules can use it; an exit on DHCP carries only the default route.
	Rules bool `json:"rules"`
	// Custom is set by hand; Editable means its next hops can be set here at all.
	Custom   bool `json:"custom"`
	Editable bool `json:"editable"`
}

// AdminDefault is what happens to everything no rule matches.
type AdminDefault struct {
	DNS string `json:"dns"`
	// Exit carries the default route; empty means the system's routes decide.
	Exit string `json:"exit"`
	// Options are the exits that can carry it: those for real addresses, not Fake-IP ones.
	Options []string `json:"options"`
	// Status is what Gate reports, nil while it cannot be asked.
	Status *gate.DefaultRouteStatus `json:"status"`
}

// AdminGroup is the rules sharing one set of domains: usually an IPv4 and an IPv6 rule.
type AdminGroup struct {
	ID       string   `json:"id"`
	Rules    []string `json:"rules"`
	Families []int    `json:"families"`
	Exit     string   `json:"exit"`
	Options  []string `json:"options"`
	Locked   string   `json:"locked"`
	DNS      string   `json:"dns"`
	// OptionDNS is the DNS each option comes with, as a Fake-IP exit's DNS is part of it.
	OptionDNS     map[string]string `json:"option_dns"`
	Files         []string          `json:"files"`
	Domains       int               `json:"domains"`
	Keywords      int               `json:"keywords"`
	KeywordValues []string          `json:"keyword_values"`
	Ranges        int               `json:"ranges"`
	RangeFiles    []string          `json:"range_files"`
}

// AdminFile is a domain or address list file. Domains counts its entries of either kind.
type AdminFile struct {
	Path    string   `json:"path"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Domains int      `json:"domains"`
	UsedBy  []string `json:"used_by"`
	Problem string   `json:"problem"`
}

type adminBackup struct {
	Path    string `json:"path"`
	Backup  string `json:"backup"`
	Existed bool   `json:"existed"`
}

// AdminPending is an applied change waiting for confirmation.
type AdminPending struct {
	Reload      bool          `json:"reload,omitempty"`
	ID          string        `json:"id"`
	Description string        `json:"description"`
	User        string        `json:"user"`
	Deadline    time.Time     `json:"deadline"`
	Files       []adminBackup `json:"files"`
	// Remove lists files to delete once the change is confirmed: a renamed list's old name,
	// kept until then so that a rollback finds it in place.
	Remove []string `json:"remove,omitempty"`
}

// AdminResult is how the last change ended.
type AdminResult struct {
	Description string    `json:"description"`
	Outcome     string    `json:"outcome"`
	Detail      string    `json:"detail"`
	OutageMs    int64     `json:"outage_ms"`
	Time        time.Time `json:"time"`
}

// AdminExitRoutes counts the routes through one exit.
type AdminExitRoutes struct {
	Name   string `json:"name"`
	Routes int    `json:"routes"`
}

// AdminRoutes counts the routes Gate has installed in VPP.
type AdminRoutes struct {
	Total   int               `json:"total"`
	Static  int               `json:"static"`  // from address lists and Fake-IP pools
	Learned int               `json:"learned"` // from DNS answers
	Exits   []AdminExitRoutes `json:"exits"`
}

// AdminState is what the panel shows.
type AdminState struct {
	Groups           []AdminGroup  `json:"groups"`
	Exits            []AdminExit   `json:"exits"`
	Default          AdminDefault  `json:"default"`
	Files            []AdminFile   `json:"files"`
	Routes           *AdminRoutes  `json:"routes"` // nil while Gate cannot be asked
	Pending          *AdminPending `json:"pending"`
	SecondsRemaining float64       `json:"seconds_remaining"`
	Last             *AdminResult  `json:"last"`
}

// stringList accepts the original single-string form as well as the multi-select array form
// used by the panel when adding a rule.
type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*s = nil
	if one != "" {
		*s = stringList{one}
	}
	return nil
}

// Admin applies changes one at a time.
type Admin struct {
	opts AdminOptions
	sys  adminSystem
	now  func() time.Time

	mu      sync.Mutex
	pending *AdminPending
	last    *AdminResult
	timer   *time.Timer
	nextID  int
	known   []map[string]any // every exit seen in a rule, so one nobody uses stays selectable
}

// NewAdmin finishes what a previous run left: an unconfirmed change is rolled back, or
// keeps its deadline if there is still time.
func NewAdmin(opts AdminOptions, sys adminSystem) (*Admin, error) {
	if opts.ListDir == "" {
		opts.ListDir = defaultListDir
	}
	a := &Admin{opts: opts, sys: sys, now: time.Now}
	if err := os.MkdirAll(opts.StateDir, 0o700); err != nil {
		return nil, err
	}
	if data, err := os.ReadFile(filepath.Join(opts.StateDir, exitsFile)); err == nil {
		if err := json.Unmarshal(data, &a.known); err != nil {
			return nil, fmt.Errorf("%s: %w", exitsFile, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if loaded, err := a.loadRules(); err == nil {
		a.learnExits(loaded.rules)
	}
	data, err := os.ReadFile(filepath.Join(opts.StateDir, pendingFile))
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	var pending AdminPending
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil, fmt.Errorf("%s: %w", pendingFile, err)
	}
	a.pending = &pending
	if pending.Deadline.IsZero() || !a.now().Before(pending.Deadline) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.rollbackLocked("the admin service restarted before the change was confirmed")
		return a, nil
	}
	a.arm()
	return a, nil
}

func (a *Admin) arm() {
	if a.timer != nil {
		a.timer.Stop()
	}
	a.timer = time.AfterFunc(a.pending.Deadline.Sub(a.now()), a.expire)
}

func (a *Admin) expire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending != nil && !a.pending.Deadline.IsZero() && !a.now().Before(a.pending.Deadline) {
		a.rollbackLocked("not confirmed in time")
	}
}

type adminRules struct {
	// defaultExit is where the default route should be once a change is made: where it was,
	// unless the change is choosing it.
	defaultExit string
	path        string
	doc         map[string]any
	rules       []map[string]any
	// custom is the exits set by hand as the change leaves them, when it changes them.
	custom    []customExit
	customSet bool
}

func (a *Admin) loadRules() (*adminRules, error) {
	entry, err := readJSONObject(a.opts.Config)
	if err != nil {
		return nil, err
	}
	loaded := &adminRules{path: a.opts.Config, doc: entry}
	if path, doc, err := linkedJSON(entry, "domain_routes_file"); err != nil {
		return nil, err
	} else if path != "" {
		loaded.path, loaded.doc = path, doc
	}
	raw, ok := loaded.doc["routes"].([]any)
	if !ok {
		return nil, fmt.Errorf("%s has no routes", loaded.path)
	}
	for _, item := range raw {
		rule, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: a route is not an object", loaded.path)
		}
		loaded.rules = append(loaded.rules, rule)
	}
	return loaded, nil
}

// ruleName is a rule's name. Gate does not require one, and a rule without it is named
// here as Gate's own install names one: by its Linux exit, else by its first domain file.
// Every lookup goes through this, so the rule is found again by the same name.
func ruleName(rule map[string]any) string {
	if name, _ := rule["name"].(string); name != "" {
		return name
	}
	if exit := linuxExit(rule); exit != "" {
		return strings.ReplaceAll(exit, ".", "_")
	}
	if files, ok := rule["domain_files"].([]any); ok && len(files) > 0 {
		if file, _ := files[0].(string); file != "" {
			return strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
		}
	}
	return ""
}

// linuxExit is the Linux interface a rule leaves by. In Gate's configuration linux_exit is an
// object; an older form gave the interface alone.
func linuxExit(rule map[string]any) string {
	switch exit := rule["linux_exit"].(type) {
	case string:
		return exit
	case map[string]any:
		name, _ := exit["interface"].(string)
		return name
	}
	return ""
}

// ruleExit names where a rule goes: its VPP interface, or for a rule whose device Gate
// generates, the Linux interface it leaves by, or else (a Fake-IP proxy) the rule itself.
func ruleExit(rule map[string]any) string {
	if name, _ := rule["tproxy_exit"].(string); name != "" {
		return name
	}
	if name, _ := rule[exitNameField].(string); name != "" && rule["interface"] != nil {
		return name
	}
	if name, ok := rule["interface"].(string); ok && name != "" {
		return name
	}
	if exit := linuxExit(rule); exit != "" {
		return exit
	}
	if rule["fakeip_range"] != nil || rule["tproxy_port"] != nil {
		return ruleName(rule)
	}
	return ""
}

// ruleFamilies returns the address families a rule routes: from its next hops, or for a
// Linux exit whose next hop is generated, from whether it asks for IPv6 or Gate gave it IPv6.
func ruleFamilies(rule map[string]any) []int {
	if rule["tproxy_exit"] != nil && rule["fakeip_range"] == nil {
		if ipv6, _ := rule["ipv6"].(bool); ipv6 {
			return []int{4, 6}
		}
		return []int{4}
	}
	var values []any
	switch via := rule["via"].(type) {
	case string:
		values = []any{via}
	case []any:
		values = via
	}
	seen := map[int]bool{}
	for _, value := range values {
		text, _ := value.(string)
		if address, err := netip.ParseAddr(text); err == nil {
			if address.Is4() {
				seen[4] = true
			} else {
				seen[6] = true
			}
		}
	}
	if dhcp, _ := rule[dhcpGatewayField].(bool); dhcp {
		seen[4] = true
	}
	if len(values) == 0 && rule["linux_exit"] != nil {
		seen[4] = true
		// Without ipv6 Gate decides, from whether the exit has IPv6.
		if ipv6, _ := rule["ipv6"].(bool); ipv6 || (rule["ipv6"] == nil && generatedIPv6(rule)) {
			seen[6] = true
		}
	}
	// A Fake-IP rule whose device Gate generates has no next hop; its pools say the families.
	if len(values) == 0 && rule["linux_exit"] == nil && rule[dhcpGatewayField] == nil {
		var pools []any
		switch pool := rule["fakeip_range"].(type) {
		case string:
			pools = []any{pool}
		case []any:
			pools = pool
		}
		for _, value := range pools {
			text, _ := value.(string)
			if prefix, err := netip.ParsePrefix(text); err == nil {
				if prefix.Addr().Is4() {
					seen[4] = true
				} else {
					seen[6] = true
				}
			}
		}
	}
	families := make([]int, 0, 2)
	for family := range seen {
		families = append(families, family)
	}
	sort.Ints(families)
	return families
}

func containsFamilies(have, want []int) bool {
	for _, family := range want {
		found := false
		for _, one := range have {
			found = found || one == family
		}
		if !found {
			return false
		}
	}
	return len(want) > 0
}

// ruleSource identifies what a rule matches, for grouping. The IPv4 and IPv6 rules of one set
// of domains stay a group although their address lists, one per family, differ.
func ruleSource(rule map[string]any) string {
	source := []any{rule["domain_files"], rule["domains"], rule["domain_keywords"]}
	if source[0] == nil && source[1] == nil && source[2] == nil {
		source = append(source, rule["ip_range_files"])
	}
	data, _ := json.Marshal(source)
	return string(data)
}

// ruleAttributes returns a copy of what says where a rule goes.
func ruleAttributes(rule map[string]any) map[string]any {
	attributes := map[string]any{}
	for key, value := range rule {
		if !ruleSourceFields[key] {
			attributes[key] = value
		}
	}
	return attributes
}

// findProfile returns how to reach the exit for the families wanted.
func findProfile(profiles []map[string]any, exit string, families []int) map[string]any {
	for _, profile := range profiles {
		if ruleExit(profile) == exit && containsFamilies(ruleFamilies(profile), families) {
			return profile
		}
	}
	return nil
}

// exitProfile is how a rule reaches an exit. Ranges go anywhere: a TPROXY listener takes real
// addresses whatever the rule's DNS.
func exitProfile(profiles []map[string]any, exit string, rule map[string]any) map[string]any {
	return findProfile(profiles, exit, ruleFamilies(rule))
}

// parseRange reads one line of an address list as Gate does: a prefix, a single address, or
// first-last, with an optional comment. The default route is refused.
func parseRange(line string) ([]netip.Prefix, error) {
	value := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
	var networks []netip.Prefix
	if first, last, isRange := strings.Cut(value, "-"); isRange {
		start, err1 := netip.ParseAddr(strings.TrimSpace(first))
		end, err2 := netip.ParseAddr(strings.TrimSpace(last))
		if err1 != nil || err2 != nil || start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
			return nil, fmt.Errorf("invalid address range: %q", value)
		}
		var err error
		if networks, err = summarizeRange(start, end); err != nil {
			return nil, fmt.Errorf("invalid address range: %q", value)
		}
	} else {
		network, err := parsePrefixStrict(value)
		if err != nil {
			return nil, fmt.Errorf("invalid address or prefix: %q", value)
		}
		networks = []netip.Prefix{network}
	}
	for _, network := range networks {
		if network.Bits() == 0 {
			return nil, fmt.Errorf("a default route cannot be a static range: %q", value)
		}
	}
	return networks, nil
}

// normalizeEntry returns the form a list line is stored and compared in.
func normalizeEntry(kind, line string) (string, error) {
	if kind == kindRanges {
		value := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		networks, err := parseRange(value)
		if err != nil {
			return "", err
		}
		if first, last, isRange := strings.Cut(value, "-"); isRange {
			start, _ := netip.ParseAddr(strings.TrimSpace(first))
			end, _ := netip.ParseAddr(strings.TrimSpace(last))
			return start.String() + "-" + end.String(), nil
		}
		return prefixString(networks[0]), nil
	}
	domain := normalizeDomain(line)
	if domain == "" || checkDomain(domain) != nil {
		return "", fmt.Errorf("invalid domain: %q", line)
	}
	return domain, nil
}

// entryKey identifies a line that is already in a file, which may not be valid.
func entryKey(kind, line string) string {
	if normal, err := normalizeEntry(kind, line); err == nil {
		return normal
	}
	if kind == kindDomains {
		return normalizeDomain(line)
	}
	return strings.TrimSpace(line)
}

// rangePrefixes reads a rule's static ranges, leaving out lines Gate would not install.
// Content in pending replaces what a file holds on disk.
func rangePrefixes(rule map[string]any, pending map[string][]byte) []netip.Prefix {
	files, err := listFiles(rule, "ip_range_files")
	if err != nil {
		return nil
	}
	var prefixes []netip.Prefix
	for _, file := range files {
		var entries []string
		if data, ok := pending[file]; ok {
			entries = parseEntries(data)
		} else if entries, err = listEntries(file); err != nil {
			continue
		}
		for _, entry := range entries {
			if networks, err := parseRange(entry); err == nil {
				prefixes = append(prefixes, networks...)
			}
		}
	}
	return prefixes
}

func samePath(a, b map[string]any) bool {
	tableA, _ := asInt(a["fib_table"])
	tableB, _ := asInt(b["fib_table"])
	if ruleExit(a) != ruleExit(b) || tableA != tableB {
		return false
	}
	for _, viaA := range anyStrings(a["via"]) {
		for _, viaB := range anyStrings(b["via"]) {
			if viaA == viaB {
				return true
			}
		}
	}
	return false
}

// poolClash finds a range that cannot use profile because a rule outside members has a
// Fake-IP pool overlapping it: Gate refuses to start unless such a range takes the pool's own
// path, and the configuration check before a restart does not see that.
func poolClash(rules []map[string]any, members []int, ranges []netip.Prefix, profile map[string]any) (network, owner string) {
	moving := make(map[int]bool, len(members))
	for _, index := range members {
		moving[index] = true
	}
	for index, other := range rules {
		if moving[index] || samePath(profile, other) {
			continue
		}
		for _, text := range anyStrings(other["fakeip_range"]) {
			pool, err := parsePrefixStrict(text)
			if err != nil {
				continue
			}
			for _, candidate := range ranges {
				if candidate.Addr().BitLen() == pool.Addr().BitLen() && prefixesOverlap(candidate, pool) {
					return prefixString(candidate), ruleName(other)
				}
			}
		}
	}
	return "", ""
}

// checkRanges refuses static ranges the rules could not carry, before anything is restarted.
func checkRanges(routes []any, pending map[string][]byte) error {
	rules := make([]map[string]any, 0, len(routes))
	for _, item := range routes {
		if rule, ok := item.(map[string]any); ok {
			rules = append(rules, rule)
		}
	}
	for _, rule := range rules {
		ranges := rangePrefixes(rule, pending)
		families := ruleFamilies(rule)
		for _, network := range ranges {
			family := 4
			if network.Addr().Is6() {
				family = 6
			}
			if len(families) > 0 && !containsFamilies(families, []int{family}) {
				return fmt.Errorf("网段 %s 是 IPv%d，规则 %s 没有这个地址族的下一跳", prefixString(network), family, ruleName(rule))
			}
		}
		if network, owner := poolClash(rules, nil, ranges, rule); network != "" {
			return fmt.Errorf("网段 %s 与规则 %s 的 Fake-IP 地址池重叠，规则 %s 走的是另一个出口", network, owner, ruleName(rule))
		}
	}
	return nil
}

// learnExits remembers the exits the rules use. Exits are only described by the rules that
// use them, so without this, moving the last rule off an exit would make it unreachable.
func (a *Admin) learnExits(rules []map[string]any) {
	seen := make(map[string]bool, len(a.known))
	for _, profile := range a.known {
		data, _ := json.Marshal(profile)
		seen[string(data)] = true
	}
	changed := false
	for _, rule := range rules {
		if ruleExit(rule) == "" || len(ruleFamilies(rule)) == 0 {
			continue
		}
		attributes := ruleAttributes(rule)
		data, _ := json.Marshal(attributes)
		if !seen[string(data)] {
			seen[string(data)] = true
			a.known = append(a.known, attributes)
			changed = true
		}
	}
	if !changed {
		return
	}
	data, err := json.Marshal(a.known)
	if err == nil {
		err = writeFileAtomic(filepath.Join(a.opts.StateDir, exitsFile), data, 0o600)
	}
	if err != nil {
		log.Printf("saving the known exits: %v", err)
	}
}

// profiles lists how each exit can be reached by a rule, what the rules say now taking
// precedence. An exit on DHCP is left out: a rule's routes need a next hop that stays.
func (a *Admin) profiles(rules []map[string]any) []map[string]any {
	all := a.allProfiles(rules)
	kept := all[:0]
	for _, profile := range all {
		if profile[dhcpGatewayField] == nil {
			kept = append(kept, profile)
		}
	}
	return kept
}

// allProfiles is profiles with the exits on DHCP, which can carry the default route.
func (a *Admin) allProfiles(rules []map[string]any) []map[string]any {
	profiles := a.proxyExits()
	for _, rule := range rules {
		profiles = append(profiles, ruleAttributes(rule))
	}
	// An exit set by hand stands for its interface: what was learned or offered for it before
	// would otherwise fill in a family it was set without.
	custom, err := a.customExits()
	if err != nil {
		log.Printf("custom exits: %v", err)
	}
	set := map[string]bool{}
	for _, exit := range custom {
		set[exit.key()] = true
		profiles = append(profiles, exit.profile())
	}
	for _, profile := range append(append([]map[string]any{}, a.known...), a.offeredExits()...) {
		// A named exit exists only as set by hand, or while a rule still uses it.
		if named, _ := profile[exitNameField].(string); named != "" && !set[named] {
			continue
		}
		if !set[ruleExit(profile)] || !fixedExit(profile) {
			profiles = append(profiles, profile)
		}
	}
	return profiles
}

// parseDNS reads "IP" or "IP:port" into what the configuration holds. Empty means none.
func parseDNS(text string) ([]any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	host, port := text, 53
	if _, err := netip.ParseAddr(text); err != nil {
		name, portText, err := net.SplitHostPort(text)
		if err != nil {
			return nil, fmt.Errorf("DNS %q 要写成 IP 或 IP:端口", text)
		}
		host = name
		if port, err = strconv.Atoi(portText); err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("DNS 端口 %q 不对", portText)
		}
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return nil, fmt.Errorf("DNS %q 要写成 IP 或 IP:端口", text)
	}
	return []any{address.Unmap().String(), float64(port)}, nil
}

func dnsLabel(upstream []any) string {
	if upstream == nil {
		return "默认 DNS"
	}
	return dnsTextOf(upstream)
}

// dnsTextOf gives the form parseDNS reads, leaving out the usual port.
func dnsTextOf(upstream []any) string {
	if len(upstream) != 2 {
		return ""
	}
	host, _ := upstream[0].(string)
	port, err := asInt(upstream[1])
	if err != nil {
		return ""
	}
	if port == 53 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

var ruleDNSFields = []string{"dns_upstream", "dns", "fake_dns"}

func dnsText(rule map[string]any) string {
	for _, key := range ruleDNSFields {
		if value, ok := rule[key].([]any); ok {
			return dnsTextOf(value)
		}
	}
	return ""
}

// exitDNS is the DNS a rule sent to the exit starts with. Only a Fake-IP exit has one: its DNS
// hands out the pool's addresses. Any other exit starts with the default DNS, whatever DNS the
// rules already on it chose.
func exitDNS(profiles []map[string]any, exit string) string {
	for _, profile := range profiles {
		if ruleExit(profile) == exit && profile["fakeip_range"] != nil {
			return dnsText(profile)
		}
	}
	return ""
}

// setRuleDNS sets the rule's DNS; none is the default DNS. Whether that makes the rule Fake-IP is
// settled on saving, by applyFakeIP.
func setRuleDNS(rule map[string]any, upstream []any) error {
	for _, field := range ruleDNSFields {
		delete(rule, field)
	}
	if upstream != nil {
		rule["dns_upstream"] = upstream
	}
	return nil
}

// SetDefaultDNS changes where queries matching no rule go.
func (a *Admin) SetDefaultDNS(dns, user string) (*AdminState, error) {
	upstream, err := parseDNS(dns)
	if err != nil {
		return nil, err
	}
	if upstream == nil {
		return nil, errors.New("默认 DNS 不能为空")
	}
	return a.change("把默认 DNS 改成 "+dnsTextOf(upstream), user, func(loaded *adminRules) (map[string][]byte, error) {
		entry, err := readJSONObject(a.opts.Config)
		if err != nil {
			return nil, err
		}
		if current, ok := entry["upstream"].([]any); ok && dnsTextOf(current) == dnsTextOf(upstream) {
			return nil, errors.New("DNS 没有变化")
		}
		entry["upstream"] = upstream
		if loaded.path == a.opts.Config {
			loaded.doc = entry
		}
		data, err := renderRules(entry)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{a.opts.Config: data}, nil
	})
}

var offeredInterface = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// offeredExits reads the exits other programs offer, from each file in ExitsFile (separated
// by commas). Without a file there are simply fewer choices, so nothing here is an error for
// the caller. An exit on DHCP has no next hop to write down: Gate reads it from the lease.
func (a *Admin) offeredExits() []map[string]any {
	var profiles []map[string]any
	for _, path := range strings.Split(a.opts.ExitsFile, ",") {
		if path = strings.TrimSpace(path); path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		var offered []struct {
			Interface string `json:"interface"`
			Via       string `json:"via"`
			DHCP      bool   `json:"dhcp"`
		}
		if err == nil {
			err = json.Unmarshal(data, &offered)
		}
		if err != nil {
			log.Printf("offered exits: %s: %v", path, err)
			continue
		}
		for _, exit := range offered {
			if !offeredInterface.MatchString(exit.Interface) {
				log.Printf("offered exits: ignoring interface %q", exit.Interface)
				continue
			}
			if exit.DHCP && exit.Via == "" {
				profiles = append(profiles, map[string]any{"interface": exit.Interface, dhcpGatewayField: true, "fib_table": float64(0)})
				continue
			}
			if _, err := netip.ParseAddr(exit.Via); err != nil {
				log.Printf("offered exits: ignoring %q via %q", exit.Interface, exit.Via)
				continue
			}
			profiles = append(profiles, map[string]any{"interface": exit.Interface, "via": exit.Via, "fib_table": float64(0)})
		}
	}
	return profiles
}

// groupedRules returns rule indexes grouped by what they match, in file order.
func groupedRules(rules []map[string]any) [][]int {
	var order []string
	groups := map[string][]int{}
	for index, rule := range rules {
		key := ruleSource(rule)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], index)
	}
	result := make([][]int, 0, len(order))
	for _, key := range order {
		result = append(result, groups[key])
	}
	return result
}

// visibleGroups are the groups the panel lists: every group but the default route's carriers.
func visibleGroups(rules []map[string]any) [][]int {
	groups := groupedRules(rules)
	kept := groups[:0]
	for _, members := range groups {
		if !isCarrier(rules[members[0]]) {
			kept = append(kept, members)
		}
	}
	return kept
}

// isCarrier tells a rule that exists only to carry the default route.
func isCarrier(rule map[string]any) bool {
	carries, _ := rule[defaultRouteField].(bool)
	if !carries {
		return false
	}
	for key := range ruleSourceFields {
		if key != "name" && key != defaultRouteField && rule[key] != nil {
			return false
		}
	}
	return true
}

// defaultExitOf names the exit carrying the default route, or empty for the system's routes.
func defaultExitOf(rules []map[string]any) string {
	for _, rule := range rules {
		if carries, _ := rule[defaultRouteField].(bool); carries {
			return ruleExit(rule)
		}
	}
	return ""
}

// defaultProfiles keeps the exits that can carry the default route. A Fake-IP exit takes only
// its pool, so real addresses sent there would miss the proxy.
func defaultProfiles(profiles []map[string]any) []map[string]any {
	kept := make([]map[string]any, 0, len(profiles))
	for _, profile := range profiles {
		if profile["tproxy_port"] == nil && profile["fakeip_range"] == nil && ruleExit(profile) != "" && len(ruleFamilies(profile)) > 0 {
			kept = append(kept, profile)
		}
	}
	return kept
}

// settleDefault puts the default route on the exit in loaded.defaultExit. It goes on the rules
// already using that exit, at most one path per family, as Gate allows; with none, a carrier
// rule is added for it. Carriers no longer needed go. Doing this after every change keeps the
// default route where it was when a rule moves away from its exit or is deleted, and gives a
// new rule on the exit the default route in place of the carrier, which on a Linux exit would
// otherwise ask for the same device twice.
func settleDefault(loaded *adminRules, profiles []map[string]any) error {
	routes, _ := loaded.doc["routes"].([]any)
	kept := make([]any, 0, len(routes))
	var rules []map[string]any
	for _, item := range routes {
		rule, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		if isCarrier(rule) {
			continue
		}
		delete(rule, defaultRouteField)
		kept = append(kept, rule)
		rules = append(rules, rule)
	}
	loaded.doc["routes"] = kept
	exit := loaded.defaultExit
	if exit == "" {
		return nil
	}
	usable := func(profile map[string]any) bool { return len(defaultProfiles([]map[string]any{profile})) == 1 }
	chosen := map[int]bool{}
	for _, rule := range rules {
		if ruleExit(rule) != exit || !usable(rule) {
			continue
		}
		fresh := false
		for _, family := range ruleFamilies(rule) {
			if !chosen[family] {
				chosen[family], fresh = true, true
			}
		}
		if fresh {
			rule[defaultRouteField] = true
		}
	}
	if len(chosen) > 0 {
		return nil
	}
	candidates := defaultProfiles(profiles)
	var carriers []map[string]any
	if profile := findProfile(candidates, exit, []int{4, 6}); profile != nil {
		carriers = append(carriers, profile)
	} else {
		for _, family := range []int{4, 6} {
			if profile := findProfile(candidates, exit, []int{family}); profile != nil {
				carriers = append(carriers, profile)
			}
		}
	}
	if len(carriers) == 0 {
		return fmt.Errorf("出口 %s 不能作为默认出口", exit)
	}
	names := map[string]bool{}
	for _, rule := range rules {
		names[ruleName(rule)] = true
	}
	for _, profile := range carriers {
		name := "default"
		for n := 2; names[name]; n++ {
			name = fmt.Sprintf("default%d", n)
		}
		names[name] = true
		carrier := map[string]any{"name": name, defaultRouteField: true}
		for key, value := range profile {
			if key != defaultRouteField && key != "dns_upstream" && key != "dns" && key != "fake_dns" {
				carrier[key] = value
			}
		}
		kept = append(kept, carrier)
	}
	loaded.doc["routes"] = kept
	return nil
}

// SetDefaultExit chooses the exit for everything no rule matches; empty goes back to the
// system's routes.
func (a *Admin) SetDefaultExit(exit, user string) (*AdminState, error) {
	description := "默认路由改走出口 " + exit
	if exit == "" {
		description = "默认路由改回系统路由表"
	}
	return a.change(description, user, func(loaded *adminRules) (map[string][]byte, error) {
		if exit == loaded.defaultExit {
			return nil, errors.New("默认出口没有变化")
		}
		if exit != "" {
			found := false
			for _, profile := range defaultProfiles(a.allProfiles(loaded.rules)) {
				found = found || ruleExit(profile) == exit
			}
			if !found {
				return nil, fmt.Errorf("出口 %s 不能作为默认出口：没有这个出口，或者它是 Fake-IP 出口", exit)
			}
		}
		loaded.defaultExit = exit
		data, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{loaded.path: data}, nil
	})
}

func listEntries(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseEntries(data), nil
}

func parseEntries(data []byte) []string {
	var entries []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			entries = append(entries, line)
		}
	}
	return entries
}

func anyStrings(value any) []string {
	var out []string
	switch typed := value.(type) {
	case []string:
		out = append(out, typed...)
	case string:
		out = append(out, typed)
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
	}
	return out
}

func describeGroup(rules, profiles []map[string]any, members []int) AdminGroup {
	first := rules[members[0]]
	group := AdminGroup{ID: ruleName(first), Options: []string{}, Rules: []string{}, Files: []string{}, RangeFiles: []string{}, DNS: dnsText(first), OptionDNS: map[string]string{}}
	familySeen := map[int]bool{}
	exits := map[string]bool{}
	for _, index := range members {
		rule := rules[index]
		group.Rules = append(group.Rules, ruleName(rule))
		exits[ruleExit(rule)] = true
		for _, family := range ruleFamilies(rule) {
			familySeen[family] = true
		}
		if len(ruleFamilies(rule)) == 0 {
			group.Locked = "无法判断这条规则的地址族"
		}
	}
	for family := range familySeen {
		group.Families = append(group.Families, family)
	}
	sort.Ints(group.Families)
	if len(exits) == 1 {
		group.Exit = ruleExit(first)
	} else {
		group.Exit = strings.Join(sortedStrings(exits), "、")
	}
	if group.Locked == "" {
		ranges := make(map[int][]netip.Prefix, len(members))
		for _, index := range members {
			ranges[index] = rangePrefixes(rules[index], nil)
		}
		clash := ""
		seen := map[string]bool{}
		for _, candidate := range profiles {
			exit := ruleExit(candidate)
			if exit == "" || seen[exit] || (len(exits) == 1 && exits[exit]) {
				continue
			}
			seen[exit] = true
			usable := true
			for _, index := range members {
				profile := exitProfile(profiles, exit, rules[index])
				if profile == nil {
					usable = false
				} else if network, owner := poolClash(rules, members, ranges[index], profile); network != "" {
					usable = false
					if clash == "" {
						clash = fmt.Sprintf("静态网段 %s 与规则 %s 的 Fake-IP 地址池重叠，从网段文件中去掉后才能切换出口", network, owner)
					}
				}
			}
			if usable {
				group.Options = append(group.Options, exit)
				group.OptionDNS[exit] = dnsText(exitProfile(profiles, exit, first))
			}
		}
		if len(group.Options) == 0 {
			group.Locked = clash
		}
	}
	group.Keywords = len(anyStrings(first["domain_keywords"]))
	group.KeywordValues = anyStrings(first["domain_keywords"])
	group.Domains = len(anyStrings(first["domains"]))
	if files, err := listFiles(first, "domain_files"); err == nil {
		group.Files = append(group.Files, files...)
		for _, file := range files {
			if entries, err := listEntries(file); err == nil {
				group.Domains += len(entries)
			}
		}
	}
	counted := map[string]bool{}
	for _, index := range members {
		files, err := listFiles(rules[index], "ip_range_files")
		if err != nil {
			continue
		}
		for _, file := range files {
			if !counted[file] {
				counted[file] = true
				group.RangeFiles = append(group.RangeFiles, file)
				if entries, err := listEntries(file); err == nil {
					group.Ranges += len(entries)
				}
			}
		}
	}
	return group
}

func sortedStrings(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// ruleFiles maps each list file in use to the rules using it. Only these files can be read
// or changed through the admin service, so a request cannot name any other path.
func ruleFiles(rules []map[string]any) (map[string][]string, error) {
	files := map[string][]string{}
	for _, rule := range rules {
		for _, key := range []string{"domain_files", "ip_range_files"} {
			paths, err := listFiles(rule, key)
			if err != nil {
				return nil, err
			}
			for _, path := range paths {
				files[path] = append(files[path], ruleName(rule))
			}
		}
	}
	return files, nil
}

// listKind says what a managed file holds: its name says, or the rules that use it.
func listKind(path string, rules []map[string]any) string {
	if strings.HasSuffix(path, ".ranges") {
		return kindRanges
	}
	for _, rule := range rules {
		if paths, err := listFiles(rule, "ip_range_files"); err == nil && slices.Contains(paths, path) {
			return kindRanges
		}
	}
	return kindDomains
}

// State returns the current rules, their files and any change in progress.
func (a *Admin) State() (*AdminState, error) {
	// Before the lock: Gate may be restarting, and a change in progress holds the lock.
	ledger, ledgerErr := a.sys.ledger()
	installed := ledger.Owned
	a.mu.Lock()
	defer a.mu.Unlock()
	loaded, err := a.loadRules()
	if err != nil {
		return nil, err
	}
	state := &AdminState{Groups: []AdminGroup{}, Exits: []AdminExit{}, Files: []AdminFile{}, Pending: a.pending, Last: a.last}
	if entry, err := readJSONObject(a.opts.Config); err == nil {
		if upstream, ok := entry["upstream"].([]any); ok {
			state.Default.DNS = dnsTextOf(upstream)
		}
	}
	a.learnExits(loaded.rules)
	profiles := a.profiles(loaded.rules)
	for _, members := range visibleGroups(loaded.rules) {
		state.Groups = append(state.Groups, describeGroup(loaded.rules, profiles, members))
	}
	state.Default.Exit = defaultExitOf(loaded.rules)
	state.Default.Options = []string{}
	offered := map[string]bool{}
	for _, profile := range defaultProfiles(a.allProfiles(loaded.rules)) {
		if exit := ruleExit(profile); !offered[exit] {
			offered[exit] = true
			state.Default.Options = append(state.Default.Options, exit)
		}
	}
	state.Exits = a.describeExits(loaded.rules, profiles)
	files, err := a.allFiles(loaded.rules)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		file := AdminFile{Path: path, Name: filepath.Base(path), Kind: listKind(path, loaded.rules), UsedBy: append([]string{}, files[path]...)}
		if entries, err := listEntries(path); err != nil {
			file.Problem = err.Error()
		} else {
			file.Domains = len(entries)
		}
		state.Files = append(state.Files, file)
	}
	if a.pending != nil {
		state.SecondsRemaining = a.pending.Deadline.Sub(a.now()).Seconds()
	}
	if ledgerErr == nil {
		state.Routes = routeStats(installed, loaded.rules)
		state.Default.Status = ledger.Default
	}
	return state, nil
}

// routeStats sorts the ledger by exit and by where each route came from. A range can be
// installed in pieces, so a route counts as static when a list or pool covers it.
func routeStats(installed []adminRoute, rules []map[string]any) *AdminRoutes {
	static := NewPrefixIndex()
	for _, rule := range rules {
		table, _ := asInt(rule["fib_table"])
		for _, network := range rangePrefixes(rule, nil) {
			static.Add(network, true, uint32(table))
		}
		for _, text := range anyStrings(rule["fakeip_range"]) {
			if pool, err := parsePrefixStrict(text); err == nil {
				static.Add(pool, true, uint32(table))
			}
		}
	}
	stats := &AdminRoutes{Total: len(installed), Exits: []AdminExitRoutes{}}
	// A route names its interface and next hop; several exits may share the interface.
	byPath := map[string]string{}
	byInterface := map[string]map[string]bool{}
	for _, rule := range rules {
		iface, _ := rule["interface"].(string)
		exit := ruleExit(rule)
		if iface == "" || exit == "" {
			continue
		}
		for _, via := range anyStrings(rule["via"]) {
			byPath[iface+" "+via] = exit
		}
		if byInterface[iface] == nil {
			byInterface[iface] = map[string]bool{}
		}
		byInterface[iface][exit] = true
	}
	exitOf := func(route adminRoute) string {
		if exit := byPath[route.Interface+" "+route.Via]; exit != "" {
			return exit
		}
		if names := byInterface[route.Interface]; len(names) == 1 {
			for name := range names {
				return name
			}
		}
		return route.Interface
	}
	counts := map[string]int{}
	for _, route := range installed {
		counts[exitOf(route)]++
		if network, err := parsePrefixStrict(route.Prefix); err == nil && len(static.Covering(network, route.Table)) > 0 {
			stats.Static++
		} else {
			stats.Learned++
		}
	}
	for name, routes := range counts {
		stats.Exits = append(stats.Exits, AdminExitRoutes{Name: name, Routes: routes})
	}
	sort.Slice(stats.Exits, func(i, j int) bool { return stats.Exits[i].Name < stats.Exits[j].Name })
	return stats
}

func findGroup(rules []map[string]any, id string) ([]int, error) {
	for _, members := range visibleGroups(rules) {
		if ruleName(rules[members[0]]) == id {
			return members, nil
		}
	}
	return nil, fmt.Errorf("no rule group named %s", id)
}

func renderRules(doc map[string]any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// SwitchExit sends a rule group to another exit.
func (a *Admin) SwitchExit(group, exit, user string) (*AdminState, error) {
	return a.SwitchRule(group, exit, nil, user)
}

// SwitchRule sends a group to an exit. A nil dns takes what the exit comes with; otherwise it
// is the group's DNS, and empty means the default one. The exit may stay as it is.
func (a *Admin) SwitchRule(group, exit string, dns *string, user string) (*AdminState, error) {
	var upstream []any
	if dns != nil {
		var err error
		if upstream, err = parseDNS(*dns); err != nil {
			return nil, err
		}
	}
	description := fmt.Sprintf("把 %s 切换到出口 %s", group, exit)
	if dns != nil {
		description += "，DNS 用 " + dnsLabel(upstream)
	}
	return a.change(description, user, func(loaded *adminRules) (map[string][]byte, error) {
		members, err := findGroup(loaded.rules, group)
		if err != nil {
			return nil, err
		}
		profiles := a.profiles(loaded.rules)
		described := describeGroup(loaded.rules, profiles, members)
		if described.Locked != "" {
			return nil, errors.New(described.Locked)
		}
		if dns != nil && exit == described.Exit {
			if text := dnsTextOf(upstream); text == described.DNS {
				return nil, errors.New("DNS 没有变化")
			}
			for _, index := range members {
				if err := setRuleDNS(loaded.rules[index], upstream); err != nil {
					return nil, err
				}
			}
			data, err := renderRules(loaded.doc)
			if err != nil {
				return nil, err
			}
			return map[string][]byte{loaded.path: data}, nil
		}
		allowed := false
		for _, option := range described.Options {
			allowed = allowed || option == exit
		}
		if !allowed {
			return nil, fmt.Errorf("%s cannot go to %s: it is already there, or that exit cannot carry it", group, exit)
		}
		for _, index := range members {
			rule := loaded.rules[index]
			profile := exitProfile(profiles, exit, rule)
			for key := range rule {
				if !ruleSourceFields[key] {
					delete(rule, key)
				}
			}
			for key, value := range profile {
				rule[key] = value
			}
			if dns != nil {
				if err := setRuleDNS(rule, upstream); err != nil {
					return nil, err
				}
			}
		}
		data, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{loaded.path: data}, nil
	})
}

// Reorder sets the priority of the rule groups: Gate uses the first rule in the file that
// matches, so order is priority. order names every group, highest priority first.
func (a *Admin) Reorder(order []string, user string) (*AdminState, error) {
	return a.change("调整规则优先级："+strings.Join(order, " > "), user, func(loaded *adminRules) (map[string][]byte, error) {
		groups := visibleGroups(loaded.rules)
		if len(order) != len(groups) {
			return nil, fmt.Errorf("the order must name all %d rule groups", len(groups))
		}
		byName := make(map[string][]int, len(groups))
		for _, members := range groups {
			byName[ruleName(loaded.rules[members[0]])] = members
		}
		reordered := make([]any, 0, len(loaded.rules))
		seen := make(map[string]bool, len(order))
		for _, id := range order {
			members, ok := byName[id]
			if !ok {
				return nil, fmt.Errorf("no rule group named %s", id)
			}
			if seen[id] {
				return nil, fmt.Errorf("%s appears twice in the order", id)
			}
			seen[id] = true
			for _, index := range members {
				reordered = append(reordered, loaded.rules[index])
			}
		}
		for _, rule := range loaded.rules {
			if isCarrier(rule) {
				reordered = append(reordered, rule) // matches nothing, so its place does not matter
			}
		}
		same := true
		for i, rule := range reordered {
			same = same && ruleName(rule.(map[string]any)) == ruleName(loaded.rules[i])
		}
		if same {
			return nil, errors.New("nothing to change: the rules are already in this order")
		}
		loaded.doc["routes"] = reordered
		data, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{loaded.path: data}, nil
	})
}

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(domain), "."))
}

// allFiles maps every list file that can be managed to the rules using it: those the rules
// name and the *.domains and *.ranges files in the list directory. A request can name no other path.
func (a *Admin) allFiles(rules []map[string]any) (map[string][]string, error) {
	files, err := ruleFiles(rules)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(a.opts.ListDir)
	if errors.Is(err, os.ErrNotExist) {
		return files, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() && (listFileName.MatchString(entry.Name()) || rangeFileName.MatchString(entry.Name())) {
			path := filepath.Join(a.opts.ListDir, entry.Name())
			if _, ok := files[path]; !ok {
				files[path] = nil
			}
		}
	}
	return files, nil
}

// fileUse says whether a rule uses a managed file, which decides if changing it needs Gate to
// restart, and what the file holds.
func (a *Admin) fileUse(path string) (used bool, kind string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	loaded, err := a.loadRules()
	if err != nil {
		return false, "", err
	}
	files, err := a.allFiles(loaded.rules)
	if err != nil {
		return false, "", err
	}
	users, ok := files[path]
	if !ok {
		return false, "", fmt.Errorf("%s is not a managed list file", path)
	}
	return len(users) > 0, listKind(path, loaded.rules), nil
}

// writeUnused saves a file no rule reads, which Gate does not need to know about.
func (a *Admin) writeUnused(path string, data []byte, description, user string) (*AdminState, error) {
	a.mu.Lock()
	if a.pending != nil {
		a.mu.Unlock()
		return nil, errors.New("a change is waiting for confirmation")
	}
	err := writeFileAtomic(path, data, 0o644)
	if err == nil {
		a.finish(description, "applied", "by "+user, 0)
	}
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.State()
}

// EditFile adds and removes entries in one list file.
func (a *Admin) EditFile(path string, add, remove []string, user string) (*AdminState, error) {
	used, kind, err := a.fileUse(path)
	if err != nil {
		return nil, err
	}
	description := fmt.Sprintf("修改%s %s：添加 %d 个，删除 %d 个", kindLabel[kind], filepath.Base(path), len(add), len(remove))
	additions := make([]string, 0, len(add))
	for _, entry := range add {
		normal, err := normalizeEntry(kind, entry)
		if err != nil {
			return nil, err
		}
		additions = append(additions, normal)
	}
	removals := make(map[string]bool, len(remove))
	for _, entry := range remove {
		removals[entryKey(kind, entry)] = true
	}
	if !used {
		data, err := editListFile(path, kind, additions, removals)
		if err != nil {
			return nil, err
		}
		return a.writeUnused(path, data, description, user)
	}
	return a.change(description, user, func(loaded *adminRules) (map[string][]byte, error) {
		data, err := editListFile(path, kind, additions, removals)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{path: data}, nil
	})
}

// normalizeList validates uploaded text as a list of the kind, keeping comments and dropping
// repeated entries. Every problem is reported, as a list is usually fixed in one go.
func normalizeList(kind, content string) ([]byte, error) {
	var lines, problems []string
	seen := map[string]bool{}
	bad := 0
	for number, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			lines = append(lines, line)
			continue
		}
		entry, err := normalizeEntry(kind, line)
		if err != nil {
			bad++
			if len(problems) < 5 {
				problems = append(problems, fmt.Sprintf("line %d: %q", number+1, line))
			}
			continue
		}
		if !seen[entry] {
			seen[entry] = true
			lines = append(lines, entry)
		}
	}
	if bad > 0 {
		return nil, fmt.Errorf("%d invalid lines, nothing saved: %s", bad, strings.Join(problems, ", "))
	}
	return []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"), nil
}

// UploadFile creates a list file, its kind given by its name, or replaces one when overwrite is set.
func (a *Admin) UploadFile(name, content string, overwrite bool, user string) (*AdminState, error) {
	kind := kindDomains
	if rangeFileName.MatchString(name) {
		kind = kindRanges
	} else if !listFileName.MatchString(name) {
		return nil, fmt.Errorf("the file name must look like streaming.domains or office.ranges: %q", name)
	}
	data, err := normalizeList(kind, content)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(a.opts.ListDir, name)
	_, statErr := os.Stat(path)
	exists := statErr == nil
	if exists && !overwrite {
		return nil, fmt.Errorf("%s already exists", name)
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	description := "上传" + kindLabel[kind] + " " + name
	if !exists {
		if err := os.MkdirAll(a.opts.ListDir, 0o755); err != nil {
			return nil, err
		}
		return a.writeUnused(path, data, description, user)
	}
	used, _, err := a.fileUse(path)
	if err != nil {
		return nil, err
	}
	if !used {
		return a.writeUnused(path, data, description, user)
	}
	return a.change(description, user, func(*adminRules) (map[string][]byte, error) {
		return map[string][]byte{path: data}, nil
	})
}

// DeleteFile removes a list file no rule uses, keeping a copy in the state directory.
func (a *Admin) DeleteFile(path, user string) (*AdminState, error) {
	a.mu.Lock()
	err := func() error {
		if a.pending != nil {
			return errors.New("a change is waiting for confirmation")
		}
		loaded, err := a.loadRules()
		if err != nil {
			return err
		}
		files, err := a.allFiles(loaded.rules)
		if err != nil {
			return err
		}
		users, ok := files[path]
		if !ok {
			return fmt.Errorf("%s is not a managed list file", path)
		}
		if len(users) > 0 {
			return fmt.Errorf("%s is used by %s; delete or change those rules first", filepath.Base(path), strings.Join(users, ", "))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		directory := filepath.Join(a.opts.StateDir, "deleted")
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		copyName := fmt.Sprintf("%s.%d", filepath.Base(path), a.now().Unix())
		if err := writeFileAtomic(filepath.Join(directory, copyName), data, 0o600); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		a.finish("删除"+kindLabel[listKind(path, loaded.rules)]+" "+filepath.Base(path), "applied", "by "+user, 0)
		return nil
	}()
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.State()
}

// RenameFile gives a list file a new name in its directory, keeping its kind. A file no rule
// uses is simply renamed. For one in use, the copy under the new name and the rules pointed at
// it are one change, which Gate restarts with and which waits for confirmation; the old name is
// removed only once the change is confirmed, so a rollback finds it where it was.
func (a *Admin) RenameFile(path, name, user string) (*AdminState, error) {
	a.mu.Lock()
	loaded, err := a.loadRules()
	var files map[string][]string
	if err == nil {
		files, err = a.allFiles(loaded.rules)
	}
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	users, ok := files[path]
	kind := listKind(path, loaded.rules)
	a.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%s is not a managed list file", path)
	}
	pattern, example := listFileName, "streaming.domains"
	if kind == kindRanges {
		pattern, example = rangeFileName, "office.ranges"
	}
	if !pattern.MatchString(name) {
		return nil, fmt.Errorf("the new name must look like %s: %q", example, name)
	}
	target := filepath.Join(filepath.Dir(path), name)
	if target == path {
		return nil, errors.New("the name is unchanged")
	}
	if _, err := os.Lstat(target); err == nil {
		return nil, fmt.Errorf("%s already exists", name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	description := fmt.Sprintf("把%s %s 改名为 %s", kindLabel[kind], filepath.Base(path), name)
	if len(users) == 0 {
		a.mu.Lock()
		err := func() error {
			if a.pending != nil {
				return errors.New("a change is waiting for confirmation")
			}
			if _, err := os.Lstat(target); err == nil {
				return fmt.Errorf("%s already exists", name)
			}
			if err := os.Rename(path, target); err != nil {
				return err
			}
			a.finish(description, "applied", "by "+user, 0)
			return nil
		}()
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return a.State()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	reference := a.listReference(target)
	return a.changeWith(description, user, []string{path}, func(loaded *adminRules) (map[string][]byte, error) {
		changed := false
		for _, rule := range loaded.rules {
			for _, key := range []string{"domain_files", "ip_range_files"} {
				switch value := rule[key].(type) {
				case string:
					if resolved, err := listFiles(map[string]any{key: value}, key); err == nil && resolved[0] == path {
						rule[key] = reference
						changed = true
					}
				case []any:
					for i, item := range value {
						text, _ := item.(string)
						if text == "" {
							continue
						}
						if resolved, err := listFiles(map[string]any{key: text}, key); err == nil && resolved[0] == path {
							value[i] = reference
							changed = true
						}
					}
				}
			}
		}
		if !changed {
			return nil, fmt.Errorf("no rule refers to %s any more", filepath.Base(path))
		}
		rules, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{loaded.path: rules, target: data}, nil
	})
}

// listReference is how a rule names a file: by name when it is in Gate's default directory.
func (a *Admin) listReference(path string) string {
	if a.opts.ListDir == defaultListDir && filepath.Dir(path) == defaultListDir {
		return filepath.Base(path)
	}
	return path
}

// AddRule adds a rule group at the lowest priority, matching a domain list, an address list
// or both. With no families given it covers every family the exit can carry, and a rule with
// only an address list covers the families in that list. IPv4 and IPv6 reached through
// separate next hops become two rules, the second named with a trailing 6.
func (a *Admin) AddRule(name, exit string, families []int, file, ranges, user string) (*AdminState, error) {
	return a.AddRuleWithDNS(name, exit, families, file, ranges, nil, user)
}

// AddRuleWithDNS is AddRule choosing the DNS as SwitchRule does.
func (a *Admin) AddRuleWithDNS(name, exit string, families []int, file, ranges string, dns *string, user string) (*AdminState, error) {
	return a.AddRuleWithKeywords(name, exit, families, file, ranges, dns, nil, user)
}

func (a *Admin) AddRuleWithKeywords(name, exit string, families []int, file, ranges string, dns *string, keywords []string, user string) (*AdminState, error) {
	files := []string{}
	if file != "" {
		files = append(files, file)
	}
	rangeFiles := []string{}
	if ranges != "" {
		rangeFiles = append(rangeFiles, ranges)
	}
	return a.AddRuleWithFiles(name, exit, families, files, rangeFiles, dns, keywords, user)
}

// AddRuleWithFiles adds a rule group matching any of the selected domain and address list files.
func (a *Admin) AddRuleWithFiles(name, exit string, families []int, files, rangeFiles []string, dns *string, keywords []string, user string) (*AdminState, error) {
	keywords, err := normalizeKeywords(keywords)
	if err != nil {
		return nil, err
	}
	var upstream []any
	if dns != nil {
		var err error
		if upstream, err = parseDNS(*dns); err != nil {
			return nil, err
		}
	}
	sources := make([]string, 0, 2)
	if len(files) > 0 {
		names := make([]string, 0, len(files))
		for _, file := range files {
			names = append(names, filepath.Base(file))
		}
		sources = append(sources, "域名表 "+strings.Join(names, "、"))
	}
	if len(rangeFiles) > 0 {
		names := make([]string, 0, len(rangeFiles))
		for _, ranges := range rangeFiles {
			names = append(names, filepath.Base(ranges))
		}
		sources = append(sources, "网段表 "+strings.Join(names, "、"))
	}
	if len(keywords) > 0 {
		sources = append(sources, fmt.Sprintf("%d 个关键词", len(keywords)))
	}
	description := fmt.Sprintf("添加规则 %s：出口 %s，%s", name, exit, strings.Join(sources, "，"))
	return a.change(description, user, func(loaded *adminRules) (map[string][]byte, error) {
		if !ruleNameRe.MatchString(name) {
			return nil, fmt.Errorf("a rule name is letters, digits, _ and -: %q", name)
		}
		if len(files) == 0 && len(rangeFiles) == 0 && len(keywords) == 0 {
			return nil, errors.New("a rule needs a domain list or an address list")
		}
		managedFiles, err := a.allFiles(loaded.rules)
		if err != nil {
			return nil, err
		}
		for _, path := range files {
			if _, ok := managedFiles[path]; !ok || listKind(path, loaded.rules) != kindDomains {
				return nil, fmt.Errorf("%s is not a managed %s", path, kindLabel[kindDomains])
			}
		}
		for _, path := range rangeFiles {
			if _, ok := managedFiles[path]; !ok || listKind(path, loaded.rules) != kindRanges {
				return nil, fmt.Errorf("%s is not a managed %s", path, kindLabel[kindRanges])
			}
		}
		profiles := a.profiles(loaded.rules)
		rangeFamilies := map[int]bool{}
		if len(rangeFiles) > 0 {
			selectedRanges := make([]any, 0, len(rangeFiles))
			for _, path := range rangeFiles {
				selectedRanges = append(selectedRanges, path)
			}
			for _, network := range rangePrefixes(map[string]any{"ip_range_files": selectedRanges}, nil) {
				if network.Addr().Is4() {
					rangeFamilies[4] = true
				} else {
					rangeFamilies[6] = true
				}
			}
			if len(rangeFamilies) == 0 {
				return nil, fmt.Errorf("选中的网段表里没有可用的网段")
			}
		}
		available := map[int]bool{}
		for _, profile := range profiles {
			if ruleExit(profile) == exit {
				for _, family := range ruleFamilies(profile) {
					available[family] = true
				}
			}
		}
		if len(available) == 0 {
			return nil, fmt.Errorf("no exit named %s", exit)
		}
		if len(families) == 0 {
			for family := range available {
				families = append(families, family)
			}
		}
		for family := range rangeFamilies {
			if !slices.Contains(families, family) {
				return nil, fmt.Errorf("网段表里有 IPv%d 网段，但规则没有选这个地址族", family)
			}
		}
		if len(files) == 0 && len(rangeFiles) > 0 && len(keywords) == 0 {
			families = families[:0]
			for family := range rangeFamilies {
				families = append(families, family)
			}
		}
		sort.Ints(families)
		wanted := make([]int, 0, 2)
		for _, family := range families {
			if !available[family] {
				return nil, fmt.Errorf("%s has no next hop for IPv%d", exit, family)
			}
			if len(wanted) == 0 || wanted[len(wanted)-1] != family {
				wanted = append(wanted, family)
			}
		}
		type planned struct {
			name       string
			profile    map[string]any
			withRanges bool
		}
		var plan []planned
		if profile := findProfile(profiles, exit, wanted); profile != nil {
			plan = append(plan, planned{name, profile, len(rangeFiles) > 0})
		} else {
			if len(rangeFamilies) > 1 {
				return nil, fmt.Errorf("出口 %s 的 IPv4 和 IPv6 是分开的规则，请把网段表拆成 IPv4 和 IPv6 两个文件", exit)
			}
			for _, family := range wanted {
				one := name
				if family == 6 && len(wanted) > 1 {
					one = name + "6"
				}
				plan = append(plan, planned{one, findProfile(profiles, exit, []int{family}), rangeFamilies[family]})
			}
		}
		existing := make(map[string]bool, len(loaded.rules))
		for _, rule := range loaded.rules {
			existing[ruleName(rule)] = true
		}
		routes := loaded.doc["routes"].([]any)
		for _, item := range plan {
			if existing[item.name] {
				return nil, fmt.Errorf("a rule named %s already exists", item.name)
			}
			rule := map[string]any{"name": item.name}
			if len(keywords) > 0 {
				rule["domain_keywords"] = keywords
			}
			if len(files) > 0 {
				fileRefs := make([]any, 0, len(files))
				for _, file := range files {
					fileRefs = append(fileRefs, a.listReference(file))
				}
				rule["domain_files"] = fileRefs
			}
			if item.withRanges {
				ruleRanges := make([]any, 0, len(rangeFiles))
				for _, ranges := range rangeFiles {
					ruleRanges = append(ruleRanges, ranges)
				}
				rule["ip_range_files"] = ruleRanges
			}
			for key, value := range item.profile {
				rule[key] = value
			}
			if dns != nil {
				if err := setRuleDNS(rule, upstream); err != nil {
					return nil, err
				}
			}
			routes = append(routes, rule)
		}
		loaded.doc["routes"] = routes
		data, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{loaded.path: data}, nil
	})
}

// DeleteRule removes a rule group. Its list files stay.
func (a *Admin) DeleteRule(group, user string) (*AdminState, error) {
	return a.change("删除规则 "+group, user, func(loaded *adminRules) (map[string][]byte, error) {
		members, err := findGroup(loaded.rules, group)
		if err != nil {
			return nil, err
		}
		removed := make(map[int]bool, len(members))
		for _, index := range members {
			removed[index] = true
		}
		kept := make([]any, 0, len(loaded.rules))
		for index, rule := range loaded.rules {
			if !removed[index] {
				kept = append(kept, rule)
			}
		}
		loaded.doc["routes"] = kept
		data, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{loaded.path: data}, nil
	})
}

// editListFile keeps comments and blank lines as they are.
func editListFile(path, kind string, additions []string, removals map[string]bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	present := map[string]bool{}
	var lines []string
	removed := 0
	text := strings.TrimRight(string(data), "\n")
	if text != "" {
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				key := entryKey(kind, trimmed)
				if removals[key] {
					removed++
					continue
				}
				present[key] = true
			}
			lines = append(lines, line)
		}
	}
	added := 0
	for _, entry := range additions {
		if !present[entry] {
			present[entry] = true
			lines = append(lines, entry)
			added++
		}
	}
	if added == 0 && removed == 0 {
		return nil, errors.New("nothing to change: the file already matches the request")
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

// FileDomains lists a file's domains, filtered, up to a limit.
func (a *Admin) FileDomains(path, query string) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	loaded, err := a.loadRules()
	if err != nil {
		return nil, err
	}
	files, err := a.allFiles(loaded.rules)
	if err != nil {
		return nil, err
	}
	if _, ok := files[path]; !ok {
		return nil, fmt.Errorf("%s is not a managed list file", path)
	}
	entries, err := listEntries(path)
	if err != nil {
		return nil, err
	}
	query = strings.ToLower(strings.TrimSpace(query))
	matched := []string{}
	count := 0
	for _, domain := range entries {
		if query == "" || strings.Contains(strings.ToLower(domain), query) {
			count++
			if len(matched) < adminDomainLimit {
				matched = append(matched, domain)
			}
		}
	}
	return map[string]any{"total": len(entries), "matched": count, "domains": matched, "limit": adminDomainLimit}, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".gate-admin-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
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

func (a *Admin) savePending() error {
	data, err := json.Marshal(a.pending)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(a.opts.StateDir, pendingFile), data, 0o600)
}

func (a *Admin) clearPending() {
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	if a.pending != nil {
		for _, file := range a.pending.Files {
			os.Remove(file.Backup)
		}
	}
	a.pending = nil
	os.Remove(filepath.Join(a.opts.StateDir, pendingFile))
}

func (a *Admin) finish(description, outcome, detail string, outage time.Duration) {
	a.last = &AdminResult{Description: description, Outcome: outcome, Detail: detail, OutageMs: outage.Milliseconds(), Time: a.now()}
	log.Printf("audit: %s: %s %s", description, outcome, detail)
}

// restartGate applies the configuration on disk, returning how long DNS was unavailable.
func (a *Admin) applyPending() (time.Duration, error) {
	if a.pending != nil && a.pending.Reload {
		restarted, err := a.sys.reload()
		if restarted && err == nil {
			a.pending.Reload = false
		}
		return 0, err
	}
	return a.restartGate()
}

func (a *Admin) restartGate() (time.Duration, error) {
	if err := a.sys.sync(); err != nil {
		return 0, fmt.Errorf("device sync: %w", err)
	}
	started := a.now()
	if err := a.sys.restart(); err != nil {
		return 0, fmt.Errorf("restart: %w", err)
	}
	if err := a.sys.ready(); err != nil {
		return a.now().Sub(started), fmt.Errorf("Gate did not come back: %w", err)
	}
	return a.now().Sub(started), nil
}

func (a *Admin) restoreFiles() error {
	var first error
	for _, file := range a.pending.Files {
		var err error
		if file.Existed {
			var data []byte
			var info os.FileInfo
			if data, err = os.ReadFile(file.Backup); err == nil {
				if info, err = os.Stat(file.Backup); err == nil {
					err = writeFileAtomic(file.Path, data, info.Mode().Perm())
				}
			}
		} else {
			err = os.Remove(file.Path)
			if errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

// rollbackLocked restores the previous files using the same apply mode as the change.
func (a *Admin) rollbackLocked(reason string) {
	description := a.pending.Description
	if err := a.restoreFiles(); err != nil {
		a.finish(description, "rollback-failed", err.Error(), 0)
		return // the backups stay, for someone to look at
	}
	outage, err := a.applyPending()
	if err != nil {
		a.finish(description, "rollback-failed", reason+": "+err.Error(), outage)
		a.clearPending()
		return
	}
	a.finish(description, "rolled-back", reason, outage)
	a.clearPending()
}

// change backs the files up, applies mutate's result, and leaves it waiting for confirmation.
func (a *Admin) change(description, user string, mutate func(*adminRules) (map[string][]byte, error)) (*AdminState, error) {
	return a.changeWith(description, user, nil, mutate)
}

// changeWith is change, also deleting the files in remove once the change is confirmed.
func (a *Admin) changeWith(description, user string, remove []string, mutate func(*adminRules) (map[string][]byte, error)) (*AdminState, error) {
	a.mu.Lock()
	unlocked := false
	defer func() {
		if !unlocked {
			a.mu.Unlock()
		}
	}()
	if a.pending != nil {
		return nil, errors.New("a change is waiting for confirmation")
	}
	loaded, err := a.loadRules()
	if err != nil {
		return nil, err
	}
	a.learnExits(loaded.rules)
	loaded.defaultExit = defaultExitOf(loaded.rules)
	files, err := mutate(loaded)
	if err != nil {
		return nil, err
	}
	if _, touched := files[loaded.path]; touched {
		if err := settleDefault(loaded, a.allProfiles(loaded.rules)); err != nil {
			return nil, err
		}
		custom := loaded.custom
		if !loaded.customSet {
			if custom, err = a.customExits(); err != nil {
				return nil, err
			}
		}
		var rules []map[string]any
		routes, _ := loaded.doc["routes"].([]any)
		for _, item := range routes {
			if rule, ok := item.(map[string]any); ok {
				rules = append(rules, rule)
			}
		}
		if err := applyFakeIP(rules, a.fakeIPOffers(custom)); err != nil {
			return nil, err
		}
		data, err := renderRules(loaded.doc)
		if err != nil {
			return nil, err
		}
		files[loaded.path] = data
	}
	if routes, ok := loaded.doc["routes"].([]any); ok {
		if err := checkRanges(routes, files); err != nil {
			return nil, err
		}
	}
	entry, err := readJSONObject(a.opts.Config)
	if err != nil {
		return nil, err
	}
	if data, changed := files[a.opts.Config]; changed {
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, err
		}
	}
	if err := gate.ValidateDNSConfig(entry, loaded.doc); err != nil {
		return nil, err
	}
	a.nextID++
	id := fmt.Sprintf("%d-%d", a.now().Unix(), a.nextID)
	pending := &AdminPending{ID: id, Description: description, User: user, Remove: remove}
	pending.Reload = len(files) > 0 && len(remove) == 0
	for path := range files {
		if !listFileName.MatchString(filepath.Base(path)) && !rangeFileName.MatchString(filepath.Base(path)) {
			pending.Reload = false
		}
	}
	for path := range files {
		backup := adminBackup{Path: path, Backup: filepath.Join(a.opts.StateDir, id+"-"+strconv.Itoa(len(pending.Files)))}
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			info, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if err := writeFileAtomic(backup.Backup, data, info.Mode().Perm()); err != nil {
				return nil, err
			}
			backup.Existed = true
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
		pending.Files = append(pending.Files, backup)
	}
	a.pending = pending
	// Saved before anything changes, so that a crash from here on is rolled back at startup.
	if err := a.savePending(); err != nil {
		a.clearPending()
		return nil, err
	}
	log.Printf("audit: %s: applying, by %s", description, user)
	for path, data := range files {
		mode := os.FileMode(0o644)
		if info, err := os.Stat(path); err == nil {
			mode = info.Mode().Perm()
		}
		if err := writeFileAtomic(path, data, mode); err != nil {
			a.restoreFiles()
			a.clearPending()
			return nil, err
		}
	}
	if err := a.sys.check(); err != nil {
		restoreErr := a.restoreFiles()
		a.finish(description, "refused", err.Error(), 0)
		a.clearPending()
		if restoreErr != nil {
			return nil, fmt.Errorf("%w (restoring the files also failed: %v)", err, restoreErr)
		}
		return nil, fmt.Errorf("the configuration was refused and nothing changed: %w", err)
	}
	outage, err := a.applyPending()
	if err != nil {
		a.rollbackLocked(err.Error())
		return nil, fmt.Errorf("the change was rolled back: %w", err)
	}
	a.pending.Deadline = a.now().Add(a.opts.Confirm)
	if err := a.savePending(); err != nil {
		log.Printf("saving the pending change: %v", err)
	}
	a.arm()
	a.finish(description, "pending", "", outage)
	a.mu.Unlock()
	unlocked = true
	return a.State()
}

// FlushRoutes removes the routes Gate installed and the leases behind them, then starts Gate
// again. Static ranges and Fake-IP pools come back at once; routes learned from DNS come back
// as clients ask again. Nothing changes in the configuration, so there is nothing to confirm
// or roll back. Gate is started again whatever happened, as DNS depends on it.
func (a *Admin) FlushRoutes(user string) (*AdminState, error) {
	const description = "清空路由"
	a.mu.Lock()
	if a.pending != nil {
		a.mu.Unlock()
		return nil, errors.New("a change is waiting for confirmation")
	}
	log.Printf("audit: %s: applying, by %s", description, user)
	started := a.now()
	flushErr := a.sys.stop()
	if flushErr == nil {
		flushErr = a.sys.flush()
	}
	startErr := a.sys.start()
	if startErr == nil {
		startErr = a.sys.ready()
	}
	outage := a.now().Sub(started)
	err := errors.Join(flushErr, startErr)
	if err != nil {
		a.finish(description, "flush-failed", err.Error(), outage)
	} else {
		a.finish(description, "flushed", "by "+user, outage)
	}
	a.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("清空路由失败: %w", err)
	}
	return a.State()
}

// Confirm keeps the pending change.
func (a *Admin) Confirm(user string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		return errors.New("no change is waiting for confirmation")
	}
	var outage int64
	if a.last != nil {
		outage = a.last.OutageMs
	}
	description := a.pending.Description
	detail := "by " + user
	for _, path := range a.pending.Remove {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			detail += "; " + err.Error()
		}
	}
	a.clearPending()
	a.finish(description, "confirmed", detail, time.Duration(outage)*time.Millisecond)
	return nil
}

// Rollback undoes the pending change now.
func (a *Admin) Rollback(user string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		return errors.New("no change is waiting for confirmation")
	}
	a.rollbackLocked("requested by " + user)
	return nil
}

// Handler serves the admin API. Whoever can reach the socket is trusted, as it is root-only.
func (a *Admin) Handler() http.Handler {
	reply := func(w http.ResponseWriter, value any, err error) {
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(value)
	}
	decode := func(w http.ResponseWriter, r *http.Request, into any) bool {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, adminMaxBody)).Decode(into); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "bad request"})
			return false
		}
		return true
	}
	user := func(r *http.Request) string {
		if name := r.Header.Get("X-Panel-User"); name != "" {
			return name
		}
		return "unknown"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /gate/state", func(w http.ResponseWriter, r *http.Request) {
		state, err := a.State()
		reply(w, state, err)
	})
	mux.HandleFunc("GET /gate/file", func(w http.ResponseWriter, r *http.Request) {
		result, err := a.FileDomains(r.URL.Query().Get("path"), r.URL.Query().Get("q"))
		reply(w, result, err)
	})
	mux.HandleFunc("POST /gate/switch", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Group, Exit string
			DNS         *string
		}
		if decode(w, r, &request) {
			state, err := a.SwitchRule(request.Group, request.Exit, request.DNS, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/default", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ DNS string }
		if decode(w, r, &request) {
			state, err := a.SetDefaultDNS(request.DNS, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/default-exit", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Exit string }
		if decode(w, r, &request) {
			state, err := a.SetDefaultExit(request.Exit, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/exit", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Name, Interface, Via4, Via6 string
			DHCP                        bool
		}
		if decode(w, r, &request) {
			state, err := a.SetExit(request.Name, request.Interface, request.Via4, request.Via6, request.DHCP, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/tproxy", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Name, DNS string
			Port      int
			Pools     []string
			IPv6      bool
		}
		if decode(w, r, &q) {
			state, err := a.SetTProxyExit(q.Name, q.Port, q.DNS, q.Pools, q.IPv6, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/exit/delete", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Name, Interface string }
		if decode(w, r, &request) {
			name := request.Name
			if name == "" {
				name = request.Interface
			}
			state, err := a.DeleteExit(name, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/order", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Order []string }
		if decode(w, r, &request) {
			state, err := a.Reorder(request.Order, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/rule", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Name, Exit string
			File       stringList `json:"file"`
			Ranges     stringList `json:"ranges"`
			Families   []int
			DNS        *string
			Keywords   []string
		}
		if decode(w, r, &request) {
			state, err := a.AddRuleWithFiles(request.Name, request.Exit, request.Families, request.File, request.Ranges, request.DNS, request.Keywords, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/rule/edit", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Group, Exit string
			DNS         *string
			File        stringList `json:"file"`
			Ranges      stringList `json:"ranges"`
			Keywords    []string
		}
		if decode(w, r, &request) {
			state, err := a.EditRule(request.Group, RuleEdit{Exit: request.Exit, DNS: request.DNS, Files: request.File, Ranges: request.Ranges, Keywords: request.Keywords}, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/defaults", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Exit, DNS *string }
		if decode(w, r, &request) {
			state, err := a.SetDefault(request.Exit, request.DNS, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/keywords", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Group    string
			Keywords []string
		}
		if decode(w, r, &q) {
			state, err := a.SetKeywords(q.Group, q.Keywords, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/rule/delete", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Group string }
		if decode(w, r, &request) {
			state, err := a.DeleteRule(request.Group, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/upload", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Name, Content string
			Overwrite     bool
		}
		if decode(w, r, &request) {
			state, err := a.UploadFile(request.Name, request.Content, request.Overwrite, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/file/delete", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Path string }
		if decode(w, r, &request) {
			state, err := a.DeleteFile(request.Path, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/file/rename", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Path, Name string }
		if decode(w, r, &request) {
			state, err := a.RenameFile(request.Path, request.Name, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/file", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Path        string
			Add, Remove []string
		}
		if decode(w, r, &request) {
			state, err := a.EditFile(request.Path, request.Add, request.Remove, user(r))
			reply(w, state, err)
		}
	})
	mux.HandleFunc("POST /gate/flush", func(w http.ResponseWriter, r *http.Request) {
		state, err := a.FlushRoutes(user(r))
		reply(w, state, err)
	})
	mux.HandleFunc("POST /gate/confirm", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]bool{"ok": true}, a.Confirm(user(r)))
	})
	mux.HandleFunc("POST /gate/rollback", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]bool{"ok": true}, a.Rollback(user(r)))
	})
	return mux
}

// realAdminSystem runs Gate's own commands.
type realAdminSystem struct {
	opts   AdminOptions
	binary string
}

func (s *realAdminSystem) run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), adminCommandLimit)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(output))
		if len(text) > 800 {
			text = text[len(text)-800:]
		}
		return fmt.Errorf("%w: %s", err, text)
	}
	return nil
}

func (s *realAdminSystem) check() error {
	return s.run(s.binary, "--config", s.opts.Config, "--sync-devices", "--dry-run")
}

func (s *realAdminSystem) sync() error {
	return s.run(s.binary, "--config", s.opts.Config, "--sync-devices")
}

func (s *realAdminSystem) reload() (bool, error) {
	if err := s.sync(); err != nil {
		return false, err
	}
	path, err := s.stateSocket()
	if err != nil {
		return false, err
	}
	conn, err := net.DialTimeout("unix", path+".reload", adminLedgerTimeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(adminCommandLimit))
	var result gate.ListReloadResult
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		return false, err
	}
	if result.Error != "" {
		return false, errors.New(result.Error)
	}
	if result.Restart {
		if err := s.restart(); err != nil {
			return false, err
		}
		return true, s.ready()
	}
	return false, nil
}

func (s *realAdminSystem) restart() error {
	return s.run("systemctl", "restart", s.opts.Unit)
}

func (s *realAdminSystem) stop() error {
	return s.run("systemctl", "stop", s.opts.Unit)
}

// flush reads the configuration the service runs, as that is the one naming its ledger.
func (s *realAdminSystem) flush() error {
	return s.run(s.binary, "--config", filepath.Join(gate.DeviceStateDir(), "gate.json"), "--flush")
}

func (s *realAdminSystem) start() error {
	return s.run("systemctl", "start", s.opts.Unit)
}

// stateSocket is where the running Gate answers with its ledger.
func (s *realAdminSystem) stateSocket() (string, error) {
	entry, err := readJSONObject(s.opts.Config)
	if err != nil {
		return "", err
	}
	_, linked, err := linkedJSON(entry, "route_config")
	if err != nil {
		return "", err
	}
	for _, doc := range []map[string]any{linked, entry} {
		if path, ok := doc["state_socket"].(string); ok && path != "" {
			return path, nil
		}
	}
	return "/run/vpp-egress-gate/state.sock", nil
}

func (s *realAdminSystem) ledger() (gateLedger, error) {
	path, err := s.stateSocket()
	if err != nil {
		return gateLedger{}, err
	}
	conn, err := net.DialTimeout("unix", path, adminLedgerTimeout)
	if err != nil {
		return gateLedger{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(adminLedgerTimeout))
	var state gateLedger
	if err := json.NewDecoder(conn).Decode(&state); err != nil {
		return gateLedger{}, err
	}
	return state, nil
}

// dnsProbe is a query for a name that cannot exist. Any answer, even an error, means Gate is
// listening; whether the upstream works is not what is being measured.
var dnsProbe = []byte{0x47, 0x41, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 10, 'g', 'a', 't', 'e', '-', 'p', 'r', 'o', 'b', 'e', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1}

func (s *realAdminSystem) ready() error {
	entry, err := readJSONObject(s.opts.Config)
	if err != nil {
		return err
	}
	listen, _ := entry["listen"].([]any)
	if len(listen) == 0 {
		return errors.New("the configuration has no listen address to check")
	}
	address, err := parseHostPort(listen[0])
	if err != nil {
		return err
	}
	deadline := time.Now().Add(adminReadyTimeout)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.Dial("udp", net.JoinHostPort(address.Host, strconv.Itoa(address.Port)))
		if err != nil {
			last = err
			time.Sleep(adminReadyProbe)
			continue
		}
		conn.SetDeadline(time.Now().Add(adminReadyProbe))
		conn.Write(dnsProbe)
		buffer := make([]byte, 512)
		n, err := conn.Read(buffer)
		conn.Close()
		if err == nil && n >= 12 && buffer[0] == dnsProbe[0] && buffer[1] == dnsProbe[1] {
			return nil
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("no DNS answer within %s: %v", adminReadyTimeout, last)
}
