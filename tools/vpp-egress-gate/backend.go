package gate

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Backend interface {
	Generation() (string, error)
	CLI(command string) (string, error)
	LookupExact(route Route) (PathSet, bool, error)
	DumpOwned(table uint32, family int) (map[RouteKey]PathSet, error)
	Snapshot(routes []Route) (map[RouteKey]PathSet, error)
	Lookup(routes []Route) (map[RouteKey]PathSet, error)
	Apply(lines []string) error
	SyncTProxy() error
	// MissingInterfaces says which of the names VPP does not have now.
	MissingInterfaces(names []string) (map[string]bool, error)
	// ApplyDrops adds or removes routes that discard traffic.
	ApplyDrops(add bool, routes []DropRoute) error
}

type BackendFactory func(*Config) Backend

type VPPBackend struct {
	Config   *Config
	routeAPI routeAPI
	ctx      context.Context
}

func (b *VPPBackend) SetContext(ctx context.Context) { b.ctx = ctx }

func (b *VPPBackend) context() context.Context {
	if b == nil || b.ctx == nil {
		return context.Background()
	}
	return b.ctx
}

func NewVPPBackend(cfg *Config) Backend { return &VPPBackend{Config: cfg} }

type contextSetter interface {
	SetContext(context.Context)
}

func withBackendContext(b Backend, ctx context.Context) Backend {
	if s, ok := b.(contextSetter); ok {
		s.SetContext(ctx)
	}
	return b
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

var commandTimeout = 5 * time.Second

func runCmd(name string, args ...string) (string, error) {
	return runCmdContext(context.Background(), name, args...)
}

func runCmdContext(ctx context.Context, name string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s timed out after %s", name, commandTimeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return "", fmt.Errorf("%s failed: %s", name, msg)
	}
	return stdout.String(), nil
}

func (b *VPPBackend) CLI(line string) (string, error) {
	return runCmdContext(b.context(), "vppctl", "-s", b.Config.VPPSocket, line)
}

func fibFamily(version int) string {
	if version == 4 {
		return "ip"
	}
	return "ip6"
}

func prefixVersion(prefix string) int {
	if strings.Contains(prefix, ":") {
		return 6
	}
	return 4
}

func (b *VPPBackend) LookupExact(route Route) (PathSet, bool, error) {
	family := fibFamily(prefixVersion(route.Prefix))
	text, err := b.CLI(fmt.Sprintf("show %s fib table %d %s", family, route.Table, route.Prefix))
	if err != nil {
		return nil, false, err
	}
	entries, err := parseFIB(text, route.Table)
	if err != nil {
		return nil, false, err
	}
	paths, ok := entries[route.Key()]
	return paths, ok, nil
}

func (b *VPPBackend) DumpOwned(table uint32, family int) (map[RouteKey]PathSet, error) {
	text, err := b.CLI(fmt.Sprintf("show %s fib table %d", fibFamily(family), table))
	if err != nil {
		return nil, err
	}
	return parseFIB(text, table)
}

func (b *VPPBackend) Snapshot(routes []Route) (map[RouteKey]PathSet, error) {
	type pair struct {
		table   uint32
		version int
	}
	seen := map[pair]struct{}{}
	result := map[RouteKey]PathSet{}
	var pairs []pair
	for _, r := range routes {
		p := pair{r.Table, prefixVersion(r.Prefix)}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		pairs = append(pairs, p)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].table != pairs[j].table {
			return pairs[i].table < pairs[j].table
		}
		return pairs[i].version < pairs[j].version
	})
	for _, p := range pairs {
		part, err := b.DumpOwned(p.table, p.version)
		if err != nil {
			return nil, err
		}
		for k, v := range part {
			result[k] = v
		}
	}
	return result, nil
}

func (b *VPPBackend) Lookup(routes []Route) (map[RouteKey]PathSet, error) {
	var wanted []Route
	seen := map[RouteKey]struct{}{}
	sorted := append([]Route{}, routes...)
	sortRoutes(sorted)
	for _, route := range sorted {
		if _, ok := seen[route.Key()]; ok {
			continue
		}
		seen[route.Key()] = struct{}{}
		wanted = append(wanted, route)
	}
	if len(wanted) > exactLookupLim {
		dump, err := b.Snapshot(wanted)
		if err != nil {
			return nil, err
		}
		result := map[RouteKey]PathSet{}
		for _, route := range wanted {
			if paths, ok := dump[route.Key()]; ok {
				result[route.Key()] = paths
			}
		}
		return result, nil
	}
	result := map[RouteKey]PathSet{}
	for _, route := range wanted {
		paths, ok, err := b.LookupExact(route)
		if err != nil {
			return nil, err
		}
		if ok {
			result[route.Key()] = paths
		}
	}
	return result, nil
}

func (b *VPPBackend) Apply(lines []string) error {
	if err := ctxErr(b.context()); err != nil {
		return err
	}
	var err error
	if b.routeAPI != nil {
		err = b.routeAPI.apply(b.context(), lines)
	} else {
		err = applyVPPRoutes(b.context(), b.Config, lines)
	}
	if err != nil {
		return fmt.Errorf("VPP Binary API request failed: %w", err)
	}
	return nil
}

func applyNft(lines []string, what string) error {
	return applyNftContext(context.Background(), lines, what)
}

func applyNftContext(ctx context.Context, lines []string, what string) error {
	if len(lines) == 0 {
		return nil
	}
	if what == "" {
		what = "nft"
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s timed out after %s", what, commandTimeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("%s update failed: %s", what, msg)
	}
	return nil
}

func (b *VPPBackend) applyNft(lines []string) error {
	return applyNftContext(b.context(), lines, "lease TPROXY")
}

var tproxyMu sync.Mutex

func (b *VPPBackend) MissingInterfaces(names []string) (map[string]bool, error) {
	return missingVPPInterfaces(b.context(), b.Config, names)
}

func (b *VPPBackend) ApplyDrops(add bool, routes []DropRoute) error {
	return applyVPPDrops(b.context(), b.Config, add, routes)
}

func (b *VPPBackend) SyncTProxy() error {
	if err := b.syncLinuxExits(true); err != nil {
		return err
	}
	tproxyMu.Lock()
	defer tproxyMu.Unlock()
	if err := ctxErr(b.context()); err != nil {
		return err
	}
	rules := tproxyPortRules(b.Config)
	if err := ensureTProxyHostSettings(rules); err != nil {
		return err
	}
	script := tproxyPortNftScript(rules)
	if len(rules) == 0 {
		return clearNftChain(b.context(), "gate_tproxy", script, "lease TPROXY")
	}
	return b.applyNft(script)
}

func parseProcessStat(text string) (string, error) {
	idx := strings.LastIndex(text, ") ")
	if idx < 0 {
		return "", fmt.Errorf("VPP process is not running")
	}
	fields := strings.Fields(text[idx+2:])
	if len(fields) < 20 {
		return "", fmt.Errorf("VPP process is not running")
	}
	if fields[0] == "Z" || fields[0] == "X" {
		return "", fmt.Errorf("VPP process is not running")
	}
	return fields[19], nil
}

func processIdentity(pid string) (string, error) {
	data, err := os.ReadFile(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		return "", fmt.Errorf("VPP process is not running")
	}
	return parseProcessStat(string(data))
}

var (
	generationMu    sync.Mutex
	generationCache = map[[3]any]generationEntry{}
)

type generationEntry struct {
	value, pid, start string
}

func (b *VPPBackend) Generation() (string, error) {
	st, err := stampOf(b.Config.VPPSocket)
	if err != nil {
		return "", err
	}
	identity := [3]any{b.Config.VPPService, st.Ino, st.Ctime}
	generationMu.Lock()
	cached, ok := generationCache[identity]
	generationMu.Unlock()
	if ok {
		start, err := processIdentity(cached.pid)
		if err != nil || start != cached.start {
			return "", fmt.Errorf("VPP process changed at route barrier")
		}
		return cached.value, nil
	}
	out, err := runCmdContext(b.context(), "systemctl", "show", b.Config.VPPService, "-p", "InvocationID", "-p", "MainPID", "-p", "ActiveState")
	if err != nil {
		return "", err
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			props[k] = v
		}
	}
	value := props["InvocationID"]
	pid := props["MainPID"]
	n, _ := strconv.Atoi(pid)
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(value) || n <= 0 || props["ActiveState"] != "active" {
		return "", fmt.Errorf("VPP has no active invocation")
	}
	start, err := processIdentity(pid)
	if err != nil {
		return "", err
	}
	generationMu.Lock()
	generationCache = map[[3]any]generationEntry{identity: {value, pid, start}}
	generationMu.Unlock()
	return value, nil
}

type FakeBackend struct {
	Instance     string
	Live         map[RouteKey]PathSet
	Batches      [][]string
	FailAfter    *int
	Lookups      [][]RouteKey
	Snapshots    int
	CLICalls     []string
	SyncTProxyFn func()
	SnapshotFn   func([]Route) (map[RouteKey]PathSet, error)
	ApplyFn      func([]string) error
	Quiet        bool
	HangApply    bool
	ApplyStarted chan struct{}
	ctx          context.Context
	mu           sync.Mutex
	// Absent names the interfaces VPP does not have.
	Absent map[string]bool
	// Drops holds the drop routes in place.
	Drops map[DropRoute]bool
}

func (f *FakeBackend) ApplyDrops(add bool, routes []DropRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Drops == nil {
		f.Drops = map[DropRoute]bool{}
	}
	for _, route := range routes {
		if add {
			f.Drops[route] = true
		} else {
			delete(f.Drops, route)
		}
	}
	return nil
}

func (f *FakeBackend) MissingInterfaces(names []string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	missing := map[string]bool{}
	for _, name := range names {
		if f.Absent[name] {
			missing[name] = true
		}
	}
	return missing, nil
}

func (f *FakeBackend) SetContext(ctx context.Context) {
	f.mu.Lock()
	f.ctx = ctx
	f.mu.Unlock()
}

func NewFakeBackend() *FakeBackend {
	return &FakeBackend{
		Instance: strings.Repeat("a", 32),
		Live:     map[RouteKey]PathSet{},
	}
}

func (f *FakeBackend) Generation() (string, error) { return f.Instance, nil }

func (f *FakeBackend) CLI(command string) (string, error) {
	f.mu.Lock()
	f.CLICalls = append(f.CLICalls, command)
	f.mu.Unlock()
	switch command {
	case "show interface":
		return "wg1 4 up 1280\nwg2 5 up 1280\n", nil
	case "show wireguard peer":
		return "[28] endpoint:[10.61.20.68:42006->10.64.20.3:42003] wg1\n", nil
	default:
		return "", fmt.Errorf("unexpected cli: %s", command)
	}
}

func (f *FakeBackend) LookupExact(route Route) (PathSet, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Lookups = append(f.Lookups, []RouteKey{route.Key()})
	paths, ok := f.Live[route.Key()]
	return paths, ok, nil
}

func (f *FakeBackend) DumpOwned(table uint32, family int) (map[RouteKey]PathSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Snapshots++
	out := map[RouteKey]PathSet{}
	for key, paths := range f.Live {
		if key.Table == table && prefixVersion(key.Prefix) == family {
			out[key] = paths
		}
	}
	return out, nil
}

func (f *FakeBackend) Snapshot(routes []Route) (map[RouteKey]PathSet, error) {
	if f.SnapshotFn != nil {
		return f.SnapshotFn(routes)
	}
	return f.DoSnapshot(routes)
}

func (f *FakeBackend) DoSnapshot(routes []Route) (map[RouteKey]PathSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Snapshots++
	out := map[RouteKey]PathSet{}
	for k, v := range f.Live {
		out[k] = v
	}
	return out, nil
}

func (f *FakeBackend) Lookup(routes []Route) (map[RouteKey]PathSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]RouteKey, 0, len(routes))
	for _, r := range routes {
		keys = append(keys, r.Key())
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Table != keys[j].Table {
			return keys[i].Table < keys[j].Table
		}
		return keys[i].Prefix < keys[j].Prefix
	})
	f.Lookups = append(f.Lookups, keys)
	out := map[RouteKey]PathSet{}
	for _, r := range routes {
		if paths, ok := f.Live[r.Key()]; ok {
			out[r.Key()] = paths
		}
	}
	return out, nil
}

func (f *FakeBackend) Apply(lines []string) error {
	f.mu.Lock()
	ctx := f.ctx
	hang := f.HangApply
	started := f.ApplyStarted
	f.mu.Unlock()
	if hang {
		if started != nil {
			select {
			case <-started:
			default:
				close(started)
			}
		}
		if ctx == nil {
			ctx = context.Background()
		}
		<-ctx.Done()
		return ctx.Err()
	}
	if err := ctxErr(ctx); err != nil {
		return err
	}
	if f.ApplyFn != nil {
		return f.ApplyFn(lines)
	}
	return f.DoApply(lines)
}

func (f *FakeBackend) DoApply(lines []string) error {
	f.mu.Lock()
	copied := append([]string{}, lines...)
	if !f.Quiet {
		f.Batches = append(f.Batches, copied)
	}
	failAfter := f.FailAfter
	if failAfter != nil {
		f.FailAfter = nil
	}
	f.mu.Unlock()
	for index, line := range lines {
		if failAfter != nil && *failAfter == index {
			return fmt.Errorf("injected batch interruption")
		}
		words := strings.Fields(line)
		if len(words) < 9 {
			continue
		}
		table, _ := strconv.Atoi(words[5])
		route := Route{uint32(table), words[3], words[7], words[8]}
		f.mu.Lock()
		if f.Absent[route.Interface] {
			f.mu.Unlock()
			if words[2] == "add" {
				return fmt.Errorf("%w: %s", errVPPInterfaceMissing, route.Interface)
			}
			f.mu.Lock()
			delete(f.Live, route.Key()) // the route went with its interface
			f.mu.Unlock()
			continue
		}
		if words[2] == "add" {
			f.Live[route.Key()] = pathSetOf(route.Via, route.Interface)
		} else if Matches(route, f.Live) {
			delete(f.Live, route.Key())
		}
		f.mu.Unlock()
	}
	return nil
}

func (f *FakeBackend) SyncTProxy() error {
	f.mu.Lock()
	ctx := f.ctx
	f.mu.Unlock()
	if err := ctxErr(ctx); err != nil {
		return err
	}
	if f.SyncTProxyFn != nil {
		f.SyncTProxyFn()
	}
	return nil
}

func (f *FakeBackend) HasRoute(table uint32, prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.Live[RouteKey{table, prefix}]
	return ok
}

func (f *FakeBackend) RoutePath(table uint32, prefix string) (Path, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	paths, ok := f.Live[RouteKey{table, prefix}]
	if !ok {
		return Path{}, false
	}
	for p := range paths {
		return p, true
	}
	return Path{}, false
}

func (f *FakeBackend) FailNext(index int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := index
	f.FailAfter = &n
}

func (f *FakeBackend) BatchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Batches)
}

func (f *FakeBackend) LookupCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Lookups)
}

func (f *FakeBackend) LiveKeys() map[RouteKey]struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[RouteKey]struct{}{}
	for k := range f.Live {
		out[k] = struct{}{}
	}
	return out
}
