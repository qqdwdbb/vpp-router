package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

var (
	stateMu    sync.Mutex
	stateStore *DeferredState
)

type SeenKey struct {
	Mapping    MappingKey
	Prefix     string
	Domain     string
	SourceHash string
	Kind       int
}

func (k SeenKey) less(o SeenKey) bool {
	if k.Mapping != o.Mapping {
		if k.Mapping.Family != o.Mapping.Family {
			return k.Mapping.Family < o.Mapping.Family
		}
		if k.Mapping.Table != o.Mapping.Table {
			return k.Mapping.Table < o.Mapping.Table
		}
		return k.Mapping.Set < o.Mapping.Set
	}
	if k.Prefix != o.Prefix {
		return k.Prefix < o.Prefix
	}
	if k.Kind != o.Kind {
		return k.Kind < o.Kind
	}
	if k.Domain != o.Domain {
		return k.Domain < o.Domain
	}
	return k.SourceHash < o.SourceHash
}

func DecodeSeen(document []any) map[SeenKey]int64 {
	now := time.Now().Unix()
	result := map[SeenKey]int64{}
	for _, item := range document {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		mappingRaw, _ := obj["mapping"].([]any)
		if len(mappingRaw) != 3 {
			continue
		}
		key := SeenKey{
			Mapping: MappingKey{fmt.Sprint(mappingRaw[0]), fmt.Sprint(mappingRaw[1]), fmt.Sprint(mappingRaw[2])},
			Prefix:  fmt.Sprint(obj["prefix"]),
			Kind:    2,
		}
		if _, ok := obj["domain"]; ok {
			key.Domain = fmt.Sprint(obj["domain"])
			key.Kind = 3
		}
		if _, ok := obj["source_hash"]; ok {
			key.SourceHash = fmt.Sprint(obj["source_hash"])
			key.Kind = 4
		}
		var value any
		if v, ok := obj["seen"]; ok {
			value = v
		} else {
			value = obj["expires"]
		}
		if value == nil {
			continue
		}
		n, err := asInt(value)
		if err != nil {
			continue
		}
		ts := int64(n)
		if ts > now {
			ts = now
		}
		result[key] = ts
	}
	return result
}

func EncodeSeen(seen map[SeenKey]int64) []map[string]any {
	keys := make([]SeenKey, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].less(keys[j]) })
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		item := map[string]any{
			"mapping": []string{key.Mapping.Family, key.Mapping.Table, key.Mapping.Set},
			"prefix":  key.Prefix,
			"seen":    seen[key],
		}
		if key.Kind >= 3 {
			item["domain"] = key.Domain
		}
		if key.Kind == 4 {
			item["source_hash"] = key.SourceHash
		}
		out = append(out, item)
	}
	return out
}

type ledgerMaps struct {
	generation string
	owned      map[RouteKey]Route
	pending    map[RouteKey]Route
	auditedAt  any
}

type DeferredState struct {
	paths         map[string]struct{}
	values        map[string]any
	dirty         map[string]struct{}
	lock          sync.Mutex
	ledgers       map[string]*ledgerMaps
	prefixIndexes map[string]*PrefixIndex
	lazy          map[string]func() any
}

func NewDeferredState(paths []string) *DeferredState {
	s := &DeferredState{
		paths:         map[string]struct{}{},
		values:        map[string]any{},
		dirty:         map[string]struct{}{},
		ledgers:       map[string]*ledgerMaps{},
		prefixIndexes: map[string]*PrefixIndex{},
		lazy:          map[string]func() any{},
	}
	for _, p := range paths {
		s.paths[filepath.Clean(p)] = struct{}{}
	}
	return s
}

func (s *DeferredState) Enter() {
	stateMu.Lock()
	stateStore = s
	stateMu.Unlock()
}

func (s *DeferredState) Exit() error {
	err := s.Flush()
	stateMu.Lock()
	if stateStore == s {
		stateStore = nil
	}
	stateMu.Unlock()
	return err
}

func (s *DeferredState) Handles(path string) bool {
	_, ok := s.paths[filepath.Clean(path)]
	return ok
}

func (s *DeferredState) Defer(path string, snapshot func() any) {
	s.lock.Lock()
	defer s.lock.Unlock()
	key := filepath.Clean(path)
	s.lazy[key] = snapshot
	s.dirty[key] = struct{}{}
}

func (s *DeferredState) Ledger(path, generation string) (owned, pending map[RouteKey]Route, index *PrefixIndex, err error) {
	key := filepath.Clean(path)
	entry, ok := s.ledgers[key]
	if !ok {
		state := s.values[key]
		if state == nil {
			state = readJSONFile(path, map[string]any{})
		}
		obj, _ := state.(map[string]any)
		if obj == nil {
			obj = map[string]any{}
		}
		if len(obj) > 0 {
			n, convErr := asInt(obj["version"])
			if convErr != nil || n != 1 {
				return nil, nil, nil, fmt.Errorf("unsupported state version")
			}
		}
		owned, pending = mapsFromState(obj, generation)
		entry = &ledgerMaps{generation: generation, owned: owned, pending: pending, auditedAt: obj["audited_at"]}
		if gen, _ := obj["generation"].(string); gen != generation {
			entry.owned, entry.pending, entry.auditedAt = map[RouteKey]Route{}, map[RouteKey]Route{}, nil
		}
		s.ledgers[key] = entry
	}
	if entry.generation != generation {
		entry.generation = generation
		entry.owned, entry.pending, entry.auditedAt = map[RouteKey]Route{}, map[RouteKey]Route{}, nil
		delete(s.prefixIndexes, key)
	}
	if s.prefixIndexes[key] == nil {
		index := NewPrefixIndex()
		for _, routes := range []map[RouteKey]Route{entry.owned, entry.pending} {
			for _, route := range routes {
				index.Add(route.PrefixNet(), route.Key(), route.Table)
			}
		}
		s.prefixIndexes[key] = index
	}
	return entry.owned, entry.pending, s.prefixIndexes[key], nil
}

func (s *DeferredState) snapshot(key string) any {
	if entry, ok := s.ledgers[key]; ok {
		state := map[string]any{
			"version":     1,
			"generation":  entry.generation,
			"owned":       routesToJSON(sortedRouteValues(entry.owned)),
			"pending_add": routesToJSON(sortedRouteValues(entry.pending)),
		}
		if entry.auditedAt != nil {
			state["audited_at"] = entry.auditedAt
		}
		return state
	}
	return cloneJSON(s.values[key])
}

func (s *DeferredState) Read(path string, defaultValue any) any {
	key := filepath.Clean(path)
	s.lock.Lock()
	snapshot := s.lazy[key]
	if _, has := s.values[key]; !has && s.ledgers[key] == nil && snapshot == nil {
		s.values[key] = readJSONFile(path, defaultValue)
	}
	if snapshot == nil {
		out := s.snapshot(key)
		s.lock.Unlock()
		return out
	}
	s.lock.Unlock()
	return snapshot()
}

func (s *DeferredState) Write(path string, value any) {
	key := filepath.Clean(path)
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.ledgers, key)
	delete(s.prefixIndexes, key)
	delete(s.lazy, key)
	s.values[key] = cloneJSON(value)
	s.dirty[key] = struct{}{}
}

func (s *DeferredState) Flush() error {
	s.lock.Lock()
	pending := map[string]any{}
	for key := range s.dirty {
		if snap := s.lazy[key]; snap != nil {
			pending[key] = snap
		} else {
			pending[key] = s.snapshot(key)
		}
	}
	s.dirty = map[string]struct{}{}
	s.lock.Unlock()
	for key, value := range pending {
		if fn, ok := value.(func() any); ok {
			value = fn()
		}
		if err := durableJSON(key, value); err != nil {
			s.lock.Lock()
			for k := range pending {
				s.dirty[k] = struct{}{}
			}
			s.lock.Unlock()
			return err
		}
	}
	return nil
}

func currentStore() *DeferredState {
	stateMu.Lock()
	defer stateMu.Unlock()
	return stateStore
}

func ReadJSON(path string, defaultValue any) any {
	if s := currentStore(); s != nil && s.Handles(path) {
		return s.Read(path, defaultValue)
	}
	return readJSONFile(path, defaultValue)
}

func AtomicJSON(path string, value any) error {
	if s := currentStore(); s != nil && s.Handles(path) {
		s.Write(path, value)
		return nil
	}
	return durableJSON(path, value)
}

func readJSONFile(path string, defaultValue any) any {
	data, err := os.ReadFile(path)
	if err != nil {
		return defaultValue
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return defaultValue
	}
	return v
}

func durableJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	dump, err := canonicalDump(cloneJSON(value))
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.WriteString(dump + "\n"); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func cloneJSON(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func routeFromJSON(item any) (Route, bool) {
	obj, ok := item.(map[string]any)
	if !ok {
		return Route{}, false
	}
	table, err := asInt(obj["table"])
	if err != nil {
		return Route{}, false
	}
	return Route{
		Table:     uint32(table),
		Prefix:    fmt.Sprint(obj["prefix"]),
		Via:       fmt.Sprint(obj["via"]),
		Interface: fmt.Sprint(obj["interface"]),
	}, true
}

func routesToJSON(routes []Route) []map[string]any {
	out := make([]map[string]any, 0, len(routes))
	for _, r := range routes {
		out = append(out, map[string]any{
			"table": r.Table, "prefix": r.Prefix, "via": r.Via, "interface": r.Interface,
		})
	}
	return out
}

func sortedRouteValues(m map[RouteKey]Route) []Route {
	out := make([]Route, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sortRoutes(out)
	return out
}

func mapsFromState(state map[string]any, generation string) (owned, pending map[RouteKey]Route) {
	owned, pending = map[RouteKey]Route{}, map[RouteKey]Route{}
	gen, _ := state["generation"].(string)
	if gen != generation {
		return
	}
	if arr, ok := state["owned"].([]any); ok {
		for _, item := range arr {
			if r, ok := routeFromJSON(item); ok {
				owned[r.Key()] = r
			}
		}
	}
	if arr, ok := state["pending_add"].([]any); ok {
		for _, item := range arr {
			if r, ok := routeFromJSON(item); ok {
				pending[r.Key()] = r
			}
		}
	}
	return
}

func splitState(path, generation string) (map[string]any, map[RouteKey]Route, map[RouteKey]Route, error) {
	raw := ReadJSON(path, map[string]any{})
	state, _ := raw.(map[string]any)
	if state == nil {
		state = map[string]any{}
	}
	if len(state) > 0 {
		if v := state["version"]; v != nil {
			n, err := asInt(v)
			if err != nil || n != 1 {
				return nil, nil, nil, fmt.Errorf("unsupported state version")
			}
		}
	}
	owned, pending := mapsFromState(state, generation)
	return state, owned, pending, nil
}

type PrefixLocks struct {
	guard sync.Mutex
	locks map[RouteKey]*lockEntry
}

type lockEntry struct {
	sem   chan struct{}
	count int
}

func NewPrefixLocks() *PrefixLocks {
	return &PrefixLocks{locks: map[RouteKey]*lockEntry{}}
}

func (p *PrefixLocks) Hold(keys []RouteKey) func() {
	release, _ := p.HoldContext(context.Background(), keys)
	return release
}

func (p *PrefixLocks) HoldContext(ctx context.Context, keys []RouteKey) (func(), error) {
	ordered := uniqueSortedKeys(keys)
	if len(ordered) == 0 {
		return func() {}, nil
	}
	type ref struct {
		key RouteKey
		sem chan struct{}
	}
	refs := make([]ref, 0, len(ordered))
	p.guard.Lock()
	for _, key := range ordered {
		e := p.locks[key]
		if e == nil {
			e = &lockEntry{sem: make(chan struct{}, 1)}
			p.locks[key] = e
		}
		e.count++
		refs = append(refs, ref{key, e.sem})
	}
	p.guard.Unlock()
	acquired := 0
	release := func() {
		for i := acquired - 1; i >= 0; i-- {
			<-refs[i].sem
		}
		p.guard.Lock()
		for _, r := range refs {
			e := p.locks[r.key]
			if e.count <= 1 {
				delete(p.locks, r.key)
			} else {
				e.count--
			}
		}
		p.guard.Unlock()
	}
	for _, r := range refs {
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		select {
		case r.sem <- struct{}{}:
			acquired++
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}

func uniqueSortedKeys(keys []RouteKey) []RouteKey {
	seen := map[RouteKey]struct{}{}
	var out []RouteKey
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return out[i].Prefix < out[j].Prefix
	})
	return out
}

func sharedLockFiles(paths []string) (func(), error) {
	return sharedLockFilesContext(context.Background(), paths)
}

func sharedLockFilesContext(ctx context.Context, paths []string) (func(), error) {
	uniq := append([]string{}, paths...)
	sort.Strings(uniq)
	seen := map[string]struct{}{}
	var files []*os.File
	closeAll := func() {
		for i := len(files) - 1; i >= 0; i-- {
			_ = syscall.Flock(int(files[i].Fd()), syscall.LOCK_UN)
			files[i].Close()
		}
	}
	for _, name := range uniq {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			closeAll()
			return nil, err
		}
		for {
			if err := ctx.Err(); err != nil {
				f.Close()
				closeAll()
				return nil, err
			}
			err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
			if err == nil {
				break
			}
			if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
				f.Close()
				closeAll()
				return nil, err
			}
			select {
			case <-ctx.Done():
				f.Close()
				closeAll()
				return nil, ctx.Err()
			case <-time.After(25 * time.Millisecond):
			}
		}
		files = append(files, f)
	}
	return closeAll, nil
}

type fileStamp struct {
	Path  string
	Mtime int64
	Ctime int64
	Size  int64
	Ino   uint64
}

func stampOf(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	s := fileStamp{Path: path, Size: info.Size(), Mtime: info.ModTime().UnixNano()}
	if ok {
		s.Ino = st.Ino
		s.Ctime = ctimeNano(st)
		s.Mtime = mtimeNano(st)
	}
	return s, nil
}
