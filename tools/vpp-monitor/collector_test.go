package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.fd.io/govpp/adapter"
)

// fakeStats stands in for the stats segment.
type fakeStats struct {
	fast         []adapter.StatEntry
	slow         []adapter.StatEntry
	updateErr    error
	prepareCount int
	disconnected bool
}

func (f *fakeStats) Connect() error                                        { return nil }
func (f *fakeStats) Disconnect() error                                     { f.disconnected = true; return nil }
func (f *fakeStats) ListStats(...string) ([]adapter.StatIdentifier, error) { return nil, nil }
func (f *fakeStats) DumpStats(...string) ([]adapter.StatEntry, error)      { return f.slow, nil }
func (f *fakeStats) PrepareDirOnIndex(...uint32) (*adapter.StatDir, error) {
	return nil, errors.New("unused")
}
func (f *fakeStats) PrepareDir(...string) (*adapter.StatDir, error) {
	f.prepareCount++
	return &adapter.StatDir{Entries: f.fast}, nil
}
func (f *fakeStats) UpdateDir(dir *adapter.StatDir) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	dir.Entries = f.fast
	return nil
}

func entry(name string, data adapter.Stat) adapter.StatEntry {
	return adapter.StatEntry{StatIdentifier: adapter.StatIdentifier{Name: []byte(name)}, Data: data}
}

// interfaces builds the fast entries for two workers, each holding half of the counters.
func interfaces(names []string, rxPackets, rxBytes []uint64) []adapter.StatEntry {
	nameStat := make(adapter.NameStat, len(names))
	worker := func(divide uint64) []adapter.CombinedCounter {
		out := make([]adapter.CombinedCounter, len(rxPackets))
		for i := range rxPackets {
			out[i] = adapter.CombinedCounter{rxPackets[i] / divide, rxBytes[i] / divide}
		}
		return out
	}
	for i, name := range names {
		nameStat[i] = adapter.Name(name)
	}
	return []adapter.StatEntry{
		entry("/if/names", nameStat),
		entry("/if/rx", adapter.CombinedCounterStat{worker(2), worker(2)}),
	}
}

func newTestCollector(f *fakeStats) (*Collector, *time.Time) {
	store := NewStore(tiersFor(1, 10))
	c := NewCollector(Config{Fast: time.Second, Slow: 10 * time.Second, StaleAfter: 30 * time.Second}, store,
		func() (adapter.StatsAPI, error) { return f, nil })
	c.host.root = "/nonexistent-root" // keeps the machine running the test out of the samples
	now := time.Unix(1000, 0)
	return c, &now
}

func step(c *Collector, now *time.Time) {
	*now = now.Add(time.Second)
	c.tick(*now, now.Unix(), now.Unix()%10 == 0)
}

func TestInterfaceRatesSumWorkersAndCountBits(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"local0", "eth0"}, []uint64{0, 1000}, []uint64{0, 100000})}
	c, now := newTestCollector(f)
	step(c, now)
	f.fast = interfaces([]string{"local0", "eth0"}, []uint64{0, 1600}, []uint64{0, 160000})
	step(c, now)
	got := c.Status().Interfaces[1]
	if got.Name != "eth0" || got.RxPps != 600 || got.RxBps != 480000 {
		t.Fatalf("row = %+v", got)
	}
}

func TestFirstReadingIsOnlyABaseline(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"eth0"}, []uint64{1 << 40}, []uint64{1 << 50})}
	c, now := newTestCollector(f)
	step(c, now)
	if got := c.Status().Interfaces[0]; got.RxPps != 0 || got.RxBps != 0 {
		t.Fatalf("row = %+v", got)
	}
}

func TestCounterGoingBackwardsIsAGapNotASpike(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"eth0"}, []uint64{5000}, []uint64{5000})}
	c, now := newTestCollector(f)
	step(c, now)
	f.fast = interfaces([]string{"eth0"}, []uint64{10}, []uint64{10})
	step(c, now)
	if len(c.samples) != 0 && c.samples[0].V > 1000 {
		t.Fatalf("spike recorded: %+v", c.samples[0])
	}
	for _, sample := range c.samples {
		if sample.S.key == "if/eth0/rx_pps" {
			t.Fatalf("a sample for the interval with the reset: %+v", sample)
		}
	}
}

func TestReusedIndexStartsAFreshBaseline(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"tap0"}, []uint64{100}, []uint64{100})}
	c, now := newTestCollector(f)
	step(c, now)
	f.fast = interfaces([]string{"tap1"}, []uint64{900}, []uint64{900})
	step(c, now)
	got := c.Status().Interfaces[0]
	if got.Name != "tap1" || got.RxPps != 0 {
		t.Fatalf("row = %+v", got)
	}
}

func TestDeletedInterfaceLeavesTheTable(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"a", "b"}, []uint64{1, 1}, []uint64{1, 1})}
	c, now := newTestCollector(f)
	step(c, now)
	// A slot never filled is empty; VPP names the slot of a deleted interface "deleted".
	for _, gone := range []string{"", "deleted"} {
		f.fast = interfaces([]string{gone, "b"}, []uint64{0, 2}, []uint64{0, 2})
		step(c, now)
		rows := c.Status().Interfaces
		if len(rows) != 1 || rows[0].Name != "b" {
			t.Fatalf("%q: rows = %+v", gone, rows)
		}
	}
}

func TestStaleDirectoryIsPreparedAgain(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"eth0"}, []uint64{1}, []uint64{1})}
	c, now := newTestCollector(f)
	step(c, now)
	f.updateErr = adapter.ErrStatsDirStale
	step(c, now)
	if f.prepareCount != 2 || c.Status().State != stateUp {
		t.Fatalf("prepares = %d, state = %s", f.prepareCount, c.Status().State)
	}
}

func TestBusySegmentKeepsTheConnection(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"eth0"}, []uint64{1}, []uint64{1})}
	c, now := newTestCollector(f)
	step(c, now)
	f.updateErr = adapter.ErrStatsDataBusy
	step(c, now)
	if f.disconnected || c.Status().State != stateUp {
		t.Fatalf("disconnected = %v, state = %s", f.disconnected, c.Status().State)
	}
}

func TestDisconnectReconnectsWithNewBaselines(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"eth0"}, []uint64{1000}, []uint64{1000})}
	c, now := newTestCollector(f)
	step(c, now)
	f.updateErr = adapter.ErrStatsDisconnected
	step(c, now)
	if !f.disconnected || c.Status().State != stateDown {
		t.Fatalf("disconnected = %v, state = %s", f.disconnected, c.Status().State)
	}
	f.updateErr = nil
	f.fast = interfaces([]string{"eth0"}, []uint64{5000}, []uint64{5000})
	*now = now.Add(reconnectDelay)
	step(c, now)
	got := c.Status()
	if got.State != stateUp || got.Interfaces[0].RxPps != 0 {
		t.Fatalf("status = %s %+v", got.State, got.Interfaces)
	}
}

func TestFrozenHeartbeatDropsTheConnection(t *testing.T) {
	f := &fakeStats{slow: []adapter.StatEntry{entry("/sys/heartbeat", adapter.ScalarStat(7))}}
	c, now := newTestCollector(f)
	for i := 0; i < 45 && !f.disconnected; i++ {
		step(c, now)
	}
	if !f.disconnected {
		t.Fatal("a frozen heartbeat was not noticed")
	}
}

func TestPanicWhileReadingDropsTheConnection(t *testing.T) {
	f := &fakeStats{fast: []adapter.StatEntry{entry("/if/names", adapter.NameStat{adapter.Name("a")})}}
	c, now := newTestCollector(f)
	step(c, now)
	c.fast = nil
	c.api = panicking{f}
	step(c, now)
	if c.Status().State != stateDown {
		t.Fatalf("state = %s", c.Status().State)
	}
}

type panicking struct{ *fakeStats }

func (panicking) PrepareDir(...string) (*adapter.StatDir, error) { panic("bad pointer") }

func slowEntries(errorCount uint64) []adapter.StatEntry {
	return []adapter.StatEntry{
		entry("/sys/heartbeat", adapter.ScalarStat(errorCount)),
		entry("/sys/vector_rate", adapter.ScalarStat(12)),
		entry("/sys/input_rate", adapter.ScalarStat(3000)),
		entry("/sys/num_worker_threads", adapter.ScalarStat(2)),
		entry("/sys/vector_rate_per_worker", adapter.SimpleCounterStat{{1, 5, 9}}),
		entry("/buffer-pools/default-numa-0/used", adapter.ScalarStat(100)),
		entry("/buffer-pools/default-numa-0/cached", adapter.ScalarStat(20)),
		entry("/buffer-pools/default-numa-0/available", adapter.ScalarStat(880)),
		entry("/mem/main heap", adapter.SimpleCounterStat{{1000, 400, 600}}),
		entry("/nat44-ei/total-sessions", adapter.SimpleCounterStat{{3}, {4}}),
		entry("/err/ip4-input/ip4 ttl time/expired", adapter.SimpleCounterStat{{adapter.Counter(errorCount)}, {adapter.Counter(errorCount)}}),
		entry("/err/ip4-input/never", adapter.SimpleCounterStat{{0}, {0}}),
	}
}

func stepSlow(c *Collector, now *time.Time) {
	*now = now.Add(10 * time.Second)
	c.tick(*now, now.Unix(), true)
}

func TestSlowCounters(t *testing.T) {
	f := &fakeStats{slow: slowEntries(10)}
	c, now := newTestCollector(f)
	stepSlow(c, now)
	f.slow = slowEntries(60)
	stepSlow(c, now)
	got := c.Status()
	if got.VectorRate != 12 || got.InputRate != 3000 || got.Workers != 2 || len(got.WorkerRates) != 3 || got.WorkerRates[2] != 9 {
		t.Fatalf("system = %+v", got)
	}
	if got.Buffers[0].Pool != "default-numa-0" || got.Buffers[0].Used != 100 || got.Buffers[0].Available != 880 {
		t.Fatalf("buffers = %+v", got.Buffers)
	}
	if got.Heaps[0].Total != 1000 || got.Heaps[0].Used != 400 {
		t.Fatalf("heaps = %+v", got.Heaps)
	}
	if got.Gauges[0].Key != "nat-ei/total-sessions" || got.Gauges[0].Value != 7 {
		t.Fatalf("gauges = %+v", got.Gauges)
	}
	if len(got.Errors) != 1 {
		t.Fatalf("errors = %+v", got.Errors)
	}
	row := got.Errors[0]
	if row.Node != "ip4-input" || row.Reason != "ip4 ttl time/expired" || row.Rate != 10 || row.Total != 120 || row.Key == "" {
		t.Fatalf("error row = %+v", row)
	}
}

func nodeEntries(clocks, vectors, calls uint64) []adapter.StatEntry {
	return []adapter.StatEntry{
		entry("/sys/node/names", adapter.NameStat{adapter.Name("cheap"), adapter.Name("costly"), adapter.Name("idle")}),
		entry("/sys/node/clocks", adapter.SimpleCounterStat{{adapter.Counter(clocks), adapter.Counter(10 * clocks), 0}}),
		entry("/sys/node/vectors", adapter.SimpleCounterStat{{adapter.Counter(vectors), adapter.Counter(vectors), 0}}),
		entry("/sys/node/calls", adapter.SimpleCounterStat{{adapter.Counter(calls), adapter.Counter(calls), 0}}),
	}
}

func TestNodeRatesRankByCost(t *testing.T) {
	f := &fakeStats{slow: nodeEntries(1000, 100, 10)}
	c, now := newTestCollector(f)
	stepSlow(c, now)
	f.slow = nodeEntries(3000, 300, 30)
	stepSlow(c, now)
	got := c.Status()
	if !got.NodesEnabled || len(got.Nodes) != 2 {
		t.Fatalf("nodes = %+v", got)
	}
	top := got.Nodes[0]
	if top.Name != "costly" || top.VectorsPerSec != 20 || top.ClocksPerVec != 100 || top.VectorsPerCall != 10 {
		t.Fatalf("top = %+v", top)
	}
}

func TestNodesKeepTheirRowsBetweenVPPUpdates(t *testing.T) {
	f := &fakeStats{slow: nodeEntries(1000, 100, 10)}
	c, now := newTestCollector(f)
	stepSlow(c, now)
	f.slow = nodeEntries(3000, 300, 30)
	stepSlow(c, now)
	stepSlow(c, now) // VPP has not refreshed the counters yet
	if got := c.Status(); len(got.Nodes) != 2 || got.Nodes[0].VectorsPerSec != 20 {
		t.Fatalf("nodes = %+v", got.Nodes)
	}
	f.slow = nodeEntries(5000, 500, 50)
	stepSlow(c, now)
	if got := c.Status(); got.Nodes[0].VectorsPerSec != 10 {
		t.Fatalf("after two intervals: %+v", got.Nodes)
	}
}

func TestNodesOffWhenCountersAreZero(t *testing.T) {
	f := &fakeStats{slow: nodeEntries(0, 0, 0)}
	c, now := newTestCollector(f)
	stepSlow(c, now)
	if got := c.Status(); got.NodesEnabled || got.Nodes != nil {
		t.Fatalf("nodes = %+v", got)
	}
}

func TestErrorHistoryIsBounded(t *testing.T) {
	var before, after []adapter.StatEntry
	for i := 0; i < maxErrors+20; i++ {
		name := "/err/n/" + strings.Repeat("x", i+1)
		before = append(before, entry(name, adapter.SimpleCounterStat{{1}}))
		after = append(after, entry(name, adapter.SimpleCounterStat{{2}}))
	}
	f := &fakeStats{slow: before}
	c, now := newTestCollector(f)
	stepSlow(c, now)
	f.slow = after
	stepSlow(c, now)
	if got := c.errorHistoryCount(); got != maxErrors {
		t.Fatalf("%d error histories", got)
	}
}

func TestIntervalsAreChecked(t *testing.T) {
	cases := []struct {
		fast, slow, stale time.Duration
		ok                bool
	}{
		{time.Second, 10 * time.Second, 30 * time.Second, true},
		{2 * time.Second, 20 * time.Second, 60 * time.Second, true},
		{500 * time.Millisecond, 10 * time.Second, 30 * time.Second, false},
		{3 * time.Second, 10 * time.Second, 30 * time.Second, false},
		{time.Second, 7 * time.Second, 30 * time.Second, false},
		{time.Second, 10 * time.Second, 10 * time.Second, false},
	}
	for _, tc := range cases {
		if err := checkIntervals(tc.fast, tc.slow, tc.stale); (err == nil) != tc.ok {
			t.Errorf("%v %v %v: %v", tc.fast, tc.slow, tc.stale, err)
		}
	}
}

func TestHandler(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"eth0"}, []uint64{1}, []uint64{1})}
	c, now := newTestCollector(f)
	step(c, now)
	handler := NewHandler(c, c.store, NewNATService(func() (natAPI, error) { return nil, errors.New("unused") }), NewVPNService(&fakeVPN{}, nil))
	cases := []struct {
		url, body string
		code      int
	}{
		{"/", "VPP 控制面板", 200},
		{"/uPlot.iife.min.js", "uPlot", 200},
		{"/login.html", "登录", 200},
		{"/style.css", ":root", 200},
		{"/app.js", "overview", 200},
		{"/pages/overview.js", "export function start", 200},
		{"/pages/exits.js", "export function openNAT", 200},
		{"/lib.js", "export function fetchJSON", 200},
		{"/pages/routes.js", "export function show", 200},
		{"/pages/vpn.js", "export function show", 200},
		{"/routes", "VPP 控制面板", 200},
		{"/vpn", "VPP 控制面板", 200},
		{"/api/vpn", `"wireguard"`, 200},
		{"/api/status", `"name":"eth0"`, 200},
		{"/api/series?range=60&key=if/eth0/rx_bps", `"step":1`, 200},
		{"/api/series?range=abc&key=a", "", 400},
		{"/api/series?range=60", "", 400},
		{"/api/series?range=99999999&key=a", "", 400},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.url, nil))
		if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.body) {
			t.Errorf("%s: %d %.200q", tc.url, w.Code, w.Body.String())
		}
	}
}
