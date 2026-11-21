package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"go.fd.io/govpp/adapter"
)

// The states shown on the dashboard.
const (
	stateUp      = "up"
	stateStalled = "stalled"
	stateDown    = "down"
)

const (
	reconnectDelay = 2 * time.Second
	// tickOffset keeps a tick away from a slot boundary, so jitter cannot move it into the next slot.
	tickOffset = 100 * time.Millisecond
	maxErrors  = 128 // error counters given a history
	errorRows  = 50
	nodeRows   = 30
)

// Interface counters read every fast tick. They are written by the workers as packets
// pass, so they are current at any interval. The anchored names leave out the /interfaces/
// symlinks, and with PrepareDir the read costs no directory scan.
var fastPatterns = []string{`^/if/(names|rx|tx|drops|punt|rx-miss|rx-no-buf|rx-error|tx-error)$`}

// Everything else is read with DumpStats at the slow interval, which also copes with the
// symlinks under /err/: GoVPP's UpdateDir does not follow them. /net/ stays out, its
// per-route counters would dominate the read on a host with a large FIB.
var slowPatterns = []string{`^/sys/`, `^/buffer-pools/`, `^/mem/`, `^/err/`, `^/nat44-(ei|ed)/total-(users|sessions)$`}

var natGauge = regexp.MustCompile(`^/nat44-(ei|ed)/total-(users|sessions)$`)

const (
	mRxPackets = iota
	mRxBytes
	mTxPackets
	mTxBytes
	mDrops
	mRxMiss
	mRxNoBuf
	mRxError
	mTxError
	mPunt
	numMetrics
)

var metricNames = [numMetrics]string{"rx_pps", "rx_bps", "tx_pps", "tx_bps", "drops", "rx_miss", "rx_no_buf", "rx_error", "tx_error", "punt"}

// IfaceRow is the current rate of one interface, per second and in bits for bandwidth.
type IfaceRow struct {
	Name    string  `json:"name"`
	Label   string  `json:"label,omitempty"`  // a readable name, for TAPs and loopbacks
	Hidden  bool    `json:"hidden,omitempty"` // an idle placeholder, left out of the lists
	RxBps   float64 `json:"rx_bps"`
	TxBps   float64 `json:"tx_bps"`
	RxPps   float64 `json:"rx_pps"`
	TxPps   float64 `json:"tx_pps"`
	Drops   float64 `json:"drops"`
	RxMiss  float64 `json:"rx_miss"`
	RxNoBuf float64 `json:"rx_no_buf"`
	RxError float64 `json:"rx_error"`
	TxError float64 `json:"tx_error"`
	Punt    float64 `json:"punt"`
}

type ErrorRow struct {
	Key    string  `json:"key"`
	Node   string  `json:"node"`
	Reason string  `json:"reason"`
	Rate   float64 `json:"rate"`
	Total  uint64  `json:"total"`
	Normal bool    `json:"normal"`
}

type NodeRow struct {
	Name           string  `json:"name"`
	VectorsPerSec  float64 `json:"vectors_per_sec"`
	CallsPerSec    float64 `json:"calls_per_sec"`
	ClocksPerVec   float64 `json:"clocks_per_vector"`
	VectorsPerCall float64 `json:"vectors_per_call"`
}

type BufferRow struct {
	Pool      string  `json:"pool"`
	Used      float64 `json:"used"`
	Cached    float64 `json:"cached"`
	Available float64 `json:"available"`
}

type HeapRow struct {
	Name  string  `json:"name"`
	Used  float64 `json:"used"`
	Total float64 `json:"total"`
}

type GaugeRow struct {
	Key   string  `json:"key"`
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

// Status is what the dashboard shows as current values.
type Status struct {
	State            string      `json:"state"`
	Detail           string      `json:"detail"`
	Time             int64       `json:"time"`
	Workers          int         `json:"workers"`
	VectorRate       float64     `json:"vector_rate"`
	InputRate        float64     `json:"input_rate"`
	WorkerRates      []float64   `json:"worker_rates"`
	Interfaces       []IfaceRow  `json:"interfaces"`
	Errors           []ErrorRow  `json:"errors"`
	Nodes            []NodeRow   `json:"nodes"`
	NodesEnabled     bool        `json:"nodes_enabled"`
	Buffers          []BufferRow `json:"buffers"`
	Heaps            []HeapRow   `json:"heaps"`
	Gauges           []GaugeRow  `json:"gauges"`
	SeriesCount      int         `json:"series_count"`
	HistoryBytes     int64       `json:"history_bytes"`
	FastSeconds      int64       `json:"fast_seconds"`
	SlowSeconds      int64       `json:"slow_seconds"`
	ReadMicros       int64       `json:"read_micros"`
	Tiers            []Tier      `json:"tiers"`
	Host             HostStatus  `json:"host"`
	VPPUptimeSeconds float64     `json:"vpp_uptime_seconds"`
	VPPRestarts      int         `json:"vpp_restarts"`
	VPPRuns          []VPPRun    `json:"vpp_runs"`
}

type Config struct {
	Fast       time.Duration
	Slow       time.Duration
	StaleAfter time.Duration
}

type ifaceState struct {
	name   string
	series [numMetrics]*Series
	prev   [numMetrics]uint64
	seen   bool
	row    IfaceRow
}

type errorState struct {
	prev   uint64
	series *Series
}

type nodeState struct {
	name                  string
	clocks, vectors, call uint64
}

// Collector reads the stats segment and feeds the store. It owns all of its fields; only
// status is read from other goroutines.
type Collector struct {
	labels  *InterfaceLabels // nil keeps VPP's names
	cfg     Config
	connect func() (adapter.StatsAPI, error)
	store   *Store

	api         adapter.StatsAPI
	fast        *adapter.StatDir
	nextConnect time.Time
	state       string
	detail      string

	ifaces   []*ifaceState
	current  [numMetrics][]uint64
	lastFast time.Time

	lastSlow time.Time
	errors   map[string]*errorState
	gauges   map[string]*Series

	nodes    []nodeState
	lastNode time.Time

	heartbeat        uint64
	heartbeatSeen    bool
	heartbeatChanged time.Time

	runs       *vppRuns
	host       hostReader
	hostStatus HostStatus

	samples    []Sample
	slowStatus Status
	readMicros int64

	status atomic.Pointer[Status]

	meter *lanMeter // per-device traffic, when vpp-interfaces counts it
}

func NewCollector(cfg Config, store *Store, connect func() (adapter.StatsAPI, error)) *Collector {
	c := &Collector{cfg: cfg, store: store, connect: connect, gauges: make(map[string]*Series), errors: make(map[string]*errorState)}
	c.setState(stateDown, "waiting for VPP")
	c.publish(time.Now().Unix())
	return c
}

// Status returns the latest values. The caller must not change them.
func (c *Collector) Status() *Status { return c.status.Load() }

// Run ticks on interval boundaries until ctx ends.
func (c *Collector) Run(ctx context.Context) {
	// A bad pointer read from shared memory becomes a panic that tick recovers from.
	debug.SetPanicOnFault(true)
	slow := int64(c.cfg.Slow / time.Second)
	for {
		next := time.Now().Truncate(c.cfg.Fast).Add(c.cfg.Fast)
		timer := time.NewTimer(time.Until(next.Add(tickOffset)))
		select {
		case <-ctx.Done():
			timer.Stop()
			if c.api != nil {
				c.api.Disconnect()
			}
			return
		case <-timer.C:
		}
		ts := next.Unix()
		c.tick(time.Now(), ts, ts%slow == 0)
	}
}

func (c *Collector) tick(now time.Time, ts int64, slow bool) {
	defer func() {
		if r := recover(); r != nil {
			c.drop(now, fmt.Sprintf("reading the stats segment failed: %v", r))
			c.publish(ts)
		}
	}()
	c.samples = c.samples[:0]
	if slow {
		c.readHost()
	}
	if c.api == nil && !c.tryConnect(now) {
		c.store.Record(ts, c.samples)
		c.publish(ts)
		return
	}
	started := time.Now()
	if err := c.readFast(now); err != nil {
		c.onReadError(now, err)
	}
	if slow && c.api != nil {
		if err := c.readSlow(now); err != nil {
			c.onReadError(now, err)
		}
		if c.api != nil && c.meter != nil {
			c.meter.read(c.api, now, c.gauge)
		}
	}
	if c.api != nil {
		c.readMicros = time.Since(started).Microseconds()
		c.checkHeartbeat(now)
	}
	c.store.Record(ts, c.samples)
	c.publish(ts)
}

func (c *Collector) readHost() {
	status, gauges := c.host.read()
	c.hostStatus = status
	for _, gauge := range gauges {
		c.gauge(gauge.key, gauge.value)
	}
}

func (c *Collector) tryConnect(now time.Time) bool {
	if now.Before(c.nextConnect) {
		return false
	}
	api, err := c.connect()
	if err != nil {
		c.nextConnect = now.Add(reconnectDelay)
		c.setState(stateDown, err.Error())
		return false
	}
	c.api = api
	c.heartbeatSeen = false
	c.setState(stateUp, "")
	return true
}

// onReadError skips the tick for a busy segment, which is routine while VPP changes its
// directory, and starts over for anything that says the connection is gone.
func (c *Collector) onReadError(now time.Time, err error) {
	if errors.Is(err, adapter.ErrStatsDataBusy) || errors.Is(err, adapter.ErrStatsAccessFailed) {
		return
	}
	c.drop(now, err.Error())
}

// drop forgets the connection and every baseline, so the next reading is not compared
// with counters from a VPP that may no longer exist.
func (c *Collector) drop(now time.Time, reason string) {
	if c.api != nil {
		c.api.Disconnect()
	}
	c.labels.Forget()
	c.api, c.fast, c.ifaces, c.nodes = nil, nil, nil, nil
	c.lastFast, c.lastSlow, c.lastNode = time.Time{}, time.Time{}, time.Time{}
	c.errors = make(map[string]*errorState)
	c.gauges = make(map[string]*Series)
	c.heartbeatSeen = false
	c.slowStatus = Status{}
	c.nextConnect = now.Add(reconnectDelay)
	c.setState(stateDown, reason)
}

func (c *Collector) setState(state, detail string) {
	if state == c.state && detail == c.detail {
		return
	}
	// A state or a reason is logged once, not once per tick.
	log.Printf("VPP stats: %s %s", state, detail)
	c.state, c.detail = state, detail
}

// checkHeartbeat notices a VPP that died without removing its socket. The segment stays
// mapped and reads as frozen counters, which would chart as zero traffic.
func (c *Collector) checkHeartbeat(now time.Time) {
	if !c.heartbeatSeen {
		return
	}
	if now.Sub(c.heartbeatChanged) > c.cfg.StaleAfter {
		c.drop(now, fmt.Sprintf("heartbeat unchanged for %s", c.cfg.StaleAfter))
		c.state = stateStalled
	}
}

func (c *Collector) refreshFast() error {
	if c.fast != nil {
		err := c.api.UpdateDir(c.fast)
		if err == nil {
			return nil
		}
		if errors.Is(err, adapter.ErrStatsDisconnected) || errors.Is(err, adapter.ErrStatsDataBusy) || errors.Is(err, adapter.ErrStatsAccessFailed) {
			return err
		}
		// The directory changed shape, which is normal when interfaces come and go.
		c.fast = nil
	}
	dir, err := c.api.PrepareDir(fastPatterns...)
	if err != nil {
		return err
	}
	c.fast = dir
	return nil
}

func (c *Collector) readFast(now time.Time) error {
	if err := c.refreshFast(); err != nil {
		return err
	}
	var names adapter.NameStat
	for m := range c.current {
		c.current[m] = c.current[m][:0]
	}
	for i := range c.fast.Entries {
		entry := &c.fast.Entries[i]
		switch string(entry.Name) {
		case "/if/names":
			names, _ = entry.Data.(adapter.NameStat)
		case "/if/rx":
			c.sumCombined(entry.Data, mRxPackets, mRxBytes)
		case "/if/tx":
			c.sumCombined(entry.Data, mTxPackets, mTxBytes)
		case "/if/drops":
			c.sumSimple(entry.Data, mDrops)
		case "/if/rx-miss":
			c.sumSimple(entry.Data, mRxMiss)
		case "/if/rx-no-buf":
			c.sumSimple(entry.Data, mRxNoBuf)
		case "/if/rx-error":
			c.sumSimple(entry.Data, mRxError)
		case "/if/tx-error":
			c.sumSimple(entry.Data, mTxError)
		case "/if/punt":
			c.sumSimple(entry.Data, mPunt)
		}
	}
	dt := now.Sub(c.lastFast).Seconds()
	if c.lastFast.IsZero() {
		dt = 0
	}
	c.lastFast = now
	c.applyInterfaces(names, dt)
	return nil
}

func (c *Collector) sumSimple(data adapter.Stat, metric int) {
	stat, ok := data.(adapter.SimpleCounterStat)
	if !ok {
		return
	}
	for _, worker := range stat {
		c.current[metric] = grow(c.current[metric], len(worker))
		for i, value := range worker {
			c.current[metric][i] += uint64(value)
		}
	}
}

func (c *Collector) sumCombined(data adapter.Stat, packets, bytes int) {
	stat, ok := data.(adapter.CombinedCounterStat)
	if !ok {
		return
	}
	for _, worker := range stat {
		c.current[packets] = grow(c.current[packets], len(worker))
		c.current[bytes] = grow(c.current[bytes], len(worker))
		for i, value := range worker {
			c.current[packets][i] += value.Packets()
			c.current[bytes][i] += value.Bytes()
		}
	}
}

// grow extends values to n, with the new elements zero.
func grow(values []uint64, n int) []uint64 {
	for len(values) < n {
		values = append(values, 0)
	}
	return values
}

// deletedInterface says whether a slot of /if/names belongs to a deleted interface: VPP
// names it "deleted" (vnet/interface/stats.c), and a slot never filled is empty.
func deletedInterface(raw adapter.Name) bool {
	return len(raw) == 0 || string(raw) == "deleted"
}

func (c *Collector) applyInterfaces(names adapter.NameStat, dt float64) {
	for len(c.ifaces) < len(names) {
		c.ifaces = append(c.ifaces, nil)
	}
	current := make([]string, 0, len(names))
	for _, raw := range names {
		if !deletedInterface(raw) {
			current = append(current, string(raw))
		}
	}
	c.labels.Refresh(labelKey(current))
	for index, raw := range names {
		// Deleted interfaces keep their index; a later one may reuse it.
		if deletedInterface(raw) {
			c.ifaces[index] = nil
			continue
		}
		state := c.ifaces[index]
		if state == nil || state.name != string(raw) {
			state = c.newInterface(string(raw))
			c.ifaces[index] = state
		}
		info := c.labels.Info(state.name)
		state.row.Label = info.Label
		idle := true
		for metric := 0; metric < numMetrics; metric++ {
			var value uint64
			if index < len(c.current[metric]) {
				value = c.current[metric][index]
			}
			idle = idle && value == 0
			rate, ok := rateOf(value, state.prev[metric], state.seen, dt)
			state.prev[metric] = value
			if !ok {
				rate = math.NaN()
			} else {
				if metric == mRxBytes || metric == mTxBytes {
					rate *= 8
				}
				c.samples = append(c.samples, Sample{S: state.series[metric], V: rate})
			}
			state.setRate(metric, rate)
		}
		state.row.Hidden = info.Placeholder && idle
		state.seen = true
	}
	for index := len(names); index < len(c.ifaces); index++ {
		c.ifaces[index] = nil
	}
}

func (c *Collector) newInterface(name string) *ifaceState {
	state := &ifaceState{name: name, row: IfaceRow{Name: name}}
	for metric, suffix := range metricNames {
		state.series[metric] = c.store.Handle("if/"+name+"/"+suffix, 0)
	}
	return state
}

func (s *ifaceState) setRate(metric int, rate float64) {
	if math.IsNaN(rate) {
		rate = 0
	}
	switch metric {
	case mRxPackets:
		s.row.RxPps = rate
	case mRxBytes:
		s.row.RxBps = rate
	case mTxPackets:
		s.row.TxPps = rate
	case mTxBytes:
		s.row.TxBps = rate
	case mDrops:
		s.row.Drops = rate
	case mRxMiss:
		s.row.RxMiss = rate
	case mRxNoBuf:
		s.row.RxNoBuf = rate
	case mRxError:
		s.row.RxError = rate
	case mTxError:
		s.row.TxError = rate
	case mPunt:
		s.row.Punt = rate
	}
}

// rateOf returns the rate since the previous reading. A counter that went backwards was
// cleared or VPP restarted; that interval has no meaningful rate.
func rateOf(value, previous uint64, seen bool, dt float64) (float64, bool) {
	if !seen || dt <= 0 || value < previous {
		return 0, false
	}
	return float64(value-previous) / dt, true
}

func (c *Collector) gauge(key string, value float64) {
	series, ok := c.gauges[key]
	if !ok {
		series = c.store.Handle(key, 1)
		c.gauges[key] = series
	}
	c.samples = append(c.samples, Sample{S: series, V: value})
}

func (c *Collector) readSlow(now time.Time) error {
	entries, err := c.api.DumpStats(slowPatterns...)
	if err != nil {
		return err
	}
	dt := now.Sub(c.lastSlow).Seconds()
	if c.lastSlow.IsZero() {
		dt = 0
	}
	c.lastSlow = now

	var next Status
	var boot int64
	var nodeNames adapter.NameStat
	var clocks, vectors, calls adapter.SimpleCounterStat
	buffers := map[string]*BufferRow{}
	var errorRowsAll []ErrorRow
	for i := range entries {
		entry := &entries[i]
		name := string(entry.Name)
		switch {
		case strings.HasPrefix(name, "/err/"):
			if row, ok := c.readError(name, entry.Data, dt); ok {
				errorRowsAll = append(errorRowsAll, row)
			}
		case strings.HasPrefix(name, "/buffer-pools/"):
			readBuffer(name, entry.Data, buffers)
		case name == "/sys/boottime":
			boot = int64(scalar(entry.Data))
		case name == "/sys/last_update":
			next.VPPUptimeSeconds = scalar(entry.Data)
		case name == "/sys/heartbeat":
			c.noteHeartbeat(now, entry.Data)
		case name == "/sys/vector_rate":
			next.VectorRate = scalar(entry.Data)
			c.gauge("sys/vector_rate", next.VectorRate)
		case name == "/sys/input_rate":
			next.InputRate = scalar(entry.Data)
			c.gauge("sys/input_rate", next.InputRate)
		case name == "/sys/num_worker_threads":
			next.Workers = int(scalar(entry.Data))
		case name == "/sys/vector_rate_per_worker":
			next.WorkerRates = c.readWorkerRates(entry.Data)
		case name == "/sys/node/names":
			nodeNames, _ = entry.Data.(adapter.NameStat)
		case name == "/sys/node/clocks":
			clocks, _ = entry.Data.(adapter.SimpleCounterStat)
		case name == "/sys/node/vectors":
			vectors, _ = entry.Data.(adapter.SimpleCounterStat)
		case name == "/sys/node/calls":
			calls, _ = entry.Data.(adapter.SimpleCounterStat)
		case name == "/mem/main heap" || name == "/mem/stat segment":
			next.Heaps = append(next.Heaps, c.readHeap(strings.TrimPrefix(name, "/mem/"), entry.Data))
		case natGauge.MatchString(name):
			key := "nat" + strings.TrimPrefix(name, "/nat44")
			value := float64(sumAny(entry.Data))
			c.gauge(key, value)
			next.Gauges = append(next.Gauges, GaugeRow{Key: key, Name: strings.TrimPrefix(name, "/"), Value: value})
		}
	}
	for _, pool := range sortedKeys(buffers) {
		row := buffers[pool]
		c.gauge("buf/"+pool+"/used", row.Used)
		c.gauge("buf/"+pool+"/available", row.Available)
		next.Buffers = append(next.Buffers, *row)
	}
	sort.Slice(errorRowsAll, func(i, j int) bool {
		if errorRowsAll[i].Normal != errorRowsAll[j].Normal {
			return errorRowsAll[j].Normal
		}
		if errorRowsAll[i].Rate != errorRowsAll[j].Rate {
			return errorRowsAll[i].Rate > errorRowsAll[j].Rate
		}
		if errorRowsAll[i].Total != errorRowsAll[j].Total {
			return errorRowsAll[i].Total > errorRowsAll[j].Total
		}
		return errorRowsAll[i].Key < errorRowsAll[j].Key
	})
	if len(errorRowsAll) > errorRows {
		errorRowsAll = errorRowsAll[:errorRows]
	}
	next.Errors = errorRowsAll
	sort.Slice(next.Gauges, func(i, j int) bool { return next.Gauges[i].Key < next.Gauges[j].Key })
	if c.runs != nil {
		c.runs.observe(boot, next.VPPUptimeSeconds, now)
	}
	next.Nodes, next.NodesEnabled = c.readNodes(now, nodeNames, clocks, vectors, calls)
	c.slowStatus = next
	return nil
}

func (c *Collector) noteHeartbeat(now time.Time, data adapter.Stat) {
	value := uint64(scalar(data))
	if !c.heartbeatSeen || value != c.heartbeat {
		c.heartbeat, c.heartbeatChanged, c.heartbeatSeen = value, now, true
	}
}

func (c *Collector) readWorkerRates(data adapter.Stat) []float64 {
	stat, ok := data.(adapter.SimpleCounterStat)
	if !ok {
		return nil
	}
	// VPP's main thread writes this one, so the threads are the inner index, not the outer.
	var rates []float64
	for _, values := range stat {
		for thread, value := range values {
			if thread == len(rates) {
				rates = append(rates, 0)
			}
			rates[thread] += float64(value)
		}
	}
	for thread, rate := range rates {
		c.gauge(fmt.Sprintf("sys/worker/%d/vector_rate", thread), rate)
	}
	return rates
}

func (c *Collector) readHeap(name string, data adapter.Stat) HeapRow {
	row := HeapRow{Name: name}
	if stat, ok := data.(adapter.SimpleCounterStat); ok {
		for _, heap := range stat {
			if len(heap) > 1 {
				row.Total += float64(heap[0])
				row.Used += float64(heap[1])
			}
		}
	}
	c.gauge("mem/"+name+"/used", row.Used)
	return row
}

func readBuffer(name string, data adapter.Stat, buffers map[string]*BufferRow) {
	rest := strings.TrimPrefix(name, "/buffer-pools/")
	cut := strings.LastIndexByte(rest, '/')
	if cut <= 0 {
		return
	}
	pool, field := rest[:cut], rest[cut+1:]
	row := buffers[pool]
	if row == nil {
		row = &BufferRow{Pool: pool}
		buffers[pool] = row
	}
	switch field {
	case "used":
		row.Used = scalar(data)
	case "cached":
		row.Cached = scalar(data)
	case "available":
		row.Available = scalar(data)
	}
}

func (c *Collector) readError(name string, data adapter.Stat, dt float64) (ErrorRow, bool) {
	total, known := sumAnyKnown(data)
	if !known {
		return ErrorRow{}, false
	}
	state := c.errors[name]
	if state == nil {
		state = &errorState{prev: total}
		c.errors[name] = state
		// The first reading is the baseline, the rate needs a second one.
		dt = 0
	}
	rate, ok := rateOf(total, state.prev, dt > 0, dt)
	state.prev = total
	rest := strings.TrimPrefix(name, "/err/")
	node, reason, _ := strings.Cut(rest, "/")
	normal := isNormalCounter(reason)
	// The limited histories go to the counters someone would want to look into.
	if ok && rate > 0 && state.series == nil && !normal && c.errorHistoryCount() < maxErrors {
		state.series = c.store.Handle("err"+strings.TrimPrefix(name, "/err"), 1)
	}
	if ok && state.series != nil {
		c.samples = append(c.samples, Sample{S: state.series, V: rate})
	}
	if total == 0 {
		return ErrorRow{}, false
	}
	key := ""
	if state.series != nil {
		key = state.series.key
	}
	return ErrorRow{Key: key, Node: node, Reason: reason, Rate: rate, Total: total, Normal: normal}, true
}

func (c *Collector) errorHistoryCount() int {
	count := 0
	for _, state := range c.errors {
		if state.series != nil {
			count++
		}
	}
	return count
}

// readNodes reports per-node cost. VPP only refreshes these counters when
// `statseg { per-node-counters on }` is set, and then once per update-interval, so the
// rates run from the last reading that moved.
func (c *Collector) readNodes(now time.Time, names adapter.NameStat, clocks, vectors, calls adapter.SimpleCounterStat) ([]NodeRow, bool) {
	sumClocks, sumVectors, sumCalls := sumNodes(clocks, len(names)), sumNodes(vectors, len(names)), sumNodes(calls, len(names))
	enabled := false
	for _, value := range sumClocks {
		if value != 0 {
			enabled = true
			break
		}
	}
	if !enabled {
		c.nodes, c.lastNode = nil, time.Time{}
		return nil, false
	}
	moved := len(c.nodes) != len(names)
	for i := range names {
		if moved {
			break
		}
		moved = sumClocks[i] != c.nodes[i].clocks
	}
	if !moved {
		return c.slowStatus.Nodes, true
	}
	dt := now.Sub(c.lastNode).Seconds()
	first := c.lastNode.IsZero() || len(c.nodes) != len(names)
	var rows []NodeRow
	type ranked struct {
		row    NodeRow
		clocks float64
	}
	var all []ranked
	if !first && dt > 0 {
		for i, raw := range names {
			if c.nodes[i].name != string(raw) || len(raw) == 0 {
				continue
			}
			if sumVectors[i] < c.nodes[i].vectors || sumCalls[i] < c.nodes[i].call || sumClocks[i] < c.nodes[i].clocks {
				continue
			}
			deltaVectors := float64(sumVectors[i] - c.nodes[i].vectors)
			deltaCalls := float64(sumCalls[i] - c.nodes[i].call)
			deltaClocks := float64(sumClocks[i] - c.nodes[i].clocks)
			if deltaCalls == 0 {
				continue
			}
			row := NodeRow{Name: string(raw), VectorsPerSec: deltaVectors / dt, CallsPerSec: deltaCalls / dt, VectorsPerCall: deltaVectors / deltaCalls}
			if deltaVectors > 0 {
				row.ClocksPerVec = deltaClocks / deltaVectors
			}
			all = append(all, ranked{row: row, clocks: deltaClocks})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].clocks > all[j].clocks })
		if len(all) > nodeRows {
			all = all[:nodeRows]
		}
		rows = make([]NodeRow, len(all))
		for i := range all {
			rows[i] = all[i].row
		}
	}
	if len(c.nodes) != len(names) {
		c.nodes = make([]nodeState, len(names))
	}
	for i, raw := range names {
		c.nodes[i] = nodeState{name: string(raw), clocks: sumClocks[i], vectors: sumVectors[i], call: sumCalls[i]}
	}
	c.lastNode = now
	return rows, true
}

func sumNodes(stat adapter.SimpleCounterStat, n int) []uint64 {
	total := make([]uint64, n)
	for _, worker := range stat {
		for i, value := range worker {
			if i < n {
				total[i] += uint64(value)
			}
		}
	}
	return total
}

func scalar(data adapter.Stat) float64 {
	value, _ := data.(adapter.ScalarStat)
	return float64(value)
}

func sumAny(data adapter.Stat) uint64 {
	total, _ := sumAnyKnown(data)
	return total
}

// sumAnyKnown adds up a counter of any shape: /err/ entries are per-worker vectors on
// current VPP and error-index counters on old ones.
func sumAnyKnown(data adapter.Stat) (uint64, bool) {
	var total uint64
	switch stat := data.(type) {
	case adapter.ScalarStat:
		return uint64(stat), true
	case adapter.ErrorStat:
		for _, value := range stat {
			total += uint64(value)
		}
		return total, true
	case adapter.SimpleCounterStat:
		for _, worker := range stat {
			for _, value := range worker {
				total += uint64(value)
			}
		}
		return total, true
	}
	return 0, false
}

func sortedKeys[V any](items map[string]V) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (c *Collector) publish(ts int64) {
	status := c.slowStatus
	status.State, status.Detail, status.Time = c.state, c.detail, ts
	status.FastSeconds = int64(c.cfg.Fast / time.Second)
	status.SlowSeconds = int64(c.cfg.Slow / time.Second)
	status.ReadMicros = c.readMicros
	status.SeriesCount, status.HistoryBytes = c.store.Usage()
	status.Tiers = c.store.tiers
	status.Host = c.hostStatus
	if c.runs != nil {
		status.VPPRuns, status.VPPRestarts = c.runs.snapshot()
	}
	status.Interfaces = make([]IfaceRow, 0, len(c.ifaces))
	for _, state := range c.ifaces {
		if state != nil {
			status.Interfaces = append(status.Interfaces, state.row)
		}
	}
	c.status.Store(&status)
}
