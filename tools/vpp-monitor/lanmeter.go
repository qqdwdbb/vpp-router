package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.fd.io/govpp/adapter"
)

// The LAN meter: vpp-interfaces keeps two ACLs on the ports the LAN devices are on, one rule
// per device address (input by source for upload, output by destination for download), and
// publishes the rules in order. Their per-rule byte counters are in the stats segment, so
// they are read here at the slow interval with the rest, without the VPP API and without
// stopping the workers. Each MAC's rates go into the history like any other series.

// meterFile is what vpp-interfaces publishes.
type meterFile struct {
	Enabled       bool     `json:"enabled"`
	Generation    int64    `json:"generation"`
	Interface     string   `json:"interface"`
	ACLIn         uint32   `json:"acl_in"`
	ACLOut        uint32   `json:"acl_out"`
	LocalPrefixes []string `json:"local_prefixes"`
	Rules         []struct {
		Address string `json:"address"`
		MAC     string `json:"mac"`
	} `json:"rules"`
	Error string `json:"error"`
}

// LANRate is one counted address.
type LANRate struct {
	Address   string  `json:"address"`
	MAC       string  `json:"mac"`
	UpBps     float64 `json:"up_bps"`
	DownBps   float64 `json:"down_bps"`
	UpBytes   uint64  `json:"up_bytes"`
	DownBytes uint64  `json:"down_bytes"`
}

// LANTraffic is what /api/lan/traffic returns.
type LANTraffic struct {
	Enabled   bool      `json:"enabled"`
	Ready     bool      `json:"ready"` // rates need two readings of the same rules
	Error     string    `json:"error,omitempty"`
	Interface string    `json:"interface,omitempty"`
	Time      int64     `json:"time"`
	Rates     []LANRate `json:"rates"`
	// Other is traffic outside the local prefixes that no device rule matched.
	OtherUpBps   float64 `json:"other_up_bps"`
	OtherDownBps float64 `json:"other_down_bps"`
	// Active is when each MAC last moved more than activeBps, since this program started.
	Active      map[string]int64    `json:"active"`
	Totals      map[string]LANBytes `json:"totals"`
	TotalsSince int64               `json:"totals_since,omitempty"`
	TotalsError bool                `json:"totals_error,omitempty"`
}

// activeBps is the rate above which a device counts as seen: more than background chatter.
const activeBps = 1000

type lanMeter struct {
	path string

	key      string // generation and ACLs of the previous reading
	at       time.Time
	up, down []uint64
	active   map[string]int64
	totals   lanTotals

	latest atomic.Pointer[LANTraffic]
}

func newLANMeter(path, totalsPath string) *lanMeter {
	m := &lanMeter{path: path, active: map[string]int64{}, totals: loadLANTotals(totalsPath)}
	m.publish(&LANTraffic{Rates: []LANRate{}})
	return m
}

func (m *lanMeter) publish(result *LANTraffic) {
	result.Active = maps.Clone(m.active)
	result.Totals = maps.Clone(m.totals.ByMAC)
	result.TotalsSince = m.totals.Since
	result.TotalsError = m.totals.loadErr != nil
	m.latest.Store(result)
}

// perRule sums a combined counter over the threads, per rule.
func perRule(data adapter.Stat) []uint64 {
	stat, ok := data.(adapter.CombinedCounterStat)
	if !ok {
		return nil
	}
	var out []uint64
	for _, worker := range stat {
		for len(out) < len(worker) {
			out = append(out, 0)
		}
		for i, value := range worker {
			out[i] += value.Bytes()
		}
	}
	return out
}

// read takes a reading; gauge records a history sample.
func (m *lanMeter) read(api adapter.StatsAPI, now time.Time, gauge func(string, float64)) {
	result := &LANTraffic{Time: now.Unix(), Rates: []LANRate{}}
	defer m.publish(result)
	if m.path == "" {
		return
	}
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		m.key = ""
		return
	}
	var file meterFile
	if err == nil {
		err = json.Unmarshal(data, &file)
	}
	if err != nil {
		result.Error = err.Error()
		m.key = ""
		return
	}
	result.Enabled, result.Error, result.Interface = file.Enabled, file.Error, file.Interface
	if !file.Enabled || file.ACLIn == ^uint32(0) || file.ACLOut == ^uint32(0) {
		m.key = ""
		return
	}
	entries, err := api.DumpStats(fmt.Sprintf(`^/acl/(%d|%d)/matches$`, file.ACLIn, file.ACLOut))
	if err != nil {
		result.Error = "读取 ACL 计数失败：" + err.Error()
		m.key = ""
		return
	}
	var up, down []uint64
	for _, e := range entries {
		switch strings.TrimRight(string(e.Name), "\x00") {
		case fmt.Sprintf("/acl/%d/matches", file.ACLIn):
			up = perRule(e.Data)
		case fmt.Sprintf("/acl/%d/matches", file.ACLOut):
			down = perRule(e.Data)
		}
	}
	n := len(file.Rules)
	offset := len(file.LocalPrefixes)
	if len(up)-offset < n || len(down)-offset < n {
		result.Error = "ACL 计数和规则对不上，等 vpp-interfaces 更新"
		m.key = ""
		return
	}
	up, down = up[offset:], down[offset:]
	key := fmt.Sprintf("%d/%d/%d/%d", file.Generation, file.ACLIn, file.ACLOut, offset)
	if file.Error == "" && offset > 0 {
		m.totals.record(file, key, up, down, now)
	}
	dt := now.Sub(m.at).Seconds()
	ready := key == m.key && dt > 0 && len(m.up) == len(up) && len(m.down) == len(down)
	rate := func(cur []uint64, prev []uint64, i int) float64 {
		if !ready {
			return 0
		}
		return float64(byteDelta(cur[i], prev[i])) * 8 / dt
	}
	byMAC := map[string][2]float64{}
	for i, r := range file.Rules {
		lr := LANRate{Address: r.Address, MAC: r.MAC, UpBps: rate(up, m.up, i), DownBps: rate(down, m.down, i), UpBytes: up[i], DownBytes: down[i]}
		result.Rates = append(result.Rates, lr)
		sum := byMAC[r.MAC]
		byMAC[r.MAC] = [2]float64{sum[0] + lr.UpBps, sum[1] + lr.DownBps}
	}
	for i := n; i < len(up); i++ {
		result.OtherUpBps += rate(up, m.up, i)
	}
	for i := n; i < len(down); i++ {
		result.OtherDownBps += rate(down, m.down, i)
	}
	result.Ready = ready
	if ready {
		for mac, v := range byMAC {
			gauge("lan/up/"+mac, v[0])
			gauge("lan/down/"+mac, v[1])
			if v[0]+v[1] > activeBps {
				m.active[mac] = now.Unix()
			}
		}
	}
	m.key, m.at, m.up, m.down = key, now, up, down
}

func (m *lanMeter) Traffic() *LANTraffic { return m.latest.Load() }
