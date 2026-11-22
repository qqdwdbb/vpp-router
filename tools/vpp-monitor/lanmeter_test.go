package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.fd.io/govpp/adapter"
)

// counters builds an ACL's per-rule bytes, split over two threads.
func counters(bytes ...uint64) adapter.CombinedCounterStat {
	a, b := make([]adapter.CombinedCounter, len(bytes)), make([]adapter.CombinedCounter, len(bytes))
	for i, v := range bytes {
		a[i] = adapter.CombinedCounter{1, v / 2}
		b[i] = adapter.CombinedCounter{1, v - v/2}
	}
	return adapter.CombinedCounterStat{a, b}
}

func TestLANMeterRatesPerAddressAndHistoryPerMAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meter.json")
	totalsPath := filepath.Join(dir, "totals.json")
	write := func(text string) {
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rules := `"local_prefixes":["10.61.30.0/24"],"rules":[{"address":"10.61.30.20","mac":"aa:00:00:00:00:01"},{"address":"2001:db8::20","mac":"aa:00:00:00:00:01"},{"address":"10.61.30.30","mac":"aa:00:00:00:00:02"}]`
	write(`{"enabled":true,"generation":1,"interface":"loop0","acl_in":12,"acl_out":13,` + rules + `}`)
	stats := &fakeStats{}
	m := newLANMeter(path, totalsPath)
	const mac = "aa:00:00:00:00:01"
	gauges := map[string]float64{}
	gauge := func(key string, v float64) { gauges[key] = v }
	at := time.Unix(1000, 0)
	read := func(up, down adapter.CombinedCounterStat, after time.Duration) *LANTraffic {
		at = at.Add(after)
		withLocal := func(data adapter.CombinedCounterStat) adapter.CombinedCounterStat {
			for i, thread := range data {
				data[i] = append([]adapter.CombinedCounter{{1, uint64(at.Unix()) * 1000000}}, thread...)
			}
			return data
		}
		stats.slow = []adapter.StatEntry{entry("/acl/12/matches", withLocal(up)), entry("/acl/13/matches", withLocal(down))}
		m.read(stats, at, gauge)
		return m.Traffic()
	}
	// Three device rules, then the two permits for everything else.
	first := read(counters(1000, 0, 500, 0, 0), counters(4000, 0, 100, 0, 0), 0)
	if !first.Enabled || first.Ready || len(first.Rates) != 3 || len(gauges) != 0 {
		t.Fatalf("first reading %+v %v", first, gauges)
	}
	second := read(counters(11000, 2000, 500, 800, 0), counters(104000, 10000, 100, 0, 1600), 10*time.Second)
	if !second.Ready || second.Rates[0].UpBps != 8000 || second.Rates[0].DownBps != 80000 || second.Rates[1].DownBps != 8000 ||
		second.Rates[2].UpBps != 0 || second.OtherUpBps != 640 || second.OtherDownBps != 1280 {
		t.Fatalf("second reading %+v", second)
	}
	// History is per MAC: a device with two addresses is their sum.
	if gauges["lan/up/aa:00:00:00:00:01"] != 9600 || gauges["lan/down/aa:00:00:00:00:01"] != 88000 || gauges["lan/down/aa:00:00:00:00:02"] != 0 {
		t.Fatalf("gauges %v", gauges)
	}
	// Only the MAC that moved traffic counts as seen.
	if second.Active["aa:00:00:00:00:01"] != at.Unix() || second.Active["aa:00:00:00:00:02"] != 0 {
		t.Fatalf("active %v", second.Active)
	}
	if second.Totals[mac] != (LANBytes{Up: 12000, Down: 110000}) || second.TotalsSince != 1000 {
		t.Fatalf("totals %+v since %d", second.Totals, second.TotalsSince)
	}
	if first.Totals[mac] != (LANBytes{}) {
		t.Fatalf("first snapshot changed: %+v", first.Totals)
	}
	if _, err := os.Stat(totalsPath); !os.IsNotExist(err) {
		t.Fatalf("read wrote a checkpoint: %v", err)
	}
	m.totals.save()
	m = newLANMeter(path, totalsPath)
	restarted := read(counters(12000, 2000, 500, 800, 0), counters(104000, 12000, 100, 0, 1600), 10*time.Second)
	if restarted.Ready || restarted.Totals[mac] != (LANBytes{Up: 13000, Down: 112000}) || restarted.TotalsSince != 1000 {
		t.Fatalf("after monitor restart %+v", restarted)
	}
	// New rules start the counters over: no rate, no sample, until the next reading.
	write(`{"enabled":true,"generation":2,"interface":"loop0","acl_in":12,"acl_out":13,` + rules + `}`)
	gauges = map[string]float64{}
	third := read(counters(10, 0, 0, 0, 0), counters(10, 0, 0, 0, 0), 10*time.Second)
	if third.Ready || third.Rates[0].UpBps != 0 || len(gauges) != 0 {
		t.Fatalf("after new rules %+v %v", third, gauges)
	}
	if third.Totals[mac] != restarted.Totals[mac] {
		t.Fatalf("new rules changed totals: %+v", third.Totals)
	}
	// Counters that go backwards (VPP restarted the same ACLs) give 0, not a spike.
	fourth := read(counters(0, 0, 0, 0, 0), counters(5, 0, 0, 0, 0), 10*time.Second)
	if !fourth.Ready || fourth.Rates[0].UpBps != 0 || fourth.Rates[0].DownBps != 0 {
		t.Fatalf("backwards %+v", fourth)
	}
	// Off, or no file: nothing, and nothing read from VPP.
	write(`{"enabled":false,"acl_in":4294967295,"acl_out":4294967295,"rules":[]}`)
	if off := read(nil, nil, 10*time.Second); off.Enabled || len(off.Rates) != 0 || off.Totals[mac] != restarted.Totals[mac] {
		t.Fatalf("off %+v", off)
	}
	os.Remove(path)
	if gone := read(nil, nil, 10*time.Second); gone.Enabled || gone.Error != "" {
		t.Fatalf("no file %+v", gone)
	}
	// Fewer counters than rules: vpp-interfaces is still updating.
	write(`{"enabled":true,"generation":3,"acl_in":12,"acl_out":13,` + rules + `}`)
	if short := read(counters(1), counters(1), 10*time.Second); short.Error == "" {
		t.Fatal("short counters accepted")
	}
}
