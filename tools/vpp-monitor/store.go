package main

import (
	"math"
	"strconv"
	"sync"
)

// maxSeries bounds memory if a deployment creates interfaces without end.
const maxSeries = 4096

// retention is how long a series with no samples is kept, the span of the last tier.
const retention = 7 * 24 * 3600

// Tier is one resolution of history: a ring of Size slots, each Step seconds wide.
type Tier struct {
	Step int64 `json:"step"`
	Size int   `json:"size"`
}

// tiersFor returns the history kept for the given intervals: 15 minutes at the fast
// interval, 3 hours at the slow one, then 24 hours and 7 days.
func tiersFor(fast, slow int64) []Tier {
	return []Tier{
		{Step: fast, Size: int(15 * 60 / fast)},
		{Step: slow, Size: int(3 * 3600 / slow)},
		{Step: 60, Size: 24 * 60},
		{Step: 300, Size: 7 * 24 * 12},
	}
}

// Series is the history of one value. A tier's ring is allocated at its first non-zero
// value, because most interface error counters stay at zero for the life of the process.
type Series struct {
	key       string
	minTier   int
	rings     [][]float32
	sum       []float64
	n         []uint32
	firstSeen int64
	lastSeen  int64
}

// Sample is one value for a series, already a rate or a gauge.
type Sample struct {
	S *Series
	V float64
}

// Store keeps every series in memory. A monitor restart loses history, which spares the
// eMMC or SD card of a small host from constant writes.
type Store struct {
	mu     sync.RWMutex
	tiers  []Tier
	series map[string]*Series
	head   []int64 // the slot each tier is filling, not readable yet
	first  []int64 // the oldest slot each tier has data for
	nextGC int64
}

func NewStore(tiers []Tier) *Store {
	return &Store{
		tiers:  tiers,
		series: make(map[string]*Series),
		head:   make([]int64, len(tiers)),
		first:  make([]int64, len(tiers)),
	}
}

// Handle returns the series for key, creating it. minTier is the finest tier the series
// has data for: one sampled at the slow interval would be mostly gaps in the fast tier.
// It returns nil at the series limit, and Record ignores a nil series.
func (s *Store) Handle(key string, minTier int) *Series {
	s.mu.Lock()
	defer s.mu.Unlock()
	if found, ok := s.series[key]; ok {
		return found
	}
	if len(s.series) >= maxSeries {
		return nil
	}
	created := &Series{
		key:     key,
		minTier: minTier,
		rings:   make([][]float32, len(s.tiers)),
		sum:     make([]float64, len(s.tiers)),
		n:       make([]uint32, len(s.tiers)),
	}
	s.series[key] = created
	return created
}

// Record adds the samples taken at ts, in Unix seconds.
func (s *Store) Record(ts int64, samples []Sample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t := range s.tiers {
		s.advance(t, ts/s.tiers[t].Step)
	}
	for _, sample := range samples {
		if sample.S == nil || math.IsNaN(sample.V) {
			continue
		}
		if sample.S.firstSeen == 0 {
			sample.S.firstSeen = ts
		}
		sample.S.lastSeen = ts
		for t := sample.S.minTier; t < len(s.tiers); t++ {
			sample.S.sum[t] += sample.V
			sample.S.n[t]++
		}
	}
	if ts >= s.nextGC {
		s.collect(ts)
		s.nextGC = ts + 3600
	}
}

// advance closes the slots before slot. A small host often has no RTC, so the clock can
// jump: forward is an ordinary gap, while backward by more than a moment restarts the tier.
func (s *Store) advance(t int, slot int64) {
	head := s.head[t]
	if head == 0 || head-slot > 2 {
		for _, series := range s.series {
			series.sum[t], series.n[t] = 0, 0
			series.firstSeen = 0
		}
		s.head[t], s.first[t] = slot, slot
		return
	}
	if slot <= head {
		return
	}
	s.commit(t, head)
	from := head + 1
	if size := int64(s.tiers[t].Size); slot-from > size {
		from = slot - size
	}
	for gap := from; gap < slot; gap++ {
		s.commit(t, gap)
	}
	s.head[t] = slot
}

// commit writes each series' average for the slot, or a gap if it had no samples.
func (s *Store) commit(t int, slot int64) {
	size := s.tiers[t].Size
	index := int(slot % int64(size))
	for _, series := range s.series {
		if t < series.minTier {
			continue
		}
		value := float32(math.NaN())
		if series.n[t] > 0 {
			value = float32(series.sum[t] / float64(series.n[t]))
			series.sum[t], series.n[t] = 0, 0
		}
		if series.rings[t] == nil {
			if value == 0 || value != value {
				continue
			}
			series.rings[t] = make([]float32, size)
		}
		series.rings[t][index] = value
	}
}

func (s *Store) collect(ts int64) {
	for key, series := range s.series {
		if series.lastSeen != 0 && ts-series.lastSeen > retention {
			delete(s.series, key)
		}
	}
}

// Usage returns the number of series and the bytes their rings hold.
func (s *Store) Usage() (series int, bytes int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, one := range s.series {
		for _, ring := range one.rings {
			bytes += int64(len(ring)) * 4
		}
	}
	return len(s.series), bytes
}

// Result is a window of history: Count slots from Start, Step seconds apart.
type Result struct {
	Start  int64
	Step   int64
	Count  int
	Values map[string][]float32
}

// Query returns the last rangeSeconds of the keys that exist, from the finest tier that
// covers the range and that every key has data for. NaN marks a slot with no data.
func (s *Store) Query(keys []string, rangeSeconds int64) Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := 0
	for t < len(s.tiers)-1 && s.tiers[t].Step*int64(s.tiers[t].Size-1) < rangeSeconds {
		t++
	}
	for _, key := range keys {
		if series, ok := s.series[key]; ok && series.minTier > t {
			t = series.minTier
		}
	}
	tier := s.tiers[t]
	count := int(rangeSeconds / tier.Step)
	if count > tier.Size-1 {
		count = tier.Size - 1
	}
	if count < 1 {
		count = 1
	}
	end := s.head[t] - 1
	start := end - int64(count) + 1
	result := Result{Start: start * tier.Step, Step: tier.Step, Count: count, Values: make(map[string][]float32, len(keys))}
	if s.head[t] == 0 {
		result.Start, result.Count = 0, 0
		return result
	}
	nan := float32(math.NaN())
	for _, key := range keys {
		series, ok := s.series[key]
		if !ok {
			continue
		}
		values := make([]float32, count)
		ring := series.rings[t]
		for i := range values {
			slot := start + int64(i)
			switch {
			// A slot that ended before the first sample is unknown, not zero.
			case slot < s.first[t], series.firstSeen == 0, (slot+1)*tier.Step <= series.firstSeen:
				values[i] = nan
			case ring != nil:
				values[i] = ring[int(slot%int64(tier.Size))]
			}
		}
		result.Values[key] = values
	}
	return result
}

// AppendJSON writes the result with a null for each gap, which encoding/json refuses.
func (r Result) AppendJSON(out []byte) []byte {
	out = append(out, `{"start":`...)
	out = strconv.AppendInt(out, r.Start, 10)
	out = append(out, `,"step":`...)
	out = strconv.AppendInt(out, r.Step, 10)
	out = append(out, `,"count":`...)
	out = strconv.AppendInt(out, int64(r.Count), 10)
	out = append(out, `,"values":{`...)
	first := true
	for key, values := range r.Values {
		if !first {
			out = append(out, ',')
		}
		first = false
		out = strconv.AppendQuote(out, key)
		out = append(out, ":["...)
		for i, value := range values {
			if i > 0 {
				out = append(out, ',')
			}
			if value != value {
				out = append(out, "null"...)
			} else {
				out = strconv.AppendFloat(out, float64(value), 'g', 6, 32)
			}
		}
		out = append(out, ']')
	}
	return append(out, "}}"...)
}
