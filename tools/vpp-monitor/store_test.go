package main

import (
	"encoding/json"
	"math"
	"testing"
)

func testStore() *Store {
	return NewStore([]Tier{{Step: 1, Size: 10}, {Step: 10, Size: 10}})
}

func record(s *Store, ts int64, series *Series, value float64) {
	s.Record(ts, []Sample{{S: series, V: value}})
}

func TestQueryReturnsCommittedSlotsInOrder(t *testing.T) {
	s := testStore()
	a := s.Handle("a", 0)
	for ts := int64(1000); ts <= 1005; ts++ {
		record(s, ts, a, float64(ts-999))
	}
	r := s.Query([]string{"a"}, 3)
	if r.Step != 1 || r.Count != 3 || r.Start != 1002 {
		t.Fatalf("window = %+v", r)
	}
	want := []float32{3, 4, 5} // 1005 is still filling
	for i, v := range r.Values["a"] {
		if v != want[i] {
			t.Fatalf("values = %v, want %v", r.Values["a"], want)
		}
	}
}

func TestCoarseTierAveragesItsSlot(t *testing.T) {
	s := testStore()
	a := s.Handle("a", 0)
	for ts := int64(1000); ts < 1020; ts++ {
		record(s, ts, a, float64(ts%10))
	}
	record(s, 1020, a, 0)
	r := s.Query([]string{"a"}, 20)
	if r.Step != 10 {
		t.Fatalf("step = %d, want the tier that covers 20s", r.Step)
	}
	last := r.Values["a"][r.Count-1]
	if last != 4.5 {
		t.Fatalf("average = %v, want 4.5", last)
	}
}

func TestMissingSamplesBecomeGaps(t *testing.T) {
	s := testStore()
	a := s.Handle("a", 0)
	record(s, 1000, a, 5)
	record(s, 1001, a, 6)
	s.Record(1002, nil)
	record(s, 1003, a, 7)
	s.Record(1004, nil)
	v := s.Query([]string{"a"}, 4).Values["a"]
	if v[0] != 5 || v[1] != 6 || !math.IsNaN(float64(v[2])) || v[3] != 7 {
		t.Fatalf("values = %v", v)
	}
}

func TestLongGapOverwritesTheWholeRing(t *testing.T) {
	s := testStore()
	a := s.Handle("a", 0)
	for ts := int64(1000); ts < 1005; ts++ {
		record(s, ts, a, 9)
	}
	record(s, 2000, a, 1)
	s.Record(2001, nil)
	v := s.Query([]string{"a"}, 9).Values["a"]
	for i, value := range v[:len(v)-1] {
		if !math.IsNaN(float64(value)) {
			t.Fatalf("slot %d kept %v from before the gap", i, value)
		}
	}
	if v[len(v)-1] != 1 {
		t.Fatalf("newest = %v", v[len(v)-1])
	}
}

func TestSlotsBeforeTheFirstAreGaps(t *testing.T) {
	s := testStore()
	a := s.Handle("a", 0)
	record(s, 1000, a, 2)
	s.Record(1001, nil)
	v := s.Query([]string{"a"}, 3).Values["a"]
	if !math.IsNaN(float64(v[0])) || !math.IsNaN(float64(v[1])) || v[2] != 2 {
		t.Fatalf("values = %v", v)
	}
}

func TestZeroSeriesAllocatesNothing(t *testing.T) {
	s := testStore()
	a := s.Handle("a", 0)
	for ts := int64(1000); ts < 1100; ts++ {
		record(s, ts, a, 0)
	}
	if _, used := s.Usage(); used != 0 {
		t.Fatalf("an all-zero series holds %d bytes", used)
	}
	if v := s.Query([]string{"a"}, 3).Values["a"]; v[2] != 0 {
		t.Fatalf("value = %v, want 0", v[2])
	}
}

func TestSlowSeriesForcesItsTier(t *testing.T) {
	s := testStore()
	s.Handle("fast", 0)
	s.Handle("slow", 1)
	for ts := int64(1000); ts < 1020; ts++ {
		s.Record(ts, nil)
	}
	if r := s.Query([]string{"fast", "slow"}, 5); r.Step != 10 {
		t.Fatalf("step = %d, want the slow series' tier", r.Step)
	}
}

func TestClockJumpingBackRestartsTheTier(t *testing.T) {
	s := testStore()
	a := s.Handle("a", 0)
	record(s, 5000, a, 1)
	record(s, 5001, a, 1)
	record(s, 1000, a, 3)
	record(s, 1001, a, 4)
	s.Record(1002, nil)
	v := s.Query([]string{"a"}, 3).Values["a"]
	if !math.IsNaN(float64(v[0])) || v[1] != 3 || v[2] != 4 {
		t.Fatalf("values = %v", v)
	}
}

func TestResultJSONUsesNullForGaps(t *testing.T) {
	s := testStore()
	a := s.Handle(`a"b`, 0)
	record(s, 1000, a, 1.5)
	s.Record(1001, nil)
	s.Record(1002, nil)
	var out struct {
		Start  int64                 `json:"start"`
		Values map[string][]*float64 `json:"values"`
	}
	if err := json.Unmarshal(s.Query([]string{`a"b`, "missing"}, 2).AppendJSON(nil), &out); err != nil {
		t.Fatal(err)
	}
	v := out.Values[`a"b`]
	if out.Start != 1000 || len(out.Values) != 1 || *v[0] != 1.5 || v[1] != nil {
		t.Fatalf("out = %+v", out)
	}
}

func TestSeriesLimit(t *testing.T) {
	s := testStore()
	for i := 0; i < maxSeries; i++ {
		s.Handle(string(rune(i+0x4000)), 0)
	}
	if got := s.Handle("over", 0); got != nil {
		t.Fatalf("got a series past the limit")
	}
	s.Record(1000, []Sample{{S: nil, V: 1}})
}

func TestUnseenSeriesAreForgotten(t *testing.T) {
	s := testStore()
	a := s.Handle("a", 0)
	record(s, 1000, a, 1)
	s.Record(1000+retention+3601, nil)
	if count, _ := s.Usage(); count != 0 {
		t.Fatalf("%d series left", count)
	}
}

func TestSlotsBeforeASeriesExistedAreGapsNotZero(t *testing.T) {
	s := testStore()
	a, late := s.Handle("a", 0), s.Handle("late", 0)
	record(s, 1000, a, 1)
	s.Record(1001, []Sample{{S: a, V: 1}})
	s.Record(1002, []Sample{{S: a, V: 1}, {S: late, V: 0}})
	s.Record(1003, []Sample{{S: a, V: 1}, {S: late, V: 5}})
	s.Record(1004, nil)
	v := s.Query([]string{"late"}, 4).Values["late"]
	if !math.IsNaN(float64(v[0])) || !math.IsNaN(float64(v[1])) || v[2] != 0 || v[3] != 5 {
		t.Fatalf("values = %v", v)
	}
}
