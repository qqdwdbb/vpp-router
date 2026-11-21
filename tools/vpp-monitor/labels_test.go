package main

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestInterfaceLabelsNaming(t *testing.T) {
	got := describeInterfaces(interfaceFacts{
		names:     []string{"tap1", "tap2", "tap3", "tap4", "tap5", "eth0.100", "loop1", "loop2", "loop3", "wg0"},
		hosts:     map[string]string{"tap1": "vpp-lan", "tap2": "eth0.100", "tap3": "", "tap4": "same", "tap5": "same"},
		addresses: map[string]string{"loop1": "192.0.2.1"},
		bridged:   map[string]bool{"loop2": true},
	})
	want := map[string]InterfaceInfo{
		"tap1":  {Label: "vpp-lan"},
		"tap2":  {Label: "eth0.100 (tap2)"},
		"tap4":  {Label: "same (tap4)"},
		"tap5":  {Label: "same (tap5)"},
		"loop1": {Label: "loop1 (192.0.2.1)"},
		"loop3": {Placeholder: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("labels = %v, want %v", got, want)
	}
}

func TestLabelKeyIgnoresOtherInterfaces(t *testing.T) {
	if got := labelKey([]string{"eth0", "tap10", "wg0", "tun2", "tap-x", "loop7"}); got != "tap10 tun2 loop7 " {
		t.Fatalf("key = %q", got)
	}
}

func TestPreferredAddress(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"fe80::1"}, ""},
		{[]string{"fe80::1", "2001:db8::1", "192.0.2.1"}, "192.0.2.1"},
		{[]string{"fe80::1", "2001:db8::1"}, "2001:db8::1"},
	} {
		if got := preferredAddress(c.in); got != c.want {
			t.Errorf("preferredAddress(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func waitIdle(t *testing.T, l *InterfaceLabels) {
	t.Helper()
	for i := 0; i < 500; i++ {
		l.mu.Lock()
		busy := l.busy
		l.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the reading never finished")
}

func TestInterfaceLabelsReadsOnlyWhenNeeded(t *testing.T) {
	var reads atomic.Int32
	var fail atomic.Bool
	now := time.Unix(1000, 0)
	l := NewInterfaceLabels(func() (map[string]InterfaceInfo, error) {
		reads.Add(1)
		if fail.Load() {
			return nil, errors.New("no VPP")
		}
		return map[string]InterfaceInfo{"tap1": {Label: "lan"}}, nil
	})
	l.now = func() time.Time { return now }

	l.Refresh("")
	waitIdle(t, l)
	if reads.Load() != 0 {
		t.Fatal("read with no TAPs")
	}
	l.Refresh("tap1 ")
	waitIdle(t, l)
	l.Refresh("tap1 ")
	waitIdle(t, l)
	if reads.Load() != 1 || l.Name("tap1") != "lan" || l.Name("eth0") != "eth0" {
		t.Fatalf("reads = %d, name = %q", reads.Load(), l.Name("tap1"))
	}

	// A VPP restart reads again, and a failed reading waits before the next try.
	fail.Store(true)
	l.Forget()
	l.Refresh("tap1 ")
	waitIdle(t, l)
	l.Refresh("tap1 ")
	waitIdle(t, l)
	if reads.Load() != 2 || l.Name("tap1") != "lan" {
		t.Fatalf("after a failure: reads = %d, name = %q", reads.Load(), l.Name("tap1"))
	}
	fail.Store(false)
	now = now.Add(labelRetry)
	l.Refresh("tap1 ")
	waitIdle(t, l)
	if reads.Load() != 3 {
		t.Fatalf("no retry: reads = %d", reads.Load())
	}

	// A new set is read again once it has settled, then rarely.
	now = now.Add(labelSettle)
	l.Refresh("tap1 ")
	waitIdle(t, l)
	if reads.Load() != 4 {
		t.Fatalf("no second reading: reads = %d", reads.Load())
	}
	now = now.Add(labelSettle)
	l.Refresh("tap1 ")
	waitIdle(t, l)
	if reads.Load() != 4 {
		t.Fatalf("read too often: reads = %d", reads.Load())
	}
	now = now.Add(labelRefresh)
	l.Refresh("tap1 ")
	waitIdle(t, l)
	if reads.Load() != 5 {
		t.Fatalf("no periodic reading: reads = %d", reads.Load())
	}
}

func TestNilLabelsKeepNames(t *testing.T) {
	var l *InterfaceLabels
	l.Refresh("tap1 ")
	l.Forget()
	if l.Name("tap1") != "tap1" || l.Info("tap1") != (InterfaceInfo{}) {
		t.Fatal("a nil set invented a label")
	}
}

func TestCollectorPublishesLabels(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"tap1", "eth0"}, []uint64{100, 100}, []uint64{100, 100})}
	c, now := newTestCollector(f)
	c.labels = NewInterfaceLabels(func() (map[string]InterfaceInfo, error) {
		return map[string]InterfaceInfo{"tap1": {Label: "lan"}}, nil
	})
	c.tick(*now, now.Unix(), true)
	waitIdle(t, c.labels)
	*now = now.Add(time.Second)
	c.tick(*now, now.Unix(), false)
	byName := map[string]string{}
	for _, row := range c.Status().Interfaces {
		byName[row.Name] = row.Label
	}
	if byName["tap1"] != "lan" || byName["eth0"] != "" {
		t.Fatalf("labels = %v", byName)
	}
}

func TestPlaceholderHiddenOnlyWhileIdle(t *testing.T) {
	f := &fakeStats{fast: interfaces([]string{"loop1", "loop2"}, []uint64{0, 500}, []uint64{0, 500})}
	c, now := newTestCollector(f)
	c.labels = NewInterfaceLabels(func() (map[string]InterfaceInfo, error) {
		return map[string]InterfaceInfo{"loop1": {Placeholder: true}, "loop2": {Placeholder: true}}, nil
	})
	hidden := func() map[string]bool {
		out := map[string]bool{}
		for _, row := range c.Status().Interfaces {
			out[row.Name] = row.Hidden
		}
		return out
	}
	c.tick(*now, now.Unix(), true)
	waitIdle(t, c.labels)
	*now = now.Add(time.Second)
	c.tick(*now, now.Unix(), false)
	if got := hidden(); !got["loop1"] || got["loop2"] {
		t.Fatalf("idle placeholders = %v", got)
	}

	f.fast = interfaces([]string{"loop1", "loop2"}, []uint64{7, 500}, []uint64{0, 500})
	*now = now.Add(time.Second)
	c.tick(*now, now.Unix(), false)
	if got := hidden(); got["loop1"] {
		t.Fatalf("a placeholder with traffic stayed hidden: %v", got)
	}
}
