package main

import (
	"strings"
	"testing"
)

func workerThreads(n int) []thread {
	list := []thread{{Index: 0, Name: "vpp_main"}}
	for i := 1; i <= n; i++ {
		list = append(list, thread{Index: uint32(i), Name: "vpp_wk", Type: "workers", CPU: i + 1})
	}
	return list
}

func threadOf(f *fakeVPP, name string, queue uint32) uint32 {
	for _, q := range f.queues {
		if q.Interface == name && q.Queue == queue {
			return q.Thread
		}
	}
	return 99
}

func TestSeparateRxMovesInterruptQueues(t *testing.T) {
	f := &fakeVPP{threads: workerThreads(3), queues: []rxQueue{
		{Index: 1, Interface: "port0", Queue: 0, Thread: 1, Mode: "polling"},
		{Index: 2, Interface: "port1", Queue: 0, Thread: 1, Mode: "adaptive"},
		{Index: 3, Interface: "tap0", Queue: 0, Thread: 1, Mode: "interrupt"},
		{Index: 4, Interface: "port2", Queue: 0, Thread: 2, Mode: "interrupt"},
		{Index: 1, Interface: "port0", Queue: 1, Thread: 3, Mode: "polling"},
	}}
	warnings, err := separateRx(f, &Config{})
	if err != nil || len(warnings) != 0 {
		t.Fatal(warnings, err)
	}
	// Only worker 1 (thread 2) polls nothing; both queues go there. Polling queues stay.
	if threadOf(f, "port1", 0) != 2 || threadOf(f, "tap0", 0) != 2 || threadOf(f, "port0", 0) != 1 || threadOf(f, "port0", 1) != 3 {
		t.Fatalf("%+v", f.queues)
	}
	// A second pass has nothing to do.
	calls := len(f.calls)
	if w, _ := separateRx(f, &Config{}); len(w) != 0 || len(f.calls) != calls {
		t.Fatal(w, f.calls)
	}
}

func TestSeparateRxPicksLeastLoaded(t *testing.T) {
	f := &fakeVPP{threads: workerThreads(3), queues: []rxQueue{
		{Index: 1, Interface: "port0", Queue: 0, Thread: 1, Mode: "polling"},
		{Index: 2, Interface: "a", Queue: 0, Thread: 1, Mode: "adaptive"},
		{Index: 3, Interface: "b", Queue: 0, Thread: 1, Mode: "interrupt"},
		{Index: 4, Interface: "c", Queue: 0, Thread: 2, Mode: "interrupt"},
	}}
	if w, err := separateRx(f, &Config{}); err != nil || len(w) != 0 {
		t.Fatal(w, err)
	}
	if threadOf(f, "a", 0) != 3 || threadOf(f, "b", 0) != 2 {
		t.Fatalf("%+v", f.queues)
	}
}

func TestSeparateRxWarnsWhenItCannot(t *testing.T) {
	// One worker: nowhere to go.
	f := &fakeVPP{threads: workerThreads(1), queues: []rxQueue{
		{Index: 1, Interface: "port0", Queue: 0, Thread: 1, Mode: "polling"},
		{Index: 2, Interface: "port1", Queue: 0, Thread: 1, Mode: "adaptive"},
		{Index: 3, Interface: "port2", Queue: 0, Thread: 1, Mode: "adaptive"},
	}}
	w, err := separateRx(f, &Config{})
	// One warning for the worker, naming every queue on it that cannot sleep.
	if err != nil || len(w) != 1 || !strings.Contains(w[0], "port1 队列 0、port2 队列 0") || !strings.Contains(w[0], "port0 队列 0") || len(f.calls) != 0 {
		t.Fatal(w, err, f.calls)
	}

	// A queue the user placed stays.
	f = &fakeVPP{threads: workerThreads(2), queues: []rxQueue{
		{Index: 1, Interface: "port0", Queue: 0, Thread: 1, Mode: "polling"},
		{Index: 2, Interface: "tap0", Queue: 0, Thread: 1, Mode: "interrupt"},
	}}
	w, err = separateRx(f, &Config{RxPlacement: map[string]map[uint32]uint32{"tap0": {0: 1}}, RxModes: map[string]string{"tap0": "interrupt"}})
	if err != nil || len(w) != 1 || !strings.Contains(w[0], "指定在 worker 0") || threadOf(f, "tap0", 0) != 1 {
		t.Fatal(w, err, f.queues)
	}

	// A polling router: the interrupt TAP beside polling cards is not worth a warning.
	f = &fakeVPP{threads: workerThreads(1), queues: []rxQueue{
		{Index: 1, Interface: "port0", Queue: 0, Thread: 1, Mode: "polling"},
		{Index: 2, Interface: "tap0", Queue: 0, Thread: 1, Mode: "interrupt"},
	}}
	if w, err := separateRx(f, &Config{}); err != nil || len(w) != 0 {
		t.Fatal(w, err)
	}

	// Without workers everything is on the main thread; nothing to say.
	f = &fakeVPP{threads: workerThreads(0), queues: []rxQueue{
		{Index: 1, Interface: "port0", Queue: 0, Mode: "polling"},
		{Index: 2, Interface: "tap0", Queue: 0, Mode: "interrupt"},
	}}
	if w, err := separateRx(f, &Config{}); err != nil || len(w) != 0 || len(f.calls) != 0 {
		t.Fatal(w, err, f.calls)
	}
}

func TestSeparateRxAfterStartAndModeChange(t *testing.T) {
	s, fake, _ := newTestService(t)
	// The fake starts with port0 polling and tap0 interrupt, all on worker 0.
	fake.start()
	s.tick(s.now())
	if threadOf(fake, "tap0", 0) != 2 || threadOf(fake, "port0", 0) != 1 || len(s.State().Warnings) != 0 {
		t.Fatalf("%+v %v", fake.queues, s.State().Warnings)
	}
	// port0 to adaptive: nothing polls, nothing moves.
	calls := len(fake.calls)
	if _, err := s.SetRxMode("port0", "adaptive", "admin"); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != calls+1 {
		t.Fatal(fake.calls)
	}
	// port0 polls again; tap0, set to interrupt in the panel and pinned back next to it, cannot
	// sleep, and that is reported.
	if _, err := s.SetRxMode("port0", "polling", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRxMode("tap0", "interrupt", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRxPlacement("tap0", 0, 1, "admin"); err != nil {
		t.Fatal(err)
	}
	ws := s.State().Warnings
	if threadOf(fake, "tap0", 0) != 1 || len(ws) != 1 || !strings.Contains(ws[0], "tap0") {
		t.Fatalf("%+v %v", fake.queues, ws)
	}
}
