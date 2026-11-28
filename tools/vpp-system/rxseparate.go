package main

import (
	"fmt"
	"log"
	"slices"
	"strings"
)

// A worker with one polling queue never sleeps, so interrupt and adaptive queues on it gain
// nothing. separateRx moves such queues to workers that poll nothing, the least loaded first.
// Polling queues stay where they are, so their throughput is not traded away, and queues the
// user placed are never moved. What cannot be separated is returned as warnings, but only when
// sleeping is wanted: some queue is adaptive (the installer's interrupt mode) or the panel set a
// queue to interrupt or adaptive. Otherwise the installer's interrupt TAP next to polling cards
// is how a polling router always runs, not something to fix.
func separateRx(v vppAPI, cfg *Config) (warnings []string, err error) {
	pinned := cfg.RxPlacement
	threads, err := v.Threads()
	if err != nil {
		return nil, err
	}
	all, err := v.RxQueues()
	if err != nil {
		return nil, err
	}
	var workers []uint32
	for _, t := range threads {
		if t.Index != 0 && t.Type == "workers" {
			workers = append(workers, t.Index)
		}
	}
	if len(workers) == 0 {
		return nil, nil // everything runs on the main thread
	}
	polls := map[uint32]bool{}
	load := map[uint32]int{}
	for _, q := range all {
		load[q.Thread]++
		if q.Mode == "polling" {
			polls[q.Thread] = true
		}
	}
	var quiet []uint32 // workers that can sleep
	for _, w := range workers {
		if !polls[w] {
			quiet = append(quiet, w)
		}
	}
	stuck := map[uint32][]string{} // queues with nowhere to go, by thread
	for _, q := range all {
		if q.Mode == "polling" || !polls[q.Thread] || !slices.Contains(workers, q.Thread) {
			continue
		}
		poller := pollerOn(all, q.Thread)
		if _, ok := pinned[q.Interface][q.Queue]; ok {
			warnings = append(warnings, fmt.Sprintf("%s 队列 %d 指定在 %s，和一直轮询的 %s 在一起，不能休眠",
				q.Interface, q.Queue, threadLabel(q.Thread), poller))
			continue
		}
		if len(quiet) == 0 {
			stuck[q.Thread] = append(stuck[q.Thread], fmt.Sprintf("%s 队列 %d", q.Interface, q.Queue))
			continue
		}
		to := quiet[0]
		for _, w := range quiet[1:] {
			if load[w] < load[to] {
				to = w
			}
		}
		if err := v.SetRxPlacement(q.Index, q.Queue, to); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s 队列 %d 不能移到 %s：%v", q.Interface, q.Queue, threadLabel(to), err))
			continue
		}
		load[q.Thread]--
		load[to]++
		log.Printf("rx: %s 队列 %d 从 %s 移到 %s，和一直轮询的 %s 分开", q.Interface, q.Queue, threadLabel(q.Thread), threadLabel(to), poller)
	}
	for _, w := range workers {
		if len(stuck[w]) > 0 {
			warnings = append(warnings, fmt.Sprintf("%s 上有一直轮询的 %s，没有空闲的 worker 可以分开，同一 worker 上的 %s 不能休眠",
				threadLabel(w), pollerOn(all, w), strings.Join(stuck[w], "、")))
		}
	}
	if !wantsSleep(all, cfg) {
		return nil, nil
	}
	return warnings, nil
}

func wantsSleep(all []rxQueue, cfg *Config) bool {
	for _, mode := range cfg.RxModes {
		if mode != "polling" {
			return true
		}
	}
	return slices.ContainsFunc(all, func(q rxQueue) bool { return q.Mode == "adaptive" })
}

// pollerOn names a polling queue on a thread, for messages.
func pollerOn(all []rxQueue, thread uint32) string {
	for _, q := range all {
		if q.Thread == thread && q.Mode == "polling" {
			return fmt.Sprintf("%s 队列 %d", q.Interface, q.Queue)
		}
	}
	return ""
}
