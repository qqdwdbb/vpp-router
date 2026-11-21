package gate

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func benchSetup(tb testing.TB, ordered bool) (*harness, func()) {
	tb.Helper()
	h := newHarness(tb)
	raw, err := os.ReadFile(h.configPath)
	if err != nil {
		tb.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		tb.Fatal(err)
	}
	config["max_routes"] = 1_000_000
	writeJSON(tb, h.configPath, config)
	if ordered {
		h.ordered(tb)
	} else {
		c, err := NewController(h.configPath, h.leasePath,
			func(*Config) Backend { return h.backend }, h.routesPath)
		if err != nil {
			tb.Fatal(err)
		}
		h.controller = c
	}
	h.backend.Quiet = true
	store := NewDeferredState([]string{h.controller.Config().StateFile, h.leasePath})
	store.Enter()
	return h, func() { store.Exit() }
}

func benchIP(i int) string {
	n := uint32(i + 1)
	return fmt.Sprintf("10.%d.%d.%d", (n>>16)&0xff, (n>>8)&0xff, n&0xff)
}

func benchQuestion() Question { return Question{"www.routing.example.net", 1, 1} }

func benchRecords(ip string) []Record {
	return []Record{{"www.routing.example.net", ip, 60}}
}

func startUpstream(tb testing.TB, reply []byte) (Upstream, func()) {
	tb.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			out := append([]byte{}, reply...)
			copy(out[0:2], buf[0:2])
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	host, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return Upstream{host, port}, func() {
		pc.Close()
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted))*p) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func summarize(ns []float64) (median, p95, p99, mean float64) {
	if len(ns) == 0 {
		return 0, 0, 0, 0
	}
	sorted := append([]float64{}, ns...)
	sort.Float64s(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	return percentile(sorted, 0.50), percentile(sorted, 0.95), percentile(sorted, 0.99), sum / float64(len(sorted))
}

func sampleReconcile(h *harness, n int, unique bool) []float64 {
	q := benchQuestion()
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		ip := "198.51.100.77"
		if unique {
			ip = benchIP(i + 100)
		}
		start := time.Now()
		if err := h.controller.Reconcile(context.Background(), benchRecords(ip), &q, false); err != nil {
			panic(err)
		}
		out[i] = float64(time.Since(start).Nanoseconds()) / 1e6
	}
	return out
}

func BenchmarkDecodeA(b *testing.B) {
	pkt := replyPacket(60)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeHTTPS(b *testing.B) {
	pkt := httpsAnswer([][]byte{[]byte("h2"), []byte("h3")}, []byte{0, 4, 0, 4, 198, 51, 100, 77})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStripHTTPSH3(b *testing.B) {
	pkt := httpsAnswer([][]byte{[]byte("h2"), []byte("h3")}, []byte{0, 4, 0, 4, 198, 51, 100, 77})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = StripHTTPSH3(pkt, nil)
	}
}

func BenchmarkServfail(b *testing.B) {
	pkt := queryPacket()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Servfail(pkt)
	}
}

func BenchmarkReconcileCacheHit(b *testing.B) {
	h, cleanup := benchSetup(b, false)
	defer cleanup()
	q := benchQuestion()
	if err := h.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := h.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReconcileFirstHit(b *testing.B) {
	h, cleanup := benchSetup(b, false)
	defer cleanup()
	q := benchQuestion()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := h.controller.Reconcile(context.Background(), benchRecords(benchIP(i)), &q, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReconcileOrderedCacheHit(b *testing.B) {
	h, cleanup := benchSetup(b, true)
	defer cleanup()
	q := benchQuestion()
	if err := h.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := h.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDNSUpstreamMatch(b *testing.B) {
	h, cleanup := benchSetup(b, false)
	defer cleanup()
	q := benchQuestion()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.controller.DNSUpstream(q)
	}
}

func BenchmarkMatchingRulesLargeSet(b *testing.B) {
	h := newHarness(b)
	const n = 8000
	domains := make([]string, n)
	for i := 0; i < n; i++ {
		domains[i] = fmt.Sprintf("host-%d.example.net", i)
	}
	domains[n-1] = "routing.example.net"
	h.domainRoutes(b, domains)
	cfg, rules := h.controller.loaded()
	_ = cfg
	names := []string{"www.routing.example.net"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := h.controller.matchingRules(rules, names); len(got) == 0 {
			b.Fatal("no match")
		}
	}
}

func BenchmarkGateExchangeCacheHit(b *testing.B) {
	h, cleanup := benchSetup(b, false)
	defer cleanup()
	reply := replyPacket(60)
	up, stop := startUpstream(b, reply)
	defer stop()
	q := benchQuestion()
	if err := h.controller.Reconcile(context.Background(), h.records(), &q, false); err != nil {
		b.Fatal(err)
	}
	g := NewGate(h.controller, up)
	query := queryPacket()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		answer := g.Exchange(query, false)
		if len(answer) < 12 || answer[3]&0x0f == 2 {
			b.Fatalf("servfail or short answer len=%d", len(answer))
		}
	}
}

func BenchmarkParallelCacheHit(b *testing.B) {
	h, cleanup := benchSetup(b, false)
	defer cleanup()
	q := benchQuestion()
	if err := h.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		q := benchQuestion()
		for pb.Next() {
			if err := h.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func TestPerfReport(t *testing.T) {
	if os.Getenv("GATE_PERF") == "" {
		t.Skip("set GATE_PERF=1 to run the latency/QPS report")
	}
	const samples = 300
	h, cleanup := benchSetup(t, false)
	defer cleanup()

	first := sampleReconcile(h, samples, true)
	cache := sampleReconcile(h, samples, false)
	fm, f95, f99, fmean := summarize(first)
	cm, c95, c99, cmean := summarize(cache)

	h2, cleanup2 := benchSetup(t, true)
	defer cleanup2()
	q := benchQuestion()
	if err := h2.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
		t.Fatal(err)
	}
	ordered := sampleReconcile(h2, samples, false)
	om, o95, o99, omean := summarize(ordered)

	he, cleanupE := benchSetup(t, false)
	defer cleanupE()
	if err := he.controller.Reconcile(context.Background(), he.records(), &q, false); err != nil {
		t.Fatal(err)
	}
	reply := replyPacket(60)
	up, stop := startUpstream(t, reply)
	defer stop()
	g := NewGate(he.controller, up)
	query := queryPacket()
	for i := 0; i < 20; i++ {
		_ = g.Exchange(query, false)
	}
	e2e := make([]float64, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		answer := g.Exchange(query, false)
		e2e[i] = float64(time.Since(start).Nanoseconds()) / 1e6
		if len(answer) < 12 || answer[3]&0x0f == 2 {
			t.Fatalf("exchange servfail")
		}
	}
	em, e95, e99, emean := summarize(e2e)

	hq, cleanupQ := benchSetup(t, false)
	defer cleanupQ()
	if err := hq.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
		t.Fatal(err)
	}
	seqStart := time.Now()
	var seqCount int64
	for time.Since(seqStart) < time.Second {
		if err := hq.controller.Reconcile(context.Background(), benchRecords("198.51.100.77"), &q, false); err != nil {
			t.Fatal(err)
		}
		seqCount++
	}
	cacheQPS := seqCount

	var parCount atomic.Int64
	var wg sync.WaitGroup
	parStop := make(chan struct{})
	workers := runtime.GOMAXPROCS(0)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		id := i
		go func() {
			defer wg.Done()
			q := benchQuestion()
			n := 0
			for {
				select {
				case <-parStop:
					return
				default:
					ip := benchIP((id << 16) + n + 1)
					n++
					if err := hq.controller.Reconcile(context.Background(), benchRecords(ip), &q, false); err != nil {
						t.Error(err)
						return
					}
					parCount.Add(1)
				}
			}
		}()
	}
	time.Sleep(time.Second)
	close(parStop)
	wg.Wait()
	uniqueQPS := parCount.Load()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	udpStop := make(chan struct{})
	go ServeUDP(pc, g, udpStop)
	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 20; i++ {
		binary.BigEndian.PutUint16(query[0:2], uint16(i+1))
		if _, err := client.Write(query); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Read(make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
	}
	udp := make([]float64, samples)
	buf := make([]byte, 4096)
	for i := 0; i < samples; i++ {
		binary.BigEndian.PutUint16(query[0:2], uint16(i+1))
		start := time.Now()
		if _, err := client.Write(query); err != nil {
			t.Fatal(err)
		}
		n, err := client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		udp[i] = float64(time.Since(start).Nanoseconds()) / 1e6
		if n < 12 || buf[3]&0x0f == 2 {
			t.Fatalf("udp servfail")
		}
	}
	close(udpStop)
	um, u95, u99, umean := summarize(udp)

	t.Logf("vpp-egress-gate perf  go=%s %s/%s  GOMAXPROCS=%d  samples=%d",
		runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), samples)
	t.Logf("first-hit reconcile     median=%.3fms p95=%.3fms p99=%.3fms mean=%.3fms", fm, f95, f99, fmean)
	t.Logf("cache-hit reconcile     median=%.3fms p95=%.3fms p99=%.3fms mean=%.3fms", cm, c95, c99, cmean)
	t.Logf("ordered cache-hit       median=%.3fms p95=%.3fms p99=%.3fms mean=%.3fms", om, o95, o99, omean)
	t.Logf("gate exchange+upstream  median=%.3fms p95=%.3fms p99=%.3fms mean=%.3fms", em, e95, e99, emean)
	t.Logf("udp ServeUDP loopback   median=%.3fms p95=%.3fms p99=%.3fms mean=%.3fms", um, u95, u99, umean)
	t.Logf("cache-hit QPS           %d/s sequential  FakeBackend (no VPP)", cacheQPS)
	t.Logf("unique-ip parallel QPS  %d/s  workers=%d", uniqueQPS, workers)

	out := map[string]any{
		"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
		"gomaxprocs": runtime.GOMAXPROCS(0), "samples": samples,
		"first_hit_ms":           map[string]float64{"median": fm, "p95": f95, "p99": f99, "mean": fmean},
		"cache_hit_ms":           map[string]float64{"median": cm, "p95": c95, "p99": c99, "mean": cmean},
		"ordered_cache_ms":       map[string]float64{"median": om, "p95": o95, "p99": o99, "mean": omean},
		"exchange_ms":            map[string]float64{"median": em, "p95": e95, "p99": e99, "mean": emean},
		"udp_ms":                 map[string]float64{"median": um, "p95": u95, "p99": u99, "mean": umean},
		"cache_hit_qps":          cacheQPS,
		"unique_ip_parallel_qps": uniqueQPS,
		"parallel_workers":       workers,
		"note":                   "FakeBackend in-process; excludes VPP CLI and upstream Internet RTT",
	}
	path := filepath.Join(os.TempDir(), "vpp-egress-gate-perf.json")
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}
