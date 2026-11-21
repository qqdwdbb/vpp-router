package gate

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Resolver is the DNS-path surface used by Gate.
type Resolver interface {
	DNSUpstreamRoute(Question) (*Upstream, uint32)
	AnswerTTL(Question) *uint32
	Reconcile(context.Context, []Record, *Question, bool) error
	SuppressAAAA(Question) bool
}

// Gate forwards a query, installs selected routes, then releases the answer.
type Gate struct {
	Controller Resolver
	Upstream   Upstream
	Timeout    time.Duration
	slots      chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewGate(controller Resolver, upstream Upstream) *Gate {
	ctx, cancel := context.WithCancel(context.Background())
	return &Gate{
		Controller: controller,
		Upstream:   upstream,
		Timeout:    5 * time.Second,
		slots:      make(chan struct{}, 32),
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (g *Gate) context() context.Context {
	if g == nil || g.ctx == nil {
		return context.Background()
	}
	return g.ctx
}

// Shutdown cancels in-flight Exchange/Reconcile work. ServeTCP/UDP call it
// after the graceful drain so remaining route writers observe ctx.Done()
// before the process flushes state.
func (g *Gate) Shutdown() {
	if g != nil && g.cancel != nil {
		g.cancel()
	}
}

func (g *Gate) Exchange(query []byte, tcp bool) []byte {
	if err := g.context().Err(); err != nil {
		return Servfail(query)
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		return Servfail(query)
	}
	var question Question
	decoded := false
	fail := func(err error) []byte {
		name := "undecoded"
		if decoded {
			name = question.Name
		}
		log.Printf("DNS answer withheld: %s (%s)", err, name)
		return Servfail(query)
	}
	msg, err := Decode(query)
	if err != nil {
		return fail(err)
	}
	question = msg.Question
	decoded = true
	if msg.Flags&0x8000 != 0 {
		return fail(errors.New("expected query"))
	}
	if g.Controller.SuppressAAAA(question) {
		return NoData(query)
	}
	upstream := g.Upstream
	selected, mark := g.Controller.DNSUpstreamRoute(question)
	if selected != nil {
		upstream = *selected
	}
	answer, err := g.queryUpstream(query, upstream, mark, tcp)
	if err != nil {
		return fail(err)
	}
	reply, err := Decode(answer)
	if err != nil {
		return fail(err)
	}
	if reply.ID != msg.ID || reply.Question != question || reply.Flags&0x8000 == 0 {
		return fail(errors.New("upstream answer mismatch"))
	}
	if reply.Flags&0x0200 != 0 {
		if tcp {
			return fail(errors.New("truncated TCP DNS reply"))
		}
		answer, err = g.queryUpstream(query, upstream, mark, true)
		if err != nil {
			return fail(err)
		}
		reply, err = Decode(answer)
		if err != nil {
			return fail(err)
		}
		if reply.ID != msg.ID || reply.Question != question || reply.Flags&0x8000 == 0 || reply.Flags&0x0200 != 0 {
			return fail(errors.New("invalid TCP retry answer"))
		}
	}
	var ttl *uint32
	if reply.Flags&15 == 0 {
		if err := g.Controller.Reconcile(g.context(), reply.Records, &question, false); err != nil {
			return fail(err)
		}
		ttl = g.Controller.AnswerTTL(question)
	}
	answer = StripHTTPSH3(answer, ttl)
	if answer == nil {
		return fail(errors.New("cannot safely rewrite DNS response"))
	}
	return answer
}

// Replaced by tests, which cannot set socket marks without Linux and privileges.
var socketMarker = setSocketMark

// markedDialControl fails the dial if the mark cannot be set, because an
// unmarked query would leave through the main table instead of the exit.
func markedDialControl(mark uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var markErr error
		if err := c.Control(func(fd uintptr) { markErr = socketMarker(fd, mark) }); err != nil {
			return err
		}
		if markErr != nil {
			return fmt.Errorf("mark DNS upstream socket: %w", markErr)
		}
		return nil
	}
}

func (g *Gate) queryUpstream(query []byte, upstream Upstream, mark uint32, tcp bool) ([]byte, error) {
	network := "udp"
	if tcp {
		network = "tcp"
	}
	if ip := net.ParseIP(upstream.Host); ip != nil && ip.To4() == nil {
		network += "6"
	}
	addr := net.JoinHostPort(upstream.Host, fmt.Sprintf("%d", upstream.Port))
	dialer := net.Dialer{Timeout: g.Timeout}
	if mark != 0 {
		dialer.Control = markedDialControl(mark)
	}
	conn, err := dialer.DialContext(g.context(), network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(g.Timeout))
	if tcp {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
		if _, err := conn.Write(append(hdr[:], query...)); err != nil {
			return nil, err
		}
		return readPrefixed(conn)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func ReadExact(r io.Reader, length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, errors.New("DNS TCP connection closed")
		}
		return nil, err
	}
	return buf, nil
}

func readPrefixed(r io.Reader) ([]byte, error) {
	hdr, err := ReadExact(r, 2)
	if err != nil {
		return nil, err
	}
	return ReadExact(r, int(binary.BigEndian.Uint16(hdr)))
}

func handleUDP(gate *Gate, conn net.PacketConn, buf []byte, addr net.Addr) {
	query := append([]byte{}, buf...)
	answer := gate.Exchange(query, false)
	limit := UDPSizeLimit(query)
	if len(answer) > limit {
		answer = setTruncated(Servfail(query))
	}
	_, _ = conn.WriteTo(answer, addr)
}

var serveDrain = 6 * time.Second

func waitGroupTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(d)
	select {
	case <-done:
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
	}
}

func drainHandlers(wg *sync.WaitGroup, gate *Gate, closeBusy func()) {
	waitGroupTimeout(wg, serveDrain)
	if gate != nil {
		gate.Shutdown()
	}
	if closeBusy != nil {
		closeBusy()
	}
	wg.Wait()
}

func handleTCP(gate *Gate, conn net.Conn, stop <-chan struct{}, busy *atomic.Bool) {
	defer conn.Close()
	for i := 0; i < 100; i++ {
		select {
		case <-stop:
			return
		default:
		}
		busy.Store(false)
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		query, err := readPrefixed(conn)
		if err != nil {
			return
		}
		busy.Store(true)
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		answer := gate.Exchange(query, true)
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(answer)))
		if _, err := conn.Write(append(hdr[:], answer...)); err != nil {
			return
		}
		busy.Store(false)
	}
}

type requestSlots struct {
	ch chan struct{}
}

func newRequestSlots(n int) *requestSlots {
	return &requestSlots{ch: make(chan struct{}, n)}
}

func (s *requestSlots) try() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *requestSlots) release() { <-s.ch }

// ServeUDP answers datagram queries until stop is closed.
func ServeUDP(conn net.PacketConn, gate *Gate, stop <-chan struct{}) {
	slots := newRequestSlots(64)
	var wg sync.WaitGroup
	go func() {
		<-stop
		_ = conn.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-stop:
				drainHandlers(&wg, gate, nil)
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				waitGroupTimeout(&wg, serveDrain)
				return
			}
		}
		if !slots.try() {
			continue
		}
		packet := append([]byte{}, buf[:n]...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer slots.release()
			handleUDP(gate, conn, packet, addr)
		}()
	}
}

type trackedConn struct {
	conn net.Conn
	busy atomic.Bool
}

// ServeTCP answers length-prefixed queries until stop is closed.
func ServeTCP(ln net.Listener, gate *Gate, stop <-chan struct{}) {
	slots := newRequestSlots(64)
	var wg sync.WaitGroup
	var mu sync.Mutex
	live := map[*trackedConn]struct{}{}
	closeLive := func(idleOnly bool) {
		mu.Lock()
		defer mu.Unlock()
		for tc := range live {
			if idleOnly && tc.busy.Load() {
				continue
			}
			_ = tc.conn.Close()
		}
	}
	go func() {
		<-stop
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				closeLive(true)
				drainHandlers(&wg, gate, func() { closeLive(false) })
				return
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				waitGroupTimeout(&wg, serveDrain)
				return
			}
		}
		if !slots.try() {
			conn.Close()
			continue
		}
		tc := &trackedConn{conn: conn}
		mu.Lock()
		live[tc] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer slots.release()
			defer func() {
				mu.Lock()
				delete(live, tc)
				mu.Unlock()
			}()
			handleTCP(gate, conn, stop, &tc.busy)
		}()
	}
}

func listenPacket(host string, port int) (net.PacketConn, error) {
	network := "udp"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "udp6"
	}
	cfg := net.ListenConfig{Control: ipv6OnlyControl}
	return cfg.ListenPacket(nil, network, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}

func listenStream(host string, port int) (net.Listener, error) {
	network := "tcp"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "tcp6"
	}
	cfg := net.ListenConfig{Control: ipv6OnlyControl}
	return cfg.Listen(nil, network, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}

func ipv6OnlyControl(network, address string, c syscall.RawConn) error {
	if network != "tcp6" && network != "udp6" {
		return nil
	}
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
	}); err != nil {
		return err
	}
	return sockErr
}

func exclusiveLock(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("vpp-egress-gate already running: %w", err)
	}
	return f, nil
}

// StartStateServer answers with the route ledger, and with the default route's status when
// status is not nil.
func StartStateServer(cfg *Config, stop <-chan struct{}, status func() DefaultRouteStatus) error {
	path := cfg.StateSocket
	if path == "" {
		path = "/run/vpp-egress-gate/state.sock"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)
	go func() {
		<-stop
		_ = ln.Close()
		_ = os.Remove(path)
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				raw := ReadJSON(cfg.StateFile, map[string]any{})
				if fields, ok := raw.(map[string]any); ok && status != nil {
					fields["default_route"] = status()
				}
				data, err := jsonMarshal(raw)
				if err != nil {
					return
				}
				_, _ = conn.Write(data)
			}()
		}
	}()
	return nil
}

func jsonMarshal(v any) ([]byte, error) {
	return marshalJSON(v)
}

func waitSignals(stop chan struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ch
		select {
		case <-stop:
		default:
			close(stop)
		}
	}()
}
