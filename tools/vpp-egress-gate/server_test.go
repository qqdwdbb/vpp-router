package gate

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

type mockResolver struct {
	ready   chan struct{}
	release chan struct{}
	fail    bool
	once    sync.Once
}

func (m *mockResolver) DNSUpstreamRoute(Question) (*Upstream, uint32) { return nil, 0 }
func (m *mockResolver) AnswerTTL(Question) *uint32                    { return nil }
func (m *mockResolver) SuppressAAAA(Question) bool                    { return false }
func (m *mockResolver) Reconcile(ctx context.Context, _ []Record, _ *Question, _ bool) error {
	m.once.Do(func() { close(m.ready) })
	select {
	case <-m.release:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		return fmt.Errorf("test timed out")
	}
	if m.fail {
		return fmt.Errorf("route installation failed")
	}
	return nil
}

func TestUDPAndTCPWithholdUntilAckAndFailClosed(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			tcp, failure := tcp, failure
			t.Run(fmt.Sprintf("tcp=%v failure=%v", tcp, failure), func(t *testing.T) {
				network := "udp"
				if tcp {
					network = "tcp"
				}
				ln, err := net.Listen(network, "127.0.0.1:0")
				var pc net.PacketConn
				var addr net.Addr
				if tcp {
					if err != nil {
						t.Fatal(err)
					}
					defer ln.Close()
					addr = ln.Addr()
				} else {
					pc, err = net.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer pc.Close()
					addr = pc.LocalAddr()
				}
				go func() {
					query := queryPacket()
					reply := replyPacket(60)
					if tcp {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						defer conn.Close()
						if _, err := readPrefixed(conn); err != nil {
							return
						}
						var hdr [2]byte
						binary.BigEndian.PutUint16(hdr[:], uint16(len(reply)))
						_, _ = conn.Write(append(hdr[:], reply...))
					} else {
						buf := make([]byte, 4096)
						_, peer, err := pc.ReadFrom(buf)
						if err != nil {
							return
						}
						_, _ = pc.WriteTo(reply, peer)
						_ = query
					}
				}()
				host, portStr, _ := net.SplitHostPort(addr.String())
				var port int
				fmt.Sscanf(portStr, "%d", &port)
				mock := &mockResolver{ready: make(chan struct{}), release: make(chan struct{}), fail: failure}
				g := NewGate(mock, Upstream{host, port})
				results := make(chan []byte, 1)
				go func() { results <- g.Exchange(queryPacket(), tcp) }()
				select {
				case <-mock.ready:
				case <-time.After(2 * time.Second):
					t.Fatal("controller was not invoked")
				}
				select {
				case got := <-results:
					t.Fatalf("answer escaped before route ACK: %x", got)
				case <-time.After(50 * time.Millisecond):
				}
				close(mock.release)
				var answer []byte
				select {
				case answer = <-results:
				case <-time.After(3 * time.Second):
					t.Fatal("exchange did not finish")
				}
				got, err := Decode(answer)
				if err != nil {
					t.Fatal(err)
				}
				want := uint16(0)
				if failure {
					want = 2
				}
				if got.Flags&15 != want {
					t.Fatalf("rcode %d want %d", got.Flags&15, want)
				}
			})
		}
	}
}

func TestServeDrainsInFlight(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		tcp := tcp
		t.Run(fmt.Sprintf("tcp=%v", tcp), func(t *testing.T) {
			upHost, upPort, stopUp := startTestUpstream(t, tcp)
			defer stopUp()
			mock := &mockResolver{ready: make(chan struct{}), release: make(chan struct{})}
			g := NewGate(mock, Upstream{upHost, upPort})
			stop := make(chan struct{})
			done := make(chan struct{})
			var clientAddr string
			if tcp {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				clientAddr = ln.Addr().String()
				go func() {
					ServeTCP(ln, g, stop)
					close(done)
				}()
			} else {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				clientAddr = pc.LocalAddr().String()
				go func() {
					ServeUDP(pc, g, stop)
					close(done)
				}()
			}
			conn := sendTestQuery(t, tcp, clientAddr)
			select {
			case <-mock.ready:
			case <-time.After(2 * time.Second):
				t.Fatal("in-flight request never reached controller")
			}
			close(stop)
			select {
			case <-done:
				t.Fatal("server returned while a DNS request was in flight")
			case <-time.After(80 * time.Millisecond):
			}
			close(mock.release)
			_ = conn.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("server did not return after in-flight request finished")
			}
		})
	}
}

func TestServeTCPStopUnblocksStuckExchange(t *testing.T) {
	upHost, upPort, stopUp := startTestUpstream(t, true)
	defer stopUp()
	hang := &hangResolver{started: make(chan struct{})}
	g := NewGate(hang, Upstream{upHost, upPort})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	old := serveDrain
	serveDrain = 80 * time.Millisecond
	defer func() { serveDrain = old }()
	go func() {
		ServeTCP(ln, g, stop)
		close(done)
	}()
	conn := sendTestQuery(t, true, ln.Addr().String())
	defer conn.Close()
	select {
	case <-hang.started:
	case <-time.After(2 * time.Second):
		t.Fatal("stuck request never reached controller")
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stuck Exchange blocked shutdown past drain")
	}
}

type hangResolver struct {
	started chan struct{}
}

func (h *hangResolver) DNSUpstreamRoute(Question) (*Upstream, uint32) { return nil, 0 }
func (h *hangResolver) AnswerTTL(Question) *uint32                    { return nil }
func (h *hangResolver) SuppressAAAA(Question) bool                    { return false }
func (h *hangResolver) Reconcile(ctx context.Context, _ []Record, _ *Question, _ bool) error {
	select {
	case <-h.started:
	default:
		close(h.started)
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestGateRewritesSignedHTTPSToH2(t *testing.T) {
	query := dnsQueryPacket(65)
	reply := withAD(httpsAnswerFor(65, [][]byte{[]byte("h2"), []byte("h3")}, nil))
	reply = appendAnswerRR(reply, 46, rrsigRdata(65))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		_, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(reply, peer)
	}()
	host, port := splitHostPort(t, pc.LocalAddr().String())
	release := make(chan struct{})
	close(release)
	g := NewGate(&mockResolver{ready: make(chan struct{}), release: release}, Upstream{host, port})
	answer := g.Exchange(query, false)
	got, err := Decode(answer)
	if err != nil || got.Flags&15 != 0 {
		t.Fatalf("signed HTTPS rewrite must keep NOERROR, got %+v %v", got, err)
	}
	if got.Flags&dnsFlagAD != 0 {
		t.Fatal("rewritten HTTPS reply kept AD")
	}
	if alpns := httpsALPNs(answer); len(alpns) != 1 || string(alpns[0]) != "h2" {
		t.Fatalf("alpns %q", alpns)
	}
}

func TestServeTCPStopDoesNotApplyAfterReturn(t *testing.T) {
	h := newHarness(t)
	store := NewDeferredState([]string{h.controller.Config().StateFile, h.leasePath})
	store.Enter()
	defer store.Exit()
	h.backend.HangApply = true
	h.backend.ApplyStarted = make(chan struct{})
	upHost, upPort, stopUp := startTestUpstream(t, true)
	defer stopUp()
	g := NewGate(h.controller, Upstream{upHost, upPort})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	old := serveDrain
	serveDrain = 80 * time.Millisecond
	defer func() { serveDrain = old }()
	go func() {
		ServeTCP(ln, g, stop)
		close(done)
	}()
	conn := sendTestQuery(t, true, ln.Addr().String())
	defer conn.Close()
	select {
	case <-h.backend.ApplyStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("apply never started")
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeTCP did not return after cancel")
	}
	if h.backend.HasRoute(0, "198.51.100.77/32") {
		t.Fatal("route written after ServeTCP returned")
	}
}

func TestServeTCPIdleDoesNotBlockStop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := NewGate(&mockResolver{ready: make(chan struct{}), release: make(chan struct{})}, Upstream{"127.0.0.1", 1})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		ServeTCP(ln, g, stop)
		close(done)
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle TCP connection blocked shutdown")
	}
}

func startTestUpstream(t *testing.T, tcp bool) (host string, port int, stop func()) {
	t.Helper()
	if tcp {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		host, port = splitHostPort(t, ln.Addr().String())
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			if _, err := readPrefixed(conn); err != nil {
				return
			}
			reply := replyPacket(60)
			var hdr [2]byte
			binary.BigEndian.PutUint16(hdr[:], uint16(len(reply)))
			_, _ = conn.Write(append(hdr[:], reply...))
		}()
		return host, port, func() { ln.Close() }
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port = splitHostPort(t, pc.LocalAddr().String())
	go func() {
		buf := make([]byte, 4096)
		_, peer, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(replyPacket(60), peer)
	}()
	return host, port, func() { pc.Close() }
}

func sendTestQuery(t *testing.T, tcp bool, addr string) net.Conn {
	t.Helper()
	query := queryPacket()
	network := "udp"
	if tcp {
		network = "tcp"
	}
	conn, err := net.Dial(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	if tcp {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
		if _, err := conn.Write(append(hdr[:], query...)); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		return conn
	}
	if _, err := conn.Write(query); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	return conn
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return host, port
}
