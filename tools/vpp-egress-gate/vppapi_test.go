package gate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/fib"
	"go.fd.io/govpp/binapi/fib_types"
	"go.fd.io/govpp/binapi/ip"
	"go.fd.io/govpp/binapi/ip_types"
)

type stubRouteAPI struct {
	calls int
	lines []string
	err   error
}

type cancellableRouteAPI struct{ started chan struct{} }

func (s *cancellableRouteAPI) apply(ctx context.Context, _ []string) error {
	close(s.started)
	<-ctx.Done()
	return ctx.Err()
}

func TestBackendPropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	api := &cancellableRouteAPI{started: make(chan struct{})}
	b := &VPPBackend{Config: &Config{}, routeAPI: api}
	b.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- b.Apply([]string{"route"}) }()
	<-api.started
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("backend did not propagate cancellation")
	}
}

func TestVPPLockCancellation(t *testing.T) {
	apiMu <- struct{}{}
	defer func() { <-apiMu }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := applyVPPRoutes(ctx, &Config{}, nil); err == nil {
		t.Fatal("waiting for API lock must honor cancellation")
	}
}

func (s *stubRouteAPI) apply(_ context.Context, lines []string) error {
	s.calls++
	s.lines = append([]string{}, lines...)
	return s.err
}

type stubReply struct{ retval int32 }

func (s stubReply) ReceiveReply(msg api.Message) error {
	if reply, ok := msg.(*ip.IPRouteAddDelV2Reply); ok {
		reply.Retval = s.retval
	}
	return nil
}

type stubChan struct {
	retval  int32
	reqs    []*ip.IPRouteAddDelV2
	sources []fib.FibSource
	reads   int
	dumps   []api.Message
}

type stubMulti struct{}

func (stubMulti) ReceiveReply(api.Message) (bool, error) { return true, nil }

type sourceDump struct {
	c *stubChan
	i int
}

func (d *sourceDump) ReceiveReply(msg api.Message) (bool, error) {
	d.c.reads++
	if d.i >= len(d.c.sources) {
		return true, nil
	}
	if details, ok := msg.(*fib.FibSourceDetails); ok {
		details.Src = d.c.sources[d.i]
	}
	d.i++
	return false, nil
}

func (s *stubChan) SendRequest(msg api.Message) api.RequestCtx {
	if req, ok := msg.(*ip.IPRouteAddDelV2); ok {
		s.reqs = append(s.reqs, req)
	}
	return stubReply{s.retval}
}
func (s *stubChan) SendMultiRequest(msg api.Message) api.MultiRequestCtx {
	s.dumps = append(s.dumps, msg)
	if len(s.sources) > 0 {
		return &sourceDump{c: s}
	}
	return stubMulti{}
}
func (s *stubChan) SubscribeNotification(chan api.Message, api.Message) (api.SubscriptionCtx, error) {
	panic("unused")
}
func (s *stubChan) SetReplyTimeout(time.Duration)          {}
func (s *stubChan) CheckCompatiblity(...api.Message) error { return nil }
func (s *stubChan) Close()                                 {}

func TestParseRouteLine(t *testing.T) {
	route := Route{Table: 2490, Prefix: "198.51.100.77/32", Via: "10.62.30.1", Interface: "wg1"}
	add, got, err := parseRouteLine(route.Command("add"))
	if err != nil || !add || got != route {
		t.Fatalf("add parse got %+v add=%v err=%v", got, add, err)
	}
	add, got, err = parseRouteLine(route.Command("del"))
	if err != nil || add || got != route {
		t.Fatalf("del parse got %+v add=%v err=%v", got, add, err)
	}
	if _, _, err := parseRouteLine("ip route add 198.51.100.77/32 table 0 via 10.62.30.1"); err == nil {
		t.Fatal("short line accepted")
	}
}

func TestApplyRejectsNonZeroRetval(t *testing.T) {
	stub := &stubChan{retval: -2, reqs: nil}
	sess := &vppAPISession{ch: stub, ifaces: map[string]uint32{"wg1": 4}, cliSrc: 1}
	route := Route{Table: 0, Prefix: "198.51.100.77/32", Via: "10.62.30.1", Interface: "wg1"}
	err := sess.routeAddDel(true, route)
	if err == nil {
		t.Fatal("nonzero retval accepted")
	}
	if !strings.Contains(err.Error(), "VPP route API failed (-2): 198.51.100.77/32") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stub.reqs) != 1 {
		t.Fatalf("requests %d", len(stub.reqs))
	}
	req := stub.reqs[0]
	if !req.IsAdd || !req.IsMultipath || req.Route.Src != 1 || req.Route.NPaths != 1 {
		t.Fatalf("request %+v", req)
	}
	if req.Route.Paths[0].SwIfIndex != 4 || req.Route.Paths[0].Weight != 1 {
		t.Fatalf("path %+v", req.Route.Paths[0])
	}
	if req.Route.Paths[0].Proto != fib_types.FIB_API_PATH_NH_PROTO_IP4 {
		t.Fatal("expected IPv4 next hop proto")
	}

	b := &VPPBackend{
		Config:   &Config{VPPSocket: "/no/such.sock", APISocket: "/no/such.sock"},
		routeAPI: &stubRouteAPI{err: fmt.Errorf("VPP route API failed (-2): 198.51.100.77/32")},
	}
	wrapped := b.Apply([]string{route.Command("add")})
	if wrapped == nil {
		t.Fatal("Apply accepted failing API")
	}
	if !strings.Contains(wrapped.Error(), "VPP Binary API request failed") {
		t.Fatalf("missing wrap: %v", wrapped)
	}
	if !strings.Contains(wrapped.Error(), "VPP route API failed (-2)") {
		t.Fatalf("missing retval: %v", wrapped)
	}
}

func TestSessionApplyReusesMetadata(t *testing.T) {
	stub := &stubChan{}
	sess := &vppAPISession{ch: stub, ifaces: map[string]uint32{"wg1": 4}, cliSrc: 2}
	route := Route{0, "198.51.100.77/32", "10.62.30.1", "wg1"}
	for _, lines := range [][]string{nil, {route.Command("add")}, {route.Command("add")}, {route.Command("del")}} {
		if err := sess.apply(context.Background(), lines); err != nil {
			t.Fatal(err)
		}
	}
	if len(stub.dumps) != 0 {
		t.Fatalf("cached submissions must not dump metadata: %v", stub.dumps)
	}
	if len(stub.reqs) != 3 {
		t.Fatalf("each route submission must reach VPP, requests=%d", len(stub.reqs))
	}
	for _, req := range stub.reqs {
		if req.Route.Src != 2 || req.Route.Paths[0].SwIfIndex != 4 {
			t.Fatalf("cached metadata not used: %+v", req.Route)
		}
	}
	if stub.reqs[2].IsAdd {
		t.Fatal("delete submitted as add")
	}
}

func TestApplyFailureDropsCachedSession(t *testing.T) {
	dropAPICache()
	t.Cleanup(dropAPICache)
	socket := t.TempDir() + "/api.sock"
	if err := os.WriteFile(socket, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{APISocket: socket}
	ident, err := socketIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubChan{retval: -2}
	apiCache = &vppAPISession{ch: stub, ifaces: map[string]uint32{"wg1": 4}, cliSrc: 2}
	apiIdent = ident
	route := Route{0, "198.51.100.77/32", "10.62.30.1", "wg1"}
	err = applyVPPRoutes(context.Background(), cfg, []string{route.Command("add")})
	if err == nil || !strings.Contains(err.Error(), "VPP route API failed (-2)") {
		t.Fatalf("route failure not propagated: %v", err)
	}
	if len(stub.reqs) != 1 || len(stub.dumps) != 0 {
		t.Fatalf("expected direct route submission, requests=%d dumps=%d", len(stub.reqs), len(stub.dumps))
	}
	if apiCache != nil || apiIdent != (apiIdentity{}) {
		t.Fatal("failed submission retained cached session")
	}
}

func TestApplyEmptyProbesBinaryAPINotCLI(t *testing.T) {
	stub := &stubRouteAPI{}
	b := &VPPBackend{
		Config:   &Config{VPPSocket: "/no/such.sock", APISocket: "/no/such.sock"},
		routeAPI: stub,
	}
	if err := b.Apply(nil); err != nil {
		t.Fatal(err)
	}
	if stub.calls != 1 {
		t.Fatalf("empty Apply must probe Binary API, calls=%d", stub.calls)
	}
}

func TestRouteAddDelIPv6NextHop(t *testing.T) {
	stub := &stubChan{}
	sess := &vppAPISession{ch: stub, ifaces: map[string]uint32{"tap2490": 12}, cliSrc: 1}
	err := sess.routeAddDel(true, Route{Table: 2490, Prefix: "2001:2::/48", Via: "fd42:1111:2222:30::2", Interface: "tap2490"})
	if err != nil {
		t.Fatal(err)
	}
	if stub.reqs[0].Route.Paths[0].Proto != fib_types.FIB_API_PATH_NH_PROTO_IP6 {
		t.Fatal("expected IPv6 next hop proto")
	}
	if stub.reqs[0].Route.Prefix.Address.Af != ip_types.ADDRESS_IP6 {
		t.Fatal("expected IPv6 prefix")
	}
}

func TestRouteAddDelMissingInterface(t *testing.T) {
	stub := &stubChan{}
	sess := &vppAPISession{
		ch:     stub,
		ifaces: map[string]uint32{},
		cliSrc: 1,
	}
	err := sess.routeAddDel(true, Route{0, "198.51.100.77/32", "10.62.30.1", "wg1"})
	if err == nil || !strings.Contains(err.Error(), "VPP route interface does not exist: wg1") {
		t.Fatalf("err %v", err)
	}
	if len(stub.dumps) != 1 {
		t.Fatalf("missing interface must trigger one interface dump, got %d", len(stub.dumps))
	}
}

func TestRouteDeleteThroughAMissingInterfaceIsDone(t *testing.T) {
	stub := &stubChan{}
	sess := &vppAPISession{ch: stub, ifaces: map[string]uint32{}, cliSrc: 1}
	if err := sess.routeAddDel(false, Route{0, "198.51.100.77/32", "10.62.30.1", "wg1"}); err != nil {
		t.Fatal(err)
	}
	if len(stub.reqs) != 1 || stub.reqs[0].IsMultipath || stub.reqs[0].Route.NPaths != 0 || stub.reqs[0].Route.Src != 1 {
		t.Fatalf("a path through a deleted interface must go by removing the entry: %+v", stub.reqs)
	}
}

func TestDropRouteRequest(t *testing.T) {
	stub := &stubChan{}
	sess := &vppAPISession{ch: stub, cliSrc: 1, dropSrc: 42}
	if err := sess.routeDrop(true, DropRoute{5, "2001:db8::/32"}); err != nil {
		t.Fatal(err)
	}
	route := stub.reqs[0].Route
	if route.Src != 42 {
		t.Fatalf("source %d: a drop route must not use the real routes' source", route.Src)
	}
	if route.TableID != 5 || route.Paths[0].Type != fib_types.FIB_API_PATH_TYPE_DROP || route.Paths[0].Proto != fib_types.FIB_API_PATH_NH_PROTO_IP6 || route.Paths[0].SwIfIndex != ^uint32(0) {
		t.Fatalf("%+v", route)
	}
}

func TestARealRouteClearsLeftoversOnADropEntry(t *testing.T) {
	rememberDrops(map[DropRoute]bool{{0, "203.0.113.0/24"}: true})
	defer rememberDrops(nil)
	stub := &stubChan{}
	sess := &vppAPISession{ch: stub, ifaces: map[string]uint32{"wg1": 4}, cliSrc: 1}
	if err := sess.routeAddDel(true, Route{0, "203.0.113.0/24", "10.62.30.1", "wg1"}); err != nil {
		t.Fatal(err)
	}
	if len(stub.reqs) != 2 || stub.reqs[0].IsAdd || stub.reqs[0].Route.NPaths != 0 || !stub.reqs[1].IsAdd {
		t.Fatalf("%+v", stub.reqs)
	}
}

func TestParseFIBTreatsOurDropEntryAsFree(t *testing.T) {
	text := "ipv4-VRF:0, fib_index:0\n203.0.113.0/24\n  unicast-ip4-chain\n  [@0]: dpo-load-balance: [proto:ip4 index:34 buckets:1 uRPF:37 to:[0:0]]\n    [0] [@0]: dpo-drop ip4\n198.51.100.0/24\n  unicast-ip4-chain\n  [@0]: dpo-load-balance: [proto:ip4 index:35 buckets:1 uRPF:38 to:[0:0]]\n    [0] [@0]: dpo-drop ip4\n"
	rememberDrops(map[DropRoute]bool{{0, "203.0.113.0/24"}: true})
	defer rememberDrops(nil)
	live, err := parseFIB(text, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := live[RouteKey{0, "203.0.113.0/24"}]; ok {
		t.Fatal("our drop entry looks occupied")
	}
	if _, ok := live[RouteKey{0, "198.51.100.0/24"}]; !ok {
		t.Fatal("somebody else's drop entry looks free")
	}
}

func TestDropSourceIsFoundByName(t *testing.T) {
	stub := &stubChan{sources: []fib.FibSource{{ID: 9, Name: "CLI"}, {ID: 31, Name: dropSourceName}}}
	sess := &vppAPISession{ch: stub}
	if id, err := sess.dropSource(); err != nil || id != 31 {
		t.Fatalf("%d %v", id, err)
	}
}

func TestDumpCLISourceDrainsMultiReply(t *testing.T) {
	stub := &stubChan{sources: []fib.FibSource{
		{ID: 1, Name: "API"},
		{ID: 2, Name: "CLI"},
		{ID: 3, Name: "interface"},
	}}
	sess := &vppAPISession{ch: stub}
	id, err := sess.dumpCLISource()
	if err != nil {
		t.Fatal(err)
	}
	if id != 2 {
		t.Fatalf("CLI source %d", id)
	}
	if stub.reads != len(stub.sources)+1 {
		t.Fatalf("dump stopped early: reads=%d", stub.reads)
	}
}

func TestLiveVPPApply(t *testing.T) {
	sock := liveAPISocket()
	if _, err := os.Stat(sock); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("live VPP API socket not present: %s", sock)
		}
		t.Fatal(err)
	}
	b := &VPPBackend{Config: &Config{APISocket: sock}}
	if err := b.Apply(nil); err != nil {
		t.Fatal(err)
	}
}
