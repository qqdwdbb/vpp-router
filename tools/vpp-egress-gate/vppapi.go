package gate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/fib"
	"go.fd.io/govpp/binapi/fib_types"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip"
	"go.fd.io/govpp/binapi/ip_types"
	"go.fd.io/govpp/core"
)

type routeAPI interface {
	apply(context.Context, []string) error
}

type vppAPISession struct {
	conn    *core.Connection
	ch      api.Channel
	ifaces  map[string]uint32
	cliSrc  uint8
	dropSrc uint8 // zero until drop routes first need it
	// defaultSrc is zero until the default route first needs it; wireguard is 1 once VPP is
	// known to have the plugin's API and -1 once known not to.
	defaultSrc uint8
	wireguard  int8
	dhcp       int8 // as wireguard, for the DHCP plugin
}

type apiIdentity struct {
	path  string
	ino   uint64
	ctime int64
	locks string
}

var (
	apiMu    = make(chan struct{}, 1)
	apiCache *vppAPISession
	apiIdent apiIdentity
)

// vppInvalidInterface is VNET_API_ERROR_INVALID_SW_IF_INDEX.
const vppInvalidInterface = -54

func parseRouteLine(line string) (add bool, route Route, err error) {
	words := strings.Fields(line)
	if len(words) != 9 || words[0] != "ip" || words[1] != "route" || words[4] != "table" || words[6] != "via" {
		return false, Route{}, fmt.Errorf("unsupported route command: %s", line)
	}
	if words[2] != "add" && words[2] != "del" {
		return false, Route{}, fmt.Errorf("unsupported route command: %s", line)
	}
	table, convErr := strconv.Atoi(words[5])
	if convErr != nil || table < 0 {
		return false, Route{}, fmt.Errorf("unsupported route command: %s", line)
	}
	if _, err := parsePrefixStrict(words[3]); err != nil {
		return false, Route{}, fmt.Errorf("unsupported route command: %s", line)
	}
	if _, err := parseAddr(words[7]); err != nil {
		return false, Route{}, fmt.Errorf("unsupported route command: %s", line)
	}
	return words[2] == "add", Route{uint32(table), words[3], words[7], words[8]}, nil
}

func lockStamp(cfg *Config) string {
	var b strings.Builder
	for _, name := range cfg.LockFiles {
		st, err := stampOf(name)
		if err != nil {
			fmt.Fprintf(&b, "%s=0;", name)
			continue
		}
		fmt.Fprintf(&b, "%s=%d;", name, st.Mtime)
	}
	return b.String()
}

func socketIdentity(cfg *Config) (apiIdentity, error) {
	path := cfg.APISocket
	if path == "" {
		path = "/run/vpp/api.sock"
	}
	st, err := stampOf(path)
	if err != nil {
		return apiIdentity{}, err
	}
	return apiIdentity{path: path, ino: st.Ino, ctime: st.Ctime, locks: lockStamp(cfg)}, nil
}

func dropAPICache() {
	if apiCache != nil {
		if apiCache.ch != nil {
			apiCache.ch.Close()
		}
		if apiCache.conn != nil {
			apiCache.conn.Disconnect()
		}
		apiCache = nil
		apiIdent = apiIdentity{}
	}
}

func vppAPI(cfg *Config) (*vppAPISession, error) {
	ident, err := socketIdentity(cfg)
	if err != nil {
		return nil, err
	}
	if apiCache != nil && apiIdent == ident {
		return apiCache, nil
	}
	dropAPICache()
	conn, err := govpp.Connect(ident.path)
	if err != nil {
		return nil, err
	}
	ch, err := conn.NewAPIChannel()
	if err != nil {
		conn.Disconnect()
		return nil, err
	}
	ch.SetReplyTimeout(2 * time.Second)
	wanted := []api.Message{
		(*ip.IPRouteAddDelV2)(nil),
		(*ip.IPRouteAddDelV2Reply)(nil),
		(*interfaces.SwInterfaceDump)(nil),
		(*interfaces.SwInterfaceDetails)(nil),
		(*fib.FibSourceDump)(nil),
		(*fib.FibSourceDetails)(nil),
	}
	if err := ch.CheckCompatiblity(wanted...); err != nil {
		ch.Close()
		conn.Disconnect()
		return nil, err
	}
	sess := &vppAPISession{conn: conn, ch: ch}
	if err := sess.refresh(); err != nil {
		ch.Close()
		conn.Disconnect()
		return nil, err
	}
	apiCache, apiIdent = sess, ident
	return sess, nil
}

func (s *vppAPISession) refresh() error {
	ifaces, err := s.dumpInterfaces()
	if err != nil {
		return err
	}
	src, err := s.dumpCLISource()
	if err != nil {
		return err
	}
	s.ifaces, s.cliSrc = ifaces, src
	return nil
}

func (s *vppAPISession) dumpInterfaces() (map[string]uint32, error) {
	req := s.ch.SendMultiRequest(&interfaces.SwInterfaceDump{SwIfIndex: ^interface_types.InterfaceIndex(0)})
	out := map[string]uint32{}
	for {
		details := &interfaces.SwInterfaceDetails{}
		last, err := req.ReceiveReply(details)
		if err != nil {
			return nil, err
		}
		if last {
			break
		}
		name := strings.TrimRight(details.InterfaceName, "\x00")
		if name != "" {
			out[name] = uint32(details.SwIfIndex)
		}
	}
	return out, nil
}

func (s *vppAPISession) dumpCLISource() (uint8, error) {
	req := s.ch.SendMultiRequest(&fib.FibSourceDump{})
	var id uint8
	found := false
	for {
		details := &fib.FibSourceDetails{}
		last, err := req.ReceiveReply(details)
		if err != nil {
			return 0, err
		}
		if last {
			break
		}
		name := strings.TrimRight(details.Src.Name, "\x00")
		if name == "CLI" {
			id = details.Src.ID
			found = true
		}
	}
	if !found {
		return 0, fmt.Errorf("VPP CLI fib source is missing")
	}
	return id, nil
}

func (s *vppAPISession) apply(ctx context.Context, lines []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Reuse session metadata loaded at connect time. A missing interface is
	// refreshed by routeAddDel; API identity changes rebuild the session.
	for _, line := range lines {
		if err := ctx.Err(); err != nil {
			return err
		}
		add, route, err := parseRouteLine(line)
		if err != nil {
			return err
		}
		if err := s.routeAddDel(add, route); err != nil {
			return err
		}
	}
	return nil
}

func (s *vppAPISession) routeAddDel(add bool, route Route) error {
	idx, ok := s.ifaces[route.Interface]
	if !ok {
		ifaces, err := s.dumpInterfaces()
		if err != nil {
			return err
		}
		s.ifaces = ifaces
		idx, ok = s.ifaces[route.Interface]
	}
	if !ok {
		if !add {
			return s.routeDeleteEntry(route)
		}
		return fmt.Errorf("%w: %s", errVPPInterfaceMissing, route.Interface)
	}
	if add && isKnownDrop(route.Key()) {
		// Whatever is there is a leftover: a working path would not be added again.
		if err := s.routeDeleteEntry(route); err != nil {
			return err
		}
	}
	prefix, err := ip_types.ParsePrefix(route.Prefix)
	if err != nil {
		return err
	}
	via := net.ParseIP(route.Via)
	if via == nil {
		return fmt.Errorf("invalid next hop %s", route.Via)
	}
	nh := ip_types.NewAddress(via)
	proto := fib_types.FIB_API_PATH_NH_PROTO_IP4
	if via.To4() == nil {
		proto = fib_types.FIB_API_PATH_NH_PROTO_IP6
	}
	req := &ip.IPRouteAddDelV2{
		IsAdd:       add,
		IsMultipath: true,
		Route: ip.IPRouteV2{
			TableID: route.Table,
			Prefix:  prefix,
			NPaths:  1,
			Src:     s.cliSrc,
			Paths: []fib_types.FibPath{{
				SwIfIndex: idx,
				Weight:    1,
				Proto:     proto,
				Nh:        fib_types.FibPathNh{Address: nh.Un},
			}},
		},
	}
	reply := &ip.IPRouteAddDelV2Reply{}
	if err := s.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		// The interface went away since it was last listed.
		var failure api.VPPApiError
		if errors.As(err, &failure) && int32(failure) == vppInvalidInterface {
			delete(s.ifaces, route.Interface)
			if !add {
				return s.routeDeleteEntry(route)
			}
			return fmt.Errorf("%w: %s", errVPPInterfaceMissing, route.Interface)
		}
		return err
	}
	if reply.Retval != 0 {
		return fmt.Errorf("VPP route API failed (%d): %s", reply.Retval, route.Prefix)
	}
	return nil
}

func applyVPPRoutes(ctx context.Context, cfg *Config, lines []string) error {
	select {
	case apiMu <- struct{}{}:
		defer func() { <-apiMu }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sess, err := vppAPI(cfg)
	if err != nil {
		dropAPICache()
		return err
	}
	if err := sess.apply(ctx, lines); err != nil {
		dropAPICache()
		return err
	}
	return nil
}

func missingVPPInterfaces(ctx context.Context, cfg *Config, names []string) (map[string]bool, error) {
	select {
	case apiMu <- struct{}{}:
		defer func() { <-apiMu }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	sess, err := vppAPI(cfg)
	if err != nil {
		dropAPICache()
		return nil, err
	}
	present, err := sess.dumpInterfaces()
	if err != nil {
		dropAPICache()
		return nil, err
	}
	sess.ifaces = present
	missing := map[string]bool{}
	for _, name := range names {
		if _, ok := present[name]; !ok {
			missing[name] = true
		}
	}
	return missing, nil
}

func liveAPISocket() string {
	if v := os.Getenv("VPP_API_SOCK"); v != "" {
		return v
	}
	return "/run/vpp/api.sock"
}
