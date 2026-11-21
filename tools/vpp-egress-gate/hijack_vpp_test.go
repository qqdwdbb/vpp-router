package gate

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"go.fd.io/govpp/binapi/acl_types"
)

func TestHijackVPPConfiguration(t *testing.T) {
	load := func(extra map[string]any) (*GateFile, error) {
		path := filepath.Join(t.TempDir(), "gate.json")
		doc := map[string]any{
			"listen": []any{[]any{"10.61.30.2", 1053}}, "upstream": []any{"127.0.0.1", 53},
			"lease_file": "/x", "hijack_dns": true, "hijack_interfaces": "n1-lan",
		}
		for k, v := range extra {
			doc[k] = v
		}
		writeJSON(t, path, doc)
		return LoadGateFile(path)
	}
	good := map[string]any{"interface": "loop200", "via": []any{"10.61.30.2", "fd00::2"}, "sources": []any{"10.61.30.0/24", "fd00::/64"}}
	g, err := load(map[string]any{"hijack_vpp": []any{good}})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.HijackVPP) != 1 || g.HijackVPP[0].Interface != "loop200" || len(g.HijackVPP[0].Via) != 2 {
		t.Fatalf("%+v", g.HijackVPP)
	}
	for name, tc := range map[string]struct {
		doc  map[string]any
		want string
	}{
		"not_a_list":  {map[string]any{"hijack_vpp": "loop200"}, "must be a list"},
		"no_via":      {map[string]any{"hijack_vpp": []any{map[string]any{"interface": "loop200", "sources": []any{"10.61.30.0/24"}}}}, "needs via and sources"},
		"bad_via":     {map[string]any{"hijack_vpp": []any{map[string]any{"interface": "loop200", "via": []any{"x"}, "sources": []any{"10.61.30.0/24"}}}}, "invalid via"},
		"bad_source":  {map[string]any{"hijack_vpp": []any{map[string]any{"interface": "loop200", "via": []any{"10.61.30.2"}, "sources": []any{"10.61.30.1/24"}}}}, "invalid source"},
		"two_vias":    {map[string]any{"hijack_vpp": []any{map[string]any{"interface": "loop200", "via": []any{"10.61.30.2", "10.61.30.3"}, "sources": []any{"10.61.30.0/24"}}}}, "one via per"},
		"no_family":   {map[string]any{"hijack_vpp": []any{map[string]any{"interface": "loop200", "via": []any{"10.61.30.2"}, "sources": []any{"fd00::/64"}}}}, "no via of its family"},
		"typo":        {map[string]any{"hijack_vpp": []any{map[string]any{"interface": "loop200", "via": []any{"10.61.30.2"}, "sources": []any{"10.61.30.0/24"}, "source": "x"}}}, "unknown field"},
		"without_dns": {map[string]any{"hijack_dns": false, "hijack_vpp": []any{good}}, "requires hijack_dns"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(tc.doc); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestHijackVPNUsesLANNextHopInterface(t *testing.T) {
	policy := vppHijackPolicy{Interface: "wg0", ViaInterface: "loop0"}
	index, err := hijackViaIndex(policy, map[string]uint32{"wg0": 8, "loop0": 4})
	if err != nil || index != 4 {
		t.Fatalf("index=%d err=%v", index, err)
	}
	policy.ViaInterface = ""
	index, err = hijackViaIndex(policy, map[string]uint32{"wg0": 8})
	if err != nil || index != 8 {
		t.Fatalf("default index=%d err=%v", index, err)
	}
	policy.ViaInterface = "missing"
	if _, err = hijackViaIndex(policy, map[string]uint32{"wg0": 8}); !errors.Is(err, errVPPInterfaceMissing) {
		t.Fatal(err)
	}
}

func TestHijackVPPRulesLeaveLinuxAlone(t *testing.T) {
	entry := HijackVPPEntry{
		Interface: "loop200", Via: []netip.Addr{netip.MustParseAddr("10.61.30.2")},
		Sources: []netip.Prefix{netip.MustParsePrefix("10.61.30.0/24"), netip.MustParsePrefix("fd00::/64")},
	}
	listen := []Upstream{{Host: "127.0.0.1", Port: 1053}, {Host: "10.61.30.2", Port: 1053}, {Host: "10.61.30.3", Port: 1053}, {Host: "fd00::2", Port: 1053}}
	rules := vppHijackRules(entry, entry.Via[0], listen)
	var text []string
	for _, r := range rules {
		action := "deny"
		if r.IsPermit == acl_types.ACL_ACTION_API_PERMIT {
			action = "permit"
		}
		text = append(text, strings.Join([]string{action, r.SrcPrefix.String(), r.DstPrefix.String(), r.Proto.String()}, " "))
	}
	got := strings.Join(text, "\n")
	// Every deny must come before a permit it overlaps, as the first match wins.
	want := strings.Join([]string{
		"deny 10.61.30.2/32 0.0.0.0/0 IP_API_PROTO_HOPOPT",
		"deny 10.61.30.3/32 0.0.0.0/0 IP_API_PROTO_HOPOPT",
		"deny 0.0.0.0/0 224.0.0.0/4 IP_API_PROTO_HOPOPT",
		"deny 0.0.0.0/0 255.255.255.255/32 IP_API_PROTO_HOPOPT",
		"permit 10.61.30.0/24 0.0.0.0/0 IP_API_PROTO_UDP",
		"permit 10.61.30.0/24 0.0.0.0/0 IP_API_PROTO_TCP",
	}, "\n")
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	last := rules[len(rules)-1]
	if last.DstportOrIcmpcodeFirst != 53 || last.DstportOrIcmpcodeLast != 53 || last.SrcportOrIcmptypeLast != 65535 {
		t.Fatalf("ports %+v", last)
	}
}

func TestHijackVPPPoliciesPerFamily(t *testing.T) {
	policies := vppHijackPolicies(&GateFile{HijackVPP: []HijackVPPEntry{
		{Interface: "a", Via: []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("fd00::2")}, Sources: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("fd00::/64")}},
		{Interface: "b", Via: []netip.Addr{netip.MustParseAddr("10.0.1.2")}, Sources: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")}},
	}})
	var ids []uint32
	for _, p := range policies {
		ids = append(ids, p.ID)
		if !strings.HasPrefix(p.Tag, vppHijackTagPrefix) {
			t.Fatalf("tag %s", p.Tag)
		}
	}
	if len(ids) != 3 || ids[0] != 5300 || ids[1] != 5301 || ids[2] != 5302 {
		t.Fatalf("ids %v", ids)
	}
}

func TestNATRunsBeforeABF(t *testing.T) {
	const after = "\nl2-output-nonip:\n  none configured\n"
	for name, tc := range map[string]struct {
		features string
		want     bool
	}{
		"nat_inside":     {"ip4-unicast:\n  ip4-sv-reassembly-feature\n  nat44-ei-in2out\n  abf-input-ip4\n" + after, true},
		"output_feature": {"ip4-unicast:\n  abf-input-ip4\n" + after, false},
		"no_abf":         {"ip4-unicast:\n  nat44-ei-in2out\n" + after, false},
		"abf_first":      {"ip4-unicast:\n  abf-input-ip4\n  nat44-ei-in2out\n" + after, false},
		"other_arc":      {"ip4-unicast:\n  abf-input-ip4\nip4-output:\n  nat44-ei-in2out-output\n", false},
		"nothing":        {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := natRunsBeforeABF(tc.features); got != tc.want {
				t.Fatalf("got %v", got)
			}
		})
	}
}

func TestVPPHijackKeeperReportsOncePerVPP(t *testing.T) {
	out := captureWaitLog(t)
	generation := "a"
	k := &vppHijackKeeper{
		apply:      func() error { return nil },
		check:      func() []string { return []string{"NAT runs first"} },
		generation: func() (string, error) { return generation, nil },
		problems:   failureLog{what: "x"},
	}
	k.ensure()
	k.ensure()
	if strings.Count(out.String(), "NAT runs first") != 1 {
		t.Fatalf("got:\n%s", out)
	}
	generation = "b"
	k.ensure()
	if strings.Count(out.String(), "NAT runs first") != 2 {
		t.Fatalf("got:\n%s", out)
	}
}

func TestVPPHijackKeeperAppliesOncePerVPP(t *testing.T) {
	captureWaitLog(t)
	generation, applied := "a", 0
	fail := errors.New("no plugin")
	var result error
	k := &vppHijackKeeper{
		apply:      func() error { applied++; return result },
		generation: func() (string, error) { return generation, nil },
		problems:   failureLog{what: "x"},
	}
	k.ensure()
	k.ensure()
	if applied != 1 {
		t.Fatalf("applied %d times for one VPP", applied)
	}
	generation = "b"
	k.ensure()
	if applied != 2 {
		t.Fatal("a restarted VPP did not get its policies back")
	}
	generation, result = "c", fail
	k.ensure()
	k.ensure()
	if applied != 4 {
		t.Fatal("a failure was not retried")
	}
	result = nil
	k.ensure()
	k.ensure()
	if applied != 5 {
		t.Fatalf("applied %d", applied)
	}
}
