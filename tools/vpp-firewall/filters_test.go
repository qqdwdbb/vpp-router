package main

import (
	"go.fd.io/govpp/binapi/acl_types"
	"testing"
)

func TestRestrictedForwardPreservesIPv6Firewall(t *testing.T) {
	f := newFake()
	st, _ := f.Read(true, true, nil)
	cfg := &Config{IPv6Firewall: true, Forwards: []Forward{{Interface: "port0.100", Protocol: "tcp", ExternalPort: 16161, InternalPort: 16161, InternalIP: "10.61.30.2", Sources: []string{"198.18.0.0/20"}}}}
	rules := inboundRules(cfg, st, []*iface{st.byName("port0.100")}, nil)
	if len(rules) < 4 || rules[0].IsPermit != acl_types.ACL_ACTION_API_PERMIT || rules[0].SrcPrefix.Len != 20 || rules[1].IsPermit != acl_types.ACL_ACTION_API_DENY || rules[1].DstportOrIcmpcodeFirst != 16161 {
		t.Fatalf("missing source restriction: %v", rules)
	}
	last := rules[len(rules)-1]
	if last.IsPermit != acl_types.ACL_ACTION_API_DENY || last.DstPrefix.Address.Af != 1 {
		t.Fatal("IPv6 default deny was lost")
	}
}

func TestLANDenyReconcilesWithoutRemovingWANACL(t *testing.T) {
	f := newFake()
	cfg := &Config{IPv6Firewall: true, LANDeny: []LANDenyRule{{Interface: "loop0", Destination: "8.8.8.8/32", Protocol: "tcp"}}}
	apply := func() {
		st, _ := f.Read(true, true, nil)
		if err := reconcile(f, cfg, st); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	wan := f.aclByTag(aclInTag)
	lan := f.aclByTag(lanTag + "loop0")
	if wan == nil || lan == nil || len(f.lists[2].Input) != 1 || len(f.lists[1].Input) != 1 {
		t.Fatal("ACL attachment missing")
	}
	index := lan.Index
	apply()
	if f.aclByTag(lanTag+"loop0").Index != index {
		t.Fatal("unchanged policy was recreated")
	}
	cfg.LANDeny = nil
	apply()
	if f.aclByTag(lanTag+"loop0") != nil || len(f.lists[1].Input) != 0 || len(f.lists[2].Input) != 1 {
		t.Fatal("removing LAN policy touched WAN ACL")
	}
}

func TestInvalidForwardSourceRejected(t *testing.T) {
	for _, source := range []string{"not-a-prefix", "2001:db8::/32", "10.61.30.1/24"} {
		if validateFilters(&Config{Forwards: []Forward{{Sources: []string{source}}}}) == nil {
			t.Fatalf("accepted %s", source)
		}
	}
}
