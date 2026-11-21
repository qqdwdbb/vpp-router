package main

import (
	"path/filepath"
	"testing"
)

func TestTProxyExitsForRealAndFakeRules(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.opts.CustomExits = filepath.Join(f.dir, "exits.json")
	if _, err := f.admin.SetTProxyExit("real", 7893, "", nil, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.AddRule("real_rule", "real", nil, f.textfixture, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "real_rule"); rule["tproxy_exit"] != "real" || rule["fakeip_range"] != nil {
		t.Fatalf("rule: %+v", rule)
	}
	f.confirm(t)
	ranges := f.upload(t, "office.ranges", "203.0.113.0/24\n")
	if _, err := f.admin.AddRule("range_rule", "real", nil, "", ranges, "admin"); err != nil {
		t.Fatal(err)
	}
	f.confirm(t)
	if _, err := f.admin.SetTProxyExit("fake", 7894, "127.0.0.1:5354", []string{"198.19.0.0/16"}, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.AddRule("fake_rule", "fake", nil, f.textfixture, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "fake_rule"); rule["tproxy_exit"] != "fake" || rule["fakeip_range"] == nil {
		t.Fatalf("rule: %+v", rule)
	}
	f.confirm(t)
	if _, err := f.admin.SetTProxyExit("bad", 0, "", nil, false, "admin"); err == nil {
		t.Fatal("accepted invalid port")
	}
	if _, err := f.admin.SetTProxyExit("bad", 7893, "", []string{"198.18.0.0/15"}, false, "admin"); err == nil {
		t.Fatal("accepted Fake-IP without DNS")
	}
}
