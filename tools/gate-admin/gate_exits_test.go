package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func (f *adminFixture) exit(t *testing.T, name string) AdminExit {
	t.Helper()
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, exit := range state.Exits {
		if exit.Name == name {
			return exit
		}
	}
	t.Fatalf("no exit %s in %+v", name, state.Exits)
	return AdminExit{}
}

func TestCustomExitMakesADHCPUplinkUsableByRules(t *testing.T) {
	f := newAdminFixture(t)
	offered := filepath.Join(f.dir, "interfaces.json")
	os.WriteFile(offered, []byte(`[{"interface":"wan1","dhcp":true}]`), 0o600)
	f.admin.opts.ExitsFile = offered
	f.admin.opts.CustomExits = filepath.Join(f.dir, "gate-exits.json")
	if exit := f.exit(t, "wan1"); exit.Rules || !exit.DHCP || !exit.Editable || exit.Custom {
		t.Fatalf("offered DHCP exit %+v", exit)
	}
	// Nothing uses it yet: saved at once, Gate not restarted.
	state, err := f.admin.SetExit("", "wan1", "10.61.20.5", "", false, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.sys.calls, "restart") || state.Pending != nil {
		t.Fatalf("calls %v", f.sys.calls)
	}
	if exit := f.exit(t, "wan1"); !exit.Rules || exit.DHCP || exit.Via4 != "10.61.20.5" || !exit.Custom || !slices.Equal(exit.Families, []int{4}) {
		t.Fatalf("custom exit %+v", exit)
	}
	if _, err := f.admin.AddRule("direct", "wan1", nil, f.textfixture, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "direct"); rule["interface"] != "wan1" || rule["via"] != "10.61.20.5" {
		t.Fatalf("rule %+v", rule)
	}
	f.confirm(t)

	// A new next hop moves the rules on the exit with it, as a change to confirm.
	f.sys.calls = nil
	if _, err := f.admin.SetExit("", "wan1", "10.61.20.6", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "direct"); rule["via"] != "10.61.20.6" || !slices.Contains(f.sys.calls, "restart") {
		t.Fatalf("rule %+v, calls %v", rule, f.sys.calls)
	}
	// Rolling back restores the rules and the exits file together.
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "direct"); rule["via"] != "10.61.20.5" {
		t.Fatalf("rollback left %+v", rule)
	}
	if exit := f.exit(t, "wan1"); exit.Via4 != "10.61.20.5" {
		t.Fatalf("exits file not rolled back: %+v", exit)
	}

	// Back to DHCP alone would leave the rule without a next hop.
	if _, err := f.admin.SetExit("", "wan1", "", "", true, "admin"); err == nil || !strings.Contains(err.Error(), "DHCP") {
		t.Fatalf("DHCP under a rule: %v", err)
	}
}

func TestCustomExitRefusals(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.opts.CustomExits = filepath.Join(f.dir, "gate-exits.json")
	for name, call := range map[string]func() error{
		"no next hop":       func() error { _, err := f.admin.SetExit("", "wan1", "", "", false, "admin"); return err },
		"IPv6 as IPv4":      func() error { _, err := f.admin.SetExit("", "wan1", "fd00::1", "", false, "admin"); return err },
		"DHCP and an IPv4":  func() error { _, err := f.admin.SetExit("", "wan1", "192.0.2.1", "", true, "admin"); return err },
		"bad name":          func() error { _, err := f.admin.SetExit("", "wan 1;x", "192.0.2.1", "", false, "admin"); return err },
		"a Fake-IP exit":    func() error { _, err := f.admin.SetExit("", "tap1", "172.31.0.9", "", false, "admin"); return err },
		"family taken away": func() error { _, err := f.admin.SetExit("", "loop10", "10.61.50.9", "", false, "admin"); return err },
		"nothing to delete": func() error { _, err := f.admin.DeleteExit("wan1", "admin"); return err },
	} {
		if err := call(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestCustomExitMovesBothFamilies(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.opts.CustomExits = filepath.Join(f.dir, "gate-exits.json")
	if _, err := f.admin.SetExit("", "loop10", "10.61.50.9", "fd00::9", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if f.rule(t, "vpn")["via"] != "10.61.50.9" || f.rule(t, "vpn6")["via"] != "fd00::9" {
		t.Fatalf("vpn %v, vpn6 %v", f.rule(t, "vpn")["via"], f.rule(t, "vpn6")["via"])
	}
	f.confirm(t)
	if exit := f.exit(t, "loop10"); exit.Via4 != "10.61.50.9" || exit.Via6 != "fd00::9" || !exit.Custom {
		t.Fatalf("%+v", exit)
	}
	// Deleting the hand-set exit leaves the rules as they are.
	if _, err := f.admin.DeleteExit("loop10", "admin"); err != nil {
		t.Fatal(err)
	}
	if f.rule(t, "vpn")["via"] != "10.61.50.9" {
		t.Fatal("deleting the exit changed a rule")
	}
}

// One interface, two next hops: each named exit keeps its own, and moves only its own rules.
func TestNamedExitsShareAnInterface(t *testing.T) {
	f := newAdminFixture(t)
	f.admin.opts.CustomExits = filepath.Join(f.dir, "gate-exits.json")
	// Lists of their own, so that each rule is a group of its own.
	direct, other := filepath.Join(f.dir, "direct.domains"), filepath.Join(f.dir, "other.domains")
	os.WriteFile(direct, []byte("direct.example\n"), 0o644)
	os.WriteFile(other, []byte("other.example\n"), 0o644)
	if _, err := f.admin.SetExit("", "wan1", "10.61.20.5", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.SetExit("wan1-b", "wan1", "10.61.20.6", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if a, b := f.exit(t, "wan1"), f.exit(t, "wan1-b"); a.Via4 != "10.61.20.5" || b.Via4 != "10.61.20.6" || b.Interface != "wan1" || !b.Rules || !b.Custom || !b.Editable {
		t.Fatalf("wan1 %+v, wan1-b %+v", a, b)
	}
	if _, err := f.admin.AddRule("direct", "wan1", nil, direct, "", "admin"); err != nil {
		t.Fatal(err)
	}
	f.confirm(t)
	if _, err := f.admin.AddRule("other", "wan1-b", nil, other, "", "admin"); err != nil {
		t.Fatal(err)
	}
	f.confirm(t)
	if rule := f.rule(t, "other"); rule["interface"] != "wan1" || rule["via"] != "10.61.20.6" || rule[exitNameField] != "wan1-b" {
		t.Fatalf("other %+v", rule)
	}
	if rule := f.rule(t, "direct"); rule["via"] != "10.61.20.5" || rule[exitNameField] != nil {
		t.Fatalf("direct %+v", rule)
	}
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range state.Groups {
		if want := map[string]string{"direct": "wan1", "other": "wan1-b"}[group.ID]; want != "" && group.Exit != want {
			t.Fatalf("group %s on %s", group.ID, group.Exit)
		}
	}

	// A new next hop for one exit leaves the other's rules alone.
	if _, err := f.admin.SetExit("wan1-b", "wan1", "10.61.20.7", "", false, "admin"); err != nil {
		t.Fatal(err)
	}
	if f.rule(t, "other")["via"] != "10.61.20.7" || f.rule(t, "direct")["via"] != "10.61.20.5" {
		t.Fatalf("other %v, direct %v", f.rule(t, "other")["via"], f.rule(t, "direct")["via"])
	}
	f.confirm(t)

	// Switching a rule between the two changes its next hop and the name it carries.
	if _, err := f.admin.SwitchExit("direct", "wan1-b", "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "direct"); rule["via"] != "10.61.20.7" || rule[exitNameField] != "wan1-b" {
		t.Fatalf("switched %+v", rule)
	}
	f.confirm(t)
	if _, err := f.admin.SwitchExit("direct", "wan1", "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "direct"); rule["via"] != "10.61.20.5" || rule[exitNameField] != nil {
		t.Fatalf("switched back %+v", rule)
	}
	f.confirm(t)

	// Routes are counted by the exit their next hop belongs to.
	stats := routeStats([]adminRoute{{Prefix: "192.0.2.1/32", Interface: "wan1", Via: "10.61.20.5"}, {Prefix: "192.0.2.2/32", Interface: "wan1", Via: "10.61.20.7"}, {Prefix: "192.0.2.3/32", Interface: "wan1", Via: "10.61.20.7"}},
		[]map[string]any{f.rule(t, "direct"), f.rule(t, "other")})
	if !slices.Equal(stats.Exits, []AdminExitRoutes{{"wan1", 1}, {"wan1-b", 2}}) {
		t.Fatalf("stats %+v", stats.Exits)
	}

	for name, call := range map[string]func() error{
		"an interface's name": func() error { _, err := f.admin.SetExit("wg1", "wan1", "10.61.20.8", "", false, "admin"); return err },
		"a bad name":          func() error { _, err := f.admin.SetExit("a b", "wan1", "10.61.20.8", "", false, "admin"); return err },
	} {
		if err := call(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// Deleted, with a rule still on it, it stays while the rule does, and goes with it.
	if _, err := f.admin.DeleteExit("wan1-b", "admin"); err != nil {
		t.Fatal(err)
	}
	if exit := f.exit(t, "wan1-b"); exit.Custom || exit.Via4 != "10.61.20.7" {
		t.Fatalf("deleted exit in use %+v", exit)
	}
	if _, err := f.admin.DeleteRule("other", "admin"); err != nil {
		t.Fatal(err)
	}
	f.confirm(t)
	state, err = f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, exit := range state.Exits {
		if exit.Name == "wan1-b" {
			t.Fatalf("deleted exit still offered: %+v", exit)
		}
	}
	if exit := f.exit(t, "wan1"); exit.Via4 != "10.61.20.5" {
		t.Fatalf("wan1 %+v", exit)
	}
}
