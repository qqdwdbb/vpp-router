package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	gate "vpp.local/vpp-egress-gate"
)

func (f *adminFixture) confirm(t *testing.T) {
	t.Helper()
	if err := f.admin.Confirm("admin"); err != nil {
		t.Fatal(err)
	}
}

// carriers lists the rules that carry the default route, by name.
func (f *adminFixture) carriers(t *testing.T) []string {
	t.Helper()
	doc, err := readJSONObject(f.routes)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, item := range doc["routes"].([]any) {
		rule := item.(map[string]any)
		if carries, _ := rule[defaultRouteField].(bool); carries {
			names = append(names, ruleName(rule))
		}
	}
	return names
}

func TestDefaultExitOptions(t *testing.T) {
	f := newAdminFixture(t)
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	// tap1 is offered through the rule that sends real addresses there, not the Fake-IP one.
	if state.Default.Exit != "" || strings.Join(state.Default.Options, ",") != "wg1,loop10,tap1" {
		t.Fatalf("%+v", state.Default)
	}
	if _, err := f.admin.SetDefaultExit("nope", "admin"); err == nil {
		t.Fatal("an unknown exit was accepted")
	}
	if _, err := f.admin.SetDefaultExit("", "admin"); err == nil {
		t.Fatal("no change was accepted")
	}
}

func TestDefaultExitGoesOnTheRulesOfTheExit(t *testing.T) {
	f := newAdminFixture(t)
	state, err := f.admin.SetDefaultExit("loop10", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.carriers(t); strings.Join(got, ",") != "vpn,vpn6" || state.Default.Exit != "loop10" {
		t.Fatalf("carriers %v, %+v", got, state.Default)
	}
	if !slices.Contains(f.sys.calls, "restart") || state.Pending == nil {
		t.Fatalf("a default exit is a change to confirm: %v", f.sys.calls)
	}
	f.confirm(t)

	// tap1 carries Fake-IP for mediafixture and real addresses for pinned: only pinned can carry it.
	if _, err := f.admin.SetDefaultExit("tap1", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.carriers(t); strings.Join(got, ",") != "pinned" {
		t.Fatalf("carriers %v", got)
	}
	f.confirm(t)
	if _, err := f.admin.SetDefaultExit("", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.carriers(t); len(got) != 0 {
		t.Fatalf("carriers %v", got)
	}
}

func TestDefaultExitStaysWhenItsRuleMoves(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SetDefaultExit("wg1", "admin"); err != nil {
		t.Fatal(err)
	}
	f.confirm(t)
	if got := f.carriers(t); strings.Join(got, ",") != "textfixture" {
		t.Fatalf("carriers %v", got)
	}
	// textfixture leaves wg1, and wg1 keeps the default route on a rule of its own.
	if _, err := f.admin.SwitchExit("textfixture", "loop10", "admin"); err != nil {
		t.Fatal(err)
	}
	f.confirm(t)
	carrier := f.rule(t, "default")
	if carrier["interface"] != "wg1" || carrier["via"] != "10.62.30.1" || carrier[defaultRouteField] != true || carrier["domain_files"] != nil {
		t.Fatalf("carrier %+v", carrier)
	}
	if f.rule(t, "textfixture")[defaultRouteField] != nil {
		t.Fatal("the default route followed the rule to another exit")
	}
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range state.Groups {
		if group.ID == "default" {
			t.Fatal("the carrier is listed as a rule")
		}
	}
	if state.Default.Exit != "wg1" {
		t.Fatalf("%+v", state.Default)
	}
	// The carrier does not count in the order, and stays.
	order := make([]string, 0, len(state.Groups))
	for i := len(state.Groups) - 1; i >= 0; i-- {
		order = append(order, state.Groups[i].ID)
	}
	if _, err := f.admin.Reorder(order, "admin"); err != nil {
		t.Fatal(err)
	}
	f.confirm(t)
	if got := f.carriers(t); strings.Join(got, ",") != "default" {
		t.Fatalf("carriers after reordering %v", got)
	}
	// A rule coming back to wg1 takes the default route over, and the carrier goes.
	if _, err := f.admin.SwitchExit("textfixture", "wg1", "admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.carriers(t); strings.Join(got, ",") != "textfixture" {
		t.Fatalf("carriers %v", got)
	}
}

func TestDefaultExitStaysWhenItsRuleIsDeleted(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SetDefaultExit("loop10", "admin"); err != nil {
		t.Fatal(err)
	}
	f.confirm(t)
	if _, err := f.admin.DeleteRule("vpn", "admin"); err != nil {
		t.Fatal(err)
	}
	// loop10's IPv4 and IPv6 were separate rules, so each family gets a carrier.
	if got := f.carriers(t); strings.Join(got, ",") != "default,default2" {
		t.Fatalf("carriers %v", got)
	}
	if f.rule(t, "default")["via"] != "10.61.50.1" || f.rule(t, "default2")["via"] != "fd00::1" {
		t.Fatal("carriers lost their next hops")
	}
	// Rolling back puts the rules back as they were.
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.carriers(t); strings.Join(got, ",") != "vpn,vpn6" {
		t.Fatalf("carriers after rollback %v", got)
	}
}

func TestDefaultExitStatusFromGate(t *testing.T) {
	f := newAdminFixture(t)
	f.sys.status = &gate.DefaultRouteStatus{Interface: "wg1", Families: []int{4}, Active: []int{}, Problem: "wg1 is down"}
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	if state.Default.Status == nil || state.Default.Status.Problem != "wg1 is down" {
		t.Fatalf("%+v", state.Default)
	}
}

func TestDefaultExitOnDHCP(t *testing.T) {
	f := newAdminFixture(t)
	wireguard := filepath.Join(f.dir, "wireguard.json")
	interfaces := filepath.Join(f.dir, "interfaces.json")
	os.WriteFile(wireguard, []byte(`[{"interface":"wg100","via":"10.9.0.1"}]`), 0o600)
	os.WriteFile(interfaces, []byte(`[{"interface":"wan2","via":"192.0.2.1"},{"interface":"wan1","dhcp":true}]`), 0o600)
	f.admin.opts.ExitsFile = wireguard + "," + interfaces
	state, err := f.admin.State()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(state.Default.Options, "wan1") || !slices.Contains(state.Default.Options, "wan2") || !slices.Contains(state.Default.Options, "wg100") {
		t.Fatalf("options %v", state.Default.Options)
	}
	// A static gateway is an exit for rules too; DHCP only for the default route.
	exits := map[string]bool{}
	for _, exit := range state.Exits {
		exits[exit.Name] = exit.Rules
	}
	if !exits["wan2"] || exits["wan1"] {
		t.Fatalf("rule exits %+v", state.Exits)
	}
	for _, group := range state.Groups {
		if slices.Contains(group.Options, "wan1") {
			t.Fatalf("group %s offers the DHCP exit", group.ID)
		}
	}
	if _, err := f.admin.SetDefaultExit("wan1", "admin"); err != nil {
		t.Fatal(err)
	}
	carrier := f.rule(t, "default")
	if carrier["interface"] != "wan1" || carrier[dhcpGatewayField] != true || carrier["via"] != nil {
		t.Fatalf("carrier %+v", carrier)
	}
	f.confirm(t)
	// Once in use it stays out of the rules' choices.
	state, _ = f.admin.State()
	for _, exit := range state.Exits {
		if exit.Name == "wan1" && exit.Rules {
			t.Fatal("the DHCP exit is offered to rules")
		}
	}
	if state.Default.Exit != "wan1" {
		t.Fatalf("%+v", state.Default)
	}
}
