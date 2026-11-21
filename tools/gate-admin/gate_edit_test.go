package main

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestEditRuleSetsMatchesExitAndDNSTogether(t *testing.T) {
	f := newAdminFixture(t)
	static := filepath.Join(f.dir, "static.ipv4")
	dns := "1.1.1.1"
	state, err := f.admin.EditRule("textfixture", RuleEdit{Exit: "wg1", DNS: &dns, Files: []string{f.textfixture, f.mediafixture, f.textfixture}, Ranges: []string{static}, Keywords: []string{"Video"}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending == nil {
		t.Fatal("an edit is a change to confirm")
	}
	rule := f.rule(t, "textfixture")
	if !slices.Equal(anyStrings(rule["domain_files"]), []string{f.textfixture, f.mediafixture}) || !slices.Equal(anyStrings(rule["ip_range_files"]), []string{static}) || !slices.Equal(anyStrings(rule["domain_keywords"]), []string{"video"}) || dnsTextOf(dnsOf(rule)) != "1.1.1.1" {
		t.Fatalf("rule=%+v", rule)
	}
	f.confirm(t)
	if group := f.group(t, "textfixture"); !slices.Equal(group.RangeFiles, []string{static}) || !slices.Equal(group.Files, []string{f.textfixture, f.mediafixture}) {
		t.Fatalf("group=%+v", group)
	}
	if _, err := f.admin.EditRule("textfixture", RuleEdit{Exit: "wg1", DNS: &dns, Files: []string{f.textfixture, f.mediafixture}, Ranges: []string{static}, Keywords: []string{"video"}}, "admin"); err == nil {
		t.Fatal("an edit changing nothing was accepted")
	}
	if _, err := f.admin.EditRule("textfixture", RuleEdit{Exit: "wg1", DNS: &dns}, "admin"); err == nil {
		t.Fatal("a rule with nothing to match was accepted")
	}
	if _, err := f.admin.EditRule("textfixture", RuleEdit{Exit: "wg1", DNS: &dns, Files: []string{f.routes}}, "admin"); err == nil {
		t.Fatal("a file that is not a domain list was accepted")
	}

	// Moving takes the new exit's next hop, keeping the matches.
	if _, err := f.admin.EditRule("textfixture", RuleEdit{Exit: "loop10", DNS: &dns, Files: []string{f.textfixture}}, "admin"); err != nil {
		t.Fatal(err)
	}
	rule = f.rule(t, "textfixture")
	if rule["interface"] != "loop10" || rule["via"] != "10.61.50.1" || !slices.Equal(anyStrings(rule["domain_files"]), []string{f.textfixture}) || rule["ip_range_files"] != nil || rule["domain_keywords"] != nil {
		t.Fatalf("rule=%+v", rule)
	}
}

func TestEditRuleGivesAddressListsToTheRulesOfTheirFamily(t *testing.T) {
	f := newAdminFixture(t)
	static := filepath.Join(f.dir, "static.ipv4")
	group := f.group(t, "vpn")
	if _, err := f.admin.EditRule("vpn", RuleEdit{Exit: group.Exit, DNS: &group.DNS, Files: group.Files, Ranges: []string{static}}, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := anyStrings(f.rule(t, "vpn")["ip_range_files"]); !slices.Equal(got, []string{static}) {
		t.Fatalf("vpn ranges=%v", got)
	}
	if got := f.rule(t, "vpn6")["ip_range_files"]; got != nil {
		t.Fatalf("vpn6 ranges=%v", got)
	}
}

func TestSetDefaultChangesExitAndDNSTogether(t *testing.T) {
	f := newAdminFixture(t)
	exit, dns := "loop10", "223.5.5.5"
	state, err := f.admin.SetDefault(&exit, &dns, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.Default.Exit != "loop10" || state.Default.DNS != "223.5.5.5" {
		t.Fatalf("%+v", state.Default)
	}
	f.confirm(t)
	if _, err := f.admin.SetDefault(&exit, &dns, "admin"); err == nil {
		t.Fatal("no change was accepted")
	}
	none := ""
	if _, err := f.admin.SetDefault(&none, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := f.carriers(t); len(got) != 0 {
		t.Fatalf("carriers %v", got)
	}
}
