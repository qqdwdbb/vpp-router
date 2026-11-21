package main

import (
	"slices"
	"testing"
)

func TestKeywordOnlyRulesCanBeAddedAndEdited(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.AddRuleWithKeywords("video", "wg1", nil, "", "", nil, []string{" Video ", "video", "media"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if got := anyStrings(f.rule(t, "video")["domain_keywords"]); !slices.Equal(got, []string{"video", "media"}) {
		t.Fatalf("keywords=%v", got)
	}
	f.confirm(t)
	if group := f.group(t, "video"); group.Keywords != 2 || !slices.Equal(group.KeywordValues, []string{"video", "media"}) {
		t.Fatalf("group=%+v", group)
	}
	if _, err := f.admin.SetKeywords("video", []string{"stream"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	if got := anyStrings(f.rule(t, "video")["domain_keywords"]); !slices.Equal(got, []string{"video", "media"}) {
		t.Fatalf("rollback keywords=%v", got)
	}
	if _, err := f.admin.SetKeywords("video", nil, "admin"); err == nil {
		t.Fatal("removed last match")
	}
	if _, err := f.admin.SetKeywords("video", []string{"bad keyword"}, "admin"); err == nil {
		t.Fatal("accepted whitespace")
	}
}

func TestKeywordsUpdateBothFamiliesAndKeepOtherMatches(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SetKeywords("vpn", []string{"corp"}, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vpn", "vpn6"} {
		rule := f.rule(t, name)
		if !slices.Equal(anyStrings(rule["domain_keywords"]), []string{"corp"}) || len(anyStrings(rule["domain_files"])) == 0 {
			t.Fatalf("rule=%+v", rule)
		}
	}
	f.confirm(t)
	if _, err := f.admin.SetKeywords("vpn", nil, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vpn", "vpn6"} {
		if f.rule(t, name)["domain_keywords"] != nil {
			t.Fatal("keywords not removed")
		}
	}
}
