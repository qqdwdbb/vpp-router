package main

import (
	"os"
	"strings"
	"testing"
)

func TestDNSLoopRejectedBeforeSavingOrRestarting(t *testing.T) {
	f := newAdminFixture(t)
	entryBefore, _ := os.ReadFile(f.admin.opts.Config)
	rulesBefore, _ := os.ReadFile(f.routes)
	dns := "127.0.0.1:1053"
	for _, change := range []func() error{
		func() error { _, err := f.admin.SetDefaultDNS(dns, "admin"); return err },
		func() error { _, err := f.admin.SwitchRule("textfixture", "wg1", &dns, "admin"); return err },
		func() error {
			_, err := f.admin.AddRuleWithDNS("loop", "wg1", nil, f.textfixture, "", &dns, "admin")
			return err
		},
	} {
		if err := change(); err == nil || !strings.Contains(err.Error(), "环路") {
			t.Fatalf("err=%v", err)
		}
	}
	entryAfter, _ := os.ReadFile(f.admin.opts.Config)
	rulesAfter, _ := os.ReadFile(f.routes)
	if string(entryBefore) != string(entryAfter) || string(rulesBefore) != string(rulesAfter) || f.admin.pending != nil || len(f.sys.calls) > 0 {
		t.Fatalf("rejected DNS changed state: calls=%v", f.sys.calls)
	}
}
