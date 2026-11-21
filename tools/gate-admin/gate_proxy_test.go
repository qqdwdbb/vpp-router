package main

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestManagedProxyExitsAreOfferedWithoutManualSetup(t *testing.T) {
	f := newAdminFixture(t)
	socket := filepath.Join(t.TempDir(), "proxy.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxy/exits" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"tproxy_exit":"tproxy","tproxy_port":2082,"ipv6":true,"fakeip_range":["198.18.0.0/15","2001:2::/48"],"dns_upstream":["127.0.0.1",5354]}]`))
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	f.admin.opts.ProxySocket = socket
	exit := f.exit(t, "tproxy")
	if !exit.Rules || exit.Custom || exit.Editable || exit.TProxyPort != 2082 || exit.DNS != "127.0.0.1:5354" {
		t.Fatalf("exit: %+v", exit)
	}
	// No DNS chosen: the exit's own, which is Fake-IP.
	if _, err := f.admin.AddRule("managed_fake", "tproxy", nil, f.textfixture, "", "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "managed_fake"); rule["fakeip_range"] == nil || rule["tproxy_port"] != float64(2082) || dnsText(rule) != "127.0.0.1:5354" {
		t.Fatalf("rule: %+v", rule)
	}
	f.confirm(t)
	// Another DNS: real addresses to the same listener.
	real := "10.61.20.2"
	names := f.upload(t, "managed.domains", "example.org\n")
	if _, err := f.admin.AddRuleWithDNS("managed", "tproxy", nil, names, "", &real, "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "managed"); rule["fakeip_range"] != nil || rule["tproxy_port"] != float64(2082) || rule["tproxy_exit"] != "tproxy" || dnsText(rule) != "10.61.20.2" {
		t.Fatalf("rule: %+v", rule)
	}
	f.confirm(t)
	// Choosing the Fake-IP DNS makes it Fake-IP, on the same exit.
	fake := "127.0.0.1:5354"
	if _, err := f.admin.SwitchRule("managed", "tproxy", &fake, "admin"); err != nil {
		t.Fatal(err)
	}
	if rule := f.rule(t, "managed"); rule["fakeip_range"] == nil || rule["tproxy_port"] != float64(2082) {
		t.Fatalf("rule: %+v", rule)
	}
	f.confirm(t)
	// The Fake-IP DNS of the proxy is no DNS for an exit that cannot turn its addresses back.
	if _, err := f.admin.SwitchRule("textfixture", "wg1", &fake, "admin"); err == nil {
		t.Fatal("Fake-IP DNS accepted on wg1")
	}
}

// A rule with address ranges can use the Fake-IP DNS: the ranges reach the listener as real
// addresses, the names through the pool.
func TestRangesAndFakeIPShareTheListener(t *testing.T) {
	f := newAdminFixture(t)
	socket := filepath.Join(t.TempDir(), "proxy.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"tproxy_exit":"tproxy","tproxy_port":2082,"ipv6":true,"fakeip_range":["198.18.0.0/15","2001:2::/48"],"dns_upstream":["127.0.0.1",5354]}]`))
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	f.admin.opts.ProxySocket = socket
	ranges := filepath.Join(f.dir, "static.ipv4")
	if _, err := f.admin.AddRuleWithFiles("mixed", "tproxy", nil, []string{f.textfixture}, []string{ranges}, nil, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	rule := f.rule(t, "mixed")
	if rule["fakeip_range"] == nil || len(anyStrings(rule["ip_range_files"])) != 1 || rule["tproxy_exit"] != "tproxy" {
		t.Fatalf("rule: %+v", rule)
	}
}
