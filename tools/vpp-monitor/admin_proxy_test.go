package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// everyService sends each API to its own handler.
func everyService(handler func(name string) http.Handler) map[string]http.Handler {
	return map[string]http.Handler{gateAPIPrefix: handler("gate"), wireGuardAPIPrefix: handler("wireguard"), interfacesAPIPrefix: handler("interfaces"),
		proxyAPIPrefix: handler("proxy"), firewallAPIPrefix: handler("firewall"), systemAPIPrefix: handler("system")}
}

func TestGateProxyForwardsWithTheSessionUser(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var seenPath, seenQuery, seenUser, seenCookie, seenBody string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath, seenQuery, seenUser, seenCookie = r.URL.Path, r.URL.RawQuery, r.Header.Get("X-Panel-User"), r.Header.Get("Cookie")
		body, _ := io.ReadAll(r.Body)
		seenBody = string(body)
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"busy"}`))
	})}
	go server.Serve(listener)
	defer server.Close()

	handler := WithAdmin(http.NotFoundHandler(), everyService(func(string) http.Handler { return NewAdminProxy(socket, "admin") }))
	r := httptest.NewRequest("POST", "/api/gate/file?q=x", strings.NewReader(`{"a":1}`))
	r.Header.Set("X-Panel-User", "forged")
	r.Header.Set("Cookie", "vpp_monitor_session=secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "busy") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if seenPath != "/gate/file" || seenQuery != "q=x" || seenUser != "admin" || seenCookie != "" || seenBody != `{"a":1}` {
		t.Fatalf("path %q query %q user %q cookie %q body %q", seenPath, seenQuery, seenUser, seenCookie, seenBody)
	}
}

func TestGateProxyReportsAMissingService(t *testing.T) {
	handler := WithAdmin(http.NotFoundHandler(), everyService(func(string) http.Handler { return NewAdminProxy(filepath.Join(t.TempDir(), "none.sock"), "admin") }))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/gate/state", nil))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "不可用") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestOtherPathsSkipTheProxy(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("inner")) })
	handler := WithAdmin(inner, everyService(func(string) http.Handler { return http.NotFoundHandler() }))
	for _, path := range []string{"/", "/api/status", "/api/gateway", "/api/wireguards", "/api/interfacesx", "/api/proxyx", "/api/firewalls", "/api/systems"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Body.String() != "inner" {
			t.Errorf("%s = %s", path, w.Body)
		}
	}
}

func TestRefreshVPNAfterOnlyOnWireGuardChanges(t *testing.T) {
	vpn := NewVPNService(&fakeVPN{wg: wgSample}, nil)
	handler := RefreshVPNAfter(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), vpn)
	for _, test := range []struct {
		method, path string
		cleared      bool
	}{
		{http.MethodGet, "/api/wireguard", false},
		{http.MethodPost, "/api/gate/switch", false},
		{http.MethodPost, "/api/wireguard/peer", true},
		{http.MethodPost, "/api/wireguard/peer/delete", true},
	} {
		vpn.Report()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(test.method, test.path, nil))
		if (vpn.cached == nil) != test.cleared {
			t.Errorf("%s %s: cleared=%v", test.method, test.path, vpn.cached == nil)
		}
	}
}

func TestAdminProxyForwardsWireGuardPaths(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var seen string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.URL.Path })}
	go server.Serve(listener)
	defer server.Close()
	handler := WithAdmin(http.NotFoundHandler(), everyService(func(string) http.Handler { return NewAdminProxy(socket, "admin") }))
	for path, want := range map[string]string{"/api/wireguard": "/wireguard", "/api/wireguard/config/start": "/wireguard/config/start", "/api/gate/state": "/gate/state"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
		if seen != want {
			t.Errorf("%s reached %q", path, seen)
		}
	}
}

func TestEachAPIReachesItsOwnService(t *testing.T) {
	var reached string
	service := func(name string) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = name })
	}
	handler := WithAdmin(http.NotFoundHandler(), everyService(service))
	for path, want := range map[string]string{"/api/gate/state": "gate", "/api/wireguard": "wireguard", "/api/wireguard/peer": "wireguard", "/api/interfaces": "interfaces", "/api/interfaces/address": "interfaces", "/api/proxy": "proxy", "/api/proxy/apply": "proxy", "/api/firewall": "firewall", "/api/firewall/forward": "firewall", "/api/system": "system", "/api/system/threads": "system"} {
		reached = ""
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
		if reached != want {
			t.Errorf("%s reached %q", path, reached)
		}
	}
}

func TestInterfaceChangesRefreshLabels(t *testing.T) {
	labels := NewInterfaceLabels(nil)
	handler := RefreshLabelsAfter(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), labels)
	labels.key = "loop0 "
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/interfaces", nil))
	if labels.key == "" {
		t.Fatal("a reading forgot the labels")
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/interfaces/address", nil))
	if labels.key != "" {
		t.Fatal("a change kept the labels")
	}
}
