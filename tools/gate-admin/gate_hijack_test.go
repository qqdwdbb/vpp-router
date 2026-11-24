package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestVPPDNSHijackSwitchAndRollback(t *testing.T) {
	f := newAdminFixture(t)
	entry, _ := readJSONObject(f.opts.Config)
	entries := []any{map[string]any{"interface": "wg0", "via_interface": "loop0", "via": []any{"192.0.2.2"}, "sources": []any{"10.1.1.0/24"}}}
	entry["hijack_dns"] = true
	entry["hijack_vpp"] = entries
	data, _ := json.Marshal(entry)
	if err := os.WriteFile(f.opts.Config, data, 0644); err != nil {
		t.Fatal(err)
	}
	state, err := f.admin.State()
	if err != nil || !state.VPPDNSHijack.Enabled {
		t.Fatalf("%+v %v", state, err)
	}
	state, err = f.admin.SetVPPDNSHijack(false, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if state.VPPDNSHijack.Enabled || !state.VPPDNSHijack.Available || state.Pending == nil {
		t.Fatalf("%+v", state)
	}
	changed, _ := readJSONObject(f.opts.Config)
	if !reflect.DeepEqual(changed["hijack_vpp"], entries) || changed["hijack_dns"] != true {
		t.Fatalf("lost settings: %+v", changed)
	}
	f.confirm(t)
	state, err = f.admin.SetVPPDNSHijack(true, "admin")
	if err != nil || !state.VPPDNSHijack.Enabled {
		t.Fatalf("%+v %v", state, err)
	}
	if err := f.admin.Rollback("admin"); err != nil {
		t.Fatal(err)
	}
	state, err = f.admin.State()
	if err != nil || state.VPPDNSHijack.Enabled {
		t.Fatalf("rollback: %+v %v", state, err)
	}
}

func TestVPPDNSHijackNeedsConfigurationAndBoolean(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.admin.SetVPPDNSHijack(true, "admin"); err == nil {
		t.Fatal("accepted missing interfaces")
	}
	for _, body := range []string{`{}`, `{"enabled":null}`, `{"enabled":"false"}`} {
		response := httptest.NewRecorder()
		f.admin.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/gate/dns-hijack", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", body, response.Code)
		}
	}
}
