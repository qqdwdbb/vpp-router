package gate

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSUpstreamsCannotPointToGate(t *testing.T) {
	for _, tc := range []struct {
		name, listen, upstream string
		port                   int
		blocked                bool
	}{
		{"loopback", "127.0.0.1", "127.0.0.1", 1053, true},
		{"lan", "10.61.30.2", "10.61.30.2", 1053, true},
		{"ipv6", "::1", "::1", 1053, true},
		{"mapped", "127.0.0.1", "::ffff:127.0.0.1", 1053, true},
		{"wildcard4", "0.0.0.0", "127.0.0.2", 1053, true},
		{"wildcard6", "::", "::1", 1053, true},
		{"dual_stack", "::", "127.0.0.1", 1053, true},
		{"fake_dns", "127.0.0.1", "127.0.0.1", 5354, false},
		{"remote_same_port", "0.0.0.0", "203.0.113.254", 1053, false},
		{"default_resolver", "10.61.30.2", "10.61.20.2", 53, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, field := range []string{"upstream", "dns", "dns_upstream", "fake_dns"} {
				entry := map[string]any{"listen": []any{[]any{tc.listen, 1053}}}
				routes := map[string]any{}
				if field == "upstream" {
					entry[field] = []any{tc.upstream, tc.port}
				} else {
					routes["routes"] = []any{map[string]any{"name": "test", field: []any{tc.upstream, tc.port}}}
				}
				err := ValidateDNSConfig(entry, routes)
				if (err != nil) != tc.blocked {
					t.Fatalf("%s: blocked=%v err=%v", field, tc.blocked, err)
				}
				if err != nil && !strings.Contains(err.Error(), "环路") {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestLoadGateFileRejectsSplitDNSLoop(t *testing.T) {
	dir := t.TempDir()
	routes := filepath.Join(dir, "routes.json")
	entry := filepath.Join(dir, "gate.json")
	writeJSON(t, routes, map[string]any{"routes": []any{map[string]any{"name": "loop", "dns": []any{"127.0.0.1", 1053}}}})
	writeJSON(t, entry, map[string]any{"listen": []any{[]any{"127.0.0.1", 1053}}, "upstream": []any{"10.61.20.2", 53}, "domain_routes_file": routes})
	if _, err := LoadGateFile(entry); err == nil || !strings.Contains(err.Error(), "环路") {
		t.Fatalf("err=%v", err)
	}
}
