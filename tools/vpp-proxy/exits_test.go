package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExitsUseManagedProxyEntry(t *testing.T) {
	s, _, box := setup(t)
	entry := `{"inbounds":[
	 {"type":"tproxy","tag":"tproxy","listen":"::","listen_port":2082},
	 {"type":"tproxy","tag":"other","listen":"::","listen_port":2080},
	 {"type":"direct","tag":"fake-dns","listen":"127.0.0.1","listen_port":5354},
	 {"type":"socks","tag":"lan-socks","listen":"::","listen_port":1080}],
	 "dns":{"servers":[{"type":"fakeip","inet4_range":"198.18.0.0/15","inet6_range":"2001:2::/48"}]}}`
	if err := os.WriteFile(filepath.Join(box, entryFile), []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}
	exits := s.Exits()
	// One listener for real addresses and Fake-IP alike; it names the Fake-IP DNS it restores.
	if len(exits) != 1 || exits[0]["tproxy_exit"] != "tproxy" || exits[0]["tproxy_port"] != 2082 || exits[0]["dns_upstream"] == nil || exits[0]["fakeip_range"] == nil {
		t.Fatalf("exits: %+v", exits)
	}
	data, _ := json.Marshal(exits)
	if strings.Contains(string(data), "lan-socks") || strings.Contains(string(data), "password") {
		t.Fatal(string(data))
	}
	if err := os.Remove(filepath.Join(box, entryFile)); err != nil {
		t.Fatal(err)
	}
	if len(s.Exits()) != 0 {
		t.Fatal("offered proxy without an entry")
	}
}
