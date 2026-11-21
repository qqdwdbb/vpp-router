package main

import (
	"os"
	"slices"
	"testing"
)

// No test reads the host's device journal.
func TestMain(m *testing.M) {
	generatedIPv6 = func(map[string]any) bool { return false }
	os.Exit(m.Run())
}

// A Linux exit rule without ipv6 has what Gate gave its device, so that the panel can add
// IPv6 rules on an exit Gate turned IPv6 on for.
func TestLinuxExitFamiliesFollowGatesDevice(t *testing.T) {
	previous := generatedIPv6
	t.Cleanup(func() { generatedIPv6 = previous })
	generatedIPv6 = func(rule map[string]any) bool {
		exit, _ := rule["linux_exit"].(map[string]any)
		return exit["interface"] == "wlan0"
	}
	rule := func(iface string) map[string]any {
		return map[string]any{"linux_exit": map[string]any{"interface": iface, "gateway": "10.61.20.1"}}
	}
	if got := ruleFamilies(rule("wlan0")); !slices.Equal(got, []int{4, 6}) {
		t.Fatalf("wlan0: %v", got)
	}
	if got := ruleFamilies(rule("eth1")); !slices.Equal(got, []int{4}) {
		t.Fatalf("eth1: %v", got)
	}
	off := rule("wlan0")
	off["ipv6"] = false
	if got := ruleFamilies(off); !slices.Equal(got, []int{4}) {
		t.Fatalf("ipv6 false: %v", got)
	}
}
