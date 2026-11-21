package gate

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"testing"
)

func TestNftDropsForward(t *testing.T) {
	const open = "table inet filter {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tip saddr 10.0.0.1 drop\n\t}\n}\n"
	for _, tc := range []struct {
		name, text string
		four, six  bool
	}{
		{name: "empty"},
		{name: "accepting chain with a conditional drop", text: open},
		{name: "default drop in inet", text: "table inet filter {\n\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n\t}\n}\n", four: true, six: true},
		{name: "default drop for IPv4 only", text: "table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n", four: true},
		{name: "default drop for IPv6 only", text: "table ip6 filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n", six: true},
		{name: "other hook", text: "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n"},
		{name: "bridge family", text: "table bridge filter {\n\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n\t}\n}\n"},
		{name: "final reject, as firewalld has", text: "table inet firewalld {\n\tchain filter_FORWARD {\n\t\ttype filter hook forward priority filter + 10; policy accept;\n\t\tct state established,related accept\n\t\treject with icmpx admin-prohibited\n\t}\n}\n", four: true, six: true},
		{name: "final counted drop", text: "table inet f {\n\tchain f {\n\t\ttype filter hook forward priority 0; policy accept;\n\t\tcounter packets 3 bytes 9 drop\n\t}\n}\n", four: true, six: true},
		{name: "final drop in a regular chain", text: "table inet f {\n\tchain helper {\n\t\tdrop\n\t}\n\tchain f {\n\t\ttype filter hook forward priority 0; policy accept;\n\t}\n}\n"},
		{name: "a set does not end the chain", text: "table inet f {\n\tchain f {\n\t\ttype filter hook forward priority 0; policy accept;\n\t\tdrop\n\t\tip saddr { 10.0.0.1, 10.0.0.2 } accept\n\t}\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nftDropsForward(tc.text, 4); got != tc.four {
				t.Fatalf("IPv4: %v", got)
			}
			if got := nftDropsForward(tc.text, 6); got != tc.six {
				t.Fatalf("IPv6: %v", got)
			}
		})
	}
}

func TestIptablesDropsForward(t *testing.T) {
	for text, want := range map[string]bool{
		"-P FORWARD ACCEPT\n":                             false,
		"-P FORWARD DROP\n":                               true,
		"-P FORWARD ACCEPT\n-A FORWARD -i eth0 -j DROP\n": false,
		"-P FORWARD ACCEPT\n-A FORWARD -i eth0 -j ACCEPT\n-A FORWARD -j DROP\n":        true,
		"-P FORWARD ACCEPT\n-A FORWARD -j REJECT --reject-with icmp-host-prohibited\n": true,
		"-P FORWARD ACCEPT\n-A FORWARD -j DROP\n-A FORWARD -i eth0 -j ACCEPT\n":        false,
	} {
		if got := iptablesDropsForward(text); got != want {
			t.Errorf("%q: %v", text, got)
		}
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &out
}

func TestForwardingWarningOnlyWhenGateTurnsItOnUnfiltered(t *testing.T) {
	const dropping = "table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n"
	for _, tc := range []struct {
		name, was, ruleset, iptables string
		warns                        bool
	}{
		{name: "no firewall at all", was: "0", warns: true},
		{name: "nft drops", was: "0", ruleset: dropping},
		{name: "iptables drops", was: "0", iptables: "-P FORWARD DROP\n"},
		{name: "iptables accepts", was: "0", iptables: "-P FORWARD ACCEPT\n", warns: true},
		{name: "already on is the host's choice", was: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useDeviceDirs(t)
			respond, _ := fakeLinuxTools(t)
			writeSysctl(t, "net/ipv4/ip_forward", tc.was)
			if tc.ruleset != "" {
				respond("nft list ruleset", "out", tc.ruleset)
			}
			if tc.iptables != "" {
				respond("iptables -w 2 -S FORWARD", "out", tc.iptables)
			}
			out := captureLog(t)
			if err := enableExitForwarding(nil); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(out.String(), "warning: IPv4 forwarding"); got != tc.warns {
				t.Fatalf("warned=%v:\n%s", got, out.String())
			}
			if data, _ := os.ReadFile(linuxSysctlRoot + "/net/ipv4/ip_forward"); strings.TrimSpace(string(data)) != "1" {
				t.Fatalf("forwarding is %q", data)
			}
		})
	}
}

func TestIPv6ForwardingWarnsToo(t *testing.T) {
	useDeviceDirs(t)
	fakeLinuxTools(t)
	writeSysctl(t, "net/ipv6/conf/all/forwarding", "0")
	out := captureLog(t)
	if err := enableIPv6Forwarding(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "warning: IPv6 forwarding") || !strings.Contains(out.String(), "ip6tables -P FORWARD DROP") {
		t.Fatal(out.String())
	}
}
