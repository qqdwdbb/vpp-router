package gate

import (
	"context"
	"log"
	"os/exec"
	"regexp"
	"strings"
)

// Turning on forwarding is host-wide, and Gate's rules cover only its devices and exits.
// Traffic from any other interface is the host's firewall's business, so a host that
// did not forward until now may need one. Forwarding stays on: Gate needs it, and what
// else the host should forward is not Gate's to decide.

var nftFinalDrop = regexp.MustCompile(`^(counter( packets \d+ bytes \d+)? )?(drop|reject( with .*)?)$`)

// nftDropsForward reads nft's plain output, since not every build of nft has JSON.
// A chain that ends in an unconditional drop or reject counts too, as firewalld's does.
func nftDropsForward(text string, family int) bool {
	inFamily, inForward := false, false
	last := ""
	for _, line := range strings.Split(text, "\n") {
		statement := strings.TrimSpace(line)
		words := strings.Fields(statement)
		switch {
		case len(words) >= 3 && words[0] == "table":
			inFamily = words[1] == "inet" || (family == 4 && words[1] == "ip") || (family == 6 && words[1] == "ip6")
		case len(words) >= 2 && words[0] == "chain":
			inForward, last = false, ""
		case statement == "}":
			if inForward && nftFinalDrop.MatchString(last) {
				return true
			}
			inForward = false
		case inFamily && strings.Contains(statement, "hook forward"):
			inForward = true
			if strings.Contains(statement, "policy drop") {
				return true
			}
		case statement != "":
			last = statement
		}
	}
	return false
}

// iptablesDropsForward reads iptables -S FORWARD.
func iptablesDropsForward(text string) bool {
	last := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "-P FORWARD DROP" {
			return true
		}
		if strings.HasPrefix(line, "-A FORWARD") {
			last = strings.TrimSpace(line)
		}
	}
	return last == "-A FORWARD -j DROP" || strings.HasPrefix(last, "-A FORWARD -j REJECT")
}

// forwardingIsFiltered answers false when it cannot tell, as a needless warning costs less.
func forwardingIsFiltered(ctx context.Context, family int) bool {
	if text, err := runCmdContext(ctx, "nft", "list", "ruleset"); err == nil && nftDropsForward(text, family) {
		return true
	}
	tool := "iptables"
	if family == 6 {
		tool = "ip6tables"
	}
	if _, err := exec.LookPath(tool); err != nil {
		return false
	}
	text, err := runCmdContext(ctx, tool, "-w", "2", "-S", "FORWARD")
	return err == nil && iptablesDropsForward(text)
}

func warnIfForwardingIsOpen(ctx context.Context, family int) {
	if forwardingIsFiltered(ctx, family) {
		return
	}
	name, tool := "IPv4", "iptables"
	if family == 6 {
		name, tool = "IPv6", "ip6tables"
	}
	log.Printf("devices: warning: %s forwarding was off and is now on for the whole host, and no firewall drops forwarded traffic by default. "+
		"A neighbor that routes through this host can reach its other networks and its exits. "+
		"To stop that, make dropping the default, for example %s -P FORWARD DROP; Gate opens its own devices itself", name, tool)
}
