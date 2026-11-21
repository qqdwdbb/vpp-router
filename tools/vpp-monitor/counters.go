package main

import (
	"regexp"
	"strings"
)

// /err/ holds every node's counters, not only failures, and neither the stats segment nor
// VPP's own severity tells them apart: `show errors` rates "no error" as an error. These
// are the reasons known to count ordinary work. Anything not listed is shown as needing
// attention, so an unfamiliar counter is seen rather than hidden.
var normalReasons = map[string]bool{
	"no error": true, "ok": true, "ack_ok": true, "received": true, "enqueued": true,
	"pkts_sent": true, "pkts_decap": true, "pkts_encap": true, "pkts-processed": true,
	"packets decapsulated": true, "packets forwarded": true, "reass_success": true,
	"conn_accepted": true, "echo_replies_sent": true,

	"request_sent": true, "replies_sent": true, "replies_received": true,
	"proxy_arp_replies_sent": true, "l3_src_address_learned": true,
	"arp replies sent": true, "arp replies received": true, "proxy arp replies sent": true,
	"arp request ip4 source address learned": true,

	"extract": true, "dhcp bind success": true, "dhcp packets for local client.": true,

	"checked packets": true, "existing session packets": true, "acl permit packets": true,
	"valid input acl packets": true, "valid output acl packets": true,

	"good ip6 local h-b-h packets": true, "ip4 source and port range check good packets": true,
	"ipsec pkts received": true, "span incoming packets processed": true,
	"p2p ethernet incoming packets processed": true,

	"l2 forward hits": true, "l2 learn hit updates": true,
}

var normalPatterns = regexp.MustCompile(`^(` +
	`l2 (input|output|flood|learn|forward|patch|inverter) packets` +
	`|dhcp\S* \S+ packets sent` +
	`|dhcp\S* packets relayed to (clients|the server)` +
	`|(flow )?classify hits( after chain walk)?` +
	`|permitted (in|out)bound whitelisted non-ip packets` +
	`|sr: .*packets` +
	`|sr steered ipv6 packets` +
	`)$`)

func isNormalCounter(reason string) bool {
	reason = strings.ToLower(reason)
	return normalReasons[reason] || normalPatterns.MatchString(reason)
}
