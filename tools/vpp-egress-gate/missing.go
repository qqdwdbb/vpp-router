package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// The wording of ip's and nft's errors changes between kernels and tool versions, and
// a table with no routes is an error on some kernels and empty output on others. So a
// failed command never says by its text that something is missing: a full listing does.
// These answer true only when that listing worked and agrees. Otherwise the caller
// reports the command's own error.

func linkMissing(ctx context.Context, name string) bool {
	text, err := runCmdContext(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return false
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if !decodeListing(text, &links) {
		return false
	}
	for _, link := range links {
		if link.Name == name {
			return false
		}
	}
	return true
}

// tableEmpty lists every table, and -N keeps a table's number even if rt_tables names it.
func tableEmpty(ctx context.Context, family int, table string) bool {
	text, err := runCmdContext(ctx, "ip", "-N", "-j", familyFlag(family), "route", "show", "table", "all")
	if err != nil {
		return false
	}
	var routes []struct {
		Table json.RawMessage `json:"table"`
	}
	if !decodeListing(text, &routes) {
		return false
	}
	for _, route := range routes {
		if strings.Trim(string(route.Table), `"`) == table {
			return false
		}
	}
	return true
}

func ruleMissing(ctx context.Context, family int, priority uint32, iif string) bool {
	text, err := runCmdContext(ctx, "ip", "-N", "-j", familyFlag(family), "rule", "show")
	if err != nil {
		return false
	}
	var rules []struct {
		Priority uint32 `json:"priority"`
		IIF      string `json:"iif"`
	}
	if !decodeListing(text, &rules) {
		return false
	}
	for _, rule := range rules {
		if rule.Priority == priority && rule.IIF == iif {
			return false
		}
	}
	return true
}

func addressMissing(ctx context.Context, family int, dev, address string) bool {
	want, err := netip.ParsePrefix(address)
	if err != nil {
		return false
	}
	text, err := runCmdContext(ctx, "ip", "-j", familyFlag(family), "addr", "show", "dev", dev)
	if err != nil {
		return false
	}
	var links []struct {
		Addresses []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if !decodeListing(text, &links) {
		return false
	}
	for _, link := range links {
		for _, address := range link.Addresses {
			if local, err := netip.ParseAddr(address.Local); err != nil || local == want.Addr() {
				return false
			}
		}
	}
	return true
}

func routeMissing(ctx context.Context, family int, table uint32, matches func(deviceRoute) bool) bool {
	routes, err := listDeviceRoutes(ctx, family, "table", fmt.Sprint(table))
	if err != nil {
		return false
	}
	for _, route := range routes {
		if matches(route) {
			return false
		}
	}
	return true
}

// ipDelete deletes something that may already be gone.
func ipDelete(ctx context.Context, missing func() bool, args ...string) error {
	if _, err := runCmdContext(ctx, "ip", args...); err != nil && !missing() {
		return err
	}
	return nil
}

func decodeListing(text string, into any) bool {
	return strings.TrimSpace(text) == "" || json.Unmarshal([]byte(text), into) == nil
}

// nftChainExists reads nft's plain listing, since not every build of nft has JSON.
func nftChainExists(ctx context.Context, table, chain string) (bool, error) {
	text, err := runCmdContext(ctx, "nft", "list", "chains")
	if err != nil {
		return false, err
	}
	inTable := false
	for _, line := range strings.Split(text, "\n") {
		words := strings.Fields(line)
		switch {
		case len(words) >= 3 && words[0] == "table":
			inTable = words[1]+" "+words[2] == table
		case inTable && len(words) >= 2 && words[0] == "chain" && words[1] == chain:
			return true, nil
		}
	}
	return false, nil
}

// clearNftChain removes one of Gate's optional chains, which most hosts never had.
func clearNftChain(ctx context.Context, chain string, script []string, what string) error {
	exists, err := nftChainExists(ctx, "inet egress_gate", chain)
	if err != nil {
		return fmt.Errorf("%s update failed: %w", what, err)
	}
	if !exists {
		return nil
	}
	return applyNftContext(ctx, script, what)
}
