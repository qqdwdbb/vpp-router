package gate

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Whatever a tool says, only the listing decides whether something is missing.
const unknownWording = "Error: wording no release has used yet."

func TestDeletingWhatIsGoneIgnoresTheWording(t *testing.T) {
	const del = "ip -6 address del fd67:7465:6500::2/126 dev tap-wg1"
	const list = "ip -j -6 addr show dev tap-wg1"
	const held = `[{"addr_info":[{"local":"fd67:7465:6500:0::2"}]}]`
	for _, tc := range []struct {
		name, message, listing string
		listingFails, fails    bool
	}{
		{name: "old kernel", message: "RTNETLINK answers: Cannot assign requested address"},
		{name: "kernel 7.0", message: "Error: ipv6: address not found."},
		{name: "future kernel", message: unknownWording},
		{name: "address still there", message: "Error: ipv6: address not found.", listing: held, fails: true},
		{name: "listing failed", message: unknownWording, listingFails: true, fails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useDeviceDirs(t)
			respond, _ := fakeLinuxTools(t)
			respond("ip -d -j link show dev tap-wg1", "out", fakeTapLink)
			respond(del, "err", tc.message)
			if tc.listing != "" {
				respond(list, "out", tc.listing)
			}
			if tc.listingFails {
				respond(list, "err", "RTNETLINK answers: Operation not permitted")
			}
			err := SyncDevices(writeDualStackConfig(t, exitRule("wg1")), false)
			if tc.fails && (err == nil || !strings.Contains(err.Error(), tc.message)) {
				t.Fatalf("want the command's own error, got %v", err)
			}
			if !tc.fails && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLinkMissingNeedsTheListingToAgree(t *testing.T) {
	const probe = "ip -d -j link show dev gone"
	ctx := context.Background()
	respond, _ := fakeLinuxTools(t)
	respond(probe, "err", unknownWording)
	respond("ip -j link show", "out", `[{"ifname":"lo"}]`)
	if link, err := readDeviceLink(ctx, "gone"); err != nil || link != nil {
		t.Fatalf("absent link: %v %v", link, err)
	}
	respond("ip -j link show", "out", `[{"ifname":"lo"},{"ifname":"gone"}]`)
	if _, err := readDeviceLink(ctx, "gone"); err == nil || !strings.Contains(err.Error(), unknownWording) {
		t.Fatalf("link in the listing: %v", err)
	}
	respond("ip -j link show", "err", "Cannot open netlink socket")
	if _, err := readDeviceLink(ctx, "gone"); err == nil || !strings.Contains(err.Error(), unknownWording) {
		t.Fatalf("failed listing: %v", err)
	}
}

func TestEmptyTableNeedsTheListingToAgree(t *testing.T) {
	const probe = "ip -j -4 route show table 2101"
	const all = "ip -N -j -4 route show table all"
	ctx := context.Background()
	respond, _ := fakeLinuxTools(t)
	respond(probe, "err", unknownWording)
	respond(all, "out", `[{"dst":"default","table":"1101"},{"dst":"10.0.0.0/8"}]`)
	if routes, err := listDeviceRoutes(ctx, 4, "table", "2101"); err != nil || routes != nil {
		t.Fatalf("empty table: %v %v", routes, err)
	}
	respond(all, "out", `[{"dst":"default","table":"2101"}]`)
	if _, err := listDeviceRoutes(ctx, 4, "table", "2101"); err == nil {
		t.Fatal("table with routes was taken for empty")
	}
	respond(all, "err", "Cannot open netlink socket")
	if _, err := listDeviceRoutes(ctx, 4, "table", "2101"); err == nil {
		t.Fatal("failed listing was taken for an empty table")
	}
}

func TestNftChainIsClearedOnlyWhenItExists(t *testing.T) {
	const chains = "table ip filter {\n\tchain hijack {\n\t}\n}\ntable inet egress_gate {\n\tchain other {\n\t}\n}\n"
	ctx := context.Background()
	respond, calls := fakeLinuxTools(t)
	respond("nft list chains", "out", chains)
	if err := clearNftChain(ctx, "hijack", dnsHijackClearScript(), "DNS hijack"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(calls(), "nft -f") {
		t.Fatalf("a chain of the same name in another table counted:\n%s", calls())
	}
	respond("nft list chains", "out", chains+"table inet egress_gate {\n\tchain hijack {\n\t}\n}\n")
	respond("nft -f -", "err", unknownWording)
	if err := clearNftChain(ctx, "hijack", dnsHijackClearScript(), "DNS hijack"); err == nil {
		t.Fatal("failure to remove an existing chain was ignored")
	}
	respond("nft list chains", "err", "Operation not permitted")
	if err := clearNftChain(ctx, "hijack", dnsHijackClearScript(), "DNS hijack"); err == nil {
		t.Fatal("failed listing was taken for a missing chain")
	}
}

// Against whatever this kernel says: every missing thing is recognised, and every present one is not.
func TestMissingStateKernel(t *testing.T) {
	if os.Getenv("GATE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	ctx := context.Background()
	if link, err := readDeviceLink(ctx, "gk-gone"); err != nil || link != nil {
		t.Fatalf("absent link: %v %v", link, err)
	}
	if up, _, err := linuxLinkInfo(ctx, "gk-gone"); err != nil || up {
		t.Fatalf("absent exit: %v %v", up, err)
	}
	if _, present, err := linuxExitUnderlay(ctx, "gk-gone"); err != nil || present {
		t.Fatalf("absent underlay: %v %v", present, err)
	}
	if linkMissing(ctx, "lo") {
		t.Fatal("lo reported missing")
	}
	for _, family := range []int{4, 6} {
		if routes, err := listDeviceRoutes(ctx, family, "table", "4242"); err != nil || len(routes) != 0 {
			t.Fatalf("empty table, family %d: %v %v", family, routes, err)
		}
		// Nothing of these exists, and clearing them twice is what a retried sync does.
		for _, d := range []DeviceEntry{{Exit: "gk-gone", ReturnPriority: 14242, ReturnTable: 4242}, {}} {
			if err := clearFamily(ctx, d, family); err != nil {
				t.Fatalf("clear, family %d, %+v: %v", family, d, err)
			}
		}
	}
	if err := ipDelete(ctx, func() bool { return addressMissing(ctx, 6, "lo", "fd67:7465:6500::2/126") }, "-6", "address", "del", "fd67:7465:6500::2/126", "dev", "lo"); err != nil {
		t.Fatalf("absent address: %v", err)
	}
	if err := removeLinuxExit(ctx, Mapping{Via: "172.30.10.2", Via6: "fd67:7465:6500::2", LinuxExit: &LinuxExit{
		InputInterface: "gk-gone", Interface: "gk-gone2", Table: 4243, Mark: 4243, Priority: 14243}}); err != nil {
		t.Fatalf("absent exit state: %v", err)
	}

	// Now everything exists, and a failed delete must not pass for a missing object.
	mustRun := func(name string, args ...string) {
		t.Helper()
		if _, err := runCmdContext(ctx, name, args...); err != nil {
			t.Fatal(err)
		}
	}
	mustRun("ip", "link", "add", "gk-here", "type", "dummy")
	mustRun("ip", "link", "set", "gk-here", "up")
	mustRun("ip", "route", "add", "default", "dev", "gk-here", "metric", "100", "table", "4244")
	mustRun("ip", "route", "add", "unreachable", "default", "metric", "32767", "table", "4244")
	mustRun("ip", "rule", "add", "priority", "14244", "iif", "gk-here", "lookup", "4244")
	mustRun("ip", "-6", "address", "add", "fd67:7465:6500::2/126", "dev", "gk-here", "nodad")
	if tableEmpty(ctx, 4, "4244") || ruleMissing(ctx, 4, 14244, "gk-here") || addressMissing(ctx, 6, "gk-here", "fd67:7465:6500::2/126") {
		t.Fatal("something present was reported missing")
	}
	isDefault := func(r deviceRoute) bool { return r.Dst == "default" && r.Dev == "gk-here" && r.Metric == 100 }
	isUnreachable := func(r deviceRoute) bool { return r.Type == "unreachable" && r.Dst == "default" }
	if routeMissing(ctx, 4, 4244, isDefault) || routeMissing(ctx, 4, 4244, isUnreachable) {
		t.Fatal("route present was reported missing")
	}
	// A delete that cannot match: the object stays, so the error stands.
	if err := ipDelete(ctx, func() bool { return ruleMissing(ctx, 4, 14244, "gk-here") }, "rule", "del", "priority", "14244", "iif", "gk-here", "lookup", "4245"); err == nil {
		t.Fatal("a failed delete of an existing rule passed")
	}
	// Real removal through the real commands, then the same code finds them gone.
	if err := clearFamily(ctx, DeviceEntry{Exit: "gk-here", ReturnPriority: 14244, ReturnTable: 4244}, 4); err != nil {
		t.Fatal(err)
	}
	if !tableEmpty(ctx, 4, "4244") || !ruleMissing(ctx, 4, 14244, "gk-here") {
		t.Fatal("clear left state behind")
	}

	if exists, err := nftChainExists(ctx, "inet egress_gate", "hijack"); err != nil || exists {
		t.Fatalf("no chain yet: %v %v", exists, err)
	}
	if err := clearDNSHijack(); err != nil {
		t.Fatalf("clearing what never existed: %v", err)
	}
	mustRun("nft", "add", "table", "inet", "egress_gate")
	if err := clearDNSHijack(); err != nil {
		t.Fatalf("table without the chain: %v", err)
	}
	mustRun("nft", "add", "chain", "inet", "egress_gate", "hijack")
	if exists, err := nftChainExists(ctx, "inet egress_gate", "hijack"); err != nil || !exists {
		t.Fatalf("chain not found: %v %v", exists, err)
	}
	if err := clearDNSHijack(); err != nil {
		t.Fatal(err)
	}
	if exists, _ := nftChainExists(ctx, "inet egress_gate", "hijack"); exists {
		t.Fatal("chain not removed")
	}
}
