# VPP ordinary DNS interception

Addresses, MACs and PCI IDs below are examples. Use the values from your device configuration.

LAN client unicast TCP/UDP destination port 53 is selected by the
`dns-intercept` VPP plugin (`plugins/dns-intercept`), independently of
destination address, for IPv4 and IPv6. It is enabled only on loop200 and
matches LAN source prefixes 10.61.20.0/24, fd42:1111:2222:10::/64, and the
current LAN delegated /64. Selected packets are looked up in table 530/531,
whose default route goes via the Linux DNS address on loop200. Other packets
only have their protocol and port read; there is no per-packet ACL match.
VPN ingress wg0/wg8/tap4061 has no DNS interception. Existing VPN source ABF
policies 620/621 keep their DNS behavior. VPN queries deliberately addressed
to Gate's DNS bind still work normally.

The helper used ABF policies 530/531 with ACLs tagged
`vrouter-dns-intercept4/6` before; it removes them after enabling the plugin.
VPP must load `dns_intercept_plugin.so`.

Linux nftables `inet vrouter_dns_route_gate legacy_frontend` DNATs received
LAN queries to `10.61.20.2:1053` or `[fd42:1111:2222:10::2]:1053`.
Conntrack restores the requested resolver's address/port on replies.
The DNAT rules also require LAN sources; IPv6 uses `lan6_sources`, updated
by the helper when the delegated prefix changes. Direct same-LAN queries to the Linux DNS address already reach this chain.
Traffic entirely between two other hosts on the same L2 segment does not
necessarily traverse the router and is outside this routed interception.

`intercept.py` exempts Linux's own assigned unicast addresses to preserve
Gate/dnsmasq upstream resolution. It updates those ACL exceptions when local
addresses change (including delegated IPv6 prefixes), and signals systemd
readiness only after policies and attachments are installed. The watcher
uses the installed VPP binary and libraries; no extra packages are needed.

`vrouter-dns-intercept.service` runs after VPP/firewall, before Gate. Gate has a
Requires/After dependency. The installed service is enabled and follows VPP
restarts. Restarting the intercept service is unnecessary for normal edits
to Gate domain lists. Legacy destination-wide public-resolver routes are
removed only when their exact old next hop is still present. New topology
hooks no longer install them. Old route-sync exclusions can remain: they
also prevent DNS upstream endpoints from being redirected by domain leases.

`sudo python3 lab.py` runs a separate VPP instance with three private network
namespaces and TAPs; it never loads DPDK or uses physical ports. It exercises
the actual production helper, repeated application, LAN source matching, non-LAN/VPN source bypass, IPv4/IPv6 TCP/UDP redirection and reply source restoration, host
upstream exemptions, and non-DNS forwarding. It requires root, iproute2,
nftables, and the installed VROUTER VPP runtime. Names beginning `drg-lab-` must
be unused before running. The test removes only namespaces it created.

Production deployment 2026-11-02: backup and standalone rollback at
`/var/lib/vpp-vrouter/backups/` on VROUTER.
The scope was corrected to LAN only; the intercept service restart also
restarted Gate through its systemd dependency. VPP was not restarted. Client queries addressed
to `203.0.113.53`, `2001:db8:9::53`, and `223.6.6.6` returned Gate FakeIP
records; both UDP and TCP and both destination address families were tested.
These documentation-prefix addresses have no DNS server: successful answers
prove destination-independent interception. Physical VPN clients were not
used for acceptance; their ABF attachments were checked and VPN source bypass was verified in the isolated dataplane test.
The previous broad deployment snapshot is superseded by this LAN-only scope.
The correction was backed up under the same directory.

LAN-only correction acceptance: querying `223.5.5.5` from the IPsec
namespace with source `10.63.10.2` returned real A `198.51.100.58`
for `www.example.com`; an explicit query to Gate returned FakeIP. The
updated isolated lab also passed non-LAN/VPN source bypass for both
address families and both DNS transports.
