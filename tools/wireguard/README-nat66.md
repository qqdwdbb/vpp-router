# wg0 NAT66

VPP's native NAT66 plugin translates each configured wg0 peer's `fd42:1111:2222:90::/64` host
address to one public address within the live delegated LAN prefix, reserving
`delegated-prefix:66::/80`. For example:

```
fd42:1111:2222:90::2 -> 2001:db8:4b73:66::2
```

This is one-to-one address translation, not port-sharing NAT. It keeps the clients'
private tunnel addresses stable as the modem's DHCPv6-PD prefix changes. The
external mapping is not an additional address assigned to the client. Native
NAT66 handles TCP, UDP and ICMPv6 on the VPP path; Linux does not forward data.

## Deployment

- Enable `nat66_plugin.so` in `/etc/vpp/startup.conf`.
- Copy `wg0-nat66.conf` to `/etc/vpp/wg0-nat66.conf`, and execute that file from
  `/etc/vpp/nat.conf` after wg0 is created. It marks wg0 inside and WAN outside.
- Install the updated `tools/vpp-egress-nat.py` as `/usr/local/sbin/vpp-egress-nat`
  and its existing systemd service. No additional timer/service is introduced.
- Install the updated `tools/vpp-wireguard-static.py` loader too. When the manual
  installer replaces wg0, it detaches NAT66 before interface deletion and restores
  the inside role after recreation. This does not add automatic WireGuard imports.
- The reconciler reuses `/usr/local/sbin/vpp-ipsec-prefix-sync`'s PD parser; this
  parser is already installed by the current IPsec deployment.
- Restart VPP to load the plugin, and restart vpp-egress-nat after updating its
  script. VPP restart briefly interrupts all forwarding/VPNs.

The existing reconciliation loop discovers current wg0 peers from VPP, selecting
only individual `/128` AllowedIPs under fd42:1111:2222:90::/64. Peers without IPv6 AllowedIPs
are unchanged; a `/64` delegated to a single peer is not expanded into host mappings.
New/removed IPv6 peers are picked up without reimporting WireGuard configuration.

Runtime state `/run/vpp/wg0-nat66.json` records owned mappings and public host IDs.
Only owned obsolete mappings are removed. Conflicting mappings abort the update.
Loss of valid PD removes owned public mappings; private gateway access remains.
Prefix renewal without a prefix change does not rewrite mappings. VPP restart
restores missing mappings by comparing the actual NAT66 table to desired state.

The `:66::/80` public range is separate from LAN DHCPv6 ::1000–::1fff and IPsec
::100–::200; SLAAC collision remains highly unlikely. Existing LAN RA off-link
configuration from the IPsec deployment is retained. Global LAN destinations
normally route to LAN and are not translated; translation follows native NAT66's
outside-interface route selection.

Client prerequisites:

```ini
[Interface]
Address = 10.62.10.2/32, fd42:1111:2222:90::2/128

[Peer]
# Existing server key, endpoint and other settings remain.
AllowedIPs = 0.0.0.0/0, ::/0
```

Use the peer's own assigned address, not another peer's example address. On the
server the corresponding peer must allow that exact IPv6 /128 and have its VPP
return route (the existing WireGuard installer already generates these).
With wg-quick, ::/0 installs the IPv6 default route through WireGuard; no explicit
next-hop gateway command is needed. The router's tunnel address is fd42:1111:2222:90::1.

## Verification

An isolated Linux WireGuard peer completed a real handshake with native VPP wg0.
Tests passed: fd42:1111:2222:90::1 ping 2/2; public IPv6 ping 2/2; IPv6 HTTPS to www.baidu.com
HTTP 200; IPv6 UDP DNS query; IPv4 public ping 2/2. The temporary peer, keys,
namespace, routes and NAT66 mapping were removed. Existing wg0/wg1 peer counts
returned to 28/1, with five configured IPv6 peer mappings.

Four focused NAT66 tests and one WireGuard-replacement regression cover mapping selection, unchanged reconciliation, PD
renumbering/withdrawal, peer removal, VPP restart restoration and ownership conflicts.

CNAT was evaluated but not deployed: its static IPv4 output feature constraints
conflict with the existing IPsec-before-NAT ordering. No CNAT plugin or custom
feature-order workaround is enabled. Native NAT66 requires no additional compilation.

Server backups: `/root/vpp-nat-backup/before-wg0-nat66/`.
