# dns-intercept

Steers client TCP/UDP to one destination port (53 by default) into a separate
FIB table. It replaces the ABF policy that `deploy/dns-intercept` used on the
LAN interface: ABF ran a full ACL match on every IPv4/IPv6 packet of that
interface, while this feature reads only the L4 protocol and destination port
of a packet and passes everything else on.

```
dns intercept <interface> ip4|ip6 table <id> [port <n>] src <prefix>...
    [exempt-src <prefix>]... [exempt-dst <prefix>]...
dns intercept <interface> ip4|ip6 disable
show dns intercept
```

Each command replaces the whole selection for that interface and family. A
packet to the port is steered when its source is in a `src` prefix and neither
its source nor its destination is exempt. Steered packets get the table as
their lookup FIB and go straight to `ip4-lookup`/`ip6-lookup`, as an ABF match
leaves the arc. The table is created if missing and locked while configured;
routes in it (normally a default route to the resolver) are added separately.

Non-first IPv4 fragments and IPv6 packets whose first next header is not TCP
or UDP have no readable port and are never steered. The `steered to intercept
table` counter in `show errors` counts selections.

`dns_intercept_plugin.so` is built like `ipsec_ike_punt`: one file against the
VPP 26.06 tree, then `plugin dns_intercept_plugin.so { enable }`.

On the RK3588 board (one little-core worker, 64-byte UDP LAN to WAN at saturation)
ABF's `abf-input-ip4` cost 234 ns per packet.
