# Dedicated TPROXY path

Addresses, MACs and PCI IDs below are examples. Use the values from your device configuration.

Deployed on VROUTER on 2026-10-23 without restarting VPP.

| Purpose | VPP interface / next hop | Linux ingress |
| --- | --- | --- |
| Fake-IP and real-IP proxy | tap2490 / 10.63.30.2, fd42:1111:2222:30::2 | vpp-tproxy |
| LAN, DNS, gateway services, internal routes including Nebula | loop200 / 10.61.20.2 | br-mgmt |

The dedicated TAP has VPP addresses 10.63.30.1/30 and
fd42:1111:2222:30::1/64. It is routed, not part of either Linux bridge.
The existing wg-proxy, hostsvc and IPsec TAPs retain their purposes.

`tproxy-path.py` defines topology and idempotent Linux reply-policy setup.
`cutover/prepare.py` includes the TAP in generated topologies;
`cutover/runtime.py host` installs its Linux setup before consumers start.
Installed `/etc/vpp/topology.vpp` contains the same TAP creation commands.
The deployed runtime was patched in place to preserve its bridge/DMA fixes.

DNS Gate domain mappings, proxylist/proxylist6 mappings, and Svc-a ASN static routes
use the new next hops. Public resolver interception, host addresses and Nebula
routes stay on loop200. Dynamic route exclusions cover the new transit subnet.
The Fake-IP cache and DNS lease history were retained.

`dns-route-gate.nft` intercepts only vpp-tproxy. Fake-IP goes to 2082 and real
IP goes to 2080. Internal destinations are excluded; the Fake-IP IPv6 pool
is 2001:2::/48. UDP/443 rejection is limited to this proxy ingress.
Unintercepted traffic arriving on vpp-tproxy is dropped in forward to prevent
fallback routing loops. br-mgmt has no transparent proxy rules.

Intercepted socket replies (ct mark 1, reply direction) receive routing bit
0x04000000. IPv4/IPv6 priority 105 selects table 2490, whose default routes
point back through the dedicated TAP to VPP. Other host-generated connections
keep their original routing. Setup refuses conflicting priority/table use.

Nebula SNAT on br-mgmt -> nebula applies to the configured LAN and VPN source prefixes and the configured overlay destination prefixes.

## Verification and rollback

Migrated 4,853 dynamic paths and 23 static ASN prefixes; all were checked
against the live FIB after switching. The owned ledger has no old loop200
proxy paths. IPv4/IPv6 Fake-IP and real-IP HTTPS returned 200 from a temporary
VPP-side test client. The client also reached the configured Nebula test host
over ICMP and received its SSH banner on TCP/22.
The namespace/TAP test fixture was removed. Host policy setup was repeated
successfully to check idempotence; nft syntax and unit tests passed.
No full VPP restart was performed as part of this migration.

Backup on VROUTER: `/root/<tproxy-backup>` contains prior configs,
runtime, state/lease files and route movement commands. To roll back, stop
Gate, reverse the recorded route moves, restore its configs/state and the
old runtime, reload the old Gate nft rules and start Gate. Do not restore an
old route ledger while Gate is running. Do not load old host.nft files with
global `flush ruleset`. An unused TAP can stay allocated during rollback.
