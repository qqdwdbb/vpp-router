# VROUTER VPP failure recovery

Addresses, MACs and PCI IDs below are examples. Use the values from your device configuration.

This deployment uses mgmt0 for management, nic1/nic0 untagged for LAN,
and nic0 VLAN 100 for WAN. The fallback restores basic IPv4 routing, DHCP,
DNS and NAT. VPN sessions, transparent proxy routing and delegated IPv6
are not migrated. Existing connections may need to reconnect.

VPP uses `Restart=on-failure`, with three starts allowed per 180 seconds.
After the start limit is exhausted, `vrouter-vpp-failure.service` latches Linux
ownership and starts `vrouter-linux-fallback.service`. An ordinary administrative
stop does not invoke the failure handler.

Linux ownership is recorded in `/var/lib/vpp-vrouter/linux-fallback/active`.
VPP refuses to start while the marker exists. The fallback service is enabled
at boot, but only runs when this marker exists, preserving Linux mode after
a reboot. Takeover also disables VPP's boot link so its Wants dependencies are
not enqueued at boot in Linux mode. `resume` reenables VPP boot startup.
The marker must not be removed manually while Linux owns the NICs.

The script verifies that VPP has exited and UIO is unused before rebinding
the two RTL8125 devices. Linux reuses `br-mgmt` with `10.61.20.1/24` and
`10.61.20.2/24`, creates `vrouter-fb-wan` (VLAN 100) at `10.61.10.2/24`, and
uses gateway `10.61.10.1`. VLAN 10 is connected to the existing `br0`.
Only VPP-owned nftables tables/chains are removed; unrelated policy remains.

On the router:

```sh
sudo python3 /usr/local/lib/vpp-vrouter/scripts/vrouter/startup/vrouter-linux-fallback.py status
sudo python3 /usr/local/lib/vpp-vrouter/scripts/vrouter/startup/vrouter-linux-fallback.py resume
```

`resume` releases Linux networking before starting VPP. If VPP start fails,
the script reapplies Linux fallback. Wait for VPP's dependent services before
declaring the return complete.

Install the `.service` files in `/etc/systemd/system`, the drop-in
`60-linux-fallback.conf` in `/etc/systemd/system/vrouter-vpp.service.d`, the DNS
configuration in `/etc/vpp`, and the Python script in the VROUTER startup directory.
Enable `vrouter-linux-fallback.service`, then reload systemd.

The installed router's legacy `/etc/network/interfaces` must not automatically
create nic0 WAN/VLAN interfaces: remove `auto nic0`, `auto wan`, `auto vps`,
and the legacy `vps` member from br0. VPP topology and the fallback script own
these ports. The current-version recovery snapshot includes that file; recovery does not
require the historical `interfaces.before-fallback` copy. The fallback unit starts after
`networking.service` to avoid racing legacy interface setup.

Failure injection for validation must be temporary and removed before returning
to VPP. A client-side forwarding test is required in addition to router ping.

Validated on the router on 2026-10-20:

- SIGKILL of VPP's main process automatically restarted VPP and its services.
- A temporary failing ExecStartPre exhausted the restart limit and triggered
  Linux takeover automatically. The test drop-in was removed afterward.
- A separate network namespace obtained a DHCP lease, resolved DNS through
  10.61.20.2 and reached 223.5.5.5 through Linux NAT without packet loss.
- An entire router reboot preserved Linux fallback and working DNS/internet.
- Manual `resume` restored VPP and its services; ordinary VPP stop did not
  trigger fallback. The router was left in VPP mode with boot startup enabled.

This handles process exit and exhausted service restarts. It does not detect
a live VPP process whose dataplane has hung. The 180-second start limit counts
all starts in the window, including successful starts; it is not a session
continuity guarantee.

## Restore accepted deployment files

The installed `install/recovery.py` snapshots the healthy current router and
restores its binaries, PMD, configuration and service units. It does not restore
the pre-migration Linux baseline. Use `recovery.py verify` to check the recovery
point, `recovery.py restore` to repair files and restart VPP, and `recovery.py
linux` for basic Linux IPv4 takeover. `resume` only switches ownership back to
the installed VPP; it does not repair damaged files. The recovery point must
be refreshed explicitly with `snapshot` after accepting a healthy new version.
See [installed recovery instructions](../../install/README.md).
