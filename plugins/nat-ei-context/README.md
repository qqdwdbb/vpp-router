# NAT44 EI per-egress isolation (VPP 26.06)

EI keys contain source address, source port, protocol and inside FIB. Two pools
in the same inside FIB cannot select a different address based on egress.

WAN uses inside VRF 0 and shared pool 10.61.10.2. wg1 uses inside VRF 101 and pool
10.62.30.2. loop101 supplies only the NAT classification context; client routing,
WireGuard interface addresses and dynamic nftset routes stay in table 0.
Table 101 has a lookup-in-table-0 default for reverse-NAT return traffic.

On the wg1 output arc, context-enter saves the original RX interface in
vnet_buffer2.unused[0] and selects loop101 before EI. context-exit restores RX
after EI and before WireGuard encryption. NAT's own opaque2 fields are separate.
The stock EI output nodes jump directly to interface-output. This plugin
redirects their successful output edges to context-exit, consumes the pending
EI feature cursor entry when there is no worker handoff, then resumes
MSS/WireGuard processing. With any configured worker the patched EI handoff node has already
consumed that entry, so context-exit advances only once. Enable
`nat44 ei output-chain host-vpp-wan` on WAN as well; context-exit does not change
RX there. Every EI output interface in this deployment must enable that chain.
Both features are enabled only by `nat44 ei context wg1 loop101`. Remove that
context before deleting wg1. The plugin does not inspect tunnel reachability.

### Return handoff

With output-feature EI, every packet of one inside address goes to that user's
worker, and that worker also ran the output ACL, the remaining output features
and the TX. `nat44 ei return-handoff enable` sends translated packets back from
context-exit to the thread that received them, which runs the rest of the
output arc and the TX. The user's EI state, port allocation and limits stay on
the owner; the ACL still sees the translated source. A flow always takes the
same RX -> owner -> RX path, so its order is kept.

It needs `patches/vpp/0020`: the EI output handoff records the receiving thread
in `vnet_buffer2 (b)->unused[4]` (thread + 1, 0 = unknown). Packets without a
mark, from the owner's own queues, or with no workers finish on the owner as
before. When the receiving thread's queue is nearly full, the packet finishes
on the owner instead of being dropped (a flow can then be reordered under
overload); drops at enqueue are counted as `return-congestion-drop`.
`returned-to-rx-thread` counts packets sent back. The default is disabled;
`show nat44 ei return-handoff` prints the state of each direction.

The out2in direction works the same way: `patches/vpp/0021` records the
receiving thread in every EI handoff, and enabling return handoff redirects
the `nat44-ei-out2in` -> `ip4-lookup` edge to `nat-ei-out2in-return`, which
sends translated packets back to their RX thread for ip4-lookup, L2 and TX.
`nat44 ei return-handoff enable|disable [in2out|out2in]` switches one
direction; without one it switches both.

Build against installed vpp-dev/libvppinfra-dev:

```sh
cc -shared -fPIC -O2 -o nat_ei_context_plugin.so nat_ei_context.c
```

Enable nat44_ei_plugin.so and nat_ei_context_plugin.so, disable nat_plugin.so,
and rebuild the project's WireGuard and IPsec output ordering plugins for EI.
Load tools/nat44-ei-context.conf before loading the wg1 static file.
This custom feature is tied to VPP's buffer layout and EI graph nodes and must
be revalidated on VPP upgrades. Validation covers zero, one and two workers.
The single-worker handoff fix and this context plugin must be deployed together.
ARM two-worker testing exposed and fixed the extra cursor advance.
VPP 26.06 also needs `docs/history/patches/nat44-ei-handoff-reassembly-order.patch` before
multi-worker use: the input handoff features must run after
`ip4-sv-reassembly-feature`. Otherwise return packets reach EI with unpopulated
L4 port metadata and report `no translation` despite a valid session.

The patch changes both input handoff registrations in a copied VPP source tree.
`build/history/build-nat44-ei-handoff.py` compiles only that translation unit and
relinks an isolated `nat44_ei_plugin.so` using recorded Ninja commands. It does
not overwrite the original VPP build/install. The resulting plugin is staged
in `/opt/vpp-vrouter-migration/plugins` on VROUTER. Two-worker UDP/TCP/ICMP functional
checks pass with sessions owned by both workers; the same warmed fixture fails
with the old plugin. Single-main-thread regression also passes. This is not a
throughput or system stability result.

`tests/integration/integration_nat44_ei.py` starts an isolated VPP and three namespaces,
checks UDP endpoint independence, separate pool selection and return traffic,
TCP and ICMP from two client addresses, and removes its fixtures afterwards.
It warms LAN neighbor resolution separately: with worker RX, the first ARP
request can be learned asynchronously and an immediate UDP reply may hit an
unresolved glean. The actual UDP checks still require successful replies and
unchanged mappings. With two workers the test also checks that both own sessions.


### VROUTER WAN ACL ordering

With output-feature NAT, WAN output ACLs must see the translated source. Apply
`docs/history/patches/nat44-ei-output-acl-order.patch` after the reassembly/handoff patch in a
copied source tree, then rebuild with `build/history/build-nat44-ei-handoff.py
--source <copied nat44_ei.c> --output-dir <isolated output>`.
Build this directory's context plugin from the same revision: context-exit must
precede `acl-plugin-out-ip4-fa` and resume that feature after EI's direct jump.
The effective chain is IPsec protection, NAT (or worker handoff), context-exit,
then ACL. Use the matching IPsec punt plugin, which also orders IPv6 protection
before the IPv6 ACL and reinjects IPv6 cleartext through a distinct graph node.
Stage all three together; do not replace the running installation during tests.

For a WAN address also used by VPP itself, configure `nat44 ei add identity
mapping external <WAN>` so local IKE and ICMP replies retain their source ports
and identifiers. The staged fragment is
`deploy/firewall/wan-output-nat.vpp.conf.example`.

Functional acceptance uses `tests/integration/integration_vrouter_firewall.py --output-nat
--plugin-path <candidate plugins> --workers 0` and `--workers 2`: private-WAN
IPv4 and global-IPv6 TCP/UDP replies, unsolicited IPv6 rejection, plus an
intentional untranslated private-source flow that must increment WAN ACL denies.
This validates routing/filtering behavior, not physical WAN throughput.

### Shared WAN host reservations

The host-service path reserves only explicitly configured fixed ports before
outside allocation starts. Nebula uses ordinary dynamic NAT. Coturn retains its
complete UDP relay range through the dedicated Linux TAP. Apply
`docs/history/patches/nat44-ei-static-port-byte-order.patch` on top of the existing candidate:
static mapping APIs pass network-order ports, whereas the allocator bitmap and
worker accounting require host-order ports. Both reserve and free must convert.
Without this correction a dynamic client can receive a reserved TURN port.
The shared-pool integration test exercises colliding client source ports and
multiple ordinary host dynamic ports before and after NAT reinitialization.

### Invalid feature next indices

Both context nodes validate the full 32-bit result of `vnet_feature_next`
against the current worker's `node->n_next_nodes` before enqueueing or narrowing
to the batch's 16-bit next array. An invalid next sends only that packet to a
reserved `error-drop` edge and assigns the node's `invalid-next-index` error.
`show errors` reports dropped packets for `nat-ei-context-enter` and
`nat-ei-context-exit`; normal forwarding and the existing feature cursor
advancement are unchanged.

Each node on each worker logs at most one warning per five seconds. The warning
includes the node name, thread, original next index, next count, RX/TX interfaces
and the feature config index before reading the next entry. Logging uses
thread-local node runtime state; suppressed warnings do not suppress drop
accounting. This guards an invalid next value, not corruption of the graph or an
invalid feature config memory access before the next value can be read.

The standalone patch is
[`nat-ei-context-invalid-next.patch`](nat-ei-context-invalid-next.patch).
It applies at the root of an unmodified copy of this repository's plugin source,
not at the upstream VPP source root:

```sh
patch --dry-run -p1 < plugins/nat-ei-context/nat-ei-context-invalid-next.patch
patch -p1 < plugins/nat-ei-context/nat-ei-context-invalid-next.patch
```

The checked-in source already includes this fix; do not apply the patch again.
Rebuild `nat_ei_context_plugin.so` using headers and generated configuration
matching the target VPP build. Deploy through that machine's existing installer
and recovery baseline process, then restart VPP to load the new plugin. Adding
the reserved drop edge changes graph slot allocation; replacing the file alone
does not update the running graph. No WAN/LAN addresses are embedded in the fix.

Run the host regression from the repository root:

```sh
python3 -m unittest discover -s tests/unit -p 'test_nat_ei_context_next.py' -v
```

It compiles the actual guard, both node functions and registrations against a
small VPP boundary shim, with ASan/UBSan. Cases cover a full 256-packet frame with
next 4 and only four exits, mixed valid/invalid packets, 32-bit truncation,
zero/one/two-worker cursor handling, RX context restoration, unmanaged exits,
and per-worker warning rate limiting. This is not a live VPP traffic test.

Deployment on the reference RK3588 board was accepted on 2026-11-03 after a controlled
restart at 13:39:48 UTC+8. Installed and installer-input plugin SHA-256:
`4369f7c4be0d07809c7072677d26d84cc7b58e02741ec5c252644372ba2cae00`.
Both nodes expose slot 0 as `error-drop` and register `invalid-next-index`;
the counters remained zero during acceptance. All 13 service checks, WAN
gateway replies, local DNS, HTTPS and three public ICMP replies passed, with no
automatic VPP restarts during acceptance. No invalid packets were injected into
production. Installation baseline manifests and the recovery snapshot were
updated; the old plugin, inputs and recovery generation were archived on the
device under `history/context-next-guard-20261103T053937Z-c0522f`.

### Stale feature cursors

With worker handoff, packets can wait in a frame queue while a feature change,
such as attaching an SPD when an IPsec client connects, rebuilds the egress
config string. The barrier does not drain that queue, so those packets reach
context-exit with a cursor into a string that has moved or been freed. The value
read there is another edge's next index or an end node index. Without a guard the
worker takes SIGSEGV in `vlib_next_frame_change_ownership`.

The range check cannot catch this reliably: reserving slot 0 makes context-exit's
table five entries long on a WAN chain, so the value 4 seen in the original crash
is a valid slot. context-exit therefore also compares the cursor with its own
position on the TX interface's current chain, computed once per TX change within a
frame. A mismatch drops the packet and counts `cursor-mismatch`. A chain containing
the node twice, from enabling both the output chain and a context on one interface,
has no unique position and falls back to the range check.

A few packets in flight during a chain change are dropped; this is expected. The
check treats the symptom of crossing a reconfiguration, and does not stop packets
from waiting in the queue.

The standalone patch against the range-check version is
[`nat-ei-context-cursor-check.patch`](nat-ei-context-cursor-check.patch).

Isolated VPP on the reference device, one worker, UDP load, toggling
`set interface ipsec spd` 40 times:

| Plugin | Packets forwarded | Result |
|---|---|---|
| Before the range check, with and without batched enqueue | 280k-380k | SIGSEGV in all 4 runs |
| Range check only | about 1.0M | Survived; 16 `invalid-next-index`, including value 4 |
| Range check and cursor check | about 1.0M | Survived; 18 `cursor-mismatch` |

Normal traffic, a steady SPD, a context chain and a duplicate exit produced no
mismatches with zero and one worker. 64 injected cursor errors produced exactly
64 mismatches with zero and one worker. The hairpin path was not exercised: the
test traffic did not reach the receiver with any plugin version.

The crash comes from this plugin's design. Stock EI output nodes go straight to
`interface-output` after handoff and never read the cursor again; context-exit
resumes the feature arc after the frame queue. Under the same SPD toggling:

| NAT44-EI | This plugin | Workers | Handoff | Result |
|---|---|---|---|---|
| Upstream | No | 1 | No | No crash in 3 runs |
| Upstream | No | 2 | Yes | No crash in 3 runs |
| Patch 0008 | No | 1 | Yes | No crash in 3 runs |
| Patch 0008 | No | 2 | Yes | No crash in 3 runs |
| Upstream | Before the guards | 2 | Yes | SIGSEGV |
| Patch 0008 | Before the guards | 1 | Yes | SIGSEGV |

Patch 0008 is what brings handoff, and so this exposure, to a single worker.

Deployment on the reference device was accepted on 2026-11-03 with installed and
installer-input plugin SHA-256
`7aaec95afbeba00ff08b3b451e9e6604e3172539402fca3a2599b3b824d857fa`. The previous
plugin, inputs and recovery generation are archived on the device under
`history/context-cursor-20261103T062107Z-ef7ea2`.

