# RTL8125 TX descriptor admission fix

The deployed DPDK 26.03 `rtl_xmit_pkts()` checks `tx_free` before its end-of-call
completion cleanup. When a previous burst exhausts the cached free count,
the next call can return zero even if the NIC has already completed packets.
VPP's `tx_burst_vector_internal()` stops retrying when a burst returns zero,
so those packets become `nic0-dpdk-tx: Tx packet drops (dpdk tx failure)`.

`r8169-tx-reclaim-before-admission.patch` reclaims completed descriptors when
the cached count cannot admit the next packet, then checks the count again.
If the ring is still full, it polls completions every 5 microseconds within
one shared 2 ms deadline for the whole burst. Progress does not restart the
deadline. It retains the normal cleanup and doorbell at the end of the call.
Packets beyond that budget remain caller-owned and can still be dropped under
sustained overload. There is no unbounded wait or extra software packet queue.

Apply this patch **in addition to** `r8169-noncoherent-dma-experimental.patch`.
The VROUTER still needs the DMA cache maintenance patch; a stock PMD cannot replace
the deployed library. The first live trial retained 1024-descriptor rings:
the fix passed the regression test but did not eliminate burst-time drops.
The next trial increased only nic0-dpdk TX rings to 4096 descriptors and the
VPP buffer pool from 8192 to 32768; RX rings and queue placement stayed unchanged.
That also failed to eliminate drops. Limited PMD diagnostics then confirmed
real descriptor exhaustion, valid single-segment packets, and a hardware
completion pointer still making progress. Logs are in VPP's `show log` ring,
not necessarily the service journal. The diagnostic logging is not in the
final PMD.

Final production acceptance on 2026-10-29 restored the original 1024 TX
descriptors and 8192 buffers. With the reclaim and bounded backpressure patch,
16 and 32 parallel WAN downloads completed with zero additional DPDK TX
failures. Eight-stream LAN TCP measured about 941 Mbps toward the client and
938 Mbps toward the router, with zero hardware RX/TX or mbuf allocation errors.
The LAN test exercises the physical TX path without NAT; public download rates
include the remote server and Internet path and do not establish NAT capacity.
The 2 ms congestion wait can delay the polling worker, so sustained overload
can still cause TX or RX loss. Acceptance covers the recorded test load.

Evidence: `artifacts/vrouter/tx-reclaim-validation-20261029.json` and
`artifacts/vrouter/tx-reclaim-client-default-final-20261029.json`. Final installed
PMD SHA256: `3c1e4dcba78dce8f1808e881aa1687ba0e63a9b7fe9c2a5934d4ae841300d84d`.

On the router, `build/history/build-r8169-tx-reclaim.py` builds a candidate from
the retained DMA-patched source and Ninja command records. Place the patch at
`/usr/local/src/vpp-vrouter/maintenance/tx-reclaim/r8169-tx-reclaim.patch` and the
regression test at `test.py` in that directory before running the builder.
The builder runs the test before compiling the PMD and normalizes its RUNPATH
for the installed `dpdk/pmds-26.1` directory. It does not install the candidate.

`tests/integration/integration_r8169_tx_reclaim.py --source PATH` extracts and compiles the
actual transmit function with deterministic completion mocks. Against the old
source, `--expect-bug` proves the zero-return problem. Against the patched
source, it covers stale zero free count, reclaim partway through a burst,
delayed completions, a full queue with a bounded wait, the shared deadline
while progress is made, partial transmission, empty input and invalid mbufs.
This test does not emulate DMA or establish a maximum forwarding rate.

`deploy/install/tx-reclaim-upgrade.py` is a one-time deployment helper to
run in an independent systemd unit. It verifies the existing recovery point,
atomically replaces the PMD, restarts VPP and waits for dependent services
before network health checks. On readiness failure it restores the previous
PMD and restarts. Keep a healthy recovery point until live acceptance finishes.
Refresh it with `recovery.py snapshot` after accepting the new version.
For the 4096-descriptor trial, pass `--tx-descriptors 4096`; that also expands
the buffer pool and restores the old startup configuration on readiness failure.
`--restore-ring-defaults` reverses that explicit trial configuration.

The network interface carries both WAN VLAN 100 and bridged LAN traffic.
Its parent TX counter includes packets forwarded toward the LAN during a
download; a parent TX drop does not by itself identify a NAT upload drop.
Also, a polling worker showing 100% CPU does not establish that useful packet
processing has saturated that core.

## 2026-10-30 tally 计数修复

当前 PMD 还须叠加 `docs/history/patches/r8169-tally-dma-sync.patch`，修复非一致性 DMA
统计读取。最终维护目录为 `maintenance/tally-verified`；安装输入及恢复点
同步为 SHA256 `7b485442401538a53c157daa8f581e59c346070f897d5a38ec54eacbcf7b77d3`。
原 `maintenance/tx-reclaim` 仅保留为重建基线，不能覆盖当前运行库。
详见 `docs/history/patches/README-r8169-tally-sync.md` 和计数修复复测报告。
