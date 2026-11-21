# TAP interrupt RX refill retry

`tap-rx-refill-retry.patch` targets the TAP plugin in the VROUTER VPP 26.06 tree.
It keeps the existing L2 bridge, interrupt RX mode, and 8192-buffer configuration.

A traffic burst can exhaust the buffer pool while `tap_refill_vring()` replenishes
the RX ring. If allocation returns zero after the last descriptor is consumed,
the backend cannot deliver more packets or generate another completion interrupt.
Buffers subsequently returning to the pool do not wake this queue.

Each RX queue now publishes an atomic `refill_pending` flag on allocation failure.
A main-thread process checks pending queues every 10 ms and schedules their owning
RX worker through `vnet_hw_if_rx_queue_set_int_pending()`. Only that worker allocates
buffers and updates descriptors; a successful refill clears the flag. The process
scans current interfaces rather than retaining queue pointers across suspension,
so interface deletion and queue-index reuse do not leave stale retry work.

Build on VROUTER using the existing compiler/linker settings, without modifying the
original build or installed plugin:

```sh
python3 build/history/build-tap-refill.py --output /var/lib/vpp-vrouter/build/tap-refill/production
```

For deterministic regression tests build separate candidates with
`--fault-injection`, and an unpatched control with `--baseline --fault-injection`.
`tests/integration/integration_tap_refill_retry.py` runs each build in an isolated VPP and
namespace with `--workers 0` or `--workers 2`. Three cycles force allocation to zero,
drain the queue, restore allocation, and check automatic refill without sending new
traffic or switching polling mode. It also deletes an interface with a pending
retry. The baseline must remain stalled; it is rescued between cycles by polling.
The test hook is excluded from production, and the upgrade helper rejects binaries
containing its CLI command. This tests allocation-failure recovery directly; it
does not characterize throughput or the peak buffer occupancy of a browser test.

`deploy/install/tap-refill-upgrade.py` backs up the installed plugin, arms an
independent 300-second rollback, restarts the installed service set, and checks
LAN/WAN, the retry node, and host HTTPS. Run it through `systemd-run` from the
independent mgmt0 management connection. Confirm only after additional live checks.
The backup and upgrade record remain under `/var/lib/vpp-vrouter`.
