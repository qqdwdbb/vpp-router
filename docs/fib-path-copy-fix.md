# Deleted-interface path-list copy crash (2026-10-23)

VPP 26.06 on VROUTER crashed at 11:18:16 while adding a multipath route.
The request added a valid path via loop10. The existing path-list also
contained a path via deleted wg2 (old sw_if_index 12, next-hop 10.14.0.1).

Interface deletion sets FIB_PATH_OPER_FLAG_DROP on dependent paths.
fib_path_list_copy_and_path_add() then calls fib_path_copy(), which cleared
all operational flags, including this permanent deletion marker. Resolving
the copied path recreated an adjacency on the deleted interface. The PMTU
delegate looked up its table: fib_index_by_sw_if_index[12] was ~0, and
fib_table_get() treated that as a pool index, causing SIGSEGV.

This does not require concurrent requests. An isolated instance running the
production library reproduced SIGSEGV with sequential CLI operations: create
interface, add route, delete interface, add another path to the same route.
The API's valid new interface is not the invalid interface in the copied path.

The patch in docs/history/patches/fib-path-copy-deleted-interface.patch preserves only
FIB_PATH_OPER_FLAG_DROP during copies; other operational flags are still
recomputed. This retains the documented permanent-drop semantics, including
when a newly created interface reuses the deleted interface index. Skipping
only the PMTU lookup would leave the invalid path alive and is insufficient.

## Build and validation

Use build/history/build-fib-path-copy.py on VROUTER with --output and --patch.
The builder retains the deployed IPv6 PD and IPv6 ESP UDP fixes. Before
linking the candidate it verifies that the reconstructed baseline is
byte-identical to the installed production library; it refuses mismatches.

tests/integration/integration_fib_deleted_interface.py starts a disposable VPP instance
without physical NICs and checks IPv4/IPv6 route updates after interface
deletion and index reuse. The original library crashed in the IPv4 case;
the fixed candidate passed both families. The installed fixed library was
tested again in isolation after deployment. No long-term soak or exhaustive
FIB path-type regression suite was performed.

## Deployment

Installed at /usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu/libvnet.so.26.06.0.
VPP restarted successfully at 11:36:29 CST on 2026-10-23, PID 1304855.
Its process mappings confirm the new library. VPP, DNS Gate and Fake-IP
services were active after restart; normal IPv4 DNS queries succeeded.

SHA256 of fixed library:
f3caf3116322b9e214726ac74d70b8e2a051dda91b8aa7a5959fd611e940e0fc

Backup on VROUTER (do not overwrite):
/opt/vpp-vrouter-migration/fib-path-copy-preserved-20261023/production-before.so

Baseline SHA256:
133cb2a5bdadcaa1cdb823af5bbe7288b50c41018003733c8ecfe232cc0e32ea

Rollback requires atomically restoring the backup library and restarting
vrouter-vpp.service. The original crash core has been retained separately.

## Regression on 2026-10-24

The next libvnet rebuild for the IPv6 ESP fix retained only the PD object, so this fix was lost. A relink without this patch is byte-identical (.text/.rodata/.data) to the version later found running. To prevent a repeat, a rebuild must include every patch in the series, and libvnet should be pinned in the installation baseline.

On the affected version, adding a path after an interface index was reused sends traffic through the unrelated new interface. tests/integration/integration_fib_deleted_interface.py detects this; the patched library passes for IPv4 and IPv6.

Restored on 2026-11-03 together with a libvnet hash pin in the installation baseline. Isolated test passes on the installed library (IPv4 and IPv6). The SIGSEGV path was not separately reproduced this time.
