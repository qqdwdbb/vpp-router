#!/usr/bin/env python3
"""VPP/network/DNS/PD startup subset (does not start strongSwan).

For the real staged strongSwan service and the full dependency chain, run
integration_vrouter_ipsec.py --eap --startup-chain with the documented candidate
plugin bundle. This older subset remains useful for focused gate/PD checks.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


def run_cmd(*args, timeout=20, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(args)}): {p.stderr.strip() or p.stdout.strip()}")
    return p.stdout


def get_unit_properties(unit):
    p = subprocess.run(['systemctl', 'show', unit, '--property=ActiveState,SubState,MainPID,NRestarts'],
                       capture_output=True, text=True, timeout=5)
    return dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)


def wait_for(predicate, message, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description='VROUTER startup orchestration integration test')
    parser.add_argument('--vnet-library-dir', type=Path, default=Path('/opt/vpp-vrouter-migration/ipsec-ip6-udp/lib'))
    args = parser.parse_args()

    base = Path('/opt/vpp-vrouter-migration')
    vpp_bin = Path('/opt/vpp-nic1-test/vpp/bin/vpp')
    vppctl = Path('/opt/vpp-nic1-test/vpp/bin/vppctl')
    scripts_dir = base / 'source/scripts'
    startup_dir = scripts_dir / 'vrouter/startup'

    pid = os.getpid()
    prefix = f'vrouter-orch-{pid}'

    # Names of transient units
    vpp_unit = f'{prefix}-vpp.service'
    prep_unit = f'{prefix}-prep.service'
    sswan_unit = f'{prefix}-sswan.service'
    gate_unit = f'{prefix}-gate.service'
    pd_unit = f'{prefix}-pd.service'
    units = [vpp_unit, prep_unit, sswan_unit, gate_unit, pd_unit]

    # Names of test network namespaces
    host_ns = f'{prefix}-host'
    wan_ns = f'{prefix}-wan'
    namespaces = [host_ns, wan_ns]

    env = dict(os.environ,
               PATH=f'/opt/vpp-nic1-test/vpp/bin:{os.environ.get("PATH", "")}',
               LD_LIBRARY_PATH=f'{args.vnet_library_dir}:/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu',
               PYTHONPATH=str(base / 'runtime/python'),
               VPP_API_DIR='/opt/vpp-nic1-test/vpp/share/vpp/api')

    unit_dir = Path(f'/run/systemd/system')
    dropin_dirs = []

    print(f"=== Starting VROUTER Startup Orchestration Integration Test (PID {pid}) ===")

    with tempfile.TemporaryDirectory(prefix='vrouter-orch-', dir='/run') as directory, ExitStack() as stack:
        root = Path(directory)
        root.chmod(0o755)
        try:
            # 1. Create test namespaces
            for ns in namespaces:
                run_cmd('ip', 'netns', 'add', ns)
                stack.callback(subprocess.run, ['ip', 'netns', 'delete', ns], capture_output=True)

            run_cmd('ip', '-n', host_ns, 'link', 'set', 'lo', 'up')
            run_cmd('ip', '-n', wan_ns, 'link', 'set', 'lo', 'up')

            # 2. Prepare VPP configuration
            sock_cli = root / 'cli.sock'
            sock_api = root / 'api.sock'
            sock_stats = root / 'stats.sock'

            plugins = ['wireguard_plugin.so', 'tap_plugin.so', 'ping_plugin.so',
                       'nat44_ei_plugin.so', 'nat_ei_context_plugin.so', 'acl_plugin.so',
                       'dhcp_plugin.so', 'mss_clamp_plugin.so']
            (root / 'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {sock_cli} }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {sock_api} }}
statseg {{ socket-name {sock_stats} }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
plugins {{ path {base}/plugins
plugin default {{ disable }}
{chr(10).join('plugin ' + name + ' { enable }' for name in plugins)}
}}
''')

            # Helper CLI runner
            def cli(command):
                out = run_cmd(str(vppctl), '-s', str(sock_cli), command)
                if any(w in out.lower() for w in ('error:', 'unknown input', 'invalid')):
                    raise RuntimeError(f"VPP command failed: {command} -> {out}")
                return out

            # 3. Create unit files under /run/systemd/system/
            # A) vpp.service
            vpp_setup_script = root / 'vpp_setup.sh'
            vpp_setup_script.write_text(f'''#!/bin/sh
set -e
/usr/bin/python3 {startup_dir}/vrouter-vpp-ready.py --socket {sock_cli} --vppctl {vppctl} --timeout 25
{vppctl} -s {sock_cli} create bridge-domain 200
{vppctl} -s {sock_cli} create loopback interface instance 200
{vppctl} -s {sock_cli} set interface l2 bridge loop200 200 bvi
{vppctl} -s {sock_cli} set interface mac address loop200 52:54:00:20:00:01
{vppctl} -s {sock_cli} set interface ip address loop200 10.61.20.1/24
{vppctl} -s {sock_cli} set interface ip address loop200 fd42:1111:2222:10::1/64
{vppctl} -s {sock_cli} set interface state loop200 up
{vppctl} -s {sock_cli} create tap id 2000 host-ns {host_ns} host-if-name vpp-lan host-mac-addr 52:54:00:12:34:56
{vppctl} -s {sock_cli} set interface l2 bridge tap2000 200
{vppctl} -s {sock_cli} set interface rx-mode tap2000 interrupt
{vppctl} -s {sock_cli} set interface state tap2000 up
{vppctl} -s {sock_cli} create tap id 2001 host-ns {wan_ns} host-if-name vpp-wan host-ip4-addr 198.18.45.2/24 host-mac-addr 52:54:00:56:78:90
{vppctl} -s {sock_cli} set interface ip address tap2001 198.18.45.1/24
{vppctl} -s {sock_cli} set interface ip address tap2001 2001:db8:45::1/64
{vppctl} -s {sock_cli} set interface rx-mode tap2001 interrupt
{vppctl} -s {sock_cli} set interface state tap2001 up
{vppctl} -s {sock_cli} ip route add ::/0 via 2001:db8:45::2 tap2001
{vppctl} -s {sock_cli} set ip neighbor loop200 10.61.20.2 52:54:00:12:34:56
{vppctl} -s {sock_cli} set ip neighbor loop200 fd42:1111:2222:10::2 52:54:00:12:34:56
''')
            vpp_setup_script.chmod(0o755)

            (unit_dir / vpp_unit).write_text(f'''[Unit]
Description=Test VPP Service
DefaultDependencies=no

[Service]
Type=simple
Environment=PATH={env["PATH"]}
Environment=LD_LIBRARY_PATH={env["LD_LIBRARY_PATH"]}
ExecStart={vpp_bin} -c {root}/startup.conf
ExecStartPost=/bin/sh {vpp_setup_script}
Restart=on-failure
RestartSec=1
KillMode=control-group
''')

            # B) prep.service
            prep_cfg = root / 'network_prep.json'
            prep_cfg.write_text(json.dumps({
                'bridge': 'br-mgmt',
                'lan_tap': 'vpp-lan',
                'lan_ip': '10.61.20.2/24',
                'lan_ula': 'fd42:1111:2222:10::2/64',
                'vpp_gw': '10.61.20.1',
                'vpp_ula_gw': 'fd42:1111:2222:10::1',
                'vpp_socket': str(sock_cli),
                'vppctl': str(vppctl),
                'vpp_bvi': 'loop200',
                'nftsets_path': None,
                'netns': host_ns
            }))

            (unit_dir / prep_unit).write_text(f'''[Unit]
Description=Test Network Prep Service
Requires={vpp_unit}
After={vpp_unit}
PartOf={vpp_unit}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {startup_dir}/vrouter-network-prep.py --action start --config {prep_cfg}
ExecStop=/usr/bin/python3 {startup_dir}/vrouter-network-prep.py --action stop --config {prep_cfg}
''')

            # C) gate.service (DNS route gate in host namespace)
            gate_nft = root / 'gate.nft'
            gate_nft.write_text(f'''table inet vrouter_test_gate {{
    set altroute {{
        type ipv4_addr;
        flags interval;
    }}
}}
''')
            routes_cfg = root / 'routes.json'
            routes_cfg.write_text(json.dumps({
                'mappings': [{'family': 'inet', 'table': 'vrouter_test_gate', 'set': 'altroute',
                              'interface': 'loop200', 'via': '10.61.20.1', 'fib_table': 0}],
                'state_file': str(root / 'gate_state.json'),
                'state_socket': str(root / 'gate_state.sock'),
                'vpp_socket': str(sock_cli),
                'api_socket': str(sock_api),
                'vpp_service': vpp_unit
            }))
            (root / 'rules').mkdir()
            (root / 'seen.json').write_text('[]')

            gate_cfg = root / 'gate.json'
            gate_cfg.write_text(json.dumps({
                'sync_program': str(scripts_dir / 'nftset-route-sync.py'),
                'route_config': str(routes_cfg),
                'rules_directory': str(root / 'rules'),
                'lease_file': str(root / 'seen.json'),
                'upstream': ['10.61.20.2', 53],
                'listen': [['10.61.20.2', 1053]]
            }))

            (unit_dir / gate_unit).write_text(f'''[Unit]
Description=Test DNS Route Gate Service
Requires={vpp_unit} {prep_unit}
After={vpp_unit} {prep_unit}
PartOf={vpp_unit}

[Service]
Type=simple
Environment=PATH={env["PATH"]}
Environment=LD_LIBRARY_PATH={env["LD_LIBRARY_PATH"]}
Environment=PYTHONPATH={env["PYTHONPATH"]}
Environment=VPP_API_DIR={env["VPP_API_DIR"]}
ExecStartPre=/usr/bin/ip netns exec {host_ns} /usr/sbin/nft -f {gate_nft}
ExecStart=/usr/bin/ip netns exec {host_ns} /usr/bin/python3 {scripts_dir}/dns-route-gate.py --config {gate_cfg}
Restart=on-failure
RestartSec=1
KillMode=control-group
''')

            # D) pd.service (PD sync)
            pd_cfg = root / 'pd_sync.json'
            pd_pool = root / 'ipsec.conf'
            pd_pool.write_text('conn %default\n rightsourceip=10.62.50.0/24,fd00::/64\nconn eap-mschapv2\n rightsourceip=10.62.20.0/24,fd01::/64\n rightauth=eap-mschapv2\n')
            pd_cfg.write_text(json.dumps({
                'vpp_socket': str(sock_cli),
                'state_file': str(root / 'pd_state.json'),
                'lan_interface': 'loop200',
                'wan_interface': 'tap2001',
                'prefix_group': 'wan-pd',
                'withdraw_seconds': 5,
                'interval_seconds': 1,
                'ra_max_interval_seconds': 2,
                'ipsec_config': str(pd_pool),
                'ipsec_pool_routes': True
            }))

            (unit_dir / pd_unit).write_text(f'''[Unit]
Description=Test PD Sync Service
Requires={vpp_unit} {prep_unit}
After={vpp_unit} {prep_unit}
PartOf={vpp_unit}

[Service]
Type=simple
Environment=PATH={env["PATH"]}
Environment=LD_LIBRARY_PATH={env["LD_LIBRARY_PATH"]}
ExecStart=/usr/bin/python3 {scripts_dir}/vrouter/ipv6/pd-sync.py --config {pd_cfg}
Restart=on-failure
RestartSec=1
KillMode=control-group
''')

            # Register cleanup for unit files
            for u in units:
                stack.callback(lambda path: path.unlink(missing_ok=True), unit_dir / u)
                stack.callback(subprocess.run, ['systemctl', 'stop', u], capture_output=True)

            run_cmd('systemctl', 'daemon-reload')
            stack.callback(subprocess.run, ['systemctl', 'daemon-reload'], capture_output=True)

            # 4. TEST STAGE 1: Ordered Cold Boot
            print("--- Stage 1: Testing Ordered Cold Boot ---")
            start_time = time.monotonic()
            run_cmd('systemctl', 'start', gate_unit, pd_unit)

            # Check that VPP starts and becomes active
            wait_for(lambda: get_unit_properties(vpp_unit).get('ActiveState') == 'active',
                     "VPP unit did not become active", timeout=25)
            vpp_active_time = time.monotonic()
            print(f"  [PASS] vrouter-vpp activated ({vpp_active_time - start_time:.2f}s)")

            # Check that network prep starts after VPP and succeeds
            wait_for(lambda: get_unit_properties(prep_unit).get('ActiveState') == 'active',
                     "Network prep unit did not become active", timeout=15)
            prep_active_time = time.monotonic()
            print(f"  [PASS] vrouter-network-prep activated ({prep_active_time - start_time:.2f}s)")

            # Check that gate and pd sync start after prep
            wait_for(lambda: get_unit_properties(gate_unit).get('ActiveState') == 'active',
                     "DNS gate unit did not become active", timeout=20)
            wait_for(lambda: get_unit_properties(pd_unit).get('ActiveState') == 'active',
                     "PD sync unit did not become active", timeout=20)
            print("  [PASS] vrouter-dns-route-gate and vrouter-pd-sync activated")

            # 5. TEST STAGE 2: Steady-State Concurrency & Functionality
            print("--- Stage 2: Testing Steady-State Functionality ---")
            # Verify br-mgmt and connectivity
            br_check = run_cmd('ip', '-n', host_ns, 'addr', 'show', 'dev', 'br-mgmt')
            assert '10.61.20.2/24' in br_check, "br-mgmt missing 10.61.20.2/24"
            assert 'fd42:1111:2222:10::2/64' in br_check, "br-mgmt missing ULA"

            # Ping VPP BVI from host
            ping_out = run_cmd('ip', 'netns', 'exec', host_ns, 'ping', '-c', '3', '-W', '1', '10.61.20.1')
            assert '3 packets transmitted, 3 received' in ping_out, f"Host to VPP ping failed: {ping_out}"
            print("  [PASS] Host br-mgmt -> VPP loop200 IPv4 connectivity confirmed")

            # Verify DNS gate is connected to Binary API
            wait_for(lambda: (root / 'gate_state.sock').exists(), "DNS gate socket not created")
            # Send test query / trigger route installation
            run_cmd('ip', 'netns', 'exec', host_ns, 'nft', 'add', 'element', 'inet', 'vrouter_test_gate', 'altroute', '{', '198.51.100.88', '}')
            wait_for(lambda: '198.51.100.88/32' in cli('show ip fib table 0 198.51.100.88/32'),
                     "DNS gate did not install FIB route into VPP", timeout=15)
            print("  [PASS] DNS route gate Binary API route installation confirmed")

            # Verify PD sync initial sync
            wait_for(lambda: (root / 'pd_state.json').exists(), "PD state file not created")
            pd_state = json.loads((root / 'pd_state.json').read_text())
            assert pd_state.get('vpp_generation') == sock_cli.stat().st_ino, "PD sync generation mismatch"
            print("  [PASS] PD sync VPP generation tracking confirmed")

            # 6. TEST STAGE 3: Cascading Auto-Recovery on VPP Restart
            print("--- Stage 3: Testing Cascading Auto-Recovery on VPP Restart ---")
            old_vpp_pid = get_unit_properties(vpp_unit)['MainPID']
            old_gate_pid = get_unit_properties(gate_unit)['MainPID']
            old_pd_pid = get_unit_properties(pd_unit)['MainPID']

            # Restart root VPP unit
            print("  Restarting VPP unit...")
            run_cmd('systemctl', 'restart', vpp_unit, timeout=45)

            # Wait for VPP to be restarted with new PID
            wait_for(lambda: get_unit_properties(vpp_unit).get('ActiveState') == 'active' and
                             get_unit_properties(vpp_unit)['MainPID'] != old_vpp_pid,
                     "VPP did not restart with new PID", timeout=30)
            print(f"  [PASS] VPP restarted with new PID {get_unit_properties(vpp_unit)['MainPID']}")

            # Wait for prep to re-run and succeed
            wait_for(lambda: get_unit_properties(prep_unit).get('ActiveState') == 'active',
                     "Network prep did not recover after VPP restart", timeout=20)
            print("  [PASS] Network prep re-executed and active")

            # Wait for gate and pd to restart/recover with new generation
            wait_for(lambda: get_unit_properties(gate_unit).get('ActiveState') == 'active' and
                             get_unit_properties(pd_unit).get('ActiveState') == 'active',
                     "Dependent units did not recover after VPP restart", timeout=30)
            print("  [PASS] Dependents recovered to active state")

            # Verify connectivity after restart
            ping_after = run_cmd('ip', 'netns', 'exec', host_ns, 'ping', '-c', '3', '-W', '1', '10.61.20.1')
            assert '3 packets transmitted, 3 received' in ping_after, "Ping failed after restart"
            print("  [PASS] Host to VPP ping verified after restart")

            # Verify DNS route gate reconciled FIB routes into new VPP
            wait_for(lambda: '198.51.100.88/32' in cli('show ip fib table 0 198.51.100.88/32'),
                     "DNS gate did not re-install FIB route into new VPP generation", timeout=20)
            print("  [PASS] DNS gate FIB routes re-installed in new VPP generation")

            # Verify PD sync generation update
            wait_for(lambda: json.loads((root / 'pd_state.json').read_text()).get('vpp_generation') == sock_cli.stat().st_ino,
                     "PD sync did not update to new VPP generation", timeout=20)
            print("  [PASS] PD sync generation updated to new VPP generation")

            # 7. TEST STAGE 4: Orderly Teardown
            print("--- Stage 4: Testing Orderly Teardown ---")
            run_cmd('systemctl', 'stop', vpp_unit, timeout=30)

            # Because PartOf=vpp_unit is set on prep, gate, pd: all must stop
            wait_for(lambda: all(get_unit_properties(u).get('ActiveState') not in ('active', 'activating')
                                 for u in [vpp_unit, prep_unit, gate_unit, pd_unit]),
                     "Stopping VPP did not stop all dependent units", timeout=25)
            print("  [PASS] Stopping vrouter-vpp cleanly stopped all dependent services")

            result = {
                'ordered_cold_boot': True,
                'vpp_readiness_gating': True,
                'network_prep_oneshot_success': True,
                'host_vpp_bvi_ping': True,
                'dns_route_gate_binary_api': True,
                'pd_sync_generation_tracking': True,
                'vpp_restart_cascading_recovery': True,
                'post_restart_ping': True,
                'post_restart_gate_reconciliation': True,
                'post_restart_pd_reconciliation': True,
                'orderly_shutdown_cascade': True
            }

            result_file = base / 'logs/startup-orchestration-20261017.json'
            result_file.write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2))
            print("=== VROUTER Startup Orchestration Integration Test PASSED ===")

        finally:
            # Cleanup any lingering units
            for u in units:
                subprocess.run(['systemctl', 'stop', u], capture_output=True, timeout=10)
                (unit_dir / u).unlink(missing_ok=True)
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=10)


if __name__ == '__main__':
    main()
