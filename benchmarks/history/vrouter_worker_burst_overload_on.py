#!/usr/bin/env python3
"""Run repeatable forwarding/NAT worker profiles with temporary policy4 lock."""
import getpass
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[2]
POLICY = '/sys/devices/system/cpu/cpufreq/policy4'
OUT = BASE / 'artifacts/vrouter/worker-burst-overload-on-20261031.json'


def main():
    password = getpass.getpass('Remote sudo password: ')

    def remote(command):
        cp = subprocess.run(['ssh', '-S', '/tmp/vrouter-prof-router.sock', '-o',
                             'BatchMode=yes', 'vpp-operator@10.61.20.1',
                             'sudo -S -p "" sh -c ' + shlex.quote(command)],
                            input=password + '\n', text=True, capture_output=True, timeout=45)
        if cp.returncode:
            raise RuntimeError(cp.stderr + cp.stdout)
        return cp.stdout

    original = remote('cat ' + POLICY + '/scaling_governor ' + POLICY +
                      '/scaling_min_freq ' + POLICY + '/scaling_max_freq').splitlines()
    governor, minimum, maximum = original
    restore = ('echo ' + maximum + ' > ' + POLICY + '/scaling_max_freq\n' +
               'echo ' + minimum + ' > ' + POLICY + '/scaling_min_freq\n' +
               'echo ' + governor + ' > ' + POLICY + '/scaling_governor\n')
    # Restore the WAN hooks and remove the temporary test resources even if the
    # local driver disconnects while the unfiltered forwarding control is active.
    cleanup = ('#!/bin/sh\n' + restore +
               '/usr/local/bin/vppctl set acl-plugin interface nic0-dpdk.100 input acl 2\n'
               '/usr/local/bin/vppctl set acl-plugin interface nic0-dpdk.100 output acl 3\n'
               '/usr/local/bin/vppctl set interface nat44 ei in nic0-dpdk.100 output-feature\n'
               '/usr/local/bin/vppctl ip route del 198.18.0.1/32 via drop\n'
               '/usr/local/bin/vppctl nat44 ei add static mapping udp local 10.61.20.198 45996 external 10.61.10.2 45996 vrf 0 del\n')
    result = {'started_at': time.time(), 'original_policy': original,
              'frequency_khz': 2208000, 'pps': [2000000], 'duration_s': 15}
    remote("cat > /run/vrouter-profile-cleanup.sh <<'EOF'\n" + cleanup + 'EOF\n' +
           'systemd-run --unit=vrouter-profile-cleanup --on-active=12m /bin/sh /run/vrouter-profile-cleanup.sh')
    try:
        remote('echo performance > ' + POLICY + '/scaling_governor\n' +
               'echo 2208000 > ' + POLICY + '/scaling_max_freq\n' +
               'echo 2208000 > ' + POLICY + '/scaling_min_freq')
        result['locked_policy'] = remote('cat ' + POLICY + '/scaling_min_freq ' +
                                         POLICY + '/scaling_max_freq ' + POLICY + '/cpuinfo_cur_freq')
        if result['locked_policy'].splitlines() != ['2208000'] * 3:
            raise RuntimeError('CPU frequency lock verification failed')
        output = BASE / 'artifacts/vrouter/worker-burst-overload-on-raw-20261031.json'
        cp = subprocess.run([sys.executable, str(BASE / 'benchmarks/vrouter_path_compare_burst_ports.py'),
                             '--modes', 'nat', '--rates', '2000000',
                             '--seconds', '15', '--run-base', '870000', '--sample-worker', '--sample-rx-status', '--router-socket', '/tmp/vrouter-prof-router.sock', '--linux-socket', '/tmp/vrouter-prof-linux.sock',
                             '--output', str(output), '--password-stdin'],
                            input=password + '\n', text=True, timeout=600)
        if cp.returncode:
            raise RuntimeError('path profiling failed')
        result['raw'] = str(output)
    finally:
        remote('/bin/sh /run/vrouter-profile-cleanup.sh\n'
               'systemctl stop vrouter-profile-cleanup.timer')
        result['restored_policy'] = remote('cat ' + POLICY + '/scaling_governor ' +
                                           POLICY + '/scaling_min_freq ' + POLICY + '/scaling_max_freq')
        result['finished_at'] = time.time()
        OUT.write_text(json.dumps(result, indent=2) + '\n')
    print(OUT)


if __name__ == '__main__':
    main()
