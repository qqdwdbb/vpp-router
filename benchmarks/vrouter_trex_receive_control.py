#!/usr/bin/env python3
"""Three-second receive/drop control on the same WAN path; no NAT mapping added."""
import getpass
import json
from pathlib import Path
import re
import shlex
import subprocess
import time


def main():
    password = getpass.getpass('Remote sudo password: ')
    hosts = {'router': '10.61.20.1', 'linux': '10.61.20.134'}
    result = {'pps': 2000000, 'count': 6000000, 'seconds': 3, 'destination_port': 45995,
              'purpose': 'unmapped WAN UDP: receive and NAT no-translation drop, no LAN output'}

    def remote(host, command, timeout=45):
        p = subprocess.run(['ssh', '-S', '/tmp/vrouter-bench-' + host + '.sock',
                            '-o', 'BatchMode=yes', 'vpp-operator@' + hosts[host],
                            'sudo -S -p "" sh -c ' + shlex.quote(command)],
                           input=password + '\n', capture_output=True, text=True, timeout=timeout)
        if p.returncode:
            raise RuntimeError(p.stderr[-1000:] + p.stdout[-1000:])
        return p.stdout

    def snapshot():
        return {name: remote('router', '/usr/local/bin/vppctl ' + shlex.quote(command))
                for name, command in {'interfaces': 'show interface', 'errors': 'show errors',
                                      'hardware': 'show hardware-interfaces nic0-dpdk detail'}.items()}

    cleanup = None
    try:
        mappings = remote('router', '/usr/local/bin/vppctl "show nat44 ei static mappings"')
        if re.search(r'\b45995\b', mappings):
            raise RuntimeError('control port already mapped')
        if remote('linux', 'pgrep -a _t-rex-64 || true').strip():
            raise RuntimeError('another TRex process is active')
        pause = remote('linux', 'ethtool -a enp3s0f0')
        result['pause_before'] = pause
        rx = re.search(r'RX:\s+(on|off)', pause)[1]
        tx = re.search(r'TX:\s+(on|off)', pause)[1]
        autoneg = re.search(r'Autonegotiate:\s+(on|off)', pause)[1]
        cleanup = ('systemctl stop vrouter-rx-control-trex.service; '
                   f'ethtool -A enp3s0f0 autoneg {autoneg} rx {rx} tx {tx}')
        remote('linux', 'systemd-run --unit=vrouter-rx-control-cleanup --on-active=45s '
               '/bin/sh -c ' + shlex.quote(cleanup))
        remote('linux', 'ethtool -A enp3s0f0 autoneg off rx off tx off\n'
               'systemd-run --unit=vrouter-rx-control-trex --property=RuntimeMaxSec=30 '
               '--property=WorkingDirectory=/var/tmp/vrouter-trex/v3.08 '
               '/var/tmp/vrouter-trex/v3.08/t-rex-64 -i --cfg /run/vrouter-sequence.yaml '
               '--no-scapy-server --no-watchdog --no-hw-flow-stat --software --no-ofed-check -c 1')
        time.sleep(3)
        result['before'] = snapshot()
        sent = remote('linux', '/var/tmp/vrouter-trex/venv/bin/python /run/vrouter-sequence-phase.py '
                      '--trex /var/tmp/vrouter-trex/v3.08 --pps 2000000 --count 6000000 '
                      '--run 663001 --port 45995')
        result['sender'] = json.loads(sent.strip().splitlines()[-1])
        time.sleep(1)
        result['after'] = snapshot()
    except Exception as exc:
        result['error'] = str(exc)
    finally:
        if cleanup:
            result['cleanup'] = remote('linux', cleanup + '\nsystemctl stop vrouter-rx-control-cleanup.timer')
            result['pause_after'] = remote('linux', 'ethtool -a enp3s0f0')
        path = Path(__file__).resolve().parent.parent / 'artifacts/vrouter/trex-rx-control-20261030.json'
        path.write_text(json.dumps(result, indent=2) + '\n')
        print('RESULT', path)


if __name__ == '__main__':
    main()
