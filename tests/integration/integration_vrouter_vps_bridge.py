#!/usr/bin/env python3
"""Isolated VLAN 10 L2: tagged TAP <-> VPP BD <-> Linux br0 + simulated gretap."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from integration_wireguard_interface_peer import run
from integration_vrouter_dns_route_gate import wait_for


def main(workers):
    base = Path('/opt/vpp-vrouter-migration')
    names = ('vrouter-vps-phy', 'vrouter-vps-br', 'vrouter-vps-remote')
    listed = run('ip', 'netns', 'list')
    assert all(name not in listed for name in names)
    unit = 'vrouter-vps-vpp-' + str(os.getpid())
    env = dict(os.environ, PATH='/opt/vpp-nic1-test/vpp/bin:' + os.environ['PATH'],
               LD_LIBRARY_PATH='/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:'
               '/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu')
    os.environ.update(env)
    created = []
    with tempfile.TemporaryDirectory(prefix='vrouter-vps-', dir='/run') as directory:
        root = Path(directory)
        try:
            for name in names:
                run('ip', 'netns', 'add', name)
                created.append(name)
                run('ip', '-n', name, 'link', 'set', 'lo', 'up')
            (root / 'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
{'cpu { main-core 4 corelist-workers 5-6 }' if workers else ''}
plugins {{ path {base}/plugins
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
}}
''')
            run('systemd-run', '--unit=' + unit, '--property=RuntimeMaxSec=120',
                '--property=KillMode=control-group',
                '--setenv=LD_LIBRARY_PATH=' + env['LD_LIBRARY_PATH'],
                '/opt/vpp-nic1-test/vpp/bin/vpp', '-c', str(root / 'startup.conf'))
            wait_for(lambda: (root / 'cli.sock').exists(), 'VPP did not start', 20)

            def cli(command):
                text = run('vppctl', '-s', str(root / 'cli.sock'), command)
                if any(word in text.lower() for word in ('error:', 'failed', 'unknown input', 'invalid')):
                    raise RuntimeError('VPP VLAN10 command failed; output suppressed')
                return text

            def execute(lines):
                (root / 'commands.conf').write_text('\n'.join(lines) + '\n')
                return cli('exec ' + str(root / 'commands.conf'))

            execute([
                'create bridge-domain 3960',
                'create tap id 3960 host-ns vrouter-vps-phy host-if-name mgmt0',
                'create tap id 3961 host-ns vrouter-vps-br host-if-name vrouter-vps host-mtu-size 1342',
                'set interface state tap3960 up',
                'set interface state tap3961 up',
                'set interface rx-mode tap3960 interrupt',
                'set interface rx-mode tap3961 interrupt',
                'create sub-interface tap3960 10 dot1q 10 exact-match',
                'set interface state tap3960.10 up',
                'set interface l2 bridge tap3960.10 3960',
                'set interface l2 tag-rewrite tap3960.10 pop 1',
                'set interface l2 bridge tap3961 3960',
            ])
            domain = cli('show bridge-domain 3960 detail')
            assert 'tap3960.10' in domain and 'tap3961' in domain, domain

            def ns(name, *args):
                return run('ip', 'netns', 'exec', name, *args)

            ns('vrouter-vps-phy', 'ip', 'link', 'set', 'mgmt0', 'up')
            ns('vrouter-vps-phy', 'ip', 'link', 'add', 'link', 'mgmt0', 'name', 'mgmt0.10', 'type', 'vlan', 'id', '10')
            ns('vrouter-vps-phy', 'ip', 'addr', 'add', '198.18.20.10/24', 'dev', 'mgmt0.10')
            ns('vrouter-vps-phy', 'ip', 'link', 'set', 'mgmt0.10', 'up')

            ns('vrouter-vps-br', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
            ns('vrouter-vps-br', 'ip', 'link', 'set', 'br0', 'mtu', '1342')
            ns('vrouter-vps-br', 'ip', 'link', 'set', 'vrouter-vps', 'mtu', '1342')
            ns('vrouter-vps-br', 'ip', 'link', 'set', 'vrouter-vps', 'master', 'br0')
            ns('vrouter-vps-br', 'ip', 'link', 'add', 'gretap-sim', 'type', 'veth',
               'peer', 'name', 'remote0', 'netns', 'vrouter-vps-remote')
            ns('vrouter-vps-br', 'ip', 'link', 'set', 'gretap-sim', 'mtu', '1342')
            ns('vrouter-vps-br', 'ip', 'link', 'set', 'gretap-sim', 'master', 'br0')
            ns('vrouter-vps-br', 'ip', 'addr', 'add', '198.18.20.2/24', 'dev', 'br0')
            ns('vrouter-vps-br', 'ip', 'link', 'set', 'br0', 'up')
            ns('vrouter-vps-br', 'ip', 'link', 'set', 'vrouter-vps', 'up')
            ns('vrouter-vps-br', 'ip', 'link', 'set', 'gretap-sim', 'up')

            ns('vrouter-vps-remote', 'ip', 'link', 'set', 'remote0', 'mtu', '1342')
            ns('vrouter-vps-remote', 'ip', 'addr', 'add', '198.18.20.8/24', 'dev', 'remote0')
            ns('vrouter-vps-remote', 'ip', 'link', 'set', 'remote0', 'up')

            def ping(src, dst):
                return ns(src, 'ping', '-c', '5', '-W', '2', dst)

            vps_remote = ping('vrouter-vps-phy', '198.18.20.8')
            assert '5 received, 0% packet loss' in vps_remote, vps_remote
            vps_br = ping('vrouter-vps-phy', '198.18.20.2')
            assert '5 received, 0% packet loss' in vps_br, vps_br
            remote_br = ping('vrouter-vps-remote', '198.18.20.2')
            assert '5 received, 0% packet loss' in remote_br, remote_br
            ns('vrouter-vps-phy', 'ip', 'addr', 'add', '198.18.20.11/24', 'dev', 'mgmt0')
            untagged = subprocess.run(
                ['ip', 'netns', 'exec', 'vrouter-vps-phy', 'ping', '-c', '3', '-W', '1',
                 '-I', 'mgmt0', '198.18.20.8'], capture_output=True, text=True, timeout=10)
            assert untagged.returncode != 0 and '0 received' in untagged.stdout, untagged.stdout
            mtu_ok = ns('vrouter-vps-phy', 'ping', '-c', '3', '-W', '2', '-M', 'do', '-s', '1314', '198.18.20.8')
            assert '3 received' in mtu_ok, mtu_ok
            report = {
                'passed': True,
                'workers': workers,
                'vps_to_remote': vps_remote.splitlines()[-2],
                'vps_to_br0': vps_br.splitlines()[-2],
                'remote_to_br0': remote_br.splitlines()[-2],
                'untagged_blocked': True,
                'mtu_1314_df': mtu_ok.splitlines()[-2],
            }
            (base / 'logs').mkdir(exist_ok=True)
            (base / 'logs' / f'vps-bridge-workers{workers}.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report))
        finally:
            subprocess.run(['systemctl', 'stop', unit], capture_output=True)
            subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True)
            for name in reversed(created):
                subprocess.run(['ip', 'netns', 'del', name], capture_output=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workers', type=int, default=0, choices=(0, 2))
    main(parser.parse_args().workers)
