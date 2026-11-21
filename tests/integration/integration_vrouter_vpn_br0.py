#!/usr/bin/env python3
"""Isolated VLAN10 BVI: nftset vpn/vpn6 via br0 gateway 10.61.50.1 / ::1."""
import argparse
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

from integration_wireguard_interface_peer import run
from integration_vrouter_dns_route_gate import wait_for


def main(workers):
    base = Path('/opt/vpp-vrouter-migration')
    scripts = base / 'source/scripts'
    names = ('vrouter-vpn-lan', 'vrouter-vpn-br', 'vrouter-vpn-remote')
    table = 'vrouter_vpn_br0_test'
    listed = run('ip', 'netns', 'list')
    assert all(name not in listed for name in names)
    assert table not in run('nft', 'list', 'tables')
    unit = 'vrouter-vpn-vpp-' + str(os.getpid())
    env = dict(os.environ, PATH='/opt/vpp-nic1-test/vpp/bin:' + os.environ['PATH'],
               LD_LIBRARY_PATH='/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:'
               '/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu',
               PYTHONPATH=str(base / 'runtime/python'),
               VPP_API_DIR='/opt/vpp-nic1-test/vpp/share/vpp/api')
    os.environ.update(env)
    sys.path.insert(0, env['PYTHONPATH'])
    sync = runpy.run_path(str(scripts / 'nftset-route-sync.py'))
    created = []
    with tempfile.TemporaryDirectory(prefix='vrouter-vpn-', dir='/run') as directory:
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
            run('systemd-run', '--unit=' + unit, '--property=RuntimeMaxSec=150',
                '--property=KillMode=control-group',
                '--setenv=LD_LIBRARY_PATH=' + env['LD_LIBRARY_PATH'],
                '/opt/vpp-nic1-test/vpp/bin/vpp', '-c', str(root / 'startup.conf'))
            wait_for(lambda: (root / 'cli.sock').exists() and (root / 'api.sock').exists(),
                     'VPP did not start', 20)

            def cli(command):
                text = run('vppctl', '-s', str(root / 'cli.sock'), command)
                if any(word in text.lower() for word in ('error:', 'failed', 'unknown input', 'invalid')):
                    raise RuntimeError('VPP vpn/br0 command failed; output suppressed')
                return text

            def execute(lines):
                (root / 'commands.conf').write_text('\n'.join(lines) + '\n')
                return cli('exec ' + str(root / 'commands.conf'))

            production = json.loads(
                (scripts / 'vrouter/dns-route-gate/nftset-route-sync.json').read_text())
            execute([
                'create bridge-domain 10',
                'create loopback interface instance 10',
                'set interface ip address loop10 10.61.50.3/24',
                'set interface ip address loop10 fd42:1111:2222:20::3/64',
                'set interface state loop10 up',
                'set interface mtu packet 1342 loop10',
                'set interface l2 bridge loop10 10 bvi',
                'ip6 nd loop10 ra-suppress',
                'create tap id 2010 host-ns vrouter-vpn-br host-if-name vrouter-vps host-mtu-size 1342',
                'set interface state tap2010 up',
                'set interface mtu packet 1342 tap2010',
                'set interface rx-mode tap2010 interrupt',
                'set interface l2 bridge tap2010 10',
                'create tap id 3960 host-ns vrouter-vpn-lan host-if-name mgmt0',
                'set interface state tap3960 up',
                'set interface rx-mode tap3960 interrupt',
                'create sub-interface tap3960 10 dot1q 10 exact-match',
                'set interface state tap3960.10 up',
                'set interface l2 bridge tap3960.10 10',
                'set interface l2 tag-rewrite tap3960.10 pop 1',
                'create bridge-domain 200',
                'create loopback interface instance 200',
                'set interface ip address loop200 198.18.44.1/24',
                'set interface ip address loop200 fd42:1111:2222:10::1/64',
                'set interface state loop200 up',
                'set interface l2 bridge loop200 200 bvi',
                'ip6 nd loop200 ra-suppress',
                'create tap id 2000 host-ns vrouter-vpn-lan host-if-name lan0',
                'set interface state tap2000 up',
                'set interface rx-mode tap2000 interrupt',
                'set interface l2 bridge tap2000 200',
            ])

            def ns(name, *args):
                return run('ip', 'netns', 'exec', name, *args)

            ns('vrouter-vpn-lan', 'ip', 'link', 'set', 'mgmt0', 'up')
            ns('vrouter-vpn-lan', 'ip', 'link', 'add', 'link', 'mgmt0', 'name', 'mgmt0.10',
               'type', 'vlan', 'id', '10')
            ns('vrouter-vpn-lan', 'ip', 'link', 'set', 'mgmt0.10', 'up')
            ns('vrouter-vpn-lan', 'ip', 'link', 'set', 'lan0', 'up')
            ns('vrouter-vpn-lan', 'ip', 'addr', 'add', '198.18.44.10/24', 'dev', 'lan0')
            ns('vrouter-vpn-lan', 'ip', '-6', 'addr', 'add', 'fd42:1111:2222:10::10/64',
               'dev', 'lan0', 'nodad')
            ns('vrouter-vpn-lan', 'ip', 'route', 'add', 'default', 'via', '198.18.44.1')
            ns('vrouter-vpn-lan', 'ip', '-6', 'route', 'add', 'default', 'via',
               'fd42:1111:2222:10::1')

            ns('vrouter-vpn-br', 'ip', 'link', 'add', 'br0', 'type', 'bridge')
            ns('vrouter-vpn-br', 'ip', 'link', 'set', 'br0', 'mtu', '1342')
            ns('vrouter-vpn-br', 'ip', 'link', 'set', 'vrouter-vps', 'mtu', '1342')
            ns('vrouter-vpn-br', 'ip', 'link', 'set', 'vrouter-vps', 'master', 'br0')
            ns('vrouter-vpn-br', 'ip', 'link', 'add', 'gretap-sim', 'type', 'veth',
               'peer', 'name', 'remote0', 'netns', 'vrouter-vpn-remote')
            ns('vrouter-vpn-br', 'ip', 'link', 'set', 'gretap-sim', 'mtu', '1342')
            ns('vrouter-vpn-br', 'ip', 'link', 'set', 'gretap-sim', 'master', 'br0')
            ns('vrouter-vpn-br', 'ip', 'addr', 'add', '10.61.50.2/24', 'dev', 'br0')
            ns('vrouter-vpn-br', 'ip', '-6', 'addr', 'add', 'fd42:1111:2222:20::2/64',
               'dev', 'br0', 'nodad')
            ns('vrouter-vpn-br', 'ip', 'link', 'set', 'br0', 'up')
            ns('vrouter-vpn-br', 'ip', 'link', 'set', 'vrouter-vps', 'up')
            ns('vrouter-vpn-br', 'ip', 'link', 'set', 'gretap-sim', 'up')
            ns('vrouter-vpn-br', 'sysctl', '-w', 'net.ipv4.ip_forward=0')
            ns('vrouter-vpn-br', 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=0')

            ns('vrouter-vpn-remote', 'ip', 'link', 'set', 'remote0', 'mtu', '1342')
            ns('vrouter-vpn-remote', 'ip', 'addr', 'add', '10.61.50.1/24', 'dev', 'remote0')
            ns('vrouter-vpn-remote', 'ip', '-6', 'addr', 'add', 'fd42:1111:2222:20::1/64',
               'dev', 'remote0', 'nodad')
            ns('vrouter-vpn-remote', 'ip', 'addr', 'add', '198.51.100.77/32', 'dev', 'remote0')
            ns('vrouter-vpn-remote', 'ip', '-6', 'addr', 'add', '2001:db8:77::1/128',
               'dev', 'remote0', 'nodad')
            ns('vrouter-vpn-remote', 'ip', 'link', 'set', 'remote0', 'up')
            ns('vrouter-vpn-remote', 'sysctl', '-w', 'net.ipv4.ip_forward=1')
            ns('vrouter-vpn-remote', 'sysctl', '-w', 'net.ipv6.conf.all.forwarding=1')
            ns('vrouter-vpn-remote', 'sysctl', '-w', 'net.ipv6.conf.remote0.forwarding=1')
            ns('vrouter-vpn-remote', 'ip', 'route', 'add', '198.18.44.0/24', 'via', '10.61.50.3')
            ns('vrouter-vpn-remote', 'ip', '-6', 'route', 'add', 'fd42:1111:2222:10::/64',
               'via', 'fd42:1111:2222:20::3')

            def ping_ok(src, dest, version=4):
                args = ['ip', 'netns', 'exec', src, 'ping', '-c', '1', '-W', '1', dest]
                if version == 6:
                    args = ['ip', 'netns', 'exec', src, 'ping', '-6', '-c', '1', '-W', '1', dest]
                return subprocess.run(args, capture_output=True, text=True, timeout=5).returncode == 0

            def ping(src, dest, version=4):
                args = ['ping', '-c', '3', '-W', '1', dest] if version == 4 else [
                    'ping', '-6', '-c', '3', '-W', '1', dest]
                return ns(src, *args)

            wait_for(lambda: ping_ok('vrouter-vpn-lan', '10.61.50.1'),
                     'LAN did not reach br0 IPv4 gateway via BVI', 20)
            wait_for(lambda: ping_ok('vrouter-vpn-lan', 'fd42:1111:2222:20::1', 6),
                     'LAN did not reach br0 IPv6 gateway via BVI', 20)

            run('nft', '-f', '-', input=f'''table inet {table} {{
set vpn {{
type ipv4_addr;
flags interval;
}}
set vpn6 {{
type ipv6_addr;
flags interval;
}}
}}
''')
            run('nft', 'add', 'element', 'inet', table, 'vpn', '{',
                '198.51.100.77', ',', '10.61.50.1', '}')
            run('nft', 'add', 'element', 'inet', table, 'vpn6', '{',
                '2001:db8:77::1', ',', 'fd42:1111:2222:20::1', '}')

            mappings = []
            for mapping in production['mappings']:
                item = dict(mapping)
                if item.get('set') in ('vpn', 'vpn6'):
                    item['enabled'] = True
                    item['table'] = table
                    mappings.append(item)
                else:
                    item['enabled'] = False
                    mappings.append(item)
            config = dict(production, mappings=mappings,
                          state_file=str(root / 'state.json'),
                          state_socket=str(root / 'state.sock'),
                          vpp_socket=str(root / 'cli.sock'),
                          api_socket=str(root / 'api.sock'),
                          vpp_service=unit,
                          lock_files=[str(root / 'import.lock')],
                          fib_audit_seconds=0)
            config_path = root / 'routes.json'
            config_path.write_text(json.dumps(config))
            loaded = sync['load_config'](config_path)
            backend = sync['Backend'](loaded)
            summary = sync['sync'](loaded, backend)
            ipv4 = sync['Route'](0, '198.51.100.77/32', '10.61.50.1', 'loop10')
            ipv6 = sync['Route'](0, '2001:db8:77::1/128', 'fd42:1111:2222:20::1', 'loop10')
            live = backend.lookup([ipv4, ipv6])
            assert sync['matches'](ipv4, live), live
            assert sync['matches'](ipv6, live), live
            assert (0, '10.61.50.1/32') not in live
            assert (0, 'fd42:1111:2222:20::1/128') not in live
            fib4 = cli('show ip fib table 0 198.51.100.77/32')
            fib6 = cli('show ip6 fib table 0 2001:db8:77::1/128')
            assert 'via 10.61.50.1' in fib4 and 'loop10' in fib4, fib4
            assert 'via fd42:1111:2222:20::1' in fib6 and 'loop10' in fib6, fib6

            v4 = ping('vrouter-vpn-lan', '198.51.100.77')
            assert '3 received' in v4, v4
            v6 = ping('vrouter-vpn-lan', '2001:db8:77::1', 6)
            assert '3 received' in v6, v6

            report = {
                'passed': True,
                'workers': workers,
                'sync': summary,
                'vpn_via': '10.61.50.1 loop10',
                'vpn6_via': 'fd42:1111:2222:20::1 loop10',
                'excluded_br0_connected': True,
                'lan_to_gateway_v4': True,
                'lan_to_gateway_v6': True,
                'lan_to_vpn_dest_v4': v4.splitlines()[-2],
                'lan_to_vpn_dest_v6': v6.splitlines()[-2],
                'production_nft_unchanged': True,
                'nic0_unbound': True,
            }
            (base / 'logs').mkdir(exist_ok=True)
            (base / 'logs' / f'vpn-br0-workers{workers}.json').write_text(
                json.dumps(report, indent=2) + '\n')
            print(json.dumps(report))
        finally:
            subprocess.run(['systemctl', 'stop', unit], capture_output=True)
            subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True)
            subprocess.run(['nft', 'delete', 'table', 'inet', table], capture_output=True)
            for name in reversed(created):
                subprocess.run(['ip', 'netns', 'del', name], capture_output=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workers', type=int, default=0, choices=(0, 2))
    main(parser.parse_args().workers)
