#!/usr/bin/env python3
"""Bounded configuration-only test in an isolated VPP; no physical NICs."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', choices=('all', 'wg0', 'wg1', 'sg'), default='all')
    parser.add_argument('--egress-config', type=Path, help='Also load a wg1 EI/destination-route fragment')
    args = parser.parse_args()
    base = Path('/opt/vpp-vrouter-migration')
    vpp = Path('/opt/vpp-nic1-test/vpp/bin')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='vpp-wg-check-', dir='/run') as temporary:
        root = Path(temporary)
        plugins = ['wireguard_plugin.so']
        if args.egress_config:
            if args.interface not in ('all', 'wg1'):
                raise RuntimeError('Egress validation requires wg1')
            plugins += ['nat44_ei_plugin.so', 'nat_ei_context_plugin.so', 'wg_nat_order_plugin.so',
                        'mss_clamp_plugin.so', 'acl_plugin.so', 'dhcp_plugin.so']
        config = root / 'startup.conf'
        config.write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
plugins {{ path {base}/plugins
plugin default {{ disable }}
{chr(10).join('plugin ' + name + ' { enable }' for name in plugins)}
}}
''')
        env = dict(os.environ, LD_LIBRARY_PATH='/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:'
                   '/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu')
        def cli(command):
            result = subprocess.run([str(vpp / 'vppctl'), '-s', str(root / 'cli.sock'), command],
                                    capture_output=True, text=True, timeout=10, env=env)
            if result.returncode or re.search(
                    r'error|failed|unknown|invalid|already|not found|not exist|unimplemented',
                    result.stdout + result.stderr, re.I):
                safe = re.sub(r'[A-Za-z0-9+/]{43}=', '<key>', result.stdout + result.stderr)
                raise RuntimeError('VPP configuration check failed: ' + safe[:1500])
            return result.stdout
        with (root / 'vpp.log').open('w') as log:
            process = subprocess.Popen([str(vpp / 'vpp'), '-c', str(config)], env=env,
                                       stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('Isolated VPP exited during startup')
                    if (root / 'cli.sock').exists():
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('Isolated VPP startup timeout')
                expected = {}
                if args.egress_config:
                    cli('nat44 ei plugin enable sessions 4096')
                for source, name in (('wg0', 'wg0'), ('wg1', 'wg1'), ('sg', 'wg8')):
                    if args.interface not in ('all', source):
                        continue
                    path = base / 'private-wireguard' / (source + '.conf')
                    expected[name] = path.read_text().count('wireguard peer add ')
                    # Keep key material out of argv and identify a failed line
                    # without printing the protected configuration.
                    for index, line in enumerate(path.read_text().splitlines(), 1):
                        single = root / 'command.conf'
                        single.write_text(line + '\n')
                        try:
                            cli('exec ' + str(single))
                        except RuntimeError as error:
                            raise RuntimeError(f'{source} configuration line {index}: {error}') from None
                interfaces = cli('show interface address')
                peers = cli('show wireguard peer')
                actual = {name: len(re.findall(r'\] ' + name + r'\s', peers)) for name in expected}
                if actual != expected or any(name + ' (up):' not in interfaces for name in expected):
                    raise RuntimeError('Loaded WireGuard interfaces or peer counts differ')
                if args.egress_config:
                    cli('exec ' + str(args.egress_config))
                    for prefix in ('10.65.0.0/16', '10.61.70.0/24'):
                        if 'wg1' not in cli('show ip fib table 0 ' + prefix):
                            raise RuntimeError('Production VPN destination route was not installed')
                result = {'configuration_load_passed': True, 'peers': actual,
                          'handshake_tested': False, 'physical_nics_used': False,
                          'egress_fragment_loaded': bool(args.egress_config),
                          'wg1': 'dedicated TAP endpoint; production proxy handshake not tested'}
                (base / ('logs/wireguard-config-check-' + args.interface + '.json')).write_text(
                    json.dumps(result, indent=2) + '\n')
                print(json.dumps(result))
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == '__main__':
    main()
