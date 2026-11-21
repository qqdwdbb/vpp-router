#!/usr/bin/env python3
"""VROUTER/root: shared client key on two VPP interfaces, real Linux handshakes."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError('Test command failed: ' + args[0])
    return result.stdout


def test(same_local_key, workers):
    base = Path('/opt/vpp-vrouter-migration')
    namespace = 'wg-key-scope-test'
    assert namespace not in run('ip', 'netns', 'list')
    process = None
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='vpp-wg-key-', dir=base / 'wireguard-interface-peer') as directory:
        root = Path(directory)
        try:
            run('ip', 'netns', 'add', namespace)
            run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
            (root / 'bin').mkdir()
            shutil.copy2('/opt/vpp-nic1-test/vpp/bin/vpp', root / 'bin/vpp')
            shutil.copytree(base / 'crypto_engines', root / 'lib/aarch64-linux-gnu/vpp_crypto_engines')
            plugins = root / 'plugins'
            plugins.mkdir()
            for name in ('tap_plugin.so', 'ping_plugin.so'):
                shutil.copy2(base / 'plugins' / name, plugins / name)
            shutil.copy2(base / 'wireguard-interface-peer/wireguard_plugin.so', plugins / 'wireguard_plugin.so')
            startup = root / 'startup.conf'
            startup.write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
{'cpu { main-core 4 corelist-workers 5-6 }' if workers else ''}
plugins {{ path {plugins}
plugin default {{ disable }}
plugin wireguard_plugin.so {{ enable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
}}
''')
            env = dict(os.environ, LD_LIBRARY_PATH='/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:'
                       '/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu')
            def cli(command):
                result = subprocess.run(['/opt/vpp-nic1-test/vpp/bin/vppctl', '-s',
                                         str(root / 'cli.sock'), command], env=env,
                                        capture_output=True, text=True, timeout=10)
                if result.returncode:
                    raise RuntimeError('VPP CLI transport failed')
                return result.stdout
            def execute(line, reject=False):
                path = root / 'command.conf'
                path.write_text(line + '\n')
                text = cli('exec ' + str(path))
                failed = bool(re.search(r'error|failed|unknown|invalid|already|not found|not exist', text, re.I))
                if failed != reject:
                    raise RuntimeError('Unexpected VPP CLI result; command/output suppressed')
            with (root / 'vpp.log').open('w') as log:
                process = subprocess.Popen([str(root / 'bin/vpp'), '-c', str(startup)],
                                           env=env, stdout=log, stderr=log)
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('Isolated VPP exited')
                    if (root / 'cli.sock').exists():
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('VPP startup timed out')
                execute(f'create tap id 3900 host-ns {namespace} host-if-name mgmt0 host-ip4-addr 10.253.90.2/24')
                execute('set interface ip address tap3900 10.253.90.1/24')
                execute('set interface state tap3900 up')
                execute('set interface rx-mode tap3900 interrupt')
                private = [run('wg', 'genkey').strip() for _ in range(3)]
                if same_local_key:
                    private[1] = private[0]
                public = [run('wg', 'pubkey', input=key + '\n').strip() for key in private]
                peer_lines = []
                for i in range(2):
                    subnet = 91 + i
                    execute(f'wireguard create instance {i} listen-port {49300+i} private-key {private[i]} src 10.253.90.1')
                    execute(f'set interface ip address wg{i} 10.253.{subnet}.1/24')
                    execute(f'set interface ip address wg{i} fd53:{subnet}::1/64')
                    peer_line = (f'wireguard peer add wg{i} public-key {public[2]} endpoint 0.0.0.0 dst-port 0 '
                                 f'allowed-ip 10.253.{subnet}.2/32 allowed-ip fd53:{subnet}::2/128')
                    peer_lines.append(peer_line)
                    execute(peer_line)
                    execute(f'ip route add 10.253.{subnet}.2/32 via 10.253.{subnet}.2 wg{i}')
                    execute(f'ip route add fd53:{subnet}::2/128 via fd53:{subnet}::2 wg{i}')
                    execute(f'set interface state wg{i} up')
                    run('ip', '-n', namespace, 'link', 'add', f'client{i}', 'type', 'wireguard')
                    path = root / f'client{i}.conf'
                    path.write_text(f'''[Interface]
PrivateKey = {private[2]}
[Peer]
PublicKey = {public[i]}
AllowedIPs = 10.253.{subnet}.1/32, fd53:{subnet}::1/128
Endpoint = 10.253.90.1:{49300+i}
''')
                    run('ip', 'netns', 'exec', namespace, 'wg', 'setconf', f'client{i}', str(path))
                    for address in (f'10.253.{subnet}.2/24', f'fd53:{subnet}::2/64'):
                        run('ip', '-n', namespace, 'address', 'add', address, 'dev', f'client{i}')
                    run('ip', '-n', namespace, 'link', 'set', f'client{i}', 'up')
                def ping(i):
                    for destination in (f'10.253.{91+i}.1', f'fd53:{91+i}::1'):
                        # First packet triggers the handshake; establish before
                        # the measured small functional burst.
                        subprocess.run(['ip', 'netns', 'exec', namespace, 'ping', '-n', '-c', '1',
                                        '-W', '1', destination], capture_output=True, timeout=3)
                        output = run('ip', 'netns', 'exec', namespace, 'ping', '-n', '-c', '5',
                                     '-i', '.1', '-W', '1', destination)
                        if not re.search(r'5 packets transmitted, 5 received', output):
                            raise RuntimeError('Encrypted ping burst lost packets')
                    handshake = run('ip', 'netns', 'exec', namespace, 'wg', 'show',
                                    f'client{i}', 'latest-handshakes').split()
                    if not handshake or int(handshake[-1]) == 0:
                        raise RuntimeError('Linux handshake not established')
                ping(1)
                ping(0)
                for line in peer_lines:
                    execute(line, reject=True)
                def count_peers():
                    return len(re.findall(r'(?m)^\[\d+\] endpoint:', cli('show wireguard peer')))
                if count_peers() != 2:
                    raise RuntimeError('Same-interface duplicate changed peer count')
                # Remove just one VPP peer; the other tunnel must keep working.
                display = cli('show wireguard peer')
                match = re.search(r'(?m)^\[(\d+)\] endpoint:.*?\] wg0\s', display)
                if not match:
                    raise RuntimeError('Cannot identify test peer for deletion')
                execute('wireguard peer remove ' + match[1])
                ping(1)
                run('ip', 'netns', 'exec', namespace, 'wg', 'set', 'client0',
                    'peer', public[0], 'remove')
                run('ip', 'netns', 'exec', namespace, 'wg', 'setconf',
                    'client0', str(root / 'client0.conf'))
                subprocess.run(['ip', 'netns', 'exec', namespace, 'ping', '-n', '-c', '1',
                                '-W', '2', '10.253.91.1'], capture_output=True, timeout=4)
                absent_handshake = run('ip', 'netns', 'exec', namespace, 'wg', 'show',
                                       'client0', 'latest-handshakes').split()
                if not absent_handshake or int(absent_handshake[-1]) != 0:
                    raise RuntimeError('Missing peer incorrectly matched another interface')
                ping(1)
                execute(peer_lines[0])
                if count_peers() != 2:
                    raise RuntimeError('Peer recreation failed')
                # Reset Linux sessions, forcing both initiators to handshake
                # again after the pool slot was reused.
                for i in (0, 1):
                    run('ip', 'netns', 'exec', namespace, 'wg', 'set', f'client{i}',
                        'peer', public[i], 'remove')
                    run('ip', 'netns', 'exec', namespace, 'wg', 'setconf',
                        f'client{i}', str(root / f'client{i}.conf'))
                    ping(i)
                return {'same_local_key': same_local_key, 'workers': workers,
                        'shared_peer_key': True, 'ipv4_ipv6_ping': True,
                        'same_interface_duplicate_rejected': True,
                        'missing_peer_not_matched_on_other_interface': True,
                        'delete_recreate_and_fresh_handshake': True}
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            subprocess.run(['ip', 'netns', 'delete', namespace], capture_output=True, timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, choices=(0, 2), default=0)
    args = parser.parse_args()
    results = [test(same, args.workers) for same in (False, True)]
    path = Path(f'/opt/vpp-vrouter-migration/logs/wireguard-interface-peer-workers{args.workers}.json')
    path.write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results))
