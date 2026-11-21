#!/usr/bin/env python3
"""VROUTER/root: VPP WG client -> root TAP/DNAT -> loopback relay -> Linux WG."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import time

from integration_wireguard_interface_peer import run


def main(workers, nat_egress=False):
    base = Path('/opt/vpp-vrouter-migration')
    host, server, table = 'vrouter-wg-proxy', 'wg-vrouter-proxy', 'vrouter_wg_proxy_test'
    for name in (host, server):
        assert not Path('/sys/class/net', name).exists(), 'Test link already exists'
    assert table not in run('nft', 'list', 'tables'), 'Test table already exists'
    # All host changes are restricted to newly created test devices/table.
    process = None
    stopped = threading.Event()
    relay_thread = None
    counters = {'to_server': 0, 'to_client': 0}
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='proxy-', dir=base / 'wireguard-interface-peer') as directory:
        root = Path(directory)
        try:
            (root / 'bin').mkdir()
            shutil.copy2('/opt/vpp-nic1-test/vpp/bin/vpp', root / 'bin/vpp')
            shutil.copytree(base / 'crypto_engines', root / 'lib/aarch64-linux-gnu/vpp_crypto_engines')
            plugins = root / 'plugins'
            plugins.mkdir()
            plugin_names = ['wireguard_plugin.so', 'tap_plugin.so', 'ping_plugin.so']
            if nat_egress:
                plugin_names += ['nat44_ei_plugin.so', 'nat_ei_context_plugin.so',
                                 'wg_nat_order_plugin.so', 'mss_clamp_plugin.so',
                                 'acl_plugin.so', 'dhcp_plugin.so']
            for name in plugin_names:
                shutil.copy2(base / 'plugins' / name, plugins / name)
            startup = root / 'startup.conf'
            startup.write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
{'cpu { main-core 4 corelist-workers 5-6 }' if workers else ''}
plugins {{ path {plugins}
plugin default {{ disable }}
{chr(10).join('plugin ' + name + ' { enable }' for name in plugin_names)}
}}
''')
            env = dict(os.environ, LD_LIBRARY_PATH='/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:'
                       '/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu')
            def cli(command):
                result = subprocess.run(['/opt/vpp-nic1-test/vpp/bin/vppctl', '-s',
                                         str(root / 'cli.sock'), command], env=env,
                                        capture_output=True, text=True, timeout=10)
                if result.returncode or re.search(r'error|failed|unknown|invalid|already|not found|not exist',
                                                  result.stdout + result.stderr, re.I):
                    raise RuntimeError('Isolated VPP command failed; details suppressed')
                return result.stdout
            def execute(line):
                path = root / 'command.conf'
                path.write_text(line + '\n')
                return cli('exec ' + str(path))
            with (root / 'vpp.log').open('w') as log:
                process = subprocess.Popen([str(root / 'bin/vpp'), '-c', str(startup)],
                                           env=env, stdout=log, stderr=log)
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError('Isolated VPP startup failed')
                    if (root / 'cli.sock').exists():
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('Isolated VPP startup timed out')
                execute(f'create tap id 3901 host-if-name {host} host-ip4-addr 10.253.90.2/30')
                execute('set interface ip address tap3901 10.253.90.1/30')
                execute('set interface state tap3901 up')
                execute('set interface rx-mode tap3901 interrupt')
                run('sysctl', '-w', f'net.ipv4.conf.{host}.route_localnet=1')
                rules = f'''table ip {table} {{
chain prerouting {{
type nat hook prerouting priority dstnat; policy accept;
iifname "{host}" ip saddr 10.253.90.1 ip daddr 10.253.90.2 udp dport 49342 counter dnat to 127.0.0.1:49342
}}
}}
'''
                run('nft', '-f', '-', input=rules)
                private = [run('wg', 'genkey').strip() for _ in range(2)]
                public = [run('wg', 'pubkey', input=key + '\n').strip() for key in private]
                run('ip', 'link', 'add', server, 'type', 'wireguard')
                path = root / 'server.conf'
                path.write_text(f'''[Interface]
PrivateKey = {private[0]}
ListenPort = 49343
[Peer]
PublicKey = {public[1]}
AllowedIPs = 10.253.95.2/32, fd53:95::2/128
''')
                run('wg', 'setconf', server, str(path))
                for address in ('10.253.95.1/24', 'fd53:95::1/64'):
                    run('ip', 'address', 'add', address, 'dev', server)
                run('ip', 'link', 'set', server, 'mtu', '1280', 'up')
                # Emulate the existing gost listener without touching it or
                # using production WG keys, which could roam the real peer.
                incoming = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                with incoming, upstream:
                    incoming.bind(('127.0.0.1', 49342))
                    upstream.connect(('127.0.0.1', 49343))
                    def relay():
                        client = None
                        while not stopped.is_set():
                            ready, _, _ = select.select([incoming, upstream], [], [], .1)
                            for sock in ready:
                                data, address = sock.recvfrom(65535)
                                if sock is incoming:
                                    if address[0] != '10.253.90.1':
                                        continue
                                    client = address
                                    upstream.send(data)
                                    counters['to_server'] += 1
                                elif client:
                                    incoming.sendto(data, client)
                                    counters['to_client'] += 1
                    relay_thread = threading.Thread(target=relay)
                    relay_thread.start()
                    # A new source port avoids reusing a previous run's Linux
                    # conntrack DNAT entry after its temporary table was removed.
                    listen_port = 49152 + os.getpid() % 16000
                    execute(f'wireguard create instance 1 listen-port {listen_port} private-key {private[1]} src 10.253.90.1')
                    execute('set interface ip address wg1 10.253.95.2/24')
                    execute('set interface ip address wg1 fd53:95::2/64')
                    execute('set interface mtu packet 1280 wg1')
                    execute(f'wireguard peer add wg1 public-key {public[0]} endpoint 10.253.90.2 dst-port 49342 '
                            'allowed-ip 0.0.0.0/0 allowed-ip ::/0 persistent-keepalive 1')
                    execute('ip route add 10.253.95.1/32 via 10.253.95.1 wg1')
                    execute('ip route add fd53:95::1/128 via fd53:95::1 wg1')
                    execute('set interface state wg1 up')
                    # Bound the establishment phase separately from assertions.
                    for _ in range(20):
                        handshakes = run('wg', 'show', server, 'latest-handshakes').split()
                        if handshakes and int(handshakes[-1]) > 0:
                            break
                        time.sleep(.25)
                    else:
                        raise RuntimeError('WireGuard through loopback DNAT did not handshake')
                    for destination in ('10.253.95.1', 'fd53:95::1'):
                        text = cli(f'ping {destination} repeat 5 interval 0.1')
                        if not re.search(r'5 sent, 5 received', text):
                            raise RuntimeError('VPP encrypted ping failed')
                    for destination in ('10.253.95.2', 'fd53:95::2'):
                        # IPv6 address DAD may still be finishing at setup.
                        subprocess.run(['ping', '-n', '-I', server, '-c', '1', '-W', '1', destination],
                                       capture_output=True, timeout=3)
                        text = run('ping', '-n', '-I', server, '-c', '5', '-i', '.1', '-W', '1', destination)
                        if not re.search(r'5 packets transmitted, 5 received', text):
                            raise RuntimeError('Linux encrypted ping failed')
                    egress_result = None
                    if nat_egress:
                        from integration_wireguard_nat_egress import EgressCheck
                        with EgressCheck(root, cli, execute, server, table, workers) as check:
                            egress_result = check.verify()
                    rules = json.loads(run('nft', '-j', 'list', 'table', 'ip', table))
                    hits = [expr['counter']['packets'] for entry in rules['nftables']
                            for expr in entry.get('rule', {}).get('expr', []) if 'counter' in expr]
                    if not hits or sum(hits) == 0 or not all(counters.values()) or not relay_thread.is_alive():
                        raise RuntimeError('DNAT/relay path was not exercised')
                    result = {'workers': workers, 'real_wireguard_handshake': True,
                              'ipv4_ipv6_bidirectional_encrypted_ping': True,
                              'loopback_dnat_packets': sum(hits), 'relay_packets': dict(counters),
                              'production_gost_used': False, 'production_keys_used': False}
                    if egress_result is not None:
                        result['nat_egress'] = egress_result
                    name = 'wireguard-nat-egress' if nat_egress else 'wireguard-loopback-proxy'
                    (base / f'logs/{name}-workers{workers}.json').write_text(
                        json.dumps(result, indent=2) + '\n')
                    print(json.dumps(result))
                    stopped.set()
                    relay_thread.join(timeout=2)
        finally:
            stopped.set()
            if relay_thread is not None:
                relay_thread.join(timeout=2)
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if table in run('nft', 'list', 'tables'):
                run('nft', 'delete', 'table', 'ip', table)
            for name in (server, host):
                if Path('/sys/class/net', name).exists():
                    run('ip', 'link', 'delete', name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, choices=(0, 2), default=0)
    parser.add_argument('--nat-egress', action='store_true')
    args = parser.parse_args()
    main(args.workers, args.nat_egress)
