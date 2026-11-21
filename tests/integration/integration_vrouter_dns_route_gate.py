#!/usr/bin/env python3
"""VROUTER/root: real dnsmasq/nft monitor/Binary API and isolated VPP recovery."""
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import runpy
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

from integration_wireguard_interface_peer import run


def wait_for(predicate, message, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise RuntimeError(message)


def port():
    with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0))
        number = tcp.getsockname()[1]
        udp.bind(('127.0.0.1', number))
        return number


def main():
    base = Path('/opt/vpp-vrouter-migration')
    scripts = base / 'source/scripts'
    unit = 'vrouter-dns-vpp-' + str(os.getpid())
    table = 'vrouter_dns_gate_test'
    assert table not in run('nft', 'list', 'tables')
    os.umask(0o077)
    env = dict(os.environ, PATH='/opt/vpp-nic1-test/vpp/bin:' + os.environ['PATH'],
               LD_LIBRARY_PATH='/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:'
               '/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu',
               PYTHONPATH=str(base / 'runtime/python'),
               VPP_API_DIR='/opt/vpp-nic1-test/vpp/share/vpp/api')
    os.environ.update(env)
    sys.path.insert(0, env['PYTHONPATH'])
    gate_module = runpy.run_path(str(scripts / 'dns-route-gate.py'))
    sync = gate_module['load_sync'](scripts / 'nftset-route-sync.py')
    children = []
    with tempfile.TemporaryDirectory(prefix='vrouter-dns-', dir='/run') as directory, ExitStack() as stack:
        root = Path(directory)
        try:
            def cli(command):
                return run('/opt/vpp-nic1-test/vpp/bin/vppctl', '-s', str(root / 'cli.sock'), command)
            def execute(lines):
                path = root / 'commands.conf'
                path.write_text('\n'.join(lines) + '\n')
                output = cli('exec ' + str(path))
                if any(word in output.lower() for word in ('error', 'failed', 'unknown', 'invalid')):
                    raise RuntimeError('Isolated VPP fixture command failed; output suppressed')
            key = run('wg', 'genkey').strip()
            create = [f'wireguard create instance 1 listen-port 49915 private-key {key} src 192.0.2.250',
                      'set interface ip address wg1 10.62.30.2/24', 'set interface state wg1 up']
            (root / 'interfaces.conf').write_text('\n'.join(create) + '\n')
            (root / 'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock exec {root}/interfaces.conf }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
plugins {{ path {base}/plugins
plugin default {{ disable }}
plugin wireguard_plugin.so {{ enable }}
}}
''')
            run('systemd-run', '--unit=' + unit, '--property=KillMode=control-group',
                '--property=RuntimeMaxSec=150',
                '--setenv=LD_LIBRARY_PATH=' + env['LD_LIBRARY_PATH'],
                '/opt/vpp-nic1-test/vpp/bin/vpp', '-c', str(root / 'startup.conf'))
            def vpp_ready():
                if not (root / 'cli.sock').exists():
                    return False
                try:
                    return 'wg1 (up):' in cli('show interface address')
                except RuntimeError:
                    return False
            wait_for(vpp_ready, 'VPP did not start')
            run('nft', '-f', '-', input=f'table inet {table} {{\nset altroute {{\ntype ipv4_addr;\nflags interval;\n}}\n}}\n')
            rules = root / 'rules'
            rules.mkdir()
            (rules / 'altroute.conf').write_text(f'nftset=/altroute.test/4#inet#{table}#altroute\n')
            mapping = {'family': 'inet', 'table': table, 'set': 'altroute',
                       'interface': 'wg1', 'via': '10.62.30.1', 'fib_table': 0}
            config = {'mappings': [mapping], 'state_file': str(root / 'state.json'),
                      'state_socket': str(root / 'state.sock'), 'vpp_socket': str(root / 'cli.sock'),
                      'api_socket': str(root / 'api.sock'), 'vpp_service': unit,
                      'lock_files': [str(root / 'import.lock')], 'exclude_prefixes': [],
                      'monitor_resync_seconds': 60, 'fib_audit_seconds': 3600, 'interval_seconds': .2}
            config_path = root / 'routes.json'
            config_path.write_text(json.dumps(config))
            backend = sync.Backend(sync.load_config(config_path))
            backend.apply([])
            answers = {'a.altroute.test': '198.51.100.77', 'b.altroute.test': '198.51.100.78',
                       'fail.altroute.test': '198.51.100.79', 'normal.test': '198.51.100.80'}
            def answer(query):
                ident, _, _, _ = gate_module['decode'](query)
                name, end = gate_module['name_at'](query, 12)
                packet = struct.pack('!6H', ident, 0x8180, 1, 1, 0, 0) + query[12:end+4]
                return packet + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(answers[name])
            class Upstream(socketserver.BaseRequestHandler):
                def handle(self):
                    query, sock = self.request
                    sock.sendto(answer(query), self.client_address)
            class TCPUpstream(socketserver.BaseRequestHandler):
                def handle(self):
                    self.request.settimeout(3)
                    size = struct.unpack('!H', gate_module['read_exact'](self.request, 2))[0]
                    packet = answer(gate_module['read_exact'](self.request, size))
                    self.request.sendall(struct.pack('!H', len(packet)) + packet)
            upstream_port = port()
            upstream = stack.enter_context(socketserver.ThreadingUDPServer(('127.0.0.1', upstream_port), Upstream))
            tcp_upstream = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', upstream_port), TCPUpstream))
            threading.Thread(target=upstream.serve_forever, daemon=True).start()
            stack.callback(upstream.shutdown)
            threading.Thread(target=tcp_upstream.serve_forever, daemon=True).start()
            stack.callback(tcp_upstream.shutdown)
            dns_port, gate_port = port(), port()
            (root / 'dnsmasq.conf').write_text(f'''port={dns_port}
listen-address=127.0.0.1
bind-interfaces
no-resolv
no-hosts
cache-size=0
server=127.0.0.1#{upstream.server_address[1]}
conf-file={rules}/altroute.conf
''')
            log = stack.enter_context((root / 'processes.log').open('w+'))
            dnsmasq = subprocess.Popen(['dnsmasq', '--keep-in-foreground', '--user=root',
                                       '--conf-file=' + str(root / 'dnsmasq.conf'),
                                       '--pid-file=' + str(root / 'dnsmasq.pid'), '--log-facility=-'],
                                      env=env, stdout=log, stderr=log)
            children.append(dnsmasq)
            gate_config = {'sync_program': str(scripts / 'nftset-route-sync.py'),
                           'route_config': str(config_path), 'rules_directory': str(rules),
                           'lease_file': str(root / 'seen.json'),
                           'upstream': ['127.0.0.1', dns_port], 'listen': [['127.0.0.1', gate_port]]}
            (root / 'gate.json').write_text(json.dumps(gate_config))
            gate = subprocess.Popen(['python3', str(scripts / 'dns-route-gate.py'),
                                     '--config', str(root / 'gate.json')], env=env, stdout=log, stderr=log)
            children.append(gate)
            def query(name, tcp=False, timeout=4):
                question = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
                packet = struct.pack('!6H', 1234, 0x100, 1, 0, 0, 0) + question + struct.pack('!HH', 1, 1)
                with socket.socket(type=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    sock.connect(('127.0.0.1', gate_port))
                    if tcp:
                        sock.sendall(struct.pack('!H', len(packet)) + packet)
                        length = struct.unpack('!H', gate_module['read_exact'](sock, 2))[0]
                        response = gate_module['read_exact'](sock, length)
                    else:
                        sock.send(packet)
                        response = sock.recv(65535)
                return gate_module['decode'](response)
            def gate_ready():
                if gate.poll() is not None or dnsmasq.poll() is not None:
                    raise RuntimeError('DNS test process exited')
                try:
                    return query('normal.test', timeout=.2)[1] & 15 == 0
                except (OSError, ValueError):
                    return False
            wait_for(gate_ready, 'DNS gate did not start')
            def route(ip):
                return sync.Route(0, ip + '/32', '10.62.30.1', 'wg1')
            def installed(ips):
                routes = [route(ip) for ip in ips]
                try:
                    live = backend.lookup(routes)
                    return all(sync.matches(item, live) for item in routes)
                except Exception:
                    return False
            assert not installed(['198.51.100.80']), 'Unmapped DNS installed a route'
            output, errors = [], []
            def first_query():
                try:
                    output.append(query('a.altroute.test'))
                except Exception as error:
                    errors.append(type(error).__name__)
            with open(config['lock_files'][0], 'a+') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                worker = threading.Thread(target=first_query)
                worker.start()
                wait_for(lambda: '198.51.100.77/32' in backend.prefixes(mapping), 'dnsmasq did not update nftset')
                time.sleep(.2)
                assert not output and not errors, 'DNS escaped before the route barrier'
                fcntl.flock(lock, fcntl.LOCK_UN)
                worker.join(5)
            assert not errors and output and output[0][1] & 15 == 0
            assert installed(['198.51.100.77']), 'Successful DNS preceded route installation'
            assert query('b.altroute.test', tcp=True)[1] & 15 == 0
            assert installed(['198.51.100.78'])
            def add(ip):
                run('nft', 'add', 'element', 'inet', table, 'altroute', '{', ip, '}')
            add('198.51.100.90')
            wait_for(lambda: installed(['198.51.100.90']), 'Direct nft event was not installed')
            def monitor_pid():
                candidates = subprocess.run(['pgrep', '-P', str(gate.pid)],
                                            capture_output=True, text=True).stdout.split()
                for pid in candidates:
                    try:
                        argv = Path('/proc', pid, 'cmdline').read_bytes().split(b'\0')
                        if argv[:4] == [b'nft', b'-j', b'monitor', b'elements']:
                            return int(pid)
                    except FileNotFoundError:
                        pass
                return None
            wait_for(monitor_pid, 'nft monitor child missing')
            old_monitor = monitor_pid()
            os.kill(old_monitor, signal.SIGTERM)
            add('198.51.100.91')
            wait_for(lambda: monitor_pid() not in (None, old_monitor) and installed(['198.51.100.91']),
                     'nft monitor did not reconnect and recover')
            expected = ['198.51.100.77', '198.51.100.78', '198.51.100.90', '198.51.100.91']
            # Reproduce the manual importer's lock + in-memory ledger cleanup.
            # Force a different sw_if_index to catch stale API interface caching.
            with open(config['lock_files'][0], 'a+') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                state = sync.importer_state(config)
                old_index = sync.Backend._interfaces['wg1']
                backend.apply([sync.Route(**item).command('del') for item in state['owned']])
                execute(['wireguard delete wg1', 'create loopback interface instance 299'] + create)
                new_index = next(item.sw_if_index for item in sync.Backend._api_client.api.sw_interface_dump()
                                 if item.interface_name == 'wg1')
                assert old_index != new_index, 'Fixture did not change the WireGuard interface index'
                lock.write('recreated\n')
                lock.flush()
            wait_for(lambda: installed(expected), 'Routes not recovered after interface recreation')
            assert not (root / 'state.json').exists() and not (root / 'seen.json').exists(), 'Runtime state wrote to disk'
            old_generation = backend.generation()
            run('systemctl', 'restart', unit)
            wait_for(vpp_ready, 'VPP restart did not restore interface')
            assert backend.generation() != old_generation
            wait_for(lambda: installed(expected), 'Routes not recovered after VPP restart')
            bad = dict(config, mappings=[dict(mapping, interface='missing-test-interface')])
            replacement = root / 'routes.new'
            replacement.write_text(json.dumps(bad))
            replacement.replace(config_path)
            rejected = query('fail.altroute.test')
            assert rejected[1] & 15 == 2 and not rejected[3], 'Failed route did not produce SERVFAIL'
            replacement.write_text(json.dumps(config))
            replacement.replace(config_path)
            assert query('a.altroute.test')[1] & 15 == 0
            assert not (root / 'state.json').exists() and not (root / 'seen.json').exists()
            gate.terminate()
            gate.wait(timeout=8)
            assert gate.returncode == 0
            assert (root / 'state.json').exists() and (root / 'seen.json').exists(), 'Stop did not persist state'
            result = {'real_binary_api': True, 'dnsmasq_nftset': True,
                      'udp_dns_held_until_route_ack': True, 'tcp_dns': True,
                      'unmapped_dns_no_route': True, 'direct_nft_event': True,
                      'monitor_disconnect_recovery': True, 'interface_recreate_recovery': True,
                      'interface_indices': [old_index, new_index],
                      'vpp_restart_recovery': True, 'route_failure_servfail': True,
                      'memory_state_until_graceful_stop': True, 'production_dns_changed': False}
            (base / 'logs/dns-route-gate-integration.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result))
        except Exception:
            if 'log' in locals():
                log.flush()
                text = (root / 'processes.log').read_text()
                print(text[-5000:], flush=True)
            raise
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
            if sync.Backend._api_client is not None:
                sync.Backend._api_client.disconnect()
            subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=20)
            if table in run('nft', 'list', 'tables'):
                run('nft', 'delete', 'table', 'inet', table)


if __name__ == '__main__':
    main()
