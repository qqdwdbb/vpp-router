#!/usr/bin/env python3
"""Controlled SOCKS backend and shared DNS TAP IPv4/IPv6 checks."""
import json
from pathlib import Path
import select
import socket
import socketserver
import struct
import sys


def exact(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


def address(sock):
    kind = exact(sock, 1)[0]
    size = {1: 4, 4: 16}[kind]
    return socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6,
                           exact(sock, size)), struct.unpack('!H', exact(sock, 2))[0]


def serve(root):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            sock.settimeout(8)
            try:
                version, count = exact(sock, 2)
                assert version == 5 and 0 in exact(sock, count)
                sock.sendall(b'\x05\x00')
                version, command, reserved = exact(sock, 3)
                target, port = address(sock)
                if command == 1:
                    assert target in ('198.18.100.10', '2001:db8:2080::10') and port == 443
                    sock.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('127.0.0.1') + b'\x00\x00')
                    while True:
                        data = sock.recv(65535)
                        if not data:
                            return
                        sock.sendall(data)
                else:
                    assert command == 3
                    with socket.socket(type=socket.SOCK_DGRAM) as udp:
                        udp.bind(('127.0.0.1', 0))
                        sock.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('127.0.0.1') +
                                     struct.pack('!H', udp.getsockname()[1]))
                        while True:
                            readable, _, _ = select.select([sock, udp], [], [], 8)
                            if not readable or sock in readable:
                                return
                            data, peer = udp.recvfrom(65535)
                            assert data[:3] == b'\x00\x00\x00' and data[3] in (1, 4)
                            size = 4 if data[3] == 1 else 16
                            destination = socket.inet_ntop(socket.AF_INET if size == 4 else socket.AF_INET6,
                                                           data[4:4+size])
                            assert destination in ('198.18.100.10', '2001:db8:2080::10')
                            assert struct.unpack('!H', data[4+size:6+size])[0] == 443
                            udp.sendto(data, peer)
            except (EOFError, ConnectionError, TimeoutError):
                pass
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    with Server(('127.0.0.1', 1080), Handler) as server:
        (root / 'socks-ready').touch()
        server.serve_forever()


PROBE = '''import socket,os,sys,json
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
 with socket.socket(family,kind) as s:
  s.settimeout(5);s.connect((sys.argv[1],443))
  payload=os.urandom(65536 if kind==socket.SOCK_STREAM else 1000)
  s.sendall(payload);received=b''
  while len(received)<len(payload):
   chunk=s.recv(65536)
   assert chunk,'unexpected EOF'
   received+=chunk
  assert received==payload
print(json.dumps({'target':sys.argv[1],'tcp_udp_payload_verified':True}))
'''


def check(root, names, nsrun, cli, spawn, wait_for, config):
    base = Path('/opt/vpp-vrouter-migration/source')
    dns = names[1]
    cli('set interface ip address loop3950 fd76:7070:44::1/64')
    for namespace, device, ip in ((dns, 'br-mgmt', 'fd76:7070:44::2/64'),
                                  (names[0], 'mgmt0', 'fd76:7070:44::100/64')):
        nsrun(namespace, 'ip', '-6', 'address', 'add', ip, 'dev', device, 'nodad')
    defaults = json.loads(nsrun(names[0], 'ip', '-j', '-6', 'route', 'show', 'default'))
    if not defaults:
        nsrun(names[0], 'ip', '-6', 'route', 'replace', 'default', 'via', 'fd76:7070:44::1')
    nsrun(dns, 'nft', '-f', '-', input='table inet mangle { set proxylist { type ipv4_addr; }; set proxylist6 { type ipv6_addr; }; }')
    nsrun(dns, 'python3', str(base / 'deploy/tproxy/setup-shared.py'),
          '--rules-file', str(base / 'deploy/tproxy/shared.nft'))
    # Apply twice to exercise idempotence without duplicating hooks or policy rules.
    nsrun(dns, 'python3', str(base / 'deploy/tproxy/setup-shared.py'),
          '--rules-file', str(base / 'deploy/tproxy/shared.nft'))
    spawn(dns, 'python3', str(base / 'tests/integration/integration_vrouter_shared_tproxy.py'), '--serve', str(root))
    wait_for(lambda: (root / 'socks-ready').exists(), 'SOCKS mock not ready')
    proxy = spawn(dns, '/usr/local/bin/ipt2socks', '-s', '127.0.0.1', '-p', '1080',
                  '-b', '127.0.0.1', '-B', '::1', '-l', '2080', '-j', '2')
    wait_for(lambda: ':2080' in nsrun(dns, 'ss', '-lnut'), 'ipt2socks not ready')
    for setname, via in (('proxylist', '198.18.44.2'), ('proxylist6', 'fd76:7070:44::2')):
        config['mappings'].append({'family': 'inet', 'table': 'mangle', 'set': setname,
                                  'interface': 'loop3950', 'via': via, 'fib_table': 0})
    temporary = root / 'routes-next.json'
    temporary.write_text(json.dumps(config))
    temporary.replace(root / 'routes.json')
    for setname, target, family, prefix in (
            ('proxylist', '198.18.100.10', 'ip', '/32'),
            ('proxylist6', '2001:db8:2080::10', 'ip6', '/128')):
        nsrun(dns, 'nft', 'add', 'element', 'inet', 'mangle', setname, '{', target, '}')
        def installed():
            fib = cli(f'show {family} fib table 0 {target}{prefix}')
            return target + prefix in fib and 'loop3950' in fib
        wait_for(installed,
                 'nft member did not become shared TAP route')
        try:
            nsrun(names[0], 'python3', '-c', PROBE, target)
        except RuntimeError:
            print('PROXY TARGET', target, cli(f'show {family} fib table 0 {target}{prefix}'), flush=True)
            for namespace in (names[0], dns):
                print(namespace, nsrun(namespace, 'ip', '-6', 'route', 'show'),
                      nsrun(namespace, 'ip', '-6', 'neigh', 'show'), flush=True)
            raise
    assert proxy.poll() is None
    rules = json.loads(nsrun(dns, 'nft', '-j', 'list', 'chain', 'inet', 'mangle', 'vpp_tproxy_shared'))
    counters = [expr['counter']['packets'] for item in rules['nftables'] if 'rule' in item
                for expr in item['rule']['expr'] if 'counter' in expr]
    assert len(counters) == 2 and all(value > 0 for value in counters), counters
    guard = json.loads(nsrun(dns, 'nft', '-j', 'list', 'chain', 'inet', 'mangle', 'vpp_tproxy_shared_guard'))
    assert all(expr['counter']['packets'] == 0 for item in guard['nftables'] if 'rule' in item
               for expr in item['rule']['expr'] if 'counter' in expr)
    return {'shared_dns_tap': True, 'ipv4_ipv6_tcp_udp': True,
            'nft_to_binary_api_routes': True, 'setup_idempotent': True,
            'tproxy_packets': counters, 'forward_leak_packets': 0}


if __name__ == '__main__':
    assert sys.argv[1] == '--serve'
    serve(Path(sys.argv[2]))
