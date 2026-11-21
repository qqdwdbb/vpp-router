#!/usr/bin/env python3
"""Isolated real sing-box TPROXY test: opaque payload -> SOCKS domain, restart."""
import argparse
import importlib.util
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import time


def exact(sock, length):
    data = b''
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


def mock(path):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            version, count = exact(self.request, 2)
            assert version == 5 and 0 in exact(self.request, count)
            self.request.sendall(b'\x05\x00')
            assert exact(self.request, 4) == b'\x05\x01\x00\x03'
            domain = exact(self.request, exact(self.request, 1)[0]).decode()
            port = struct.unpack('!H', exact(self.request, 2))[0]
            with path.open('a') as out:
                out.write(json.dumps([domain, port]) + '\n')
            self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
            self.request.sendall(exact(self.request, 12))
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
    with Server(('127.0.0.1', 1080), Handler) as server:
        server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('fakeip_prepare',
        Path(__file__).resolve().parents[2] / 'deploy/fakeip/prepare.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    proxy, client = 'vpp-fake-proxy', 'vpp-fake-client'
    created, children = [], []
    def run(*cmd):
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=15)
    def ns(name, *cmd):
        return run('ip', 'netns', 'exec', name, *cmd)
    with tempfile.TemporaryDirectory(prefix='vpp-fakeip-test-') as tmp:
        root = Path(tmp)
        log = (root / 'process.log').open('w+')
        def spawn(name, *cmd):
            child = subprocess.Popen(['ip', 'netns', 'exec', name, *cmd], stdout=log, stderr=log)
            children.append(child)
            return child
        try:
            for name in (proxy, client):
                run('ip', 'netns', 'add', name)
                created.append(name)
                ns(name, 'ip', 'link', 'set', 'lo', 'up')
            ns(proxy, 'ip', 'link', 'add', 'fake-in', 'type', 'veth', 'peer', 'name', 'fake-out')
            ns(proxy, 'ip', 'link', 'set', 'fake-out', 'netns', client)
            for name, dev, addr in ((proxy, 'fake-in', '10.254.239.1/24'),
                                    (client, 'fake-out', '10.254.239.2/24')):
                ns(name, 'ip', 'addr', 'add', addr, 'dev', dev)
                ns(name, 'ip', 'link', 'set', dev, 'up')
                ns(name, 'ip', '-6', 'addr', 'add',
                   'fd00:239::1/64' if name == proxy else 'fd00:239::2/64', 'dev', dev, 'nodad')
            ns(client, 'ip', 'route', 'add', 'default', 'via', '10.254.239.1')
            ns(client, 'ip', '-6', 'route', 'add', 'default', 'via', 'fd00:239::1')
            for family, prefix in (('-4', '0.0.0.0/0'), ('-6', '::/0')):
                ns(proxy, 'ip', family, 'rule', 'add', 'fwmark', '1', 'lookup', '100')
                ns(proxy, 'ip', family, 'route', 'add', 'local', prefix, 'dev', 'lo', 'table', '100')
            rules = ('table inet fake_test { chain in { type filter hook prerouting priority mangle; '
                     'policy accept; iifname "fake-in" meta l4proto tcp '
                     'tproxy to :2082 meta mark set 1 accept; }; }\n')
            subprocess.run(['ip', 'netns', 'exec', proxy, 'nft', '-f', '-'],
                           input=rules, text=True, check=True)
            cfg = module.frontend({'type': 'socks', 'tag': 'test-socks',
                                   'server': '127.0.0.1', 'server_port': 1080},
                                  legacy_listeners=False)
            cfg['experimental']['cache_file']['path'] = str(root / 'cache.db')
            path = root / 'sing-box.json'
            path.write_text(json.dumps(cfg))
            targets = root / 'targets.jsonl'
            spawn(proxy, sys.executable, str(Path(__file__).resolve()), '--mock', str(targets))
            box = spawn(proxy, args.binary, 'run', '-c', str(path))
            def dns(kind):
                return ns(proxy, 'dig', '@127.0.0.1', '-p', '5354', 'www.google.com', kind,
                          '+short', '+time=1', '+tries=1').strip()
            for _ in range(30):
                time.sleep(.1)
                if box.poll() is not None:
                    raise RuntimeError((root / 'process.log').read_text())
                try:
                    a = dns('A')
                    if a.startswith('198.'):
                        break
                except subprocess.CalledProcessError:
                    pass
            else:
                raise RuntimeError('Fake DNS did not start')
            aaaa = dns('AAAA')
            assert aaaa.startswith('2001:2:')
            assert not dns('HTTPS')
            probe = ('import socket,sys; s=socket.create_connection((sys.argv[1],443),5); '
                     's.sendall(b"opaque-bytes"); assert s.recv(12)==b"opaque-bytes"')
            ns(client, sys.executable, '-c', probe, a)
            ns(client, sys.executable, '-c', probe, aaaa)
            box.terminate()
            box.wait(timeout=10)
            box = spawn(proxy, args.binary, 'run', '-c', str(path))
            time.sleep(1)
            # Connect using OLD cached addresses, before any post-restart query.
            ns(client, sys.executable, '-c', probe, a)
            ns(client, sys.executable, '-c', probe, aaaa)
            assert dns('A') == a and dns('AAAA') == aaaa
            observed = [json.loads(line) for line in targets.read_text().splitlines()]
            assert observed == [['www.google.com', 443]] * 4, observed
            print(json.dumps({'ipv4': a, 'ipv6': aaaa, 'socks_atyp': 3,
                'opaque_payload_echo': True, 'restart_old_mapping': True,
                'https_no_real_hints': True, 'production_changed': False}))
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=10)
            for name in reversed(created):
                run('ip', 'netns', 'del', name)
            log.close()


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--mock':
        mock(Path(sys.argv[2]))
    else:
        main()
