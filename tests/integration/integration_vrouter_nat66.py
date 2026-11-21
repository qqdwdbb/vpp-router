#!/usr/bin/env python3
"""Actual Linux WireGuard client -> VPP NAT66 -> isolated IPv6 WAN."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
from pathlib import Path
import socket
import sys

from integration_wireguard_interface_peer import run


TARGET = '2001:db8:45::2'
SCRIPT = '/opt/vpp-vrouter-migration/source/tests/integration_vrouter_nat66.py'


def server(role, root):
    if role == 'udp':
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind((TARGET, 49406))
            (root / 'nat66-udp-ready').touch()
            while True:
                data, peer = sock.recvfrom(65535)
                sock.sendto(socket.inet_pton(socket.AF_INET6, peer[0]) + data, peer)
    else:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                data = bytes(range(256))*256
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('X-Source-IP', self.client_address[0])
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *unused):
                pass
        class Server(HTTPServer):
            address_family = socket.AF_INET6
        with Server((TARGET, 49407), Handler) as http:
            (root / 'nat66-tcp-ready').touch()
            http.serve_forever()


UDP = '''import socket,json,sys
with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as s:
 s.settimeout(4)
 if sys.argv[1]!='auto':s.bind((sys.argv[1],0))
 s.connect(('2001:db8:45::2',49406));data=bytes(range(256))*4
 s.send(data);answer=s.recv(8192)
 assert answer[16:]==data
 source=socket.inet_ntop(socket.AF_INET6,answer[:16]);assert source==sys.argv[2],source
print(json.dumps(source))
'''
TCP = '''import http.client,sys
c=http.client.HTTPConnection('2001:db8:45::2',49407,timeout=5,source_address=(sys.argv[1],0))
c.request('GET','/');r=c.getresponse();assert r.status==200
assert r.getheader('X-Source-IP')==sys.argv[2]
assert r.read()==bytes(range(256))*256;c.close()
'''


class Check:
    def __init__(self, root, names, created, cli, spawn, nsrun, wait_for):
        self.root, self.names, self.cli = root, names, cli
        self.spawn, self.nsrun, self.wait_for = spawn, nsrun, wait_for
        self.namespace = 'vrouter-wg-nat66'
        assert self.namespace not in run('ip', 'netns', 'list')
        run('ip', 'netns', 'add', self.namespace)
        created.append(self.namespace)
        run('ip', '-n', self.namespace, 'link', 'set', 'lo', 'up')
        for command in (
                f'create tap id 3953 host-ns {self.namespace} host-if-name mgmt0 host-ip4-addr 198.18.46.2/24',
                'set interface ip address tap3953 198.18.46.1/24',
                'set interface state tap3953 up', 'set interface rx-mode tap3953 interrupt'):
            cli(command)
        private = [run('wg', 'genkey').strip() for _ in range(2)]
        public = [run('wg', 'pubkey', input=value+'\n').strip() for value in private]
        cli(f'wireguard create instance 0 listen-port 49919 private-key {private[0]} src 198.18.46.1')
        for command in ('set interface ip address wg0 fd42:1111:2222:90::1/64',
                        'set interface mtu packet 1280 wg0', 'set interface state wg0 up'):
            cli(command)
        cli(f'wireguard peer add wg0 public-key {public[1]} endpoint 0.0.0.0 dst-port 0 '
            'allowed-ip fd42:1111:2222:90::2/128 allowed-ip fd42:1111:2222:90::3/128 persistent-keepalive 1')
        for address in ('fd42:1111:2222:90::2', 'fd42:1111:2222:90::3'):
            cli(f'ip route add {address}/128 via {address} wg0')
        self.nsrun(self.namespace, 'ip', 'link', 'add', 'wg-client', 'type', 'wireguard')
        config = root / 'nat66-client.conf'
        config.write_text(f'''[Interface]
PrivateKey = {private[1]}
[Peer]
PublicKey = {public[0]}
Endpoint = 198.18.46.1:49919
AllowedIPs = ::/0
PersistentKeepalive = 1
''')
        self.nsrun(self.namespace, 'wg', 'setconf', 'wg-client', str(config))
        for address in ('fd42:1111:2222:90::2/64', 'fd42:1111:2222:90::3/64'):
            self.nsrun(self.namespace, 'ip', '-6', 'address', 'add', address, 'dev', 'wg-client', 'nodad')
        self.nsrun(self.namespace, 'ip', 'link', 'set', 'wg-client', 'mtu', '1280', 'up')
        self.nsrun(self.namespace, 'ip', '-6', 'route', 'add', 'default', 'dev', 'wg-client')
        for command in ('nat66 plugin enable', 'set interface nat66 in wg0',
                        'set interface nat66 out tap3952',
                        'nat66 add static mapping local fd42:1111:2222:70::9 external 2001:db8:999::9'):
            cli(command)
        self.policy_file = root / 'nat66-policy.json'
        self.policy_file.write_text(json.dumps({'interface': 'wg0', 'peers': ['fd42:1111:2222:90::2', 'fd42:1111:2222:90::3'],
                                               'state_file': str(root / 'nat66-state.json')}))
        self.serving = False
        self.prefixes = []

    def mappings(self):
        return self.cli('show nat66 static mappings')

    def verify(self, prefix, lan_source):
        if not self.serving:
            for role in ('udp', 'tcp'):
                self.spawn(self.names[2], 'python3', SCRIPT, '--server', role, '--root', str(self.root))
            self.wait_for(lambda: all((self.root/f'nat66-{role}-ready').exists() for role in ('udp', 'tcp')),
                          'NAT66 WAN servers not ready')
            self.serving = True
        # Establish the real encrypted tunnel independently of the translated path.
        self.nsrun(self.namespace, 'ping', '-6', '-n', '-c', '2', '-W', '2', 'fd42:1111:2222:90::1')
        assert int(self.nsrun(self.namespace, 'wg', 'show', 'wg-client', 'latest-handshakes').split()[-1]) > 0
        network = ipaddress.IPv6Network(prefix)
        observed = []
        for ident in (2, 3):
            local = f'fd42:1111:2222:90::{ident}'
            external = str(ipaddress.IPv6Address(int(network.network_address)+(0x66 << 48)+ident))
            self.wait_for(lambda: external in self.mappings(), 'PD NAT66 mapping not installed')
            self.nsrun(self.namespace, 'ping', '-6', '-n', '-I', local, '-c', '3', '-W', '2', TARGET)
            self.nsrun(self.namespace, 'python3', '-c', UDP, local, external)
            self.nsrun(self.namespace, 'python3', '-c', TCP, local, external)
            observed.append(external)
        # LAN is not a NAT66 inside interface: preserve its public SLAAC source.
        self.nsrun(self.names[0], 'python3', '-c', UDP, lan_source, lan_source)
        assert 'local fd42:1111:2222:70::9 external 2001:db8:999::9' in self.mappings()
        self.prefixes.append(prefix)
        return observed

    def withdrawn(self):
        self.wait_for(lambda: 'local fd42:1111:2222:90::2 ' not in self.mappings() and 'local fd42:1111:2222:90::3 ' not in self.mappings(),
                      'Withdrawn PD NAT66 mappings remain')
        assert 'local fd42:1111:2222:70::9 external 2001:db8:999::9' in self.mappings()

    def result(self):
        return {'real_wireguard_handshake': True, 'ipv6_icmp_udp_tcp': True,
                'tcp_64k_integrity': True, 'two_peer_addresses': True,
                'prefixes': self.prefixes, 'native_lan_source_preserved': True,
                'unowned_mapping_preserved': True, 'pd_withdrawal_and_recovery': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', choices=('udp', 'tcp'), required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    server(args.server, args.root)
