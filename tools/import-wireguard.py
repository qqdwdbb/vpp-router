#!/usr/bin/env python3
"""Convert wg0.conf to VPP CLI; shared protected CLI helpers for installation."""

import base64
import ipaddress
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile

SOURCE = Path('/etc/wireguard/wg0.conf')
WAN = 'host-vpp-wan'


def key(value):
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError()
    except (ValueError, base64.binascii.Error):
        raise ValueError('Invalid WireGuard key; value suppressed') from None
    return value


def parse(text):
    interface, peers, current = {}, [], None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line == '[Interface]':
            if current is not None:
                raise ValueError('Interface must appear once, before peers')
            current = interface
        elif line == '[Peer]':
            current = {}
            peers.append(current)
        elif current is not None and '=' in line:
            name, value = (part.strip() for part in line.split('=', 1))
            if name in current:
                raise ValueError('Duplicate configuration field: ' + name)
            current[name] = value
        else:
            raise ValueError('Invalid configuration line; content suppressed')
    unsupported = set(interface) - {'PrivateKey', 'Address', 'ListenPort', 'MTU'}
    if unsupported:
        raise ValueError('Unsupported Interface options: ' + ', '.join(sorted(unsupported)))
    key(interface['PrivateKey'])
    interface['addresses'] = [ipaddress.ip_interface(a.strip())
                              for a in interface['Address'].split(',')]
    interface['port'] = int(interface['ListenPort'])
    interface['mtu'] = int(interface.get('MTU', '1420'))
    if not 1 <= interface['port'] <= 65535 or not 1280 <= interface['mtu'] <= 9000:
        raise ValueError('Invalid ListenPort or MTU')
    seen_keys, seen_addresses = set(), set()
    for peer in peers:
        unsupported = set(peer) - {'PublicKey', 'PresharedKey', 'AllowedIPs',
                                   'Endpoint', 'PersistentKeepalive'}
        if unsupported:
            raise ValueError('Unsupported Peer options: ' + ', '.join(sorted(unsupported)))
        public = key(peer['PublicKey'])
        if public in seen_keys:
            raise ValueError('Duplicate peer public key; value suppressed')
        seen_keys.add(public)
        if 'PresharedKey' in peer:
            key(peer['PresharedKey'])
        peer['networks'] = [ipaddress.ip_network(a.strip(), strict=True)
                            for a in peer['AllowedIPs'].split(',')]
        for network in peer['networks']:
            # This server's peers are road-warrior host addresses, not site routes.
            if network.prefixlen != network.max_prefixlen:
                raise ValueError('This importer requires peer /32 or /128 host routes')
            if str(network) in seen_addresses:
                raise ValueError('Duplicate allowed tunnel address')
            if any(network.network_address == a.ip for a in interface['addresses']):
                raise ValueError('Peer tunnel address conflicts with server')
            seen_addresses.add(str(network))
        peer['keepalive'] = int(peer.get('PersistentKeepalive', '0'))
        if not 0 <= peer['keepalive'] <= 65535:
            raise ValueError('Invalid keepalive')
        peer['endpoint'], peer['endpoint_port'] = '0.0.0.0', 0
        if 'Endpoint' in peer:
            host, port = peer['Endpoint'].rsplit(':', 1)
            host = host.strip('[]')
            address = socket.getaddrinfo(host, int(port), socket.AF_INET,
                                         socket.SOCK_DGRAM)[0][4][0]
            if not 1 <= int(port) <= 65535:
                raise ValueError('Invalid endpoint port')
            peer['endpoint'], peer['endpoint_port'] = address, int(port)
    return interface, peers


def command(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Command failed: ' + args[0] + '; details suppressed')
    return result.stdout


def cli(line):
    return command(['vppctl', line])



def identity_cleanup(interface, port, addresses):
    """A DHCP address/pool change may already have removed this mapping."""
    display = cli('show nat44 ei static mappings')
    placeholder = re.search(r'\bexternal ' + re.escape(interface) + ':' + str(port) + r'\b', display)
    active = any(re.search(r'identity mapping udp ' + re.escape(ip) + ':' + str(port) + r'\b', display, re.I)
                 for ip in addresses if ip)
    return [f'nat44 ei add identity mapping external {interface} udp {port} del'] if placeholder or active else []


def peer_cleanup(interface):
    # Remove peers explicitly before deleting the interface: VPP can otherwise
    # leave a peer behind, preventing a subsequent import of its public key.
    display = cli('show wireguard peer')
    return [f'wireguard peer remove {index}' for index in re.findall(
        r'(?m)^\[(\d+)\] endpoint:.*?\] ' + re.escape(interface) + r'\s', display)]


def export_config(lines, destination):
    path = Path(destination)
    if path.exists():
        raise RuntimeError('Export destination already exists; refusing to overwrite')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('\n'.join(lines) + '\n')
    print('Exported static VPP configuration: ' + str(path))


def execute(lines):
    # vppctl argv and the top-level CLI log contain only the protected file path.
    fd, name = tempfile.mkstemp(prefix='wireguard-import-', suffix='.conf', dir='/run/vpp')
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write('\n'.join(lines) + '\n')
        result = cli('exec ' + name)
        if re.search(r'error|failed|unknown|invalid|already|not found|not exist', result, re.I):
            raise RuntimeError('VPP rejected import commands; details suppressed')
    finally:
        os.unlink(name)


def main():
    interface, peers = parse(SOURCE.read_text())
    if '--check' in sys.argv:
        print(f'Validated {len(interface["addresses"])} interface addresses and {len(peers)} peers')
        return
    if 'wg0' in command(['wg', 'show', 'interfaces']).split():
        raise RuntimeError('Linux wg0 is running; stop it before migration')
    if '--export' not in sys.argv or '--source-address' not in sys.argv:
        raise RuntimeError('Use vpp-install-wireguard; converter requires --export and --source-address')
    source_ip = str(ipaddress.IPv4Address(sys.argv[sys.argv.index('--source-address') + 1]))
    lines = [
        f'wireguard create instance 0 listen-port {interface["port"]} '
        f'private-key {interface["PrivateKey"]} src {source_ip}',
        f'set interface mtu packet {interface["mtu"]} wg0',
    ]
    for address in interface['addresses']:
        lines.append(f'set interface ip address wg0 {address}')
    for peer in peers:
        line = f'wireguard peer add wg0 public-key {peer["PublicKey"]}'
        if 'PresharedKey' in peer:
            line += ' preshared-key ' + peer['PresharedKey']
        line += f' endpoint {peer["endpoint"]} dst-port {peer["endpoint_port"]}'
        line += ''.join(f' allowed-ip {n}' for n in peer['networks'])
        line += f' persistent-keepalive {peer["keepalive"]}'
        lines.append(line)
        for network in peer['networks']:
            lines.append(f'ip route add {network} via {network.network_address} wg0')
    lines += [f'nat44 ei add identity mapping external {WAN} udp {interface["port"]}',
              'set interface state wg0 up']
    export_config(lines, sys.argv[sys.argv.index('--export') + 1])


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception as error:
        # Some parser/library exceptions echo key material or source lines.
        print('WireGuard import failed: ' + (str(error) if isinstance(error, RuntimeError)
                                            else type(error).__name__), file=sys.stderr)
        sys.exit(1)
