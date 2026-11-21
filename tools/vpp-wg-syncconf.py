#!/usr/bin/env python3
"""Synchronize VPP WireGuard peers without recreating the interface."""

import argparse
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile


STATIC_PATHS = {
    'wg0': Path('/etc/vpp/wg0.vpp'),
    'wg1': Path('/etc/vpp/wg1.vpp'),
}
DEFAULT_SOURCE = Path('/etc/wireguard')
SOURCE_PATHS = {
    'wg0': DEFAULT_SOURCE / 'wg0.conf',
    'wg1': DEFAULT_SOURCE / 'wg1.conf',
}
LOCKS = {
    'wg0': Path('/run/lock/vpp-wireguard-import.lock'),
    'wg1': Path('/run/lock/vpp-wireguard-client-import.lock'),
}
VPPCTL = '/usr/local/bin/vppctl'


def key(value):
    import base64
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError()
    except (ValueError, base64.binascii.Error):
        raise ValueError('Invalid WireGuard key') from None
    return value


def resolve_endpoint(host, port):
    return socket.getaddrinfo(host.strip('[]'), port,
                              socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]


def parse_wireguard(text, interface, endpoint_resolver=None):
    config, peers, section = {}, [], None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line.lower() == '[interface]':
            if section is not None:
                raise ValueError('Duplicate interface section')
            section = config
        elif line.lower() == '[peer]':
            section = {}
            peers.append(section)
        elif section is not None and '=' in line:
            name, value = (part.strip() for part in line.split('=', 1))
            name = name.lower()
            if name in section:
                raise ValueError('Duplicate configuration field')
            section[name] = value
        else:
            raise ValueError('Invalid configuration line')
    if section is None or not config:
        raise ValueError('Missing interface configuration')

    allowed_interface = {'privatekey', 'address', 'listenport', 'mtu'}
    if interface != 'wg0':
        allowed_interface |= {'table', 'postup'}
    if set(config) - allowed_interface:
        raise ValueError('Unsupported interface option')
    key(config['privatekey'])
    addresses = [ipaddress.ip_interface(value.strip())
                 for value in config['address'].split(',')]
    port = int(config.get('listenport', '0'))
    mtu = int(config.get('mtu', '1420'))
    if not 1 <= port <= 65535 or not 1280 <= mtu <= 9000:
        raise ValueError('Invalid interface port or MTU')

    seen_keys, seen_addresses = set(), set()
    normalized = []
    for peer in peers:
        allowed = {'publickey', 'presharedkey', 'allowedips', 'endpoint',
                   'persistentkeepalive'}
        if set(peer) - allowed:
            raise ValueError('Unsupported peer option')
        public = key(peer['publickey'])
        if public in seen_keys:
            raise ValueError('Duplicate peer public key')
        seen_keys.add(public)
        psk = key(peer['presharedkey']) if 'presharedkey' in peer else None
        networks = [ipaddress.ip_network(value.strip(), strict=True)
                    for value in peer['allowedips'].split(',')]
        for network in networks:
            if interface == 'wg0' and network.prefixlen != network.max_prefixlen:
                raise ValueError('wg0 requires host allowed IPs')
            if str(network) in seen_addresses:
                raise ValueError('Duplicate allowed tunnel address')
            if any(network.network_address == address.ip for address in addresses):
                raise ValueError('Peer address conflicts with interface')
            seen_addresses.add(str(network))
        keepalive = int(peer.get('persistentkeepalive', '0'))
        if not 0 <= keepalive <= 65535:
            raise ValueError('Invalid keepalive')

        endpoint, endpoint_port = '0.0.0.0', 0
        if 'endpoint' in peer:
            host, port_text = peer['endpoint'].rsplit(':', 1)
            endpoint_port = int(port_text)
            if not 1 <= endpoint_port <= 65535:
                raise ValueError('Invalid endpoint port')
            endpoint = (endpoint_resolver(host, endpoint_port, public)
                        if endpoint_resolver else resolve_endpoint(host, endpoint_port))
        elif interface != 'wg0':
            raise ValueError(interface + ' requires an endpoint')
        normalized.append({
            'public_key': public,
            'preshared_key': psk,
            'endpoint': endpoint,
            'port': endpoint_port,
            'allowed': tuple(sorted(str(network) for network in networks)),
            'keepalive': keepalive,
        })
    return {
        'private_key': config['privatekey'],
        'port': port,
        'mtu': mtu,
        'addresses': tuple(sorted(str(address) for address in addresses)),
    }, normalized


def parse_source(interface, path, endpoint_resolver=None):
    return parse_wireguard(path.read_text(), interface, endpoint_resolver)


def cli(line):
    result = subprocess.run([VPPCTL, line], capture_output=True, text=True,
                            timeout=20)
    if result.returncode:
        raise RuntimeError('VPP CLI command failed')
    return result.stdout


def execute(lines):
    fd, name = tempfile.mkstemp(prefix='wireguard-syncconf-', suffix='.conf',
                                 dir='/run/vpp')
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write('\n'.join(lines) + '\n')
        output = cli('exec ' + name)
        if re.search(r'error|failed|unknown|invalid|already|not found|not exist',
                     output, re.I):
            raise RuntimeError('VPP rejected peer synchronization')
    finally:
        Path(name).unlink(missing_ok=True)


def parse_vpp_peer(tokens):
    def value(name):
        try:
            return tokens[tokens.index(name) + 1]
        except (ValueError, IndexError):
            raise RuntimeError('Invalid installed peer configuration') from None

    allowed = []
    for index, token in enumerate(tokens):
        if token == 'allowed-ip':
            try:
                allowed.append(str(ipaddress.ip_network(tokens[index + 1], strict=True)))
            except (IndexError, ValueError):
                raise RuntimeError('Invalid installed peer allowed IP') from None
    if not allowed:
        raise RuntimeError('Installed peer has no allowed IP')
    return {
        'public_key': value('public-key'),
        'preshared_key': value('preshared-key') if 'preshared-key' in tokens else None,
        'endpoint': str(ipaddress.ip_address(value('endpoint'))),
        'port': int(value('dst-port')),
        'allowed': tuple(sorted(allowed)),
        'keepalive': int(value('persistent-keepalive')),
    }


def parse_static(interface, path):
    lines = [line.strip() for line in path.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    create = None
    mtu = None
    addresses = []
    peers = {}
    for line in lines:
        tokens = shlex.split(line)
        if tokens[:2] == ['wireguard', 'create']:
            if create is not None:
                raise RuntimeError('Multiple WireGuard create commands')
            create = tokens
        elif tokens[:4] == ['set', 'interface', 'mtu', 'packet'] and len(tokens) == 6 \
                and tokens[5] == interface:
            mtu = int(tokens[4])
        elif tokens[:4] == ['set', 'interface', 'ip', 'address'] and len(tokens) == 6 \
                and tokens[4] == interface:
            addresses.append(str(ipaddress.ip_interface(tokens[5])))
        elif tokens[:3] == ['wireguard', 'peer', 'add'] and len(tokens) >= 4 \
                and tokens[3] == interface:
            peer = parse_vpp_peer(tokens)
            if peer['public_key'] in peers:
                raise RuntimeError('Duplicate installed peer')
            peers[peer['public_key']] = peer
    if create is None or mtu is None:
        raise RuntimeError('Installed static configuration is incomplete')
    try:
        private_key = create[create.index('private-key') + 1]
        port = int(create[create.index('listen-port') + 1])
        source = str(ipaddress.ip_address(create[create.index('src') + 1]))
    except (ValueError, IndexError):
        raise RuntimeError('Installed create command is incomplete') from None
    return {
        'private_key': private_key,
        'port': port,
        'mtu': mtu,
        'source': source,
        'addresses': tuple(sorted(addresses)),
    }, peers, lines


def peer_command(interface, peer):
    line = 'wireguard peer add ' + interface + ' public-key ' + peer['public_key']
    if peer['preshared_key']:
        line += ' preshared-key ' + peer['preshared_key']
    line += ' endpoint ' + peer['endpoint'] + ' dst-port ' + str(peer['port'])
    line += ''.join(' allowed-ip ' + network for network in peer['allowed'])
    return line + ' persistent-keepalive ' + str(peer['keepalive'])


def route_commands(interface, peer, action):
    if interface != 'wg0':
        return []
    commands = []
    for value in peer['allowed']:
        network = ipaddress.ip_network(value, strict=True)
        commands.append('ip route ' + action + ' ' + str(network) +
                        ' via ' + str(network.network_address) + ' ' + interface)
    return commands


def live_peer_indices(display, interface):
    result = {}
    blocks = re.split(r'(?m)(?=^\[\d+\] endpoint:)', display)
    for block in blocks:
        header = re.match(r'^\[(\d+)\] endpoint:.*\]\s+(\S+)\s', block)
        if not header or header[2] != interface:
            continue
        key = re.search(r'(?m)^\s*public key:\s*([A-Za-z0-9+/]{43}=)', block)
        if not key:
            raise RuntimeError('Cannot read a live WireGuard peer key')
        if key[1] in result:
            raise RuntimeError('Duplicate live WireGuard peer key')
        result[key[1]] = int(header[1])
    return result


def interface_changed(desired, installed):
    fields = ('private_key', 'port', 'mtu', 'addresses')
    return [field for field in fields if desired[field] != installed[field]]


def plan(interface, desired, installed, live):
    old = installed[1]
    new = {peer['public_key']: peer for peer in desired[1]}
    if set(live) != set(old):
        raise RuntimeError('Live peers differ from the installed VPP configuration')

    remove = set(old) - set(new)
    add = set(new) - set(old)
    replace = {key for key in set(old) & set(new) if old[key] != new[key]}
    remove |= replace
    add |= replace

    commands = []
    for key in sorted(remove, key=lambda value: live[value]):
        commands.extend(route_commands(interface, old[key], 'del'))
        commands.append('wireguard peer remove ' + str(live[key]))
    for key in sorted(add):
        commands.append(peer_command(interface, new[key]))
        commands.extend(route_commands(interface, new[key], 'add'))
    return commands, len(add), len(remove), new


def persisted_lines(interface, installed_lines, peers):
    peer_prefix = 'wireguard peer add ' + interface + ' '
    old_routes = set()
    for peer in peers.values():
        old_routes.update(route_commands(interface, peer, 'add'))
    base = [line for line in installed_lines
            if not line.startswith(peer_prefix) and line not in old_routes]
    insert_at = next((index for index, line in enumerate(base)
                      if line.startswith(('nat44 ', 'set interface state '))), len(base))
    generated = []
    for key in sorted(peers):
        generated.append(peer_command(interface, peers[key]))
        generated.extend(route_commands(interface, peers[key], 'add'))
    return base[:insert_at] + generated + base[insert_at:]


def atomic_write(path, lines):
    temporary = path.with_name(path.name + '.syncconf')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write('\n'.join(lines) + '\n')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def sync(interface, source, dry_run=False):
    static_path = STATIC_PATHS[interface]
    installed_config, installed_peers, installed_lines = parse_static(interface, static_path)
    parser_config, desired_peers = parse_source(interface, source)
    changed = interface_changed(parser_config, installed_config)
    if changed:
        raise RuntimeError('Interface fields changed (' + ', '.join(changed) +
                           '); use vpp-install-wireguard for an interface change')
    if interface != 'wg0':
        for peer in desired_peers:
            installed = installed_peers.get(peer['public_key'])
            if (installed and peer['endpoint'] != installed['endpoint'] and
                    ipaddress.ip_address(peer['endpoint']).is_loopback):
                raise RuntimeError('wg1 source endpoint is loopback; use the reachable VPP proxy endpoint')

    live = live_peer_indices(cli('show wireguard peer'), interface)
    commands, added, removed, new_peers = plan(
        interface, (parser_config, desired_peers),
        (installed_config, installed_peers), live)
    if not commands:
        print(interface + ': no peer changes')
        return
    if dry_run:
        print(interface + ': would add/update ' + str(added) +
              ' peer(s), remove ' + str(removed) + ' peer(s)')
        return

    execute(commands)
    live_after = live_peer_indices(cli('show wireguard peer'), interface)
    if set(live_after) != set(new_peers):
        raise RuntimeError('Live peer set did not match the synchronized configuration')
    atomic_write(static_path, persisted_lines(interface, installed_lines, new_peers))
    print(interface + ': synchronized ' + str(added) +
          ' added/updated, ' + str(removed) + ' removed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('interface', choices=('wg0', 'wg1'))
    parser.add_argument('config', nargs='?', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    source = args.config or SOURCE_PATHS[args.interface]
    if not source.is_file():
        raise RuntimeError('Configuration file does not exist')
    with LOCKS[args.interface].open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        sync(args.interface, source, args.dry_run)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception as error:
        print('WireGuard syncconf failed: ' +
              (str(error) if isinstance(error, RuntimeError) else type(error).__name__),
              file=sys.stderr)
        sys.exit(1)
