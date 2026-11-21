#!/usr/bin/env python3
"""Import wg1 and explicit destination routes without executing wg-quick hooks."""

import ipaddress
import os
from pathlib import Path
import runpy
import socket
import sys


def parse(text, validate_key):
    interface, peers, section = {}, [], None
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line.lower() == '[interface]':
            if section is not None:
                raise ValueError('Duplicate interface section')
            section = interface
        elif line.lower() == '[peer]':
            section = {}
            peers.append(section)
        elif section is not None and '=' in line:
            name, value = (part.strip() for part in line.split('=', 1))
            name = name.lower()
            if name in section:
                raise ValueError('Duplicate field')
            section[name] = value
        else:
            raise ValueError('Invalid configuration')
    if len(peers) != 1:
        raise ValueError('Client importer requires exactly one peer')
    if set(interface) - {'address', 'listenport', 'privatekey', 'mtu', 'table', 'postup'}:
        raise ValueError('Unsupported interface option')
    peer = peers[0]
    if set(peer) - {'publickey', 'presharedkey', 'allowedips', 'endpoint', 'persistentkeepalive'}:
        raise ValueError('Unsupported peer option')
    validate_key(interface['privatekey'])
    validate_key(peer['publickey'])
    if 'presharedkey' in peer:
        validate_key(peer['presharedkey'])
    interface['addresses'] = [ipaddress.ip_interface(a.strip())
                              for a in interface['address'].split(',')]
    interface['port'] = int(interface['listenport'])
    interface['mtu'] = int(interface.get('mtu', '1420'))
    if not 1 <= interface['port'] <= 65535 or not 1280 <= interface['mtu'] <= 9000:
        raise ValueError('Invalid port or MTU')
    peer['networks'] = [ipaddress.ip_network(n.strip(), strict=True)
                        for n in peer['allowedips'].split(',')]
    peer['keepalive'] = int(peer.get('persistentkeepalive', '0'))
    if not 0 <= peer['keepalive'] <= 65535:
        raise ValueError('Invalid keepalive')
    host, port = peer['endpoint'].rsplit(':', 1)
    peer['port'] = int(port)
    if not 1 <= peer['port'] <= 65535:
        raise ValueError('Invalid endpoint port')
    peer['ip'] = socket.getaddrinfo(host.strip('[]'), peer['port'], socket.AF_INET,
                                   socket.SOCK_DGRAM)[0][4][0]
    # Linux loopback endpoints are not reachable from the VPP network stack.
    peer['ready'] = not ipaddress.IPv4Address(peer['ip']).is_loopback
    return interface, peer


def main():
    helpers = runpy.run_path('/usr/local/sbin/vpp-import-wireguard', run_name='wg_import_helpers')
    command = helpers['command']
    text = Path('/etc/wireguard/wg1.conf').read_text()
    interface, peer = parse(text, helpers['key'])
    route_file = Path('/etc/vpp/wg1-routes.conf')
    route_text = route_file.read_text() if route_file.exists() else ''
    routes = []
    for raw in route_text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        prefix, via = line.split()
        network, gateway = ipaddress.ip_network(prefix, strict=True), ipaddress.ip_address(via)
        if network.prefixlen == 0 or network.version != gateway.version:
            raise ValueError('Default routes and address family mismatches are not allowed')
        if ipaddress.ip_address(peer['ip']) in network:
            raise ValueError('VPN endpoint must not be routed into the tunnel')
        if not any(gateway in a.network for a in interface['addresses']):
            raise ValueError('Gateway must be inside a tunnel interface subnet')
        routes.append((str(network), str(gateway)))
    if '--check' in sys.argv:
        print(f'Validated wg1: {len(interface["addresses"])} addresses, 1 peer; '
              f'endpoint {peer["ip"]}:{peer["port"]}; usable={peer["ready"]}; '
              f'{len(routes)} explicit destination routes')
        return
    if 'wg1' in command(['wg', 'show', 'interfaces']).split():
        raise RuntimeError('Linux wg1 is running; refusing concurrent import')
    if '--export' not in sys.argv or '--source-address' not in sys.argv:
        raise RuntimeError('Use vpp-install-wireguard; converter requires --export and --source-address')
    if not peer['ready']:
        raise RuntimeError('Linux loopback endpoint cannot be used by VPP')
    source_ip = str(ipaddress.IPv4Address(sys.argv[sys.argv.index('--source-address') + 1]))
    lines = [f'wireguard create instance 1 listen-port {interface["port"]} '
             f'private-key {interface["privatekey"]} src {source_ip}',
             f'set interface mtu packet {interface["mtu"]} wg1']
    lines += [f'set interface ip address wg1 {a}' for a in interface['addresses']]
    add_peer = f'wireguard peer add wg1 public-key {peer["publickey"]}'
    if 'presharedkey' in peer:
        add_peer += ' preshared-key ' + peer['presharedkey']
    add_peer += f' endpoint {peer["ip"]} dst-port {peer["port"]}'
    add_peer += ''.join(f' allowed-ip {n}' for n in peer['networks'])
    add_peer += f' persistent-keepalive {peer["keepalive"]}'
    lines.append(add_peer)
    if peer['ready']:
        lines += [f'nat44 ei add identity mapping external host-vpp-wan udp {interface["port"]}',
                  'set interface state wg1 up',
                  'set interface nat44 ei out wg1 output-feature',
                  'nat44 ei context wg1 loop101',
                  'set interface tcp-mss-clamp wg1 ip4 disable ip6 disable',
                  f'set interface tcp-mss-clamp wg1 ip4 enable ip4-mss {interface["mtu"] - 40} ip6 disable']
        nat_pool = next((str(a.ip) for a in interface['addresses'] if a.version == 4), None)
        if nat_pool:
            lines.append(f'nat44 ei add address {nat_pool} tenant-vrf 101')
        lines += [f'ip route add {n} via {g} wg1' for n, g in routes]
    helpers['export_config'](lines, sys.argv[sys.argv.index('--export') + 1])


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception as error:
        print('WireGuard client import failed: ' + (str(error) if isinstance(error, RuntimeError)
                                                   else type(error).__name__), file=sys.stderr)
        sys.exit(1)
