#!/usr/bin/env python3
"""Render an isolated native VPP WireGuard interface; never apply host hooks."""
import argparse
import ipaddress
import json
import re
import os
from pathlib import Path
import runpy
import sys


def render(source, instance, source_address, helpers, client_helpers, endpoint=None):
    # The server parser uses canonical wg-quick field spelling.
    names = {name.lower(): name for name in (
        'PrivateKey', 'Address', 'ListenPort', 'MTU', 'PublicKey',
        'PresharedKey', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive')}
    text = source.read_text()
    client = source.stem == 'wg1'
    if client:
        interface, peer = client_helpers['parse'](text, helpers['key'])
        peers = [peer]
        private = interface['privatekey']
        if endpoint:
            host, port = endpoint.rsplit(':', 1)
            peer['ip'], peer['port'] = str(ipaddress.IPv4Address(host)), int(port)
        if ipaddress.ip_address(peer['ip']).is_loopback or not 1 <= peer['port'] <= 65535:
            raise RuntimeError('VPP cannot reach the Linux loopback proxy; specify a reachable --endpoint')
    else:
        normalized = []
        for raw in text.splitlines():
            line = raw.split('#', 1)[0].strip()
            if '=' in line:
                name, value = map(str.strip, line.split('=', 1))
                line = names.get(name.lower(), name) + ' = ' + value
            normalized.append(line)
        interface, peers = helpers['parse']('\n'.join(normalized))
        private = interface['PrivateKey']
        if endpoint:
            raise RuntimeError('--endpoint is only supported for wg1')
    name = 'wg' + str(instance)
    lines = [f'wireguard create instance {instance} listen-port {interface["port"]} '
             f'private-key {private} src {ipaddress.IPv4Address(source_address)}',
             f'set interface mtu packet {interface["mtu"]} {name}']
    lines += [f'set interface ip address {name} {address}' for address in interface['addresses']]
    for peer in peers:
        public = peer['publickey' if client else 'PublicKey']
        psk = peer.get('presharedkey' if client else 'PresharedKey')
        host = peer['ip' if client else 'endpoint']
        port = peer['port' if client else 'endpoint_port']
        line = f'wireguard peer add {name} public-key {public}'
        if psk:
            line += ' preshared-key ' + psk
        line += f' endpoint {host} dst-port {port}'
        line += ''.join(f' allowed-ip {network}' for network in peer['networks'])
        line += f' persistent-keepalive {peer["keepalive"]}'
        lines.append(line)
        if not client:
            lines += [f'ip route add {network} via {network.network_address} {name}'
                      for network in peer['networks']]
    lines.append(f'set interface state {name} up')
    return lines, len(peers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--instance', type=int, required=True)
    parser.add_argument('--source-address', required=True)
    parser.add_argument('--endpoint', help='Explicit reachable IPv4:port for wg1 proxy migration')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--nat66-policy', type=Path, help='Export static wg0 fd42:1111:2222:90::/64 /128 peers for PD NAT66')
    args = parser.parse_args()
    if not 0 <= args.instance < 0xffffffff:
        raise RuntimeError('Invalid VPP interface instance')
    scripts = Path(__file__).resolve().parent.parent
    helpers = runpy.run_path(str(scripts / 'import-wireguard.py'))
    client = runpy.run_path(str(scripts / 'import-wireguard-client.py'))
    lines, peers = render(args.source, args.instance, args.source_address, helpers, client, args.endpoint)
    if args.nat66_policy:
        if args.instance != 0 or args.source.stem != 'wg0':
            raise RuntimeError('NAT66 policy export is restricted to wg0')
        addresses = set()
        for line in lines:
            if not line.startswith('wireguard peer add wg0 '):
                continue
            for value in re.findall(r' allowed-ip (\S+)', line):
                network = ipaddress.ip_network(value)
                if network.version == 6 and network.subnet_of(ipaddress.ip_network('fd42:1111:2222:90::/64')):
                    if network.prefixlen != 128:
                        raise RuntimeError('NAT66 requires individual fd42:1111:2222:90::/64 peer /128 addresses')
                    addresses.add(str(network.network_address))
        policy = dict(interface='wg0', peers=sorted(addresses), state_file='/run/vrouter-pd-sync/wg0-nat66.json')
    helpers['export_config'](lines, args.output)
    if args.nat66_policy:
        args.nat66_policy.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.nat66_policy.with_suffix('.tmp')
        temporary.write_text(json.dumps(policy, indent=2)+'\n')
        temporary.chmod(0o600)
        temporary.replace(args.nat66_policy)
    print(f'{args.source.stem} -> wg{args.instance}: {peers} peers; no NAT, host hooks or default routes applied')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main()
    except Exception as error:
        print('WireGuard rendering failed: ' + (str(error) if isinstance(error, RuntimeError)
                                                else type(error).__name__), file=sys.stderr)
        sys.exit(1)
