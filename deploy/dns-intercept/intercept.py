#!/usr/bin/python3
"""Steer client TCP/UDP DNS to Linux before destination/source routing.

The dns-intercept VPP plugin selects LAN TCP/UDP to port 53 and looks it up in
table 530/531, whose default route points at the Linux DNS address."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import socket
import time

VPPCTL = os.environ.get('VROUTER_VPPCTL', '/usr/local/bin/vppctl')
INTERFACES = ('loop200',)
POLICIES = ((4, 530), (6, 531))  # ABF policies of the previous design
TABLES = {4: 530, 6: 531}
VIA = {4: '10.61.20.2', 6: 'fd42:1111:2222:10::2'}
OLD4 = ('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '114.114.114.114')
OLD6 = ('2606:4700:4700::1111', '2606:4700:4700::1001',
        '2001:4860:4860::8888', '2001:4860:4860::8844', '2620:fe::fe', '2620:fe::9')


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=15)


def cli(command):
    out = run(VPPCTL, command)
    if re.search(r'unknown|failed|invalid|error:|already|not found|not exist', out, re.I):
        raise RuntimeError(command + ': ' + out)
    return out


def local_addresses():
    addresses = {4: set(), 6: set()}
    for interface in json.loads(run('ip', '-j', 'address', 'show')):
        for address in interface.get('addr_info', []):
            ip = ipaddress.ip_address(address['local'])
            if not ip.is_loopback and not ip.is_link_local:
                addresses[ip.version].add(str(ip))
    # Configured bind addresses must be exempt even during host setup.
    addresses[4].add('10.61.20.2')
    addresses[6].add('fd42:1111:2222:10::2')
    return addresses


def client_prefixes():
    result = {4: ['10.61.20.0/24'], 6: ['fd42:1111:2222:10::/64']}
    path = Path('/run/vrouter-pd-sync/state.json')
    if path.exists():
        value = json.loads(path.read_text()).get('pool_prefix')
        if value:
            network = ipaddress.ip_network(value)
            if network.version != 6 or network.prefixlen != 64 or not network.is_global:
                raise ValueError('Invalid LAN delegated prefix')
            result[6].append(str(network))
    return result


def update_nft_sources(prefixes):
    values = ', '.join(prefixes[6])
    text = ('flush set inet vrouter_dns_route_gate lan6_sources\n'
            f'add element inet vrouter_dns_route_gate lan6_sources {{ {values} }}\n')
    subprocess.run(['nft', '-f', '-'], input=text, text=True, check=True, timeout=15)


def intercept_command(version, addresses, prefixes, interface):
    width = 32 if version == 4 else 128
    # Link-local/multicast DNS is not routed off-link.
    destinations = ('224.0.0.0/4', '255.255.255.255/32') if version == 4 else ('ff00::/8', 'fe80::/10')
    words = [f'dns intercept {interface} ip{version} table {TABLES[version]} port 53']
    words += [f'src {prefix}' for prefix in prefixes]
    words += [f'exempt-src {ip}/{width}' for ip in sorted(addresses)]
    words += [f'exempt-dst {dst}' for dst in destinations]
    return ' '.join(words)


def retire_abf(version, policy):
    """Remove the ABF policy and ACL this helper used before dns-intercept."""
    if not re.search(rf'policy:{policy}\b', cli('show abf policy')):
        return
    for interface in INTERFACES:
        if re.search(rf'policy:{policy} priority:', cli('show abf attach ' + interface)):
            cli(f'abf attach ip{version} del policy {policy} {interface}')
    cli(f'abf policy del id {policy} via {VIA[version]} loop200')
    old = re.search(r'(?m)^acl-index\s+(\d+)\s+count\s+\d+\s+tag \{vrouter-dns-intercept'
                    + str(version) + r'\}', cli('show acl-plugin acl'))
    if old:
        cli(f'delete acl-plugin acl index {old[1]}')


def apply(addresses, prefixes):
    for version, policy in POLICIES:
        table = TABLES[version]
        for interface in INTERFACES:
            # Creates and locks the table, then replaces the whole selection.
            cli(intercept_command(version, addresses[version], prefixes[version], interface))
        anynet = '0.0.0.0/0' if version == 4 else '::/0'
        route = cli(f'show ip{"6" if version == 6 else ""} fib table {table} {anynet}')
        if f'{VIA[version]} loop200' not in route:
            cli(f'ip route add {anynet} table {table} via {VIA[version]} loop200')
        retire_abf(version, policy)
    # Retire the destination-wide routes installed by older topology hooks.
    # Only remove our exact next-hop path, leaving unrelated routes untouched.
    for version, values in ((4, OLD4), (6, OLD6)):
        width = 32 if version == 4 else 128
        via = VIA[version]
        for ip in values:
            text = cli(f'show ip{version if version == 6 else ""} fib table 0 {ip}')
            if f'{ip}/{width} ' in text and f'{via} loop200' in text:
                cli(f'ip route del {ip}/{width} via {via} loop200')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    previous = None
    ready = False
    while True:
        addresses = local_addresses()
        pid = run('systemctl', 'show', 'vrouter-vpp', '-p', 'MainPID', '--value').strip()
        prefixes = client_prefixes()
        state = (pid, addresses, prefixes)
        if state != previous:
            update_nft_sources(prefixes)
            apply(addresses, prefixes)
            previous = state
            if not ready and os.environ.get('NOTIFY_SOCKET'):
                address = os.environ['NOTIFY_SOCKET']
                if address.startswith('@'):
                    address = '\0' + address[1:]
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                    sock.sendto(b'READY=1', address)
                ready = True
            print('LAN DNS interception active: IPv4/IPv6 TCP/UDP 53; VPN and host upstream exempt', flush=True)
        if args.once:
            return
        time.sleep(1)


if __name__ == '__main__':
    main()
