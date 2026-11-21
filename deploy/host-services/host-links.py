#!/usr/bin/env python3
"""Prepare site-owned Linux links and return paths from a declarative JSON file."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess

def run(*args, check=True):
    p = subprocess.run([str(a) for a in args], check=check, capture_output=True, text=True, timeout=20)
    return p.stdout

def name(value):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', value):
        raise ValueError('invalid Linux interface')
    return value

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    for link in config.get('links', []):
        interface = name(link['interface'])
        run('ip', 'link', 'set', interface, 'up')
        if link.get('mac'):
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', link['mac']):
                raise ValueError('invalid MAC address')
            run('ip', 'link', 'set', interface, 'address', link['mac'])
        if link.get('master'):
            run('ip', 'link', 'set', interface, 'master', name(link['master']))
        if link.get('mtu'):
            run('ip', 'link', 'set', interface, 'mtu', int(link['mtu']))
        for address in link.get('addresses', []):
            run('ip', 'address', 'replace', address, 'dev', interface)
        for key, value in link.get('sysctls', {}).items():
            if key not in ('route_localnet', 'rp_filter', 'accept_ra', 'autoconf'):
                raise ValueError('unsupported interface sysctl')
            run('sysctl', '-qw', f'net.ipv{6 if key in ("accept_ra","autoconf") else 4}.conf.{interface}.{key}={int(value)}')
    for route in config.get('routes', []):
        run('ip', '-6' if ':' in route['prefix'] else '-4', 'route', 'replace',
            route['prefix'], 'via', route['via'], 'dev', name(route['interface']))
    if config.get('wg_proxy_nft'):
        run('nft', '-f', config['wg_proxy_nft'])
    for policy in config.get('nft_files', []):
        run('nft', '-f', policy)
    for flow in config.get('clear_conntrack', []):
        run('conntrack', '-D', '-p', 'udp', '--orig-src', flow['source'],
            '--orig-dst', flow['destination'], '--dport', str(int(flow['port'])), check=False)
    services = config.get('services_config')
    if services:
        settings = json.loads(Path(services).read_text())
        spec = importlib.util.spec_from_file_location('host_routing', Path(__file__).with_name('host-routing.py'))
        routing = importlib.util.module_from_spec(spec); spec.loader.exec_module(routing)
        routing.install(settings, run, Path(config['routing_state']))
    if config.get('direct_dns_route'):
        route = config['direct_dns_route']
        run('ip', 'route', 'replace', route['prefix'], 'via', route['via'], 'dev', name(route['interface']), 'src', route['source'])

if __name__ == '__main__':
    main()
