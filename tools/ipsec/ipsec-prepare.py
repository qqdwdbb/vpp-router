#!/usr/bin/env python3
"""Prepare isolated strongSwan IKE sockets without changing root WAN routes."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time


def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if p.returncode:
        raise RuntimeError('Command failed: ' + args[0])
    return p.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace-only', action='store_true')
    parser.add_argument('--check-ready', action='store_true')
    args = parser.parse_args()
    if args.check_ready:
        for unused in range(25):
            result = subprocess.run(
                ['ip', 'netns', 'exec', 'vpp-ipsec', 'ipsec', 'statusall'],
                capture_output=True, text=True, timeout=5)
            if re.search(r'loaded plugins:.*\bkernel-vpp\b', result.stdout) and all(
                    re.search(r'(?m)^\s*' + name + r':', result.stdout)
                    for name in ('cert', 'eap-mschapv2')):
                print('strongSwan ready with VPP backend and both connection profiles')
                return
            time.sleep(1)
        raise RuntimeError('strongSwan VPP backend or connection profiles are not ready')
    namespaces = run('ip', 'netns', 'list')
    if not re.search(r'(?m)^vpp-ipsec(?:\s|$)', namespaces):
        run('ip', 'netns', 'add', 'vpp-ipsec')
    if args.namespace_only:
        return
    resolver = Path('/etc/netns/vpp-ipsec/resolv.conf')
    resolver.parent.mkdir(parents=True, exist_ok=True)
    resolver.write_text('nameserver 223.5.5.5\nnameserver 1.1.1.1\n')
    for unused in range(65):
        display = run('vppctl', 'show interface address')
        wan = re.search(r'(?ms)^host-vpp-wan \(up\):\s*(.*?)(?=^\S+ \((?:up|dn)\):|\Z)', display)
        addresses = re.findall(r'L3 (\S+)', wan[1]) if wan else []
        ip4 = next((str(ipaddress.ip_interface(a).ip) for a in addresses if ipaddress.ip_interface(a).version == 4), None)
        if ip4 and subprocess.run(['ip', '-n', 'vpp-ipsec', 'link', 'show', 'host-vpp-wan'],capture_output=True).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('VPP WAN DHCP or IPsec TAP is not ready')
    run('ip', '-n', 'vpp-ipsec', 'link', 'set', 'lo', 'up')
    run('ip', '-n', 'vpp-ipsec', 'link', 'set', 'host-vpp-wan', 'up')
    run('ip', 'netns', 'exec', 'vpp-ipsec', 'sysctl', '-qw',
        'net.ipv6.conf.host-vpp-wan.accept_ra=0', 'net.ipv6.conf.host-vpp-wan.autoconf=0')
    run('ip', '-n', 'vpp-ipsec', 'addr', 'replace', ip4 + '/32', 'dev', 'host-vpp-wan')
    # IKE binds the WAN alias explicitly. Other control-plane connections need
    # the transit source so their replies are routed back to the namespace.
    run('ip', '-n', 'vpp-ipsec', 'route', 'replace', 'default', 'via', '10.63.40.1', 'dev', 'host-vpp-wan', 'src', '10.63.40.2')
    for address in addresses:
        addr = ipaddress.ip_interface(address).ip
        if addr.version == 6 and addr.is_global:
            run('ip', '-n', 'vpp-ipsec', '-6', 'addr', 'replace', str(addr) + '/128', 'dev', 'host-vpp-wan')
            run('ip', '-n', 'vpp-ipsec', '-6', 'route', 'replace', 'default', 'via', 'fd42:1111:2222:40::1',
                'dev', 'host-vpp-wan', 'src', 'fd42:1111:2222:40::2')
            break
    for network in ('10.62.50.0/24', '10.62.20.0/24'):
        run('ip', '-4', 'route', 'replace', network, 'via', '10.61.30.1', 'dev', 'br-vpp-lan')
    run('/usr/local/sbin/vpp-ipsec-prefix-sync', '--once')
    print('Isolated strongSwan IKE namespace ready; IPsec SA backend is VPP')


if __name__ == '__main__':
    main()
