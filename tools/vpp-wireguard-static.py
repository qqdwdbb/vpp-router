#!/usr/bin/env python3
"""Load explicit VPP WireGuard CLI files; never monitor Linux configs or WAN."""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import sys
import time


def describe(text, interface):
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    instance = int(interface[2:])
    create = [line for line in lines if line.startswith('wireguard create ')]
    if len(create) != 1 or not re.search(r'\binstance ' + str(instance) + r'\b', create[0]):
        raise RuntimeError('Static file must create exactly the selected WireGuard interface')
    port = re.search(r'\blisten-port (\d+)\b', create[0])
    source = re.search(r'\bsrc (\S+)', create[0])
    if not port or not source:
        raise RuntimeError('Static interface creation requires explicit listen-port and src')
    addresses = []
    for line in lines:
        match = re.fullmatch(r'set interface ip address ' + interface + r' (\S+)', line)
        if match:
            addresses.append(str(ipaddress.ip_interface(match[1])))
    routes = [line.replace('ip route add ', 'ip route del ', 1)
              for line in lines if line.startswith('ip route add ') and line.endswith(' ' + interface)]
    return lines, {'port': int(port[1]), 'source': str(ipaddress.ip_address(source[1])),
                   'addresses': addresses, 'route_cleanup': routes}


def host_routes(helpers, addresses):
    for network in sorted({str(ipaddress.ip_interface(a).network) for a in addresses}):
        ipv6 = ipaddress.ip_network(network).version == 6
        gateway = 'fe80::76:70ff:fe70:801' if ipv6 else '10.61.30.1'
        helpers['command'](['ip', '-6' if ipv6 else '-4', 'route', 'replace', network,
                            'via', gateway, 'dev', 'br-vpp-lan'])


def load(interface, helpers, directory=Path('/etc/vpp/wireguard'),
         runtime=Path('/run/vpp'), adopt=False, replace=False):
    text = (directory / (interface + '.conf')).read_text()
    lines, description = describe(text, interface)
    digest = hashlib.sha256(text.encode()).hexdigest()
    generation = helpers['command'](['systemctl', 'show', 'vpp', '-p', 'InvocationID', '--value']).strip()
    state_path = runtime / (interface + '-static.json')
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    exists = bool(re.search(r'^' + interface + r'\s', helpers['cli']('show interface'), re.M))
    same = state.get('generation') == generation
    if exists and not adopt:
        if same and state.get('digest') == digest:
            host_routes(helpers, description['addresses'])
            return
        if not replace or not same:
            raise RuntimeError('Existing interface differs or is unmanaged; use --replace only for a managed interface')
        cleanup = state['route_cleanup'][:]
        route_sync = Path('/usr/local/sbin/vpp-nft-route-sync')
        if route_sync.exists():
            route_helpers = runpy.run_path(str(route_sync), run_name='static_route_helpers')
            cleanup += route_helpers['interface_delete_commands'](interface, generation)
        if interface == 'wg1':
            cleanup += ['nat44 ei context wg1 loop101 del',
                        'set interface nat44 ei out wg1 output-feature del',
                        'set interface tcp-mss-clamp wg1 ip4 disable ip6 disable']
        if interface == 'wg0' and Path('/etc/vpp/wg0-nat66.conf').exists():
            cleanup += ['set interface nat66 in wg0 del']
        cleanup += helpers['peer_cleanup'](interface)
        cleanup += ['wireguard delete ' + interface]
        cleanup += helpers['identity_cleanup']('host-vpp-wan', state['port'], (state['source'],))
        helpers['execute'](cleanup)
    elif adopt and not exists:
        raise RuntimeError('Cannot adopt an absent interface')
    if adopt:
        peers = helpers['cli']('show wireguard peer')
        expected = re.findall(r'(?m)^wireguard peer add ' + interface + r' public-key (\S+)', text)
        blocks = re.split(r'(?m)(?=^\[\d+\] endpoint:)', peers)
        actual = [block for block in blocks if re.search(r'\] ' + interface + r'\s', block)]
        if len(actual) != len(expected) or any(not any(key in block for block in actual) for key in expected):
            raise RuntimeError('Cannot adopt: live peers do not match static configuration')
        addresses = helpers['cli']('show interface address')
        block = re.search(r'(?ms)^' + interface + r' \(up\):\s*(.*?)(?=^\S+ \((?:up|dn)\):|\Z)', addresses)
        if not block or any('L3 ' + address not in block[1] for address in description['addresses']):
            raise RuntimeError('Cannot adopt: live interface addresses differ')
    if not adopt:
        # NAT pools are managed by vpp-egress-nat; avoid adding an existing pool
        # when explicitly replacing wg1. All other static commands are unchanged.
        pools = helpers['cli']('show nat44 ei addresses')
        lines = [line for line in lines if not (
            (match := re.fullmatch(r'nat44 ei add address (\S+) tenant-vrf (?:0|101)', line))
            and re.search(r'(?m)^' + re.escape(match[1]) + r'\s*$', pools))]
        helpers['execute'](lines)
        if interface == 'wg0' and Path('/etc/vpp/wg0-nat66.conf').exists():
            helpers['execute'](['set interface nat66 in wg0'])
    if not re.search(r'(?m)^' + interface + r' \(up\):', helpers['cli']('show interface address')):
        raise RuntimeError('Static WireGuard interface is not up')
    host_routes(helpers, description['addresses'])
    temporary = state_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(dict(description, digest=digest, generation=generation)))
    temporary.chmod(0o600)
    temporary.replace(state_path)
    print(interface + ': static configuration ' + ('adopted' if adopt else 'loaded'))


def main():
    os.umask(0o077)
    if len(sys.argv) < 2 or sys.argv[1] not in ('wg0', 'wg1'):
        raise RuntimeError('Usage: vpp-wireguard-static wg0|wg1 [--replace|--adopt]')
    interface = sys.argv[1]
    suffix = '-client' if interface == 'wg1' else ''
    helpers = runpy.run_path('/usr/local/sbin/vpp-import-wireguard', run_name='static_helpers')
    with open('/run/lock/vpp-wireguard' + suffix + '-import.lock', 'a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        lock.seek(0)
        lock.truncate()
        lock.write(str(time.time_ns()) + '\n')
        lock.flush()
        load(interface, helpers, adopt='--adopt' in sys.argv, replace='--replace' in sys.argv)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # VPP files contain private keys: never print parser or subprocess data.
        print('Static WireGuard load failed; configuration details suppressed', file=sys.stderr)
        sys.exit(1)
