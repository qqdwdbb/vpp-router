#!/usr/bin/env python3
"""Capture/check Linux recovery state without changing networking or reading keys."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import subprocess

SERVICES = ('networking.service', 'dhcpcd.service', 'dhcpcd-prefix-refresh.service',
            'dnsmasq.service', 'strongswan-starter.service', 'gost-tunnel.service', 'miniupnpd.service', 'coturn.service')


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout


def addresses(rows):
    result = {}
    for row in rows:
        values = []
        for address in row.get('addr_info', []):
            ip = ipaddress.ip_address(address['local'])
            # Delegated GUA, RA routes and link-local addresses must be relearned.
            if ip.version == 4 or ip in ipaddress.ip_network('fc00::/7') or ip.is_loopback:
                values.append(f"{ip}/{address['prefixlen']}")
        result[row['ifname']] = sorted(values)
    return result


def firewall_policy(document):
    """Keep ordered policy, ignoring handles, dynamic set elements and counters."""
    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items()
                    if key not in ('handle', 'packets', 'bytes', 'elem')}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    return [clean(item) for item in document.get('nftables', [])
            if 'metainfo' not in item and 'element' not in item]


def capture():
    links = json.loads(command('ip', '-j', '-d', 'link', 'show'))
    index = {row['ifindex']: row['ifname'] for row in links}
    state = {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'links': {}, 'addresses': addresses(json.loads(command('ip', '-j', 'addr', 'show'))),
             'services': {}, 'drivers': {}}
    for row in links:
        if row['ifname'] not in ('mgmt0', 'nic1', 'nic0', 'lan', 'wan', 'vps', 'br0', 'tap0', 'tap1', 'wg0', 'wg1', 'sg', 'nebula'):
            continue
        info = row.get('linkinfo', {})
        state['links'][row['ifname']] = {
            'mac': row.get('address'), 'mtu': row['mtu'], 'up': 'UP' in row.get('flags', []),
            'master': row.get('master'), 'kind': info.get('info_kind'),
            'vlan_id': info.get('info_data', {}).get('id') if info.get('info_kind') == 'vlan' else None,
            'parent': index.get(row.get('link_index'))}
    for family in ('4', '6'):
        state['rules'+family] = json.loads(command('ip', '-j', '-'+family, 'rule', 'show'))
        state['routes'+family] = json.loads(command('ip', '-j', '-'+family, 'route', 'show', 'table', 'all'))
    for unit in SERVICES:
        p = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=5)
        state['services'][unit] = p.stdout.strip()
    for name in ('nic1', 'nic0'):
        driver = Path('/sys/class/net')/name/'device/driver'
        state['drivers'][name] = driver.resolve().name if driver.is_symlink() else None
    state['firewall'] = firewall_policy(json.loads(command('nft', '-j', 'list', 'ruleset')))
    return state


def compare(expected, actual):
    errors = []
    for category in ('drivers', 'links'):
        for name, value in expected[category].items():
            if actual[category].get(name) != value:
                errors.append(f'{category}: {name} differs')
    for name, values in expected['addresses'].items():
        if not set(values).issubset(actual['addresses'].get(name, [])):
            errors.append(f'addresses: {name} missing static address')
    for family in ('4', '6'):
        if expected['rules'+family] != actual['rules'+family]:
            errors.append(f'IPv{family} policy rules differ')
        def static_routes(rows):
            fields = ('type', 'dst', 'gateway', 'dev', 'table', 'metric', 'scope', 'prefsrc', 'mtu')
            return {json.dumps({k: row[k] for k in fields if k in row}, sort_keys=True)
                    for row in rows if row.get('protocol') not in ('kernel', 'ra', 'dhcp')
                    and row.get('table') != 'local' and 'cache' not in row}
        if not static_routes(expected['routes'+family]).issubset(static_routes(actual['routes'+family])):
            errors.append(f'IPv{family} static/policy routes missing or changed')
    if expected.get('firewall') != actual.get('firewall'):
        errors.append('nftables policy differs (counters and dynamic set elements ignored)')
    for unit, status in expected['services'].items():
        if status == 'active' and actual['services'].get(unit) != 'active':
            errors.append(f'service: {unit} is not active')
    if not any(r.get('dst') == 'default' and r.get('dev') == 'wan' and r.get('table', 'main') == 'main'
               for r in actual['routes6']):
        errors.append('IPv6 WAN default route not learned')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('capture', 'check'))
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root; snapshots remain on the router')
    if args.action == 'capture':
        os.umask(0o077)
        args.directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        state = capture()
        rules = command('nft', 'list', 'ruleset')
        (args.directory/'linux-state.json').write_text(json.dumps(state, indent=2)+'\n')
        # One atomic nft transaction restores the captured Linux policy.
        firewall = args.directory/'restore-firewall.nft'
        firewall.write_text('flush ruleset\n'+rules)
        command('nft', '-c', '-f', str(firewall))
        print('Linux baseline and firewall dry-check saved:', args.directory)
    else:
        expected = json.loads((args.directory/'linux-state.json').read_text())
        errors = compare(expected, capture())
        print(json.dumps({'linux_state_matches': not errors, 'differences': errors}, indent=2))
        raise SystemExit(1 if errors else 0)


if __name__ == '__main__':
    main()
