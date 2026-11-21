#!/usr/bin/env python3
"""Reconcile one NAPT66 policy against the live VPP WAN IPv6 address."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess


def interfaces(display):
    result = {}
    current = None
    for line in display.splitlines():
        match = re.match(r'^(\S+) \((up|dn)\):', line)
        if match:
            current = match[1] if match[2] == 'up' else None
            if current:
                result[current] = []
        elif current:
            match = re.match(r'\s+L3 (\S+)', line)
            if match:
                address = ipaddress.ip_interface(match[1]).ip
                if address.version == 6 and address in ipaddress.ip_network('2000::/3'):
                    result[current].append(str(address))
    return result


def reconcile(config, old, generation, cli):
    present = interfaces(cli('show interface address'))
    policies = config.get('insides', [dict(interface=config.get('inside'), prefix=config.get('prefix'))])
    active = [p for p in policies if p['interface'] in present]
    outside = config['outside']
    candidates = present.get(outside, [])
    external = old.get('external') if old.get('external') in candidates else next(iter(candidates), None)
    enabled = 'NAPT66 enabled,' in cli('show napt66')
    if not active or not external:
        if enabled:
            cli('napt66 disable')
        return {}
    desired = dict(config, external=external, generation=generation)
    if 'insides' in config:
        desired['insides'] = active
    attached = all(re.search(r'(?m)^\s+napt66\s*$', cli('show interface features ' + name))
                   for name in [p['interface'] for p in active] + [outside]) if enabled else False
    if desired != old or not attached:
        sources = ' '.join(f'inside {p["interface"]} prefix {p["prefix"]}' for p in active)
        cli(f'napt66 {sources} outside {outside} external {external}')
        print(f'NAPT66 {sources} -> {outside}: external {external}', flush=True)
    return desired


def validate(config):
    if set(config) not in ({'inside', 'outside', 'prefix'}, {'insides', 'outside'}):
        raise ValueError('invalid NAPT66 policy')
    policies = config.get('insides', [dict(interface=config.get('inside'), prefix=config.get('prefix'))])
    if not isinstance(policies, list) or not 1 <= len(policies) <= 16:
        raise ValueError('require 1..16 inside policies')
    names, networks = {config['outside']}, []
    if not isinstance(config['outside'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', config['outside']):
        raise ValueError('invalid outside')
    for policy in policies:
        if set(policy) != {'interface', 'prefix'}:
            raise ValueError('invalid inside policy')
        name = policy['interface']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name in names:
            raise ValueError('inside interfaces must be distinct')
        prefix = ipaddress.ip_network(policy['prefix'])
        if prefix.version != 6 or not prefix.subnet_of(ipaddress.ip_network('fc00::/7')):
            raise ValueError('NAPT66 prefix must be ULA')
        if any(prefix.overlaps(other) for other in networks):
            raise ValueError('inside prefixes must not overlap')
        names.add(name)
        networks.append(prefix)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/vpp/napt66-sync.json')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    validate(config)
    def cli(command):
        result = subprocess.run(['vppctl', command], text=True, capture_output=True, check=True, timeout=8)
        if re.search(r'unknown input|unknown interface|unknown.*function|failed|error:', result.stdout, re.I):
            raise RuntimeError(result.stdout)
        return result.stdout
    generation = subprocess.check_output(
        ['systemctl', 'show', 'vpp-router.service', '-p', 'InvocationID', '--value'], text=True).strip()
    if not re.fullmatch('[a-f0-9]{32}', generation):
        raise RuntimeError('VPP generation unavailable')
    state = Path('/run/napt66-sync/state.json')
    old = json.loads(state.read_text()) if state.exists() else {}
    desired = reconcile(config, old, generation, cli)
    if desired != old:
        state.parent.mkdir(parents=True, exist_ok=True)
        temporary = state.with_suffix('.tmp')
        temporary.write_text(json.dumps(desired) + '\n')
        temporary.replace(state)


if __name__ == '__main__':
    main()
