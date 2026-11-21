#!/usr/bin/env python3
"""Discover host listeners and report service admission policy."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def port_bounds(value):
    if type(value) is int:
        first = last = value
    elif isinstance(value, str) and re.fullmatch(r'[0-9]{1,5}-[0-9]{1,5}', value):
        first, last = map(int, value.split('-'))
    else:
        raise ValueError('port must be an integer or first-last range')
    if not 1 <= first <= last <= 65535:
        raise ValueError('invalid port range')
    return first, last


def listeners(text):
    rows = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ('tcp', 'udp'):
            continue
        address, port = fields[4].rsplit(':', 1)
        if not port.isdigit():
            continue
        # ss exposes the actual IPV6_V6ONLY flag with -e. Only a wildcard
        # socket explicitly reported as dual-stack is an IPv4 wildcard too.
        if address in ('*', '[::]', '::') and re.search(r'\bv6only:0(?:\s|$)', line):
            address = '0.0.0.0'
        # Keep address/process association: another socket on the same port
        # must not make a management-only service look reachable after DNAT.
        key = fields[0], int(port), address
        row = rows.setdefault(key, dict(protocol=key[0], port=key[1], addresses=[], processes=[]))
        row['addresses'] = sorted(set(row['addresses']) | {address})
        row['processes'] = sorted(set(row['processes']) | set(re.findall(r'\("([^\"]+)"', line)))
    return [rows[key] for key in sorted(rows)]


def current_listeners():
    return listeners(subprocess.run(['ss', '-H', '-lntupe'], capture_output=True,
                                    text=True, check=True, timeout=10).stdout)


def resolved_services(config, inventory):
    result = list(config['services'])
    for service in config.get('dynamic_services', []):
        ports = sorted({row['port'] for row in inventory
                        if row['protocol'] == service['protocol'] and service['process'] in row['processes']
                        and any(address in ('0.0.0.0', config['host']) for address in row['addresses'])})
        if ports:
            result.append({**service, 'ports': ports})
    for service in result:
        if service['protocol'] not in ('tcp', 'udp') or type(service['wan']) is not bool:
            raise ValueError('invalid service policy')
        if type(service.get('dedicated_ingress', False)) is not bool:
            raise ValueError('invalid dedicated ingress policy')
        for port in service['ports']:
            port_bounds(port)
    return result


def acl_ports(services):
    return {scope+'_'+proto+'_services': sorted(
        {port for service in services if service['protocol'] == proto and (scope == 'lan' or service['wan'])
         for port in service['ports']}, key=lambda item: port_bounds(item))
        for scope in ('lan', 'wan') for proto in ('tcp', 'udp')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).with_name('services.json'))
    parser.add_argument('--inventory', type=Path, help='Use a saved inventory; otherwise query ss (read-only)')
    parser.add_argument('--output', type=Path, help='Render files; never applies firewall or VPP commands')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    inventory = json.loads(args.inventory.read_text()) if args.inventory else current_listeners()
    services = resolved_services(config, inventory)
    result = dict(inventory=inventory, resolved_services=services, acl_ports=acl_ports(services),
                  dynamic_snapshot_only=bool(config.get('dynamic_services')))
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output/'inventory-policy.json').write_text(json.dumps(result, indent=2)+'\n')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
