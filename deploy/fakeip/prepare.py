#!/usr/bin/env python3
"""Prepare a Fake-IP frontend with a native Trojan outbound for DNS Gate."""
import argparse
import copy
import ipaddress
import json
from pathlib import Path
import re

POOL4 = '198.18.0.0/15'
POOL6 = '2001:2::/48'
FAKEIP_FILES = {4: 'fakeip.ipv4', 6: 'fakeip.ipv6'}
DNS_PORT = 5354
TPROXY_PORT = 2082


def wireguard_domains(directory=Path('/etc/wireguard')):
    """VPP WireGuard endpoints consume real IPs, even when their domain matches PLIST."""
    domains = set()
    for path in directory.glob('*.conf'):
        for endpoint in re.findall(r'(?im)^\s*Endpoint\s*=\s*([^\s#]+)', path.read_text()):
            host = endpoint.rsplit(':', 1)[0].strip('[]')
            try:
                ipaddress.ip_address(host)
            except ValueError:
                domains.add(host.lower().rstrip('.'))
    return sorted(domains)


def trojan_outbound(config):
    """Import credentials locally at preparation time; never print this result."""
    if config.get('run_type') != 'client':
        raise ValueError('Expected trojan-plist client configuration')
    password = config.get('password')
    if isinstance(password, list) and password:
        password = password[0]
    if not isinstance(password, str) or not password:
        raise ValueError('Trojan password is missing')
    ssl = config.get('ssl', {})
    # Preserve full verification; do not silently weaken hostname-only settings.
    if ssl.get('verify', True) and not ssl.get('verify_hostname', True):
        raise ValueError('Partial TLS verification requires explicit configuration')
    tls = {'enabled': True,
           'server_name': ssl.get('sni') or config['remote_addr'],
           'insecure': not ssl.get('verify', True)}
    if ssl.get('alpn'):
        tls['alpn'] = list(ssl['alpn'])
    if ssl.get('cert'):
        tls['certificate_path'] = ssl['cert']
    return {'type': 'trojan', 'tag': 'trojan-out',
            'server': config['remote_addr'], 'server_port': config['remote_port'],
            'password': password, 'tls': tls, 'domain_resolver': 'auxiliary',
            'tcp_fast_open': config.get('tcp', {}).get('fast_open', False)}


def frontend(outbound, real_dns_domains=(), *, legacy_listeners=True):
    return {
        'log': {'level': 'error', 'timestamp': True},
        'dns': {
            'servers': [{'type': 'fakeip', 'tag': 'fake',
                         'inet4_range': POOL4, 'inet6_range': POOL6},
                        {'type': 'udp', 'tag': 'auxiliary',
                         'server': '10.61.20.2', 'server_port': 53}],
            'rules': ([{'domain': list(real_dns_domains), 'action': 'route',
                        'server': 'auxiliary'}] if real_dns_domains else []) + [
                {'query_type': ['A', 'AAAA'], 'action': 'route', 'server': 'fake'},
                # No real HTTPS/SVCB hints or ECH lookup can escape the mapping.
                {'query_type': ['HTTPS', 'SVCB', 'ANY'],
                 'action': 'predefined', 'rcode': 'NOERROR'}],
            'final': 'auxiliary'},
        'inbounds': [
            {'type': 'direct', 'tag': 'fake-dns', 'listen': '127.0.0.1',
             'listen_port': DNS_PORT},
            {'type': 'tproxy', 'tag': 'fake-tproxy', 'listen': '::',
             'listen_port': TPROXY_PORT}] + ([
            {'type': 'tproxy', 'tag': 'real-tproxy', 'listen': '::', 'listen_port': 2080},
            {'type': 'socks', 'tag': 'lan-socks', 'listen': '0.0.0.0', 'listen_port': 1080}
            ] if legacy_listeners else []),
        'outbounds': [copy.deepcopy(outbound)],
        'route': {'rules': [{'inbound': ['fake-dns'], 'action': 'hijack-dns'}],
                  'final': outbound['tag']},
        'experimental': {'cache_file': {'enabled': True, 'store_fakeip': True,
                         'path': '/var/lib/vrouter-fakeip/cache.db'}}}


def configure(domains, routes, nft, *, extra_ipv4_rule=None, extra_ipv6_rule=None):
    domains, routes = copy.deepcopy(domains), copy.deepcopy(routes)
    selected = [r for r in domains['routes'] if r['name'] in ('proxylist', 'proxylist6')]
    if {r['name'] for r in selected} != {'proxylist', 'proxylist6'} or len(selected) != 2:
        raise ValueError('Expected one proxylist and one proxylist6 exit')
    domain_files = (['gate/tproxy.domains']
                    if all(r.get('domain_files') == ['gate/tproxy.domains'] for r in selected)
                    else ['tproxy.domains'])
    for item in selected:
        expected = '10.63.30.2' if item['name'] == 'proxylist' else 'fd42:1111:2222:30::2'
        if item['interface'] != 'tap2490' or item['via'] != expected:
            raise ValueError('PLIST exit must use the dedicated proxy TAP')
        item['dns_upstream'] = ['127.0.0.1', DNS_PORT]
        item['domain_files'] = list(domain_files)
        item['fakeip_range'] = POOL4 if item['name'] == 'proxylist' else POOL6
        item['ip_range_files'] = [FAKEIP_FILES[4 if item['name'] == 'proxylist' else 6]]

    if extra_ipv4_rule and extra_ipv4_rule == extra_ipv6_rule:
        raise ValueError('Additional IPv4 and IPv6 Fake-IP rule names must differ')
    for name, via, pool in ((extra_ipv4_rule, '10.63.30.2', POOL4),
                            (extra_ipv6_rule, 'fd42:1111:2222:30::2', POOL6)):
        if name is None:
            continue
        matches = [r for r in domains['routes'] if r['name'] == name]
        if len(matches) != 1 or matches[0] in selected:
            raise ValueError(f'Expected one additional DNS route named {name}')
        item = matches[0]
        if ipaddress.ip_address(item['via']).version != ipaddress.ip_address(via).version:
            raise ValueError(f'Unexpected address family for DNS route {name}')
        item.update(interface='tap2490',
                    via=via,
                    dns_upstream=['127.0.0.1', DNS_PORT],
                    fakeip_range=pool)
    for prefix in routes.get('exclude_prefixes', []):
        network = ipaddress.ip_network(prefix)
        pool = ipaddress.ip_network(POOL4 if network.version == 4 else POOL6)
        if network.overlaps(pool):
            raise ValueError('Fake-IP pool overlaps exclusion: ' + prefix)
    routes['dns_upstream_policy'] = 'first'
    anchor = 'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" ip6 daddr fc00::/7'
    if nft.count(anchor) != 1 or '# BEGIN VROUTER Fake-IP' in nft:
        raise ValueError('Unexpected or already modified TPROXY rules')
    rules = '# BEGIN VROUTER Fake-IP\n'
    for family, pool in (('ip', POOL4), ('ip6', POOL6)):
        rules += (f'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" '
                  f'{family} daddr {pool} meta l4proto {{ tcp, udp }} counter '
                  f'tproxy {family} to :{TPROXY_PORT} meta mark set 1 ct mark set 1 accept\n')
    rules += '# END VROUTER Fake-IP\n'
    return domains, routes, nft.replace(anchor, rules + anchor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir', type=Path, default=Path('/etc/vpp'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--trojan-config', type=Path, default=Path('/etc/trojan/trojan.json'),
                        help='Read existing credentials on device; no runtime trojan-plist dependency')
    parser.add_argument('--extra-ipv4-rule', help='Additional IPv4 DNS route to move to Fake-IP')
    parser.add_argument('--extra-ipv6-rule', help='Additional IPv6 DNS route to move to Fake-IP')
    args = parser.parse_args()
    domains, routes, nft = configure(
        json.loads((args.config_dir / 'dns-route-domains.json').read_text()),
        json.loads((args.config_dir / 'nftset-route-sync.json').read_text()),
        (args.config_dir / 'dns-route-gate.nft').read_text(),
        extra_ipv4_rule=args.extra_ipv4_rule, extra_ipv6_rule=args.extra_ipv6_rule)
    args.output.mkdir(mode=0o700)  # Never overwrite a prepared plan.
    for name, data in [('dns-route-domains.json', domains),
                       ('nftset-route-sync.json', routes),
                       ('sing-box.json', frontend(trojan_outbound(json.loads(
                           args.trojan_config.read_text())), wireguard_domains()))]:
        (args.output / name).write_text(json.dumps(data, indent=2) + '\n')
    for name in FAKEIP_FILES.values():
        (args.output / name).write_text((Path(__file__).with_name(name)).read_text())
    (args.output / 'dns-route-gate.nft').write_text(nft)


if __name__ == '__main__':
    main()
