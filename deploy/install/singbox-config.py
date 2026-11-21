#!/usr/bin/env python3
"""sing-box as the LAN's proxy entry, as on the RK3588 board, configured in two files of one directory that
sing-box loads with -C and merges:

  entry.json     what the LAN reaches, written by the installer every time: Fake-IP DNS, one
                 TPROXY inbound on the port Gate sends to, for real addresses and Fake-IP ones
                 alike (sing-box turns the latter back into names), and a SOCKS5 inbound on the
                 LAN address. Everything goes to the outbound tagged "proxy".
  upstream.json  where it goes, written once and then left to the person running the router: any
                 sing-box outbound or endpoint tagged "proxy" (SOCKS5, Trojan, Shadowsocks,
                 VLESS, WireGuard, ...). Until there is one, a placeholder rejects proxied traffic.

Gate's ports and pools come from its proxy rule when Gate is installed, so the two agree;
otherwise the ports given here (Gate's installer defaults unless the installer says otherwise)
are used, and the installer passes the same values to Gate.
Passwords are read from standard input so that they never appear in a command line.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys

POOLS = ['198.18.0.0/15', '2001:2::/48']
FAKE_DNS = ['127.0.0.1', 5354]
TPROXY = 2082
LAN_SOCKS = 1080
TAG = 'proxy'
PROXIED = ['tproxy', 'lan-socks']
# Types that are endpoints rather than outbounds in sing-box 1.11 and later.
ENDPOINT_TYPES = {'wireguard', 'tailscale'}


def proxy_rule(path):
    """Gate's proxy rule: one with a TPROXY port, a Fake-IP one if there is."""
    if not path or not Path(path).is_file():
        return {}
    rules = [rule for rule in json.loads(Path(path).read_text()).get('routes', [])
             if isinstance(rule, dict) and rule.get('tproxy_port')]
    return next((rule for rule in rules if rule.get('fakeip_range')), rules[0] if rules else {})


def endpoints(rule, tproxy=TPROXY, fake_dns_port=FAKE_DNS[1]):
    """Where Gate sends DNS and connections, and the pools its DNS hands out. The ports given
    are used only when there is no rule of Gate's to follow."""
    pools = rule.get('fakeip_range') or POOLS
    pools = [pools] if isinstance(pools, str) else list(pools)
    fake_dns = (rule.get('dns_upstream') if rule.get('fakeip_range') else None) or [FAKE_DNS[0], fake_dns_port]
    listen = rule.get('tproxy_address') or '::'
    if isinstance(listen, list):
        listen = listen[0] if len(listen) == 1 else '::'
    return pools, [str(fake_dns[0]), int(fake_dns[1])], listen, int(rule.get('tproxy_port') or tproxy)


def port_number(text):
    value = int(text)
    if not 1 <= value <= 65535:
        raise ValueError(f'端口 {value} 不在 1 到 65535 之间')
    return value


def entry(rule, lan_address, cache, ipv6=False, socks_port=LAN_SOCKS, tproxy=TPROXY, fake_dns_port=FAKE_DNS[1]):
    """ipv6: the LAN has IPv6, so Fake-IP hands out IPv6 addresses too, even where Gate's rule
    was made before it did; the panel's rules then offer that pool."""
    pools, fake_dns, tproxy_listen, tproxy_port = endpoints(rule, tproxy, fake_dns_port)
    # TPROXY listens on every address, and sing-box's direct and socks inbounds take TCP as well.
    used = {'SOCKS5': socks_port, 'TPROXY': tproxy_port, 'Fake-IP DNS': fake_dns[1]}
    if len(set(used.values())) != len(used):
        raise ValueError('SOCKS5、TPROXY 和 Fake-IP DNS 要用不同的端口：'
                         + '，'.join(f'{name} {value}' for name, value in used.items()))
    if ipv6 and not any(ipaddress.ip_network(pool).version == 6 for pool in pools):
        pools = pools + [POOLS[1]]
    fake = {'type': 'fakeip', 'tag': 'fake'}
    for pool in pools:
        fake['inet4_range' if ipaddress.ip_network(pool).version == 4 else 'inet6_range'] = pool
    return {
        'log': {'level': 'error', 'timestamp': True},
        'dns': {
            'servers': [fake, {'type': 'local', 'tag': 'system'}],
            'rules': [
                {'query_type': ['A', 'AAAA'], 'action': 'route', 'server': 'fake'},
                # No real HTTPS/SVCB hints or ECH lookup can escape the mapping.
                {'query_type': ['HTTPS', 'SVCB', 'ANY'], 'action': 'predefined', 'rcode': 'NOERROR'}],
            'final': 'system'},
        'inbounds': [
            {'type': 'direct', 'tag': 'fake-dns', 'listen': fake_dns[0], 'listen_port': fake_dns[1]},
            {'type': 'tproxy', 'tag': 'tproxy', 'listen': tproxy_listen, 'listen_port': tproxy_port},
            {'type': 'socks', 'tag': 'lan-socks', 'listen': lan_address, 'listen_port': socks_port}],
        # The upstream's own server names resolve by the system resolver, not to Fake-IP.
        'route': {'rules': [{'inbound': ['fake-dns'], 'action': 'hijack-dns'}],
                  'final': TAG, 'default_domain_resolver': 'system'},
        'experimental': {'cache_file': {'enabled': True, 'store_fakeip': True, 'path': cache}}}


def placeholder():
    # A rule, not the deprecated block outbound. Replacing the whole file with an upstream
    # removes the rule and lets route.final send traffic to it.
    return {'outbounds': [{'type': 'direct', 'tag': TAG}],
            'route': {'rules': [{'inbound': PROXIED, 'action': 'reject'}]}}


def host_port(server, port):
    server = server.strip()
    if not server or any(c.isspace() for c in server):
        raise ValueError('服务器地址不能为空，也不能有空格')
    if not 1 <= port <= 65535:
        raise ValueError('端口要在 1 到 65535 之间')
    return server, port


def socks(server, port, username, password):
    out = {'type': 'socks', 'tag': TAG, 'server': server, 'server_port': port, 'version': '5'}
    if password and not username:
        raise ValueError('有密码时必须有用户名')
    if username:
        out.update(username=username, password=password)
    return {'outbounds': [out]}


def trojan(server, port, password, sni):
    if not password:
        raise ValueError('Trojan 要有密码')
    return {'outbounds': [{'type': 'trojan', 'tag': TAG, 'server': server, 'server_port': port, 'password': password,
                           'tls': {'enabled': True, 'server_name': sni or server}}]}


def imported(path):
    """An outbound or endpoint from a file: one object, a list, or a fragment with outbounds and
    endpoints. A single one becomes "proxy"; with several, one must be tagged so."""
    try:
        data = json.loads(Path(path).read_text())
    except json.JSONDecodeError as error:
        raise ValueError(f'{path} 不是合法的 JSON：{error}') from None
    if isinstance(data, dict) and ('outbounds' in data or 'endpoints' in data):
        items = list(data.get('outbounds', [])) + list(data.get('endpoints', []))
        if not any(isinstance(i, dict) and i.get('tag') == TAG for i in items):
            raise ValueError(f'{path} 里没有标签为 "{TAG}" 的出站或 endpoint')
        return data
    items = data if isinstance(data, list) else [data]
    if not items or not all(isinstance(i, dict) and i.get('type') for i in items):
        raise ValueError(f'{path} 不是 sing-box 的出站或 endpoint（要有 "type"）')
    if len(items) == 1:
        items[0]['tag'] = TAG
    elif not any(i.get('tag') == TAG for i in items):
        raise ValueError(f'{path} 有多个出站，要把其中一个的标签设为 "{TAG}"')
    out = {}
    for item in items:
        out.setdefault('endpoints' if item['type'] in ENDPOINT_TYPES else 'outbounds', []).append(item)
    return out


def write_private(path, document):
    """Only root reads it, from the moment it exists: an upstream holds credentials."""
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(document, out, indent=2, ensure_ascii=False)
        out.write('\n')
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    e = commands.add_parser('entry', help='write entry.json')
    e.add_argument('--dir', required=True, type=Path)
    e.add_argument('--gate-config', help="Gate's configuration, for the ports and pools of its proxy rule")
    e.add_argument('--lan-address', default='127.0.0.1', help='where the SOCKS5 inbound listens')
    e.add_argument('--cache', default='/var/lib/vpp-router-sing-box/cache.db')
    e.add_argument('--ipv6', action='store_true', help='the LAN has IPv6: add an IPv6 Fake-IP pool when the rule has none')
    e.add_argument('--socks-port', type=port_number, default=LAN_SOCKS, help='port of the LAN SOCKS5 inbound')
    u = commands.add_parser('upstream', help='write upstream.json')
    u.add_argument('--dir', required=True, type=Path)
    u.add_argument('--type', required=True, choices=['none', 'socks', 'trojan', 'file'])
    u.add_argument('--server', default='')
    u.add_argument('--port', type=int, default=0)
    u.add_argument('--username', default='')
    u.add_argument('--sni', default='')
    u.add_argument('--file', help='sing-box outbound or endpoint JSON, for --type file')
    u.add_argument('--password-stdin', action='store_true')
    c = commands.add_parser('check-file', help='check a file --type file would accept')
    c.add_argument('file')
    p = commands.add_parser('endpoints', help="print Gate's Fake-IP DNS and TPROXY port")
    p.add_argument('--gate-config')
    for sub in (e, p):
        sub.add_argument('--tproxy-port', type=port_number, default=TPROXY, help="TPROXY port when Gate has no proxy rule")
        sub.add_argument('--fake-dns-port', type=port_number, default=FAKE_DNS[1], help="Fake-IP DNS port when Gate has no proxy rule")
    args = parser.parse_args()

    if args.command == 'endpoints':
        _, fake_dns, _, tproxy = endpoints(proxy_rule(args.gate_config), args.tproxy_port, args.fake_dns_port)
        print(f'{fake_dns[0]}:{fake_dns[1]} {tproxy}')
    elif args.command == 'check-file':
        imported(args.file)
    elif args.command == 'entry':
        args.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        ipaddress.ip_address(args.lan_address)
        write_private(args.dir / 'entry.json', entry(proxy_rule(args.gate_config), args.lan_address, args.cache, args.ipv6,
                                                     args.socks_port, args.tproxy_port, args.fake_dns_port))
    else:
        args.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        password = sys.stdin.readline().rstrip('\n') if args.password_stdin else ''
        if args.type == 'none':
            document = placeholder()
        elif args.type == 'file':
            document = imported(args.file)
        else:
            server, port = host_port(args.server, args.port)
            document = socks(server, port, args.username, password) if args.type == 'socks' else trojan(server, port, password, args.sni)
        write_private(args.dir / 'upstream.json', document)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f'sing-box 配置：{exc}', file=sys.stderr)
        sys.exit(1)
