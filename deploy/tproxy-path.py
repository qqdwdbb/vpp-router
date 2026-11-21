"""Dedicated routed TAP and reply policy for the VROUTER transparent proxy."""
import ipaddress
import json

INTERFACE = 'tap2490'
HOST_INTERFACE = 'vpp-tproxy'
VIA4 = '10.63.30.2'
VIA6 = 'fd42:1111:2222:30::2'
MARK = '0x04000000'
TABLE = '2490'


def topology():
    return [
        'create tap id 2490 host-if-name vpp-tproxy host-ip4-addr 10.63.30.2/30 host-ip6-addr fd42:1111:2222:30::2/64 gso',
        'set interface ip address tap2490 10.63.30.1/30',
        'set interface ip address tap2490 fd42:1111:2222:30::1/64',
        'set interface state tap2490 up',
        'set interface rx-mode tap2490 interrupt',
    ]


def host(run):
    run('ip', 'link', 'set', HOST_INTERFACE, 'up')
    run('sysctl', '-w', 'net.ipv4.conf.vpp-tproxy.rp_filter=0',
        'net.ipv6.conf.vpp-tproxy.accept_ra=0', 'net.ipv6.conf.vpp-tproxy.autoconf=0')
    run('ethtool', '-K', HOST_INTERFACE, 'tx', 'off')
    for family, gateway in (('-4', '10.63.30.1'), ('-6', 'fd42:1111:2222:30::1')):
        # Priority and table are reserved for intercepted socket replies only.
        rules = json.loads(run('ip', '-j', family, 'rule', 'show'))
        existing = [r for r in rules if r.get('priority') == 105]
        expected = lambda r: (int(str(r.get('fwmark', '0')), 0) == int(MARK, 0)
                              and int(str(r.get('fwmask', '0')), 0) == int(MARK, 0)
                              and str(r.get('table')) == TABLE)
        if existing and not all(expected(r) for r in existing):
            raise ValueError('TPROXY reply priority 105 is occupied')
        routes = json.loads(run('ip', '-j', family, 'route', 'show', 'table', 'all'))
        if any(str(r.get('table')) == TABLE and
               (r.get('dst') != 'default' or r.get('gateway') != gateway or
                r.get('dev') != HOST_INTERFACE or r.get('type', 'unicast') != 'unicast')
               for r in routes):
            raise ValueError('TPROXY reply table 2490 is occupied')
        run('ip', family, 'route', 'replace', 'default', 'via', gateway,
            'dev', HOST_INTERFACE, 'table', TABLE)
        if not existing:
            run('ip', family, 'rule', 'add', 'priority', '105',
                'fwmark', MARK + '/' + MARK, 'lookup', TABLE)


def proxy_route(route):
    route['interface'] = INTERFACE
    route['via'] = VIA4 if ipaddress.ip_address(route['via']).version == 4 else VIA6


def nft_proxy_rules(fakeip=True):
    lines = [
        'add chain inet mangle vrouter_lease_tproxy { type filter hook prerouting priority mangle - 1; policy accept; }',
        'flush chain inet mangle vrouter_lease_tproxy',
        'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" fib daddr type local return',
        # A proxy-only ingress must never proxy internal/control destinations.
        'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } counter return',
        'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" ip6 daddr { ::/128, ::1/128, fe80::/10, ff00::/8 } counter return',
        'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" ip protocol udp udp dport 443 counter reject with icmp port-unreachable',
        'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" ip6 nexthdr udp udp dport 443 counter reject with icmpv6 port-unreachable',
    ]
    if fakeip:
        lines.append('# BEGIN VROUTER Fake-IP')
        for family, pool in (('ip', '198.18.0.0/15'), ('ip6', '2001:2::/48')):
            lines.append(f'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" {family} daddr {pool} meta l4proto {{ tcp, udp }} counter tproxy {family} to :2082 meta mark set 1 ct mark set 1 accept')
        lines.append('# END VROUTER Fake-IP')
    # Keep Fake-IP dispatch before the internal IPv6 exclusion.
    lines.append('add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" ip6 daddr fc00::/7 counter return')
    for family, nf in (('ip', 'ipv4'), ('ip6', 'ipv6')):
        lines.append(f'add rule inet mangle vrouter_lease_tproxy iifname "vpp-tproxy" meta nfproto {nf} meta l4proto {{ tcp, udp }} counter tproxy {family} to :2080 meta mark set 1 ct mark set 1 accept')
    lines += [
        'add chain inet mangle vrouter_proxy_reply { type route hook output priority mangle; policy accept; }',
        'flush chain inet mangle vrouter_proxy_reply',
        'add rule inet mangle vrouter_proxy_reply ct mark 1 ct direction reply meta mark set meta mark | 0x04000000',
        'add chain inet mangle vrouter_proxy_guard { type filter hook forward priority filter - 2; policy accept; }',
        'flush chain inet mangle vrouter_proxy_guard',
        'add rule inet mangle vrouter_proxy_guard iifname "vpp-tproxy" counter drop',
    ]
    return '\n'.join(lines) + '\n'


def separate_nft(text):
    start = text.index('# loop200 delivers only')
    end = text.index('# Routed traffic sent back', start)
    text = text[:start] + '# Only the dedicated routed TAP is a proxy ingress.\n' + nft_proxy_rules(
        fakeip='# BEGIN VROUTER Fake-IP' in text) + text[end:]
    text = text.replace('ip daddr 10.64.20.0/24 counter masquerade',
                        'ip daddr { 10.64.10.0/24, 10.64.30.0/24, 10.64.40.0/24, 10.64.20.0/24 } counter masquerade')
    return text
