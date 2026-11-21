#!/usr/bin/env python3
"""Controlled DHCPv6-PD server and VPP PD/SLAAC integration probe."""
import ipaddress
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import re


def option(kind, value):
    return struct.pack('!HH', kind, len(value)) + value


def options(data):
    result = {}
    while data:
        if len(data) < 4:
            raise ValueError('truncated DHCPv6 option')
        kind, size = struct.unpack('!HH', data[:4])
        if len(data) < 4 + size:
            raise ValueError('truncated DHCPv6 payload')
        result[kind] = data[4:4+size]
        data = data[4+size:]
    return result


def serve(root):
    index = socket.if_nametoindex('mgmt0')
    identity = bytes.fromhex('00030001020000003952')
    def router_advertisements():
        with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as raw:
            raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
            raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            header = struct.pack('!BBHBBHII', 134, 0, 0, 64, 0, 30, 0, 0)
            prefix = struct.pack('!BBBBIII16s', 3, 4, 64, 0xc0, 180, 120, 0,
                                 ipaddress.IPv6Address('2001:db8:45::').packed)
            while True:
                raw.sendto(header + prefix, ('ff02::1', 0, 0, index))
                time.sleep(1)
    threading.Thread(target=router_advertisements, daemon=True).start()
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('::', 547))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        socket.inet_pton(socket.AF_INET6, 'ff02::1:2') + struct.pack('@I', index))
        (root / 'pd-ready').touch()
        while True:
            packet, peer = sock.recvfrom(8192)
            kind = packet[0]
            if kind not in (1, 3, 5, 6, 8):
                continue
            fields = options(packet[4:])
            if 1 not in fields or 25 not in fields:
                continue
            requested = (root / 'pd-prefix').read_text().strip()
            prefix = ipaddress.IPv6Network(requested) if requested != 'none' else None
            # Short T1 gives a bounded real Renew test without forcing VPP restart.
            ia_prefix = (struct.pack('!IIB', 120, 180, prefix.prefixlen) + prefix.network_address.packed) if prefix else None
            old = options(fields[25][12:]).get(26)
            withdrawn = b''
            if old and (prefix is None or old[9:25] != prefix.network_address.packed):
                withdrawn = option(26, struct.pack('!IIB', 0, 0, old[8]) + old[9:25])
            ia_pd = fields[25][:4] + struct.pack('!II', 3, 6) + withdrawn + (option(26, ia_prefix) if prefix else b'')
            reply = bytes([2 if kind == 1 else 7]) + packet[1:4]
            reply += option(1, fields[1]) + option(2, identity) + option(25, ia_pd)
            if kind == 1:
                reply += option(7, b'\xff')
            sock.sendto(reply, peer)
            with (root / 'pd-events.jsonl').open('a') as log:
                log.write(json.dumps({'kind': kind, 'prefix': str(prefix) if prefix else None}) + '\n')


def capture(root):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86dd)) as sock:
        sock.bind(('mgmt0', 0))
        (root / 'ra-capture-ready').touch()
        while True:
            frame = sock.recv(65535)
            if len(frame) < 70 or frame[20] != 58 or frame[54] != 134:
                continue
            data, offset = frame[54:], 16
            router = {'source': socket.inet_ntop(socket.AF_INET6, frame[22:38]),
                      'lifetime': struct.unpack('!H', data[6:8])[0], 'flags': data[5], 'rdnss': []}
            while offset + 2 <= len(data):
                kind, units = data[offset:offset+2]
                if not units or offset + units*8 > len(data):
                    break
                value = data[offset:offset+units*8]
                if kind == 25 and len(value) >= 24:
                    router['rdnss'] += [socket.inet_ntop(socket.AF_INET6, value[pos:pos+16])
                                       for pos in range(8, len(value), 16)]
                if kind == 3 and len(value) == 32:
                    prefix = str(ipaddress.IPv6Network((ipaddress.IPv6Address(value[16:32]), value[2])))
                    valid, preferred = struct.unpack('!II', value[4:12])
                    with (root / 'ra-events.jsonl').open('a') as log:
                        log.write(json.dumps({'prefix': prefix, 'source': router['source'], 'flags': value[3],
                                              'valid': valid, 'preferred': preferred}) + '\n')
                offset += units*8
            with (root / 'ra-router-events.jsonl').open('a') as log:
                log.write(json.dumps(router) + '\n')


def check(root, names, nsrun, cli, spawn, wait_for, nat66=None, runtime=None, prepare_recovery=False):
    script = '/opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipv6_pd.py'
    client, dns, wan = names
    nsrun(client, 'sysctl', '-qw', 'net.ipv6.conf.mgmt0.accept_ra=2',
          'net.ipv6.conf.mgmt0.autoconf=1')
    nsrun(wan, 'ip', '-6', 'address', 'add', '2001:db8:45::2/64', 'dev', 'mgmt0', 'nodad')
    nsrun(dns, 'ip', '-6', 'address', 'replace', 'fd42:1111:2222:10::2/64', 'dev', 'br-mgmt', 'nodad')
    cli('enable ip6 interface tap3952')
    cli('ip6 nd tap3952 ra-suppress')
    cli('set interface ip address loop3950 fd42:1111:2222:10::1/64')
    cli('ip6 nd loop3950 prefix fd42:1111:2222:10::/64 180 120')
    cli('ip6 nd loop3950 ra-interval 4 3 ra-lifetime 30 ra-other-config-flag')
    pool_config = root / 'ipsec.conf'
    pool_config.write_text('conn %default\n rightsourceip=10.62.50.0/24,fd00::/64\nconn eap-mschapv2\n rightsourceip=10.62.20.0/24,fd01::/64\n rightauth=eap-mschapv2\n')
    publisher_config = {'vpp_socket': str(root / 'cli.sock'), 'lan_interface': 'loop3950',
                        'wan_interface': 'tap3952', 'prefix_group': 'wan-pd',
                        'interval_seconds': .25, 'withdraw_seconds': 5,
                        'ra_max_interval_seconds': 4, 'state_file': str(root / 'pd-state.json'),
                        'ipsec_config': str(pool_config), 'dhcp_lease_file': str(root / 'no-leases')}
    if nat66:
        publisher_config['nat66_policy_file'] = str(nat66.policy_file)
    (root / 'pd-sync.json').write_text(json.dumps(publisher_config))
    ra_capture = spawn(client, 'python3', script, '--capture', str(root))
    wait_for(lambda: (root / 'ra-capture-ready').exists(), 'RA capture not ready')
    publisher = spawn(dns, 'python3', '/opt/vpp-vrouter-migration/source/scripts/vrouter/ipv6/pd-sync.py',
                      '--config', str(root / 'pd-sync.json'))
    def pool_ready(prefix):
        state = root / 'pd-state.json'
        return state.exists() and json.loads(state.read_text()).get('pool_prefix') == prefix
    (root / 'pd-prefix').write_text('2001:db8:4400:1::/64')
    pd_server = spawn(wan, 'python3', script, '--serve', str(root))
    wait_for(lambda: (root / 'pd-ready').exists(), 'PD server not ready')
    # The Linux namespace must have completed link-local DAD before receiving multicast.
    wait_for(lambda: any(a['scope'] == 'link' and 'tentative' not in a
                        for i in json.loads(nsrun(wan, 'ip', '-j', '-6', 'address', 'show', 'dev', 'mgmt0'))
                        for a in i['addr_info']), 'WAN link-local DAD incomplete')
    cli('dhcp6 pd client tap3952 prefix group wan-pd')
    cli('set ip6 address loop3950 prefix group wan-pd ::1/64')
    cli('ip6 nd address autoconfig tap3952 default-route')
    def wan_address():
        text = cli('show interface address').split('tap3952 (up):', 1)[1].split('wg1 (', 1)[0]
        match = re.search(r'L3 (2001:db8:45:[0-9a-f:]+)/64', text)
        return match[1] if match else None
    wait_for(wan_address, 'VPP WAN did not acquire SLAAC address')
    wait_for(lambda: 'ipv6 via fe80:' in cli('show ip6 fib ::/0'), 'VPP did not learn upstream RA default')
    nsrun(wan, 'ip', '-6', 'route', 'add', '2001:db8:4400::/56', 'via', wan_address())
    def lease(prefix):
        return prefix in cli('show ip6 prefixes') and prefix.replace('/64', '1/64') in cli('show interface address')
    first = '2001:db8:4400:1::/64'
    wait_for(lambda: lease(first), 'VPP did not acquire delegated prefix')
    try:
        wait_for(lambda: pool_ready(first), 'Automatic initial RA/pool publication failed')
    except RuntimeError:
        print(cli('show ip6 prefixes'), cli('show interface address'), cli('show ip6 fib ::/0'), flush=True)
        print((root / 'pd-state.json').read_text(), flush=True)
        raise
    def address_for(prefix):
        network = ipaddress.IPv6Network(prefix)
        for link in json.loads(nsrun(client, 'ip', '-j', '-6', 'address', 'show', 'dev', 'mgmt0')):
            for addr in link['addr_info']:
                if ipaddress.IPv6Address(addr['local']) in network and 'tentative' not in addr:
                    return addr['local']
        return None
    wait_for(lambda: address_for(first), 'Client did not acquire SLAAC address')
    wait_for(lambda: any(r.get('dst') == 'default' and r.get('protocol') == 'ra'
                        for r in json.loads(nsrun(client, 'ip', '-j', '-6', 'route', 'show'))),
             'Client did not learn VPP default router')
    for target in ('2001:db8:4400:1::1', '2001:db8:45::2', 'fd42:1111:2222:10::2'):
        nsrun(client, 'ping', '-6', '-n', '-c', '3', '-W', '2', target)
    original = address_for(first)
    if nat66:
        nat66.verify(first, original)
    assert '2001:db8:4400:1::100-2001:db8:4400:1::200' in pool_config.read_text()
    if prepare_recovery:
        assert runtime is not None and nat66 is None
        runtime.update(publisher=publisher,pd_server=pd_server,ra_capture=ra_capture,first=first,
                       wan_address=wan_address,pool_ready=pool_ready,address_for=address_for)
        return {'native_dhcpv6_pd':True,'slaac_and_ra_default':True,
                'ipv6_wan_forwarding':True,'ipsec_pool_exact_range':True,
                'production_wan_untouched':True,'scope':'initial PD setup for joint restart; renumbering not rerun'}
    unchanged_time = pool_config.stat().st_mtime_ns
    start_events = len((root / 'ra-events.jsonl').read_text().splitlines())
    # Observe at least two further successful renewals after publication.
    renew_count = (root / 'pd-events.jsonl').read_text().count('"kind": 5')
    wait_for(lambda: (root / 'pd-events.jsonl').read_text().count('"kind": 5') >= renew_count + 2,
             'Did not observe repeated same-prefix renewals')
    assert pool_config.stat().st_mtime_ns == unchanged_time
    def renewed_public_ra():
        observed = [json.loads(line) for line in (root / 'ra-events.jsonl').read_text().splitlines()[start_events:]]
        return [event for event in observed if event['prefix'] == first and event['valid'] > 0]
    wait_for(renewed_public_ra, 'No public PIO observed after repeated renewals', seconds=8)
    public = renewed_public_ra()
    assert all(event['flags'] & 0xc0 == 0x40 for event in public), public
    assert not any(route['dst'] == first for route in json.loads(nsrun(client, 'ip', '-j', '-6', 'route', 'show')))

    second = '2001:db8:4400:2::/64'
    (root / 'pd-prefix').write_text(second)
    try:
        wait_for(lambda: lease(second), 'VPP did not apply changed prefix on Renew', seconds=18)
    except RuntimeError:
        print((root / 'pd-events.jsonl').read_text(), flush=True)
        print(cli('show ip6 prefixes'), flush=True)
        print(cli('show ip6 pd clients'), flush=True)
        print(cli('show interface address'), flush=True)
        raise
    wait_for(lambda: pool_ready(second), 'Automatic renumbered RA/pool publication failed')
    assert '2001:db8:4400:2::100-2001:db8:4400:2::200' in pool_config.read_text()
    assert '2001:db8:4400:1::100' not in pool_config.read_text()
    assert 'rightauth=eap-mschapv2' in pool_config.read_text()
    wait_for(lambda: address_for(second), 'Client did not acquire renewed SLAAC prefix')
    nsrun(client, 'ping', '-6', '-n', '-I', address_for(second), '-c', '3', '-W', '2', '2001:db8:45::2')
    assert original != address_for(second)
    def old_deprecated():
        addresses = json.loads(nsrun(client, 'ip', '-j', '-6', 'address', 'show', 'dev', 'mgmt0'))
        return all(addr.get('preferred_life_time') == 0 for link in addresses
                   for addr in link['addr_info'] if addr['local'] == original)
    wait_for(old_deprecated, 'Withdrawn SLAAC address is still preferred')
    nsrun(client, 'ping', '-6', '-n', '-c', '2', '-W', '2', '2001:db8:45::2')
    if nat66:
        nat66.verify(second, address_for(second))
    # A publisher restart must not withdraw an unchanged working pool.
    before_restart = pool_config.stat().st_mtime_ns
    publisher.terminate()
    publisher.wait(timeout=5)
    publisher = spawn(dns, 'python3', '/opt/vpp-vrouter-migration/source/scripts/vrouter/ipv6/pd-sync.py',
                      '--config', str(root / 'pd-sync.json'))
    time.sleep(1)
    assert publisher.poll() is None and pool_ready(second)
    assert pool_config.stat().st_mtime_ns == before_restart
    nsrun(client, 'ping', '-6', '-n', '-I', address_for(second), '-c', '2', '-W', '2', '2001:db8:45::2')
    (root / 'pd-prefix').write_text('none')
    wait_for(lambda: pool_ready(None), 'Withdrawn PD did not clear VPN pool')
    if nat66:
        nat66.withdrawn()
    assert 'rightsourceip=10.62.50.0/24\n' in pool_config.read_text()
    assert 'rightsourceip=10.62.20.0/24,fd01::/64' in pool_config.read_text()
    wait_for(lambda: any(json.loads(line)['prefix'] == second and json.loads(line)['valid'] > 0
                         and json.loads(line)['preferred'] == 0
                        for line in (root / 'ra-events.jsonl').read_text().splitlines()),
             'No deprecated RA for withdrawn prefix')
    (root / 'pd-prefix').write_text(first)
    wait_for(lambda: pool_ready(first), 'PD did not recover after withdrawal', seconds=20)
    nsrun(client, 'ping', '-6', '-n', '-I', address_for(first), '-c', '2', '-W', '2', '2001:db8:45::2')
    if nat66:
        nat66.verify(first, address_for(first))
    events = [json.loads(line) for line in (root / 'pd-events.jsonl').read_text().splitlines()]
    assert {1, 3, 5} <= {event['kind'] for event in events}, events
    if runtime is not None:
        runtime.update(publisher=publisher,pd_server=pd_server,ra_capture=ra_capture,first=first,
                       wan_address=wan_address,pool_ready=pool_ready,address_for=address_for)
    return {'native_dhcpv6_pd': True, 'solicit_request_renew': True,
            'slaac_and_ra_default': True, 'wan_slaac_and_ra_default': True, 'ipv6_wan_forwarding': True,
            'linux_dns_ula_reachable': True, 'prefix_change': [first, second],
            'ra_prefix_update': 'automatic daemon', 'pd_renewal_keeps_offlink_pio': True,
            'unchanged_pool_not_rewritten': True, 'ipsec_pool_exact_range': True,
            'publisher_restart': True, 'withdrawal_and_recovery': True,
            'withdrawn_slaac_deprecated': True, 'automatic_source_selection': True,
            'production_wan_untouched': True, **({'nat66': nat66.result()} if nat66 else {})}


if __name__ == '__main__':
    assert sys.argv[1] in ('--serve', '--capture')
    (serve if sys.argv[1] == '--serve' else capture)(Path(sys.argv[2]))
