#!/usr/bin/env python3
"""IPv6 DNS discovery and transport checks over the existing LAN/DNS TAP."""
import ipaddress
import fcntl
import json
import os
import socket
import struct
import sys
import subprocess
import time

DNS = 'fd42:1111:2222:10::2'


def information_request():
    index = socket.if_nametoindex('mgmt0')
    transaction = os.urandom(3)
    def option(kind, data):
        return struct.pack('!HH', kind, len(data)) + data
    identity = b'\x00\x03\x00\x01\x02\x00\x00\x00\x44\x01'
    message = b'\x0b' + transaction + option(1, identity) + option(6, struct.pack('!H', 23))
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        sock.bind(('::', 546))
        sock.sendto(message, ('ff02::1:2', 547, 0, index))
        while True:
            data, peer = sock.recvfrom(8192)
            if data[:4] != b'\x07' + transaction:
                continue
            fields = {}
            pos = 4
            while pos + 4 <= len(data):
                kind, size = struct.unpack('!HH', data[pos:pos+4])
                fields[kind] = data[pos+4:pos+4+size]
                pos += 4+size
            assert fields[1] == identity and fields[2]
            servers = [socket.inet_ntop(socket.AF_INET6, fields[23][pos:pos+16])
                       for pos in range(0, len(fields[23]), 16)]
            assert servers == [DNS], servers
            print(json.dumps({'servers': servers, 'server': peer[0]}))
            return


def check(root, names, nsrun, cli, wait_for, query):
    client, dns, _ = names
    result = json.loads(nsrun(client, 'python3', '/opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipv6_dns.py', '--dhcp'))
    addresses = json.loads(nsrun(dns, 'ip', '-j', '-6', 'address', 'show', 'dev', 'br-mgmt'))
    linux_link = next(a['local'] for link in addresses for a in link['addr_info'] if a['scope'] == 'link')
    assert all(not ipaddress.IPv6Address(a['local']) in ipaddress.IPv6Network('2001:db8:4400::/56')
               for link in addresses for a in link['addr_info'])
    def routers():
        return [json.loads(line) for line in (root / 'ra-router-events.jsonl').read_text().splitlines()]
    wait_for(lambda: any(event['source'] == linux_link and DNS in event['rdnss'] for event in routers()),
             'Linux RA did not publish DNS RDNSS')
    linux = [event for event in routers() if event['source'] == linux_link]
    assert linux and all(event['lifetime'] == 0 and event['flags'] & 0x40 for event in linux), linux
    defaults = json.loads(nsrun(client, 'ip', '-j', '-6', 'route', 'show', 'default'))
    assert defaults and all(route.get('gateway') != linux_link for route in defaults)
    pios = [json.loads(line) for line in (root / 'ra-events.jsonl').read_text().splitlines()]
    assert all(event['prefix'] == 'fd42:1111:2222:10::/64'
               for event in pios if event['source'] == linux_link)
    for mode, target in (('udp', '2001:db8:2080::77'), ('tcp', '2001:db8:2080::78')):
        assert target + '/128' not in cli('show ip6 fib table 0 ' + target + '/128')
        if mode == 'udp':
            with (root / 'import.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                process = subprocess.Popen(['ip', 'netns', 'exec', client, 'python3', '-c', query,
                                            mode + '.six.test', mode, 'ok', DNS, '28'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    wait_for(lambda: target in nsrun(dns, 'nft', 'list', 'set', 'inet', 'vrouter_lan_dns', 'proxylist6'),
                             'DNS query did not reach dnsmasq', seconds=2)
                    time.sleep(.2)
                    assert process.poll() is None, 'IPv6 DNS answered before route installation'
                    fcntl.flock(lock, fcntl.LOCK_UN)
                    output, error = process.communicate(timeout=5)
                    assert process.returncode == 0, error
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=2)
        else:
            nsrun(client, 'python3', '-c', query, mode + '.six.test', mode, 'ok', DNS, '28')
        fib = cli('show ip6 fib table 0 ' + target + '/128')
        assert target + '/128' in fib and DNS in fib and 'loop3950' in fib
        nsrun(client, 'python3', '-c', query, 'a.altroute.test', mode, 'ok', DNS, '1')
    return {'dhcpv6_information_request': result, 'rdnss_fixed_ula': True,
            'linux_ra_no_default_router': True, 'linux_no_public_pio': True,
            'udp_tcp_ipv6_dns': True, 'aaaa_nft_to_binary_api_route': True, 'ipv6_answer_waits_for_route_ack': True}


if __name__ == '__main__':
    assert sys.argv[1] == '--dhcp'
    information_request()
