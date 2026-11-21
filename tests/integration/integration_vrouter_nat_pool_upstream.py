#!/usr/bin/env python3
"""Probe an unused pool IP through the real Linux WAN; never bind nic0 to VPP."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time


def run(*args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=25)
    if result.returncode:
        raise RuntimeError('upstream probe subprocess failed: '+str(args[0]))
    return result.stdout


def address_conflict(parent, address):
    target = socket.inet_aton(address)
    mac = bytes.fromhex(Path('/sys/class/net', parent, 'address').read_text().strip().replace(':', ''))
    frame = (b'\xff'*6+mac+b'\x08\x06'+struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)+
             mac+b'\x00'*4+b'\x00'*6+target)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as sock:
        sock.bind((parent, 0))
        sock.settimeout(.1)
        for _ in range(3):
            sock.send(frame)
            deadline = time.monotonic()+.4
            while time.monotonic() < deadline:
                try:
                    packet = sock.recv(2048)
                    if len(packet) >= 42 and packet[12:14] == b'\x08\x06' and packet[28:32] == target:
                        return True
                except TimeoutError:
                    pass
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', default='wan')
    parser.add_argument('--pool', required=True, help='Unused IPv4 address on the WAN subnet')
    parser.add_argument('--gateway', required=True, help='IPv4 gateway on the WAN subnet')
    parser.add_argument('--dns', default='119.29.29.29')
    parser.add_argument('--url', default='https://www.baidu.com/')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on the Linux VROUTER baseline')
    if subprocess.run(['pgrep', '-x', 'vpp'], capture_output=True).returncode == 0:
        raise RuntimeError('VPP already running; refusing pool-address probe')
    pool, gateway = ipaddress.IPv4Address(args.pool), ipaddress.IPv4Address(args.gateway)
    ipaddress.IPv4Address(args.dns)
    parent = json.loads(run('ip', '-j', '-4', 'addr', 'show', 'dev', args.parent))[0]
    candidates = [ipaddress.IPv4Interface(f'{a["local"]}/{a["prefixlen"]}')
                  for a in parent['addr_info'] if a['family'] == 'inet']
    candidates = [a for a in candidates if pool in a.network and gateway in a.network]
    if len(candidates) != 1 or pool == candidates[0].ip or pool == gateway:
        raise ValueError('pool and gateway must be distinct addresses on the existing WAN subnet')
    for link in json.loads(run('ip', '-j', '-4', 'addr', 'show')):
        if any(a.get('local') == str(pool) for a in link.get('addr_info', [])):
            raise ValueError('pool already assigned locally')
    namespace, link_name = 'vrouter-pool-upstream', 'vrouter-pool-probe'
    resolver_dir = Path('/etc/netns', namespace)
    if namespace in run('ip', 'netns', 'list').split() or resolver_dir.exists():
        raise ValueError('reserved probe namespace or resolver directory exists')
    if Path('/sys/class/net', link_name).exists():
        raise ValueError('reserved macvlan exists')
    if address_conflict(args.parent, str(pool)):
        raise ValueError('ARP address conflict observed; no namespace created')
    os.umask(0o077)
    created = False
    resolver_created = False
    try:
        run('ip', 'netns', 'add', namespace)
        created = True
        run('ip', 'link', 'add', 'link', args.parent, 'name', link_name, 'type', 'macvlan', 'mode', 'bridge')
        run('ip', 'link', 'set', link_name, 'netns', namespace)
        run('ip', '-n', namespace, 'link', 'set', link_name, 'name', 'mgmt0')
        run('ip', '-n', namespace, 'addr', 'add', f'{pool}/{candidates[0].network.prefixlen}', 'dev', 'mgmt0')
        for dev in ('lo', 'mgmt0'):
            run('ip', '-n', namespace, 'link', 'set', dev, 'up')
        run('ip', '-n', namespace, 'route', 'add', 'default', 'via', str(gateway), 'dev', 'mgmt0')
        resolver_dir.mkdir(parents=True, mode=0o700)
        resolver_created = True
        (resolver_dir/'resolv.conf').write_text(f'nameserver {args.dns}\noptions timeout:2 attempts:2\n')
        dns = r'''import socket,struct,sys,json
ident=19347
q=struct.pack('!6H',ident,0x100,1,0,0,0)+b'\x03www\x05baidu\x03com\x00'+struct.pack('!HH',1,1)
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
 s.settimeout(5);s.connect((sys.argv[1],53));s.send(q);data=s.recv(65535)
 answer_id,flags,_,answers,_,_=struct.unpack_from('!6H',data)
 assert answer_id==ident and flags&0x8000 and flags&15==0 and answers>0
 print(json.dumps({'local_ip':s.getsockname()[0],'rcode':flags&15,'answers':answers}))
'''
        dns_result = json.loads(run('ip', 'netns', 'exec', namespace, 'python3', '-c', dns, args.dns))
        assert dns_result['local_ip'] == str(pool), dns_result
        curl = ['curl', '-4', '--noproxy', '*', '--connect-timeout', '5', '--max-time', '15',
                '--silent', '--show-error', '--output', '/dev/null', '--write-out',
                '{"http_code":%{http_code},"local_ip":"%{local_ip}","remote_ip":"%{remote_ip}","ssl_verify_result":%{ssl_verify_result}}']
        baseline = json.loads(run(*curl, '--interface', args.parent, args.url))
        candidate = json.loads(run('ip', 'netns', 'exec', namespace, *curl, args.url))
        for result, expected in ((baseline, str(candidates[0].ip)), (candidate, str(pool))):
            assert result['local_ip'] == expected and result['ssl_verify_result'] == 0, result
            assert 100 <= result['http_code'] < 600, result
        neighbors = json.loads(run('ip', '-j', '-n', namespace, 'neigh', 'show', 'to', str(gateway)))
        assert len(neighbors) == 1 and neighbors[0].get('lladdr'), neighbors
        print(json.dumps({'pool':str(pool), 'arp_conflict_observed':False,
                          'gateway_arp_resolved':True, 'udp_dns':dns_result,
                          'baseline_https':baseline, 'pool_https':candidate,
                          'uses_vpp':False, 'uses_new_macvlan_mac':True,
                          'physical_vpp_cutover_verified':False}))
    finally:
        if created:
            subprocess.run(['ip', 'netns', 'delete', namespace], capture_output=True)
        if Path('/sys/class/net', link_name).exists():
            subprocess.run(['ip', 'link', 'delete', link_name], capture_output=True)
        if resolver_created:
            shutil.rmtree(resolver_dir)


if __name__ == '__main__':
    main()
