#!/usr/bin/env python3
"""Temporary production NAT benchmark: VROUTER nic1 <-> peer eno1 (2.5 GbE).

Root/Linux only. Copy to /run/vrouter-nic1-nat-bench/tool.py on both machines.
Set up peer and router, run router benchmark, then clean router before peer.
Independent timers restore both ends if the controller disappears.
"""
import argparse
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import time

ROOT = Path('/run/vrouter-nic1-nat-bench')
STATE = ROOT/'state.json'
TOOL = ROOT/'tool.py'
RESULT = Path('/var/tmp/vrouter-nic1-nat-benchmark-20261029.json')
LAN = 'vrouter-nic1-perf-lan'
WAN = 'vrouter-nic1-perf-wan'
TARGET = '172.31.246.2'
POOL = '172.31.246.1'
TABLE = 166


def run(*args, check=True, timeout=30):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('Command failed: '+repr(args)+' '+p.stderr[-600:]+p.stdout[-600:])
    return p.stdout.strip()


def cli(command, check=True):
    out = run('/usr/local/bin/vppctl', command, check=check)
    pattern = r'unknown input' if command.startswith('show ') else r'unknown input|error:|failed|invalid|already exist'
    if check and re.search(pattern, out, re.I):
        raise RuntimeError('VPP rejected '+command+': '+out)
    return out


def save(path, value):
    tmp = path.with_name(path.name+'.new')
    tmp.write_text(json.dumps(value, indent=2)+'\n')
    tmp.chmod(0o600)
    tmp.replace(path)


def arm(role):
    run('systemd-run', '--unit=vrouter-nic1-bench-restore',
        '--on-active='+('25m' if role == 'router' else '26m'),
        '--timer-property=AccuracySec=1s', '/usr/bin/python3', TOOL, role, 'cleanup')


def unused_address(namespace, device, address):
    # ARP duplicate-address detection, also used by integration_nat44_ei_live.py.
    program = r'''
import socket,struct,time,sys
device,address=sys.argv[1:]
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x806))
s.bind((device,0));s.settimeout(.1);mac=s.getsockname()[4];target=socket.inet_aton(address)
frame=b'\xff'*6+mac+b'\x08\x06'+struct.pack('!HHBBH',1,0x800,6,4,1)+mac+b'\0'*4+b'\0'*6+target
for _ in range(3):
 s.send(frame);end=time.monotonic()+.3
 while time.monotonic()<end:
  try:d=s.recv(2048)
  except socket.timeout:continue
  if len(d)>=42 and d[28:32]==target:raise RuntimeError('test address occupied')
'''
    run('ip', 'netns', 'exec', namespace, 'python3', '-c', program, device, address)


def setup(role, lan_client, lan_gateway, peer_management_interface):
    if STATE.exists():
        raise RuntimeError('An existing test must be cleaned first')
    assert (LAN if role == 'router' else WAN) not in run('ip', 'netns', 'list')
    if role == 'router':
        assert not run('ip', 'link', 'show', 'vrouter-perf-br', check=False)
    if role == 'router':
        baseline = cli('show bridge-domain 200 detail')
        assert 'nic1-dpdk' in baseline
        assert 'loop166' not in cli('show interface')
        assert '172.31.246.' not in cli('show interface address')
        source = str(lan_client.ip)
        assert source not in run('ip', 'neigh', 'show', 'dev', 'br-mgmt')
        state = dict(role=role, source=source, bridge_domain=200, mtu=2026,
                     bridge_before=baseline, startup_sha=run('sha256sum', '/etc/vpp/startup.conf'))
    else:
        state = dict(role=role, uuid=run('nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', 'eno1'),
                     ipv4_before=json.loads(run('ip', '-j', '-4', 'addr', 'show', 'eno1')))
        assert state['uuid']
        assert peer_management_interface != 'eno1', 'management must use a separate interface'
        assert run('ip', '-o', '-4', 'addr', 'show', 'dev', peer_management_interface,
                   'scope', 'global'), 'peer management interface has no global IPv4 address'
    save(STATE, state)
    arm(role)
    try:
        if role == 'peer':
            run('ip', 'netns', 'add', WAN)
            run('nmcli', 'device', 'set', 'eno1', 'managed', 'no')
            run('ip', 'link', 'set', 'eno1', 'netns', WAN)
            run('ip', '-n', WAN, 'addr', 'flush', 'dev', 'eno1')
            run('ip', '-n', WAN, 'link', 'set', 'lo', 'up')
            run('ip', '-n', WAN, 'addr', 'add', TARGET+'/30', 'dev', 'eno1')
            run('ip', '-n', WAN, 'link', 'set', 'eno1', 'up')
            run('ip', '-n', WAN, 'route', 'add', 'default', 'via', POOL)
            for suffix, args in [('iperf', ['/usr/bin/iperf3', '-s', '-B', TARGET, '-p', '55201']),
                                 ('echo', ['/usr/bin/python3', str(TOOL), 'peer', 'echo']),
                                 ('accept', ['/usr/bin/python3', str(TOOL), 'peer', 'accept'])]:
                run('systemd-run', '--unit=vrouter-nic1-bench-'+suffix, '--property=RuntimeMaxSec=1500',
                    '/usr/sbin/ip', 'netns', 'exec', WAN, *args)
        else:
            run('ip', 'netns', 'add', LAN)
            run('ip', '-n', LAN, 'link', 'set', 'lo', 'up')
            run('ip', 'link', 'add', 'vrouter-perf-br', 'type', 'veth', 'peer', 'name', 'vrouter-perf-cli')
            run('ip', 'link', 'set', 'vrouter-perf-cli', 'netns', LAN)
            run('ip', '-n', LAN, 'link', 'set', 'vrouter-perf-cli', 'name', 'mgmt0')
            run('ip', 'link', 'set', 'vrouter-perf-br', 'master', 'br-mgmt')
            run('ip', 'link', 'set', 'vrouter-perf-br', 'up')
            run('ip', '-n', LAN, 'link', 'set', 'mgmt0', 'up')
            unused_address(LAN, 'mgmt0', source)
            state['lan_test_mac'] = json.loads(run('ip', '-n', LAN, '-j', 'link', 'show', 'mgmt0'))[0]['address']
            save(STATE, state)
            run('ip', '-n', LAN, 'addr', 'add', str(lan_client), 'dev', 'mgmt0')
            run('ip', '-n', LAN, 'route', 'add', 'default', 'via', lan_gateway)
            for cmd in ['set interface l3 nic1-dpdk',
                        'set interface mtu packet 1500 nic1-dpdk',
                        f'set interface ip address nic1-dpdk {POOL}/30',
                        f'ip table add {TABLE}', 'create loopback interface instance 166',
                        f'set interface ip table loop166 {TABLE}', 'set interface state loop166 up',
                        f'ip route add 0.0.0.0/0 table {TABLE} via ip4-lookup-in-table 0',
                        f'nat44 ei add address {POOL} tenant-vrf {TABLE}',
                        'set interface nat44 ei out nic1-dpdk output-feature',
                        'nat44 ei context nic1-dpdk loop166']:
                cli(cmd)
        print('SETUP OK', role, flush=True)
    except BaseException:
        cleanup(role)
        raise


def cleanup(role):
    if not STATE.exists():
        print('No test state to clean')
        return
    state = json.loads(STATE.read_text())
    assert state['role'] == role
    errors = []
    if role == 'peer':
        for suffix in ('iperf', 'echo', 'accept', 'monitor'):
            run('systemctl', 'stop', 'vrouter-nic1-bench-'+suffix+'.service', check=False)
        if WAN in run('ip', 'netns', 'list'):
            run('ip', 'netns', 'exec', WAN, 'ip', 'addr', 'flush', 'dev', 'eno1', check=False)
            run('ip', 'netns', 'exec', WAN, 'ip', 'link', 'set', 'eno1', 'netns', '1')
            run('ip', 'netns', 'delete', WAN)
        run('nmcli', 'device', 'set', 'eno1', 'managed', 'yes')
        run('nmcli', 'connection', 'up', 'uuid', state['uuid'], 'ifname', 'eno1', timeout=90)
    else:
        source = state.get('source')
        if source is None and LAN in run('ip', 'netns', 'list'):
            # A restore timer may still reference state written by the previous script.
            output = run('ip', '-n', LAN, '-j', '-4', 'addr', 'show', 'dev', 'mgmt0', check=False)
            addresses = json.loads(output or '[]')
            source = next((addr['local'] for link in addresses for addr in link['addr_info']), None)
        users = ([source] if source else []) + state.get('extra_sources', [])
        mappings = [f'nat44 ei add static mapping udp local {item["local"]} {item["port"]} external {POOL} {item["port"]} vrf {TABLE} del'
                    for item in state.get('static_mappings', [])]
        for cmd in [*mappings, *[f'nat44 ei del user {source} fib {TABLE}' for source in users],
                    'nat44 ei context nic1-dpdk loop166 del',
                    'set interface nat44 ei out nic1-dpdk output-feature del',
                    f'nat44 ei add address {POOL} tenant-vrf {TABLE} del',
                    f'ip route del 0.0.0.0/0 table {TABLE} via ip4-lookup-in-table 0',
                    'delete loopback interface intfc loop166',
                    f'ip table del {TABLE}',
                    f'set interface ip address del nic1-dpdk {POOL}/30',
                    'set interface mtu packet 2026 nic1-dpdk',
                    'set interface l2 bridge nic1-dpdk 200']:
            try:
                out = cli(cmd, check=False)
                if out:
                    errors.append({'command': cmd, 'output': out})
            except Exception as exc:
                errors.append({'command': cmd, 'error': str(exc)})
        if LAN in run('ip', 'netns', 'list'):
            for pid in run('ip', 'netns', 'pids', LAN).split():
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
            run('ip', 'netns', 'delete', LAN)
        run('ip', 'link', 'delete', 'vrouter-perf-br', check=False)
        if state.get('lan_test_mac'):
            if source:
                cli(f'set ip neighbor del loop200 {source} {state["lan_test_mac"]}', check=False)
            cli(f'l2fib del {state["lan_test_mac"]} 200', check=False)
        assert 'nic1-dpdk' in cli('show bridge-domain 200 detail')
        assert POOL not in cli('show interface address')
        assert 'loop166' not in cli('show interface')
        assert POOL not in cli('show nat44 ei addresses')
        assert state['startup_sha'] == run('sha256sum', '/etc/vpp/startup.conf')
    run('systemctl', 'stop', 'vrouter-nic1-bench-restore.timer', check=False)
    save(ROOT/'cleanup.json', dict(role=role, diagnostics=errors, restored_at=time.time()))
    STATE.unlink()
    print('CLEANUP OK', role, json.dumps(errors), flush=True)


def echo_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((TARGET, 46090))
        while True:
            data, peer = s.recvfrom(2048)
            s.sendto(json.dumps({'peer': peer, 'payload': data.decode()}).encode(), peer)


def accept_server():
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((TARGET, 55202))
        s.listen(8192)
        while True:
            conn, _ = s.accept()
            conn.close()


def snapshot():
    return dict(timestamp=time.time(), interface=cli('show interface nic1-dpdk'),
                hardware=cli('show hardware-interfaces nic1-dpdk detail'),
                errors=cli('show errors'), runtime=cli('show runtime'))


def monitor_peer():
    result = dict(start=time.time(), before_driver=run('ip', 'netns', 'exec', WAN, 'ethtool', '-S', 'eno1'), samples=[])
    path = Path('/var/tmp/vrouter-nic1-peer-metrics-20261029.json')
    try:
        for _ in range(900):
            lines = run('ip', 'netns', 'exec', WAN, 'cat', '/proc/net/snmp').splitlines()
            udp = [line.split()[1:] for line in lines if line.startswith('Udp:')]
            result['samples'].append(dict(time=time.time(), udp=dict(zip(udp[0], map(int, udp[1]))),
                link=json.loads(run('ip', '-n', WAN, '-s', '-j', 'link', 'show', 'eno1'))))
            save(path, result)
            time.sleep(1)
    finally:
        result.update(end=time.time(), after_driver=run('ip', 'netns', 'exec', WAN, 'ethtool', '-S', 'eno1', check=False))
        save(path, result)


def benchmark():
    state = json.loads(STATE.read_text())
    assert state['role'] == 'router'
    probe = '''import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
s.sendto(b'physical-nat-proof',('172.31.246.2',46090))
d=json.loads(s.recv(4096));assert d['peer'][0]=='172.31.246.1',d;print(json.dumps(d))'''
    proof = json.loads(run('ip', 'netns', 'exec', LAN, 'python3', '-c', probe))
    data = dict(start=time.time(), topology='LAN netns -> br-mgmt/TAP -> production VPP NAT44-EI -> nic1 -> physical eno1 WAN netns',
                pool=POOL, inside_vrf=TABLE, proof=proof, results=[])
    save(RESULT, data)
    scenarios = [('tcp', 0, 0, parallel, reverse) for reverse in (False, True) for parallel in (1, 4, 16)]
    scenarios += [('udp', size, rate, 1, reverse) for size, rates in
                  [(1400, [500, 1000, 1500, 2000, 2350]), (512, [500, 1000, 2000]),
                   (18, [10, 25, 50, 75, 100, 150])]
                  for reverse in (False, True) for rate in rates]
    for proto, size, rate, parallel, reverse in scenarios:
        cmd = ['ip', 'netns', 'exec', LAN, 'taskset', '-c', '6,7', 'iperf3', '-4',
               '-c', TARGET, '-p', '55201', '-B', state['source'], '-t', '6' if proto == 'tcp' else '5',
               '-P', str(parallel), '-J']
        if reverse:
            cmd.append('-R')
        if proto == 'udp':
            cmd += ['-u', '-b', str(rate)+'M', '-l', str(size), '--udp-counters-64bit']
        before = snapshot()
        try:
            raw = json.loads(run(*cmd, timeout=25))
        except Exception as exc:
            raw = {'error': str(exc)}
        item = dict(protocol=proto, payload_bytes=size, target_mbps=rate,
                    streams=parallel, reverse=reverse, before=before, after=snapshot(), raw=raw)
        data['results'].append(item)
        save(RESULT, data)
        end = raw.get('end', {})
        receiver = end.get('sum_received', end.get('sum', {}))
        print(json.dumps(dict(protocol=proto, payload_bytes=size, target_mbps=rate, streams=parallel,
                              reverse=reverse, received_mbps=receiver.get('bits_per_second', 0)/1e6,
                              loss_percent=receiver.get('lost_percent'), error=raw.get('error'))), flush=True)
        if raw.get('error'):
            raise RuntimeError('Benchmark scenario failed; results saved')
        time.sleep(.3)
    cps = r'''
import asyncio,time,json
async def main():
 ok=0; start=time.monotonic()
 async def connect():
  try:
   _,w=await asyncio.wait_for(asyncio.open_connection('172.31.246.2',55202),2)
   w.close();await w.wait_closed();return 1
  except Exception:return 0
 for _ in range(50):ok+=sum(await asyncio.gather(*(connect() for _ in range(100))))
 elapsed=time.monotonic()-start;print(json.dumps({'attempts':5000,'success':ok,'seconds':elapsed,'cps':ok/elapsed}))
asyncio.run(main())
'''
    data['cps'] = json.loads(run('ip', 'netns', 'exec', LAN, 'taskset', '-c', '6,7', 'python3', '-c', cps, timeout=120))
    data['end'] = time.time()
    save(RESULT, data)
    print('BENCHMARK COMPLETE', json.dumps(data['cps']), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['router', 'peer'])
    parser.add_argument('action', choices=['setup', 'cleanup', 'benchmark', 'echo', 'accept', 'monitor', 'snapshot'])
    parser.add_argument('--lan-client', type=ipaddress.IPv4Interface, help='Temporary LAN address and prefix')
    parser.add_argument('--lan-gateway', type=ipaddress.IPv4Address)
    parser.add_argument('--peer-management-interface', help='Independent Linux management interface on the peer')
    args = parser.parse_args()
    if args.action == 'setup':
        if args.role == 'router' and (args.lan_client is None or args.lan_gateway is None):
            parser.error('router setup requires --lan-client and --lan-gateway')
        if args.role == 'peer' and not args.peer_management_interface:
            parser.error('peer setup requires --peer-management-interface')
    assert os.geteuid() == 0
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    if args.action == 'setup':
        setup(args.role, args.lan_client, args.lan_gateway, args.peer_management_interface)
    elif args.action == 'cleanup':
        cleanup(args.role)
    elif args.action == 'benchmark':
        assert args.role == 'router'
        benchmark()
    elif args.action == 'echo':
        echo_server()
    elif args.action == 'monitor':
        monitor_peer()
    elif args.action == 'snapshot':
        print('BENCH_SNAPSHOT'+json.dumps(snapshot()), flush=True)
    else:
        accept_server()


if __name__ == '__main__':
    main()
