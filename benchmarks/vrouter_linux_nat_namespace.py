#!/usr/bin/env python3
"""Create a dedicated LAN receiver namespace on the unused second mlx5 port.

Run as root on the Linux benchmark host. No VROUTER or management-port changes.
The namespace is transient; teardown restores the port and NetworkManager state.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time

NS = 'vrouter-nat-rx'
NIC = 'enp3s0f1'
STATE = Path('/run/vrouter-nat-rx.json')
HOOK = Path('/run/vrouter-nat-rx-dhcp-hook.py')
LEASE = Path('/run/vrouter-nat-rx-lease.json')
UNIT = 'vrouter-nat-rx-dhcp.service'


def run(*args, check=True, text_input=None):
    return subprocess.run(args, check=check, text=True, input=text_input, capture_output=True).stdout.strip()


def receiver_irqs():
    result={}
    for line in Path('/proc/interrupts').read_text().splitlines():
        if 'mlx5_comp' in line and '0000:b0:00.1' in line:
            irq=int(line.split(':',1)[0])
            result[line.split()[-1]]=Path(f'/proc/irq/{irq}/smp_affinity_list')
    if not result:
        raise RuntimeError('Receiver interrupts not found')
    return result


def tune():
    state=json.loads(STATE.read_text())
    if 'tuning' in state:
        raise RuntimeError('Receiver already tuned')
    prefix=['ip','netns','exec',NS]
    rings=run(*prefix,'ethtool','-g',NIC)
    rx=int(re.search(r'^RX:\s+(\d+)',rings.split('Current hardware settings:')[1],re.M)[1])
    state['tuning']={'rx':rx,'affinities':{name:path.read_text().strip() for name,path in receiver_irqs().items()}}
    STATE.write_text(json.dumps(state,indent=2)+'\n')
    try:
        run(*prefix,'ethtool','-G',NIC,'rx','8192')
        for path in receiver_irqs().values():
            path.write_text('5')
        address=state['lease']['address']
        # ETH_P_ALL packet taps run before netdev ingress. Skip the IP/UDP
        # stack after the sequence receiver has observed the test packet.
        rules=('add table netdev vrouter_capture\n'
               f'add chain netdev vrouter_capture ingress {{ type filter hook ingress device "{NIC}" priority -500; policy accept; }}\n'
               f'add rule netdev vrouter_capture ingress ip saddr 203.0.113.10 ip daddr {address} udp sport 50000 udp dport 45996 counter drop\n')
        run(*prefix,'nft','-f','-',text_input=rules)
        return state
    except Exception:
        untune()
        raise


def untune():
    state=json.loads(STATE.read_text())
    settings=state.get('tuning')
    if not settings:
        return state
    prefix=['ip','netns','exec',NS]
    run(*prefix,'nft','delete','table','netdev','vrouter_capture',check=False)
    run(*prefix,'ethtool','-G',NIC,'rx',str(settings['rx']))
    for name,path in receiver_irqs().items():
        if name in settings['affinities']:
            path.write_text(settings['affinities'][name])
    del state['tuning']
    STATE.write_text(json.dumps(state,indent=2)+'\n')
    return state


def teardown():
    if not STATE.exists():
        return {'status': 'absent'}
    state = json.loads(STATE.read_text())
    run('systemctl', 'stop', 'vrouter-nat-rx-capture.service', 'vrouter-nat-rx-dpdk.service', UNIT, check=False)
    if 'tuning' in state:
        untune()
    if run('ip', 'netns', 'list').splitlines():
        if any(line.split()[0] == NS for line in run('ip', 'netns', 'list').splitlines()):
            # DHCP is stopped; no address or route from the namespace is retained.
            run('ip', '-n', NS, '-4', 'addr', 'flush', 'dev', NIC, check=False)
            run('ip', '-n', NS, 'link', 'set', NIC, 'down', check=False)
            run('ip', '-n', NS, 'link', 'set', NIC, 'netns', '1', check=False)
            run('ip', 'netns', 'del', NS)
    run('ethtool', '-K', NIC, 'gro', state['gro'])
    run('ip', 'link', 'set', NIC, 'up' if state['up'] else 'down')
    run('nmcli', 'device', 'set', NIC, 'managed', state['nm_managed'])
    STATE.unlink()
    return {'status': 'restored', 'interface': NIC}


def setup():
    if STATE.exists() or any(line.split()[0] == NS for line in run('ip', 'netns', 'list').splitlines()):
        raise RuntimeError('Existing receiver state/namespace; inspect or teardown first')
    addresses = json.loads(run('ip', '-j', 'addr', 'show', 'dev', NIC))[0]
    if addresses['addr_info']:
        raise RuntimeError('Receiver port already has addresses')
    driver = run('ethtool', '-i', NIC)
    if 'driver: mlx5_core' not in driver or 'bus-info: 0000:b0:00.1' not in driver:
        raise RuntimeError('Unexpected receiver hardware')
    if 'Link detected: yes' not in run('ethtool', NIC):
        raise RuntimeError('LAN receiver link is down')
    state = dict(interface=NIC, namespace=NS, mac=addresses['address'],
                 up='UP' in addresses['flags'],
                 nm_managed=run('nmcli', '-g', 'GENERAL.NM-MANAGED', 'device', 'show', NIC),
                 gro=re.search(r'^generic-receive-offload: (on|off)', run('ethtool', '-k', NIC), re.M)[1])
    if run('nmcli', '-g', 'GENERAL.CONNECTION', 'device', 'show', NIC):
        raise RuntimeError('Receiver has an active NetworkManager connection')
    STATE.write_text(json.dumps(state, indent=2)+'\n')
    STATE.chmod(0o600)
    try:
        run('nmcli', 'device', 'set', NIC, 'managed', 'no')
        run('ip', 'netns', 'add', NS)
        run('ip', 'link', 'set', NIC, 'netns', NS)
        run('ip', '-n', NS, 'link', 'set', 'lo', 'up')
        run('ip', 'netns', 'exec', NS, 'sysctl', '-q', '-w', 'net.ipv6.conf.all.disable_ipv6=1')
        run('ip', '-n', NS, 'link', 'set', NIC, 'up')
        run('ip', 'netns', 'exec', NS, 'ethtool', '-K', NIC, 'gro', 'off')
        HOOK.write_text('''#!/usr/bin/python3
import ipaddress,json,os,subprocess,sys
from pathlib import Path
interface=os.environ['interface']
if sys.argv[1]=='deconfig':
 subprocess.run(['ip','-4','addr','flush','dev',interface],check=True)
elif sys.argv[1] in ('bound','renew'):
 address=ipaddress.IPv4Address(os.environ['ip'])
 prefix=ipaddress.IPv4Network('0.0.0.0/'+os.environ['subnet']).prefixlen
 gateway=ipaddress.IPv4Address(os.environ['router'].split()[0])
 subprocess.run(['ip','addr','replace',str(address)+'/'+str(prefix),'dev',interface],check=True)
 subprocess.run(['ip','route','replace','default','via',str(gateway),'dev',interface],check=True)
 Path('/run/vrouter-nat-rx-lease.json').write_text(json.dumps(dict(address=str(address),prefix=prefix,gateway=str(gateway),lease_seconds=os.environ.get('lease')))+'\\n')
''')
        HOOK.chmod(0o700)
        LEASE.unlink(missing_ok=True)
        run('systemd-run', '--unit=vrouter-nat-rx-dhcp', '--property=Restart=no',
            '/usr/sbin/ip', 'netns', 'exec', NS, '/usr/bin/busybox', 'udhcpc',
            '-f', '-n', '-t', '5', '-T', '2', '-i', NIC, '-s', str(HOOK))
        deadline = time.monotonic()+25
        while not LEASE.exists() and time.monotonic()<deadline:
            time.sleep(0.2)
        if not LEASE.exists():
            raise RuntimeError('No DHCP lease; inspect DHCP unit journal')
        lease = json.loads(LEASE.read_text())
        if not lease['address'].startswith('10.61.20.') or lease['gateway'] != '10.61.20.1':
            raise RuntimeError('Receiver port is not on the expected VROUTER LAN')
        state['lease'] = lease
        STATE.write_text(json.dumps(state, indent=2)+'\n')
        run('ip', 'netns', 'exec', NS, 'ping', '-c', '3', '-W', '2', '10.61.20.1')
        return state
    except Exception:
        teardown()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['setup', 'status', 'tune', 'untune', 'teardown'])
    args = parser.parse_args()
    if os.geteuid()!=0:
        parser.error('Run as root on Linux benchmark host')
    if args.action=='setup':
        result=setup()
    elif args.action=='tune':
        result=tune()
    elif args.action=='untune':
        result=untune()
    elif args.action=='teardown':
        result=teardown()
    else:
        result=json.loads(STATE.read_text()) if STATE.exists() else {'status':'absent'}
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
