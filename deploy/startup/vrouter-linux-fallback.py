#!/usr/bin/env python3
"""Recover basic IPv4 routing after repeated VPP failure on this VROUTER."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

STATE = Path('/var/lib/vpp-vrouter/linux-fallback')
LATCH = STATE / 'active'
WAN = 'vrouter-fb-wan'
VPS = 'vrouter-fb-vps'
BRIDGE = 'br-mgmt'
DEVICES = {'nic1': '0000:02:00.0', 'nic0': '0000:01:00.0'}


def run(*args, check=True, input=None):
    p = subprocess.run(list(map(str, args)), input=input, capture_output=True,
                       text=True, timeout=60)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr.strip() or p.stdout.strip()}')
    return p


def exists(dev):
    return Path('/sys/class/net', dev).exists()


def nft_exists(*args):
    return run('nft', 'list', *args, check=False).returncode == 0


def remove_nft(family, table):
    if nft_exists('table', family, table):
        run('nft', 'delete', 'table', family, table)


def announce_gateway():
    mac = bytes.fromhex(Path('/sys/class/net', BRIDGE, 'address').read_text().strip().replace(':', ''))
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as sock:
        sock.bind((BRIDGE, 0))
        for address in ('10.61.20.1', '10.61.20.2'):
            ip = socket.inet_aton(address)
            packet = (b'\xff' * 6 + mac + b'\x08\x06' +
                      struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
                      mac + ip + b'\xff' * 6 + ip)
            for _ in range(3):
                sock.send(packet)


def reclaim(name, bdf):
    pci = Path('/sys/bus/pci/devices', bdf)
    if (pci / 'vendor').read_text().strip() != '0x10ec' or (pci / 'device').read_text().strip() != '0x8125':
        raise RuntimeError('Unexpected PCI hardware: ' + bdf)
    driver = pci / 'driver'
    if driver.exists() and driver.resolve().name != 'r8125':
        # Refuse to unbind a UIO device held by a surviving process.
        for uio in (pci / 'uio').glob('uio*'):
            if run('fuser', '/dev/' + uio.name, check=False).returncode != 1:
                raise RuntimeError('UIO device still in use: ' + uio.name)
        (driver / 'unbind').write_text(bdf)
    if not driver.exists():
        (pci / 'driver_override').write_text('r8125')
        Path('/sys/bus/pci/drivers_probe').write_text(bdf)
    if driver.resolve().name != 'r8125':
        raise RuntimeError('Kernel driver binding failed: ' + bdf)
    deadline = time.monotonic() + 10
    while not list((pci / 'net').glob('*')):
        if time.monotonic() > deadline:
            raise RuntimeError('Kernel netdevice missing: ' + bdf)
        time.sleep(0.1)
    actual = next((pci / 'net').iterdir()).name
    run('ip', 'link', 'set', actual, 'down')
    run('ip', 'link', 'set', actual, 'nomaster')
    if actual != name:
        run('ip', 'link', 'set', actual, 'name', name)


def fallback():
    STATE.mkdir(parents=True, exist_ok=True)
    # Persist ownership before stopping VPP so queued starts cannot reclaim NICs.
    LATCH.touch()
    # Do not enqueue VPP's Wants dependencies at the next boot in Linux mode.
    run('systemctl', 'disable', 'vrouter-vpp.service')
    run('systemctl', 'stop', 'vrouter-vpp.service')
    if run('pgrep', '-x', 'vpp', check=False).returncode == 0:
        raise RuntimeError('VPP is still running')
    run('modprobe', 'r8125')
    for name, bdf in DEVICES.items():
        reclaim(name, bdf)
    if not exists(BRIDGE):
        run('ip', 'link', 'add', BRIDGE, 'type', 'bridge')
    run('ip', 'link', 'set', BRIDGE, 'type', 'bridge',
        'stp_state', '0', 'forward_delay', '0')
    run('ip', 'link', 'set', 'nic0', 'address', '02:00:00:00:10:01')
    for name in DEVICES:
        run('ip', 'link', 'set', name, 'master', BRIDGE)
        run('ip', 'link', 'set', name, 'up')
    run('ip', 'link', 'set', BRIDGE, 'up')
    run('ip', 'addr', 'replace', '10.61.20.2/24', 'dev', BRIDGE)
    run('ip', 'addr', 'replace', '10.61.20.1/24', 'dev', BRIDGE)
    for name, vlan in ((WAN, 100), (VPS, 10)):
        if not exists(name):
            run('ip', 'link', 'add', 'link', 'nic0', 'name', name,
                'type', 'vlan', 'id', str(vlan))
        run('ip', 'link', 'set', name, 'up')
    if exists('br0'):
        run('ip', 'link', 'set', VPS, 'master', 'br0')
        run('ip', 'link', 'set', 'br0', 'up')
    run('ip', 'addr', 'replace', '10.61.10.2/24', 'dev', WAN)
    run('ip', 'route', 'replace', 'default', 'via', '10.61.10.1', 'dev', WAN)
    # Remove stale VPP host-service policy routes, preserving unrelated rules.
    for pref in ('90', '91', '92', '100', '101', '102'):
        for family in ('-4', '-6'):
            rules = json.loads(run('ip', '-j', family, 'rule', 'show').stdout)
            for rule in rules:
                if str(rule.get('priority')) == pref and str(rule.get('fwmark', '')) in ('0x1000000', '0x2000000', '16777216', '33554432'):
                    run('ip', family, 'rule', 'del', 'pref', pref)
    for family, table in (('ip', 'vrouter_host_path'), ('ip', 'vpp_wg_proxy'),
                          ('inet', 'vrouter_dns_route_gate')):
        remove_nft(family, table)
    for chain in ('vrouter_lease_tproxy', 'vrouter_lease_guard'):
        if nft_exists('chain', 'inet', 'mangle', chain):
            run('nft', 'flush', 'chain', 'inet', 'mangle', chain)
    # An atomic replacement makes repeated fallback runs safe.
    prefix = 'delete table inet vrouter_linux_fallback\n' if nft_exists('table', 'inet', 'vrouter_linux_fallback') else ''
    rules = prefix + '''table inet vrouter_linux_fallback {
 chain input { type filter hook input priority filter; policy accept;
  iifname "vrouter-fb-wan" ct state established,related accept
  iifname "vrouter-fb-wan" drop
 }
 chain forward { type filter hook forward priority filter; policy drop;
  ct state established,related accept
  iifname "br-mgmt" oifname "br-mgmt" accept
  iifname "br-mgmt" oifname "vrouter-fb-wan" ip saddr 10.61.20.0/24 accept
 }
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
  oifname "vrouter-fb-wan" ip saddr 10.61.20.0/24 masquerade
 }
}
'''
    run('nft', '-c', '-f', '-', input=rules)
    run('nft', '-f', '-', input=rules)
    run('sysctl', '-w', 'net.ipv4.ip_forward=1',
        'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.br-mgmt.rp_filter=0')
    run('systemctl', 'restart', 'vrouter-linux-dnsmasq.service')
    deadline = time.monotonic() + 15
    while Path('/sys/class/net/nic0/carrier').read_text().strip() != '1':
        if time.monotonic() >= deadline:
            raise RuntimeError('WAN physical link did not recover')
        time.sleep(0.2)
    announce_gateway()
    (STATE / 'status.json').write_text(json.dumps({'mode': 'linux', 'time': time.time(),
                                                'wan': WAN, 'gateway': '10.61.10.1'}) + '\n')
    print('Linux IPv4 fallback ready', flush=True)


def resume():
    if not LATCH.exists():
        raise RuntimeError('Linux fallback is not active')
    run('systemctl', 'stop', 'vrouter-linux-fallback.service')
    run('systemctl', 'stop', 'vrouter-linux-dnsmasq.service')
    remove_nft('inet', 'vrouter_linux_fallback')
    for dev in (WAN, VPS):
        if exists(dev):
            run('ip', 'link', 'delete', dev)
    run('ip', 'addr', 'del', '10.61.20.1/24', 'dev', BRIDGE, check=False)
    for dev in DEVICES:
        if exists(dev):
            run('ip', 'link', 'set', dev, 'nomaster')
            run('ip', 'link', 'set', dev, 'down')
    LATCH.unlink()
    run('systemctl', 'enable', 'vrouter-vpp.service')
    run('systemctl', 'reset-failed', 'vrouter-vpp.service')
    try:
        run('systemctl', 'start', 'vrouter-vpp.service')
    except Exception:
        # A failed manual return must leave the router in Linux mode.
        fallback()
        raise
    (STATE / 'status.json').write_text(json.dumps({'mode': 'vpp', 'time': time.time()}) + '\n')
    print('VPP started; dependent services may still be starting', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('fallback', 'on-failure', 'resume', 'status'))
    args = parser.parse_args()
    if args.action == 'status':
        print('linux (latched)' if LATCH.exists() else 'vpp (not latched)')
        return
    if os.geteuid() != 0:
        parser.error('root required')
    STATE.mkdir(parents=True, exist_ok=True)
    with (STATE / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'on-failure':
            properties = run('systemctl', 'show', 'vrouter-vpp.service',
                             '-p', 'ActiveState', '-p', 'Result', '-p', 'Job').stdout
            state = dict(line.split('=', 1) for line in properties.splitlines())
            # systemd may retain exit-code/signal when the start limit is hit.
            # OnFailure is dispatched after automatic restarts are exhausted.
            if state.get('ActiveState') != 'failed' or state.get('Job'):
                print('VPP can still restart; no Linux takeover:', state)
                return
            LATCH.touch()
            run('systemctl', '--no-block', 'start', 'vrouter-linux-fallback.service')
        elif args.action == 'fallback':
            fallback()
        else:
            resume()


if __name__ == '__main__':
    main()
