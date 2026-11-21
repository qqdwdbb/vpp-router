#!/usr/bin/env python3
"""Derive IPsec IPv6 pools and return routes from VPP's live DHCPv6-PD lease."""
import argparse
import fcntl
import ipaddress as ip
import json
import logging
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time

LOG = logging.getLogger('vpp-ipsec-prefix')
STATE = Path('/var/lib/vpp-ipsec-prefix/state.json')
CONFIG = Path('/etc/ipsec.conf')
LAN = 'host-vpp-lan'
WAN = 'host-vpp-wan'


def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if p.returncode:
        raise RuntimeError('Command failed: ' + args[0])
    return p.stdout


def delegated(prefixes, addresses):
    block = re.search(r'(?ms)^host-vpp-lan \(up\):\s*(.*?)(?=^\S+ \((?:up|dn)\):|\Z)', addresses)
    lan = [ip.ip_interface(a).network for a in re.findall(r'L3 (\S+)', block[1] if block else '')
           if ':' in a]
    choices = []
    for line in prefixes.splitlines():
        m = re.search(r'prefix: (\S+), prefix group: wan-pd, preferred lifetime: (\d+), valid lifetime: \d+ \(([\d.]+) remaining\)', line)
        if not m or int(m[2]) == 0 or float(m[3]) <= 0:
            continue
        parent = ip.ip_network(m[1])
        for network in lan:
            if network.prefixlen == 64 and network.subnet_of(parent):
                choices.append((float(m[3]), network))
    return max(choices, key=lambda x: x[0])[1] if choices else None


def pool_ranges(network, leases, now):
    if network is None:
        return []
    first = int(network.network_address) + 0x100
    last = int(network.network_address) + 0x200
    occupied = set()
    for line in leases.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            expiry = int(fields[0])
            address = int(ip.IPv6Address(fields[2]))
        except ValueError:
            continue
        if (expiry == 0 or expiry > now) and first <= address <= last:
            occupied.add(address)
    result = []
    cursor = first
    for address in sorted(occupied):
        if cursor < address:
            result.append((ip.IPv6Address(cursor), ip.IPv6Address(address - 1)))
        cursor = address + 1
    if cursor <= last:
        result.append((ip.IPv6Address(cursor), ip.IPv6Address(last)))
    return result


def ra_command(prefixes, network):
    for line in prefixes.splitlines():
        match = re.search(r'prefix: (\S+), prefix group: wan-pd, preferred lifetime: (\d+), valid lifetime: (\d+) \(([\d.]+) remaining\)', line)
        if match and network.subnet_of(ip.ip_network(match[1])) and float(match[4]) > 0:
            remaining = int(float(match[4]))
            preferred = max(0, remaining - (int(match[3]) - int(match[2])))
            return f'ip6 nd {LAN} prefix {network} {min(remaining, 2592000)} {min(preferred, 604800)} off-link'
    raise RuntimeError('No live delegated prefix for LAN RA')


EAP_ULA = 'fd42:1111:2222:60::/64'


def ipv6_is_ula(token):
    first = token.strip().split('-', 1)[0].split('/', 1)[0]
    try:
        return ip.IPv6Address(first) in ip.IPv6Network('fc00::/7')
    except ip.AddressValueError:
        return False


def rewrite_sourceip(conn, value, ranges):
    """Cert/default get the PD GUA pool. Password EAP keeps a unique-local pool."""
    parts = [item.strip() for item in value.split(',') if item.strip()]
    ipv4 = [item for item in parts if ':' not in item]
    if conn == 'eap-mschapv2':
        ula = [item for item in parts if ':' in item and ipv6_is_ula(item)]
        return ','.join(ipv4 + [ula[0] if ula else EAP_ULA])
    pools = [str(first) + '-' + str(last) for first, last in ranges]
    return ','.join(ipv4 + pools)


def rewrite_config(text, ranges):
    count = 0
    conn = None
    lines = []
    for raw in text.splitlines(True):
        newline = '\n' if raw.endswith('\n') else ''
        body = raw[:-1] if newline else raw
        match = re.match(r'^conn\s+(\S+)', body)
        if match:
            conn = match[1]
        match = re.match(r'^(\s*rightsourceip\s*=\s*)([^\n#]+)(.*)$', body)
        if match:
            count += 1
            body = match[1] + rewrite_sourceip(conn, match[2], ranges) + match[3]
        lines.append(body + newline)
    if count != 2:
        raise RuntimeError('Expected the two existing rightsourceip settings; configuration left unchanged')
    return ''.join(lines)


def atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    original = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if original:
            os.chmod(name, original.st_mode & 0o777)
            os.chown(name, original.st_uid, original.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def vpp_batch(lines):
    if not lines:
        return
    fd, name = tempfile.mkstemp(dir='/run/vpp', prefix='ipsec-prefix-', suffix='.conf')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        output = run('vppctl', 'exec', name)
        if re.search(r'unknown input|failed|error|invalid', output, re.I):
            raise RuntimeError('VPP rejected IPsec prefix routing configuration')
    finally:
        os.unlink(name)


def reconcile(force=False):
    with open('/run/lock/vpp-ipsec-prefix.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        prefixes = run('vppctl', 'show ip6 prefixes')
        addresses = run('vppctl', 'show interface address')
        network = delegated(prefixes, addresses)
        default = run('vppctl', 'show ip6 fib ::/0')
        match = re.search(r'ipv6 via ([0-9a-f:]+) host-vpp-wan', default)
        gateway = str(ip.IPv6Address(match[1])) if match else None
        if not gateway:
            network = None
        leasefile = Path('/var/lib/misc/dnsmasq.leases')
        ranges = pool_ranges(network, leasefile.read_text() if leasefile.exists() else '', time.time())
        routes = sorted({str(p) for a, b in ranges for p in ip.summarize_address_range(a, b)})
        previous = json.loads(STATE.read_text()) if STATE.exists() else {}
        old_routes = previous.get('routes', [])
        before = CONFIG.read_text()
        after = rewrite_config(before, ranges)
        desired = {'prefix': str(network) if network else None, 'routes': routes, 'gateway': gateway}
        expiries = [time.time() + float(m[2]) for m in re.finditer(
            r'prefix: (\S+), prefix group: wan-pd, preferred lifetime: \d+, valid lifetime: \d+ \(([\d.]+) remaining\)', prefixes)
            if network and network.subnet_of(ip.ip_network(m[1]))]
        expires = max(expiries) if expiries else 0
        renewed = abs(expires - previous.get('lease_expires', 0)) > 5
        if network:
            # L=0 alone does not withdraw hosts' existing on-link routes.
            # Send a short deprecated lifetime first, leaving SLAAC addresses
            # intact without asking VPP to advertise a zero valid lifetime.
            if previous.get('prefix') != str(network) or renewed:
                vpp_batch([f'ip6 nd {LAN} prefix {network} 5 0 no-autoconfig'])
                time.sleep(2)
            vpp_batch([ra_command(prefixes, network)])
        comparable = {k: previous.get(k) for k in desired}
        if not force and not renewed and comparable == desired and before == after:
            return False
        # SPD encryption is selected on WAN egress, overriding the LAN /64.
        old_gateway = previous.get('gateway')
        lines = [f'ip route del {p} via {old_gateway} {WAN}' for p in old_routes
                 if old_gateway and (p not in routes or old_gateway != gateway)]
        lines += [f'ip route add {p} via {gateway} {WAN}' for p in routes]
        vpp_batch(lines)
        for p in routes:
            run('ip', '-6', 'route', 'replace', p, 'via', 'fe80::76:70ff:fe70:801', 'dev', 'br-vpp-lan')
        for p in old_routes:
            if p not in routes:
                subprocess.run(['ip', '-6', 'route', 'del', p, 'via', 'fe80::76:70ff:fe70:801', 'dev', 'br-vpp-lan'], capture_output=True)
        changed = before != after
        if changed:
            atomic_write(CONFIG, after)
        atomic_write(STATE, json.dumps(dict(desired, lease_expires=expires)) + '\n')
        if changed or previous.get('prefix') != (str(network) if network else None):
            LOG.info('IPv6 pool prefix %s; %s addresses available', network, sum(int(b)-int(a)+1 for a,b in ranges))
        return changed


def update(restart, force=False):
    changed = reconcile(force)
    # Release the lock first: service startup calls --once under the same lock.
    if changed and restart and subprocess.run(['systemctl', 'is-active', '--quiet', 'strongswan-vpp'], capture_output=True).returncode == 0:
        run('systemctl', 'restart', 'strongswan-vpp')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true', help='prepare pools before daemon start; never restart strongSwan')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.once:
        update(False, True)
        return
    # Netlink address events wake updates after PD-triggered LAN RAs. The
    # bounded audit also catches PD withdrawal, lease expiry and missed events.
    monitor = subprocess.Popen(['ip', '-6', 'monitor', 'address', 'dev', 'br-vpp-lan'], stdout=subprocess.PIPE, text=True)
    selector = selectors.DefaultSelector()
    selector.register(monitor.stdout, selectors.EVENT_READ)
    try:
        force = True
        while True:
            try:
                update(True, force)
                force = False
                delay = 30
            except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as error:
                LOG.warning('Prefix update deferred: %s; retrying', error)
                delay = 3
            if selector.select(timeout=delay):
                if not monitor.stdout.readline():
                    raise RuntimeError('IPv6 address monitor ended')
    finally:
        selector.close()
        monitor.terminate()
        monitor.wait(timeout=5)


if __name__ == '__main__':
    main()
