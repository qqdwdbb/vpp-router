#!/usr/bin/env python3
"""Maintain NAT44 pools and the explicitly enabled wg0 IPv6 source NAT policy."""
from contextlib import ExitStack
import fcntl
import json
import ipaddress
import logging
import os
from pathlib import Path
import re
import runpy
import signal
import threading


def reconcile(helpers, state_path=None):
    cli, command = helpers['cli'], helpers['command']
    generation = command(['systemctl', 'show', 'vpp', '-p', 'InvocationID', '--value']).strip()
    if not re.fullmatch('[a-f0-9]{32}', generation):
        return
    state_path = Path(state_path or '/run/vpp/egress-nat.json')
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    owned = set(state.get('addresses', [])) if state.get('generation') == generation else set()
    desired = {}
    wan_address = None
    display = cli('show interface address')
    outside = cli('show nat44 ei interfaces')
    for interface in ('host-vpp-wan', 'wg1'):
        block = re.search(r'(?ms)^' + re.escape(interface) + r' \(up\):\s*(.*?)(?=^\S+ \((?:up|dn)\):|\Z)', display)
        if not block:
            continue
        ips = re.findall(r'L3 (\d+\.\d+\.\d+\.\d+)/\d+', block[1])
        if not ips:
            continue
        if not re.search(r'(?m)^\s*' + re.escape(interface) + r' output-feature in out\s*$', outside):
            raise RuntimeError(interface + ' must use output-feature NAT')
        desired[ips[0]] = 101 if interface == 'wg1' else 0
        if interface == 'host-vpp-wan':
            wan_address = ips[0]
    pools = cli('show nat44 ei addresses')
    present = set(re.findall(r'(?m)^(\d+\.\d+\.\d+\.\d+)\s*$', pools))
    static = cli('show nat44 ei static mappings')
    ports = {int(port) for port in re.findall(
        r'udp local \S+:(\d+) external host-vpp-wan:\d+ vrf', static, re.I)}
    identities = {(wan_address, port) for port in ports} if wan_address else set()
    active = {(ip, int(port)) for ip, port in re.findall(
        r'identity mapping udp (\S+):(\d+) vrf 0\b', static, re.I)}
    old_identities = {tuple(item) for item in state.get('identity_mappings', [])} if state.get('generation') == generation else set()
    lines = [f'nat44 ei add identity mapping {ip} udp {port} vrf 0 del'
             for ip, port in sorted((old_identities - identities) & active)]
    lines += [f'nat44 ei add address {ip} del' for ip in sorted(owned - desired.keys()) if ip in present]
    for ip in sorted(desired):
        if ip not in present:
            lines.append(f'nat44 ei add address {ip} tenant-vrf {desired[ip]}')
        elif not re.search(r'(?m)^' + re.escape(ip) + r'\s*\n\s*tenant VRF: ' + str(desired[ip]) + r'\s*$', pools):
            raise RuntimeError(ip + ' has conflicting NAT pool ownership/VRF')
    lines += [f'nat44 ei add identity mapping {ip} udp {port} vrf 0'
              for ip, port in sorted(identities - active)]
    # All inputs checked before mutations; only addresses managed here are removed.
    if lines:
        helpers['execute'](lines)
    temporary = state_path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'generation': generation, 'addresses': sorted(desired),
                                     'identity_mappings': sorted(identities)}))
    temporary.chmod(0o600)
    temporary.replace(state_path)
    if lines:
        logging.info('updated NAT pools: %s', sorted(desired))


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    helpers = runpy.run_path('/usr/local/sbin/vpp-import-wireguard', run_name='egress_nat_helpers')
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *unused: stop.set())
    previous = None
    while not stop.is_set():
        try:
            with ExitStack() as locks:
                for name in ('/run/lock/vpp-wireguard-client-import.lock', '/run/lock/vpp-wireguard-import.lock'):
                    fd = os.open(name, os.O_CREAT | os.O_RDWR, 0o600)
                    lock = locks.enter_context(os.fdopen(fd, 'r+'))
                    fcntl.flock(lock, fcntl.LOCK_EX)
                reconcile(helpers)
                if Path('/etc/vpp/wg0-nat66.conf').exists():
                    reconcile_nat66(helpers)
            previous = None
        except Exception as error:
            if str(error) != previous:
                logging.error('NAT reconciliation failed: %s', error)
            previous = str(error)
        stop.wait(2)


def nat66_peers(display):
    addresses = set()
    for block in re.split(r'(?m)(?=^\[\d+\])', display):
        if not re.match(r'^\[\d+\].* wg0 ', block):
            continue
        match = re.search(r'allowed-ips: ([^\n]+)', block)
        for token in match[1].split() if match else []:
            if ':' not in token:
                continue
            network = ipaddress.ip_network(token)
            if network.subnet_of(ipaddress.ip_network('fd42:1111:2222:90::/64')):
                if network.prefixlen != 128:
                    raise RuntimeError('wg0 NAT66 requires individual IPv6 peer AllowedIPs (/128)')
                addresses.add(str(network.network_address))
    return sorted(addresses, key=lambda a: int(ipaddress.ip_address(a)))


def reconcile_nat66(helpers, state_path=None):
    state_path = Path(state_path or '/run/vpp/wg0-nat66.json')
    display = helpers['cli']('show interface address')
    # Reuse the live DHCPv6-PD parser; stale SLAAC alone is not delegation.
    prefix_helpers = runpy.run_path('/usr/local/sbin/vpp-ipsec-prefix-sync', run_name='nat66_prefix_helpers')
    network = prefix_helpers['delegated'](helpers['cli']('show ip6 prefixes'), display)
    peers = nat66_peers(helpers['cli']('show wireguard peer'))
    return reconcile_nat66_policy(helpers, state_path, network, peers)


def reconcile_nat66_policy(helpers, state_path, network, peers):
    """Reconcile only explicit /128 peers; caller supplies the live PD policy."""
    state_path = Path(state_path)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    ids = {a: n for a, n in state.get('ids', {}).items() if a in peers}
    for address in peers:
        if address in ids:
            continue
        candidate = int(ipaddress.ip_address(address)) & ((1 << 64) - 1)
        if not 0 < candidate < (1 << 48) or candidate in ids.values():
            candidate = 1
            while candidate in ids.values():
                candidate += 1
        ids[address] = candidate
    # Reserve delegated-prefix:66::/80, away from LAN DHCPv6 and IPsec pools.
    desired = {a: str(ipaddress.IPv6Address(int(network.network_address) + (0x66 << 48) + ids[a]))
               for a in peers} if network else {}
    present = {}
    for local, external, vrf in re.findall(r'local ([0-9a-f:]+) external ([0-9a-f:]+) vrf (\d+)', helpers['cli']('show nat66 static mappings')):
        if vrf == '0':
            present[local] = external
    owned = state.get('mappings', {})
    for local, external in desired.items():
        if local in present and present[local] != external and present[local] != owned.get(local):
            raise RuntimeError('Conflicting NAT66 mapping for ' + local)
        if any(a != local and e == external and not (owned.get(a) == e and desired.get(a) != e)
               for a, e in present.items()):
            raise RuntimeError('Conflicting external NAT66 address')
    lines = []
    for local, external in owned.items():
        if present.get(local) == external and desired.get(local) != external:
            lines.append(f'nat66 add static mapping local {local} external {external} del')
    for local, external in desired.items():
        if present.get(local) != external:
            lines.append(f'nat66 add static mapping local {local} external {external}')
    if lines:
        helpers['execute'](lines)
        logging.info('Updated wg0 NAT66 mappings: %d peers, prefix %s', len(desired), network)
    desired_state = dict(ids=ids, mappings=desired)
    if state != desired_state:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = state_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(desired_state))
        temporary.chmod(0o600)
        temporary.replace(state_path)


if __name__ == '__main__':
    main()
