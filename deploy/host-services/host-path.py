#!/usr/bin/env python3
"""Render the isolated host-service path; watch only Linux admission policy."""
import argparse
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import re
from pathlib import Path
import subprocess
import time

spec = importlib.util.spec_from_file_location('service_ports', Path(__file__).with_name('service-ports.py'))
ports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ports)

spec = importlib.util.spec_from_file_location('host_routing', Path(__file__).with_name('host-routing.py'))
routing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routing)

POLICY_LOCK = Path('/run/lock/vrouter-host-policy.lock')
LAN_INPUT = '{ "br-mgmt", "nic1", "vpp-lan", "lan" }'


def addresses(config):
    names = ('gateway', 'host', 'wan_address', 'wan_backend')
    result = {name: str(ipaddress.IPv4Address(config[name])) for name in names}
    if len(set(result.values())) != len(result):
        raise ValueError('host path addresses must be distinct')
    if config['wan_host_interface'] != 'vpp-hostsvc':
        raise ValueError('unexpected host service interface')
    return result


def topology(config):
    a = addresses(config)
    lan_bvi = config.get('lan_bvi', 'loop200')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', lan_bvi):
        raise ValueError('invalid LAN BVI')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', config['wan_interface']):
        raise ValueError('invalid WAN interface')
    network = ipaddress.IPv4Network(a['wan_backend']+'/30', strict=False)
    if ipaddress.IPv4Address(a['wan_backend']) != network.network_address+2:
        raise ValueError('host backend must use the second usable /30 address')
    return '\n'.join([
        f'nat44 ei pool receive {a["wan_address"]} {config["wan_interface"]}',
        # The Linux end receives its address only AFTER its admission policy.
        'create tap id 2480 host-if-name vpp-hostsvc gso',
        f'set interface ip address tap2480 {network.network_address+1}/30',
        'set interface state tap2480 up',
        'set interface rx-mode tap2480 interrupt',
        'set punt tcp all', 'set punt udp all',
        f'ip punt redirect rx {lan_bvi} via {a["host"]} {lan_bvi}',
    ])+'\n'


def static_mappings(config, reserved_udp):
    """Reserve configured fixed ports only; dynamic listeners use VPP NAT."""
    a = addresses(config)
    mappings = {}
    reserved_udp = set(reserved_udp)
    for service in ports.resolved_services(config, []):
        if not service['wan']:
            continue
        target = a['wan_backend'] if service.get('dedicated_ingress', False) else a['host']
        for value in service['ports']:
            first, last = ports.port_bounds(value)
            for port in range(first, last+1):
                key = service['protocol'], port
                conflict = ((key[0] == 'udp' and port in reserved_udp)
                            or (key in mappings and mappings[key] != target))
                if conflict:
                    raise ValueError('host static mapping conflicts with a reserved port')
                mappings[key] = target
    return mappings


def mapping_commands(config, mappings):
    a = addresses(config)
    return [f'nat44 ei add static mapping local {target} {port} external {a["wan_address"]} {port} {proto}'
            for (proto, port), target in sorted(mappings.items())]


def coturn_config(text, config):
    """Keep credentials private; change only migrated IPv4 binding/mapping."""
    a = addresses(config)
    relay = [service for service in config['services'] if service['name'] == 'turn-relay']
    if len(relay) != 1 or relay[0]['protocol'] != 'udp' or len(relay[0]['ports']) != 1:
        raise ValueError('coturn needs one UDP relay port range')
    first, last = ports.port_bounds(relay[0]['ports'][0])
    result = []
    old = {a['gateway'], a['wan_address']}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == 'daemon':
            continue  # The private systemd unit tracks the foreground process.
        key, separator, value = stripped.partition('=')
        if separator and key in ('min-port', 'max-port'):
            continue
        if separator and key in ('listening-ip', 'relay-ip') and value in old:
            line = key+'='+a['host']
        elif separator and key == 'external-ip' and '/' in value:
            public, private = value.split('/', 1)
            if private in old:
                line = 'external-ip='+public+'/'+a['host']
        if line not in result or key not in ('listening-ip', 'relay-ip'):
            result.append(line)
    return '\n'.join([*result, f'min-port={first}', f'max-port={last}'])+'\n'


def owner_cgroups(config):
    """A missing service has no admission; inode changes invalidate the watcher."""
    result = {}
    for service in config['services']:
        unit = service.get('owner_unit')
        if unit is None:
            continue
        if service['protocol'] != 'udp':
            raise ValueError('socket owner admission supports UDP only')
        if not re.fullmatch(r'[A-Za-z0-9_@.-]+\.service', unit) or unit.startswith('.'):
            raise ValueError('invalid owner service unit')
        try:
            result[unit] = Path('/sys/fs/cgroup/system.slice', unit).stat().st_ino
        except FileNotFoundError:
            pass
    return result


def nft(config, inventory, owners=None):
    a = addresses(config)
    lan_input = LAN_INPUT
    if 'lan_interfaces' in config:
        names = config['lan_interfaces']
        if not names or any(not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', name) for name in names):
            raise ValueError('invalid LAN interfaces')
        lan_input = '{ ' + ', '.join(json.dumps(name) for name in names) + ' }'
    services = ports.resolved_services(config, inventory)
    available_owners = owner_cgroups(config)
    owners = available_owners if owners is None else owners
    dedicated = [s for s in services if s.get('dedicated_ingress', False)]
    allowed = ports.acl_ports([s for s in dedicated if s['wan'] and not s.get('owner_unit')])
    trusted = ', '.join(str(ipaddress.IPv4Network(p)) for p in config['trusted_ipv4'])
    lines = [
        'add table ip vrouter_host_path',
        'add chain ip vrouter_host_path frontend { type nat hook prerouting priority -105; policy accept; }',
        'add chain ip vrouter_host_path admission { type filter hook input priority -20; policy accept; }',
        'add chain ip vrouter_host_path ingress { type filter hook prerouting priority -106; policy accept; }',
        'add chain ip vrouter_host_path egress { type route hook output priority -140; policy accept; }',
        'add chain ip vrouter_host_path source { type nat hook postrouting priority srcnat; policy accept; }',
        'flush chain ip vrouter_host_path frontend',
        'flush chain ip vrouter_host_path admission',
        'flush chain ip vrouter_host_path ingress',
        'flush chain ip vrouter_host_path egress',
        'flush chain ip vrouter_host_path source',
        f'add rule ip vrouter_host_path ingress iifname "vpp-hostsvc" ip daddr {a["wan_backend"]} ct direction original ct mark set ct mark | {routing.INBOUND}',
        # WAN traffic has a dedicated ingress. Never infer WAN from source IP:
        # VPN clients and routed LAN networks can also have public addresses.
        f'add rule ip vrouter_host_path frontend iifname "vpp-hostsvc" ip daddr {a["wan_backend"]} dnat to {a["host"]}',
        # The first DNAT wins: gateway DNS must reach the route gate here,
        # before the later DNS NAT chain can be skipped by the generic DNAT.
        f'add rule ip vrouter_host_path frontend iifname {lan_input} ip saddr {{ {trusted} }} ip daddr {a["gateway"]} meta l4proto {{ tcp, udp }} th dport 53 dnat to {a["host"]}:1053',
        # Keep gateway HTTP on the local nginx listener instead of sending it
        # through the host-service path.
        f'add rule ip vrouter_host_path frontend iifname {lan_input} ip saddr {{ {trusted} }} ip daddr {a["gateway"]} meta l4proto {{ tcp, udp }} th dport != 80 dnat to {a["host"]}',
    ]
    # Classify only locally initiated connections. Inbound LAN replies must
    # never acquire WAN routing just because their service has a public port.
    outgoing = (f'add rule ip vrouter_host_path egress ip saddr {a["host"]} '
                f'ct direction original ct state new ct mark & {routing.MASK} == 0')
    for proto in ('tcp', 'udp'):
        values = ', '.join(map(str, allowed['wan_'+proto+'_services']))
        if values:
            lines.append(f'{outgoing} {proto} sport {{ {values} }} ct mark set ct mark | {routing.OUTBOUND}')
    # Coturn can also originate TCP/UDP using ephemeral ports. Classify its
    # sockets by the same declared cgroup used for relay admission.
    for unit in sorted(owners):
        if unit not in {s.get('owner_unit') for s in services}:
            raise ValueError('undeclared socket owner')
        if any(s['wan'] and s.get('owner_unit') == unit for s in dedicated):
            lines.append(f'{outgoing} meta l4proto {{ tcp, udp }} socket cgroupv2 level 2 "system.slice/{unit}" ct mark set ct mark | {routing.OUTBOUND}')
    lines += [
        f'add rule ip vrouter_host_path egress ct mark & {routing.MASK} != 0 meta mark set meta mark & {routing.KEEP}',
        f'add rule ip vrouter_host_path egress ct mark & {routing.INBOUND} != 0 meta mark set meta mark | {routing.INBOUND}',
        f'add rule ip vrouter_host_path egress ct mark & {routing.OUTBOUND} != 0 meta mark set meta mark | {routing.OUTBOUND}',
        f'add rule ip vrouter_host_path source oifname "vpp-hostsvc" ip saddr {a["host"]} ct direction original ct mark & {routing.OUTBOUND} != 0 counter snat to {a["wan_backend"]}',
    ]
    lines.append(f'add rule ip vrouter_host_path admission iifname "vpp-hostsvc" ip daddr {a["host"]} ip protocol icmp counter accept')
    for proto in ('tcp', 'udp'):
        values = ', '.join(map(str, allowed['wan_'+proto+'_services']))
        if values:
            lines.append(f'add rule ip vrouter_host_path admission iifname "vpp-hostsvc" ip daddr {a["host"]} {proto} dport {{ {values} }} counter accept')
    for unit in sorted(owners):
        if unit not in {s.get('owner_unit') for s in services}:
            raise ValueError('undeclared socket owner')
        generation = owners[unit]
        if type(generation) is not int or generation <= 0:
            raise ValueError('invalid cgroup generation')
        # Outbound coturn can use ephemeral ports, but its conntrack entry must
        # not let a different process take over that socket after coturn exits.
        if any(s['wan'] and s.get('owner_unit') == unit for s in dedicated):
            lines.append(f'add rule ip vrouter_host_path admission iifname "vpp-hostsvc" ip daddr {a["host"]} ct direction reply ct status snat ct mark & {routing.OUTBOUND} != 0 socket cgroupv2 level 2 "system.slice/{unit}" counter accept comment "owner-generation {generation}"')
        owned = ports.acl_ports([s for s in dedicated if s['wan'] and s.get('owner_unit') == unit])
        values = ', '.join(map(str, owned['wan_udp_services']))
        if values:
            lines.append(f'add rule ip vrouter_host_path admission iifname "vpp-hostsvc" ip daddr {a["host"]} udp dport {{ {values} }} socket cgroupv2 level 2 "system.slice/{unit}" counter accept comment "owner-generation {generation}"')
    # No established bypass: the UDP owner check must also reject port takeover
    # before the watcher notices the service exit. Replies travel outwards.
    lines += ['add rule ip vrouter_host_path admission iifname "vpp-hostsvc" counter drop']
    policy = '\n'.join(lines)+'\n'
    marker = 'vrouter-host-policy:'+hashlib.sha256(policy.encode()).hexdigest()
    return policy+f'add rule ip vrouter_host_path admission counter comment "{marker}"\n'


def update_policy(config, previous=None):
    # Serialize discovery AND installation: an older watcher snapshot must not
    # overwrite the owner's ExecStartPre policy after the service starts.
    with POLICY_LOCK.open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        policy = nft(config, ports.current_listeners())
        installed = False
        if policy == previous:
            # A global nft reload can replace the table without changing the
            # service/cgroup inventory. Do not mistake the cached policy for
            # the policy still installed in the kernel.
            marker = re.search(r'vrouter-host-policy:[0-9a-f]{64}', policy)[0]
            current = subprocess.run(['nft', 'list', 'chain', 'ip', 'vrouter_host_path', 'admission'],
                                     capture_output=True, text=True)
            installed = current.returncode == 0 and marker in current.stdout
        if not installed:
            result = subprocess.run(['nft', '-f', '-'], input=policy, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError('host admission policy update failed')
        return policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--watch', action='store_true')
    parser.add_argument('--apply', action='store_true', help='Discover and apply the current policy once')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    addresses(config)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output/'host-path.vpp').write_text(topology(config))
        (args.output/'host-path.nft').write_text(nft(config, [], owners={}))
    if args.watch:
        previous = None
        while True:
            previous = update_policy(config, previous)
            time.sleep(2)
    elif args.apply:
        update_policy(config)
    elif not args.output:
        parser.error('select --output, --apply or --watch')


if __name__ == '__main__':
    main()
