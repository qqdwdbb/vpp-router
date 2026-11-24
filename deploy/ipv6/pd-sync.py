#!/usr/bin/env python3
"""Publish consumed VPP PD prefixes and update an optional staged IPsec pool."""
import argparse
import fcntl
import ipaddress as ip
import json
import logging
from pathlib import Path
import re
import runpy
import signal
import subprocess
import threading
import time

LOG = logging.getLogger('vrouter-pd-sync')
def _shared_tool(name):
    installed = Path(__file__).resolve().parent / name
    if installed.is_file():
        return str(installed)
    # Installed tree: <root>/<name>. Source tree: <root>/tools/<name>.
    root = Path(__file__).resolve().parents[2]
    return str(root / name if (root / name).exists() else root / 'tools' / name)


def consumed(prefixes, addresses, interface, group):
    block = re.search(r'(?ms)^' + re.escape(interface) + r' \(up\):\s*(.*?)(?=^\S+ \((?:up|dn)\):|\Z)', addresses)
    networks = {ip.ip_interface(a).network for a in re.findall(r'L3 (\S+)', block[1] if block else '') if ':' in a}
    result = {}
    for line in prefixes.splitlines():
        match = re.search(r'prefix: (\S+), prefix group: (\S+), preferred lifetime: (\d+), valid lifetime: (\d+) \(([\d.]+) remaining\)', line)
        if not match or match[2] != group:
            continue
        parent = ip.ip_network(match[1])
        preferred, valid, remaining = int(match[3]), int(match[4]), float(match[5])
        if preferred > valid or remaining <= 0:
            continue
        for network in networks:
            if network.version == 6 and network.prefixlen == 64 and network.subnet_of(parent):
                result[str(network)] = (int(remaining), max(0, int(remaining - (valid-preferred))))
    return result


class Publisher:
    def __init__(self, config, cli):
        self.config, self.cli = config, cli
        self.state_path = Path(config['state_file'])
        if not str(config['state_file']).startswith('/run/'):
            raise ValueError('PD runtime state must be under /run')
        saved = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        self.managed = {prefix: dict(value) for prefix, value in saved.get('managed', {}).items()}
        self.published = {}
        self.status = saved or None
        self.generation = saved.get('vpp_generation')
        self.reload_pending = bool(config.get('ipsec_reload_command'))
        self.pool_routes = saved.get('ipsec_routes', [])
        self.pool_gateway = saved.get('ipsec_gateway')
        self.pool_interface = saved.get('ipsec_interface')
        self.host_address = saved.get('host_address')
        self.host_pool_routes = saved.get('ipsec_host_routes', {})
        self.host_pool_installed = False
        self.ipsec_addresses = None
        self.nat66 = None
        self.pools = runpy.run_path(_shared_tool('ipsec/ipsec-prefix-sync.py')) if config.get('ipsec_config') else None
        if config.get('nat66_policy_file'):
            policy = json.loads(Path(config['nat66_policy_file']).read_text())
            if policy['interface'] != 'wg0' or not str(policy['state_file']).startswith('/run/'):
                raise ValueError('Invalid wg0 NAT66 policy')
            policy['peers'] = [str(ip.IPv6Address(value)) for value in policy['peers']]
            if len(policy['peers']) != len(set(policy['peers'])) or any(
                    ip.IPv6Address(value) not in ip.ip_network('fd42:1111:2222:90::/64') for value in policy['peers']):
                raise ValueError('Invalid wg0 NAT66 peer addresses')
            module = runpy.run_path(_shared_tool('vpp-egress-nat.py'))
            self.nat66 = policy, module['reconcile_nat66_policy']

    def command(self, prefix, value):
        self.cli(f"ip6 nd {self.config['lan_interface']} prefix {prefix} {value}")

    def sync_host_pool_routes(self, prefixes):
        gateway = self.config.get('ipsec_host_gateway')
        if not gateway:
            return
        gateway = str(ip.IPv6Address(gateway))
        interface = self.config.get('host_interface', '')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', interface):
            raise ValueError('Invalid host interface')
        desired = {prefix: [gateway, interface] for prefix in prefixes}
        # Override a Linux connected LAN /64 for proxy replies to VPN clients.
        # Reapply after process restart even when the saved plan is unchanged.
        for prefix, path in desired.items():
            if not self.host_pool_installed or self.host_pool_routes.get(prefix) != path:
                subprocess.run(['ip', '-6', 'route', 'replace', prefix, 'via', path[0],
                                'dev', path[1], 'metric', '100'],
                               check=True, capture_output=True, timeout=10)
        for prefix, path in self.host_pool_routes.items():
            if desired.get(prefix) != path:
                subprocess.run(['ip', '-6', 'route', 'del', prefix, 'via', path[0],
                                'dev', path[1], 'metric', '100'],
                               check=True, capture_output=True, timeout=10)
        self.host_pool_routes = desired
        self.host_pool_installed = True

    def withdrawal_lifetime(self, no_autoconfig=False):
        """Return a finite deprecated lifetime for a withdrawing prefix.

        VPP logs a BUG when it tries to advertise an RA PIO with valid_time
        zero.  The preferred lifetime is zero; the valid lifetime outlasts
        the grace period, since the prefix is removed only on the first sync
        after it ends and VPP counts the advertised lifetime down meanwhile.
        """
        suffix = ' no-autoconfig' if no_autoconfig else ''
        return f"{2 * self.config['withdraw_seconds']} 0{suffix}"

    def sync(self, now=None):
        now = time.monotonic() if now is None else now
        generation = Path(self.config['vpp_socket']).stat().st_ino
        restarted = generation != self.generation
        if restarted:
            self.managed = {prefix: {'phase': 'new', 'since': 0} for prefix in self.managed}
            self.published.clear()
            self.generation = generation
            self.pool_routes, self.pool_gateway, self.pool_interface = [], None, None
        prefixes = self.cli('show ip6 prefixes')
        addresses = self.cli('show interface address')
        if self.config.get('ipsec_update_command'):
            block = re.search(r'(?ms)^' + re.escape(self.config['wan_interface']) +
                              r' \(up\):\s*(.*?)(?=^\S+ \((?:up|dn)\):|\Z)', addresses)
            signature = generation, tuple(sorted(re.findall(r'\bL3 (\S+)', block[1] if block else '')))
            if signature != self.ipsec_addresses:
                subprocess.run(self.config['ipsec_update_command'], check=True, capture_output=True, timeout=15)
                self.ipsec_addresses = signature
        default = self.cli('show ip6 fib ::/0')
        active = consumed(prefixes, addresses, self.config['lan_interface'], self.config['prefix_group'])
        gateway = re.search(r'ipv6 via (\S+) ' + re.escape(self.config['wan_interface']) + r'(?::|\s|$)', default)
        if not gateway:
            active = {}
        # Remove expired publications before introducing the new pool.
        for prefix in list(self.managed):
            if prefix in active:
                continue
            state = self.managed[prefix]
            if state['phase'] != 'withdrawing':
                self.command(prefix, self.withdrawal_lifetime())
                self.managed[prefix] = {'phase': 'withdrawing', 'since': now}
                self.published.pop(prefix, None)
            elif now - state['since'] >= self.config['withdraw_seconds']:
                self.cli(f"ip6 nd {self.config['lan_interface']} no prefix {prefix}")
                del self.managed[prefix]
        ready = {}
        for prefix, lifetimes in active.items():
            state = self.managed.get(prefix, {'phase': 'new', 'since': now})
            if state['phase'] in ('new', 'withdrawing'):
                # Clear a cached L=1 route before advertising SLAAC with L=0.
                self.command(prefix, self.withdrawal_lifetime(no_autoconfig=True))
                state = {'phase': 'clearing', 'since': now}
                self.managed[prefix] = state
                self.published.pop(prefix, None)
            if state['phase'] == 'clearing':
                if now - state['since'] < self.config['withdraw_seconds']:
                    # PD renewals also update lifetimes in native RA code.
                    self.command(prefix, self.withdrawal_lifetime(no_autoconfig=True))
                    continue
                state['phase'] = 'active'
            valid, preferred = lifetimes
            if valid <= 0:
                continue
            previous = self.published.get(prefix)
            expires = (now + valid, now + preferred if preferred else 0)
            if previous is None or any(abs(a-b) > 2 for a, b in zip(previous, expires)):
                self.command(prefix, f'{valid} {preferred} off-link')
                self.published[prefix] = expires
            if preferred > 0:
                ready[prefix] = preferred
        # Keep both valid PIOs during overlap, but select a single preferred VPN pool.
        current = self.status.get('pool_prefix') if self.status else None
        pool = current if current in ready else max(ready, key=ready.get, default=None)
        host_interface = self.config.get('host_interface')
        if host_interface:
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', host_interface):
                raise ValueError('Invalid host interface')
            index = int(self.config.get('host_address_index', 2))
            if not 1 < index < 65535:
                raise ValueError('Invalid host address index')
            address = str(ip.ip_network(pool).network_address + index)+'/128' if pool else None
            if address != self.host_address or restarted:
                if self.host_address and self.host_address != address:
                    subprocess.run(['ip', '-6', 'addr', 'del', self.host_address, 'dev', host_interface],
                                   capture_output=True, timeout=10)
                if address:
                    subprocess.run(['ip', '-6', 'addr', 'replace', address, 'dev', host_interface, 'nodad'],
                                   check=True, capture_output=True, timeout=10)
                self.host_address = address
        if self.nat66:
            policy, reconcile = self.nat66
            def execute(lines):
                for line in lines:
                    self.cli(line)
            reconcile({'cli': self.cli, 'execute': execute}, policy['state_file'],
                      ip.ip_network(pool) if pool else None, policy['peers'])
        target = self.config.get('ipsec_config')
        if target:
            path = Path(target)
            before = path.read_text()
            leasefile = Path(self.config.get('dhcp_lease_file', '/var/lib/misc/dnsmasq.leases'))
            ranges = self.pools['pool_ranges'](ip.ip_network(pool) if pool else None,
                                         leasefile.read_text() if leasefile.exists() else '', time.time())
            after = self.pools['rewrite_config'](before, ranges)
            if self.config.get('ipsec_pool_routes'):
                # Override the connected LAN /64: VPN return traffic must reach
                # the WAN SPD instead of attempting LAN neighbour discovery.
                routes = sorted({str(prefix) for first, last in ranges
                                 for prefix in ip.summarize_address_range(first, last)})
                self.sync_host_pool_routes(routes)
                next_hop = str(ip.IPv6Address(gateway[1])) if gateway else None
                interface = self.config['wan_interface']
                old_path = (self.pool_gateway, self.pool_interface)
                new_path = (next_hop, interface)
                old_routes = self.pool_routes
                if next_hop:
                    for prefix in routes:
                        if prefix not in old_routes or old_path != new_path:
                            self.cli(f'ip route add {prefix} via {next_hop} {interface}')
                    for prefix in old_routes:
                        if prefix not in routes or old_path != new_path:
                            self.cli(f'ip route del {prefix} via {self.pool_gateway} {self.pool_interface}')
                    self.pool_routes, self.pool_gateway, self.pool_interface = routes, next_hop, interface
                elif old_routes:
                    for prefix in old_routes:
                        if self.pool_gateway:
                            self.cli(f'ip route del {prefix} via {self.pool_gateway} {self.pool_interface}')
                    self.pool_routes, self.pool_gateway, self.pool_interface = [], None, None
            if before != after:
                self.pools['atomic_write'](path, after)
                self.reload_pending = bool(self.config.get('ipsec_reload_command'))
            if self.reload_pending:
                subprocess.run(self.config['ipsec_reload_command'], check=True, timeout=30, capture_output=True)
                self.reload_pending = False
        status = {'managed': self.managed, 'pool_prefix': pool, 'vpp_generation': self.generation}
        if host_interface:
            status['host_address'] = self.host_address
        if self.config.get('ipsec_pool_routes'):
            status.update(ipsec_routes=self.pool_routes, ipsec_gateway=self.pool_gateway,
                          ipsec_interface=self.pool_interface)
        if self.config.get('ipsec_host_gateway'):
            status['ipsec_host_routes'] = self.host_pool_routes
        # Volatile state changes only; lease polling never writes /var/lib.
        encoded = json.dumps(status, sort_keys=True)
        if self.status != json.loads(encoded):
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_suffix('.tmp')
            temporary.write_text(encoded + '\n')
            temporary.chmod(0o600)
            temporary.replace(self.state_path)
            self.status = json.loads(encoded)
            LOG.info('RA phases updated; VPN pool prefix %s', pool)
        return self.status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if not 0.2 <= config['interval_seconds'] <= 30:
        raise ValueError('interval_seconds out of range')
    if config['withdraw_seconds'] <= config['ra_max_interval_seconds']:
        raise ValueError('withdraw_seconds must exceed LAN maximum RA interval')
    for key in ('lan_interface', 'wan_interface', 'prefix_group'):
        if not re.fullmatch(r'[A-Za-z0-9_.:/-]+', config[key]):
            raise ValueError('invalid ' + key)
    if config['wan_interface'] == 'WAN_INTERFACE':
        raise ValueError('Configure the actual WAN interface before starting')
    logging.basicConfig(level=logging.INFO)
    def cli(command):
        result = subprocess.run(['vppctl', '-s', config['vpp_socket'], command],
                                capture_output=True, text=True, timeout=5)
        if result.returncode or re.search(r'unknown input|failed|error:|invalid', result.stdout, re.I):
            raise RuntimeError('VPP PD operation failed')
        return result.stdout
    stopping = threading.Event()
    def stop(*unused):
        stopping.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    lockpath = Path(config['state_file']).with_suffix('.lock')
    lockpath.parent.mkdir(parents=True, exist_ok=True)
    with lockpath.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        publisher = Publisher(config, cli)
        while not stopping.is_set():
            try:
                publisher.sync()
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                LOG.warning('PD reconciliation deferred; retrying')
                publisher.published.clear()
            stopping.wait(config['interval_seconds'])


if __name__ == '__main__':
    main()
