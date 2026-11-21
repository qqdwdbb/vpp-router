#!/usr/bin/env python3
"""Maintain declarative VPP source-based ABF routes independently of firewall ACLs."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time

NAME = re.compile(r'[A-Za-z0-9_.-]{1,40}\Z')
# Seconds between full reconciles while nothing changes.
RESYNC = 300

def command(socket, text):
    p = subprocess.run(['vppctl', '-s', socket, text], check=True,
                       capture_output=True, text=True, timeout=15)
    if re.search(r'unknown input|failed|invalid|cannot', p.stdout, re.I):
        raise RuntimeError(p.stdout.strip())
    return p.stdout

def rules(policy, addresses):
    via = ipaddress.ip_address(policy['via'])
    anynet = '::/0' if via.version == 6 else '0.0.0.0/0'
    excluded = list(policy.get('exclude_destinations', []))
    if policy.get('exclude_lan_interface'):
        for value in re.findall(r'\bL3 (\S+)', addresses):
            prefix = ipaddress.ip_interface(value).network
            if prefix.version == via.version:
                excluded.append(str(prefix))
    result = []
    for value in sorted(set(excluded)):
        prefix = ipaddress.ip_network(value)
        if prefix.version != via.version:
            raise ValueError('source policy address families differ')
        result.append(f'deny src {anynet} dst {prefix}')
    for value in policy['sources']:
        prefix = ipaddress.ip_network(value)
        if prefix.version != via.version:
            raise ValueError('source policy address families differ')
        result.append(f'permit src {prefix} dst {anynet}')
    return ', '.join(result)

def reconcile(config, saved, cli):
    interfaces = set(re.findall(r'^(\S+) \((?:up|dn)\):', cli('show interface address'), re.M))
    acls = cli('show acl-plugin acl')
    policies = cli('show abf policy')
    result = {}
    wanted_ids = {str(int(policy['id'])) for policy in config['policies']}
    for ident, previous in saved.items():
        if ident in wanted_ids:
            continue
        for name in previous.get('interfaces', []):
            if name in interfaces and re.search(rf'policy:{ident}\b', cli(f'show abf attach {name}')):
                family = 'ip6' if ':' in previous['path'].split()[0] else 'ip4'
                cli(f'abf attach {family} del policy {ident} {name}')
        if re.search(rf'policy:{ident}\b', policies):
            cli(f'abf policy del id {ident}')
    for policy in config['policies']:
        ident = int(policy['id'])
        if not 1 <= ident <= 0xffffffff or not NAME.fullmatch(policy['name']):
            raise ValueError('invalid source policy identity')
        if not NAME.fullmatch(policy['output_interface']):
            raise ValueError('invalid source policy output')
        if policy['output_interface'] not in interfaces:
            raise RuntimeError('source policy output is not ready')
        attached = [name for name in policy['interfaces'] if name in interfaces]
        if any(not NAME.fullmatch(name) for name in policy['interfaces']):
            raise ValueError('invalid source policy input')
        lan = policy.get('exclude_lan_interface')
        if lan and not NAME.fullmatch(lan):
            raise ValueError('invalid source policy LAN')
        text = rules(policy, cli(f'show interface address {lan}') if lan else '')
        tag = 'source-route-' + policy['name']
        match = re.search(rf'^acl-index\s+(\d+)\s+count\s+\d+\s+tag \{{{re.escape(tag)}\}}', acls, re.M)
        fingerprint = hashlib.sha256(text.encode()).hexdigest()
        previous = saved.get(str(ident), {})
        if not match or previous.get('rules') != fingerprint:
            prefix = f'set acl-plugin acl index {match[1]}' if match else f'set acl-plugin acl tag {tag}'
            output = cli(prefix + ' ' + text + (f' tag {tag}' if match else ''))
            match = re.search(r'ACL index:\s*(\d+)', output) or match
        if not match:
            raise RuntimeError('source policy ACL was not created')
        index = int(match[1])
        existing = re.search(rf'policy:{ident}\s+acl:(\d+)', policies)
        if existing and int(existing[1]) != index:
            raise RuntimeError('ABF policy ID is owned by another configuration')
        path = f'{ipaddress.ip_address(policy["via"])} {policy["output_interface"]}'
        if existing and previous and previous.get('path') != path:
            for name in set(previous.get('interfaces', []) + attached):
                if name in interfaces and re.search(rf'policy:{ident}\b', cli(f'show abf attach {name}')):
                    family = 'ip6' if ':' in previous['path'].split()[0] else 'ip4'
                    cli(f'abf attach {family} del policy {ident} {name}')
            cli(f'abf policy del id {ident}')
            existing = None
        if not existing:
            cli(f'abf policy add id {ident} acl {index} via {path}')
        for name in attached:
            if not re.search(rf'policy:{ident}\b', cli(f'show abf attach {name}')):
                cli(f'abf attach {"ip6" if ":" in policy["via"] else "ip4"} policy {ident} {name}')
        result[str(ident)] = {'rules': fingerprint, 'path': path, 'interfaces': attached}
    return result

class Watcher:
    """Decide when a full reconcile is due.

    A reconcile dumps every ACL and ABF policy through the CLI, so it runs
    only when its inputs change: the configuration, the VPP instance, or the
    interfaces and addresses it reads. A failed attempt is retried on the next
    poll, and a slow resync repairs policies removed by hand."""

    def __init__(self, resync=RESYNC, clock=time.monotonic):
        self.resync, self.clock = resync, clock
        self.inputs = None
        self.last = None

    def due(self, inputs):
        return (inputs != self.inputs or self.last is None
                or self.clock() - self.last >= self.resync)

    def done(self, inputs):
        self.inputs, self.last = inputs, self.clock()

    def failed(self):
        self.inputs = self.last = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    saved = {}
    generation = None
    watcher = Watcher()
    while True:
        try:
            text = args.config.read_text()
            config = json.loads(text)
            socket = config.get('vpp_socket', '/run/vpp/cli.sock')
            stat = Path(socket).stat()
            current = stat.st_ino, stat.st_ctime_ns
            if current != generation:
                saved = {}; generation = current
                state_path = Path(config.get('state_file', '/run/vpp-source-routes/state.json'))
                if not str(state_path).startswith('/run/'):
                    raise ValueError('source policy state must be under /run')
                if state_path.exists():
                    record = json.loads(state_path.read_text())
                    if record.get('generation') == list(current):
                        saved = record['policies']
            cli = lambda text: command(socket, text)
            # Interfaces appearing and LAN prefixes changing (IPv6-PD) both
            # show up here; this one command is the whole idle poll.
            inputs = text, current, cli('show interface address')
            if watcher.due(inputs):
                saved = reconcile(config, saved, cli)
                state_path.parent.mkdir(parents=True, exist_ok=True)
                temporary = state_path.with_suffix('.tmp')
                temporary.write_text(json.dumps({'generation': current, 'policies': saved})+'\n')
                temporary.replace(state_path)
                watcher.done(inputs)
            if args.once:
                return
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            watcher.failed()
            if args.once:
                raise
            print(f'source routes waiting: {exc}', flush=True)
        time.sleep(2)

if __name__ == '__main__':
    main()
