#!/usr/bin/env python3
"""Shared VPP route backend and in-memory ledger for DNS Gate and importers."""

import copy
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import asdict, dataclass
import fcntl
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

LOG = logging.getLogger('vpp-nft-route-sync')
STATE_STORE = None
NAME = re.compile(r'[A-Za-z0-9_.:/-]{1,128}\Z')
# DNS answers are a handful of prefixes; beyond this, one table dump beats N vppctl processes.
EXACT_LOOKUP_LIMIT = 16


@dataclass(frozen=True, order=True)
class Route:
    table: int
    prefix: str
    via: str
    interface: str

    @property
    def key(self):
        return self.table, self.prefix

    def command(self, action):
        return f'ip route {action} {self.prefix} table {self.table} via {self.via} {self.interface}'


class PrefixIndex:
    """Sparse prefix lengths with integer address keys, separated by FIB/family.

    A host lookup probes only occupied prefix lengths, never all stored routes.
    Values retain every matching policy; the caller applies configuration order.
    """
    def __init__(self):
        self.groups = {}

    def add(self, network, value, table=0):
        lengths = self.groups.setdefault((table, network.version), {})
        addresses = lengths.setdefault(network.prefixlen, {})
        addresses.setdefault(int(network.network_address), set()).add(value)

    def covering(self, network, table=0):
        address = int(network.network_address)
        bits = network.max_prefixlen
        for length, addresses in self.groups.get((table, network.version), {}).items():
            if length <= network.prefixlen:
                shift = bits - length
                yield from addresses.get((address >> shift) << shift, ())


def static_prefix_index(config):
    source = config.get('_static_prefixes', {})
    cached = config.get('_static_index')
    if cached is None or cached[0] is not source:
        index = PrefixIndex()
        for key, prefixes in source.items():
            for prefix in prefixes:
                index.add(ipaddress.ip_network(prefix), (key, prefix))
        config['_static_index'] = source, index
        return index
    return cached[1]


def exclusion_index(config):
    source = tuple(config['exclude_prefixes'])
    cached = config.get('_exclusion_index')
    if cached is None or cached[0] != source:
        networks = tuple(ipaddress.ip_network(prefix) for prefix in source)
        index = PrefixIndex()
        for network in networks:
            index.add(network, True)
        cached = source, index, networks
        config['_exclusion_index'] = cached
    return cached[1:]


def prefix_excluded(config, network):
    index, networks = exclusion_index(config)
    if network.num_addresses == 1:
        return next(index.covering(network), False)
    return is_excluded(network, set(), networks)


def address(value):
    result = ipaddress.ip_address(value)
    if '%' in str(result) or result.is_unspecified or result.is_multicast:
        raise ValueError('a unicast address without a scope suffix is required')
    return result


def load_config(path):
    config = json.loads(Path(path).read_text())
    if not isinstance(config, dict) or not isinstance(config.get('mappings'), list):
        raise ValueError('configuration must contain a mappings array')
    config.setdefault('interval_seconds', 2)
    config.setdefault('monitor_resync_seconds', 60)
    config.setdefault('max_routes', 10000)
    config.setdefault('idle_seconds', 7 * 24 * 3600)
    config.setdefault('fib_audit_seconds', 60)
    config.setdefault('vpp_socket', '/run/vpp/cli.sock')
    config.setdefault('vpp_service', 'vpp')
    config.setdefault('state_file', '/var/lib/vpp-nft-route-sync/state.json')
    config.setdefault('lock_files', ['/run/lock/vpp-wireguard-client-import.lock',
                                     '/run/lock/vpp-wireguard-import.lock'])
    config.setdefault('exclude_prefixes', [])
    if config.get('dns_upstream_policy', 'first-upstream') not in ('first', 'first-upstream'):
        raise ValueError('dns_upstream_policy must be first or first-upstream')
    if config.get('overlap_policy', 'error') not in ('error', 'first'):
        raise ValueError('overlap_policy must be error or first')
    if not 0.2 <= float(config['interval_seconds']) <= 3600:
        raise ValueError('interval_seconds must be between 0.2 and 3600')
    if not 1 <= float(config['monitor_resync_seconds']) <= 3600:
        raise ValueError('monitor_resync_seconds must be between 1 and 3600')
    if not isinstance(config['max_routes'], int) or not 1 <= config['max_routes'] <= 1000000:
        raise ValueError('max_routes must be between 1 and 1000000')
    if not isinstance(config['idle_seconds'], int) or not 0 <= config['idle_seconds'] <= 90 * 24 * 3600:
        raise ValueError('idle_seconds must be between 0 and 90 days')
    if not isinstance(config['fib_audit_seconds'], (int, float)) or not 0 <= float(config['fib_audit_seconds']) <= 86400:
        raise ValueError('fib_audit_seconds must be between 0 and 86400')
    for name in ('vpp_service',):
        if not NAME.fullmatch(config[name]):
            raise ValueError('invalid ' + name)
    for mapping in config['mappings']:
        if not isinstance(mapping.get('enabled', True), bool):
            raise ValueError('enabled must be boolean')
        if not mapping.get('enabled', True):
            continue
        for name in ('family', 'table', 'set', 'interface'):
            if not isinstance(mapping.get(name), str) or not NAME.fullmatch(mapping[name]):
                raise ValueError('invalid mapping ' + name)
        if mapping['family'] not in ('ip', 'ip6', 'inet'):
            raise ValueError('only ip, ip6 and inet nftables families are supported')
        if 'tproxy_set' in mapping and (not isinstance(mapping['tproxy_set'], str)
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', mapping['tproxy_set'])):
            raise ValueError('invalid tproxy_set')
        if mapping.get('tproxy_set') and config.get('overlap_policy') != 'first':
            raise ValueError('tproxy_set requires ordered reconciliation')
        mapping['via'] = str(address(mapping['via']))
        mapping.setdefault('fib_table', 0)
        if type(mapping['fib_table']) is not int or not 0 <= mapping['fib_table'] < 2**32:
            raise ValueError('invalid fib_table')
    for prefix in config['exclude_prefixes']:
        ipaddress.ip_network(prefix, strict=True)
    return config


def nft_prefixes(document, family, table, name):
    """Read typed address sets; honor the kernel-reported remaining lifetime."""
    sets = [item['set'] for item in document.get('nftables', []) if 'set' in item
            and (item['set'].get('family'), item['set'].get('table'), item['set'].get('name'))
            == (family, table, name)]
    if len(sets) != 1:
        raise ValueError(f'missing or ambiguous nft set {family}/{table}/{name}')
    data = sets[0]
    version = {'ipv4_addr': 4, 'ipv6_addr': 6}.get(data.get('type'))
    if not version or 'map' in data.get('flags', []):
        raise ValueError('only ipv4_addr and ipv6_addr sets are supported')
    result = set()
    for element in data.get('elem', []):
        if isinstance(element, dict) and 'elem' in element:
            metadata = element['elem']
            if 'expires' in metadata and metadata['expires'] <= 0:
                continue
            element = metadata['val']
        if isinstance(element, str):
            networks = [ipaddress.ip_network(element, strict=True)]
        elif isinstance(element, dict) and set(element) == {'prefix'}:
            p = element['prefix']
            networks = [ipaddress.ip_network(f'{p["addr"]}/{p["len"]}', strict=True)]
        elif isinstance(element, dict) and set(element) == {'range'}:
            first, last = map(ipaddress.ip_address, element['range'])
            networks = list(ipaddress.summarize_address_range(first, last))
        else:
            raise ValueError('unsupported nft set element; refusing an incomplete snapshot')
        for network in networks:
            if network.version != version or network.prefixlen == 0:
                raise ValueError('set family mismatch or forbidden default route')
            result.add(str(network))
    return result


def parse_fib(text, table):
    """Parse VPP 26.06's full FIB display, excluding recursively stacked paths."""
    if not re.search(r'ipv[46]-VRF:' + str(table) + r'\b', text):
        raise ValueError(f'VPP table {table} was not returned')
    result = {}
    chunks = re.split(r'(?m)^([0-9a-fA-F:.]+/\d+)(?:[^\n]*)\n', text)
    for index in range(1, len(chunks), 2):
        prefix = str(ipaddress.ip_network(chunks[index], strict=True))
        paths = set()
        for via, interface in re.findall(
                r'(?m)^    \[\d+\] \[@\d+\]: ipv[46][^\n]*?\bvia (\S+) ([^\s:]+)',
                chunks[index + 1]):
            paths.add((str(ipaddress.ip_address(via)), interface))
        # Even a drop/local/connected route reserves this exact prefix.
        result[(table, prefix)] = frozenset(paths)
    return result


def is_excluded(network, protected, exclusions):
    return any(p.version == network.version and p in network for p in protected) or any(
        n.version == network.version and n.overlaps(network) for n in exclusions)


def matches(route, live):
    return live.get(route.key) == frozenset({(route.via, route.interface)})


def plan(desired, owned, live):
    # Losing/changing a route externally relinquishes ownership, never deletes it.
    current = {r.key: r for r in owned if matches(r, live)}
    remove = [r for key, r in current.items() if desired.get(key) != r]
    add, conflicts = [], []
    for key, route in desired.items():
        if current.get(key) == route:
            continue
        if key not in live or key in current:
            add.append(route)
        else:
            conflicts.append(route)
    return sorted(remove), sorted(add), sorted(current.values()), sorted(conflicts)


class PrefixLocks:
    """Per-prefix locks. DNS renewal and background withdraw of one prefix serialize."""

    def __init__(self):
        self._guard = threading.Lock()
        self._locks = {}

    @contextmanager
    def hold(self, keys):
        ordered = sorted(set(keys))
        if not ordered:
            yield
            return
        refs = []
        with self._guard:
            for key in ordered:
                lock, count = self._locks.get(key, (threading.Lock(), 0))
                self._locks[key] = (lock, count + 1)
                refs.append((key, lock))
        for _, lock in refs:
            lock.acquire()
        try:
            yield
        finally:
            for _, lock in reversed(refs):
                lock.release()
            with self._guard:
                for key, _ in refs:
                    lock, count = self._locks[key]
                    if count <= 1:
                        del self._locks[key]
                    else:
                        self._locks[key] = (lock, count - 1)


def open_lock(path):
    """Create or open a lock file without truncating it."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    return os.fdopen(fd, 'r+')


def shared_lock_files(paths):
    """Shared flock. Does not rewrite the files, so importer mtime remains the rebuild epoch."""
    stack = ExitStack()
    try:
        for name in sorted(set(paths)):
            handle = stack.enter_context(open_lock(name))
            fcntl.flock(handle, fcntl.LOCK_SH)
        return stack
    except Exception:
        stack.close()
        raise


def read_json(path, default=None):
    if STATE_STORE is not None and STATE_STORE.handles(path):
        return STATE_STORE.read(path, default)
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def atomic_json(path, value):
    if STATE_STORE is not None and STATE_STORE.handles(path):
        STATE_STORE.write(path, value)
        return
    durable_json(path, value)


class DeferredState:
    """Memory-authoritative ledger, persisted only when the daemon stops."""
    def __init__(self, paths):
        self.paths = {str(Path(p)) for p in paths}
        self.values = {}
        self.dirty = set()
        self.lock = threading.Lock()
        self.ledgers = {}
        self.prefix_indexes = {}
        self.lazy = {}

    def defer(self, path, snapshot):
        with self.lock:
            key = str(Path(path))
            self.lazy[key] = snapshot
            self.dirty.add(key)

    def ledger(self, path, generation):
        """Called under lock; keep Route objects indexed until a bulk replacement."""
        key = str(Path(path))
        if key not in self.ledgers:
            state = self.values.get(key)
            if state is None:
                state = json.loads(Path(path).read_text()) if Path(path).exists() else {}
            if state and state.get('version') != 1:
                raise ValueError('unsupported state version')
            maps = [{Route(**item).key: Route(**item) for item in state.get(name, [])}
                    if state.get('generation') == generation else {}
                    for name in ('owned', 'pending_add')]
            self.ledgers[key] = (generation, maps, state.get('audited_at'))
        if self.ledgers[key][0] != generation:
            self.ledgers[key] = (generation, [{}, {}], None)
            self.prefix_indexes.pop(key, None)
        if key not in self.prefix_indexes:
            index = PrefixIndex()
            for routes in self.ledgers[key][1]:
                for route in routes.values():
                    index.add(ipaddress.ip_network(route.prefix), route.key, route.table)
            self.prefix_indexes[key] = index
        return self.ledgers[key][1]

    def _snapshot(self, key):
        if key in self.ledgers:
            generation, maps, audited = self.ledgers[key]
            state = {'version': 1, 'generation': generation,
                     'owned': [asdict(r) for r in sorted(maps[0].values())],
                     'pending_add': [asdict(r) for r in sorted(maps[1].values())]}
            if audited is not None:
                state['audited_at'] = audited
            return state
        return copy.deepcopy(self.values[key])

    def handles(self, path):
        return str(Path(path)) in self.paths

    def read(self, path, default):
        key = str(Path(path))
        with self.lock:
            snapshot = self.lazy.get(key)
            if key not in self.values and key not in self.ledgers and snapshot is None:
                self.values[key] = json.loads(Path(path).read_text()) if Path(path).exists() else default
            if snapshot is None:
                return self._snapshot(key)
        return snapshot()

    def write(self, path, value):
        key = str(Path(path))
        with self.lock:
            self.ledgers.pop(key, None)
            self.prefix_indexes.pop(key, None)
            self.lazy.pop(key, None)
            self.values[key] = copy.deepcopy(value)
            self.dirty.add(key)

    def flush(self):
        with self.lock:
            pending = {key: self.lazy.get(key) or self._snapshot(key) for key in self.dirty}
            self.dirty.clear()
        for key, value in pending.items():
            try:
                if callable(value):
                    value = value()
                durable_json(key, value)
            except Exception:
                with self.lock:
                    self.dirty.update(pending)
                raise

    def __enter__(self):
        global STATE_STORE
        STATE_STORE = self
        return self

    def __exit__(self, *unused):
        global STATE_STORE
        try:
            self.flush()
        finally:
            STATE_STORE = None


class StateServer:
    """Expose the current in-memory ledger to the manual interface importer."""
    def __init__(self, config):
        self.path = Path(config.get('state_socket', '/run/vpp-nft-route-sync/state.sock'))
        self.state_file = config['state_file']

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.unlink(missing_ok=True)
        state_file = self.state_file
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                self.request.sendall(json.dumps(read_json(state_file, {})).encode())
        self.server = socketserver.UnixStreamServer(str(self.path), Handler)
        self.path.chmod(0o600)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=.1),
                                       name='route-ledger', daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *unused):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.path.unlink(missing_ok=True)


def importer_state(config):
    path = Path(config.get('state_socket', '/run/vpp-nft-route-sync/state.sock'))
    if not path.exists():
        return read_json(config['state_file'], {})  # Daemon stopped: saved ledger is authoritative.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        stream.connect(str(path))
        with stream.makefile('r') as source:
            return json.load(source)


def durable_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.state-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _covered_by(prefix, networks):
    return any(prefix.subnet_of(other) or prefix == other for other in networks)


def tproxy_nft_script(desired, current):
    """Build add/delete lines that converge lease sets without flushing them.

    Lease sets are interval sets and already hold collapsed CIDRs. A host /32 is
    already intercepted when a covering interval exists, so membership is
    coverage, not exact CIDR equality. Add only uncovered hosts; delete only
    intervals that cover no desired prefix. Apply deletes before adds.
    """
    add_lines, delete_lines = [], []
    for family, table, name in sorted(set(desired) | set(current)):
        want = set(desired.get((family, table, name), set()))
        have = set(current.get((family, table, name), set()))
        extra_add = {prefix for prefix in want if not _covered_by(prefix, have)}
        extra_del = {prefix for prefix in have if not any(_covered_by(item, {prefix}) for item in want)}
        if extra_del:
            members = ', '.join(str(network) for network in sorted(extra_del))
            delete_lines.append(f'delete element {family} {table} {name} {{ {members} }}')
        if extra_add:
            members = ', '.join(str(network) for network in sorted(extra_add))
            add_lines.append(f'add element {family} {table} {name} {{ {members} }}')
    return add_lines, delete_lines


class Backend:
    _generations = {}
    _generation_lock = threading.Lock()
    _api_lock = threading.Lock()
    _tproxy_lock = threading.Lock()
    _api_client = None
    _api_identity = None
    _interfaces = {}
    _cli_source = None
    def __init__(self, config):
        self.config = config

    @staticmethod
    def run(args):
        result = subprocess.run(args, text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(f'{args[0]} failed: {result.stderr.strip()[:300]}')
        return result.stdout

    def _tproxy_desired(self, routes):
        groups = {}
        for mapping in self.config['mappings']:
            if not mapping.get('enabled', True) or 'tproxy_set' not in mapping:
                continue
            key = mapping['family'], mapping['table'], mapping['tproxy_set']
            prefixes = groups.setdefault(key, set())
            prefixes.update(ipaddress.ip_network(route.prefix) for route in routes
                            if (route.table, route.via, route.interface) ==
                            (mapping['fib_table'], mapping['via'], mapping['interface']))
        return groups

    def _set_networks(self, family, table, name):
        document = json.loads(self.run(['nft', '-j', 'list', 'set', family, table, name]))
        return {ipaddress.ip_network(prefix) for prefix in nft_prefixes(document, family, table, name)}

    def _apply_nft(self, lines, allow_missing=False):
        if not lines:
            return
        result = subprocess.run(['nft', '-f', '-'], input='\n'.join(lines) + '\n',
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            message = 'lease TPROXY update failed: ' + result.stderr.strip()[:300]
            if allow_missing:
                LOG.warning(message)
                return
            raise RuntimeError(message)

    def sync_tproxy(self, routes):
        """Make lease sets match these routes; add/delete the diff, do not flush."""
        with self._tproxy_lock:
            desired = self._tproxy_desired(routes)
            current = {key: self._set_networks(*key) for key in desired}
            add_lines, delete_lines = tproxy_nft_script(desired, current)
            try:
                self._apply_nft(delete_lines)
            except RuntimeError as error:
                LOG.warning('%s; retrying deletes one set at a time', error)
                for line in delete_lines:
                    self._apply_nft([line], allow_missing=True)
            self._apply_nft(add_lines)

    def cli(self, line):
        return self.run(['vppctl', '-s', self.config['vpp_socket'], line])

    @staticmethod
    def _process_identity(pid):
        try:
            fields = Path('/proc', str(pid), 'stat').read_text().rpartition(') ')[2].split()
            if fields[0] in ('Z', 'X'):
                raise RuntimeError('VPP process is not running')
            return fields[19]  # starttime, field 22; comm may contain spaces.
        except (OSError, IndexError) as error:
            raise RuntimeError('VPP process is not running') from error

    def generation(self):
        sock = Path(self.config['vpp_socket']).stat()
        identity = (self.config['vpp_service'], sock.st_ino, sock.st_ctime_ns)
        with self._generation_lock:
            cached = self._generations.get(identity)
        if cached is not None:
            value, pid, start = cached
            if self._process_identity(pid) != start:
                raise RuntimeError('VPP process changed at route barrier')
            return value
        properties = dict(line.split('=', 1) for line in self.run(
            ['systemctl', 'show', self.config['vpp_service'], '-p', 'InvocationID',
             '-p', 'MainPID', '-p', 'ActiveState']).splitlines() if '=' in line)
        value = properties.get('InvocationID', '')
        pid = properties.get('MainPID', '0')
        if (not re.fullmatch(r'[a-f0-9]{32}', value) or not pid.isdigit() or int(pid) <= 0
                or properties.get('ActiveState') != 'active'):
            raise RuntimeError('VPP has no active invocation')
        start = self._process_identity(pid)
        with self._generation_lock:
            self._generations.clear()
            self._generations[identity] = (value, pid, start)
        return value

    def prefixes(self, mapping):
        document = json.loads(self.run(['nft', '-j', 'list', 'set',
                                        mapping['family'], mapping['table'], mapping['set']]))
        return nft_prefixes(document, mapping['family'], mapping['table'], mapping['set'])

    @staticmethod
    def _fib_family(version):
        return 'ip' if version == 4 else 'ip6'

    def lookup_exact(self, route):
        """Exact table+prefix paths, or None if absent. Covering LPM is ignored."""
        family = self._fib_family(ipaddress.ip_network(route.prefix).version)
        entries = parse_fib(self.cli(f'show {family} fib table {route.table} {route.prefix}'),
                            route.table)
        return entries.get(route.key)

    def dump_owned(self, table, family):
        """One `show ip fib table` for startup, recovery, and background reconcile."""
        return parse_fib(self.cli(f'show {self._fib_family(family)} fib table {table}'), table)

    def snapshot(self, routes):
        """Bulk dump of each FIB table touched by these routes. One CLI per table."""
        result = {}
        for table, version in sorted({(r.table, ipaddress.ip_network(r.prefix).version) for r in routes}):
            result.update(self.dump_owned(table, version))
        return result

    def lookup(self, routes):
        """Exact-prefix query for a few routes; table dump when the set is large."""
        wanted, seen = [], set()
        for route in sorted(routes):
            if route.key in seen:
                continue
            seen.add(route.key)
            wanted.append(route)
        if len(wanted) > EXACT_LOOKUP_LIMIT:
            dump = self.snapshot(wanted)
            return {route.key: dump[route.key] for route in wanted if route.key in dump}
        result = {}
        for route in wanted:
            paths = self.lookup_exact(route)
            if paths is not None:
                result[route.key] = paths
        return result

    def apply(self, lines):
        from vpp_papi import VPPApiClient
        cls = Backend
        socket_path = self.config.get('api_socket', '/run/vpp/api.sock')
        sock = Path(socket_path).stat()
        lock_stamp = tuple((name, Path(name).stat().st_mtime_ns if Path(name).exists() else 0)
                           for name in self.config.get('lock_files', []))
        identity = (socket_path, sock.st_ino, sock.st_ctime_ns, lock_stamp)
        with cls._api_lock:
            try:
                if cls._api_identity != identity:
                    if cls._api_client is not None:
                        cls._api_client.disconnect()
                    cls._api_client = VPPApiClient(server_address=socket_path, read_timeout=2)
                    cls._api_client.connect('nft-route-sync')
                    cls._api_identity = identity
                    cls._interfaces = {}
                    cls._cli_source = next(item.src.id for item in cls._api_client.api.fib_source_dump()
                                           if item.src.name == 'CLI')
                    cls._interfaces = {item.interface_name: item.sw_if_index
                                       for item in cls._api_client.api.sw_interface_dump()}
                api = cls._api_client.api
                for line in lines:
                    words = line.split()
                    if len(words) != 9 or words[:2] != ['ip', 'route'] or words[2] not in ('add', 'del') or words[4] != 'table' or words[6] != 'via':
                        raise ValueError('unsupported route command: ' + line)
                    _, _, action, prefix, _, table, _, via, interface = words
                    if interface not in cls._interfaces:
                        cls._interfaces.update({item.interface_name: item.sw_if_index
                                                for item in api.sw_interface_dump()})
                    if interface not in cls._interfaces:
                        raise RuntimeError('VPP route interface does not exist: ' + interface)
                    reply = api.ip_route_add_del_v2(is_add=action == 'add', is_multipath=True,
                        route={'table_id': int(table), 'prefix': prefix, 'n_paths': 1, 'src': cls._cli_source,
                               'paths': [{'sw_if_index': cls._interfaces[interface],
                                          'weight': 1, 'label_stack': [{} for _ in range(16)],
                                          'proto': 0 if ipaddress.ip_address(via).version == 4 else 1,
                                          'nh': {'address': {'ip4' if ':' not in via else 'ip6': via}}}]})
                    if reply.retval != 0:
                        raise RuntimeError(f'VPP route API failed ({reply.retval}): {prefix}')
            except Exception as error:
                cls._api_identity = None
                cls._interfaces = {}
                raise RuntimeError(f'VPP Binary API request failed: {error}') from error


def interface_delete_commands(interface, generation, config_path='/etc/vpp/nftset-route-sync.json',
                              backend_factory=Backend):
    """Called while the WireGuard importer holds our shared interface lock."""
    if not Path(config_path).exists():
        return []
    config = load_config(config_path)
    path = Path(config['state_file'])
    if config['vpp_socket'] != '/run/vpp/cli.sock' or config['vpp_service'] != 'vpp':
        return []
    state = importer_state(config)
    if not state:
        return []
    if state.get('version') != 1:
        raise ValueError('unsupported route-sync state version')
    if state.get('generation') != generation:
        return []
    routes = {Route(**r) for r in state.get('owned', []) + state.get('pending_add', [])
              if r['interface'] == interface}
    backend = backend_factory(config)
    live = backend.lookup(routes)
    # Remove owned paths before their interface index becomes invalid. The daemon
    # retains ownership intent and restores still-desired members on its next poll.
    return [r.command('del') for r in sorted(routes) if matches(r, live)]


def _load_owned(config, backend):
    path = Path(config['state_file'])
    generation = backend.generation()
    state, owned_map, pending_map = _split_state(path, generation)
    return path, state, generation, list(owned_map.values()), list(pending_map.values())


def _commit_owned(path, generation, desired, live):
    state, owned_map, pending_map = _split_state(path, generation)
    for route in desired.values():
        if not matches(route, live):
            raise RuntimeError('DNS route barrier rejected an excluded or conflicting route')
        if owned_map.get(route.key) == route or pending_map.get(route.key) == route:
            owned_map[route.key] = route
            pending_map.pop(route.key, None)
    final = {'version': 1, 'generation': generation,
             'pending_add': [asdict(r) for r in sorted(pending_map.values())],
             'owned': [asdict(r) for r in sorted(owned_map.values())]}
    if final != state:
        atomic_json(path, final)


def _ordered_winners(config, required, claimed):
    mappings = [mapping for mapping in config['mappings'] if mapping.get('enabled', True)]
    _, exclusions = exclusion_index(config)
    if any(prefix_excluded(config, ipaddress.ip_network(route.prefix)) for route in required):
        raise RuntimeError('DNS route barrier rejected an excluded or conflicting route')
    extra = {}
    for route in required:
        candidates = [mapping for mapping in mappings
                      if (mapping['fib_table'], mapping['via'], mapping['interface']) ==
                      (route.table, route.via, route.interface)]
        if not candidates:
            raise ValueError('route has no configured mapping')
        for mapping in candidates:
            extra.setdefault(_mapping_key(mapping), set()).add(route.prefix)
    needed = [ipaddress.ip_network(route.prefix) for route in required]
    prefix_sets = {key: set(prefixes) for key, prefixes in extra.items()}
    if all(network.num_addresses == 1 for network in needed):
        index = static_prefix_index(config)
        for network in needed:
            for key, prefix in index.covering(network):
                prefix_sets.setdefault(key, set()).add(prefix)
    else:
        for key, prefixes in config.get('_static_prefixes', {}).items():
            for prefix in prefixes:
                network = ipaddress.ip_network(prefix)
                if any(network.version == other.version and network.overlaps(other) for other in needed):
                    prefix_sets.setdefault(key, set()).add(prefix)
    by_path = {(mapping['fib_table'], mapping['via'], mapping['interface']): _mapping_key(mapping)
               for mapping in mappings}
    for route in claimed.values():
        key = by_path.get((route.table, route.via, route.interface))
        if key is None:
            continue
        network = ipaddress.ip_network(route.prefix)
        if any(network.version == other.version and network.overlaps(other) for other in needed):
            prefix_sets.setdefault(key, set()).add(route.prefix)
    desired, _ = _collect_desired(mappings, prefix_sets, set(), exclusions, 'first')
    return covering_routes(desired, required)


def _add_memory_hosts(config, backend, required, mutex=None):
    """Update only the requested hosts; materialize the ledger at audit/stop."""
    store, path = STATE_STORE, config['state_file']
    generation = backend.generation()
    lock = mutex if mutex is not None else nullcontext()
    with lock, store.lock:
        owned, pending = store.ledger(path, generation)
        claimed = {}
        for route in required:
            network = ipaddress.ip_network(route.prefix)
            for key in store.prefix_indexes[str(Path(path))].covering(network, route.table):
                candidate = pending.get(key) or owned.get(key)
                if candidate is not None:
                    claimed[key] = candidate
        if config.get('overlap_policy') == 'first':
            winners = _ordered_winners(config, required, claimed)
        else:
            desired = {}
            exclusions = [ipaddress.ip_network(n) for n in config['exclude_prefixes']]
            for route in required:
                if (route.key in desired and desired[route.key] != route
                        or (pending.get(route.key) or owned.get(route.key)) not in (None, route)):
                    raise RuntimeError('direct route install found a conflicting local route claim')
                if is_excluded(ipaddress.ip_network(route.prefix), set(), exclusions):
                    raise RuntimeError('DNS route barrier rejected an excluded or conflicting route')
                desired[route.key] = route
            winners = sorted(desired.values())
        new_keys = {r.key for r in winners if r.key not in owned and r.key not in pending}
        if len(owned) + sum(key not in owned for key in pending) + len(new_keys) > config['max_routes']:
            raise ValueError('max_routes exceeded')
        remove = []
        for route in winners:
            previous = pending.get(route.key) or owned.get(route.key)
            if previous is not None and previous != route:
                remove.append(previous)
            pending[route.key] = route
            store.prefix_indexes[str(Path(path))].add(
                ipaddress.ip_network(route.prefix), route.key, route.table)
        store.dirty.add(str(Path(path)))
    backend.apply([r.command('del') for r in remove] + [r.command('add') for r in winners])
    if backend.generation() != generation:
        raise RuntimeError('VPP restarted during reconciliation; retrying')
    with lock, store.lock:
        owned, pending = store.ledger(path, generation)
        for route in winners:
            if pending.get(route.key) == route:
                owned[route.key] = route
                pending.pop(route.key, None)
        store.dirty.add(str(Path(path)))
    return {'add': len(winners), 'delete': len(remove), 'conflicts': 0,
            'excluded': 0, 'desired': len(winners), 'winners': winners}


def _add_ordered_routes(config, backend, required, mutex=None):
    """Install ordered winners without listing nft sets or rewriting lease sets."""
    lock = mutex if mutex is not None else nullcontext()
    add, remove = [], []
    with lock:
        path, state, generation, owned, pending = _load_owned(config, backend)
        owned_map = {route.key: route for route in owned}
        pending_map = {route.key: route for route in pending}
        claimed = {route.key: route for route in list(owned) + list(pending)}
        winners = _ordered_winners(config, required, claimed)
        for route in winners:
            previous = owned_map.get(route.key) or pending_map.get(route.key)
            if previous is not None and previous != route:
                remove.append(previous)
            add.append(route)
            pending_map[route.key] = route
        add, remove = sorted(set(add)), sorted(set(remove))
        if len({*owned_map, *pending_map}) > config['max_routes']:
            raise ValueError('max_routes exceeded')
        if add or remove:
            pending_state = {'version': 1, 'generation': generation,
                             'owned': [asdict(route) for route in sorted(owned_map.values())],
                             'pending_add': [asdict(route) for route in sorted(pending_map.values())]}
            if 'audited_at' in state:
                pending_state['audited_at'] = state['audited_at']
            atomic_json(path, pending_state)
    if add or remove:
        backend.apply([route.command('del') for route in remove] +
                      [route.command('add') for route in add])
        if backend.generation() != generation:
            raise RuntimeError('VPP restarted during reconciliation; retrying')
    with lock:
        state, owned_map, pending_map = _split_state(path, generation)
        for route in remove:
            if owned_map.get(route.key) == route:
                owned_map.pop(route.key, None)
            if pending_map.get(route.key) == route:
                pending_map.pop(route.key, None)
        for route in winners:
            owned_map[route.key] = route
            pending_map.pop(route.key, None)
        final = {'version': 1, 'generation': generation,
                 'pending_add': [asdict(route) for route in sorted(pending_map.values())],
                 'owned': [asdict(route) for route in sorted(owned_map.values())]}
        if 'audited_at' in state:
            final['audited_at'] = state['audited_at']
        if final != state:
            atomic_json(path, final)
    return {'add': len(add), 'delete': len(remove), 'conflicts': 0, 'excluded': 0,
            'desired': len(winners), 'winners': winners}


def ensure_routes(config, backend, required, mutex=None):
    """Install only these prefixes without a pre-install FIB lookup.

    `mutex` guards state.json read-modify-write. VPP apply runs without it so a
    first DNS IP can install while background reconcile applies other prefixes.
    """
    return add_routes(config, backend, required, mutex=mutex)


def add_routes(config, backend, required, mutex=None):
    """Directly add routes and record successful commands without querying FIB.

    This is the fast path for a new nftset member or DNS answer. The VPP batch
    result is authoritative for the operation; the background audit repairs
    missing routes and detects externally-created conflicts later.
    """
    required = sorted(set(required))
    if (required and STATE_STORE is not None and STATE_STORE.handles(config['state_file'])
            and all(ipaddress.ip_network(r.prefix).num_addresses == 1 for r in required)):
        return _add_memory_hosts(config, backend, required, mutex)
    if required and config.get('overlap_policy') == 'first':
        return _add_ordered_routes(config, backend, required, mutex)
    lock = mutex if mutex is not None else nullcontext()
    if not required:
        return {'add': 0, 'delete': 0, 'conflicts': 0, 'excluded': 0, 'desired': 0, 'winners': []}
    desired = {}
    for route in required:
        if route.key in desired and desired[route.key] != route:
            raise ValueError(f'conflicting mappings for {route.prefix}; refusing partial reconciliation')
        desired[route.key] = route
    exclusions = [ipaddress.ip_network(n) for n in config['exclude_prefixes']]
    if any(is_excluded(ipaddress.ip_network(route.prefix), set(), exclusions)
           for route in desired.values()):
        raise RuntimeError('DNS route barrier rejected an excluded or conflicting route')
    add = []
    with lock:
        path, state, generation, owned, pending = _load_owned(config, backend)
        owned_map = {r.key: r for r in owned}
        pending_map = {r.key: r for r in pending}
        for route in desired.values():
            previous = owned_map.get(route.key) or pending_map.get(route.key)
            if previous is not None and previous != route:
                raise RuntimeError('direct route install found a conflicting local route claim')
            # Re-submit even an owned route. This is intentional: a WireGuard
            # rebuild can remove the FIB path while the local ownership record
            # remains, and VPP de-duplicates an identical path.
            add.append(route)
        add = sorted(add)
        claimed = len({*owned_map, *pending_map, *(r.key for r in add)})
        if claimed > config['max_routes']:
            raise ValueError('max_routes exceeded')
        if add:
            for route in add:
                pending_map[route.key] = route
            pending_state = {'version': 1, 'generation': generation,
                             'owned': [asdict(r) for r in sorted(owned_map.values())],
                             'pending_add': [asdict(r) for r in sorted(pending_map.values())]}
            if 'audited_at' in state:
                pending_state['audited_at'] = state['audited_at']
            atomic_json(path, pending_state)
    if add:
        backend.apply([r.command('add') for r in add])
        if backend.generation() != generation:
            raise RuntimeError('VPP restarted during reconciliation; retrying')
    with lock:
        state, owned_map, pending_map = _split_state(path, generation)
        for route in desired.values():
            if owned_map.get(route.key) == route or pending_map.get(route.key) == route:
                owned_map[route.key] = route
                pending_map.pop(route.key, None)
        final = {'version': 1, 'generation': generation,
                 'pending_add': [asdict(r) for r in sorted(pending_map.values())],
                 'owned': [asdict(r) for r in sorted(owned_map.values())]}
        if 'audited_at' in state:
            final['audited_at'] = state['audited_at']
        if final != state:
            atomic_json(path, final)
    return {'add': len(add), 'delete': 0, 'conflicts': 0, 'excluded': 0, 'desired': len(desired),
            'winners': list(desired.values())}


def _mapping_key(mapping):
    return mapping['family'], mapping['table'], mapping['set']


def _read_state(path, generation):
    state, owned_map, pending_map = _split_state(path, generation)
    return state, list(owned_map.values()) + list(pending_map.values())


def _split_state(path, generation):
    path = Path(path)
    state = read_json(path, {})
    if state and state.get('version') != 1:
        raise ValueError('unsupported state version')
    if state.get('generation') != generation:
        return state, {}, {}
    owned = {Route(**item).key: Route(**item) for item in state.get('owned', [])}
    pending = {Route(**item).key: Route(**item) for item in state.get('pending_add', [])}
    return state, owned, pending


def _protect_concurrent(desired, candidates, prepared_state, generation):
    """Keep DNS installs that landed after prepare_sync in desired so commit does not delete them."""
    if prepared_state.get('generation') != generation:
        prepared_keys = set()
    else:
        prepared_keys = {(item['table'], item['prefix'])
                         for item in prepared_state.get('owned', []) + prepared_state.get('pending_add', [])}
    for route in candidates:
        if route.key not in prepared_keys and route.key not in desired:
            desired[route.key] = route


def _collect_desired(mappings, prefix_sets, protected, exclusions, overlap_policy="error"):
    desired, excluded = {}, 0
    prior_ranges, prior_hosts = {}, {}
    range_index, excluded_index = PrefixIndex(), PrefixIndex()
    for network in exclusions:
        excluded_index.add(network, True)
    for mapping in mappings:
        key = _mapping_key(mapping)
        accepted = []
        version = ipaddress.ip_address(mapping['via']).version
        for prefix in prefix_sets.get(key, ()):
            network = ipaddress.ip_network(prefix)
            if network.version != version:
                raise ValueError(f'address family mismatch for set {mapping["set"]}')
            host = network.num_addresses == 1
            blocked = (network.network_address in protected or next(excluded_index.covering(network), False)
                       if host else is_excluded(network, protected, exclusions))
            if blocked:
                excluded += 1
                continue
            group = mapping['fib_table'], network.version
            parts = [network]
            if overlap_policy == 'first':
                # Subtract earlier sets, including ranges. Otherwise a later
                # /32 would incorrectly override an earlier /24 in the FIB.
                # Host duplicates are resolved by desired. Do not scan every
                # earlier host for each host in a later set (quadratic work).
                if host:
                    if next(range_index.covering(network, mapping['fib_table']), False):
                        parts = []
                else:
                    for covered in (*prior_ranges.get(group, ()), *prior_hosts.get(group, ())):
                        parts = subtract_prefix(parts, covered)
            for part in parts:
                route = Route(mapping['fib_table'], str(part), mapping['via'], mapping['interface'])
                if route.key in desired and desired[route.key] != route:
                    if overlap_policy == 'first':
                        continue
                    raise ValueError(f'conflicting mappings for {prefix}; refusing partial reconciliation')
                desired[route.key] = route
            accepted.append(network)
        if overlap_policy == 'first':
            for network in accepted:
                prior = prior_hosts if network.num_addresses == 1 else prior_ranges
                prior.setdefault((mapping['fib_table'], network.version), []).append(network)
                if network.num_addresses != 1:
                    range_index.add(network, True, mapping['fib_table'])
    return desired, excluded


def subtract_prefix(parts, covered):
    result = []
    for part in parts:
        if not part.overlaps(covered):
            result.append(part)
        elif part.subnet_of(covered):
            continue
        else:
            result.extend(part.address_exclude(covered))
    return result


def covering_routes(desired, required):
    result = set()
    for request in required:
        network = ipaddress.ip_network(request.prefix)
        remaining = [network]
        for route in desired.values():
            prefix = ipaddress.ip_network(route.prefix)
            if route.table == request.table and prefix.version == network.version and prefix.overlaps(network):
                result.add(route)
                remaining = subtract_prefix(remaining, prefix)
        if remaining:
            raise RuntimeError('ordered route barrier rejected an excluded or missing prefix')
    return sorted(result)


def prepare_sync(config, backend, withdraw=False, audit=None, read_nft=True):
    """Read nft sets. Dump FIB tables on audit; otherwise skip the bulk snapshot."""
    path = Path(config['state_file'])
    generation = backend.generation()
    state, candidates = _read_state(path, generation)
    if audit is None:
        interval = float(config.get('fib_audit_seconds', 60))
        last = float(state.get('audited_at') or 0)
        audit = interval <= 0 or time.time() - last >= interval or state.get('generation') != generation
    mappings = [] if withdraw else [m for m in config['mappings'] if m.get('enabled', True)]
    protected = set()
    exclusions = [ipaddress.ip_network(n) for n in config['exclude_prefixes']]
    nft = ({_mapping_key(mapping): backend.prefixes(mapping) for mapping in mappings}
           if read_nft else {})
    markers = []
    for mapping in mappings:
        version = ipaddress.ip_address(mapping['via']).version
        markers.append(Route(mapping['fib_table'], '0.0.0.0/32' if version == 4 else '::/128',
                             mapping['via'], mapping['interface']))
    live = backend.snapshot(markers + candidates) if audit else {}
    return {'path': path, 'generation': generation, 'state': state, 'mappings': mappings,
            'protected': protected, 'exclusions': exclusions, 'nft': nft,
            'live': live, 'withdraw': withdraw, 'audit': audit, 'read_nft': read_nft}


def commit_sync(config, backend, prepared, dry_run=False, extra_prefixes=None, mutex=None,
                prefix_locks=None, refresh_prefixes=None, on_withdraw=None, verify_apply=True):
    """Apply a prepared reconcile. mutex covers state.json only, not VPP apply.

    prefix_locks serializes withdraw of a prefix with DNS observation of that prefix.
    After taking those locks, last-seen observations and nft are re-read before any delete.
    """
    lock = mutex if mutex is not None else nullcontext()
    generation = prepared['generation']
    if backend.generation() != generation:
        raise RuntimeError('VPP restarted during snapshot; retrying')
    mappings = prepared['mappings']
    protected = set()
    exclusions = prepared['exclusions']
    path = prepared['path']
    prefix_sets = {key: set(prefixes) for key, prefixes in prepared['nft'].items()}
    for key, prefixes in (extra_prefixes or {}).items():
        prefix_sets.setdefault(key, set()).update(prefixes)
    desired, excluded = _collect_desired(mappings, prefix_sets, protected, exclusions, config.get('overlap_policy', 'error'))
    live = dict(prepared['live'])
    preview_state, preview = _read_state(path, generation)
    audit = prepared.get('audit', True)
    if audit:
        refresh = [route for route in preview if route.key not in live]
        if refresh and len(refresh) <= EXACT_LOOKUP_LIMIT:
            live.update(backend.lookup(refresh))
    else:
        # Pending additions have not received a successful API result. Retry
        # them even without an audit; identical successful paths are harmless.
        confirmed = (preview_state.get('owned', [])
                     if preview_state.get('generation') == generation else [])
        for item in confirmed:
            route = Route(**item)
            if route.key not in live:
                live[route.key] = frozenset({(route.via, route.interface)})
    with lock:
        state, owned_map, pending_map = _split_state(path, generation)
        candidates = list(owned_map.values()) + list(pending_map.values())
        _protect_concurrent(desired, candidates, prepared['state'], generation)
        if len(desired) > config['max_routes']:
            raise ValueError('max_routes exceeded')
        remove, add, owned, conflicts = plan(desired, candidates, live)
        planned_keys = {r.key for r in candidates}
        summary = {'add': len(add), 'delete': len(remove), 'conflicts': len(conflicts),
                   'excluded': excluded, 'desired': len(desired)}
        if dry_run:
            for route in conflicts:
                LOG.warning('dry-run: existing exact route retained: table %s %s', route.table, route.prefix)
            for route in remove:
                LOG.info('dry-run: %s', route.command('del'))
            for route in add:
                LOG.info('dry-run: %s', route.command('add'))
            return summary
        if remove or add:
            ck_owned = {r.key: r for r in owned}
            ck_pending = {r.key: r for r in add}
            for key, route in owned_map.items():
                if key not in ck_owned and key not in ck_pending:
                    ck_owned[key] = route
            for key, route in pending_map.items():
                if key not in ck_owned and key not in ck_pending:
                    ck_pending[key] = route
            atomic_json(path, {'version': 1, 'generation': generation,
                               'owned': [asdict(r) for r in sorted(ck_owned.values())],
                               'pending_add': [asdict(r) for r in sorted(ck_pending.values())]})

    lease_sets = any(m.get('tproxy_set') for m in config['mappings'] if m.get('enabled', True))
    if lease_sets:
        # Keep interception for old claims until their FIB paths are removed.
        # Failure here must prevent any new route from directing traffic to Linux.
        backend.sync_tproxy(candidates + list(desired.values()))

    def run_apply(to_add, to_remove):
        if not to_add and not to_remove:
            return
        backend.apply([r.command('del') for r in to_remove] + [r.command('add') for r in to_add])
        changed = to_add + to_remove
        if verify_apply:
            fresh = backend.lookup(changed)
            for route in changed:
                if route.key in fresh:
                    live[route.key] = fresh[route.key]
                else:
                    live.pop(route.key, None)
        else:
            # API success is authoritative for the managed paths. DNS Gate
            # must not turn a large change batch into a full FIB dump.
            for route in to_remove:
                live.pop(route.key, None)
            for route in to_add:
                live[route.key] = frozenset({(route.via, route.interface)})
        if backend.generation() != generation:
            raise RuntimeError('VPP restarted during reconciliation; retrying')
        if verify_apply and (any(not matches(r, live) for r in to_add) or any(
                matches(r, live) for r in to_remove if r not in to_add)):
            raise RuntimeError('VPP batch verification failed; persisted intent will be retried')

    remove_keys = {r.key for r in remove}
    run_apply([r for r in add if r.key not in remove_keys], [])
    holder = (prefix_locks.hold(remove_keys)
              if prefix_locks is not None and remove else nullcontext())
    with holder:
        if remove and prefix_locks is not None and not prepared.get('withdraw'):
            extra = refresh_prefixes() if refresh_prefixes else extra_prefixes
            prefix_sets = ({_mapping_key(mapping): backend.prefixes(mapping) for mapping in mappings}
                           if prepared.get('read_nft', True) else {})
            for key, prefixes in (extra or {}).items():
                prefix_sets.setdefault(key, set()).update(prefixes)
            desired_now, _ = _collect_desired(mappings, prefix_sets, protected, exclusions, config.get('overlap_policy', 'error'))
            remove = [route for route in remove if desired_now.get(route.key) != route]
            summary['delete'] = len(remove)
        run_apply([r for r in add if r.key in remove_keys], remove)
        if on_withdraw and remove:
            on_withdraw([route.key for route in remove])
    with lock:
        state, latest_owned, latest_pending = _split_state(path, generation)
        removed = {r.key for r in remove}
        keep = {r.key: r for r in owned + add if matches(r, live)}
        for key, route in latest_owned.items():
            if key in keep or key in removed or key in planned_keys:
                continue
            keep[key] = route
        pending = {key: route for key, route in latest_pending.items() if key not in keep}
        final = {'version': 1, 'generation': generation,
                 'pending_add': [asdict(r) for r in sorted(pending.values())],
                 'owned': [asdict(r) for r in sorted(keep.values())]}
        if audit:
            final['audited_at'] = int(time.time())
        elif 'audited_at' in state:
            final['audited_at'] = state['audited_at']
        if final != state:
            atomic_json(path, final)
        if lease_sets:
            # Only release interception after route withdrawal and verification.
            backend.sync_tproxy([Route(**r) for r in final['owned'] + final['pending_add']])
    return summary


def sync(config, backend, dry_run=False, withdraw=False, extra_prefixes=None):
    return commit_sync(config, backend, prepare_sync(config, backend, withdraw),
                       dry_run, extra_prefixes)
