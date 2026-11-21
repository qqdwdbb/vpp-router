#!/usr/bin/env python3
"""DNS forwarding barrier: verify selected VPP routes before releasing answers."""
import argparse
from contextlib import ExitStack
import fcntl
from functools import lru_cache
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import ipaddress
import json
import logging
from pathlib import Path
import re
import signal
import socket
import socketserver
import struct
import sys
import threading
import time

LOG = logging.getLogger('vpp-dns-route-gate')
SEEN_PERSIST = 60
MIGRATED_DOMAIN = '@legacy'


def load_sync(path):
    spec = importlib.util.spec_from_loader('route_sync', SourceFileLoader('route_sync', str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def name_at(packet, offset):
    labels, seen, end = [], set(), None
    while True:
        if offset in seen or offset >= len(packet):
            raise ValueError('invalid DNS name')
        seen.add(offset)
        size = packet[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError('short DNS pointer')
            end = end if end is not None else offset + 2
            offset = ((size & 63) << 8) | packet[offset + 1]
            continue
        if size & 0xc0 or offset + 1 + size > len(packet):
            raise ValueError('invalid DNS label')
        offset += 1
        if not size:
            return '.'.join(labels).lower(), end if end is not None else offset
        labels.append(packet[offset:offset + size].decode('ascii'))
        if sum(map(len, labels)) + len(labels) > 254:
            raise ValueError('DNS name too long')
        offset += size


def decode(packet):
    if len(packet) < 12:
        raise ValueError('short DNS header')
    ident, flags, qd, an, ns, ar = struct.unpack_from('!6H', packet)
    if qd != 1 or flags & 0x7800:
        raise ValueError('only single-question DNS QUERY is supported')
    name, offset = name_at(packet, 12)
    qtype, qclass = struct.unpack_from('!HH', packet, offset)
    offset += 4
    question = (name, qtype, qclass)
    records = []
    for index in range(an + ns + ar):
        owner, offset = name_at(packet, offset)
        kind, cls, ttl, length = struct.unpack_from('!HHIH', packet, offset)
        offset += 10
        end = offset + length
        if end > len(packet):
            raise ValueError('short DNS record')
        if index < an and cls == 1:
            if kind in (1, 28):
                if length != (4 if kind == 1 else 16):
                    raise ValueError('bad address record')
                records.append((owner, str(ipaddress.ip_address(packet[offset:end])), ttl))
            elif kind == 5:
                target, used = name_at(packet, offset)
                if used != end:
                    raise ValueError('bad CNAME record')
                records.append((owner, target, ttl))
            elif kind in (64, 65):
                # Route HTTPS/SVCB address hints before a browser can use them.
                if length < 3:
                    raise ValueError('short HTTPS/SVCB record')
                target, pos = name_at(packet, offset + 2)
                if target:
                    records.append((owner, target, ttl))
                while pos < end:
                    key, size = struct.unpack_from('!HH', packet, pos)
                    pos += 4
                    if pos + size > end:
                        raise ValueError('short SVCB parameter')
                    if key in (4, 6):
                        width = 4 if key == 4 else 16
                        if not size or size % width:
                            raise ValueError('invalid SVCB address hints')
                        for start in range(pos, pos + size, width):
                            records.append((owner, str(ipaddress.ip_address(packet[start:start + width])), ttl))
                    pos += size
        offset = end
    return ident, flags, question, records


def _alpn_without_h3(value):
    kept = bytearray()
    pos = 0
    while pos < len(value):
        size = value[pos]
        pos += 1
        if pos + size > len(value):
            raise ValueError('short ALPN id')
        ident = value[pos:pos + size]
        pos += size
        if ident == b'h3' or ident.startswith(b'h3-'):
            continue
        kept.append(size)
        kept.extend(ident)
    return bytes(kept) if kept else b'\x02h2'


def _svcb_rdata_without_h3(packet, start, end):
    if end - start < 3:
        return packet[start:end]
    _, pos = name_at(packet, start + 2)
    if pos > end:
        raise ValueError('short HTTPS/SVCB record')
    out = bytearray(packet[start:pos])
    changed = False
    while pos < end:
        key, size = struct.unpack_from('!HH', packet, pos)
        pos += 4
        if pos + size > end:
            raise ValueError('short SVCB parameter')
        value = packet[pos:pos + size]
        pos += size
        if key == 1:
            filtered = _alpn_without_h3(value)
            if filtered != value:
                changed = True
            value = filtered
        out += struct.pack('!HH', key, len(value)) + value
    return bytes(out) if changed else packet[start:end]


def strip_https_h3(packet, address_ttl=None):
    """Remove HTTP/3 from HTTPS/SVCB ALPN so browsers use TCP through TPROXY."""
    try:
        if len(packet) < 12:
            return packet
        _, _, qd, an, ns, ar = struct.unpack_from('!6H', packet)
        offset = 12
        for _ in range(qd):
            _, offset = name_at(packet, offset)
            offset += 4
        pieces = [packet[:offset]]
        changed = False
        for index in range(an + ns + ar):
            start = offset
            _, offset = name_at(packet, offset)
            kind, cls, ttl, length = struct.unpack_from('!HHIH', packet, offset)
            offset += 10
            end = offset + length
            if end > len(packet):
                raise ValueError('short DNS record')
            if kind in (64, 65) and cls == 1:
                rewritten = _svcb_rdata_without_h3(packet, offset, end)
                if rewritten != packet[offset:end]:
                    changed = True
                    name_end = offset - 10
                    pieces.append(packet[start:name_end])
                    pieces.append(struct.pack('!HHIH', kind, cls, min(ttl, 60), len(rewritten)))
                    pieces.append(rewritten)
                else:
                    pieces.append(packet[start:end])
            elif index < an and cls == 1 and kind in (1, 5, 28) and address_ttl is not None:
                changed = True
                pieces.append(packet[start:offset - 10])
                pieces.append(struct.pack('!HHIH', kind, cls, address_ttl, length))
                pieces.append(packet[offset:end])
            else:
                pieces.append(packet[start:end])
            offset = end
        return b''.join(pieces) + packet[offset:] if changed else packet
    except (ValueError, UnicodeError, struct.error):
        return packet


def servfail(query):
    try:
        _, _, _, _ = decode(query)
        _, end = name_at(query, 12)
        flags = struct.unpack_from('!H', query, 2)[0]
        return query[:2] + struct.pack('!5H', 0x8082 | (flags & 0x0110), 1, 0, 0, 0) + query[12:end + 4]
    except (ValueError, UnicodeError, struct.error):
        return query[:2].ljust(2, b'\0') + struct.pack('!5H', 0x8082, 0, 0, 0, 0)


def rules_from_files(paths, mappings):
    enabled = {m['set']: m for m in mappings if m.get('enabled', True)}
    rules = []
    for path in paths:
        for raw in Path(path).read_text().splitlines():
            line = raw.strip()
            if not line.startswith(('nftset=', 'route=')):
                continue
            direct = line.startswith('route=')
            parts = line[6 if direct else 7:].split('/')
            if len(parts) < 3 or parts[0]:
                raise ValueError('unsupported DNS route rule in ' + str(path))
            targets = []
            for value in parts[-1].split(','):
                fields = value.split('#')
                version = int(fields.pop(0)) if fields[0] in ('4', '6') else None
                if direct:
                    if len(fields) != 1 or fields[0] not in enabled:
                        raise ValueError('unknown DNS route target: ' + value)
                    mapping = enabled[fields[0]]
                else:
                    mapping = enabled.get(fields[-1]) if len(fields) == 3 else None
                    if mapping and (mapping['family'], mapping['table']) != tuple(fields[:2]):
                        mapping = None
                if mapping:
                    targets.append((version, mapping))
            if targets:
                for domain in parts[1:-1]:
                    domain = domain.lower().rstrip('.')
                    if not domain or '*' in domain or not all(c.isalnum() or c in '.-' for c in domain):
                        raise ValueError('unsupported mapped nftset domain: ' + domain)
                    rules.append((domain, targets))
    return rules


def domain_list_files(item, config_path):
    files = item.get('domain_files', [])
    if not isinstance(files, list) or any(not isinstance(name, str) or not name for name in files):
        raise ValueError('domain_files must be a list of file paths')
    base = Path(config_path).parent
    return [Path(name) if Path(name).is_absolute() else base / name for name in files]


def ip_range_list_files(item, config_path):
    files = item.get('ip_range_files', [])
    if not isinstance(files, list) or any(not isinstance(name, str) or not name for name in files):
        raise ValueError('ip_range_files must be a list of file paths')
    base = Path(config_path).parent
    return [Path(name) if Path(name).is_absolute() else base / name for name in files]


def domain_route_files(item, config_path):
    return domain_list_files(item, config_path) + ip_range_list_files(item, config_path)


def dns_upstream(value):
    if value is None:
        return None
    if (not isinstance(value, list) or len(value) != 2
            or not isinstance(value[0], str) or type(value[1]) is not int
            or not 1 <= value[1] <= 65535):
        raise ValueError('dns_upstream must be [IP address, port]')
    try:
        ipaddress.ip_address(value[0])
    except ValueError as error:
        raise ValueError('dns_upstream host must be an IP address') from error
    return (value[0], value[1])


def rule_parts(rule):
    if len(rule) == 2:
        return rule[0], rule[1], None, 'suffix'
    if len(rule) == 4:
        return rule[0], rule[1], rule[2], rule[3]
    raise ValueError('invalid domain route rule')


def rule_matches(name, pattern, match_type):
    name = name.lower().rstrip('.')
    if match_type == 'contains':
        return pattern in name
    return name == pattern or name.endswith('.' + pattern)


@lru_cache(maxsize=16)
def domain_route_paths(path, identity):
    document = json.loads(Path(path).read_text())
    if not isinstance(document, dict) or not isinstance(document.get('routes'), list):
        raise ValueError('domain routes must contain a routes array')
    paths = [Path(path)]
    for item in document['routes']:
        if not isinstance(item, dict):
            raise ValueError('invalid domain route')
        paths.extend(domain_route_files(item, path))
    return paths


def domain_source_hash(paths):
    digest = hashlib.sha256()
    for path in paths:
        name = str(path).encode()
        content = path.read_bytes()
        digest.update(len(name).to_bytes(4, 'big') + name)
        digest.update(len(content).to_bytes(8, 'big') + content)
    return digest.hexdigest()


def domain_outlet_hashes(path):
    document = json.loads(Path(path).read_text())
    hashes = {}
    for item in document['routes']:
        digest = hashlib.sha256(json.dumps(item, sort_keys=True).encode())
        for filename in domain_route_files(item, path):
            name = str(filename).encode()
            content = filename.read_bytes()
            digest.update(len(name).to_bytes(4, 'big') + name)
            digest.update(len(content).to_bytes(8, 'big') + content)
        hashes[item['name']] = digest.hexdigest()
    return hashes


def domain_routes_from_file(path, config, module):
    """Load domain lists and their VPP exits without consulting nftables."""
    document = json.loads(Path(path).read_text())
    if not isinstance(document, dict) or not isinstance(document.get('routes'), list):
        raise ValueError('domain routes must contain a routes array')
    mappings, rules, names = [], [], set()
    pools = {}
    ip_range_prefixes = {}
    for item in document['routes']:
        if not isinstance(item, dict):
            raise ValueError('invalid domain route')
        name = item.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name) or name in names:
            raise ValueError('invalid or duplicate domain route name')
        names.add(name)
        interface = item.get('interface')
        if not isinstance(interface, str) or not module.NAME.fullmatch(interface):
            raise ValueError('invalid domain route interface')
        via = str(module.address(item['via']))
        fib_table = item.get('fib_table', 0)
        if type(fib_table) is not int or not 0 <= fib_table < 2**32:
            raise ValueError('invalid domain route fib_table')
        domains = item.get('domains', [])
        if not isinstance(domains, list):
            raise ValueError('domains must be a list')
        domains = list(domains)
        keywords = item.get('domain_keywords', [])
        if not isinstance(keywords, list):
            raise ValueError('domain_keywords must be a list')
        keywords = list(keywords)
        upstream = dns_upstream(item.get('dns_upstream'))
        for filename in domain_list_files(item, path):
            for line in filename.read_text().splitlines():
                domain = line.partition('#')[0].strip()
                if domain:
                    domains.append(domain)
        family = ipaddress.ip_address(via).version
        ip_prefixes = []
        for filename in ip_range_list_files(item, path):
            for line_number, raw in enumerate(filename.read_text().splitlines(), 1):
                value = raw.partition('#')[0].strip()
                if not value:
                    continue
                try:
                    if '-' in value:
                        first, last = (ipaddress.ip_address(part.strip())
                                       for part in value.split('-', 1))
                        if first.version != family or last.version != family or first > last:
                            raise ValueError('address family or range order mismatch')
                        networks = ipaddress.summarize_address_range(first, last)
                    else:
                        networks = [ipaddress.ip_network(value, strict=True)]
                    for network in networks:
                        if network.version != family or network.prefixlen == 0:
                            raise ValueError('address family mismatch or default route')
                        ip_prefixes.append(str(network))
                except ValueError as error:
                    raise ValueError(f'invalid IP range in {filename}:{line_number}: {value}') from error
        if not domains and not keywords and not ip_prefixes:
            raise ValueError('domain route needs domains, domain_keywords, or a nonempty source file')
        mapping = {'family': 'inet', 'table': 'dns_gate', 'set': name,
                   'interface': interface, 'via': via, 'fib_table': fib_table}
        mapping_key = tuple(mapping[k] for k in ('family', 'table', 'set'))
        if ip_prefixes:
            ip_range_prefixes.setdefault(mapping_key, set()).update(ip_prefixes)
        if 'fakeip_range' in item:
            network = ipaddress.ip_network(item['fakeip_range'], strict=True)
            if (network.version != ipaddress.ip_address(via).version or network.prefixlen == 0
                    or network.num_addresses == 1 or upstream is None
                    or config.get('dns_upstream_policy') != 'first'
                    or config.get('overlap_policy') != 'first'):
                raise ValueError('fakeip_range requires ordered DNS policy, an upstream and a matching pool family')
            route = module.Route(fib_table, str(network), via, interface)
            for other, entry in pools.items():
                if network.version == other.version and network.overlaps(other):
                    if network != other or (route, upstream) != (entry['route'], entry['upstream']):
                        raise ValueError('overlapping Fake-IP pools have different policies')
            mapping['fakeip_range'] = str(network)
            pools.setdefault(network, {'route': route, 'upstream': upstream,
                                      'mapping': tuple(mapping[k] for k in ('family', 'table', 'set'))})
        if 'tproxy_set' in item:
            value = item['tproxy_set']
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value):
                raise ValueError('invalid domain route tproxy_set')
            if config.get('overlap_policy') != 'first':
                raise ValueError('domain route tproxy_set requires ordered reconciliation')
            mapping['tproxy_set'] = value
        mappings.append(mapping)
        for raw in domains:
            if not isinstance(raw, str):
                raise ValueError('invalid domain')
            domain = raw.lower().rstrip('.')
            labels = domain.split('.')
            if (len(domain) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',
                                                       label) for label in labels)):
                raise ValueError('invalid domain: ' + raw)
            rules.append((domain, [(ipaddress.ip_address(via).version, mapping)], upstream, 'suffix'))
        for raw in keywords:
            if not isinstance(raw, str):
                raise ValueError('invalid domain keyword')
            keyword = raw.lower().strip()
            if not keyword or any(c.isspace() for c in keyword):
                raise ValueError('invalid domain keyword: ' + raw)
            rules.append((keyword, [(ipaddress.ip_address(via).version, mapping)], upstream, 'contains'))
    if not rules:
        raise ValueError('domain routes contain no domains')
    config['mappings'] = mappings
    config['_fakeip_pools'] = pools
    config['_ip_range_prefixes'] = ip_range_prefixes
    ttl = document.get('fakeip_ttl', 604800)
    if type(ttl) is not int or not 1 <= ttl <= 2147483647:
        raise ValueError('fakeip_ttl must be an integer between 1 and 2147483647')
    config['fakeip_ttl'] = ttl
    return rules


def _nft_body(source, opening):
    depth = 1
    for index in range(opening + 1, len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise ValueError('unclosed nftables element block')


def static_prefixes_from_nft(path, mappings):
    """Read only persistent nftables.conf members for configured DNS exits."""
    source = re.sub(r'(?m)#.*$', '', Path(path).read_text())
    by_name = {mapping['set']: mapping for mapping in mappings}
    groups = {name: [] for name in by_name}
    table = re.search(r'\btable\s+inet\s+mangle\s*\{', source)
    if not table:
        raise ValueError('missing inet mangle table in static nftables file')
    table_body = _nft_body(source, table.end() - 1)
    for match in re.finditer(r'\bset\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{', table_body):
        name = match.group(1)
        if name in groups:
            body = _nft_body(table_body, match.end() - 1)
            elements = re.search(r'\belements\s*=\s*\{', body)
            if elements:
                groups[name].append(_nft_body(body, elements.end() - 1))
    for match in re.finditer(r'\badd\s+element\s+inet\s+mangle\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{', source):
        name = match.group(1)
        if name in groups:
            groups[name].append(_nft_body(source, match.end() - 1))
    result = {}
    for name, bodies in groups.items():
        mapping = by_name[name]
        version = ipaddress.ip_address(mapping['via']).version
        key = tuple(mapping[field] for field in ('family', 'table', 'set'))
        for body in bodies:
            for raw in body.split(','):
                value = raw.strip()
                if not value:
                    continue
                if '-' in value:
                    first, last = (ipaddress.ip_address(part.strip()) for part in value.split('-', 1))
                    if first.version != version or last.version != version or first > last:
                        raise ValueError(f'invalid static range for {name}: {value}')
                    networks = ipaddress.summarize_address_range(first, last)
                else:
                    networks = [ipaddress.ip_network(value, strict=True)]
                for network in networks:
                    if network.version != version or network.prefixlen == 0:
                        raise ValueError(f'invalid static prefix for {name}: {value}')
                    result.setdefault(key, set()).add(str(network))
    return result


def decode_seen(document):
    now = int(time.time())
    result = {}
    for item in document:
        key = (tuple(item['mapping']), item['prefix'])
        if 'domain' in item:
            key += (item['domain'],)
        if 'source_hash' in item:
            key += (item['source_hash'],)
        value = item.get('seen', item.get('expires'))
        if value is None:
            continue
        result[key] = now if int(value) > now else int(value)
    return result


def encode_seen(seen):
    return [dict(mapping=list(key[0]), prefix=key[1], seen=int(ts),
                 **({'domain': key[2]} if len(key) >= 3 else {}),
                 **({'source_hash': key[3]} if len(key) == 4 else {}))
            for key, ts in sorted(seen.items())]


class Controller:
    def __init__(self, module, config_path, rule_paths, lease_path, backend_factory=None,
                 domain_routes_path=None, static_nftables_path=None, reload_rules=True):
        self.module, self.config_path = module, config_path
        self.rule_paths, self.lease_path = rule_paths, Path(lease_path)
        self.domain_routes_path = Path(domain_routes_path) if domain_routes_path else None
        self.static_nftables_path = Path(static_nftables_path) if static_nftables_path else None
        self.reload_rules = reload_rules
        self.backend_factory = backend_factory or module.Backend
        self.mutex = threading.Lock()
        self.cache_lock = threading.Lock()
        self.flight_lock = threading.Lock()
        self.ordered_lock = threading.RLock()
        self.prefix_locks = module.PrefixLocks()
        self.in_flight = {}
        self.verified = {}
        self.verified_generation = None
        self._lock_epoch = None
        self._config = self._rules = None
        self._rule_index = None
        self._config_mtime = self._rules_mtime = self._mapping_sig = None
        self._rules_error = self._failed_stamp = None
        self._active_claims = None
        self._background_signature = None
        self._install_failure_revision = 0
        self.seen = decode_seen(json.loads(self.lease_path.read_text())) if self.lease_path.exists() else {}
        self._load()

    def _stamp(self):
        if not self.reload_rules and self._config is not None:
            return self._config_mtime, self._rules_mtime, ()
        config_mtime = Path(self.config_path).stat().st_mtime_ns
        if self.domain_routes_path:
            stat = self.domain_routes_path.stat()
            identity = stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino
            rule_paths = domain_route_paths(self.domain_routes_path, identity)
        else:
            rule_paths = list(self.rule_paths())
        if not rule_paths:
            raise ValueError('DNS route rules directory has no .conf files')
        rules_mtime = []
        for path in rule_paths:
            stat = path.stat()
            rules_mtime.append((str(path), stat.st_mtime_ns, stat.st_ctime_ns,
                                stat.st_size, stat.st_ino))
        rules_mtime = tuple(rules_mtime)
        if self.static_nftables_path:
            stat = self.static_nftables_path.stat()
            rules_mtime += ((str(self.static_nftables_path), stat.st_mtime_ns, stat.st_ctime_ns,
                             stat.st_size, stat.st_ino),)
        return config_mtime, rules_mtime, rule_paths

    def _load(self):
        config_mtime, rules_mtime, rule_paths = self._stamp()
        stamp = (config_mtime, rules_mtime)
        with self.cache_lock:
            if self._rules_error is not None and self._failed_stamp == stamp:
                raise self._rules_error
            if (self._rules_error is None and self._config is not None
                    and self._config_mtime == config_mtime and self._rules_mtime == rules_mtime):
                return self._config, self._rules
        try:
            config = self.module.load_config(self.config_path)
            rules = (domain_routes_from_file(rule_paths[0], config, self.module)
                     if self.domain_routes_path else rules_from_files(rule_paths, config['mappings']))
            if not rules:
                raise ValueError('DNS route rules contain no enabled domain mappings')
            config['_static_prefixes'] = (static_prefixes_from_nft(self.static_nftables_path, config['mappings'])
                                          if self.static_nftables_path else {})
            for key, prefixes in config.get('_ip_range_prefixes', {}).items():
                config['_static_prefixes'].setdefault(key, set()).update(prefixes)
            for network, entry in config.get('_fakeip_pools', {}).items():
                if self.module.prefix_excluded(config, network):
                    raise ValueError('Fake-IP pool overlaps an excluded prefix')
                for mapping in config['mappings']:
                    key = tuple(mapping[k] for k in ('family', 'table', 'set'))
                    for prefix in config['_static_prefixes'].get(key, ()):
                        other = ipaddress.ip_network(prefix)
                        if (network.version == other.version and network.overlaps(other)
                                and (mapping['fib_table'], mapping['via'], mapping['interface']) !=
                                (entry['route'].table, entry['route'].via, entry['route'].interface)):
                            raise ValueError('Fake-IP pool overlaps a different static exit')
                config['_static_prefixes'].setdefault(entry['mapping'], set()).add(str(network))
            self.module.static_prefix_index(config)
            self.module.exclusion_index(config)
        except Exception as error:
            with self.cache_lock:
                self._rules_error, self._failed_stamp = error, stamp
            raise
        signature = (
            tuple((m.get('enabled', True), m.get('family'), m.get('table'), m.get('set'),
                   m.get('interface'), m.get('via'), m.get('fib_table', 0), m.get('fakeip_range'))
                  for m in config['mappings']),
            tuple(sorted(config['exclude_prefixes'])),
            config.get('overlap_policy', 'error'),
            tuple(sorted((key, tuple(sorted(prefixes)))
                         for key, prefixes in config['_static_prefixes'].items())),
        )
        with self.cache_lock:
            if self.domain_routes_path:
                valid = {(tuple(mapping[k] for k in ('family', 'table', 'set')), pattern)
                         for rule in rules
                         for pattern, targets, _, _ in [rule_parts(rule)]
                         for _, mapping in targets}
                source_hash = domain_source_hash(rule_paths)
                outlet_hashes = domain_outlet_hashes(self.domain_routes_path)
                mapping_keys = {mapping['set']: tuple(mapping[k] for k in ('family', 'table', 'set'))
                                for mapping in config['mappings']}
                current = {}
                for key, ts in self.seen.items():
                    if len(key) == 3 and (key[0], key[2]) in valid:
                        current[key] = ts
                    elif (len(key) == 4 and key[2] == MIGRATED_DOMAIN
                          and key[0][-1] in mapping_keys
                          and key[3] in (source_hash, outlet_hashes[key[0][-1]])):
                        migrated = (mapping_keys[key[0][-1]], key[1], MIGRATED_DOMAIN,
                                    outlet_hashes[key[0][-1]])
                        current[migrated] = ts
                    elif len(key) == 2 and key[0][-1] in mapping_keys:
                        migrated = (mapping_keys[key[0][-1]], key[1], MIGRATED_DOMAIN,
                                    outlet_hashes[key[0][-1]])
                        current[migrated] = ts
                # Pool routes replace all old per-address Fake-IP leases.
                pools = config.get('_fakeip_pools', {})
                current = {key: ts for key, ts in current.items()
                           if not any(ipaddress.ip_network(key[1]).version == pool.version
                                      and ipaddress.ip_network(key[1]).subnet_of(pool) for pool in pools)}
                if current != self.seen:
                    self.module.atomic_json(self.lease_path, encode_seen(current))
                    self.seen = current
                self._active_claims = valid
            if self._mapping_sig is not None and signature != self._mapping_sig:
                self.verified.clear()
            self._mapping_sig = signature
            self._config, self._config_mtime = config, config_mtime
            self._rules, self._rules_mtime = rules, rules_mtime
            self._rule_index = self._index_rules(rules)
            self._rules_error = self._failed_stamp = None
            return config, rules

    def _lock_stamp(self, config):
        stamps = []
        for name in sorted(set(config.get('lock_files', []))):
            path = Path(name)
            stamps.append((name, path.stat().st_mtime if path.exists() else 0))
        return tuple(stamps)

    def _remember_seen(self, config, extra):
        now = int(time.time())
        idle = int(config.get('idle_seconds', 7 * 24 * 3600))
        persist_after = SEEN_PERSIST if idle <= 0 else min(SEEN_PERSIST, idle)
        observed = {((tuple(item[0]), item[1], item[2]) if len(item) == 3
                    else (tuple(item[0]), item[1])) for item in extra}
        with self.cache_lock:
            if self._active_claims is not None and any(
                    len(key) != 3 or (key[0], key[2]) not in self._active_claims
                    for key in observed):
                raise RuntimeError('DNS domain rules changed during route installation')
            store = self.module.STATE_STORE
            if extra and store is not None and store.handles(self.lease_path):
                keys = {(tuple(item[0]), *item[1:]) for item in extra}
                if len(self.seen) + sum(key not in self.seen for key in keys) <= config['max_routes']:
                    for key in keys:
                        self.seen[key] = now
                    store.defer(self.lease_path, self._seen_snapshot)
                    return None
            current = dict(self.seen)
            if idle > 0:
                current = {key: ts for key, ts in current.items()
                           if key in observed or now - ts <= idle}
            changed = current != self.seen
            for item in extra:
                key = (tuple(item[0]), *item[1:])
                stored = current.get(key)
                current[key] = now
                if stored is None or now - stored >= persist_after:
                    changed = True
            if len(current) > config['max_routes']:
                overflow = sorted((ts, key) for key, ts in current.items() if key not in observed)
                drop = len(current) - config['max_routes']
                for _, key in overflow[:drop]:
                    del current[key]
                    changed = True
                if len(current) > config['max_routes']:
                    raise ValueError('desired route limit exceeded')
            if changed:
                if store is not None and store.handles(self.lease_path):
                    store.defer(self.lease_path, self._seen_snapshot)
                else:
                    self.module.atomic_json(self.lease_path, encode_seen(current))
            self.seen = current
            return dict(current)

    def _seen_snapshot(self):
        with self.cache_lock:
            current = dict(self.seen)
        return encode_seen(current)

    def _extra_prefixes(self, config):
        extra = {key: set(prefixes) for key, prefixes in config['_static_prefixes'].items()}
        for key in self._remember_seen(config, []):
            extra.setdefault(key[0], set()).add(key[1])
        return extra

    def _interface_locks(self, config):
        """Shared flock: DNS install and background apply overlap; importer still exclusive."""
        return self.module.shared_lock_files(config['lock_files'])

    def _epoch_is_valid(self, generation, stamp):
        return (self.verified_generation in (None, generation)
                and self._lock_epoch in (None, stamp))

    def _mark(self, routes, generation):
        with self.cache_lock:
            if self.verified_generation not in (None, generation):
                self.verified.clear()
            self.verified_generation = generation
            for route in routes:
                self.verified[route.key] = route

    def _drop_stale(self, generation, owned):
        keep = {route.key: route for route in owned}
        with self.cache_lock:
            if self.verified_generation not in (None, generation):
                self.verified.clear()
            else:
                self.verified = {key: route for key, route in self.verified.items()
                                 if keep.get(key) == route}
                self.verified.update(keep)
            self.verified_generation = generation

    def _excluded(self, config, routes):
        return [route for route in routes
                if self.module.prefix_excluded(config, ipaddress.ip_network(route.prefix))]

    def _forget(self, routes):
        with self.cache_lock:
            for route in routes:
                if self.verified.get(route.key) == route:
                    del self.verified[route.key]

    def _ensure(self, config, backend, routes):
        desired = {}
        for route in routes:
            if route.key in desired and desired[route.key] != route:
                raise ValueError(f'conflicting mappings for {route.prefix}; refusing partial reconciliation')
            desired[route.key] = route
        remaining = sorted(desired.values())
        for _ in range(3):
            if not remaining:
                return
            lead, wait_for = [], []
            with self.flight_lock:
                for route in remaining:
                    event = self.in_flight.get(route.key)
                    if event is None:
                        event = threading.Event()
                        self.in_flight[route.key] = event
                        lead.append(route)
                    wait_for.append(event)
            error = None
            if lead:
                try:
                    with self._interface_locks(config):
                        self.module.ensure_routes(config, backend, lead, mutex=self.mutex)
                    self._mark(lead, backend.generation())
                except Exception as exc:
                    error = exc
                finally:
                    with self.flight_lock:
                        for route in lead:
                            self.in_flight.pop(route.key).set()
            for event in wait_for:
                event.wait()
            if error:
                raise error
            with self.cache_lock:
                remaining = [route for route in remaining
                             if self.verified.get(route.key) != route]
            if not remaining:
                return
        raise RuntimeError('DNS route barrier rejected an excluded or conflicting route')

    @staticmethod
    def _index_rules(rules):
        suffixes, keywords = {}, []
        for index, rule in enumerate(rules):
            pattern, _, _, match_type = rule_parts(rule)
            if match_type == 'contains':
                keywords.append((index, pattern))
            else:
                node = suffixes
                for label in reversed(pattern.split('.')):
                    node = node.setdefault(label, {})
                node.setdefault(None, []).append(index)
        return rules, suffixes, keywords

    def _matching_rules(self, rules, names):
        with self.cache_lock:
            index = self._rule_index
        if index is None or index[0] is not rules:
            index = self._index_rules(rules)
        _, suffixes, keywords = index
        matched = set()
        for name in names:
            name = name.lower().rstrip('.')
            node = suffixes
            for label in reversed(name.split('.')):
                node = node.get(label)
                if node is None:
                    break
                matched.update(node.get(None, ()))
            for position, pattern in keywords:
                if pattern in name:
                    matched.add(position)
        return [rules[position] for position in sorted(matched)]

    def _dns_routes(self, config, rules, records, question):
        extra, required = [], set()
        selected = self._dns_rule(config, rules, question)
        if selected is not None and any(mapping.get('fakeip_range')
                                        for _, mapping in rule_parts(selected)[1]):
            # Fake-IP DNS owns a fixed address pool. Its domain policy is
            # sufficient: no answer parsing, host routes or leases are needed.
            return extra, required
        names = {question[0]} | {owner for owner, _, _ in records}
        names.update(value for _, value, _ in records if not is_ip(value))
        targets = [(pattern, version, mapping)
                   for rule in self._matching_rules(rules, names)
                   for pattern, items, _, match_type in [rule_parts(rule)]
                   for version, mapping in items]
        for _, value, _ttl in records:
            if not is_ip(value):
                continue
            ip = ipaddress.ip_address(value)
            for domain, version, mapping in targets:
                if ((version is None or version == ip.version)
                        and ip.version == ipaddress.ip_address(mapping['via']).version):
                    route = self.module.Route(mapping['fib_table'], str(ipaddress.ip_network(value)),
                                              mapping['via'], mapping['interface'])
                    required.add(route)
                    claim = (tuple(mapping[k] for k in ('family', 'table', 'set')), route.prefix)
                    extra.append((*claim, domain) if self.domain_routes_path else claim)
        return extra, required

    def _dns_rule(self, config, rules, question):
        for rule in self._matching_rules(rules, [question[0]]):
            _, targets, upstream, _ = rule_parts(rule)
            if config.get('dns_upstream_policy') == 'first':
                version = {1: 4, 28: 6}.get(question[1])
                if version and not any(v in (None, version) for v, _ in targets):
                    continue
                return rule
            if upstream is not None:
                return rule
        return None

    def dns_upstream(self, question):
        """Select the domain policy before querying its real or Fake-IP DNS."""
        config, rules = self._load()
        rule = self._dns_rule(config, rules, question)
        return rule_parts(rule)[2] if rule is not None else None

    def answer_ttl(self, question):
        config, rules = self._load()
        rule = self._dns_rule(config, rules, question)
        if rule is not None and any(m.get('fakeip_range') for _, m in rule_parts(rule)[1]):
            return config['fakeip_ttl']
        return None

    def reconcile(self, records=None, question=None, force_audit=False):
        stamp = self._stamp()[:2]
        config, _ = self._load()
        try:
            if config.get('overlap_policy') == 'first':
                if records is not None and not force_audit:
                    prepared = self._dns_routes(config, self._rules, records, question)
                    result = self._reconcile(records, question, force_audit, prepared)
                else:
                    with self.ordered_lock:
                        result = self._reconcile(records, question, force_audit)
            else:
                result = self._reconcile(records, question, force_audit)
        except Exception:
            if records is not None:
                with self.cache_lock:
                    self._install_failure_revision += 1
            raise
        if self._stamp()[:2] != stamp:
            raise RuntimeError('DNS domain rules changed during route installation')
        return result

    def _reconcile(self, records=None, question=None, force_audit=False, prepared=None):
        config, rules = self._load()
        extra, required = [], set()
        if records is not None:
            extra, required = prepared if prepared is not None else self._dns_routes(config, rules, records, question)
            if not required:
                return
        ordered_required = set()
        if required and config.get('overlap_policy') == 'first':
            if self._excluded(config, required):
                raise RuntimeError('DNS route barrier rejected an excluded route')
            backend = self.backend_factory(config)
            if not force_audit:
                with self.prefix_locks.hold(route.key for route in required):
                    self._remember_seen(config, extra)
                    with self._interface_locks(config):
                        result = self.module.ensure_routes(config, backend, list(required), mutex=self.mutex)
                winners = result.get('winners') or ()
                self._mark(winners, backend.generation())
                return
            ordered_required = required
            self._remember_seen(config, extra)
            required = set()
        if required:
            blocked = self._excluded(config, required)
            if blocked:
                self._forget(blocked)
                raise RuntimeError('DNS route barrier rejected an excluded or conflicting route')
            with self.prefix_locks.hold(route.key for route in required):
                self._remember_seen(config, extra)
                backend = self.backend_factory(config)
                generation = backend.generation()
                stamp = self._lock_stamp(config)
                with self.cache_lock:
                    if not self._epoch_is_valid(generation, stamp):
                        self.verified.clear()
                    self.verified_generation = generation
                    self._lock_epoch = stamp
                # Re-submit on every answer. API success is the barrier;
                # local history cannot prove the path still exists in VPP.
                self._ensure(config, backend, sorted(required))
            return
        backend = self.backend_factory(config)
        generation = backend.generation()
        stamp = self._lock_stamp(config)
        with self.cache_lock:
            changed_epoch = not self._epoch_is_valid(generation, stamp)
            if changed_epoch:
                self.verified.clear()
            self.verified_generation = generation
            self._lock_epoch = stamp
        # DNS answers reinstall their paths. Background work only reconciles
        # policy/lease changes; a FIB audit must be explicitly requested.
        audit = force_audit
        extra = self._extra_prefixes(config)
        with self.cache_lock:
            failure_revision = self._install_failure_revision
        signature = (generation, stamp, self._config_mtime, self._rules_mtime, failure_revision,
                     frozenset((key, frozenset(prefixes)) for key, prefixes in extra.items()))
        previous = self._background_signature
        if (not force_audit and previous is not None and previous[:-1] == signature[:-1]
                and all(prefixes.issubset(extra.get(key, ())) for key, prefixes in previous[-1])):
            # Lease timestamps change on every reply, but the installed paths
            # need no bulk planning until claims expire or policy changes.
            # Newly observed claims already received a successful direct add;
            # failed adds change failure_revision and must be reconciled.
            # Still repair interception sets after an nftables reload.
            if any(m.get('enabled', True) and m.get('tproxy_set') for m in config['mappings']):
                with self.cache_lock:
                    owned = list(self.verified.values())
                with self._interface_locks(config):
                    backend.sync_tproxy(owned)
            if backend.generation() != generation:
                raise RuntimeError('VPP restarted at DNS route barrier')
            self._background_signature = signature
            return
        prepared = self.module.prepare_sync(config, backend, audit=audit, read_nft=False)

        def forget(keys):
            with self.cache_lock:
                for key in keys:
                    self.verified.pop(key, None)

        with self._interface_locks(config):
            self.module.commit_sync(config, backend, prepared, extra_prefixes=extra, mutex=self.mutex,
                                    prefix_locks=self.prefix_locks, refresh_prefixes=lambda: self._extra_prefixes(config),
                                    on_withdraw=forget, verify_apply=force_audit)
            if backend.generation() != generation:
                raise RuntimeError('VPP restarted at DNS route barrier')
        path = Path(config['state_file'])
        owned = []
        state = self.module.read_json(path, {})
        if state:
            if state.get('generation') == generation:
                owned = [self.module.Route(**item) for item in state.get('owned', [])]
        self._drop_stale(generation, owned)
        self._background_signature = signature
        if ordered_required:
            prefix_sets = {key: set(value) for key, value in prepared['nft'].items()}
            for key, prefixes in extra.items():
                prefix_sets.setdefault(key, set()).update(prefixes)
            desired, _ = self.module._collect_desired(prepared['mappings'], prefix_sets,
                prepared['protected'], prepared['exclusions'], 'first')
            winners = self.module.covering_routes(desired, ordered_required)
            live = backend.lookup(winners)
            if backend.generation() != generation or any(not self.module.matches(route, live) for route in winners):
                raise RuntimeError('ordered DNS route verification failed')
def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def read_exact(sock, length):
    result = bytearray()
    while len(result) < length:
        data = sock.recv(length - len(result))
        if not data:
            raise EOFError('DNS TCP connection closed')
        result.extend(data)
    return bytes(result)


class Gate:
    def __init__(self, controller, upstream, timeout=5):
        self.controller, self.upstream, self.timeout = controller, upstream, timeout
        self.slots = threading.BoundedSemaphore(32)

    def exchange(self, query, tcp=False):
        if not self.slots.acquire(blocking=False):
            return servfail(query)
        question = None
        try:
            ident, flags, question, _ = decode(query)
            if flags & 0x8000:
                raise ValueError('expected query')
            selector = getattr(self.controller, 'dns_upstream', None)
            upstream = (selector(question) if selector is not None else None) or self.upstream
            family = socket.AF_INET6 if ':' in upstream[0] else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(upstream)
                if tcp:
                    sock.sendall(struct.pack('!H', len(query)) + query)
                    answer = read_exact(sock, struct.unpack('!H', read_exact(sock, 2))[0])
                else:
                    sock.send(query)
                    answer = sock.recv(65535)
            rid, rflags, rq, records = decode(answer)
            if rid != ident or rq != question or not rflags & 0x8000:
                raise ValueError('upstream answer mismatch')
            if rflags & 0x0200:
                # Resolve full TCP answer before exposing even a truncated UDP answer.
                if tcp:
                    raise ValueError('truncated TCP DNS reply')
                with socket.socket(family, socket.SOCK_STREAM) as retry:
                    retry.settimeout(self.timeout)
                    retry.connect(upstream)
                    retry.sendall(struct.pack('!H', len(query)) + query)
                    answer = read_exact(retry, struct.unpack('!H', read_exact(retry, 2))[0])
                rid, rflags, rq, records = decode(answer)
                if rid != ident or rq != question or not rflags & 0x8000 or rflags & 0x0200:
                    raise ValueError('invalid TCP retry answer')
            ttl = None
            if not rflags & 15:
                self.controller.reconcile(records, question)
                ttl_selector = getattr(self.controller, 'answer_ttl', None)
                if ttl_selector is not None:
                    ttl = ttl_selector(question)
            return strip_https_h3(answer, address_ttl=ttl)
        except Exception as error:
            name = question[0] if question else 'undecoded'
            LOG.warning('DNS answer withheld: %s (%s)', error, name)
            return servfail(query)
        finally:
            self.slots.release()



class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        answer = self.server.gate.exchange(query)
        # A TCP retry of a truncated reply can exceed the client's UDP allowance.
        limit = 512
        try:
            _, offset = name_at(query, 12)
            offset += 4
            counts = struct.unpack_from('!6H', query)
            if counts[4] == 0 and counts[3] == 0 and counts[5] == 1:
                _, offset = name_at(query, offset)
                kind, size = struct.unpack_from('!HH', query, offset)
                if kind == 41:
                    limit = max(512, min(size, 4096))
        except (ValueError, struct.error):
            pass
        if len(answer) > limit:
            answer = servfail(query)
            flags = struct.unpack_from('!H', answer, 2)[0]
            answer = answer[:2] + struct.pack('!H', (flags & ~15) | 0x0200) + answer[4:]
        sock.sendto(answer, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            for _ in range(100):
                length = struct.unpack('!H', read_exact(self.request, 2))[0]
                answer = self.server.gate.exchange(read_exact(self.request, length), True)
                self.request.sendall(struct.pack('!H', len(answer)) + answer)
        except (OSError, EOFError):
            pass


class BoundedRequests:
    def __init__(self, *args, **kwargs):
        self.request_slots = threading.BoundedSemaphore(64)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


class UDPServer(BoundedRequests, socketserver.ThreadingUDPServer):
    daemon_threads = True
    block_on_close = False


class TCPServer(BoundedRequests, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/vpp/dns-route-gate.json')
    parser.add_argument('--export-domain-routes', type=Path,
                        help='write editable JSON domain lists converted from dnsmasq rules')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    config = json.loads(Path(args.config).read_text())
    module = load_sync(config['sync_program'])
    if args.export_domain_routes:
        route_config = module.load_config(config['route_config'])
        source_directory = config.get('legacy_rules_directory') or config.get('rules_directory')
        if not source_directory:
            raise ValueError('no source dnsmasq rules directory configured')
        rules = rules_from_files(sorted(Path(source_directory).glob('*.conf')),
                                 route_config['mappings'])
        if not rules:
            raise ValueError('no mapped domain rules to export')
        domains = {m['set']: set() for m in route_config['mappings']}
        for domain, targets in rules:
            for version, mapping in targets:
                if version is None or version == ipaddress.ip_address(mapping['via']).version:
                    domains[mapping['set']].add(domain)
        routes = []
        files = []
        exported_names = set()
        tproxy_domains = domains.get('proxylist', set()) | domains.get('proxylist6', set())
        for mapping in route_config['mappings']:
            if domains[mapping['set']]:
                name = mapping['set']
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name) or name in exported_names:
                    raise ValueError('mapping name cannot be used as a domain-list filename: ' + name)
                exported_names.add(name)
                shared = name in ('proxylist', 'proxylist6')
                filename = 'tproxy.domains' if shared else name + '.domains'
                routes.append({key: mapping[key] for key in
                               ('set', 'interface', 'via', 'fib_table', 'tproxy_set') if key in mapping}
                              | {'name': name, 'domain_files': [filename]})
                routes[-1].pop('set', None)
                target = args.export_domain_routes.parent / filename
                if not any(path == target for path, _ in files):
                    files.append((target, '\n'.join(sorted(tproxy_domains if shared else domains[name])) + '\n'))
        if not routes:
            raise ValueError('no compatible domain routes to export')
        for filename in [args.export_domain_routes] + [path for path, _ in files]:
            if filename.exists():
                raise FileExistsError(filename)
        args.export_domain_routes.parent.mkdir(parents=True, exist_ok=True)
        for filename, content in files:
            filename.write_text(content)
        args.export_domain_routes.write_text(json.dumps({'routes': routes}, indent=2) + '\n')
        return 0
    route_config = module.load_config(config['route_config'])
    with module.DeferredState([route_config['state_file'], config['lease_file']]) as state_store:
        controller = Controller(module, config['route_config'],
                                lambda: sorted(Path(config.get('rules_directory', '')).glob('*.conf')),
                                config['lease_file'], domain_routes_path=config.get('domain_routes_file'),
                                static_nftables_path=config.get('static_nftables_file'), reload_rules=False)
        gate = Gate(controller, tuple(config['upstream']))
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *unused: stop.set())
        with open('/run/lock/vpp-nft-route-sync.lock', 'w') as singleton, ExitStack() as stack:
            fcntl.flock(singleton, fcntl.LOCK_EX | fcntl.LOCK_NB)
            route_config, _ = controller._load()
            stack.enter_context(module.StateServer(route_config))
            backend = module.Backend(route_config)
            backend.apply([])  # Connect and load schemas before accepting DNS requests.
            # Validate rule syntax and mappings before taking any client queries.
            controller._load()
            controller.reconcile()
            if route_config.get('_fakeip_pools'):
                # Checkpoint the pool migration before accepting queries so
                # a crash cannot resurrect deleted per-address route claims.
                state_store.flush()
            with state_store.lock:
                state_store.ledger(route_config['state_file'], backend.generation())
            for host, port in config['listen']:
                for server_class, handler in ((UDPServer, UDPHandler), (TCPServer, TCPHandler)):
                    class BoundServer(server_class):
                        address_family = socket.AF_INET6 if ':' in host else socket.AF_INET
                        def server_bind(self):
                            if self.address_family == socket.AF_INET6:
                                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                            super().server_bind()
                    bind_address = socket.getaddrinfo(host, port, BoundServer.address_family, socket.SOCK_STREAM if handler is TCPHandler else socket.SOCK_DGRAM)[0][4]
                    server = stack.enter_context(BoundServer(bind_address, handler))
                    server.gate = gate
                    threading.Thread(target=server.serve_forever, daemon=True).start()
            LOG.info('DNS barrier listening on %s; backend %s', config['listen'], config['upstream'])
            full_sync = False
            last_loaded = controller._config_mtime, controller._rules_mtime
            next_resync = time.monotonic() + float(route_config['monitor_resync_seconds'])
            while not stop.is_set():
                try:
                    route_config, _ = controller._load()
                    loaded = controller._config_mtime, controller._rules_mtime
                    if full_sync or loaded != last_loaded or time.monotonic() >= next_resync:
                        controller.reconcile(force_audit=full_sync)
                        full_sync = False
                        last_loaded = loaded
                        next_resync = time.monotonic() + float(route_config['monitor_resync_seconds'])
                except Exception as error:
                    LOG.error('background reconciliation failed: %s', error)
                stop.wait(2)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
