import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

SPEC = importlib.util.spec_from_file_location(
    'nft_sync', Path(__file__).parents[2] / 'tools/nftset-route-sync.py')
sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sync
SPEC.loader.exec_module(sync)


def document(elements, kind='ipv4_addr'):
    return {'nftables': [{'set': {'family': 'inet', 'table': 'mangle', 'name': 'altroute',
                                'type': kind, 'elem': elements}}]}


class FakeBackend:
    def __init__(self):
        self.instance = 'a' * 32
        self.sets = {'altroute': {'198.51.100.77/32'}}
        self.live = {}
        self.batches = []
        self.fail_after = None
        self.lookups = []
        self.snapshots = 0
        self.prefix_reads = 0
        self.cli_calls = []
        self._mu = threading.Lock()

    def generation(self):
        return self.instance

    def cli(self, command):
        with self._mu:
            self.cli_calls.append(command)
        if command == 'show interface':
            return 'wg1 4 up 1280\nwg2 5 up 1280\n'
        if command == 'show wireguard peer':
            return '[28] endpoint:[192.0.2.68:31000->10.64.20.3:32000] wg1\n'
        raise AssertionError(command)

    def prefixes(self, mapping):
        with self._mu:
            self.prefix_reads += 1
            value = self.sets[mapping['set']]
        if isinstance(value, Exception):
            raise value
        return value

    def lookup_exact(self, route):
        with self._mu:
            self.lookups.append((route.key,))
            return self.live.get(route.key)

    def dump_owned(self, table, family):
        with self._mu:
            self.snapshots += 1
            return {key: paths for key, paths in self.live.items()
                    if key[0] == table and ipaddress.ip_network(key[1]).version == family}

    def snapshot(self, routes):
        with self._mu:
            self.snapshots += 1
            return self.live.copy()

    def lookup(self, routes):
        with self._mu:
            self.lookups.append(tuple(sorted(r.key for r in routes)))
            return {r.key: self.live[r.key] for r in routes if r.key in self.live}

    def apply(self, lines):
        with self._mu:
            self.batches.append(lines)
            fail_after = self.fail_after
            if fail_after is not None:
                self.fail_after = None
        for index, line in enumerate(lines):
            if fail_after == index:
                raise RuntimeError('injected batch interruption')
            words = line.split()
            route = sync.Route(int(words[5]), words[3], words[7], words[8])
            with self._mu:
                if words[2] == 'add':
                    self.live[route.key] = frozenset({(route.via, route.interface)})
                elif sync.matches(route, self.live):
                    del self.live[route.key]


class ParsingTests(unittest.TestCase):
    def test_addresses_timeouts_prefixes_ranges(self):
        data = document(['198.51.100.1',
                         {'elem': {'val': '198.51.100.2', 'expires': 1000}},
                         {'elem': {'val': '198.51.100.3', 'expires': 0}},
                         {'prefix': {'addr': '203.0.113.0', 'len': 25}},
                         {'range': ['192.0.2.0', '192.0.2.3']}])
        self.assertEqual(sync.nft_prefixes(data, 'inet', 'mangle', 'altroute'),
                         {'198.51.100.1/32', '198.51.100.2/32',
                          '203.0.113.0/25', '192.0.2.0/30'})

    def test_ipv6(self):
        self.assertEqual(sync.nft_prefixes(document(['2001:db8::77'], 'ipv6_addr'),
                                           'inet', 'mangle', 'altroute'), {'2001:db8::77/128'})

    def test_unsupported_and_missing_sets_fail(self):
        for data in [document(['1.2.3.4'], 'ipv4_addr . inet_service'),
                     document([{'unknown': 1}]), document(['0.0.0.0/0']), {},
                     document(['2001:db8::1'])]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                sync.nft_prefixes(data, 'inet', 'mangle', 'altroute')

    def test_fib_does_not_confuse_recursive_next_hop(self):
        text = '''ipv4-VRF:0, fib_index:0
198.51.100.77/32
  unicast-ip4-chain
    [0] [@6]: ipv4 [features] via 10.62.30.1 wg1: mtu:1280
        stacked-on:
          [0] [@5]: ipv4 via 10.61.20.1 host-vpp-wan: mtu:1500
198.51.100.78/32
    [0] [@0]: dpo-drop ip4
'''
        entries = sync.parse_fib(text, 0)
        self.assertEqual(entries[(0, '198.51.100.77/32')], frozenset({('10.62.30.1', 'wg1')}))
        self.assertEqual(entries[(0, '198.51.100.78/32')], frozenset())

    def test_fib_ipv6_and_multipath(self):
        text = '''ipv6-VRF:7, fib_index:1
2001:db8::77/128
    [0] [@6]: ipv6 [features] via fd42:1111:2222:90::2 wg0: mtu:1420
    [1] [@6]: ipv6 [features] via fd42:1111:2222:90::5 wg0: mtu:1420
'''
        self.assertEqual(sync.parse_fib(text, 7)[(7, '2001:db8::77/128')],
                         frozenset({('fd42:1111:2222:90::2', 'wg0'), ('fd42:1111:2222:90::5', 'wg0')}))

    def test_lookup_queries_exact_prefix_not_full_table(self):
        class Recording(sync.Backend):
            def __init__(self):
                self.config = {'vpp_socket': '/dev/null'}
                self.commands = []

            def cli(self, command):
                self.commands.append(command)
                if command.startswith('show ip6'):
                    return '''ipv6-VRF:7, fib_index:1
2001:db8::77/128
    [0] [@6]: ipv6 via fd42:1111:2222:90::2 wg0: mtu:1420
'''
                return '''ipv4-VRF:0, fib_index:0
198.51.100.77/32
    [0] [@6]: ipv4 via 10.62.30.1 wg1: mtu:1280
'''

        v4 = sync.Route(0, '198.51.100.77/32', '10.62.30.1', 'wg1')
        v6 = sync.Route(7, '2001:db8::77/128', 'fd42:1111:2222:90::2', 'wg0')
        backend = Recording()
        live = backend.lookup([v4, v6])
        self.assertEqual(backend.commands, [
            'show ip fib table 0 198.51.100.77/32',
            'show ip6 fib table 7 2001:db8::77/128',
        ])
        self.assertTrue(sync.matches(v4, live) and sync.matches(v6, live))
        backend.commands.clear()
        self.assertEqual(backend.lookup_exact(v4), frozenset({('10.62.30.1', 'wg1')}))
        self.assertEqual(backend.commands, ['show ip fib table 0 198.51.100.77/32'])
        backend.commands.clear()
        self.assertTrue(sync.matches(v4, backend.snapshot([v4])))
        self.assertEqual(backend.commands, ['show ip fib table 0'])

    def test_lookup_ignores_covering_lpm_prefix(self):
        class Covering(sync.Backend):
            def __init__(self):
                self.config = {'vpp_socket': '/dev/null'}

            def cli(self, command):
                return '''ipv4-VRF:0, fib_index:0
0.0.0.0/0
    [0] [@6]: ipv4 via 10.61.20.1 host-vpp-wan: mtu:1500
'''

        route = sync.Route(0, '198.51.100.77/32', '10.62.30.1', 'wg1')
        self.assertIsNone(Covering().lookup_exact(route))
        self.assertEqual(Covering().lookup([route]), {})
        self.assertNotIn(route.key, Covering().snapshot([route]))

    def test_lookup_exact_drop_route_is_present_conflict(self):
        class Drop(sync.Backend):
            def __init__(self):
                self.config = {'vpp_socket': '/dev/null'}

            def cli(self, command):
                return '''ipv4-VRF:0, fib_index:0
198.51.100.78/32
    [0] [@0]: dpo-drop ip4
'''

        route = sync.Route(0, '198.51.100.78/32', '10.62.30.1', 'wg1')
        self.assertEqual(Drop().lookup_exact(route), frozenset())
        self.assertFalse(sync.matches(route, Drop().lookup([route])))

    def test_dump_owned_queries_full_table(self):
        class Recording(sync.Backend):
            def __init__(self):
                self.config = {'vpp_socket': '/dev/null'}
                self.commands = []

            def cli(self, command):
                self.commands.append(command)
                if command.startswith('show ip6'):
                    return '''ipv6-VRF:7, fib_index:1
2001:db8::77/128
    [0] [@6]: ipv6 via fd42:1111:2222:90::2 wg0: mtu:1420
::/0
    [0] [@6]: ipv6 via fc00::1 wg0: mtu:1420
'''
                return '''ipv4-VRF:0, fib_index:0
198.51.100.77/32
    [0] [@6]: ipv4 via 10.62.30.1 wg1: mtu:1280
0.0.0.0/0
    [0] [@6]: ipv4 via 10.61.20.1 host-vpp-wan: mtu:1500
'''

        backend = Recording()
        v4 = backend.dump_owned(0, 4)
        self.assertEqual(backend.commands, ['show ip fib table 0'])
        self.assertEqual(v4[(0, '198.51.100.77/32')], frozenset({('10.62.30.1', 'wg1')}))
        self.assertEqual(v4[(0, '0.0.0.0/0')], frozenset({('10.61.20.1', 'host-vpp-wan')}))
        backend.commands.clear()
        v6 = backend.dump_owned(7, 6)
        self.assertEqual(backend.commands, ['show ip6 fib table 7'])
        self.assertEqual(v6[(7, '2001:db8::77/128')], frozenset({('fd42:1111:2222:90::2', 'wg0')}))

    def test_lookup_many_prefixes_dumps_each_table_once(self):
        class Recording(sync.Backend):
            def __init__(self):
                self.config = {'vpp_socket': '/dev/null'}
                self.commands = []

            def cli(self, command):
                self.commands.append(command)
                if command.startswith('show ip6'):
                    return 'ipv6-VRF:7, fib_index:1\n'
                return '''ipv4-VRF:0, fib_index:0
198.51.100.1/32
    [0] [@6]: ipv4 via 10.62.30.1 wg1: mtu:1280
'''

        routes = [sync.Route(0, f'198.51.100.{index}/32', '10.62.30.1', 'wg1')
                  for index in range(1, sync.EXACT_LOOKUP_LIMIT + 2)]
        routes.append(sync.Route(7, '2001:db8::77/128', 'fd42:1111:2222:90::2', 'wg0'))
        backend = Recording()
        live = backend.lookup(routes)
        self.assertEqual(backend.commands, ['show ip fib table 0', 'show ip6 fib table 7'])
        self.assertEqual(live[(0, '198.51.100.1/32')], frozenset({('10.62.30.1', 'wg1')}))
        self.assertNotIn((0, '198.51.100.2/32'), live)


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.json'
        self.mapping = {'family': 'inet', 'table': 'mangle', 'set': 'altroute',
                        'interface': 'wg1', 'via': '10.62.30.1', 'fib_table': 0}
        self.config = {'state_file': str(self.path), 'mappings': [self.mapping],
                       'exclude_prefixes': ['10.64.20.3/32'], 'max_routes': 100, 'fib_audit_seconds': 0}
        self.backend = FakeBackend()
        self.route = sync.Route(0, '198.51.100.77/32', '10.62.30.1', 'wg1')

    def cycle(self, **kwargs):
        return sync.sync(self.config, self.backend, **kwargs)

    def test_lease_interception_survives_nft_expiry_and_withdraws_after_fib(self):
        self.mapping['tproxy_set'] = 'lease4'
        events = []
        self.backend.sync_tproxy = lambda routes: events.append(
            ({r.prefix for r in routes}, dict(self.backend.live)))
        self.cycle()
        self.assertIn(self.route.prefix, events[0][0])
        self.assertFalse(events[0][1])  # Intercept exists before FIB installation.
        self.backend.sets['altroute'] = set()
        extra = {('inet', 'mangle', 'altroute'): {self.route.prefix}}
        self.cycle(extra_prefixes=extra)
        self.assertIn(self.route.prefix, events[-1][0])
        self.assertTrue(sync.matches(self.route, self.backend.live))
        self.cycle()
        self.assertEqual(events[-1], (set(), {}))  # Release only after FIB deletion.

    def test_interception_failure_prevents_route_install(self):
        self.mapping['tproxy_set'] = 'lease4'
        def fail(routes):
            raise RuntimeError('nft failed')
        self.backend.sync_tproxy = fail
        with self.assertRaisesRegex(RuntimeError, 'nft failed'):
            self.cycle()
        self.assertFalse(self.backend.live)
        self.assertFalse(self.backend.batches)

    def test_failed_route_withdraw_keeps_interception(self):
        self.mapping['tproxy_set'] = 'lease4'
        intercepted = []
        self.backend.sync_tproxy = lambda routes: intercepted.append({r.prefix for r in routes})
        self.cycle()
        self.backend.sets['altroute'] = set()
        self.backend.fail_after = 0
        with self.assertRaises(RuntimeError):
            self.cycle()
        self.assertIn(self.route.prefix, intercepted[-1])
        self.assertTrue(sync.matches(self.route, self.backend.live))

    def test_tproxy_script_adds_and_deletes_diff_without_flush(self):
        key = ('inet', 'mangle', 'lease4')
        have = {ipaddress.ip_network('198.51.100.1/32'), ipaddress.ip_network('198.51.100.2/32')}
        want = {ipaddress.ip_network('198.51.100.2/32'), ipaddress.ip_network('198.51.100.3/32')}
        add, delete = sync.tproxy_nft_script({key: want}, {key: have})
        self.assertEqual(add, ['add element inet mangle lease4 { 198.51.100.3/32 }'])
        self.assertEqual(delete, ['delete element inet mangle lease4 { 198.51.100.1/32 }'])
        self.assertEqual(sync.tproxy_nft_script({key: have}, {key: have}), ([], []))

    def test_tproxy_script_matches_collapsed_intervals_without_readd(self):
        key = ('inet', 'mangle', 'lease4')
        have = {ipaddress.ip_network('198.51.100.0/31')}
        want = {ipaddress.ip_network('198.51.100.0/32'), ipaddress.ip_network('198.51.100.1/32')}
        self.assertEqual(sync.tproxy_nft_script({key: want}, {key: have}), ([], []))
        want_extra = want | {ipaddress.ip_network('198.51.100.2/32')}
        add, delete = sync.tproxy_nft_script({key: want_extra}, {key: have})
        self.assertEqual(delete, [])
        self.assertEqual(add, ['add element inet mangle lease4 { 198.51.100.2/32 }'])
        add, delete = sync.tproxy_nft_script({key: {ipaddress.ip_network('198.51.100.0/32')}}, {key: have})
        self.assertEqual((add, delete), ([], []))

    def test_sync_tproxy_does_not_flush_existing_members(self):
        self.mapping['tproxy_set'] = 'lease4'
        keep = ipaddress.ip_network('198.51.100.1/32')
        backend = sync.Backend(self.config)
        backend._set_networks = lambda family, table, name: {keep}
        scripts = []

        def capture(lines, allow_missing=False):
            if lines:
                scripts.append((list(lines), allow_missing))

        backend._apply_nft = capture
        backend.sync_tproxy([self.route])
        self.assertEqual(scripts, [
            (['delete element inet mangle lease4 { 198.51.100.1/32 }'], False),
            (['add element inet mangle lease4 { 198.51.100.77/32 }'], False),
        ])
        self.assertFalse(any('flush' in line for lines, _ in scripts for line in lines))

    def test_ordered_overlap_replaces_owned_path_and_falls_back_after_expiry(self):
        low = {**self.mapping, 'set': 'proxylist', 'via': '10.61.20.2', 'interface': 'loop200'}
        self.config.update(overlap_policy='first', mappings=[self.mapping, low])
        self.backend.sets['altroute'] = set()
        self.backend.sets['proxylist'] = {self.route.prefix}
        self.cycle()
        self.backend.sets['altroute'] = {self.route.prefix}
        sync.add_routes(self.config, self.backend, [self.route])
        self.assertTrue(sync.matches(self.route, self.backend.live))
        self.assertEqual(self.backend.batches[-1][0].split()[2], 'del')
        self.backend.sets['altroute'] = set()
        self.cycle()
        self.assertEqual(self.backend.live[self.route.key], frozenset({('10.61.20.2', 'loop200')}))

    def test_ordered_ranges_preserve_first_match_in_both_families(self):
        for high, low, via in [('198.51.100.0/25', '198.51.100.77/32', '10.62.30.1'),
                               ('2001:db8::/120', '2001:db8::77/128', 'fd00::1'),
                               ('198.51.100.77/32', '198.51.100.0/24', '10.62.30.1'),
                               ('2001:db8::77/128', '2001:db8::/120', 'fd00::1'),
                               ('198.51.100.77/32', '198.51.100.77/32', '10.62.30.1'),
                               ('2001:db8::77/128', '2001:db8::77/128', 'fd00::1')]:
            mappings = [{**self.mapping, 'via': via}, {**self.mapping, 'set': 'other', 'via': via, 'interface': 'loop200'}]
            sets = {sync._mapping_key(mappings[0]): {high}, sync._mapping_key(mappings[1]): {low}}
            desired, _ = sync._collect_desired(mappings, sets, set(), [], 'first')
            probe = sync.Route(0, high, via, 'wg1')
            winners = sync.covering_routes(desired, [probe])
            self.assertTrue(all(r.interface == 'wg1' for r in winners))
            for a in desired.values():
                for b in desired.values():
                    if a != b:
                        self.assertFalse(ipaddress.ip_network(a.prefix).overlaps(ipaddress.ip_network(b.prefix)))

    def test_overlap_still_errors_without_explicit_policy(self):
        other = {**self.mapping, 'set': 'other', 'interface': 'loop200'}
        with self.assertRaises(ValueError):
            sync._collect_desired([self.mapping, other],
                {sync._mapping_key(self.mapping): {self.route.prefix}, sync._mapping_key(other): {self.route.prefix}}, set(), [])

    def test_add_idempotence_and_expiry(self):
        self.assertEqual(self.cycle()['add'], 1)
        self.assertTrue(sync.matches(self.route, self.backend.live))
        self.assertEqual(self.backend.lookups, [((0, '198.51.100.77/32'),)])
        self.assertEqual(self.cycle()['add'], 0)
        self.assertEqual(self.backend.lookups, [((0, '198.51.100.77/32'),)])
        self.backend.sets['altroute'] = set()
        self.assertEqual(self.cycle()['delete'], 1)
        self.assertNotIn(self.route.key, self.backend.live)

    def test_last_seen_keeps_route_after_nft_empty(self):
        self.cycle()
        self.backend.sets['altroute'] = set()
        extra = {('inet', 'mangle', 'altroute'): {self.route.prefix}}
        self.assertEqual(self.cycle(extra_prefixes=extra)['delete'], 0)
        self.assertTrue(sync.matches(self.route, self.backend.live))

    def test_prepare_sync_skips_dump_when_not_auditing(self):
        self.cycle()
        snapshots = self.backend.snapshots
        prepared = sync.prepare_sync(self.config, self.backend, audit=False)
        self.assertFalse(prepared['audit'])
        self.assertEqual(prepared['live'], {})
        self.assertEqual(self.backend.snapshots, snapshots)

    def test_shared_lock_files_do_not_rewrite(self):
        lock = Path(self.temp.name) / 'wg.lock'
        lock.write_text('keep\n')
        mtime = lock.stat().st_mtime
        with sync.shared_lock_files([str(lock)]):
            pass
        self.assertEqual(lock.read_text(), 'keep\n')
        self.assertEqual(lock.stat().st_mtime, mtime)

    def test_commit_rechecks_leases_before_delete(self):
        self.cycle()
        self.backend.sets['altroute'] = set()
        prepared = sync.prepare_sync(self.config, self.backend)
        extra = {('inet', 'mangle', 'altroute'): {self.route.prefix}}
        summary = sync.commit_sync(
            self.config, self.backend, prepared, extra_prefixes={},
            prefix_locks=sync.PrefixLocks(), refresh_prefixes=lambda: extra)
        self.assertEqual(summary['delete'], 0)
        self.assertTrue(sync.matches(self.route, self.backend.live))
        self.assertEqual(json.loads(self.path.read_text())['owned'], [sync.asdict(self.route)])

    def test_commit_rechecks_nft_before_delete(self):
        self.cycle()
        self.backend.sets['altroute'] = set()
        prepared = sync.prepare_sync(self.config, self.backend)
        self.backend.sets['altroute'] = {self.route.prefix}
        summary = sync.commit_sync(
            self.config, self.backend, prepared, extra_prefixes={},
            prefix_locks=sync.PrefixLocks(), refresh_prefixes=lambda: {})
        self.assertEqual(summary['delete'], 0)
        self.assertTrue(sync.matches(self.route, self.backend.live))

    def test_commit_keeps_route_installed_during_dump(self):
        prepared = sync.prepare_sync(self.config, self.backend)
        self.assertEqual(self.backend.lookups, [])
        self.backend.live[self.route.key] = frozenset({(self.route.via, self.route.interface)})
        sync.atomic_json(self.path, {
            'version': 1, 'generation': self.backend.instance,
            'owned': [sync.asdict(self.route)], 'pending_add': []})
        extra = {('inet', 'mangle', 'altroute'): {self.route.prefix}}
        summary = sync.commit_sync(self.config, self.backend, prepared, extra_prefixes=extra)
        self.assertEqual(summary['add'], 0)
        self.assertEqual(summary['delete'], 0)
        self.assertEqual(self.backend.lookups, [((0, '198.51.100.77/32'),)])
        self.assertTrue(sync.matches(self.route, self.backend.live))
        self.assertEqual(json.loads(self.path.read_text())['owned'], [sync.asdict(self.route)])

    def test_existing_manual_route_is_never_adopted_or_deleted(self):
        self.backend.live[self.route.key] = frozenset({('10.62.30.1', 'wg1')})
        self.assertEqual(self.cycle()['conflicts'], 1)
        self.backend.sets['altroute'] = set()
        self.assertEqual(self.cycle()['delete'], 0)
        self.assertIn(self.route.key, self.backend.live)

    def test_read_failure_keeps_owned_routes_and_state(self):
        self.cycle()
        previous = self.path.read_bytes()
        self.backend.sets['altroute'] = RuntimeError('set unavailable')
        with self.assertRaises(RuntimeError):
            self.cycle()
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertTrue(sync.matches(self.route, self.backend.live))

    def test_external_route_change_is_not_overwritten(self):
        self.cycle()
        external = frozenset({('10.61.20.1', 'host-vpp-wan')})
        self.backend.live[self.route.key] = external
        self.assertEqual(self.cycle()['conflicts'], 1)
        self.assertEqual(self.backend.live[self.route.key], external)
        self.assertEqual(json.loads(self.path.read_text())['owned'], [])

    def test_missing_owned_route_is_repaired(self):
        self.cycle()
        self.backend.live.clear()
        self.assertEqual(self.cycle()['add'], 1)

    def test_restart_rebuilds_but_does_not_claim_new_manual_routes(self):
        self.cycle()
        self.backend.instance = 'b' * 32
        self.backend.live.clear()
        self.assertEqual(self.cycle()['add'], 1)
        self.backend.instance = 'c' * 32
        self.assertEqual(self.cycle()['conflicts'], 1)

    def test_shared_membership_requires_removal_from_all_sets(self):
        self.config['mappings'].append(dict(self.mapping, set='other'))
        self.backend.sets['other'] = self.backend.sets['altroute'].copy()
        self.cycle()
        self.backend.sets['altroute'] = set()
        self.assertEqual(self.cycle()['delete'], 0)
        self.backend.sets['other'] = set()
        self.assertEqual(self.cycle()['delete'], 1)

    def test_conflicting_outputs_abort_before_any_change(self):
        self.cycle()
        self.config['mappings'].append(dict(self.mapping, set='other', interface='wg2', via='10.2.0.1'))
        self.backend.sets['other'] = self.backend.sets['altroute'].copy()
        previous = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.cycle()
        self.assertEqual(self.path.read_bytes(), previous)

    def test_endpoint_exclusion_and_family_check(self):
        self.backend.sets['altroute'] = {'10.64.20.3/32'}
        self.assertEqual(self.cycle()['excluded'], 1)
        self.assertFalse(self.backend.live)
        self.backend.sets['altroute'] = {'2001:db8::77/128'}
        with self.assertRaises(ValueError):
            self.cycle()

    def test_partial_batch_failure_recovers_owned_additions(self):
        self.backend.sets['altroute'].add('198.51.100.78/32')
        self.backend.fail_after = 1
        with self.assertRaises(RuntimeError):
            self.cycle()
        self.assertEqual(len(json.loads(self.path.read_text())['pending_add']), 2)
        result = self.cycle()
        self.assertEqual(result['add'], 1)
        self.assertEqual(result['conflicts'], 0)
        self.assertEqual(len(json.loads(self.path.read_text())['owned']), 2)

    def test_disabled_mapping_withdraws_owned_only(self):
        self.cycle()
        self.mapping['enabled'] = False
        self.assertEqual(self.cycle()['delete'], 1)

    def test_dry_run_does_not_touch_routes_or_state(self):
        self.assertEqual(self.cycle(dry_run=True)['add'], 1)
        self.assertFalse(self.backend.live)
        self.assertFalse(self.path.exists())

    def test_withdraw_does_not_read_missing_set(self):
        self.cycle()
        self.backend.sets.clear()
        self.assertEqual(self.cycle(withdraw=True)['delete'], 1)

    def test_interface_rebuild_removes_owned_paths_then_restores_them(self):
        self.cycle()
        config = Path(self.temp.name) / 'config.json'
        config.write_text(json.dumps(self.config))
        commands = sync.interface_delete_commands('wg1', self.backend.instance, str(config),
                                                  lambda unused: self.backend)
        self.assertEqual(commands, [self.route.command('del')])
        self.backend.apply(commands)
        self.assertEqual(self.cycle()['add'], 1)
        self.backend.live[self.route.key] = frozenset({('10.61.20.1', 'host-vpp-wan')})
        self.assertEqual(sync.interface_delete_commands('wg1', self.backend.instance, str(config),
                                                        lambda unused: self.backend), [])

    def test_ensure_routes_adds_only_required_prefix(self):
        extra = sync.Route(0, '198.51.100.99/32', '10.62.30.1', 'wg1')
        self.backend.sets['altroute'] = {'198.51.100.77/32', extra.prefix}
        result = sync.ensure_routes(self.config, self.backend, [self.route])
        self.assertEqual(result['add'], 1)
        self.assertEqual(self.backend.prefix_reads, 0)
        self.assertEqual(self.backend.snapshots, 0)
        self.assertEqual(self.backend.cli_calls, [])
        self.assertIn(self.route.key, self.backend.live)
        self.assertNotIn(extra.key, self.backend.live)
        self.assertEqual(json.loads(self.path.read_text())['owned'], [sync.asdict(self.route)])

    def test_ensure_routes_is_idempotent_and_does_not_delete_others(self):
        other = sync.Route(0, '198.51.100.88/32', '10.62.30.1', 'wg1')
        self.backend.sets['altroute'] = {self.route.prefix, other.prefix}
        self.cycle()
        snapshots = self.backend.snapshots
        lookups = len(self.backend.lookups)
        sync.ensure_routes(self.config, self.backend, [self.route])
        self.assertEqual(len(self.backend.batches), 2)
        self.assertEqual(len(self.backend.lookups), lookups)
        self.assertEqual(self.backend.snapshots, snapshots)
        self.assertIn(other.key, self.backend.live)
        self.backend.sets['altroute'] = set()
        self.assertEqual(self.cycle()['delete'], 2)

    def test_ensure_routes_conflict_and_endpoint(self):
        self.backend.live[self.route.key] = frozenset({('10.61.20.1', 'host-vpp-wan')})
        sync.ensure_routes(self.config, self.backend, [self.route])
        self.assertFalse(self.backend.lookups)
        self.assertEqual(self.backend.live[self.route.key],
                         frozenset({('10.62.30.1', 'wg1')}))
        with self.assertRaises(RuntimeError):
            sync.ensure_routes(self.config, self.backend,
                               [sync.Route(0, '10.64.20.3/32', '10.62.30.1', 'wg1')])
        self.assertEqual(len(self.backend.batches), 1)

    def test_ensure_routes_rejects_matching_route_after_exclude(self):
        sync.ensure_routes(self.config, self.backend, [self.route])
        self.config['exclude_prefixes'] = ['198.51.100.0/24']
        with self.assertRaises(RuntimeError):
            sync.ensure_routes(self.config, self.backend, [self.route])
        self.assertTrue(sync.matches(self.route, self.backend.live))

    def test_ensure_records_ownership_so_background_can_withdraw(self):
        sync.ensure_routes(self.config, self.backend, [self.route])
        self.backend.sets['altroute'] = set()
        self.assertEqual(self.cycle()['delete'], 1)
        self.assertNotIn(self.route.key, self.backend.live)


class VROUTERVpnBr0ConfigTests(unittest.TestCase):
    def test_vpn4_uses_vpp_snat_and_vpn6_retains_br0_gateway(self):
        path = Path(__file__).parents[2] / 'deploy/dns-route-gate/nftset-route-sync.json'
        config = sync.load_config(path)
        mappings = {item['set']: item for item in config['mappings'] if item.get('enabled', True)}
        self.assertEqual(mappings['vpn']['via'], '10.61.50.1')
        self.assertEqual(mappings['vpn']['interface'], 'loop10')
        self.assertEqual(mappings['vpn6']['via'], 'fd42:1111:2222:20::1')
        self.assertEqual(mappings['vpn6']['interface'], 'loop10')
        self.assertEqual(mappings['altroute']['via'], '10.62.30.1')
        self.assertIn('proxylist', mappings)
        self.assertIn('proxylist6', mappings)
        exclusions = [ipaddress.ip_network(item) for item in config['exclude_prefixes']]
        self.assertTrue(sync.is_excluded(ipaddress.ip_network('10.61.50.1/32'), set(), exclusions))
        self.assertTrue(sync.is_excluded(
            ipaddress.ip_network('fd42:1111:2222:20::1/128'), set(), exclusions))
        self.assertTrue(sync.is_excluded(ipaddress.ip_network('1.1.1.1/32'), set(), exclusions))
        self.assertTrue(sync.is_excluded(ipaddress.ip_network('8.8.8.8/32'), set(), exclusions))
        self.assertTrue(sync.is_excluded(
            ipaddress.ip_network('2606:4700:4700::1111/128'), set(), exclusions))
        self.assertEqual(config['vpp_service'], 'vrouter-vpp.service')


class BackendGenerationTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import patch
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        socket = Path(self.tmp.name)/'cli.sock'
        socket.touch()
        self.backend = sync.Backend({'vpp_socket':str(socket),'vpp_service':'private-test.service'})
        sync.Backend._generations.clear()
        self.addCleanup(sync.Backend._generations.clear)
        self.systemctl = patch.object(sync.Backend, 'run', return_value=
            'InvocationID='+'a'*32+'\nMainPID=123\nActiveState=active\n').start()
        self.process_patch = patch.object(sync.Backend, '_process_identity', return_value='start-a')
        self.process = self.process_patch.start()
        self.addCleanup(patch.stopall)

    def test_live_cached_generation_does_not_repeat_systemctl(self):
        self.assertEqual(self.backend.generation(), 'a'*32)
        self.assertEqual(self.backend.generation(), 'a'*32)
        self.assertEqual(self.systemctl.call_count, 1)
        self.assertEqual(self.process.call_count, 2)

    def test_dead_vpp_with_remaining_socket_rejects_cached_generation(self):
        self.backend.generation()
        self.process.side_effect = RuntimeError('VPP process is not running')
        with self.assertRaises(RuntimeError):
            self.backend.generation()
        self.assertEqual(self.systemctl.call_count, 1)

    def test_reused_pid_rejects_old_generation(self):
        self.backend.generation()
        self.process.return_value = 'start-b'
        with self.assertRaises(RuntimeError):
            self.backend.generation()

    def test_inactive_service_cannot_initialize_generation(self):
        self.systemctl.return_value = 'InvocationID='+'a'*32+'\nMainPID=0\nActiveState=inactive\n'
        with self.assertRaises(RuntimeError):
            self.backend.generation()

    def test_process_stat_handles_spaces_and_rejects_zombies(self):
        from unittest.mock import patch
        # Exercise the actual helper, bypassing the mock used in other tests.
        self.process_patch.stop()
        text = '123 (vpp worker name) S '+' '.join(['0']*18)+' 987 0'
        with patch.object(Path, 'read_text', return_value=text):
            self.assertEqual(sync.Backend._process_identity('123'), '987')
        with patch.object(Path, 'read_text', return_value=text.replace(') S ', ') Z ')):
            with self.assertRaises(RuntimeError):
                sync.Backend._process_identity('123')


if __name__ == '__main__':
    unittest.main()
