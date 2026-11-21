import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from test_nftset_route_sync import FakeBackend, sync

SPEC = importlib.util.spec_from_file_location('dns_gate', Path(__file__).parents[2] / 'tools/dns-route-gate.py')
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


def packet(reply=False, ttl=60):
    question = b'\x03www\x07example\x03net\0' + struct.pack('!HH', 1, 1)
    header = struct.pack('!6H', 123, 0x8180 if reply else 0x0100, 1, int(reply), 0, 0)
    rr = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, ttl, 4) + socket.inet_aton('198.51.100.77')
    return header + question + (rr if reply else b'')


class ControllerTests(unittest.TestCase):
    def test_rule_index_matches_linear_rules_in_original_order(self):
        rules = [('example.com', []), ('api.example.com', [], None, 'suffix'),
                 ('proxy', [], ('127.0.0.1', 54), 'contains'),
                 ('example.com', [], ('127.0.0.1', 55), 'suffix')]
        self.controller._rule_index = self.controller._index_rules(rules)
        for names in [['WWW.API.EXAMPLE.COM.'], ['badexample.com'],
                      ['proxy.example.com'], ['cdn.example.com', 'dualstack.proxy.net']]:
            expected = [rule for rule in rules
                        if any(gate.rule_matches(name, gate.rule_parts(rule)[0],
                                                 gate.rule_parts(rule)[3]) for name in names)]
            self.assertEqual(self.controller._matching_rules(rules, names), expected)
        replacement = [('other.net', [])]
        self.assertEqual(self.controller._matching_rules(replacement, ['www.other.net']), replacement)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        config = {'state_file': str(root / 'state.json'), 'lock_files': [],
                  'exclude_prefixes': ['10.64.20.3/32'], 'mappings': [
            {'family': 'inet', 'table': 'mangle', 'set': 'altroute', 'interface': 'wg1', 'via': '10.62.30.1'}]}
        (root / 'config.json').write_text(json.dumps(config))
        (root / 'rules.conf').write_text('nftset=/example.net/4#inet#mangle#altroute\n')
        self.backend = FakeBackend()
        self.backend.sets['altroute'] = set()
        self.controller = gate.Controller(sync, root / 'config.json', lambda: [root / 'rules.conf'], root / 'leases.json', lambda c: self.backend)
        self.question = ('www.example.net', 1, 1)
        self.records = [('www.example.net', '198.51.100.77', 60)]

    def ordered_controller(self):
        path = Path(self.controller.config_path)
        config = json.loads(path.read_text())
        config['overlap_policy'] = 'first'
        config['mappings'].append({**config['mappings'][0], 'set': 'proxylist', 'via': '10.61.20.2', 'interface': 'loop200'})
        path.write_text(json.dumps(config))
        (path.parent/'rules.conf').write_text('nftset=/example.net/4#inet#mangle#altroute\nnftset=/example.net/4#inet#mangle#proxylist\n')
        self.backend.sets['proxylist'] = set()
        # Construct with the final fixture: these tests exercise ordered
        # routing, independently of the filesystem's timestamp resolution.
        self.controller = gate.Controller(sync, path, self.controller.rule_paths,
                                          self.controller.lease_path, lambda c: self.backend)

    def test_static_nft_members_are_routed_and_restored(self):
        self.ordered_controller()
        root = Path(self.controller.config_path).parent
        nft = root / 'nftables.conf'
        nft.write_text('''table inet mangle {
            set altroute { type ipv4_addr; elements = { 203.0.113.1 } }
            set local { type ipv4_addr; elements = { 192.0.2.1 } }
        }
        add element inet mangle proxylist { 198.51.100.0-198.51.100.3 }
        ''')
        self.controller = gate.Controller(sync, self.controller.config_path,
                                          self.controller.rule_paths, self.controller.lease_path,
                                          lambda c: self.backend, static_nftables_path=nft)
        self.controller.reconcile(force_audit=True)
        self.assertEqual(self.backend.live[(0, '203.0.113.1/32')],
                         frozenset({('10.62.30.1', 'wg1')}))
        self.assertEqual(self.backend.live[(0, '198.51.100.0/30')],
                         frozenset({('10.61.20.2', 'loop200')}))
        self.assertNotIn((0, '192.0.2.1/32'), self.backend.live)
        self.backend.live.clear()
        self.backend.instance = 'b' * 32
        restarted = gate.Controller(sync, self.controller.config_path,
                                    self.controller.rule_paths, self.controller.lease_path,
                                    lambda c: self.backend, static_nftables_path=nft)
        restarted.reconcile(force_audit=True)
        self.assertIn((0, '203.0.113.1/32'), self.backend.live)
        nft.write_text('table inet mangle { set altroute { type ipv4_addr; } }\n')
        restarted.reconcile(force_audit=True)
        self.assertNotIn((0, '203.0.113.1/32'), self.backend.live)
        self.assertNotIn((0, '198.51.100.0/30'), self.backend.live)

    def test_static_priority_applies_to_first_dns_answer(self):
        self.ordered_controller()
        root = Path(self.controller.config_path).parent
        nft = root / 'nftables.conf'
        nft.write_text('table inet mangle { set altroute { type ipv4_addr; } }\n'
                       'add element inet mangle altroute { 198.51.100.64/26 }\n')
        (root / 'rules.conf').write_text('nftset=/example.net/4#inet#mangle#proxylist\n')
        self.controller = gate.Controller(sync, self.controller.config_path,
                                          self.controller.rule_paths, self.controller.lease_path,
                                          lambda c: self.backend, static_nftables_path=nft)
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(self.backend.live[(0, '198.51.100.64/26')],
                         frozenset({('10.62.30.1', 'wg1')}))
        self.assertNotIn((0, '198.51.100.77/32'), self.backend.live)

    def test_fakeip_range_files_are_installed_for_their_fakeip_exit(self):
        root = Path(self.tmp.name)
        ranges4 = root / 'fakeip.ipv4'
        ranges6 = root / 'fakeip.ipv6'
        ranges4.write_text('198.18.0.0/15\n203.0.113.0/24\n203.0.114.1-203.0.114.3\n')
        ranges6.write_text('2001:2::/48\n2001:db8:10::/48\n')
        path = root / 'domain-routes.json'
        path.write_text(json.dumps({'routes': [
            {'name': 'proxylist', 'interface': 'tap2490', 'via': '10.63.30.2',
             'domains': ['plist.example'], 'ip_range_files': [ranges4.name],
             'fakeip_range': '198.18.0.0/15', 'dns_upstream': ['127.0.0.1', 5354]},
            {'name': 'proxylist6', 'interface': 'tap2490',
             'domains': ['plist.example'], 'via': 'fd42:1111:2222:30::2',
             'ip_range_files': [ranges6.name], 'fakeip_range': '2001:2::/48',
             'dns_upstream': ['127.0.0.1', 5354]}]}))
        config_path = root / 'config.json'
        config = json.loads(config_path.read_text())
        config.update(overlap_policy='first', dns_upstream_policy='first')
        config_path.write_text(json.dumps(config))
        self.controller = gate.Controller(sync, root / 'config.json', lambda: [],
                                          root / 'leases.json', lambda c: self.backend,
                                          domain_routes_path=path)
        self.controller.reconcile()
        self.assertEqual(self.backend.live[(0, '198.18.0.0/15')],
                         frozenset({('10.63.30.2', 'tap2490')}))
        self.assertEqual(self.backend.live[(0, '203.0.113.0/24')],
                         frozenset({('10.63.30.2', 'tap2490')}))
        self.assertEqual(self.backend.live[(0, '203.0.114.1/32')],
                         frozenset({('10.63.30.2', 'tap2490')}))
        self.assertEqual(self.backend.live[(0, '2001:2::/48')],
                         frozenset({('fd42:1111:2222:30::2', 'tap2490')}))
        self.assertEqual(self.backend.live[(0, '2001:db8:10::/48')],
                         frozenset({('fd42:1111:2222:30::2', 'tap2490')}))

    def test_ip_range_files_reject_wrong_family_and_default_route(self):
        root = Path(self.tmp.name)
        ranges = root / 'bad.ranges'
        path = root / 'domain-routes.json'
        path.write_text(json.dumps({'routes': [{
            'name': 'bad', 'interface': 'tap2490', 'via': '10.63.30.2',
            'domains': ['bad.example'], 'ip_range_files': [ranges.name]}]}))
        ranges.write_text('2001:db8::/32\n')
        with self.assertRaisesRegex(ValueError, 'invalid IP range'):
            gate.Controller(sync, root / 'config.json', lambda: [],
                            root / 'leases.json', lambda c: self.backend,
                            domain_routes_path=path)
        ranges.write_text('0.0.0.0/0\n')
        with self.assertRaisesRegex(ValueError, 'invalid IP range'):
            gate.Controller(sync, root / 'config.json', lambda: [],
                            root / 'leases.json', lambda c: self.backend,
                            domain_routes_path=path)

    def test_ordered_dns_ignores_nft_membership(self):
        self.ordered_controller()
        self.controller.reconcile(self.records, self.question)
        key = (0, '198.51.100.77/32')
        self.assertEqual(self.backend.live[key], frozenset({('10.62.30.1', 'wg1')}))
        self.backend.sets['proxylist'] = {key[1]}
        self.assertEqual(self.backend.live[key], frozenset({('10.62.30.1', 'wg1')}))
        self.controller.reconcile()
        self.assertEqual(self.backend.live[key], frozenset({('10.62.30.1', 'wg1')}))

    def test_ordered_cached_dns_does_not_read_nft(self):
        self.ordered_controller()
        self.controller.reconcile(self.records, self.question)
        reads = self.backend.prefix_reads
        snapshots = self.backend.snapshots
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(self.backend.prefix_reads, reads)
        self.assertEqual(self.backend.snapshots, snapshots)
        self.controller.reconcile(self.records, self.question, force_audit=True)
        self.assertGreater(self.backend.snapshots, snapshots)

    def test_ordered_dns_install_skips_fib_dump(self):
        self.ordered_controller()
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(self.backend.snapshots, 0)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)

    def test_ordered_cache_hit_not_blocked_by_background(self):
        self.ordered_controller()
        self.controller.reconcile(self.records, self.question)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = self.backend.snapshot

        def slow(routes):
            entered.set()
            if not release.wait(2):
                raise RuntimeError('test timed out')
            return original(routes)

        self.backend.snapshot = slow
        background = threading.Thread(target=lambda: self.controller.reconcile(force_audit=True))
        background.start()
        self.assertTrue(entered.wait(2))

        def hit():
            self.controller.reconcile(self.records, self.question)
            finished.set()

        worker = threading.Thread(target=hit)
        worker.start()
        self.assertTrue(finished.wait(2), 'ordered cache hit blocked by background audit')
        release.set()
        background.join(3)
        worker.join(3)

    def test_ordered_first_seen_not_blocked_by_background(self):
        self.ordered_controller()
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = self.backend.snapshot

        def slow(routes):
            entered.set()
            if not release.wait(2):
                raise RuntimeError('test timed out')
            return original(routes)

        self.backend.snapshot = slow
        background = threading.Thread(target=lambda: self.controller.reconcile(force_audit=True))
        background.start()
        self.assertTrue(entered.wait(2))

        def first_seen():
            self.controller.reconcile(self.records, self.question)
            finished.set()

        worker = threading.Thread(target=first_seen)
        worker.start()
        self.assertTrue(finished.wait(2), 'ordered first-seen blocked by background audit')
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        release.set()
        background.join(3)
        worker.join(3)

    def test_ordered_nft_change_does_not_invalidate_cached_winner(self):
        self.ordered_controller()
        prefix = '198.51.100.77/32'
        self.backend.sets['proxylist'] = {prefix}
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(self.backend.live[(0, prefix)], frozenset({('10.62.30.1', 'wg1')}))
        self.backend.sets['altroute'] = {prefix}
        self.controller.reconcile()
        self.assertEqual(self.backend.live[(0, prefix)], frozenset({('10.62.30.1', 'wg1')}))
        self.assertEqual(self.backend.prefix_reads, 0)

    def test_ordered_dns_accepts_api_success_without_fib_queries(self):
        self.ordered_controller()
        self.backend.live[(0, '198.51.100.77/32')] = frozenset({('10.61.10.1', 'external')})
        self.controller.reconcile(self.records, self.question)
        self.assertFalse(self.backend.lookups)
        self.assertTrue(self.backend.batches)

    def test_lease_updates_stay_in_memory_until_stop(self):
        path = self.controller.lease_path
        before = path.read_bytes() if path.exists() else None
        with sync.DeferredState([path]):
            self.controller.reconcile(self.records, self.question)
            self.assertEqual(path.read_bytes() if path.exists() else None, before)
            self.assertTrue(sync.read_json(path, []))
        self.assertTrue(json.loads(path.read_text()))

    def test_cache_hit_without_nft_membership_and_expiry(self):
        self.controller.reconcile(self.records, self.question)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        self.controller.reconcile()
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        for key in list(self.controller.seen):
            self.controller.seen[key] = time.time() - 8 * 24 * 3600
        self.controller.reconcile()
        self.assertNotIn((0, '198.51.100.77/32'), self.backend.live)

    def test_dns_path_does_not_full_sync(self):
        extra = '203.0.113.1/32'
        self.backend.sets['altroute'] = {extra}
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(self.backend.prefix_reads, 0)
        self.assertEqual(self.backend.snapshots, 0)
        self.assertFalse(self.backend.lookups)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        self.assertNotIn((0, extra), self.backend.live)
        lookups = len(self.backend.lookups)
        cli_calls = list(self.backend.cli_calls)
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(self.backend.prefix_reads, 0)
        self.assertEqual(self.backend.snapshots, 0)
        self.assertEqual(self.backend.cli_calls, cli_calls)
        self.assertEqual(len(self.backend.lookups), lookups)
        self.controller.reconcile()
        self.assertEqual(self.backend.prefix_reads, 0)
        self.assertEqual(self.backend.snapshots, 0)
        self.assertNotIn((0, extra), self.backend.live)

    def test_conflict_fails_barrier(self):
        self.backend.live[(0, '198.51.100.77/32')] = frozenset({('10.61.20.1', 'host-vpp-wan')})
        self.controller.reconcile(self.records, self.question)
        self.assertFalse(self.backend.lookups)
        self.assertEqual(self.backend.live[(0, '198.51.100.77/32')],
                         frozenset({('10.62.30.1', 'wg1')}))

    def test_endpoint_is_not_acknowledged(self):
        with self.assertRaises(RuntimeError):
            self.controller.reconcile([('www.example.net', '10.64.20.3', 60)], self.question)

    def test_recovery_forces_fib_audit_before_interval_expires(self):
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile()
        self.backend.live.clear()
        snapshots = self.backend.snapshots
        self.controller.reconcile(force_audit=True)
        self.assertGreater(self.backend.snapshots, snapshots)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)

    def test_unselected_domain_does_not_change_routes(self):
        self.controller.reconcile([('example.org', '198.51.100.77', 60)], ('example.org', 1, 1))
        self.assertFalse(self.backend.batches)

    def test_cname_target_matches_mapping(self):
        self.controller.reconcile([('outside.test', 'www.example.net', 60), *self.records], ('outside.test', 1, 1))
        self.assertTrue(self.backend.live)

    def test_restart_keeps_client_cache_lease(self):
        self.controller.reconcile(self.records, self.question)
        other = gate.Controller(sync, self.controller.config_path, self.controller.rule_paths, self.controller.lease_path, lambda c: self.backend)
        self.backend.live.clear()
        self.backend.instance = 'b' * 32
        other.reconcile()
        self.assertTrue(self.backend.live)

    def test_same_prefix_queries_each_wait_for_successful_add(self):
        entered, release = threading.Event(), threading.Event()
        original = self.backend.apply

        def slow(lines):
            entered.set()
            if not release.wait(2):
                raise RuntimeError('test timed out')
            return original(lines)

        self.backend.apply = slow
        errors = []

        def worker():
            try:
                self.controller.reconcile(self.records, self.question)
            except Exception as error:
                errors.append(error)

        first, second = threading.Thread(target=worker), threading.Thread(target=worker)
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        deadline = time.time() + 2
        while time.time() < deadline:
            with self.controller.flight_lock:
                if (0, '198.51.100.77/32') in self.controller.in_flight:
                    break
            time.sleep(0.01)
        self.assertIn((0, '198.51.100.77/32'), self.controller.in_flight)
        release.set()
        first.join(3)
        second.join(3)
        self.assertFalse(errors)
        self.assertEqual(len(self.backend.batches), 2)

    def test_cache_hit_not_blocked_by_background(self):
        self.controller.reconcile(self.records, self.question)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = self.backend.snapshot

        def slow(mapping):
            entered.set()
            if not release.wait(2):
                raise RuntimeError('test timed out')
            return original(mapping)

        self.backend.snapshot = slow
        background = threading.Thread(target=lambda: self.controller.reconcile(force_audit=True))
        background.start()
        self.assertTrue(entered.wait(2))

        def hit():
            self.controller.reconcile(self.records, self.question)
            finished.set()

        worker = threading.Thread(target=hit)
        worker.start()
        self.assertTrue(finished.wait(2), 'cache hit blocked by background reconcile')
        release.set()
        background.join(3)
        worker.join(3)

    def test_new_ip_not_blocked_by_background_fib_dump(self):
        self.controller.reconcile(self.records, self.question)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = self.backend.snapshot

        def slow(routes):
            entered.set()
            if not release.wait(2):
                raise RuntimeError('test timed out')
            return original(routes)

        self.backend.snapshot = slow
        background = threading.Thread(target=lambda: self.controller.reconcile(force_audit=True))
        background.start()
        self.assertTrue(entered.wait(2))

        def install():
            self.controller.reconcile([('www.example.net', '198.51.100.88', 60)], self.question)
            finished.set()

        worker = threading.Thread(target=install)
        worker.start()
        self.assertTrue(finished.wait(2), 'new IP blocked by background FIB dump')
        self.assertIn((0, '198.51.100.88/32'), self.backend.live)
        release.set()
        background.join(3)
        worker.join(3)

    def test_new_ip_not_blocked_by_background_apply(self):
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile([('www.example.net', '198.51.100.1', 60)], self.question)
        self.backend.live.pop((0, '198.51.100.1/32'))
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = self.backend.apply

        def slow(lines):
            if any('198.51.100.1/32' in line for line in lines):
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('test timed out')
            return original(lines)

        self.backend.apply = slow
        background = threading.Thread(target=lambda: self.controller.reconcile(force_audit=True))
        background.start()
        self.assertTrue(entered.wait(2))

        def install():
            self.controller.reconcile([('www.example.net', '198.51.100.88', 60)], self.question)
            finished.set()

        worker = threading.Thread(target=install)
        worker.start()
        self.assertTrue(finished.wait(2), 'new IP blocked by background apply')
        self.assertIn((0, '198.51.100.88/32'), self.backend.live)
        release.set()
        background.join(3)
        worker.join(3)
        self.assertIn((0, '198.51.100.88/32'), self.backend.live)
        owned = {item['prefix'] for item in json.loads(Path(self.controller._config['state_file']).read_text())['owned']}
        self.assertIn('198.51.100.88/32', owned)

    def test_mapping_change_invalidates_cache(self):
        self.controller.reconcile(self.records, self.question)
        path = Path(self.controller.config_path)
        config = json.loads(path.read_text())
        config['mappings'][0]['via'] = '10.62.30.9'
        path.write_text(json.dumps(config))
        os.utime(path, (path.stat().st_mtime + 2, path.stat().st_mtime + 2))
        with self.assertRaises(RuntimeError):
            self.controller.reconcile(self.records, self.question)
        self.assertEqual(self.backend.live[(0, '198.51.100.77/32')],
                         frozenset({('10.62.30.1', 'wg1')}))

    def test_renewal_not_deleted_by_inflight_withdraw(self):
        self.controller.reconcile(self.records, self.question)
        for key in list(self.controller.seen):
            self.controller.seen[key] = time.time() - 8 * 24 * 3600
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = self.backend.apply

        def slow(lines):
            if any(line.startswith('ip route del') and '198.51.100.77/32' in line for line in lines):
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('test timed out')
            return original(lines)

        self.backend.apply = slow
        background = threading.Thread(target=self.controller.reconcile)
        background.start()
        self.assertTrue(entered.wait(2), 'background did not reach delete')

        def renew():
            self.controller.reconcile(self.records, self.question)
            finished.set()

        worker = threading.Thread(target=renew)
        worker.start()
        self.assertFalse(finished.wait(0.3), 'renewal completed during same-prefix withdraw')
        release.set()
        self.assertTrue(finished.wait(2))
        background.join(3)
        worker.join(3)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        owned = {item['prefix'] for item in json.loads(
            Path(self.controller._config['state_file']).read_text())['owned']}
        self.assertIn('198.51.100.77/32', owned)

    def test_exclude_prefixes_change_rejects_cached_ip(self):
        self.controller.reconcile(self.records, self.question)
        path = Path(self.controller.config_path)
        config = json.loads(path.read_text())
        config['exclude_prefixes'] = ['198.51.100.0/24']
        path.write_text(json.dumps(config))
        os.utime(path, (path.stat().st_mtime + 2, path.stat().st_mtime + 2))
        with self.assertRaises(RuntimeError):
            self.controller.reconcile(self.records, self.question)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        self.assertNotIn((0, '198.51.100.77/32'), self.controller.verified)

    def test_generation_change_reinstalls(self):
        self.controller.reconcile(self.records, self.question)
        self.backend.live.clear()
        self.backend.instance = 'b' * 32
        self.controller.reconcile(self.records, self.question)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)

    def _with_lock_file(self):
        lock = Path(self.tmp.name) / 'wg.lock'
        lock.write_text('epoch\n')
        path = Path(self.controller.config_path)
        config = json.loads(path.read_text())
        config['lock_files'] = [str(lock)]
        path.write_text(json.dumps(config))
        os.utime(path, (path.stat().st_mtime + 2, path.stat().st_mtime + 2))
        return lock

    def test_shared_flock_does_not_invalidate_verified(self):
        lock = self._with_lock_file()
        before = (lock.read_text(), lock.stat().st_mtime)
        self.controller.reconcile(self.records, self.question)
        lookups = len(self.backend.lookups)
        with self.controller._interface_locks(self.controller._load()[0]):
            pass
        self.assertEqual((lock.read_text(), lock.stat().st_mtime), before)
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(len(self.backend.lookups), lookups)

    def test_lock_file_epoch_reinstalls(self):
        lock = self._with_lock_file()
        self.controller.reconcile(self.records, self.question)
        lookups = len(self.backend.lookups)
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(len(self.backend.lookups), lookups)
        lock.write_text('rebuilt\n')
        os.utime(lock, (lock.stat().st_mtime + 2, lock.stat().st_mtime + 2))
        self.backend.live.clear()
        self.controller.reconcile(self.records, self.question)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        self.assertEqual(len(self.backend.lookups), lookups)

    def test_idle_zero_keeps_unobserved_route(self):
        path = Path(self.controller.config_path)
        config = json.loads(path.read_text())
        config['idle_seconds'] = 0
        path.write_text(json.dumps(config))
        os.utime(path, (path.stat().st_mtime + 2, path.stat().st_mtime + 2))
        self.controller.reconcile(self.records, self.question)
        for key in list(self.controller.seen):
            self.controller.seen[key] = time.time() - 90 * 24 * 3600
        self.controller.reconcile()
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)

    def test_background_does_not_audit_fib(self):
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile()
        snapshots = self.backend.snapshots
        self.assertEqual(snapshots, 0)
        self.controller.reconcile()
        self.assertEqual(self.backend.snapshots, snapshots)
        self.assertFalse(self.backend.lookups)
        for key in self.controller.seen:
            self.controller.seen[key] = time.time() - 8 * 24 * 3600
        self.controller.reconcile()
        self.assertNotIn((0, '198.51.100.77/32'), self.backend.live)
        self.assertEqual(self.backend.snapshots, 0)
        self.assertFalse(self.backend.lookups)

    def test_ordered_renewal_waits_for_inflight_withdraw(self):
        self.ordered_controller()
        self.test_renewal_not_deleted_by_inflight_withdraw()

    def test_background_retries_failed_add_without_fib_reads(self):
        config, _ = self.controller._load()
        config['_static_prefixes'] = {('inet', 'mangle', 'altroute'): {'198.51.100.77/32'}}
        self.backend.fail_after = 0
        with self.assertRaises(RuntimeError):
            self.controller.reconcile()
        self.assertNotIn((0, '198.51.100.77/32'), self.backend.live)
        self.controller.reconcile()
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        self.assertEqual(self.backend.snapshots, 0)
        self.assertFalse(self.backend.lookups)

    def test_unchanged_background_skips_bulk_planning_but_repairs_interception(self):
        self.ordered_controller()
        path = Path(self.controller.config_path)
        config = json.loads(path.read_text())
        config['mappings'][0]['tproxy_set'] = 'lease4'
        path.write_text(json.dumps(config))
        intercepted = []
        self.backend.sync_tproxy = lambda routes: intercepted.append({r.prefix for r in routes})
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile()
        intercepted.clear()
        with mock.patch.object(sync, 'prepare_sync', side_effect=AssertionError('unneeded bulk sync')):
            self.controller.reconcile(self.records, self.question)
            self.controller.reconcile()
        self.assertEqual(intercepted, [{'198.51.100.77/32'}])
        # Expiry changes membership and must still trigger a real withdrawal.
        for key in self.controller.seen:
            self.controller.seen[key] = time.time() - 8 * 24 * 3600
        self.controller.reconcile()
        self.assertNotIn((0, '198.51.100.77/32'), self.backend.live)

    def test_successful_new_dns_claim_skips_bulk_sync_but_failed_add_is_retried(self):
        self.ordered_controller()
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile()
        added = [('www.example.net', '198.51.100.88', 60)]
        self.controller.reconcile(added, self.question)
        with mock.patch.object(sync, 'prepare_sync', side_effect=AssertionError('unneeded bulk sync')):
            self.controller.reconcile()
        failed = [('www.example.net', '198.51.100.99', 60)]
        self.backend.fail_after = 0
        with self.assertRaises(RuntimeError):
            self.controller.reconcile(failed, self.question)
        self.controller.reconcile()
        self.assertIn((0, '198.51.100.99/32'), self.backend.live)
        self.assertFalse(self.backend.lookups)
        self.assertEqual(self.backend.snapshots, 0)

    def test_frozen_rules_read_once_and_take_changes_only_after_restart(self):
        def start():
            return gate.Controller(sync, self.controller.config_path, self.controller.rule_paths,
                                   self.controller.lease_path, lambda c: self.backend, reload_rules=False)
        first = start()
        path = Path(self.controller.config_path).parent / 'rules.conf'
        path.write_text('nftset=/example.org/4#inet#mangle#altroute\n')
        with mock.patch.object(Path, 'stat', side_effect=AssertionError('rules stat in request path')):
            config, rules = first._load()
            self.assertTrue(first._matching_rules(rules, ['www.example.net']))
            self.assertFalse(first._matching_rules(rules, ['example.org']))
        restarted = start()
        config, rules = restarted._load()
        self.assertFalse(restarted._matching_rules(rules, ['www.example.net']))
        self.assertTrue(restarted._matching_rules(rules, ['example.org']))

    def test_every_dns_answer_restores_deleted_route_without_fib_reads(self):
        for ordered in (False, True):
            if ordered:
                self.ordered_controller()
            self.controller.reconcile(self.records, self.question)
            self.backend.live.clear()
            batches = len(self.backend.batches)
            self.controller.reconcile(self.records, self.question)
            self.assertEqual(len(self.backend.batches), batches + 1)
            self.assertIn((0, '198.51.100.77/32'), self.backend.live)
            self.assertEqual(self.backend.snapshots, 0)
            self.assertFalse(self.backend.lookups)
            self.backend.fail_after = 0
            with self.assertRaises(RuntimeError):
                self.controller.reconcile(self.records, self.question)

    def _lease_writes(self):
        writes = []
        real = self.controller.module.atomic_json

        def counted(path, value):
            if Path(path) == self.controller.lease_path:
                writes.append(json.dumps(value, sort_keys=True))
            return real(path, value)

        self.controller.module.atomic_json = counted
        return writes

    def test_new_lease_persisted_and_repeat_skips_rewrite(self):
        writes = self._lease_writes()
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(len(writes), 1)
        self.assertIn('198.51.100.77/32', writes[0])
        on_disk = json.loads(self.controller.lease_path.read_text())
        self.assertEqual(on_disk[0]['prefix'], '198.51.100.77/32')
        self.assertIsInstance(on_disk[0]['seen'], int)
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(len(writes), 1)

    def test_last_seen_rewritten_after_persist_interval(self):
        writes = self._lease_writes()
        self.controller.reconcile(self.records, self.question)
        key = next(iter(self.controller.seen))
        self.controller.seen[key] = int(time.time()) - 61
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(len(writes), 2)
        self.assertGreater(self.controller.seen[key], int(time.time()) - 5)

    def test_rules_cached_until_files_or_config_change(self):
        calls = []
        real = gate.rules_from_files

        def wrapped(*args, **kwargs):
            calls.append(1)
            return real(*args, **kwargs)

        gate.rules_from_files = wrapped
        self.addCleanup(lambda: setattr(gate, 'rules_from_files', real))
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(calls, [])
        rules = Path(self.tmp.name) / 'rules.conf'
        rules.write_text(rules.read_text() + '# touch\n')
        os.utime(rules, (rules.stat().st_mtime + 2, rules.stat().st_mtime + 2))
        self.controller.reconcile(self.records, self.question)
        self.assertEqual(len(calls), 1)

    def test_direct_domain_rule_needs_no_nft_member(self):
        rules = Path(self.tmp.name) / 'rules.conf'
        rules.write_text('route=/example.net/4#altroute\n')
        self.backend.sets.clear()
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile()
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        self.assertEqual(self.backend.prefix_reads, 0)

    def domain_routes_controller(self, domains=None):
        root = Path(self.tmp.name)
        path = root / 'domain-routes.json'
        route = {'name': 'altroute', 'interface': 'wg1', 'via': '10.62.30.1',
                 'domains': domains or ['example.net']}
        path.write_text(json.dumps({'routes': [route]}))
        self.controller = gate.Controller(sync, root / 'config.json', lambda: [],
                                          root / 'leases.json', lambda c: self.backend,
                                          domain_routes_path=path)
        return path, route

    def fakeip_controller(self, pools=True):
        root = Path(self.tmp.name)
        config = json.loads((root / 'config.json').read_text())
        config.update(overlap_policy='first', dns_upstream_policy='first')
        (root / 'config.json').write_text(json.dumps(config))
        routes = [{'name': 'real', 'interface': 'wg1', 'via': '10.62.30.1',
                   'domains': ['real.example.com']}]
        for name, via, prefix in [('fake4', '10.63.30.2', '198.18.0.0/15'),
                                  ('fake6', 'fd42:1111:2222:30::2', '2001:2::/48')]:
            route = {'name': name, 'interface': 'tap2490', 'via': via,
                     'domains': ['example.com'], 'dns_upstream': ['127.0.0.1', 5354]}
            if pools:
                route['fakeip_range'] = prefix
            routes.append(route)
        path = root / 'domain-routes.json'
        path.write_text(json.dumps({'routes': routes}))
        self.controller = gate.Controller(sync, root / 'config.json', lambda: [], root / 'leases.json',
                                          lambda c: self.backend, domain_routes_path=path)
        return path

    def test_fakeip_pools_install_once_and_answers_write_no_routes_or_leases(self):
        self.fakeip_controller()
        self.controller.reconcile()
        self.assertEqual(set(self.backend.live), {(0, '198.18.0.0/15'), (0, '2001:2::/48')})
        batches = len(self.backend.batches)
        for kind, ip in [(1, '198.18.0.12'), (28, '2001:2::12')]:
            question = ('www.example.com', kind, 1)
            self.assertEqual(self.controller.dns_upstream(question), ('127.0.0.1', 5354))
            self.assertEqual(self.controller.answer_ttl(question), 604800)
            for _ in range(3):
                self.controller.reconcile([('www.example.com', ip, 60)], question)
        self.controller.reconcile()
        self.assertEqual(len(self.backend.batches), batches)
        self.assertFalse(self.controller.seen)
        self.assertFalse(self.backend.lookups)
        self.assertEqual(self.backend.snapshots, 0)

    def test_fakeip_migration_removes_old_host_routes_and_preserves_real_leases(self):
        path = self.fakeip_controller(pools=False)
        for name, kind, ip in [('www.example.com', 1, '198.18.0.12'),
                               ('www.example.com', 28, '2001:2::12'),
                               ('real.example.com', 1, '198.51.100.12')]:
            self.controller.reconcile([(name, ip, 60)], (name, kind, 1))
        document = json.loads(path.read_text())
        for route in document['routes'][1:]:
            route['fakeip_range'] = '198.18.0.0/15' if route['name'] == 'fake4' else '2001:2::/48'
        path.write_text(json.dumps(document))
        self.controller = gate.Controller(sync, self.controller.config_path, lambda: [],
                                          self.controller.lease_path, lambda c: self.backend,
                                          domain_routes_path=path)
        self.controller.reconcile()
        self.assertEqual(set(self.backend.live), {(0, '198.18.0.0/15'), (0, '2001:2::/48'),
                                                  (0, '198.51.100.12/32')})
        self.assertEqual({key[1] for key in self.controller.seen}, {'198.51.100.12/32'})
        self.assertTrue(all('ip route add' in line for line in self.backend.batches[-2]))
        self.assertTrue(all('ip route del' in line for line in self.backend.batches[-1]))

    def test_fakeip_pool_install_failure_retries_and_vpp_restart_restores_pools(self):
        self.fakeip_controller()
        records, question = [('www.example.com', '198.18.0.12', 60)], ('www.example.com', 1, 1)
        self.backend.fail_after = 0
        with self.assertRaises(RuntimeError):
            self.controller.reconcile()
        self.assertFalse(self.backend.live)
        self.controller.reconcile()
        self.backend.instance = 'b' * 32
        self.backend.live.clear()
        self.controller.reconcile()
        self.controller.reconcile(records, question)
        self.assertEqual(len(self.backend.live), 2)

    def test_real_dns_domain_still_installs_host_route(self):
        self.fakeip_controller()
        self.controller.reconcile()
        question = ('real.example.com', 1, 1)
        self.assertIsNone(self.controller.dns_upstream(question))
        self.assertIsNone(self.controller.answer_ttl(question))
        self.controller.reconcile([('real.example.com', '198.51.100.12', 60)], question)
        self.assertIn((0, '198.51.100.12/32'), self.backend.live)
        self.assertTrue(self.controller.seen)

    def test_fakeip_pool_conflicting_exit_is_rejected(self):
        path = self.fakeip_controller()
        document = json.loads(path.read_text())
        document['routes'].append(dict(document['routes'][1], name='other', via='10.62.30.1', interface='wg1'))
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, 'different policies'):
            self.controller._load()

    def test_domain_list_updates_routes_without_nft(self):
        path, route = self.domain_routes_controller()
        self.controller.reconcile(self.records, self.question)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        route['domains'] = ['example.org']
        path.write_text(json.dumps({'routes': [route]}))
        os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000_000))
        self.controller.reconcile()
        self.assertNotIn((0, '198.51.100.77/32'), self.backend.live)
        self.controller.reconcile([('example.org', '198.51.100.88', 60)], ('example.org', 1, 1))
        self.assertIn((0, '198.51.100.88/32'), self.backend.live)
        self.assertEqual(self.backend.prefix_reads, 0)

    def test_domain_list_routes_cname_answer(self):
        self.domain_routes_controller(['example.net'])
        self.controller.reconcile([('outside.test', 'www.example.net', 60), *self.records],
                                  ('outside.test', 1, 1))
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)

    def test_domain_keyword_routes_and_selects_dns_upstream(self):
        path, route = self.domain_routes_controller()
        route.pop('domains')
        route['domain_keywords'] = ['demo-edge-node', 'dualstack.demo-edge']
        route['dns_upstream'] = ['127.0.0.1', 54]
        path.write_text(json.dumps({'routes': [route]}))
        question = ('foo.dualstack.demo-edge.example', 1, 1)
        records = [('foo.dualstack.demo-edge.example', '198.51.100.88', 60)]
        self.controller.reconcile(records, question)
        self.assertIn((0, '198.51.100.88/32'), self.backend.live)
        self.assertEqual(self.controller.dns_upstream(question), ('127.0.0.1', 54))
        self.assertIsNone(self.controller.dns_upstream(('example.org', 1, 1)))

    def test_first_dns_upstream_preserves_higher_priority_real_exit(self):
        path, route = self.domain_routes_controller()
        later = {**route, 'name': 'proxylist', 'interface': 'loop200',
                 'via': '10.61.20.2', 'dns_upstream': ['127.0.0.1', 5354]}
        path.write_text(json.dumps({'routes': [route, later]}))
        # Existing configurations retain their first-explicit-upstream behavior.
        self.assertEqual(self.controller.dns_upstream(self.question), ('127.0.0.1', 5354))
        config_path = Path(self.controller.config_path)
        config = json.loads(config_path.read_text())
        config['dns_upstream_policy'] = 'first'
        config_path.write_text(json.dumps(config))
        self.assertIsNone(self.controller.dns_upstream(self.question))
        # An IPv4-only exit does not take ownership of an AAAA lookup.
        later['name'] = 'proxylist6'
        later['via'] = 'fd42:1111:2222:10::2'
        path.write_text(json.dumps({'routes': [route, later]}))
        self.assertEqual(self.controller.dns_upstream(('www.example.net', 28, 1)),
                         ('127.0.0.1', 5354))

    def test_domain_file_hot_reload(self):
        path, route = self.domain_routes_controller()
        names = path.parent / 'altroute.domains'
        names.write_text('# research sites\nexample.net\n')
        route.pop('domains')
        route['domain_files'] = [names.name]
        path.write_text(json.dumps({'routes': [route]}))
        self.controller.reconcile(self.records, self.question)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        names.write_text('example.org # moved\n')
        os.utime(names, ns=(names.stat().st_atime_ns, names.stat().st_mtime_ns + 1_000_000_000))
        self.controller.reconcile()
        self.assertNotIn((0, '198.51.100.77/32'), self.backend.live)
        self.controller.reconcile([('example.org', '198.51.100.88', 60)], ('example.org', 1, 1))
        self.assertIn((0, '198.51.100.88/32'), self.backend.live)
        self.assertEqual(self.backend.prefix_reads, 0)

    def test_missing_domain_file_fails_closed(self):
        path, route = self.domain_routes_controller()
        route.pop('domains')
        route['domain_files'] = ['missing.domains']
        path.write_text(json.dumps({'routes': [route]}))
        with self.assertRaises(FileNotFoundError):
            self.controller.reconcile(self.records, self.question)

    def test_legacy_leases_survive_migration_until_domain_file_changes(self):
        self.controller.reconcile(self.records, self.question)
        path = Path(self.tmp.name) / 'domain-routes.json'
        route = {'name': 'altroute', 'interface': 'wg1', 'via': '10.62.30.1',
                 'domain_files': ['altroute.domains']}
        names = path.parent / 'altroute.domains'
        names.write_text('example.net\n')
        path.write_text(json.dumps({'routes': [route]}))
        self.controller = gate.Controller(sync, path.parent / 'config.json', lambda: [],
                                          path.parent / 'leases.json', lambda c: self.backend,
                                          domain_routes_path=path)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        self.controller.reconcile()
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        self.assertTrue(any(len(key) == 4 for key in self.controller.seen))
        self.controller = gate.Controller(sync, path.parent / 'config.json', lambda: [],
                                          path.parent / 'leases.json', lambda c: self.backend,
                                          domain_routes_path=path)
        self.controller.reconcile()
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)
        names.write_text('example.org\n')
        os.utime(names, ns=(names.stat().st_atime_ns, names.stat().st_mtime_ns + 1_000_000_000))
        self.controller.reconcile()
        self.assertNotIn((0, '198.51.100.77/32'), self.backend.live)

    def test_editing_one_domain_file_keeps_other_outlet_migration(self):
        root = Path(self.tmp.name)
        path = root / 'domain-routes.json'
        routes = [
            {'name': 'altroute', 'interface': 'wg1', 'via': '10.62.30.1',
             'domain_files': ['altroute.domains']},
            {'name': 'proxylist', 'interface': 'loop200', 'via': '10.61.20.2',
             'domain_files': ['proxylist.domains']},
        ]
        path.write_text(json.dumps({'routes': routes}))
        (root / 'altroute.domains').write_text('example.net\n')
        (root / 'proxylist.domains').write_text('example.org\n')
        (root / 'leases.json').write_text(json.dumps([
            {'mapping': ['inet', 'mangle', name], 'prefix': prefix, 'seen': int(time.time())}
            for name, prefix in [('altroute', '198.51.100.77/32'),
                                 ('proxylist', '198.51.100.88/32')]]))
        controller = gate.Controller(sync, root / 'config.json', lambda: [], root / 'leases.json',
                                     lambda c: self.backend, domain_routes_path=path)
        self.assertEqual(len(controller.seen), 2)
        (root / 'altroute.domains').write_text('new.example\n')
        controller._load()
        self.assertEqual({key[0][-1] for key in controller.seen}, {'proxylist'})

    def test_upgrade_converts_global_migration_hash(self):
        root = Path(self.tmp.name)
        path = root / 'domain-routes.json'
        path.write_text(json.dumps({'routes': [
            {'name': 'altroute', 'interface': 'wg1', 'via': '10.62.30.1',
             'domain_files': ['altroute.domains']},
        ]}))
        (root / 'altroute.domains').write_text('example.net\n')
        old_hash = gate.domain_source_hash([path, root / 'altroute.domains'])
        (root / 'leases.json').write_text(json.dumps([
            {'mapping': ['inet', 'dns_gate', 'altroute'], 'prefix': '198.51.100.77/32',
             'domain': '@legacy', 'source_hash': old_hash, 'seen': int(time.time())},
        ]))
        controller = gate.Controller(sync, root / 'config.json', lambda: [], root / 'leases.json',
                                     lambda c: self.backend, domain_routes_path=path)
        self.assertEqual(len(controller.seen), 1)
        self.assertNotEqual(next(iter(controller.seen))[3], old_hash)

    def test_multiple_domain_files_and_inline_domains(self):
        path, route = self.domain_routes_controller(['inline.example'])
        (path.parent / 'first.domains').write_text('example.net\n')
        (path.parent / 'second.domains').write_text('example.org\n')
        route['domain_files'] = ['first.domains', 'second.domains']
        path.write_text(json.dumps({'routes': [route]}))
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile([('example.org', '198.51.100.88', 60)], ('example.org', 1, 1))
        self.controller.reconcile([('inline.example', '198.51.100.99', 60)],
                                  ('inline.example', 1, 1))
        self.assertEqual(len(self.backend.live), 3)

    def test_domain_outlet_change_reconciles_existing_address(self):
        path, route = self.domain_routes_controller()
        self.controller.reconcile(self.records, self.question)
        route['via'] = '10.62.30.9'
        path.write_text(json.dumps({'routes': [route]}))
        os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000_000))
        self.controller.reconcile(force_audit=True)
        self.assertEqual(self.backend.live[(0, '198.51.100.77/32')],
                         frozenset({('10.62.30.9', 'wg1')}))

    def test_shared_address_stays_when_one_domain_is_removed(self):
        path, route = self.domain_routes_controller(['example.net', 'example.org'])
        self.controller.reconcile(self.records, self.question)
        self.controller.reconcile([('example.org', '198.51.100.77', 60)], ('example.org', 1, 1))
        route['domains'] = ['example.org']
        path.write_text(json.dumps({'routes': [route]}))
        os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000_000))
        self.controller.reconcile(force_audit=True)
        self.assertIn((0, '198.51.100.77/32'), self.backend.live)

    def test_invalid_domain_list_fails_closed_on_reload(self):
        path, _ = self.domain_routes_controller()
        path.write_text('{bad json')
        with self.assertRaises(json.JSONDecodeError):
            self.controller.reconcile(self.records, self.question)

    def test_empty_domain_rules_fail_closed(self):
        rules = Path(self.tmp.name) / 'rules.conf'
        rules.write_text('# no route rules\n')
        with self.assertRaisesRegex(ValueError, 'no enabled domain mappings'):
            self.controller.reconcile(self.records, self.question)

    def test_export_independent_domain_rules(self):
        root = Path(self.tmp.name)
        route_config = json.loads((root / 'config.json').read_text())
        route_config['mappings'].extend([
            {'family': 'inet', 'table': 'mangle', 'set': 'proxylist',
             'interface': 'tap2490', 'via': '10.63.30.2'},
            {'family': 'inet', 'table': 'mangle', 'set': 'proxylist6',
             'interface': 'tap2490', 'via': 'fd42:1111:2222:30::2'}])
        (root / 'config.json').write_text(json.dumps(route_config))
        with (root / 'rules.conf').open('a') as source:
            source.write('nftset=/shared.example/4#inet#mangle#proxylist,6#inet#mangle#proxylist6\n'
                         'nftset=/extra.example/4#inet#mangle#proxylist\n')
        gate_config = root / 'gate.json'
        gate_config.write_text(json.dumps({
            'sync_program': str(Path(__file__).parents[2] / 'tools/nftset-route-sync.py'),
            'route_config': str(root / 'config.json'),
            'legacy_rules_directory': str(root),
        }))
        exported = root / 'exported' / 'domains.json'
        result = subprocess.run([sys.executable, str(Path(gate.__file__)),
                                 '--config', str(gate_config), '--export-domain-routes', str(exported)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        routes = json.loads(exported.read_text())['routes']
        self.assertEqual(routes[0]['name'], 'altroute')
        self.assertEqual(routes[0]['domain_files'], ['altroute.domains'])
        self.assertEqual((exported.parent / 'altroute.domains').read_text(), 'example.net\n')
        self.assertEqual(routes[0]['via'], '10.62.30.1')
        self.assertEqual([r['domain_files'] for r in routes[1:]],
                         [['tproxy.domains'], ['tproxy.domains']])
        self.assertEqual((exported.parent / 'tproxy.domains').read_text(),
                         'extra.example\nshared.example\n')
        self.assertFalse((exported.parent / 'proxylist.domains').exists())
        self.assertFalse((exported.parent / 'proxylist6.domains').exists())
        loaded = sync.load_config(root / 'config.json')
        self.assertEqual(gate.domain_routes_from_file(exported, loaded, sync)[0][0], 'example.net')

    def test_rules_reload_error_does_not_release_without_match(self):
        self.controller.reconcile(self.records, self.question)
        rules = Path(self.tmp.name) / 'rules.conf'
        rules.write_text('nftset=broken\n')
        os.utime(rules, (rules.stat().st_mtime + 2, rules.stat().st_mtime + 2))
        with self.assertRaises(ValueError):
            self.controller.reconcile(self.records, self.question)
        with self.assertRaises(ValueError):
            self.controller.reconcile(self.records, self.question)
        rules.write_text('nftset=/example.net/4#inet#mangle#altroute\n')
        os.utime(rules, (rules.stat().st_mtime + 4, rules.stat().st_mtime + 4))
        self.controller.reconcile(self.records, self.question)


class WireTests(unittest.TestCase):
    def test_fakeip_ttl_override_preserves_opt_and_real_answer_ttl(self):
        answer = bytearray(packet(True))
        struct.pack_into('!H', answer, 10, 1)
        opt = b'\0' + struct.pack('!HHIH', 41, 1232, 0x8000, 0)
        answer = bytes(answer) + opt
        changed = gate.strip_https_h3(answer, address_ttl=604800)
        self.assertEqual(gate.decode(changed)[3], [('www.example.net', '198.51.100.77', 604800)])
        self.assertTrue(changed.endswith(opt))
        self.assertEqual(len(changed), len(answer))
        self.assertEqual(gate.strip_https_h3(answer), answer)

    def test_compressed_answer(self):
        self.assertEqual(gate.decode(packet(True))[3], [('www.example.net', '198.51.100.77', 60)])

    def test_pointer_loop_rejected(self):
        with self.assertRaises(ValueError):
            gate.name_at(b'\xc0\x00', 0)

    def test_servfail_carries_no_addresses(self):
        answer = gate.servfail(packet())
        self.assertEqual(gate.decode(answer)[1] & 15, 2)
        self.assertEqual(gate.decode(answer)[3], [])

    def test_https_hints_parsed(self):
        q = packet()[12:]
        data = struct.pack('!H', 1) + b'\0' + struct.pack('!HH', 4, 4) + socket.inet_aton('198.51.100.77')
        rr = b'\xc0\x0c' + struct.pack('!HHIH', 65, 1, 60, len(data)) + data
        answer = struct.pack('!6H', 123, 0x8180, 1, 1, 0, 0) + q + rr
        self.assertIn(('www.example.net', '198.51.100.77', 60), gate.decode(answer)[3])

    def _https_answer(self, alpns, extra=b''):
        encoded = b''.join(bytes([len(item)]) + item for item in alpns)
        data = struct.pack('!H', 1) + b'\0' + struct.pack('!HH', 1, len(encoded)) + encoded + extra
        q = packet()[12:]
        rr = b'\xc0\x0c' + struct.pack('!HHIH', 65, 1, 3600, len(data)) + data
        return struct.pack('!6H', 123, 0x8180, 1, 1, 0, 0) + q + rr

    def _https_alpns(self, packet):
        _, offset = gate.name_at(packet, 12)
        offset += 4
        _, offset = gate.name_at(packet, offset)
        kind, cls, ttl, length = struct.unpack_from('!HHIH', packet, offset)
        offset += 10
        self.assertEqual((kind, cls), (65, 1))
        _, pos = gate.name_at(packet, offset + 2)
        alpns = []
        end = offset + length
        while pos < end:
            key, size = struct.unpack_from('!HH', packet, pos)
            pos += 4
            value = packet[pos:pos + size]
            pos += size
            if key != 1:
                continue
            cursor = 0
            while cursor < len(value):
                ident_size = value[cursor]
                cursor += 1
                alpns.append(value[cursor:cursor + ident_size])
                cursor += ident_size
        return alpns

    def test_https_alpn_drops_h3_keeps_h2(self):
        answer = self._https_answer([b'h2', b'h3'])
        stripped = gate.strip_https_h3(answer)
        self.assertEqual(self._https_alpns(stripped), [b'h2'])
        self.assertEqual(gate.strip_https_h3(stripped), stripped)
        _, offset = gate.name_at(stripped, 12)
        offset += 4
        _, offset = gate.name_at(stripped, offset)
        _, _, ttl, _ = struct.unpack_from('!HHIH', stripped, offset)
        self.assertEqual(ttl, 60)

    def test_https_alpn_h3_only_becomes_h2(self):
        stripped = gate.strip_https_h3(self._https_answer([b'h3', b'h3-29']))
        self.assertEqual(self._https_alpns(stripped), [b'h2'])

    def test_https_strip_keeps_address_hints(self):
        extra = struct.pack('!HH', 4, 4) + socket.inet_aton('198.51.100.77')
        answer = self._https_answer([b'h2', b'h3'], extra)
        stripped = gate.strip_https_h3(answer)
        self.assertEqual(self._https_alpns(stripped), [b'h2'])
        self.assertIn(('www.example.net', '198.51.100.77', 60), gate.decode(stripped)[3])

    def test_https_strip_leaves_a_records_alone(self):
        reply = packet(True)
        self.assertEqual(gate.strip_https_h3(reply), reply)

    def test_udp_and_tcp_withhold_until_ack_and_fail_closed(self):
        for tcp in (False, True):
            for failure in (False, True):
                with self.subTest(tcp=tcp, failure=failure):
                    ready, release = threading.Event(), threading.Event()
                    class Controller:
                        def reconcile(self, *args):
                            ready.set()
                            if not release.wait(2):
                                raise RuntimeError('test timed out')
                            if failure:
                                raise RuntimeError('route installation failed')
                    kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
                    with socket.socket(socket.AF_INET, kind) as upstream:
                        upstream.bind(('127.0.0.1', 0))
                        if tcp:
                            upstream.listen()
                        def answer():
                            if tcp:
                                conn, _ = upstream.accept()
                                with conn:
                                    size = struct.unpack('!H', gate.read_exact(conn, 2))[0]
                                    gate.read_exact(conn, size)
                                    response = packet(True)
                                    conn.sendall(struct.pack('!H', len(response)) + response)
                            else:
                                _, peer = upstream.recvfrom(4096)
                                upstream.sendto(packet(True), peer)
                        producer = threading.Thread(target=answer)
                        producer.start()
                        proxy = gate.Gate(Controller(), upstream.getsockname())
                        results = []
                        worker = threading.Thread(target=lambda: results.append(proxy.exchange(packet(), tcp)))
                        worker.start()
                        self.assertTrue(ready.wait(2))
                        time.sleep(0.05)
                        self.assertEqual(results, [], 'answer escaped before route ACK')
                        release.set()
                        worker.join(3)
                        producer.join(3)
                        self.assertEqual(gate.decode(results[0])[1] & 15, 2 if failure else 0)


if __name__ == '__main__':
    unittest.main()
