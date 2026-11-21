import json
import ipaddress
import random
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch

from test_nftset_route_sync import FakeBackend, sync


class FastPathTests(unittest.TestCase):
    def test_prefix_index_matches_linear_containment_for_both_families_and_tables(self):
        randomizer = random.Random(17)
        index, entries = sync.PrefixIndex(), []
        for version, bits in ((4, 32), (6, 128)):
            cls = ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network
            for position in range(300):
                network = cls((randomizer.getrandbits(bits), randomizer.randrange(bits + 1)), strict=False)
                table = position % 3
                index.add(network, position, table)
                entries.append((network, position, table))
            for _ in range(100):
                host = cls((randomizer.getrandbits(bits), bits))
                for table in range(3):
                    expected = {value for prefix, value, fib in entries
                                if fib == table and prefix.version == version and host.subnet_of(prefix)}
                    self.assertEqual(set(index.covering(host, table)), expected)

    def test_static_index_preserves_first_policy_over_more_specific_host(self):
        for prefix, host, via1, via2 in [
                ('198.51.100.0/24', '198.51.100.77/32', '10.0.0.1', '10.0.1.1'),
                ('2001:db8::/64', '2001:db8::77/128', '2001:db8:1::1', '2001:db8:2::1')]:
            mappings = [{'family': 'inet', 'table': 'mangle', 'set': name,
                         'fib_table': 0, 'via': via, 'interface': name}
                        for name, via in [('early', via1), ('late', via2)]]
            key = sync._mapping_key(mappings[0])
            config = {'mappings': mappings, 'exclude_prefixes': [], '_static_prefixes': {key: {prefix}}}
            request = sync.Route(0, host, via2, 'late')
            self.assertEqual(sync._ordered_winners(config, [request], {}),
                             [sync.Route(0, prefix, via1, 'early')])
            # Replacing a rules snapshot must replace its index too.
            config['_static_prefixes'] = {}
            self.assertEqual(sync._ordered_winners(config, [request], {}), [request])

    def test_indexed_hosts_keep_priority_and_flush_without_bulk_query_work(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            config_path = Path(directory) / 'config.json'
            config_path.write_text(json.dumps({'state_file': str(path), 'lock_files': [],
                'overlap_policy': 'first', 'mappings': [
                    {'family': 'inet', 'table': 'mangle', 'set': 'early', 'via': '10.0.0.1', 'interface': 'wg1'},
                    {'family': 'inet', 'table': 'mangle', 'set': 'late', 'via': '10.0.1.1', 'interface': 'wg2'}]}))
            config = sync.load_config(config_path)
            backend = FakeBackend()
            ancestor = sync.Route(0, '198.51.100.0/24', '10.0.0.1', 'wg1')
            request = sync.Route(0, '198.51.100.77/32', '10.0.1.1', 'wg2')
            with sync.DeferredState([path]) as store:
                store.write(path, {'version': 1, 'generation': backend.instance,
                                   'owned': [sync.asdict(ancestor)], 'pending_add': []})
                with store.lock:
                    store.ledger(path, backend.instance)
                with patch.object(sync, 'asdict', side_effect=AssertionError('bulk serialization')), \
                     patch.object(sync.copy, 'deepcopy', side_effect=AssertionError('bulk copy')):
                    result = sync.ensure_routes(config, backend, [request])
                    sync.ensure_routes(config, backend, [request])
                self.assertEqual(result['winners'], [ancestor])
                self.assertFalse(backend.lookups)
                self.assertFalse(path.exists())
                snapshot = store.read(path, {})
                self.assertEqual(snapshot['owned'], [sync.asdict(ancestor)])
                # A background replacement invalidates the cached index.
                snapshot['owned'] = []
                store.write(path, snapshot)
                self.assertEqual(sync.ensure_routes(config, backend, [request])['winners'], [request])
            self.assertEqual(json.loads(path.read_text())['owned'], [sync.asdict(request)])

    def test_indexed_api_failure_keeps_pending_without_claiming_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            route = sync.Route(0, '2001:db8::1/128', '2001:db8::2', 'wg1')
            config = {'state_file': str(path), 'max_routes': 100, 'overlap_policy': 'first',
                      'exclude_prefixes': [], 'mappings': [
                          {'family': 'inet', 'table': 'mangle', 'set': 'v6', 'enabled': True,
                           'fib_table': 0, 'via': route.via, 'interface': route.interface}]}
            backend = FakeBackend()
            with sync.DeferredState([path]) as store:
                with patch.object(backend, 'apply', side_effect=RuntimeError('API failed')):
                    with self.assertRaisesRegex(RuntimeError, 'API failed'):
                        sync.ensure_routes(config, backend, [route])
                state = store.read(path, {})
                self.assertEqual(state['owned'], [])
                self.assertEqual(state['pending_add'], [sync.asdict(route)])
                sync.ensure_routes(config, backend, [route])
                self.assertEqual(store.read(path, {})['pending_add'], [])

    def test_deferred_reads_see_unflushed_state_and_exit_flushes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            with sync.DeferredState([path]):
                sync.atomic_json(path, {'owned': [1]})
                time.sleep(1.1)
                self.assertFalse(path.exists())
                value = sync.read_json(path, {})
                value['owned'].append(2)
                self.assertEqual(sync.read_json(path, {}), {'owned': [1]})
            self.assertEqual(json.loads(path.read_text()), {'owned': [1]})

    def test_failed_flush_retains_dirty_state(self):
        store = sync.DeferredState(['/unused/state.json'])
        store.write('/unused/state.json', {'owned': [1]})
        with patch.object(sync, 'durable_json', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                store.flush()
        self.assertIn('/unused/state.json', store.dirty)

    def test_importer_reads_memory_ledger_before_shutdown_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {'state_file': str(Path(directory) / 'state.json'),
                      'state_socket': str(Path(directory) / 'state.sock')}
            with sync.DeferredState([config['state_file']]), sync.StateServer(config):
                state = {'version': 1, 'owned': [{'prefix': '198.51.100.77/32'}]}
                sync.atomic_json(config['state_file'], state)
                self.assertFalse(Path(config['state_file']).exists())
                self.assertEqual(sync.importer_state(config), state)
            self.assertEqual(sync.importer_state(config), state)

    def test_generation_cached_until_socket_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cli.sock'
            path.touch()
            backend = sync.Backend({'vpp_socket': str(path), 'vpp_service': 'vpp'})
            ret_a = 'InvocationID=' + 'a' * 32 + '\nMainPID=123\nActiveState=active\n'
            ret_b = 'InvocationID=' + 'b' * 32 + '\nMainPID=124\nActiveState=active\n'
            with patch.object(backend, 'run', side_effect=[ret_a, ret_b]) as run, \
                 patch.object(sync.Backend, '_process_identity', return_value='start-1'):
                self.assertEqual(backend.generation(), 'a' * 32)
                self.assertEqual(backend.generation(), 'a' * 32)
                self.assertEqual(run.call_count, 1)
                path.unlink()
                path.touch()
                self.assertEqual(backend.generation(), 'b' * 32)

    def test_api_retval_error_invalidates_cached_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'api.sock'
            path.touch()
            client = SimpleNamespace(api=SimpleNamespace(
                fib_source_dump=lambda: [SimpleNamespace(src=SimpleNamespace(name='CLI', id=9))],
                sw_interface_dump=lambda: [SimpleNamespace(interface_name='wg1', sw_if_index=4)],
                ip_route_add_del_v2=lambda **kwargs: SimpleNamespace(retval=-1)),
                connect=lambda name: None, disconnect=lambda: None)
            backend = sync.Backend({'api_socket': str(path), 'lock_files': []})
            with patch.dict('sys.modules', {'vpp_papi': SimpleNamespace(VPPApiClient=lambda **kw: client)}):
                with patch.object(sync.Backend, '_api_client', None), patch.object(sync.Backend, '_api_identity', None):
                    with self.assertRaisesRegex(RuntimeError, 'API failed'):
                        backend.apply(['ip route add 198.51.100.77/32 table 0 via 10.62.30.1 wg1'])
                    self.assertIsNone(sync.Backend._api_identity)


if __name__ == '__main__':
    unittest.main()
