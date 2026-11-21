import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('sync', Path(__file__).parents[2] / 'tools/napt66-sync.py')
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class SyncTests(unittest.TestCase):
    def test_multi_inside_missing_wireguard_and_recovery(self):
        config = dict(outside='wan', insides=[dict(interface='lan', prefix='fd00::/64'),
                                             dict(interface='wg100', prefix='fd42:1111:2222:90::/64')])
        sync.validate(config)
        commands = []
        wg = False
        def cli(command):
            if command == 'show interface address':
                return 'wan (up):\n L3 2001:db8::1/64\nlan (up):\n' + ('wg100 (up):\n' if wg else '')
            if command == 'show napt66': return 'NAPT66 enabled, sessions 5/16384'
            if command.startswith('show interface features'): return '  napt66\n'
            commands.append(command)
            return ''
        old = sync.reconcile(config, {}, 'run1', cli)
        self.assertEqual(old['insides'], config['insides'][:1])
        self.assertNotIn('wg100', commands[-1])
        wg = True
        old = sync.reconcile(config, old, 'run1', cli)
        self.assertIn('inside lan prefix fd00::/64 inside wg100 prefix fd42:1111:2222:90::/64', commands[-1])
        commands.clear()
        self.assertEqual(sync.reconcile(config, old, 'run1', cli), old)
        self.assertEqual(commands, [])
        wg = False
        sync.reconcile(config, old, 'run1', cli)
        self.assertNotEqual(commands, ['napt66 disable'])
        self.assertIn('inside lan', commands[-1])

    def test_rejects_overlaps_and_duplicate_interfaces(self):
        for second in [dict(interface='wg100', prefix='fd00::/65'),
                       dict(interface='lan', prefix='fd42:1111:2222:90::/64'),
                       dict(interface='wan', prefix='fd42:1111:2222:90::/64')]:
            with self.assertRaises(ValueError):
                sync.validate(dict(outside='wan', insides=[dict(interface='lan', prefix='fd00::/64'), second]))

    def test_address_change_restart_and_idempotence(self):
        config = dict(inside='wg100', outside='port0.100', prefix='fd42:1111:2222:90::/64')
        address = '2001:db8::1'
        commands = []
        def cli(command):
            if command == 'show interface address':
                return f'wg100 (up):\n L3 fd42:1111:2222:90::1/64\nport0.100 (up):\n L3 fe80::1/64\n L3 {address}/64\n'
            if command == 'show napt66':
                return 'NAPT66 enabled, sessions 5/16384'
            if command.startswith('show interface features'):
                return 'ip6-unicast:\n  napt66\n'
            commands.append(command)
            return ''
        old = sync.reconcile(config, {}, 'run1', cli)
        self.assertEqual(len(commands), 1)
        commands.clear()
        self.assertEqual(sync.reconcile(config, old, 'run1', cli), old)
        self.assertEqual(commands, [])
        address = '2001:db8:1::1'
        updated = sync.reconcile(config, old, 'run1', cli)
        self.assertEqual(updated['external'], address)
        self.assertIn('external ' + address, commands[-1])
        commands.clear()
        sync.reconcile(config, updated, 'run2', cli)
        self.assertEqual(len(commands), 1)

    def test_address_withdrawal_and_missing_wireguard(self):
        for display in ('wg100 (up):\nport0.100 (up):\n L3 fe80::1/64\n',
                        'port0.100 (up):\n L3 2001:db8::1/64\n'):
            commands = []
            def cli(command):
                if command == 'show interface address': return display
                if command == 'show napt66': return 'NAPT66 enabled, sessions 5/16384'
                commands.append(command)
                return ''
            self.assertEqual(sync.reconcile(dict(inside='wg100', outside='port0.100',
                prefix='fd42:1111:2222:90::/64'), {}, 'run1', cli), {})
            self.assertEqual(commands, ['napt66 disable'])

    def test_retains_existing_address_during_overlap(self):
        config = dict(inside='wg100', outside='port0.100', prefix='fd42:1111:2222:90::/64')
        old = dict(config, external='2001:db8::2', generation='run1')
        def cli(command):
            if command == 'show interface address':
                return 'wg100 (up):\nport0.100 (up):\n L3 2001:db8::1/64\n L3 2001:db8::2/64\n'
            if command == 'show napt66': return 'NAPT66 enabled, sessions 5/16384'
            if command.startswith('show interface features'): return '  napt66\n'
            self.fail('unnecessary session reset')
        self.assertEqual(sync.reconcile(config, old, 'run1', cli), old)
