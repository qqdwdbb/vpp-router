import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).parents[2]/'deploy/host-services'
spec = importlib.util.spec_from_file_location('host_routing', ROOT/'host-routing.py')
routing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routing)


class HostRoutingTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT/'services.json').read_text())
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.journal = Path(self.directory.name)/'routing.json'

    def execute(self, policy=(), routes=()):
        def result(*args, **kwargs):
            if args[:3] == ('ip', '-j', '-4'):
                return json.dumps(policy if args[3] == 'rule' else routes)
            return ''
        return Mock(side_effect=result)

    def route_rows(self):
        return [dict(type='unreachable', dst='default', metric=32767, table=2480),
                dict(dst='default', gateway='10.63.20.1', dev='vpp-hostsvc',
                     prefsrc='10.61.20.2', metric=100, table=2480)]

    def test_inbound_forces_tap_but_outbound_preserves_specific_main_routes(self):
        inbound, specific, fallback = routing.rules()
        self.assertEqual(inbound['table'], 2480)
        self.assertNotEqual(inbound['fwmark'], fallback['fwmark'])
        self.assertEqual(specific['table'], 'main')
        self.assertEqual(specific['suppress_prefixlen'], 0)
        self.assertLess(specific['priority'], fallback['priority'])
        self.assertEqual(fallback['table'], 2480)

    def test_reserved_priority_or_table_rejected_before_mutation(self):
        for policy, routes in (([dict(priority=90)], []),
                               ([dict(priority=500, table=2480)], []),
                               ([], [dict(table=2480)])):
            with self.subTest(policy=policy, routes=routes):
                execute = self.execute(policy, routes)
                with self.assertRaises(ValueError):
                    routing.install(self.config, execute, self.journal)
                self.assertFalse(self.journal.exists())
                self.assertEqual(execute.call_count, 2)

    def test_journal_precedes_mutations_and_routes_precede_rules(self):
        execute = self.execute()
        original = execute.side_effect
        def result(*args, **kwargs):
            if args[:3] != ('ip', '-j', '-4'):
                self.assertTrue(self.journal.exists())
            return original(*args, **kwargs)
        execute.side_effect = result
        routing.install(self.config, execute, self.journal)
        mutations = [call.args for call in execute.call_args_list[2:]]
        self.assertEqual([call[2:4] for call in mutations],
                         [('route', 'replace')]*2+[('rule', 'add')]*3)
        self.assertIn('unreachable', mutations[0])
        self.assertIn('10.63.20.1', mutations[1])

    def test_restart_does_not_duplicate_rules(self):
        self.journal.write_text(json.dumps(routing.route_plan(self.config)))
        # iproute2 may render marks as decimal and the main table numerically.
        policy = [dict(rule, src='all', fwmark=routing.number(rule['fwmark']),
                       fwmask=routing.number(rule['fwmask'])) for rule in routing.rules()]
        policy[1]['table'] = 254
        execute = self.execute(policy, self.route_rows())
        routing.install(self.config, execute, self.journal)
        self.assertFalse(any(call.args[2:4] == ('rule', 'add') for call in execute.call_args_list))

    def test_boot_preserves_legacy_routing_priorities(self):
        self.journal.write_text(json.dumps(routing.route_plan(self.config)))
        policy = [dict(priority=101, src='all', fwmark='0x4', table='uk'),
                  dict(priority=102, src='all', fwmark='0x3', table='altroute')]
        execute = self.execute(policy)
        routing.install(self.config, execute, self.journal)
        changes = [call.args for call in execute.call_args_list[2:]]
        self.assertEqual(sum(call[2:4] == ('rule', 'add') for call in changes), 3)
        self.assertFalse(any(call[2:4] == ('rule', 'del') for call in changes))

    def test_failed_install_keeps_journal_for_partial_recovery(self):
        execute = self.execute()
        original = execute.side_effect
        def result(*args, **kwargs):
            if args[2:4] == ('rule', 'add'):
                raise RuntimeError('simulated rule installation failure')
            return original(*args, **kwargs)
        execute.side_effect = result
        with self.assertRaises(RuntimeError):
            routing.install(self.config, execute, self.journal)
        self.assertEqual(json.loads(self.journal.read_text()), routing.route_plan(self.config))
        cleanup = self.execute(routes=self.route_rows())
        routing.remove(cleanup, self.journal)
        self.assertEqual(sum(call.args[2:4] == ('route', 'del') for call in cleanup.call_args_list), 2)
        self.assertFalse(self.journal.exists())

    def test_restart_rejects_foreign_replacement(self):
        self.journal.write_text(json.dumps(routing.route_plan(self.config)))
        for policy, routes in (([dict(priority=90, table='main')], []),
                               ([], [dict(table=2480, dst='203.0.113.0/24')])):
            with self.subTest(policy=policy):
                execute = self.execute(policy, routes)
                with self.assertRaises(ValueError):
                    routing.install(self.config, execute, self.journal)
                self.assertEqual(execute.call_count, 2)

    def test_partial_startup_cleanup_removes_only_owned_objects(self):
        self.journal.write_text(json.dumps(routing.route_plan(self.config)))
        policy = [routing.rules()[0], dict(priority=91, table='vpn')]
        routes = self.route_rows()[:1]+[dict(table=2480, dst='203.0.113.0/24')]
        execute = self.execute(policy, routes)
        routing.remove(execute, self.journal)
        changes = [call.args for call in execute.call_args_list[2:]]
        self.assertEqual(len(changes), 2)
        self.assertEqual(changes[0], ('ip', '-4', 'rule', 'del', *routing.rule_args(routing.rules()[0])))
        self.assertIn('unreachable', changes[1])
        self.assertFalse(self.journal.exists())

    def test_missing_journal_never_deletes_rules(self):
        execute = self.execute()
        routing.remove(execute, self.journal)
        execute.assert_not_called()

    def test_backend_peer_and_source_follow_configuration(self):
        self.config.update(wan_backend='172.30.10.2', host='192.168.3.2')
        route = routing.route_plan(self.config)[1]
        self.assertIn('172.30.10.1', route)
        self.assertIn('192.168.3.2', route)
        self.config['wan_backend'] = '172.30.10.1'
        with self.assertRaises(ValueError):
            routing.route_plan(self.config)


if __name__ == '__main__':
    unittest.main()
