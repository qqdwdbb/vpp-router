import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).parents[2]/'deploy/policy-routing/source-routes.py'
spec = importlib.util.spec_from_file_location('source_routes', path)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

class SourceRouteTests(unittest.TestCase):
    def test_delegated_lan_is_excluded_before_source_match(self):
        text = policy.rules({'via':'2001:db8:20::1', 'sources':['fd42:1111:2222:70::/64'],
                             'exclude_lan_interface':'loop0', 'exclude_destinations':['fc00::/7']},
                            'loop0 (up):\n L3 2001:db8:123::1/64\n')
        self.assertLess(text.index('dst 2001:db8:123::/64'), text.index('permit src fd42:1111:2222:70::/64'))

    def test_existing_policy_does_not_append_another_next_hop(self):
        calls = []
        def cli(text):
            calls.append(text)
            if text == 'show interface address': return 'loop10 (up):\nwg8 (up):\n'
            if text == 'show acl-plugin acl': return 'acl-index 7 count 1 tag {source-route-vpn4}\n'
            if text == 'show abf policy': return 'abf:[0]: policy:620 acl:7\n'
            if text == 'show abf attach wg8': return 'policy:620 priority:0\n'
            if text.startswith('set acl-plugin'): return 'ACL index: 7\n'
            raise AssertionError(text)
        config={'policies':[dict(id=620,name='vpn4',sources=['10.62.40.0/24'],
                                via='10.61.50.1',output_interface='loop10',interfaces=['wg8'])]}
        saved=policy.reconcile(config,{},cli)
        policy.reconcile(config,saved,cli)
        self.assertFalse(any(text.startswith('abf policy add') for text in calls))

    def test_reconcile_runs_only_when_inputs_change(self):
        now = [0.0]
        watcher = policy.Watcher(resync=300, clock=lambda: now[0])
        inputs = ('config', (1, 2), 'wg8 (up):\n')
        self.assertTrue(watcher.due(inputs))
        watcher.done(inputs)
        now[0] = 2
        self.assertFalse(watcher.due(inputs))
        self.assertTrue(watcher.due(('config', (1, 2), 'wg8 (up):\nwg9 (up):\n')))
        self.assertTrue(watcher.due(('config', (3, 4), 'wg8 (up):\n')))
        now[0] = 300
        self.assertTrue(watcher.due(inputs))

    def test_failed_reconcile_is_retried(self):
        watcher = policy.Watcher(resync=300, clock=lambda: 0.0)
        inputs = ('config', (1, 2), '')
        watcher.done(inputs)
        watcher.failed()
        self.assertTrue(watcher.due(inputs))

    def test_mixed_address_families_are_rejected(self):
        with self.assertRaises(ValueError):
            policy.rules({'via':'10.61.50.1','sources':['fd42:1111:2222:70::/64']},'')
