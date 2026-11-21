import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location('tproxy_path', ROOT/'deploy/tproxy-path.py')
tp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tp)


class TproxyPathTests(unittest.TestCase):
    def test_only_proxy_tap_is_intercepted_and_fake_ula_precedes_private_return(self):
        rules = tp.nft_proxy_rules()
        self.assertNotIn('br-mgmt', rules)
        self.assertLess(rules.index('2001:2::/48'), rules.index('ip6 daddr fc00::/7'))
        self.assertIn('ct mark 1 ct direction reply', rules)
        self.assertIn('vrouter_proxy_guard iifname "vpp-tproxy" counter drop', rules)

    def test_host_setup_is_idempotent_and_refuses_foreign_routes(self):
        calls = []
        policy = []
        routes = []

        def run(*args):
            calls.append(args)
            if args[:2] == ('ip', '-j'):
                return json.dumps(policy if 'rule' in args else routes)
            return ''

        tp.host(run)
        self.assertEqual(sum('add' in c and 'rule' in c for c in calls), 2)
        policy.append(dict(priority=105, fwmark=tp.MARK, fwmask=tp.MARK, table=2490))
        calls.clear()
        tp.host(run)
        self.assertFalse(any('add' in c and 'rule' in c for c in calls))
        routes.append(dict(table=2490, dst='default', gateway='192.0.2.1', dev='foreign'))
        with self.assertRaisesRegex(ValueError, 'table 2490'):
            tp.host(run)
        routes.clear()
        policy[0]['fwmark'] = '0x1'
        with self.assertRaisesRegex(ValueError, 'priority 105'):
            tp.host(run)


if __name__ == '__main__':
    unittest.main()
