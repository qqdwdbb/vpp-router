import copy
import importlib.util
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fakeip_prepare',
    Path(__file__).resolve().parents[2] / 'deploy/fakeip/prepare.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class FakeIPTests(unittest.TestCase):
    def native_module(self):
        spec = importlib.util.spec_from_file_location('fakeip_native',
            Path(__file__).resolve().parents[2] / 'deploy/fakeip/native.py')
        module = importlib.util.module_from_spec(spec)
        with patch.dict('sys.modules', {'prepare': m}):
            spec.loader.exec_module(module)
        return module

    def test_migration_preserves_dns_cache_and_unrelated_supervisor_settings(self):
        native = self.native_module()
        original = m.frontend({'type': 'socks', 'tag': 'old-out',
            'server': '127.0.0.1', 'server_port': 1080}, ['wg.example.com'],
            legacy_listeners=False)
        trojan = {'run_type': 'client', 'local_addr': '0.0.0.0', 'local_port': 1080,
                  'remote_addr': '127.0.0.1', 'remote_port': 1443, 'password': 'test',
                  'ssl': {'sni': 'proxy.example.com'}}
        changed = native.native_config(original, trojan)
        self.assertEqual(changed['dns'], original['dns'])
        self.assertEqual(changed['experimental'], original['experimental'])
        self.assertEqual(changed['outbounds'][0]['type'], 'trojan')
        self.assertEqual(original['outbounds'][0]['type'], 'socks')
        text = ('[program:trojan]\ncommand=/usr/bin/trojan config.json\n'
                'autostart=true\nautorestart=unexpected\n'
                '[program:other]\nautostart=true\n')
        disabled = native.disable_program(text, 'trojan')
        self.assertIn('command=/usr/bin/trojan config.json', disabled)
        self.assertIn('autostart=false\nautorestart=false', disabled)
        self.assertTrue(disabled.endswith('[program:other]\nautostart=true\n'))

    def test_infrastructure_endpoints_are_extracted_without_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'wg2.conf').write_text('[Interface]\nPrivateKey = secret\n'
                '[Peer]\nEndpoint = uk.example.com:51820 # endpoint\n'
                'Endpoint = 127.0.0.1:44441\nEndpoint = [2001:db8::1]:1234\n')
            domains = m.wireguard_domains(root)
            self.assertEqual(domains, ['uk.example.com'])
            cfg = m.frontend({'type': 'trojan', 'tag': 'test-out'}, domains)
            self.assertEqual(cfg['dns']['rules'][0], {
                'domain': domains, 'action': 'route', 'server': 'auxiliary'})

    def test_native_trojan_import_and_listener_migration(self):
        config = {'run_type': 'client', 'remote_addr': '127.0.0.1', 'remote_port': 1443,
                  'password': ['test-password'], 'ssl': {'verify': True,
                  'verify_hostname': True, 'sni': 'proxy.example.com', 'alpn': ['http/1.1']}}
        outbound = m.trojan_outbound(config)
        self.assertEqual(outbound['password'], 'test-password')
        self.assertEqual(outbound['tls']['server_name'], 'proxy.example.com')
        self.assertFalse(outbound['tls']['insecure'])
        cfg = m.frontend(outbound)
        self.assertEqual(cfg['log'], {'level': 'error', 'timestamp': True})
        self.assertEqual([o['type'] for o in cfg['outbounds']], ['trojan'])
        self.assertEqual({i['listen_port'] for i in cfg['inbounds']}, {5354, 2082, 2080, 1080})
        self.assertEqual(cfg['experimental']['cache_file']['path'], '/var/lib/vrouter-fakeip/cache.db')
        config['ssl']['verify_hostname'] = False
        with self.assertRaisesRegex(ValueError, 'Partial TLS'):
            m.trojan_outbound(config)

    def test_only_plist_dns_and_reserved_pool_interception_change(self):
        domains = {'routes': [
            {'name': 'altroute', 'interface': 'wg1', 'via': '10.62.30.1'},
            {'name': 'proxylist', 'interface': 'tap2490', 'via': '10.63.30.2'},
            {'name': 'proxylist6', 'interface': 'tap2490', 'via': 'fd42:1111:2222:30::2'}]}
        routes = {'exclude_prefixes': ['192.168.0.0/16']}
        nft = (Path(__file__).resolve().parents[2] /
               'deploy/dns-route-gate/dns-route-gate.nft').read_text()
        original = copy.deepcopy(domains)
        changed, config, rules = m.configure(domains, routes, nft)
        self.assertEqual(domains, original)
        self.assertEqual(changed['routes'][0], domains['routes'][0])
        self.assertEqual(changed['routes'][1]['dns_upstream'], ['127.0.0.1', 5354])
        self.assertEqual(changed['routes'][1]['domain_files'], ['tproxy.domains'])
        self.assertEqual(changed['routes'][2]['domain_files'], ['tproxy.domains'])
        for item in domains['routes'][1:]:
            item['domain_files'] = ['gate/tproxy.domains']
        relocated, _, _ = m.configure(domains, routes, nft)
        self.assertEqual(relocated['routes'][1]['domain_files'], ['gate/tproxy.domains'])
        self.assertEqual(relocated['routes'][2]['domain_files'], ['gate/tproxy.domains'])
        self.assertEqual(changed['routes'][1]['fakeip_range'], '198.18.0.0/15')
        self.assertEqual(changed['routes'][1]['ip_range_files'], ['fakeip.ipv4'])
        self.assertEqual(changed['routes'][2]['fakeip_range'], '2001:2::/48')
        self.assertEqual(changed['routes'][2]['ip_range_files'], ['fakeip.ipv6'])
        self.assertEqual(config['dns_upstream_policy'], 'first')
        self.assertLess(rules.index('udp udp dport 443'), rules.index('# BEGIN VROUTER Fake-IP'))
        self.assertLess(rules.index('to :2082'), rules.index('to :2080'))
        self.assertLess(rules.index('to :2082'), rules.index('ip6 daddr fc00::/7'))
        self.assertNotIn('iifname "br-mgmt" meta nfproto', rules)
        for prefix in ('198.18.0.0/16', '2001:2::/32'):
            with self.assertRaisesRegex(ValueError, 'overlaps exclusion'):
                m.configure(domains, {'exclude_prefixes': [prefix]}, nft)

    def test_prepare_moves_selected_routes_to_fakeip_pools(self):
        domains = {'routes': [
            {'name': 'proxylist', 'interface': 'tap2490', 'via': '10.63.30.2'},
            {'name': 'proxylist6', 'interface': 'tap2490', 'via': 'fd42:1111:2222:30::2'},
            {'name': 'sample-edge', 'interface': 'loop10', 'via': '10.61.50.1',
             'domain_keywords': ['demo-edge-node', 'dualstack.demo-edge'],
             'dns_upstream': ['127.0.0.1', 54]},
            {'name': 'sample-edge6', 'interface': 'loop10',
             'via': 'fd42:1111:2222:20::1',
             'domain_keywords': ['demo-edge-node', 'dualstack.demo-edge'],
             'dns_upstream': ['127.0.0.1', 54]}]}
        routes = {'exclude_prefixes': []}
        nft = (Path(__file__).resolve().parents[2] /
               'deploy/dns-route-gate/dns-route-gate.nft').read_text()
        unchanged, _, _ = m.configure(domains, routes, nft)
        self.assertEqual(unchanged['routes'][2:], domains['routes'][2:])
        with self.assertRaisesRegex(ValueError, 'Expected one additional DNS route'):
            m.configure(domains, routes, nft, extra_ipv4_rule='missing')
        with self.assertRaisesRegex(ValueError, 'Unexpected address family'):
            m.configure(domains, routes, nft, extra_ipv4_rule='sample-edge6')
        changed, _, _ = m.configure(domains, routes, nft,
                                     extra_ipv4_rule='sample-edge', extra_ipv6_rule='sample-edge6')
        by_name = {r['name']: r for r in changed['routes']}
        self.assertEqual(by_name['sample-edge']['interface'], 'tap2490')
        self.assertEqual(by_name['sample-edge']['via'], '10.63.30.2')
        self.assertEqual(by_name['sample-edge']['dns_upstream'], ['127.0.0.1', 5354])
        self.assertEqual(by_name['sample-edge']['fakeip_range'], '198.18.0.0/15')
        self.assertEqual(by_name['sample-edge6']['interface'], 'tap2490')
        self.assertEqual(by_name['sample-edge6']['via'], 'fd42:1111:2222:30::2')
        self.assertEqual(by_name['sample-edge6']['dns_upstream'], ['127.0.0.1', 5354])
        self.assertEqual(by_name['sample-edge6']['fakeip_range'], '2001:2::/48')


if __name__ == '__main__':
    unittest.main()
