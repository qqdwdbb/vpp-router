import importlib.util
import ipaddress as ip
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('ipsec_prefix', Path(__file__).parents[2] / 'tools/ipsec/ipsec-prefix-sync.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PrefixTests(unittest.TestCase):
    def test_only_live_delegated_group_consumed_by_lan(self):
        addresses = 'host-vpp-lan (up):\n  L3 2001:db8:1::1/64\nhost-vpp-wan (up):\n  L3 2001:db8:9::1/64\n'
        leases = 'opaque_data: 2, prefix: 2001:db8:1::/64, prefix group: wan-pd, preferred lifetime: 100, valid lifetime: 200 (120.0 remaining)'
        self.assertEqual(str(m.delegated(leases, addresses)), '2001:db8:1::/64')
        self.assertIsNone(m.delegated(leases.replace('wan-pd', 'other'), addresses))
        self.assertIsNone(m.delegated(leases.replace('(120.0', '(0.0'), addresses))

    def test_exact_inclusive_original_range(self):
        ranges = m.pool_ranges(ip.ip_network('2001:db8::/64'), '', 100)
        self.assertEqual([(str(a), str(b)) for a, b in ranges], [('2001:db8::100', '2001:db8::200')])
        routes = [p for a,b in ranges for p in ip.summarize_address_range(a,b)]
        self.assertFalse(any(ip.ip_address('2001:db8::201') in p for p in routes))

    def test_active_dhcp_lease_is_excluded_until_expiry(self):
        leases = '200 ignored 2001:db8::1a7 client *\n99 ignored 2001:db8::100 client *'
        ranges = m.pool_ranges(ip.ip_network('2001:db8::/64'), leases, 100)
        self.assertEqual(sum(int(b)-int(a)+1 for a,b in ranges),256)
        self.assertFalse(any(a <= ip.ip_address('2001:db8::1a7') <= b for a,b in ranges))
        self.assertEqual(len(m.pool_ranges(ip.ip_network('2001:db8::/64'), leases, 201)),1)

    def test_both_profiles_share_ipv6_pool_and_preserve_ipv4(self):
        text = 'conn %default\n rightsourceip=10.62.50.0/24,2001:db8:old::1-2001:db8:old::2\nconn eap-mschapv2\n rightsourceip=10.62.20.0/24,fd00::/64\n rightauth=eap-mschapv2\n'
        ranges = m.pool_ranges(ip.ip_network('2001:db8::/64'), '', 100)
        out=m.rewrite_config(text,ranges)
        self.assertIn('10.62.50.0/24,2001:db8::100-2001:db8::200',out)
        self.assertIn('10.62.20.0/24,fd00::/64',out)
        self.assertNotIn('10.62.20.0/24,2001:db8::100-2001:db8::200',out)
        self.assertIn('rightauth=eap-mschapv2',out)
        out=m.rewrite_config(out,[])
        self.assertIn('rightsourceip=10.62.50.0/24\n',out)
        self.assertIn('10.62.20.0/24,fd00::/64',out)
        self.assertNotIn('2001:db8',out)

    def test_eap_public_pool_is_replaced_with_ula(self):
        text = 'conn %default\n rightsourceip=10.62.50.0/24\nconn eap-mschapv2\n rightsourceip=10.62.20.0/24,2001:db8::100-2001:db8::200\n'
        out = m.rewrite_config(text, m.pool_ranges(ip.ip_network('2001:db8::/64'), '', 100))
        self.assertIn('10.62.50.0/24,2001:db8::100-2001:db8::200', out)
        self.assertIn('10.62.20.0/24,' + m.EAP_ULA, out)

    def test_unexpected_configuration_fails_closed(self):
        with self.assertRaises(RuntimeError):m.rewrite_config('conn only\n rightsourceip=10.62.50.0/24\n',[])

    def test_reconcile_renumber_withdraw_and_unchanged_renewal(self):
        import json
        import tempfile
        from unittest.mock import patch, Mock
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            config=base/'ipsec.conf'
            state=base/'state.json'
            config.write_text('conn %default\n rightsourceip=10.62.50.0/24,fd00::/64\nconn eap-mschapv2\n rightsourceip=10.62.20.0/24,fd01::/64\n')
            snapshot={'prefix':'2001:db8:1::/64'}
            def run(*args):
                network=snapshot['prefix']
                if args == ('vppctl','show ip6 prefixes'):
                    return '' if network is None else f'prefix: {network}, prefix group: wan-pd, preferred lifetime: 100, valid lifetime: 200 (120.0 remaining)'
                if args == ('vppctl','show interface address'):
                    return '' if network is None else f'host-vpp-lan (up):\n  L3 {ip.ip_network(network).network_address + 1}/64\n'
                if args == ('vppctl','show ip6 fib ::/0'):
                    return 'ipv6 via fe80::1 host-vpp-wan'
                return ''
            with patch.object(m,'CONFIG',config), patch.object(m,'STATE',state), patch.object(m,'run',side_effect=run), patch.object(m,'vpp_batch') as batch, patch.object(m.time,'time',return_value=100), patch.object(m.time,'sleep'), patch.object(m,'open',side_effect=lambda *a,**kw: open(base/'lock','a'),create=True), patch.object(m.subprocess,'run',return_value=Mock(returncode=0)):
                self.assertTrue(m.reconcile())
                self.assertIn('2001:db8:1::100-2001:db8:1::200',config.read_text())
                batch.reset_mock()
                self.assertFalse(m.reconcile())
                self.assertFalse(any('ip route' in line for call in batch.call_args_list for line in call.args[0]))
                snapshot['prefix']='2001:db8:2::/64'
                self.assertTrue(m.reconcile())
                self.assertNotIn('2001:db8:1',config.read_text())
                self.assertTrue(any('ip route del 2001:db8:1::' in line for call in batch.call_args_list for line in call.args[0]))
                snapshot['prefix']=None
                self.assertTrue(m.reconcile())
                self.assertNotIn('2001:db8',config.read_text())
                self.assertIn('10.62.20.0/24',config.read_text())
                self.assertEqual(json.loads(state.read_text())['routes'],[])
