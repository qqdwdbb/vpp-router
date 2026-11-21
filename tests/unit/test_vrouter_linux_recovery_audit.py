import copy
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).parents[2]/'deploy/cutover/linux-recovery-audit.py'
spec = importlib.util.spec_from_file_location('recovery_audit', path)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class RecoveryAuditTests(unittest.TestCase):
    def baseline(self):
        return {'drivers': {'nic0':'r8125'}, 'links': {'wan':{'vlan_id':100}},
                'addresses': {'lan':['10.64.40.1/24','fd42:1111:2222::1/64']},
                'rules4':[{'priority':32764,'fwmark':2,'table':'vpn'}], 'rules6':[],
                'routes4':[{'dst':'default','gateway':'10.61.50.1','dev':'br0','table':'vpn'}],
                'routes6':[{'dst':'default','gateway':'fe80::1','dev':'wan','protocol':'ra','expires':100}],
                'services':{'dnsmasq.service':'active'}}

    def test_dynamic_gua_and_link_local_not_replayed(self):
        rows = [{'ifname':'lan','addr_info':[
            {'local':'10.64.40.1','prefixlen':24}, {'local':'fd42:1111:2222::1','prefixlen':64},
            {'local':'2001:db8::1','prefixlen':64}, {'local':'fe80::1','prefixlen':64}]}]
        self.assertEqual(audit.addresses(rows), {'lan':['10.64.40.1/24','fd42:1111:2222::1/64']})

    def test_ra_gateway_lifetime_can_change(self):
        baseline = self.baseline()
        restored = copy.deepcopy(baseline)
        restored['routes6'][0].update(gateway='fe80::2',expires=400)
        self.assertEqual(audit.compare(baseline,restored), [])

    def test_missing_policy_route_or_static_address_fails(self):
        for category in ('routes4','addresses','drivers','links','rules4','services'):
            baseline = self.baseline()
            restored = copy.deepcopy(baseline)
            restored[category] = {} if isinstance(restored[category],dict) else []
            with self.subTest(category=category):
                self.assertTrue(audit.compare(baseline,restored))

    def test_firewall_counters_and_dns_set_contents_can_change(self):
        original = {'nftables':[
            {'set':{'name':'vpn','elem':['192.0.2.1'],'handle':4}},
            {'rule':{'chain':'input','expr':[{'counter':{'packets':1,'bytes':64}},{'accept':None}]}}]}
        changed = copy.deepcopy(original)
        changed['nftables'][0]['set'].update(elem=['192.0.2.2'],handle=8)
        changed['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 100
        self.assertEqual(audit.firewall_policy(original),audit.firewall_policy(changed))

    def test_firewall_rule_change_fails_recovery_check(self):
        baseline = self.baseline()
        baseline['firewall'] = [{'rule':{'chain':'input','expr':[{'accept':None}]}}]
        restored = copy.deepcopy(baseline)
        restored['firewall'] = []
        self.assertTrue(audit.compare(baseline,restored))

    def test_missing_ipv6_default_fails(self):
        baseline = self.baseline()
        restored = copy.deepcopy(baseline)
        restored['routes6'] = []
        self.assertIn('IPv6 WAN default route not learned',audit.compare(baseline,restored))


if __name__ == '__main__':
    unittest.main()
