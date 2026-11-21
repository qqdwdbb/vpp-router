import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).parents[2]/'deploy'
spec = importlib.util.spec_from_file_location('persistent', ROOT/'firewall/persistent-rules.py')
persistent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(persistent)


class PersistentRulesTests(unittest.TestCase):
    def test_base_preserves_linux_and_vpp_interfaces_without_invalid_flowtable(self):
        original = '''flush ruleset
table inet base {
 flowtable f { hook ingress priority 0; devices = { lan, wan }; }
 chain c {
  iifname "lan" accept
  iifname { "wg0", "lan" } accept
  oifname "wan" snat to 10.61.10.2
  iifname "lan" flow add @f
 }
}
'''
        result = persistent.main_ruleset(original)
        self.assertNotIn('flowtable', result)
        self.assertNotIn('flow add', result)
        self.assertIn('iifname { "lan", "br-mgmt" } accept', result)
        self.assertIn('iifname { "wg0", "lan", "br-mgmt" } accept', result)
        self.assertIn('oifname "wan" snat to 10.61.10.2', result)
        self.assertEqual(result, persistent.main_ruleset(result))

    def test_base_drops_vpp_owned_marks_and_keeps_tproxy(self):
        original = '''flush ruleset
table inet mangle {
 chain prerouting {
  ip daddr @uk meta mark set 0x00000004 ct mark set 0x00000004 return
  ip daddr @altroute meta mark set 0x00000003 return
  ip daddr @vpn meta mark set 0x00000002 ct mark set 0x00000002 return
  ip6 daddr @vpn6 meta mark set 0x00000002 return
  ip saddr 10.62.20.0/24 meta mark set 0x00000002 return
  ip saddr { 10.62.20.0/24, 10.62.40.0/24 } meta mark set 2 return
  ip6 saddr fd42:1111:2222:70::/64 meta mark set 0x00000002 return
  iifname "br-mgmt" ip daddr @proxylist meta l4proto { tcp, udp } counter tproxy ip to 127.0.0.1:2080 meta mark set 0x2080 accept
 }
}
'''
        result = persistent.main_ruleset(original)
        self.assertNotIn('daddr @uk meta mark set', result)
        self.assertNotIn('daddr @altroute meta mark set', result)
        self.assertNotIn('daddr @vpn meta mark set', result)
        self.assertNotIn('daddr @vpn6 meta mark set', result)
        self.assertNotIn('saddr 10.62.20.0/24 meta mark set', result)
        self.assertNotIn('saddr fd42:1111:2222:70::/64 meta mark set', result)
        self.assertIn('daddr @proxylist', result)
        self.assertIn('tproxy ip to 127.0.0.1:2080 meta mark set 0x2080 accept', result)

    def test_fragments_include_transport_host_and_dns_in_one_transaction(self):
        result = persistent.includes()
        for name in ('wg-proxy.nft', 'host-path.nft', 'dns-route-gate.nft'):
            self.assertIn('/etc/vpp/'+name, result)
        self.assertNotIn('flush ruleset', result)
