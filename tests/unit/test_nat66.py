import importlib.util
import ipaddress
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

root=Path(__file__).parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
nat=module('nat66',root/'tools/vpp-egress-nat.py')
prefix=module('pd',root/'tools/ipsec/ipsec-prefix-sync.py')


class NAT66Tests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state=Path(self.directory.name)/'state.json'
        self.network='2001:db8:2::/64'
        self.commands=[]
        self.mappings={}
        self.peers='[0] endpoint:[10.61.10.4:42008->0.0.0.0:0] wg0 keep-alive:25\n allowed-ips: 10.62.10.2/32 fd42:1111:2222:90::2/128\n[1] endpoint:[0.0.0.0:1->0.0.0.0:2] wg1 keep-alive:25\n allowed-ips: fd42:1111:2222:90::9/128\n'
        self.helpers={'cli':self.cli,'execute':self.execute}
        self.patcher=patch.object(nat.runpy,'run_path',return_value={'delegated':prefix.delegated})
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def cli(self,command):
        if command=='show interface address':
            return 'host-vpp-lan (up):\n L3 '+self.network.replace('/64','1/64')+'\nwg0 (up):\n L3 fd42:1111:2222:90::1/64\n'
        if command=='show ip6 prefixes':
            return 'prefix: '+self.network+', prefix group: wan-pd, preferred lifetime: 100, valid lifetime: 200 (120.0 remaining)' if self.network else ''
        if command=='show wireguard peer':return self.peers
        if command=='show nat66 static mappings':
            return '\n'.join('local '+a+' external '+b+' vrf 0' for a,b in self.mappings.items())
        raise AssertionError(command)

    def execute(self,lines):
        self.commands.extend(lines)
        for line in lines:
            words=line.split()
            if words[-1]=='del':self.mappings.pop(words[5])
            else:self.mappings[words[5]]=words[7]

    def test_peer_scope_mapping_and_idempotence(self):
        nat.reconcile_nat66(self.helpers,self.state)
        self.assertEqual(self.mappings,{'fd42:1111:2222:90::2':'2001:db8:2:0:66::2'})
        self.commands.clear()
        stamp=self.state.stat().st_mtime_ns
        nat.reconcile_nat66(self.helpers,self.state)
        self.assertEqual(self.commands,[])
        self.assertEqual(self.state.stat().st_mtime_ns,stamp)
        def explicit_policy_cli(command):
            self.assertEqual(command,'show nat66 static mappings')
            return self.cli(command)
        nat.reconcile_nat66_policy({'cli':explicit_policy_cli,'execute':self.execute},
                                   self.state,ipaddress.ip_network(self.network),['fd42:1111:2222:90::2'])
        self.assertFalse(self.commands)
        self.assertEqual(self.state.stat().st_mtime_ns,stamp)

    def test_prefix_change_preserves_unowned_mapping(self):
        nat.reconcile_nat66(self.helpers,self.state)
        self.mappings['fd42:1111:2222:90::8']='2001:db8::8'
        self.network='2001:db8:3::/64'
        nat.reconcile_nat66(self.helpers,self.state)
        self.assertEqual(self.mappings['fd42:1111:2222:90::2'],'2001:db8:3:0:66::2')
        self.assertEqual(self.mappings['fd42:1111:2222:90::8'],'2001:db8::8')

    def test_withdraw_restore_and_peer_removal(self):
        nat.reconcile_nat66(self.helpers,self.state)
        self.network=''
        nat.reconcile_nat66(self.helpers,self.state)
        self.assertFalse(self.mappings)
        self.network='2001:db8:2::/64'
        nat.reconcile_nat66(self.helpers,self.state)
        self.assertIn('fd42:1111:2222:90::2',self.mappings)
        self.peers=''
        nat.reconcile_nat66(self.helpers,self.state)
        self.assertFalse(self.mappings)

    def test_restart_and_conflicting_mapping(self):
        nat.reconcile_nat66(self.helpers,self.state)
        self.mappings.clear()
        nat.reconcile_nat66(self.helpers,self.state)
        self.assertIn('fd42:1111:2222:90::2',self.mappings)
        self.mappings['fd42:1111:2222:90::2']='2001:db8::bad'
        self.commands.clear()
        with self.assertRaises(RuntimeError):nat.reconcile_nat66(self.helpers,self.state)
        self.assertFalse(self.commands)
