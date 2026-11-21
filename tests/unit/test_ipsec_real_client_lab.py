import ipaddress
from pathlib import Path
import runpy
import unittest

m=runpy.run_path(str(Path(__file__).parents[2]/'deploy/ipsec/real-client-lab.py'))
CONFIG='''config setup
    uniqueids=no
conn %default
    keyexchange=ikev2
    leftauth=pubkey
    left=%any
    leftid=vpn.example.test
    leftcert=server.crt
    leftsubnet=0.0.0.0/0,::/0
    right=%any
    rightsourceip=10.62.50.0/24,2001:db8:1::100-2001:db8:1::200
    auto=add
conn cert
    rightauth=pubkey
    rightca="C=CN, O=Test, CN=Test CA"
conn eap-mschapv2
    rightauth=eap-mschapv2
    leftsubnet=0.0.0.0/5,8.0.0.0/7,::/0
    rightsourceip=10.62.20.0/24,fd42:1111:2222:60::/64
    rightdns=1.1.1.1
'''


class RealClientTests(unittest.TestCase):
    def test_production_authentication_and_split_selectors_are_preserved(self):
        text,pools,identity,cert=m['render'](CONFIG.replace('uniqueids=no','uniqueids = no'))
        self.assertIn('leftsubnet=0.0.0.0/5,8.0.0.0/7,::/0',text)
        self.assertIn('rightca="C=CN, O=Test, CN=Test CA"',text)
        self.assertIn('rightauth=eap-mschapv2',text)
        self.assertIn('forceencaps=yes',text)
        self.assertIn('mobike=no',text)
        self.assertEqual(identity,'vpn.example.test')
        self.assertEqual(cert,'server.crt')
        networks=list(map(ipaddress.ip_network,pools))
        self.assertTrue(any(ipaddress.ip_address('2001:db8:1::100') in n for n in networks if n.version==6))
        self.assertFalse(any(ipaddress.ip_address('2001:db8:1::ff') in n for n in networks if n.version==6))

    def test_hooks_includes_secrets_and_duplicate_fields_are_rejected(self):
        for line in ('leftupdown=/sbin/change-production','include /etc/other.conf','psk=SECRET', 'rightauth=pubkey'):
            with self.subTest(line=line),self.assertRaises(ValueError):
                m['render'](CONFIG+'    '+line+'\n')

    def test_real_client_profiles_are_required(self):
        with self.assertRaises(ValueError):m['render'](CONFIG.replace('conn cert','conn other'))

    def test_automatic_connection_is_not_started(self):
        text,*_=m['render'](CONFIG.replace('auto=add','auto=start'))
        self.assertNotIn('auto=start',text)

    def test_nft_ingress_is_restricted_to_original_wan_addresses_and_ike(self):
        text=m['nft_script']({'wan_endpoints':{'4':['192.0.2.2'],'6':['2001:db8::2']},
            'pools':['10.62.50.0/24','fd42:1111:2222:60::/64','2001:db8:1::100/120']})
        self.assertIn('iifname "wan" ip daddr 192.0.2.2 udp dport {500,4500}',text)
        self.assertIn('iifname "wan" ip6 daddr 2001:db8::2 udp dport {500,4500}',text)
        self.assertNotIn('flush ruleset',text)
        self.assertNotIn('nic0',text)
        self.assertNotIn('2001:db8:1::100/120 oifname "wan" counter masquerade',text)
        self.assertIn('fd42:1111:2222:60::/64 oifname "wan" counter masquerade',text)

    def test_ipv4_client_sources_reach_linux_policy_routing(self):
        text=m['nft_script']({'wan_endpoints':{},'pools':['10.62.50.0/24','10.62.20.0/24']})
        for pool in ('10.62.50.0/24','10.62.20.0/24'):
            self.assertIn('ip saddr '+pool+' counter accept',text)
            self.assertNotIn('ip saddr '+pool+' oifname "wan" counter masquerade',text)

    def test_conntrack_cleanup_failure_still_restores_production(self):
        import json
        import tempfile
        from unittest.mock import patch
        from types import SimpleNamespace
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            state={'routes_added':[],'network_owned':True,'production_stopped':True,
                   'production_was_active':True,'wan_endpoints':{'4':['192.0.2.2'],'6':['2001:db8::2']}}
            (root/'state.json').write_text(json.dumps(state))
            def command(args,**kwargs):
                calls.append(args)
                if args[:3]==['nft','-j','list']:
                    return SimpleNamespace(returncode=0,stdout=json.dumps({'nftables':[
                        {'rule':{'comment':'vrouter-ike-live:ike','handle':100}},
                        {'rule':{'comment':'unrelated','handle':101}}]}))
                failed='clear-ike-conntrack' in args[0]
                return SimpleNamespace(returncode=int(failed),stdout='')
            with patch.dict(m['recover'].__globals__,ROOT=root),patch('subprocess.run',side_effect=command),patch('builtins.print'):
                m['recover']()
            final=json.loads((root/'state.json').read_text())
            self.assertFalse(final['production_stopped'])
            self.assertIn(['systemctl','start','strongswan-starter'],calls)
            deleted=[a for a in calls if a[:3]==['nft','delete','rule']]
            self.assertEqual(len(deleted),1)
            self.assertEqual(deleted[0][-1],'100')
            self.assertIn('IKE conntrack cleanup',final['recovery_errors'])

    def test_recovery_does_not_start_previously_inactive_service(self):
        import json
        import tempfile
        from unittest.mock import patch
        from types import SimpleNamespace
        calls=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'state.json').write_text(json.dumps({'routes_added':[],'network_owned':False,
                'production_stopped':False,'production_was_active':False,'wan_endpoints':{}}))
            def command(args,**kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=1,stdout='')
            with patch.dict(m['recover'].__globals__,ROOT=root),patch('subprocess.run',side_effect=command),patch('builtins.print'):
                m['recover']()
            self.assertNotIn(['systemctl','start','strongswan-starter'],calls)
