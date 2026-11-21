import copy
import importlib.util
import json
import re
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[2]/'deploy/cutover'


def load(name):
    spec = importlib.util.spec_from_file_location('cutover_'+name,ROOT/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load('prepare')
transition = load('transition')
runtime = load('runtime')


class CutoverTests(unittest.TestCase):
    def test_eap_dns_stays_inside_vpn_selectors(self):
        config = prepare.ipsec_dns_config(
            'conn %default\n'
            'conn cert\n    rightdns=8.8.8.8\n'
            'conn eap-mschapv2\n    rightdns=10.61.20.2\n')
        self.assertIn('conn cert\n    rightdns=10.61.20.2,fd42:1111:2222:10::2\n', config)
        self.assertIn('conn eap-mschapv2\n    rightdns=1.1.1.1,2606:4700:4700::1111\n', config)

    def test_vrouter_dnsmasq_conflicts_with_debian_unit(self):
        self.assertIn('\nConflicts=dnsmasq.service\n', (ROOT/'prepare.py').read_text())

    def test_host_uses_vpp_lan_when_profile_member_missing(self):
        self.assertEqual(runtime.lan_bridge_member({'linux_lan_member': None}), 'vpp-lan')
        self.assertEqual(runtime.lan_bridge_member({}), 'vpp-lan')
        self.assertEqual(runtime.lan_bridge_member({'linux_lan_member': 'vpp-lan'}), 'vpp-lan')

    def test_tap_offload_is_enabled_except_for_ipsec_peer(self):
        profile = json.loads((ROOT/'profile.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'baseline').mkdir()
            (root/'baseline/linux-state.json').write_text(json.dumps(
                {'links': {'br0': {'mac': '02:00:00:00:00:01'}}}))
            (root/'config').mkdir()
            with patch.object(runtime, 'run') as run, \
                    patch.object(runtime, 'ike_addresses'), \
                    patch.object(runtime, 'tproxy_path_module'):
                runtime.host(root, profile)

            calls = [call.args for call in run.call_args_list]
            enabled = ('ethtool', '-K', 'vpp-lan',
                       'tx', 'off', 'gro', 'on', 'gso', 'on', 'tso', 'off')
            ipsec = ('ip', 'netns', 'exec', profile['namespace'], 'ethtool', '-K',
                     profile['wan'], 'tx', 'off', 'gro', 'off', 'gso', 'off', 'tso', 'off')
            self.assertIn(enabled, calls)
            self.assertIn(ipsec, calls)

    def test_source_policy_keeps_private_destinations_on_vpp_fib(self):
        calls = []

        def fake_cli(command):
            calls.append(command)
            if command == 'show acl-plugin acl':
                return ''
            return 'ACL index: 42' if command.startswith('set acl-plugin acl') else ''

        with patch.object(runtime, 'cli', side_effect=fake_cli), \
                patch.object(runtime, 'lan_pd_prefixes', return_value=['2a00:1111:2222:4b74::/64']):
            runtime.policy({'unused': True})

        v4 = calls[1]
        v6 = calls[3]
        joined = ' '.join(calls)
        self.assertIn('deny src 0.0.0.0/0 dst 10.0.0.0/8', v4)
        self.assertIn('deny src 0.0.0.0/0 dst 172.16.0.0/12', v4)
        self.assertIn('deny src 0.0.0.0/0 dst 192.168.0.0/16', v4)
        self.assertNotIn('dst 1.1.1.1/32', v4)
        self.assertNotIn('via 10.61.20.2 loop200', joined)
        self.assertLess(v4.index('dst 192.168.0.0/16'), v4.index('permit src 10.62.20.0/24'))
        self.assertIn('deny src ::/0 dst fc00::/7', v6)
        self.assertIn('deny src ::/0 dst fe80::/10', v6)
        self.assertIn('deny src ::/0 dst ff00::/8', v6)
        self.assertIn('deny src ::/0 dst 2a00:1111:2222:4b74::/64', v6)
        self.assertNotIn('dst 2606:4700:4700::1111/128', v6)
        self.assertIn('permit src fd42:1111:2222:60::/64 dst ::/0', v6)
        self.assertIn('permit src fd42:1111:2222:70::/64 dst ::/0', v6)
        self.assertLess(v6.index('dst fc00::/7'), v6.index('permit src fd42:1111:2222:60::/64'))
        self.assertLess(v6.index('dst fc00::/7'), v6.index('permit src fd42:1111:2222:70::/64'))
        self.assertEqual(calls[4:], [
            'show abf policy',
            'abf policy add id 620 acl 42 via 10.61.50.1 loop10',
            'abf policy add id 621 acl 42 via fd42:1111:2222:20::1 loop10',
            'abf attach ip4 policy 620 tap4061',
            'abf attach ip6 policy 621 tap4061',
        ])

    def test_source_policy_replaces_existing_acl_by_tag(self):
        calls = []

        def fake_cli(command):
            calls.append(command)
            if command == 'show acl-plugin acl':
                return (
                    'acl-index 7 count 3 tag {vrouter-source-policy}\n'
                    'acl-index 9 count 4 tag {vrouter-source-policy6}'
                )
            return ''

        with patch.object(runtime, 'cli', side_effect=fake_cli):
            runtime.policy({'unused': True})

        self.assertTrue(calls[1].startswith('set acl-plugin acl index 7 '))
        self.assertIn('deny src 0.0.0.0/0 dst 192.168.0.0/16', calls[1])
        self.assertNotIn('dst 1.1.1.1/32', calls[1])
        self.assertTrue(calls[3].startswith('set acl-plugin acl index 9 '))
        self.assertIn('permit src fd42:1111:2222:60::/64 dst ::/0', calls[3])
        self.assertIn('permit src fd42:1111:2222:70::/64 dst ::/0', calls[3])

    def test_source_policy_does_not_append_via_to_existing_abf(self):
        calls = []

        def fake_cli(command):
            calls.append(command)
            if command == 'show acl-plugin acl':
                return (
                    'acl-index 7 count 3 tag {vrouter-source-policy}\n'
                    'acl-index 9 count 4 tag {vrouter-source-policy6}'
                )
            if command == 'show abf policy':
                return 'abf:[0]: policy:620 acl:7\nabf:[1]: policy:621 acl:9'
            return ''

        with patch.object(runtime, 'cli', side_effect=fake_cli):
            runtime.policy({'unused': True})

        self.assertEqual([c for c in calls if c.startswith('abf policy add')], [])
        self.assertIn('abf attach ip6 policy 621 tap4061', calls)

    def test_lan_pd_prefixes_only_accepts_global_slash64(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'state.json'
            path.write_text('{"pool_prefix": "2a00:1111:2222:4b74::/64"}')
            with patch.object(runtime, 'PD_SYNC_STATE', path):
                self.assertEqual(runtime.lan_pd_prefixes(), ['2a00:1111:2222:4b74::/64'])
            path.write_text('{"pool_prefix": "fd42:1111:2222:60::/64"}')
            with patch.object(runtime, 'PD_SYNC_STATE', path):
                self.assertEqual(runtime.lan_pd_prefixes(), [])
            path.write_text('{}')
            with patch.object(runtime, 'PD_SYNC_STATE', path):
                self.assertEqual(runtime.lan_pd_prefixes(), [])

    def test_pool_receive_cli_rejects_configuration_error_output(self):
        with patch.object(runtime, 'run', return_value='nat44 ei pool receive: Expected configured pool address and NAT outside interface'):
            with self.assertRaisesRegex(RuntimeError, 'pool receive'):
                runtime.cli('nat44 ei pool receive 10.61.10.4 nic0-dpdk.100')

    def test_host_path_skips_duplicate_socks_rule_but_original_path_loads_it(self):
        profile = json.loads((ROOT/'profile.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'baseline').mkdir()
            (root/'baseline/linux-state.json').write_text(json.dumps(
                {'links': {'br0': {'mac': '02:00:00:00:00:01'}}}))
            (root/'config').mkdir()
            (root/'config/socks-frontend.nft').write_text('placeholder')
            (root/'config/host-services.json').write_text(
                (ROOT.parent/'host-services/services.json').read_text())
            for enabled in (False, True):
                with self.subTest(host_service_path=enabled), patch.object(runtime, 'run') as run, \
                        patch.object(runtime, 'ike_addresses'), patch.object(runtime, 'tproxy_path_module'), \
                        patch.object(runtime, 'host_routing_module') as routing:
                    runtime.host(root, dict(profile, host_service_path=enabled))
                    socks_call = unittest.mock.call('nft', '-f', root/'config/socks-frontend.nft')
                    self.assertEqual(socks_call in run.call_args_list, not enabled)
                    host_call = unittest.mock.call('python3', ROOT.parent/'host-services/host-path.py',
                                                   '--config', root/'config/host-services.json', '--apply')
                    self.assertEqual(host_call in run.call_args_list, enabled)
                    self.assertEqual(routing.return_value.install.called, enabled)
                    self.assertNotIn(unittest.mock.call('nft', '-f', root/'config/host.nft'), run.call_args_list)

    def test_dns_replaces_gateway_and_reserves_host_address(self):
        config = prepare.dns_config('server=198.51.100.53\ninterface=lan\nlisten-address=10.61.20.1\ndhcp-range=10.61.20.2,10.61.20.254,6h\ndhcp-option=lan,6,10.61.20.1\n', '/bundle/config/dnsmasq.d')
        self.assertIn('server=198.51.100.53',config)
        self.assertIn('conf-dir=/bundle/config/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new',config)
        self.assertNotIn('conf-dir=/etc/dnsmasq.d',config)
        self.assertNotIn('interface=lan',config)
        self.assertNotIn('dhcp-range=10.61.20.2,',config)
        self.assertEqual(config.count('dhcp-option=option:router,'),1)
        self.assertIn('ra-param=br-mgmt,10,0',config)

    def test_dns_keeps_existing_rule_directory_once(self):
        config = prepare.dns_config('conf-dir=/etc/dnsmasq.d,.dpkg-old\n', '/bundle/config/dnsmasq.d')
        self.assertEqual(config.count('conf-dir='), 1)
        self.assertIn('conf-dir=/bundle/config/dnsmasq.d', config)

    def test_dnsmasq_fragments_remove_nftset_but_keep_other_rules(self):
        self.assertEqual(prepare.dnsmasq_fragment(
            'server=/example.test/192.0.2.53\n'
            'nftset=/example.test/4#inet#mangle#proxy\n'
            'cache-rr=64,65\n'),
            'server=/example.test/192.0.2.53\ncache-rr=64,65\n')

    def test_stage_dnsmasq_fragments_uses_private_sanitized_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/'source'
            bundle = Path(tmp)/'bundle'
            source.mkdir()
            (source/'rules.conf').write_text('server=/example.test/192.0.2.53\nnftset=/example.test/4#inet#mangle#proxy\n')
            staged = prepare.stage_dnsmasq_fragments(source, bundle)
            self.assertEqual(staged, bundle/'config/dnsmasq.d')
            self.assertEqual((staged/'rules.conf').read_text(), 'server=/example.test/192.0.2.53\n')

    def test_lease_tproxy_rejects_quic_before_intercept(self):
        rules = (ROOT.parent/'dns-route-gate/dns-route-gate.nft').read_text()
        v4_reject = 'iifname "vpp-tproxy" ip protocol udp udp dport 443 counter reject with icmp port-unreachable'
        v6_reject = 'iifname "vpp-tproxy" ip6 nexthdr udp udp dport 443 counter reject with icmpv6 port-unreachable'
        v4_tproxy = 'iifname "vpp-tproxy" meta nfproto ipv4 meta l4proto { tcp, udp } counter tproxy ip to :2080'
        v6_tproxy = 'iifname "vpp-tproxy" meta nfproto ipv6 meta l4proto { tcp, udp } counter tproxy ip6 to :2080'
        self.assertFalse(any('iifname "br-mgmt"' in line and 'tproxy ' in line
                             for line in rules.splitlines()))
        self.assertIn(v4_reject, rules)
        self.assertIn(v6_reject, rules)
        self.assertLess(rules.index(v4_reject), rules.index(v4_tproxy))
        self.assertLess(rules.index(v6_reject), rules.index(v6_tproxy))
        v4_icmp = 'iifname "br-mgmt" oifname "br-mgmt" icmp type destination-unreachable counter accept'
        v6_icmp = 'iifname "br-mgmt" oifname "br-mgmt" icmpv6 type { destination-unreachable, packet-too-big } counter accept'
        hairpin = 'iifname "br-mgmt" oifname "br-mgmt" counter drop'
        self.assertIn(v4_icmp, rules)
        self.assertIn(v6_icmp, rules)
        self.assertLess(rules.index(v4_icmp), rules.index(hairpin))
        self.assertLess(rules.index(v6_icmp), rules.index(hairpin))

    def test_vpn_dns_translates_to_the_actual_gate_listener(self):
        rules = (ROOT.parent/'dns-route-gate/dns-route-gate.nft').read_text()
        vpn = [line for line in rules.splitlines() if 'ip daddr 10.62.10.1 ' in line]
        self.assertEqual(len(vpn), 1)
        self.assertIn('iifname { "br-mgmt", "nic1", "vpp-lan", "lan" }', vpn[0])
        self.assertIn('meta l4proto { tcp, udp } th dport 53', vpn[0])
        self.assertIn('dnat ip to 10.61.20.2:1053', vpn[0])
        self.assertNotIn('redirect to', vpn[0])
        gate = json.loads((ROOT.parent/'dns-route-gate/dns-route-gate.json').read_text())
        self.assertIn(['10.61.20.2', 1053], gate['listen'])
        self.assertEqual(gate['upstream'], ['10.61.20.2', 53])

    def test_lan_dns_is_intercepted_without_overriding_vpn_dns(self):
        rules = (ROOT.parent/'dns-route-gate/dns-route-gate.nft').read_text()
        frontend = [line for line in rules.splitlines()
                    if 'legacy_frontend' in line and 'th dport 53' in line]
        self.assertEqual(len(frontend), 2)
        for line in frontend:
            self.assertIn('meta l4proto { tcp, udp }', line)
            self.assertNotIn('daddr', line)
            self.assertIn('saddr', line)
        self.assertIn('ip saddr 10.61.20.0/24', frontend[0])
        self.assertIn('ip6 saddr @lan6_sources', frontend[1])
        self.assertIn('dnat ip to 10.61.20.2:1053', frontend[0])
        self.assertIn('dnat ip6 to [fd42:1111:2222:10::2]:1053', frontend[1])

    def test_remove_nested_flowtable_preserves_other_policy(self):
        rules = 'table inet x {\n flowtable f { hook ingress priority 0; devices = { lan, wan }; }\n chain forward { policy accept; }\n}'
        result=prepare.remove_flowtable(rules)
        self.assertNotIn('flowtable f',result)
        self.assertIn('chain forward { policy accept; }',result)
        self.assertEqual(result.count('{'),result.count('}'))

    def test_topology_preserves_wan_identity_and_ike_ipv6(self):
        profile=json.loads((ROOT/'profile.json').read_text())
        config=prepare.topology(profile)
        self.assertIn('nat44 ei add identity mapping external nic0-dpdk.100 udp 500',config)
        self.assertNotIn('nat44 ei add identity mapping external nic0-dpdk.100\n',config)
        self.assertIn('nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384',config)
        self.assertIn('set nat44 ei timeout tcp-established 1800 tcp-transitory 120', config)
        self.assertLess(config.index('nat44 ei plugin enable'), config.index('nat44 ei context loop10 loop102'))
        self.assertLess(config.index('set interface ip address loop10 10.61.50.3/24'),
                        config.index('nat44 ei add address 10.61.50.3 tenant-vrf 102'))
        self.assertIn('ip table add 102', config)
        self.assertIn('set interface tcp-mss-clamp loop10 ip4 enable ip4-mss 960 ip6 enable ip6-mss 940', config)
        self.assertNotIn('tcp-mss-clamp tap4061', config)
        self.assertNotIn('tap2011', config)
        self.assertNotIn('vrouter-vpn', config)
        self.assertLess(config.index('set interface ip address tap4061 fd42:1111:2222:50:'),config.index('ipsec cleartext ingress tap4061'))
        self.assertNotIn('192.0.2.',config)
        self.assertNotIn('WAN_INTERFACE',config)
        self.assertNotIn('mgmt0',config)
        self.assertIn('set interface mtu packet 1500 nic0-dpdk.100', config)
        self.assertNotIn('set interface mtu ip4 1500 nic0-dpdk.100', config)
        self.assertNotIn('set interface mtu ip6 1500 nic0-dpdk.100', config)
        self.assertIn('set interface mtu packet 1500 loop200', config)
        self.assertIn('set interface mtu packet 1500 tap2000', config)
        lan_tap = next(line for line in config.splitlines() if line.startswith('create tap id 2000 '))
        self.assertIn(' host-if-name vpp-lan ', lan_tap)
        self.assertIn(' gso', lan_tap)
        self.assertIn('create tap id 2010 host-if-name vrouter-vps host-mtu-size 1342 gso', config)
        self.assertIn('create tap id 3901 host-if-name vpp-wg-proxy host-ip4-addr 10.63.50.2/30 gso', config)
        self.assertIn('create tap id 2490 host-if-name vpp-tproxy', config)
        ipsec_tap = next(line for line in config.splitlines() if line.startswith('create tap id 4061 '))
        self.assertNotIn(' gso', ipsec_tap)
        self.assertNotIn('set interface mtu ip4 1500 loop200', config)
        self.assertNotIn('set interface mtu ip6 1500 loop200', config)
        self.assertLess(config.index('set interface mtu packet 1500 loop200'),
                        config.index('set interface ip address loop200 10.61.20.1/24'))

    def test_native_identity_ports_have_one_authoritative_source(self):
        profile = json.loads((ROOT/'profile.json').read_text())
        services = json.loads((ROOT.parent/'host-services/services.json').read_text())
        self.assertNotIn('native_udp_ports', services)
        profile['wan_identity_udp_ports'] = [500, 4500, 42042]
        for host_path in (False, True):
            with self.subTest(host_service_path=host_path):
                config = prepare.topology(dict(profile, host_service_path=host_path))
                mappings = [line for line in config.splitlines()
                            if line.startswith('nat44 ei add identity mapping external ')]
                self.assertEqual(mappings, [
                    f'nat44 ei add identity mapping external {profile["wan"]} udp {port}'
                    for port in profile['wan_identity_udp_ports']])

    def test_native_identity_ports_are_required_and_validated(self):
        profile = json.loads((ROOT/'profile.json').read_text())
        profile.pop('wan_identity_udp_ports')
        with self.assertRaisesRegex(ValueError, 'WAN identity UDP ports'):
            prepare.topology(profile)
        for ports in ([], '500', [True], [0], [65536]):
            with self.subTest(ports=ports), self.assertRaisesRegex(ValueError, 'WAN identity UDP ports'):
                prepare.topology(dict(profile, wan_identity_udp_ports=ports))

    def test_recovery_replays_policy_routes_with_onlink(self):
        route={'dst':'default','gateway':'10.61.50.1','dev':'br0','table':'vpn','metric':2,'flags':['onlink']}
        self.assertEqual(transition.route_command('4',route),['ip','-4','route','replace','default','via','10.61.50.1','dev','br0','metric','2','table','vpn','onlink'])
        for protocol in ('kernel','ra','dhcp'):
            self.assertIsNone(transition.route_command('6',dict(route,protocol=protocol)))

    def test_host_ports_reserved_before_shared_wan_dynamic_nat(self):
        profile = json.loads((ROOT/'profile.json').read_text())
        profile['host_service_path'] = True
        config = prepare.topology(profile)
        self.assertNotIn('10.61.10.4', config)
        self.assertNotIn('4094', config)
        self.assertIn('nat44 ei add address 10.61.10.2 tenant-vrf 0', config)
        self.assertNotIn('nat44 ei add interface address nic0-dpdk.100', config)
        reservation = '# vrouter-host-static-reservations'
        self.assertLess(config.index('identity mapping external nic0-dpdk.100 udp 500'), config.index(reservation))
        self.assertLess(config.index(reservation), config.index('set interface nat44 ei out nic0-dpdk.100'))
        self.assertIn('identity mapping external nic0-dpdk.100 udp 500', config)

    def test_wrong_management_connection_rejected_before_route_query(self):
        profile=json.loads((ROOT/'profile.json').read_text())
        with patch.object(transition,'run') as run:
            with self.assertRaises(ValueError):
                transition.management(profile,'10.61.20.20 1 10.61.20.1 22')
            run.assert_not_called()

    def test_manifest_detects_configuration_change(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'config').write_text('good')
            (root/'manifest.json').write_text(json.dumps({'config':hashlib.sha256(b'good').hexdigest()}))
            transition.verify_manifest(root)
            (root/'config').write_text('changed')
            with self.assertRaises(ValueError):
                transition.verify_manifest(root)

    def test_prepared_recovery_is_non_mutating(self):
        with patch.object(transition,'run') as run:
            transition.restore_linux(Path('/unused'),{'phase':'prepared'})
            run.assert_not_called()

    def test_nftset_route_sync_enables_ordered_transparent_mappings(self):
        source = json.loads((ROOT.parent/'dns-route-gate/nftset-route-sync.json').read_text())
        mappings = {item['set']: item for item in source['mappings']}
        self.assertTrue(mappings['proxylist'].get('enabled', True))
        self.assertTrue(mappings['proxylist6'].get('enabled', True))
        self.assertEqual(source['overlap_policy'], 'first')
        self.assertEqual([m['set'] for m in source['mappings']], ['altroute', 'vpn', 'vpn6', 'proxylist', 'proxylist6'])
        self.assertTrue(mappings['altroute'].get('enabled', True))
        self.assertTrue(mappings['vpn'].get('enabled', True))
        self.assertEqual(mappings['vpn']['via'], '10.61.50.1')
        self.assertEqual(mappings['vpn']['interface'], 'loop10')
        self.assertEqual(mappings['vpn6']['via'], 'fd42:1111:2222:20::1')

    def test_wg1_proxy_setup_precedes_wireguard_loading(self):
        profile = json.loads((ROOT/'profile.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'config').mkdir()
            (root/'config/topology.vpp').write_text('create tap id 3901 host-if-name vpp-wg-proxy\n')
            (root/'config/host.nft').write_text('flush ruleset\n')
            (root/'config/egress-vrf.vpp').write_text('ip table add 101\n')
            (root/'config/wg-proxy.nft').write_text('table ip vpp_wg_proxy {}\n')
            (root/'baseline').mkdir()
            (root/'baseline/linux-state.json').write_text(json.dumps({'routes4': []}))

            events = []
            def fake_run(*args, **kwargs):
                events.append(('run', args[0], args[1:]))
                return ''
            def fake_cli(cmd):
                events.append(('cli', cmd))
                if cmd.startswith('set acl-plugin acl'):
                    return 'ACL index: 0'
                return ''

            with patch.object(runtime, 'run', side_effect=fake_run), \
                 patch.object(runtime, 'cli', side_effect=fake_cli):
                runtime.topology(root, profile)

            sysctl_idx = next(i for i, ev in enumerate(events)
                              if ev[0] == 'run' and any('net.ipv4.conf.vpp-wg-proxy.route_localnet=1' in str(a) for a in ev[2]))
            nft_idx = next(i for i, ev in enumerate(events)
                           if ev[0] == 'run' and any(str(root/'config/wg-proxy.nft') == str(a) for a in ev[2]))
            base_idx = next(i for i, ev in enumerate(events)
                           if ev[0] == 'run' and any(str(root/'config/host.nft') == str(a) for a in ev[2]))
            ct_idx = next(i for i, ev in enumerate(events)
                          if ev[0] == 'run' and ev[1] == 'conntrack')
            self.assertLess(base_idx, nft_idx, "global reload must not wipe the prepared wg1 DNAT")
            self.assertLess(sysctl_idx, ct_idx, "route_localnet must be configured before conntrack is cleared")
            self.assertFalse([ev for ev in events if ev[0] == 'cli' and re.search(r'wireguard|\bwg[018]\b', ev[1])],
                             "VPP's startup must know nothing about tunnels")
            self.assertIn('--orig-src', events[ct_idx][2])
            self.assertIn('10.63.50.1', events[ct_idx][2])
            self.assertIn('--orig-dst', events[ct_idx][2])
            cli_cmds = [ev[1] for ev in events if ev[0] == 'cli']
            self.assertIn('ip punt redirect rx tap4061 via 10.61.20.2 loop200', cli_cmds)
            self.assertNotIn('ip route add 1.1.1.1/32 via 10.61.20.2 loop200', cli_cmds)
            self.assertIn('nat44 ei pool receive 10.61.50.3 loop10', cli_cmds)

    def test_vps_pool_receive_follows_all_nat_outsides(self):
        profile = json.loads((ROOT/'profile.json').read_text())
        profile['host_service_path'] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'config').mkdir()
            (root/'config/topology.vpp').write_text(
                '# vrouter-host-static-reservations\nset interface nat44 ei out loop10\n')
            (root/'config/host.nft').write_text('flush ruleset\n')
            (root/'config/egress-vrf.vpp').write_text('ip table add 101\n')
            (root/'config/host-path.vpp').write_text('nat44 ei pool receive 10.61.10.2 nic0-dpdk.100\n')
            (root/'config/wg-proxy.nft').write_text('table ip vpp_wg_proxy {}\n')
            (root/'baseline').mkdir()
            (root/'baseline/linux-state.json').write_text(json.dumps({'routes4': []}))
            cli_cmds = []

            def fake_cli(cmd):
                cli_cmds.append(cmd)
                if cmd == 'show nat44 ei host-fallback':
                    return 'host-fallback-v1 pool-receive-v1'
                if cmd.startswith('set acl-plugin acl'):
                    return 'ACL index: 0'
                return ''

            with patch.object(runtime, 'run', return_value=''), \
                    patch.object(runtime, 'cli', side_effect=fake_cli), \
                    patch.object(runtime, 'reserve_host_ports'):
                runtime.topology(root, profile)

            self.assertIn('nat44 ei pool receive 10.61.10.2 nic0-dpdk.100', cli_cmds)
            self.assertIn('nat44 ei pool receive 10.61.50.3 loop10', cli_cmds)
            self.assertGreater(
                cli_cmds.index('nat44 ei pool receive 10.61.50.3 loop10'),
                cli_cmds.index('nat44 ei pool receive 10.61.10.2 nic0-dpdk.100'),
            )

    def test_installed_topology_skips_full_nft_reload(self):
        profile = json.loads((ROOT/'profile.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'config').mkdir()
            (root/'config/topology.vpp').write_text('create tap id 3901 host-if-name vpp-wg-proxy\n')
            (root/'config/host.nft').write_text('flush ruleset\n')
            (root/'config/egress-vrf.vpp').write_text('ip table add 101\n')
            (root/'config/wg-proxy.nft').write_text('table ip vpp_wg_proxy {}\n')
            (root/'baseline').mkdir()
            (root/'baseline/linux-state.json').write_text(json.dumps({'routes4': []}))
            events = []

            def fake_run(*args, **kwargs):
                events.append(args)
                return ''

            with patch.dict(os.environ, {'VROUTER_RUNTIME_DIRECTORY': '/usr/local/lib/vpp-vrouter'}), \
                    patch.object(runtime, 'run', side_effect=fake_run), \
                    patch.object(runtime, 'cli', return_value=''), \
                    patch.object(runtime, 'policy'):
                runtime.topology(root, profile)

            nft_files = [str(a) for args in events for a in args if str(a).endswith('.nft') or str(a).endswith('.conf')]
            self.assertIn(str(root/'config/wg-proxy.nft'), nft_files)
            self.assertNotIn(str(root/'config/host.nft'), nft_files)
            self.assertNotIn('/etc/nftables.conf', nft_files)

    def test_wg1_missing_transport_fails_before_loading(self):
        with patch.object(runtime, 'run', side_effect=RuntimeError('missing TAP')) as run:
            with self.assertRaisesRegex(RuntimeError, 'missing TAP'):
                runtime.setup_wg_proxy(Path('/unused'))
            run.assert_called_once_with('ip', 'link', 'set', 'vpp-wg-proxy', 'up')

    def test_vpp_owner_prevents_driver_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            state={'phase':'switching','installed_units':['vrouter-vpp.service']}
            with patch.object(transition,'run',return_value='') as run, patch.object(transition.subprocess,'run') as process:
                process.return_value.returncode=0
                with self.assertRaisesRegex(RuntimeError,'VPP still running'):
                    transition.restore_linux(root,state)
                self.assertFalse(any('restore-nic0.sh' in str(call) for call in run.call_args_list))
                self.assertEqual(json.loads((root/'state.json').read_text())['phase'],'rolling-back')


if __name__=='__main__':
    unittest.main()

