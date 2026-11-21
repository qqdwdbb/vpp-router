import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).parents[2]/'deploy'


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host = load(ROOT/'host-services/host-path.py')
firewall = load(ROOT/'firewall/vrouter-firewall.py')


class HostPathTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT/'host-services/services.json').read_text())

    def discovered_ports(self, inventory):
        return {(service['protocol'], port) for service in
                host.ports.resolved_services(self.config, inventory)
                for port in service['ports']}

    def test_installer_interface_names_are_configuration_data(self):
        self.config.update(lan_bvi='loop0', lan_interfaces=['vpp-host'])
        self.assertIn('ip punt redirect rx loop0 via 10.61.20.2 loop0', host.topology(self.config))
        policy = host.nft(self.config, [], owners={})
        self.assertIn('frontend iifname { "vpp-host" }', policy)
        self.assertNotIn('frontend iifname { "br-mgmt"', policy)

    def test_policy_discovery_is_locked_and_unchanged_policy_is_not_reloaded(self):
        with tempfile.TemporaryDirectory() as directory:
            locked = []
            installed = []
            def command(args, **kwargs):
                self.assertTrue(locked)
                if args == ['nft', '-f', '-']:
                    installed[:] = [kwargs['input']]
                if args[:3] == ['nft', 'list', 'chain']:
                    return Mock(stdout=installed[0], returncode=0)
                return Mock(stdout='', returncode=0)
            with patch.object(host, 'POLICY_LOCK', Path(directory)/'policy.lock'), \
                    patch.object(host.fcntl, 'flock', side_effect=lambda *args: locked.append(True)), \
                    patch.object(host.subprocess, 'run', side_effect=command) as run:
                policy = host.update_policy(self.config)
                self.assertEqual(run.call_count, 2)
                locked.clear()
                self.assertEqual(host.update_policy(self.config, policy), policy)
                self.assertEqual(run.call_count, 4)

    def test_full_reload_reinstalls_unchanged_dynamic_owner_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config
            with patch.object(host, 'POLICY_LOCK', Path(directory)/'policy.lock'), \
                    patch.object(host.ports, 'current_listeners', return_value=[]), \
                    patch.object(host, 'owner_cgroups', return_value={'vrouter-coturn.service': 123}), \
                    patch.object(host.subprocess, 'run', return_value=Mock(stdout='', returncode=0)) as run:
                policy = host.update_policy(config)
                run.reset_mock()
                self.assertEqual(host.update_policy(config, policy), policy)
                self.assertEqual(run.call_args_list[0].args[0][:3], ['nft', 'list', 'chain'])
                self.assertEqual(run.call_args_list[1].args[0], ['nft', '-f', '-'])
                self.assertIn('owner-generation 123', run.call_args_list[1].kwargs['input'])

    def test_policy_install_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(host, 'POLICY_LOCK', Path(directory)/'policy.lock'), \
                    patch.object(host.subprocess, 'run', side_effect=[Mock(stdout=''), Mock(returncode=1)]):
                with self.assertRaisesRegex(RuntimeError, 'policy update failed'):
                    host.update_policy(self.config)

    def test_shared_pool_reserves_only_explicit_ports(self):
        commands = host.topology(self.config)
        self.assertNotIn('add static mapping', commands)
        self.assertIn('nat44 ei pool receive 10.61.10.2 nic0-dpdk.100', commands)
        self.assertNotIn('host-ip4-addr', commands)
        mappings = host.static_mappings(self.config, [500, 4500, 42008, 42001])
        self.assertEqual(mappings['tcp', 42002], '10.61.20.2')
        self.assertEqual(mappings['udp', 49152], '10.63.20.2')
        self.assertEqual(mappings['udp', 50151], '10.63.20.2')
        self.assertNotIn(('udp', 50152), mappings)
        self.assertNotIn(('tcp', 22), mappings)
        self.assertNotIn(('udp', 42001), mappings)
        self.assertEqual(len(mappings), 1005)
        self.config['host'] = self.config['wan_address']
        with self.assertRaises(ValueError):
            host.topology(self.config)

    def test_lan_frontend_excludes_gateway_http_and_internal_tproxy_is_not_advertised(self):
        rules = host.nft(self.config, [], owners={})
        lan = [line for line in rules.splitlines() if 'frontend iifname { "br-mgmt", "nic1", "vpp-lan", "lan" }' in line]
        self.assertEqual(len(lan), 2)
        self.assertIn('meta l4proto { tcp, udp } th dport != 80 dnat to 10.61.20.2', lan[1])
        services = host.ports.resolved_services(self.config, [])
        self.assertFalse(any(2080 in service['ports'] for service in services))
        self.assertTrue(any(1080 in service['ports'] for service in services))
        internal = self.config['internal_services'][0]
        self.assertEqual(internal['port'], 2080)
        self.assertEqual(internal['listen_addresses'], ['127.0.0.1', '::1'])

    def test_gateway_dns_reaches_gate_before_generic_dnat(self):
        for gateway, address in (('10.61.20.1', '10.61.20.2'),
                                 ('192.168.3.1', '192.168.3.2')):
            with self.subTest(gateway=gateway, host=address):
                self.config.update(gateway=gateway, host=address)
                rules = host.nft(self.config, [], owners={})
                lan = [line for line in rules.splitlines() if 'frontend iifname { "br-mgmt", "nic1", "vpp-lan", "lan" }' in line]
                trusted = ', '.join(self.config['trusted_ipv4'])
                self.assertEqual(lan[0],
                                 f'add rule ip vrouter_host_path frontend iifname {{ "br-mgmt", "nic1", "vpp-lan", "lan" }} ip saddr {{ {trusted} }} ip daddr {gateway} meta l4proto {{ tcp, udp }} th dport 53 dnat to {address}:1053')
                self.assertIn(f'dnat to {address}', lan[1])

    def test_nebula_listener_never_gets_a_static_mapping(self):
        inventory = [dict(protocol='udp', port=36145, addresses=['0.0.0.0'], processes=['nebula'])]
        nft = host.nft(self.config, inventory, owners={'vrouter-coturn.service': 123})
        self.assertIn('49152-50151', nft)
        self.assertNotIn('36145', nft)
        self.config['dynamic_services'][0]['ports'] = [36145, 42345]
        with patch.object(host.ports, 'current_listeners', side_effect=AssertionError('must not query listeners')):
            mappings = host.static_mappings(self.config, [])
        self.assertNotIn(('udp', 36145), mappings)
        self.assertNotIn(('udp', 42345), mappings)
        self.assertNotIn('dport { 22', nft)
        self.assertIn('iifname "vpp-hostsvc" counter drop', nft)
        self.assertNotIn('flush ruleset', nft)

    def test_wan_reply_routing_and_active_service_snat_are_separate(self):
        policy = host.nft(self.config, [], owners={})
        ingress = next(line for line in policy.splitlines() if 'ingress iifname' in line)
        self.assertIn('ip daddr 10.63.20.2 ct direction original', ingress)
        self.assertIn('ct mark set ct mark | 0x01000000', ingress)
        self.assertIn('type route hook output priority -140', policy)
        self.assertIn('meta mark set meta mark & 0xfcffffff', policy)
        for flag in ('0x01000000', '0x02000000'):
            self.assertIn(f'ct mark & {flag} != 0 meta mark set meta mark | {flag}', policy)
        snat = next(line for line in policy.splitlines() if 'counter snat to' in line)
        self.assertIn('oifname "vpp-hostsvc" ip saddr 10.61.20.2 ct direction original', snat)
        self.assertIn('snat to 10.63.20.2', snat)
        self.assertNotIn('ct direction reply ct status snat', policy)
        owned = host.nft(self.config, [], owners={'vrouter-coturn.service': 123})
        admission = [line for line in owned.splitlines() if 'ct direction reply ct status snat' in line]
        self.assertEqual(len(admission), 1)
        self.assertIn('socket cgroupv2 level 2 "system.slice/vrouter-coturn.service"', admission[0])
        self.assertIn('owner-generation 123', admission[0])
        self.assertNotIn('ct state established', policy)

    def test_active_nebula_and_coturn_classification_does_not_capture_lan_replies(self):
        inventory = [dict(protocol='udp', port=36145, addresses=['0.0.0.0'], processes=['nebula'])]
        policy = host.nft(self.config, inventory, owners={'vrouter-coturn.service': 123})
        classifiers = [line for line in policy.splitlines() if 'egress ip saddr' in line]
        self.assertFalse(any('36145' in line for line in classifiers))
        self.assertTrue(any('meta l4proto { tcp, udp } socket cgroupv2' in line for line in classifiers))
        for line in classifiers:
            self.assertIn('ct direction original ct state new', line)
            self.assertIn('ct mark & 0x03000000 == 0', line)
        self.config['dynamic_services'][0]['wan'] = False
        for service in self.config['services']:
            if service.get('owner_unit'):
                service['wan'] = False
        private = host.nft(self.config, inventory, owners={'vrouter-coturn.service': 123})
        self.assertNotIn('udp sport { 36145 }', private)
        self.assertNotIn('meta l4proto { tcp, udp } socket cgroupv2', private)

    def test_turn_range_is_guarded_by_socket_cgroup_and_absent_at_boot(self):
        initial = host.nft(self.config, [], owners={})
        self.assertNotIn('49152-50151', initial)
        self.assertNotIn('udp dport { 42004', initial)
        self.assertTrue(any('tcp dport' in line and '42004' in line and 'socket cgroupv2' not in line
                            for line in initial.splitlines()))
        active = host.nft(self.config, [], owners={'vrouter-coturn.service': 123})
        relay = [line for line in active.splitlines() if '49152-50151' in line]
        self.assertEqual(len(relay), 1)
        self.assertIn('socket cgroupv2 level 2 "system.slice/vrouter-coturn.service"', relay[0])
        self.assertNotEqual(active, host.nft(self.config, [], owners={'vrouter-coturn.service': 124}))

    def test_tcp_owner_guard_is_rejected_instead_of_breaking_handshake(self):
        self.config['services'][0]['owner_unit'] = 'vrouter-coturn.service'
        with self.assertRaisesRegex(ValueError, 'UDP only'):
            host.nft(self.config, [])

    def test_random_nebula_port_does_not_take_coturn_reservation(self):
        inventory = [dict(protocol='udp', port=49500, addresses=['0.0.0.0'], processes=['nebula'])]
        policy = host.nft(self.config, inventory, owners={})
        self.assertNotIn('udp dport { 49500 } counter accept', policy)
        self.assertNotIn('49152-50151', policy)
        self.assertEqual(host.static_mappings(self.config, [])['udp', 49500], self.config['wan_backend'])
        self.config['dynamic_services'][0]['wan'] = False
        private = host.nft(self.config, inventory, owners={'vrouter-coturn.service': 123})
        self.assertNotIn('udp dport { 49500 } counter accept', private)
        self.assertIn('socket cgroupv2', private)

    def test_loopback_dynamic_service_is_not_exposed(self):
        inventory = [dict(protocol='udp', port=36145, addresses=['127.0.0.1'], processes=['nebula'])]
        self.assertNotIn(('udp', 36145), self.discovered_ports(inventory))

    def test_dynamic_service_requires_ipv4_dnat_listener(self):
        for address in ('0.0.0.0', self.config['host'], '10.64.30.1',
                        '127.0.0.1', '[::1]', '[::]', '::', '*', '[::ffff:10.61.20.2]'):
            with self.subTest(address=address):
                inventory = [dict(protocol='udp', port=42345, addresses=[address], processes=['nebula'])]
                mappings = self.discovered_ports(inventory)
                self.assertEqual(('udp', 42345) in mappings,
                                 address in ('0.0.0.0', self.config['host']))

    def test_kernel_confirmed_dual_stack_wildcard_is_ipv4_reachable(self):
        for address, flag, reachable in (('*', 'v6only:0', True),
                                          ('[::]', 'v6only:0', True),
                                          ('*', 'v6only:1', False),
                                          ('*', '', False),
                                          ('[2001:db8::1]', 'v6only:0', False)):
            with self.subTest(address=address, flag=flag):
                inventory = host.ports.listeners(
                    f'udp UNCONN 0 0 {address}:36145 *:* users:(("nebula",pid=1,fd=6)) {flag}\n')
                mappings = self.discovered_ports(inventory)
                self.assertEqual(('udp', 36145) in mappings, reachable)

    def test_same_port_other_listener_does_not_supply_nebula_address(self):
        inventory = host.ports.listeners(
            'udp UNCONN 0 0 10.64.30.1:42345 0.0.0.0:* users:(("nebula",pid=1,fd=3))\n'
            'udp UNCONN 0 0 10.61.20.2:42345 0.0.0.0:* users:(("private",pid=2,fd=3))\n')
        self.assertEqual(len(inventory), 2)
        self.assertNotIn(('udp', 42345), self.discovered_ports(inventory))
        inventory = host.ports.listeners(
            'udp UNCONN 0 0 10.61.20.2:42345 0.0.0.0:* users:(("nebula",pid=1,fd=3))\n'
            'udp UNCONN 0 0 10.64.30.1:42345 0.0.0.0:* users:(("private",pid=2,fd=3))\n')
        self.assertIn(('udp', 42345), self.discovered_ports(inventory))

    def test_dynamic_target_follows_configured_host(self):
        self.config['host'] = '10.61.20.3'
        for address in ('10.61.20.2', '10.61.20.3'):
            inventory = [dict(protocol='udp', port=42345, addresses=[address], processes=['nebula'])]
            self.assertEqual(('udp', 42345) in self.discovered_ports(inventory),
                             address == self.config['host'])

    def test_wan_and_lan_acl_are_destination_scoped(self):
        acl = firewall.generate_vpp_acls({'vpp': {'host_service_path': True}})
        self.assertIn('dst 10.61.10.2/32 proto 17', acl['wan_in'])
        self.assertIn('src 10.61.10.2/32', acl['wan_out'])
        self.assertNotIn('10.61.10.4', acl['wan_out'])
        self.assertIn('dst 10.61.20.1/32 proto 6', acl['lan_in'])
        self.assertLess(acl['wan_in'].index('deny src 10.'), acl['wan_in'].index('dst 10.61.10.2/32 proto 17'))

    def test_coturn_keeps_credentials_and_ipv6_changes_only_ipv4_mapping(self):
        source = 'user=synthetic:placeholder\nexternal-ip=198.51.100.1/10.61.10.2\nlistening-ip=10.61.20.1\nrelay-ip=2001:db8::2\nmin-port=40000\nmax-port=60000\ndaemon\n'
        result = host.coturn_config(source, self.config)
        self.assertIn('user=synthetic:placeholder', result)
        self.assertIn('external-ip=198.51.100.1/10.61.20.2', result)
        self.assertIn('listening-ip=10.61.20.2', result)
        self.assertIn('relay-ip=2001:db8::2', result)
        self.assertIn('min-port=49152\nmax-port=50151\n', result)
        self.assertNotIn('min-port=40000', result)
        self.assertNotIn('\ndaemon\n', result)


if __name__ == '__main__':
    unittest.main()
