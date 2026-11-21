#!/usr/bin/env python3
"""Unit tests for VROUTER startup orchestration services and helper scripts."""
import configparser
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

STARTUP_DIR = Path(__file__).parents[2] / 'deploy/startup'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vpp_ready_mod = load_module('vrouter_vpp_ready', STARTUP_DIR / 'vrouter-vpp-ready.py')
sswan_ready_mod = load_module('vrouter_sswan_ready', STARTUP_DIR / 'vrouter-strongswan-ready.py')
net_prep_mod = load_module('vrouter_net_prep', STARTUP_DIR / 'vrouter-network-prep.py')


class SystemdUnitDependencyTests(unittest.TestCase):
    def parse_unit(self, filename):
        path = STARTUP_DIR / filename
        self.assertTrue(path.exists(), f"Unit file {filename} does not exist")
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        cp.read_string(path.read_text())
        return cp

    def test_vrouter_vpp_service_definition(self):
        cp = self.parse_unit('vrouter-vpp.service')
        self.assertIn('Service', cp)
        self.assertIn('ExecStartPost', cp['Service'])
        self.assertIn('vrouter-vpp-ready.py', cp['Service']['ExecStartPost'])
        self.assertEqual(cp['Service']['KillMode'], 'control-group')
        self.assertEqual(cp['Service']['Restart'], 'on-failure')

    def test_vrouter_network_prep_dependencies(self):
        cp = self.parse_unit('vrouter-network-prep.service')
        self.assertEqual(cp['Service']['Type'], 'oneshot')
        self.assertEqual(cp['Service']['RemainAfterExit'], 'yes')
        self.assertIn('vrouter-vpp.service', cp['Unit']['Requires'])
        self.assertIn('vrouter-vpp.service', cp['Unit']['After'])
        self.assertIn('vrouter-vpp.service', cp['Unit']['PartOf'])
        self.assertIn('vrouter-network-prep.py --action start', cp['Service']['ExecStart'])

    def test_vrouter_strongswan_dependencies(self):
        cp = self.parse_unit('vrouter-strongswan.service')
        self.assertIn('vrouter-vpp.service', cp['Unit']['Requires'])
        self.assertIn('vrouter-network-prep.service', cp['Unit']['Requires'])
        self.assertIn('vrouter-network-prep.service', cp['Unit']['After'])
        self.assertIn('vrouter-vpp.service', cp['Unit']['PartOf'])
        self.assertIn('vrouter-strongswan-ready.py', cp['Service']['ExecStartPost'])
        self.assertEqual(cp['Service']['KillMode'], 'control-group')

    def test_consumers_require_firewall_success(self):
        for name in ('vrouter-strongswan.service', 'vrouter-dns-route-gate.service'):
            cp = self.parse_unit(name)
            self.assertIn('vrouter-firewall.service', cp['Unit']['Requires'].split())
            self.assertIn('vrouter-firewall.service', cp['Unit']['After'].split())

    def test_strongswan_uses_private_config_runtime_and_reload_target(self):
        cp = self.parse_unit('vrouter-strongswan.service')
        service = cp['Service']
        self.assertEqual(service['NetworkNamespacePath'], '/run/netns/vrouter-ipsec')
        self.assertEqual(service['PrivateMounts'], 'yes')
        self.assertIn('/run/vrouter-strongswan:/run', service['BindPaths'])
        self.assertIn('/etc/vpp/ipsec-plugins:/usr/lib/ipsec/plugins', service['BindPaths'])
        self.assertIn('--conf /etc/vpp/ipsec.conf', service['ExecStart'])
        self.assertIn('--pid $MAINPID', service['ExecStartPost'])
        self.assertIn('/run/vpp', service['BindReadOnlyPaths'])
        self.assertEqual(service['ExecReload'], '/bin/kill -HUP $MAINPID')

    def test_vrouter_pd_sync_dependencies(self):
        cp = self.parse_unit('vrouter-pd-sync.service')
        self.assertIn('vrouter-vpp.service', cp['Unit']['Requires'])
        self.assertIn('vrouter-strongswan.service', cp['Unit']['Requires'])
        self.assertIn('vrouter-strongswan.service', cp['Unit']['After'])
        self.assertIn('vrouter-vpp.service', cp['Unit']['PartOf'])
        self.assertIn('pd-sync.py', cp['Service']['ExecStart'])

    def test_vrouter_dns_route_gate_dependencies(self):
        cp = self.parse_unit('vrouter-dns-route-gate.service')
        self.assertIn('vrouter-vpp.service', cp['Unit']['Requires'])
        self.assertIn('vrouter-network-prep.service', cp['Unit']['Requires'])
        self.assertIn('vrouter-network-prep.service', cp['Unit']['After'])
        self.assertIn('dnsmasq.service', cp['Unit']['After'])
        self.assertIn('vrouter-vpp.service', cp['Unit']['PartOf'])
        self.assertIn('dns-route-gate.py', cp['Service']['ExecStart'])


class VppReadyProbeTests(unittest.TestCase):
    def test_socket_missing_times_out(self):
        self.assertFalse(vpp_ready_mod.check_ready('/nonexistent/cli.sock', timeout=0.2))

    @patch('subprocess.run')
    def test_socket_ready_when_vppctl_succeeds(self, mock_run):
        with tempfile.TemporaryDirectory() as d:
            sock = Path(d) / 'cli.sock'
            sock.touch()
            mock_run.return_value = MagicMock(returncode=0, stdout='vpp v26.06-rc0~1')
            self.assertTrue(vpp_ready_mod.check_ready(str(sock), timeout=1))


class StrongSwanReadyProbeTests(unittest.TestCase):
    @patch('subprocess.run')
    def test_invalid_explicit_pid_never_probes_another_daemon(self, mock_run):
        self.assertFalse(sswan_ready_mod.check_ready('/private/cli.sock', pid=0))
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_missing_target_unit_never_falls_back_to_production_stroke(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='0')
        self.assertFalse(sswan_ready_mod.check_ready('/private/cli.sock', unit='missing.service', timeout=0.15))
        self.assertTrue(mock_run.called)
        self.assertTrue(all(call.args[0][:2] == ['systemctl', 'show'] for call in mock_run.call_args_list))

    @patch('subprocess.run')
    def test_strongswan_ready_when_plugin_and_client_present(self, mock_run):
        with tempfile.TemporaryDirectory() as d:
            sock = Path(d) / 'cli.sock'
            sock.touch()

            def fake_run(args, **kwargs):
                cmd_str = ' '.join(str(a) for a in args)
                if 'statusall' in cmd_str:
                    return MagicMock(returncode=0, stdout='loaded plugins: charon kernel-vpp stroke\nConnections:\n  lab: ...')
                if 'show api clients' in cmd_str:
                    return MagicMock(returncode=0, stdout='Clients:\n strongswan (pid 1234)\n')
                return MagicMock(returncode=0, stdout='')

            mock_run.side_effect = fake_run
            self.assertTrue(sswan_ready_mod.check_ready(str(sock), conn_name='lab', timeout=1))

    @patch('subprocess.run')
    def test_strongswan_not_ready_if_kernel_vpp_missing(self, mock_run):
        with tempfile.TemporaryDirectory() as d:
            sock = Path(d) / 'cli.sock'
            sock.touch()

            def fake_run(args, **kwargs):
                cmd_str = ' '.join(str(a) for a in args)
                if 'statusall' in cmd_str:
                    return MagicMock(returncode=0, stdout='loaded plugins: charon stroke\nConnections:\n  lab: ...')
                if 'show api clients' in cmd_str:
                    return MagicMock(returncode=0, stdout='Clients:\n')
                return MagicMock(returncode=0, stdout='')

            mock_run.side_effect = fake_run
            self.assertFalse(sswan_ready_mod.check_ready(str(sock), conn_name='lab', timeout=0.2))


class NetworkPrepTests(unittest.TestCase):
    @patch('subprocess.run')
    def test_missing_tap_fails_before_network_mutation(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        with self.assertRaisesRegex(RuntimeError, 'LAN TAP is missing'):
            net_prep_mod.configure_network({'netns': 'isolated'})
        self.assertEqual(mock_run.call_args_list[0].args[0],
                         ['ip', '-n', 'isolated', 'link', 'show', 'vpp-lan'])
        self.assertEqual(mock_run.call_count, 1)

    def test_invalid_explicit_config_never_runs_network_commands(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'network.json'
            for content in (None, '{broken', '[]', 'null', '"bad"'):
                if content is not None:
                    path.write_text(content)
                with self.subTest(content=content), patch('sys.argv',
                        ['vrouter-network-prep.py', '--config', str(path)]), \
                        patch.object(net_prep_mod, 'configure_network') as configure, \
                        patch.object(net_prep_mod, 'deconfigure_network') as deconfigure, \
                        patch('subprocess.run') as commands:
                    with self.assertRaises(SystemExit) as failure:
                        net_prep_mod.main()
                    self.assertEqual(failure.exception.code, 1)
                    configure.assert_not_called()
                    deconfigure.assert_not_called()
                    commands.assert_not_called()

    @patch('subprocess.run')
    def test_network_prep_configure(self, mock_run):
        calls = []

        def fake_run(args, **kwargs):
            calls.append(list(args))
            cmd_str = ' '.join(str(a) for a in args)
            if 'link show br-mgmt' in cmd_str:
                return MagicMock(returncode=1, stdout='')
            if 'link show vpp-lan' in cmd_str:
                return MagicMock(returncode=0, stdout='[{"address":"52:54:00:12:34:56"}]')
            if 'show hardware-interfaces loop200' in cmd_str:
                return MagicMock(returncode=0, stdout='Ethernet address 52:54:00:ab:cd:ef')
            return MagicMock(returncode=0, stdout='')

        mock_run.side_effect = fake_run

        with tempfile.TemporaryDirectory() as d:
            sock = Path(d) / 'cli.sock'
            sock.touch()
            config = {
                'bridge': 'br-mgmt',
                'lan_tap': 'vpp-lan',
                'lan_ip': '10.64.40.2/24',
                'lan_ula': 'fd42:1111:2222:10::2/64',
                'vpp_gw': '10.64.40.1',
                'vpp_ula_gw': 'fd42:1111:2222:10::1',
                'vpp_socket': str(sock),
                'vpp_bvi': 'loop200',
                'nftsets_path': None,
                'netns': None
            }
            res = net_prep_mod.configure_network(config)
            self.assertTrue(res)

            call_strs = [' '.join(str(a) for a in c) for c in calls]
            self.assertTrue(any('link add br-mgmt type bridge' in c for c in call_strs))
            self.assertTrue(any('link set vpp-lan master br-mgmt' in c for c in call_strs))
            self.assertTrue(any('addr replace 10.64.40.2/24 dev br-mgmt' in c for c in call_strs))
            self.assertTrue(any('route replace default via 10.64.40.1 dev br-mgmt' in c for c in call_strs))
            self.assertTrue(any('neigh replace 10.64.40.1 lladdr 52:54:00:ab:cd:ef' in c for c in call_strs))


if __name__ == '__main__':
    unittest.main()
