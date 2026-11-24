import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vrouter_pd', Path(__file__).parents[2] / 'deploy/ipv6/pd-sync.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PrefixPublisherTests(unittest.TestCase):
    def test_shutdown_interrupts_long_poll_interval(self):
        # Exercise real signals while main() waits between reconciliations.
        child = '''
import importlib.util, os, signal, sys, threading
spec = importlib.util.spec_from_file_location('pd', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
signum = int(sys.argv[3])
class Publisher:
    def __init__(self, config, cli):
        pass
    def sync(self):
        timer = threading.Timer(0.1, lambda: os.kill(os.getpid(), signum))
        timer.daemon = True
        timer.start()
m.Publisher = Publisher
sys.argv = ['pd-sync', '--config', sys.argv[2]]
m.main()
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config.json'
            config.write_text(json.dumps(dict(
                interval_seconds=30, withdraw_seconds=60, ra_max_interval_seconds=30,
                lan_interface='loop0', wan_interface='wan0.100', prefix_group='wan-pd',
                state_file=str(root / 'state.json'))))
            for signum in (signal.SIGTERM, signal.SIGINT):
                with self.subTest(signal=signum):
                    result = subprocess.run(
                        [sys.executable, '-c', child, str(spec.origin), str(config), str(int(signum))],
                        capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_host_address_follows_selected_pool_and_withdrawal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); socket = root/'cli.sock'; socket.touch()
            config = dict(vpp_socket=str(socket), state_file='/run/pd-test/state.json',
                          lan_interface='loop0', wan_interface='wan0.100', prefix_group='wan-pd',
                          withdraw_seconds=5, host_interface='vpp-host')
            active = [True]
            def cli(command):
                if command == 'show ip6 prefixes':
                    return ('prefix: 2001:db8:1::/64, prefix group: wan-pd, preferred lifetime: 120, '
                            'valid lifetime: 180 (179.0 remaining)') if active[0] else ''
                if command == 'show interface address': return 'loop0 (up):\n L3 2001:db8:1::1/64\n'
                if command == 'show ip6 fib ::/0': return 'ipv6 via fe80::1 wan0.100: mtu:1500'
                return ''
            def path(value): return root/'state.json' if str(value)==config['state_file'] else Path(value)
            with patch.object(m, 'Path', side_effect=path), patch.object(m.subprocess, 'run') as run:
                publisher=m.Publisher(config,cli)
                publisher.sync(0); publisher.sync(6)
                self.assertEqual(publisher.host_address,'2001:db8:1::2/128')
                self.assertEqual(run.call_args.args[0], ['ip','-6','addr','replace','2001:db8:1::2/128','dev','vpp-host','nodad'])
                active[0]=False; publisher.sync(7)
                self.assertIsNone(publisher.host_address)
                self.assertEqual(run.call_args.args[0], ['ip','-6','addr','del','2001:db8:1::2/128','dev','vpp-host'])

    def test_ra_only_does_not_require_ipsec_tools(self):
        config = dict(state_file='/run/pd-test/state.json')
        with patch.object(m, '_shared_tool', side_effect=AssertionError('unexpected IPsec dependency')):
            publisher = m.Publisher(config, lambda command: '')
        self.assertIsNone(publisher.pools)

    def test_only_consumed_live_prefixes_and_deprecated_lifetimes(self):
        text = ('opaque_data: 4, prefix: 2001:db8:1::/64, prefix group: wan-pd, '
                'preferred lifetime: 100, valid lifetime: 200 (80.0 remaining)')
        addresses = 'loop200 (up):\n L3 2001:db8:1::1/64\nwan100 (up):\n L3 2001:db8:9::1/64\n'
        self.assertEqual(m.consumed(text, addresses, 'loop200', 'wan-pd'), {'2001:db8:1::/64': (80, 0)})
        self.assertFalse(m.consumed(text.replace('wan-pd', 'other'), addresses, 'loop200', 'wan-pd'))
        self.assertFalse(m.consumed(text.replace('80.0', '0.0'), addresses, 'loop200', 'wan-pd'))
        self.assertFalse(m.consumed(text, addresses, 'missing', 'wan-pd'))

    def test_pool_lifecycle_restart_and_failed_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sock = root / 'cli.sock'
            sock.touch()
            pool = root / 'ipsec.conf'
            pool.write_text('conn %default\n rightsourceip=10.62.50.0/24,fd00::/64\nconn eap-mschapv2\n rightsourceip=10.62.20.0/24,fd01::/64\n rightauth=eap-mschapv2\n')
            config = dict(vpp_socket=str(sock), state_file='/run/pd-test/state.json',
                          lan_interface='loop200', wan_interface='wan100', prefix_group='wan-pd',
                          withdraw_seconds=5, ipsec_config=str(pool), dhcp_lease_file=str(root/'leases'),
                          ipsec_pool_routes=True, host_interface='vpp-host',
                          ipsec_host_gateway='fd42::1')
            snapshot = {'network': '2001:db8:1::', 'default': True, 'fail': False, 'gateway': 'fe80::1'}
            commands = []
            def cli(command):
                if snapshot['fail']:
                    raise RuntimeError('VPP unavailable')
                network = snapshot['network']
                if command == 'show ip6 prefixes':
                    return '' if network is None else f'prefix: {network}/64, prefix group: wan-pd, preferred lifetime: 120, valid lifetime: 180 (179.0 remaining)'
                if command == 'show interface address':
                    return '' if network is None else f'loop200 (up):\n L3 {network}1/64\n'
                if command == 'show ip6 fib ::/0':
                    return f"ipv6 via {snapshot['gateway']} wan100: mtu:1500" if snapshot['default'] else 'drop'
                commands.append(command)
                return ''
            def path(value):
                return root/'state.json' if str(value) == config['state_file'] else Path(value)
            with patch.object(m, 'Path', side_effect=path), patch.object(m.subprocess, 'run') as execute:
                publisher = m.Publisher(config, cli)
                self.assertIsNone(publisher.sync(0)['pool_prefix'])
                self.assertEqual(publisher.sync(6)['pool_prefix'], '2001:db8:1::/64')
                self.assertIn('2001:db8:1::100-2001:db8:1::200', pool.read_text())
                self.assertIn('10.62.20.0/24,fd01::/64', pool.read_text())
                self.assertNotIn('10.62.20.0/24,2001:db8:1::100-2001:db8:1::200', pool.read_text())
                self.assertIn('ip route add 2001:db8:1::100/120 via fe80::1 wan100', commands)
                self.assertIn('ip route add 2001:db8:1::200/128 via fe80::1 wan100', commands)
                host_route = ['ip', '-6', 'route', 'replace', '2001:db8:1::100/120',
                              'via', 'fd42::1', 'dev', 'vpp-host', 'metric', '100']
                self.assertIn(host_route, [c.args[0] for c in execute.call_args_list])
                self.assertEqual(publisher.status['ipsec_host_routes']['2001:db8:1::100/120'],
                                 ['fd42::1', 'vpp-host'])
                route_count = len([c for c in commands if c.startswith('ip route')])
                stamp = pool.stat().st_mtime_ns
                publisher.sync(7)
                self.assertEqual([c.args[0] for c in execute.call_args_list].count(host_route), 1)
                self.assertEqual(pool.stat().st_mtime_ns, stamp)
                self.assertEqual(len([c for c in commands if c.startswith('ip route')]), route_count)
                restarted = m.Publisher(config, cli)
                self.assertEqual(restarted.sync(8)['pool_prefix'], '2001:db8:1::/64')
                self.assertEqual([c.args[0] for c in execute.call_args_list].count(host_route), 2)
                self.assertEqual(pool.stat().st_mtime_ns, stamp)
                snapshot['gateway'] = 'fe80::2'
                restarted.sync(8.5)
                self.assertIn('ip route add 2001:db8:1::100/120 via fe80::2 wan100', commands)
                self.assertIn('ip route del 2001:db8:1::100/120 via fe80::1 wan100', commands)
                self.assertEqual(pool.stat().st_mtime_ns, stamp)
                snapshot['fail'] = True
                with self.assertRaises(RuntimeError):
                    restarted.sync(9)
                self.assertEqual(pool.stat().st_mtime_ns, stamp)
                snapshot.update(fail=False, default=False)
                self.assertIsNone(restarted.sync(10)['pool_prefix'])
                self.assertEqual(restarted.status['ipsec_host_routes'], {})
                self.assertIn(host_route[:3]+['del']+host_route[4:],
                              [c.args[0] for c in execute.call_args_list])
                self.assertNotIn('2001:db8', pool.read_text())
                self.assertIn('ip route del 2001:db8:1::100/120 via fe80::2 wan100', commands)
                self.assertIn('ip6 nd loop200 prefix 2001:db8:1::/64 10 0', commands)
                self.assertNotIn('ip6 nd loop200 prefix 2001:db8:1::/64 0 0', commands)
                restarted.sync(16)
                self.assertIn('ip6 nd loop200 no prefix 2001:db8:1::/64', commands)
                snapshot.update(network='2001:db8:2::', default=True)
                restarted.sync(17)
                self.assertIn('ip6 nd loop200 prefix 2001:db8:2::/64 10 0 no-autoconfig', commands)
                self.assertEqual(restarted.sync(23)['pool_prefix'], '2001:db8:2::/64')
                self.assertIn('2001:db8:2::100/120', restarted.status['ipsec_host_routes'])
                self.assertNotIn('2001:db8:1::100/120', restarted.status['ipsec_host_routes'])
                self.assertIn('rightauth=eap-mschapv2', pool.read_text())
                replacement = root / 'replacement.sock'
                replacement.touch()
                replacement.replace(sock)
                self.assertIsNone(restarted.sync(24)['pool_prefix'])
                self.assertEqual(restarted.sync(30)['pool_prefix'], '2001:db8:2::/64')


if __name__ == '__main__':
    unittest.main()
