"""The sing-box entry the router installer writes."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).parents[2] / 'deploy/install/singbox-config.py'


def generator():
    spec = importlib.util.spec_from_file_location('singbox_config', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_server(document):
    return next(s for s in document['dns']['servers'] if s['type'] == 'fakeip')


class SingBoxEntryTests(unittest.TestCase):
    def test_ipv6_lan_adds_an_ipv6_pool_to_an_ipv4_rule(self):
        module = generator()
        rule = {'tproxy_port': 2082, 'fakeip_range': ['198.18.0.0/15'], 'dns_upstream': ['127.0.0.1', 5354]}
        self.assertNotIn('inet6_range', fake_server(module.entry(rule, '10.61.30.2', '/tmp/c.db')))
        server = fake_server(module.entry(rule, '10.61.30.2', '/tmp/c.db', ipv6=True))
        self.assertEqual((server['inet4_range'], server['inet6_range']), ('198.18.0.0/15', '2001:2::/48'))

    def test_a_rules_own_ipv6_pool_is_kept(self):
        module = generator()
        rule = {'tproxy_port': 2082, 'fakeip_range': ['198.18.0.0/15', 'fc00:1::/48']}
        self.assertEqual(fake_server(module.entry(rule, '10.61.30.2', '/tmp/c.db', ipv6=True))['inet6_range'], 'fc00:1::/48')


    def test_one_tproxy_inbound_takes_real_and_fake_addresses(self):
        module = generator()
        rule = {'tproxy_exit': 'tproxy', 'tproxy_port': 2082, 'fakeip_range': ['198.18.0.0/15'], 'dns_upstream': ['127.0.0.1', 5354]}
        document = module.entry(rule, '10.61.30.2', '/tmp/c.db')
        tproxy = [i for i in document['inbounds'] if i['type'] == 'tproxy']
        self.assertEqual([(i['tag'], i['listen_port']) for i in tproxy], [('tproxy', 2082)])
        dns = next(i for i in document['inbounds'] if i['tag'] == 'fake-dns')
        self.assertEqual((dns['listen'], dns['listen_port']), ('127.0.0.1', 5354))

    def test_ports_given_are_used_without_a_gate_rule(self):
        module = generator()
        document = module.entry({}, '10.61.30.2', '/tmp/c.db', socks_port=11080, tproxy=12082, fake_dns_port=15354)
        ports = {i['tag']: i['listen_port'] for i in document['inbounds']}
        self.assertEqual(ports, {'lan-socks': 11080, 'tproxy': 12082, 'fake-dns': 15354})
        self.assertEqual(module.endpoints({}, 12082, 15354)[1:], (['127.0.0.1', 15354], '::', 12082))

    def test_a_gate_rule_wins_over_the_ports_given(self):
        module = generator()
        rule = {'tproxy_port': 7893, 'fakeip_range': ['198.18.0.0/15'], 'dns_upstream': ['127.0.0.1', 7874]}
        document = module.entry(rule, '10.61.30.2', '/tmp/c.db', socks_port=11080, tproxy=12082, fake_dns_port=15354)
        ports = {i['tag']: i['listen_port'] for i in document['inbounds']}
        self.assertEqual(ports, {'lan-socks': 11080, 'tproxy': 7893, 'fake-dns': 7874})

    def test_inbounds_cannot_share_a_port(self):
        module = generator()
        with self.assertRaisesRegex(ValueError, '不同的端口'):
            module.entry({}, '10.61.30.2', '/tmp/c.db', socks_port=2082)
        with self.assertRaisesRegex(ValueError, '1 到 65535'):
            module.port_number('70000')

    def test_command_line_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            run = lambda *args: subprocess.run([sys.executable, '-I', str(SCRIPT), *args],
                                               capture_output=True, text=True)
            result = run('entry', '--dir', directory, '--lan-address', '10.61.30.2', '--socks-port', '7890',
                         '--tproxy-port', '12082', '--fake-dns-port', '15354')
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(Path(directory, 'entry.json').read_text())
            self.assertEqual({i['tag']: i['listen_port'] for i in document['inbounds']},
                             {'lan-socks': 7890, 'tproxy': 12082, 'fake-dns': 15354})
            result = run('endpoints', '--tproxy-port', '12082', '--fake-dns-port', '15354')
            self.assertEqual(result.stdout, '127.0.0.1:15354 12082\n')
            self.assertNotEqual(run('entry', '--dir', directory, '--socks-port', '2082').returncode, 0)
            self.assertNotEqual(run('entry', '--dir', directory, '--socks-port', '70000').returncode, 0)


if __name__ == '__main__':
    unittest.main()
