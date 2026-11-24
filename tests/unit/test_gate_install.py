"""Check what the one-time Gate installer renders, and that the README's example is honest."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
import unittest.mock

GATE = Path(__file__).resolve().parents[2] / 'tools/vpp-egress-gate'


def render(document=None):
    document = document if document is not None else {'upstream': ['127.0.0.1', 53], 'routes': []}
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp).resolve()
        (root / 'gate').touch()
        (root / 'startup.conf').touch()
        config = root / 'gate.json'
        config.write_text(json.dumps(document))
        output = subprocess.run(
            [sys.executable, str(GATE / 'install.py'), '--config', str(config), '--binary', str(root / 'gate'),
             '--vpp-cli-file', str(root / 'startup.conf'), '--dry-run'],
            capture_output=True, text=True, check=True).stdout
        self_check = json.loads(config.read_text())
    assert self_check == document, 'a dry run changed the configuration'
    result = json.loads(output)
    result['config'] = str(config)
    return result


def installer():
    spec = importlib.util.spec_from_file_location('gate_install', GATE / 'install.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def link(name, flags=('UP',), kind=None, addrs=('global',), link_type='none', data=None):
    info = {'info_kind': kind, 'info_data': data or {}} if kind else {}
    return {'ifname': name, 'flags': list(flags), 'link_type': link_type, 'linkinfo': info,
            'addr_info': [{'scope': scope} for scope in addrs]}


class DetectionTests(unittest.TestCase):
    def test_startup_file(self):
        text = ('unix {\n  nodaemon\n  cli-listen /run/vpp/cli.sock\n  exec /etc/vpp/n1-router.conf\n}\n'
                'api-segment { prefix n1 }\nsocksvr { socket-name /run/vpp/api.sock }\n')
        self.assertEqual(installer().parse_startup(text),
                         {'cli_file': '/etc/vpp/n1-router.conf', 'vpp_socket': '/run/vpp/cli.sock', 'api_socket': '/run/vpp/api.sock'})

    def test_startup_file_on_one_line_and_with_comments(self):
        text = '# exec /old.conf\nunix { nodaemon cli-listen /run/x.sock exec /etc/vpp/r.conf }\n'
        self.assertEqual(installer().parse_startup(text), {'cli_file': '/etc/vpp/r.conf', 'vpp_socket': '/run/x.sock'})

    def test_nameserver(self):
        module = installer()
        self.assertEqual(module.first_nameserver('# c\nsearch x\nnameserver 127.0.0.1\nnameserver 8.8.8.8\n'), '127.0.0.1')
        self.assertIsNone(module.first_nameserver('search x\n'))

    def test_existing_configuration_is_not_regenerated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / 'gate').touch()
            (root / 'cli').touch()
            config = root / 'gate.json'
            config.write_text('{"routes": []}')
            result = subprocess.run([sys.executable, str(GATE / 'install.py'), '--config', str(config), '--binary', str(root / 'gate'),
                                     '--vpp-cli-file', str(root / 'cli'), '--lan-prefix', '10.0.0.0/24', '--dry-run'],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('edit it instead', result.stderr)
            self.assertEqual(config.read_text(), '{"routes": []}')


class StatedConfigurationTests(unittest.TestCase):
    STARTUP = 'unix { cli-listen /run/x.sock }\n'
    VPP = ('eth2.100 (up):\n  L3 10.61.20.253/24\nloop10 (up):\n  L3 10.61.50.2/24\n'
           'loop200 (up):\n  L3 10.61.30.1/24\n  L3 fd99:77::1/64\nwg7 (up):\n  L3 10.62.30.2/24\nlocal0 (dn):\n')

    def generate(self, answers=None, links=(), vpp=None, proxy=('', ''), **flags):
        """Runs generate_config. Without answers there is no terminal, as in a script. The
        proxy answers come last, after the exits, and take the defaults unless given."""
        module = installer()
        prompts = []
        pending = list(answers) + list(proxy) if answers is not None else None
        def read_answer(prompt):
            prompts.append(prompt)
            return None if pending is None else pending.pop(0)
        module.read_answer = read_answer
        module.say = prompts.append
        with tempfile.TemporaryDirectory() as temp:
            startup = Path(temp, 'startup.conf')
            startup.write_text(self.STARTUP)
            outputs = {'systemctl show': f'{{ argv[]=/usr/bin/vpp -c {startup} ; }}',
                       'vppctl -s /run/x.sock show interface addr': self.VPP if vpp is None else vpp,
                       'vppctl': '', 'ip -j addr': json.dumps(list(links))}
            module.run = lambda *a: next(v for k, v in outputs.items() if ' '.join(a).startswith(k))
            options = {'vpp_service': 'n1-vpp.service', 'lan_prefix': None, 'upstream': None, 'vpp_exit': None, 'linux_exit': None,
                       'hijack_public_dns': None, 'tproxy': None, 'fake_dns': None}
            options.update(flags)
            result = module.generate_config(types.SimpleNamespace(**options))
        if pending:
            self.fail(f'unasked answers: {pending}')
        return result, prompts

    @staticmethod
    def address(name, *addresses, **options):
        found = link(name, **options)
        found['addr_info'] = [{'scope': 'global', 'local': local} for local in addresses]
        return found

    def test_answers_become_the_configuration(self):
        links = [self.address('wg0', '10.9.0.2'), self.address('eth1', '192.0.2.5')]
        (document, linux, vpp, _), prompts = self.generate(
            ['10.61.30.0/24', '10.61.20.2', 'wg7, loop10', '10.62.30.1', '10.61.50.1', 'wg0 eth1', '', '192.0.2.1'], links)
        self.assertEqual(document['lan_prefixes'], ['10.61.30.0/24'])
        self.assertEqual(document['upstream'], ['10.61.20.2', 53])
        # loop200 holds the LAN: Gate follows its IPv6 prefixes, which may be delegated.
        self.assertEqual(document['lan_interfaces'], ['loop200'])
        self.assertEqual(document['vpp_socket'], '/run/x.sock')
        self.assertEqual((linux, vpp), (['wg0', 'eth1'], ['wg7', 'loop10']))
        self.assertEqual(document['routes'], [
            {'name': 'wg0', 'owner': 'host', 'domain_files': ['wg0.domains'], 'linux_exit': {'interface': 'wg0', 'masquerade': True}},
            {'name': 'eth1', 'owner': 'host', 'domain_files': ['eth1.domains'], 'linux_exit': {'interface': 'eth1', 'masquerade': True, 'gateway': '192.0.2.1'}},
            {'name': 'vpp-wg7', 'owner': 'vpp', 'interface': 'wg7', 'via': '10.62.30.1', 'domain_files': ['vpp-wg7.domains']},
            {'name': 'vpp-loop10', 'owner': 'vpp', 'interface': 'loop10', 'via': '10.61.50.1', 'domain_files': ['vpp-loop10.domains']},
            {'name': 'proxy', 'domain_files': ['proxy.domains'], 'tproxy_exit': 'tproxy', 'tproxy_port': 2082, 'ipv6': False,
             'dns_upstream': ['127.0.0.1', 5354], 'fakeip_range': '198.18.0.0/15'}])
        listed = ''.join(prompts)
        self.assertIn('WireGuard 隧道填对端的隧道地址', listed)
        self.assertIn('wg7  10.62.30.2/24', listed)
        self.assertIn('eth1  192.0.2.5', listed)

    def test_no_lan_interfaces_when_vpp_does_not_hold_the_lan(self):
        (document, _, _, _), _ = self.generate(['10.77.0.0/24', '10.61.20.2', '', ''])
        self.assertNotIn('lan_interfaces', document)

    def test_nothing_becomes_an_exit_unless_stated(self):
        (document, linux, vpp, _), _ = self.generate(['10.61.30.0/24', '10.61.20.2', '', ''], [self.address('wg0', '10.9.0.2')])
        self.assertEqual((linux, vpp), ([], []))
        self.assertEqual([r['name'] for r in document['routes']], ['proxy'])

    def test_no_next_hop_advice_without_a_vpp_exit(self):
        _, prompts = self.generate(['10.61.30.0/24', '10.61.20.2', '', ''])
        self.assertNotIn('隧道地址', ''.join(prompts))

    def test_a_bad_answer_is_asked_again(self):
        answers = ['', '10.61.30.1/24', '10.61.30.0/24', 'not-an-address', '10.61.20.2', 'nope', 'loop200', 'wg7', '', '2001:db8::1', '10.62.30.1', '']
        (document, _, vpp, _), _ = self.generate(answers)
        self.assertEqual(document['lan_prefixes'], ['10.61.30.0/24'])
        self.assertEqual(vpp, ['wg7'])

    def test_no_terminal_needs_flags_for_what_has_no_default(self):
        with self.assertRaisesRegex(ValueError, '--lan-prefix'):
            self.generate()
        with self.assertRaisesRegex(ValueError, '--upstream'):
            self.generate(lan_prefix=['10.61.30.0/24'])

    def test_flags_replace_the_questions(self):
        links = [self.address('eth1', '192.0.2.5'), self.address('wg0', '10.9.0.2')]
        (document, linux, vpp, _), prompts = self.generate(
            None, links, lan_prefix=['10.61.30.0/24', 'fd99:77::/64'], upstream='10.61.20.2',
            vpp_exit=['loop10=10.61.50.1,fd00::1'], linux_exit=['eth1=192.0.2.1,fe80::1', 'wg0=ipv6'], tproxy='2082', fake_dns='127.0.0.1:5354')
        self.assertEqual(prompts, [])
        rules = {r.get('name') or r['linux_exit']['interface']: r for r in document['routes']}
        self.assertEqual(rules['vpp-loop10']['via'], ['10.61.50.1', 'fd00::1'])
        self.assertEqual(rules['eth1']['linux_exit']['gateway6'], 'fe80::1')
        self.assertTrue(rules['eth1']['ipv6'])
        self.assertTrue(rules['wg0']['ipv6'])
        self.assertNotIn('gateway6', rules['wg0']['linux_exit'])
        self.assertEqual(rules['proxy']['fakeip_range'], ['198.18.0.0/15', '2001:2::/48'])

    def test_exits_without_a_terminal_stay_out(self):
        (document, _, _, _), _ = self.generate(None, [], lan_prefix=['10.61.30.0/24'], upstream='10.61.20.2')
        self.assertEqual([r['name'] for r in document['routes']], ['proxy'])

    def test_several_gateways_become_a_rule_each(self):
        (document, _, _, _), _ = self.generate(None, [self.address('longname.10', '192.0.2.5')], lan_prefix=['10.61.30.0/24'],
                                               upstream='10.61.20.2', linux_exit=['longname.10=203.0.113.1,203.0.113.2'])
        rules = [r for r in document['routes'] if 'linux_exit' in r]
        self.assertEqual([(r['name'], r['linux_exit']['gateway']) for r in rules],
                         [('longname_10-1', '203.0.113.1'), ('longname_10-2', '203.0.113.2')])
        self.assertEqual(rules[0]['domain_files'], ['longname_10-1.domains'])

    def test_an_interface_clients_arrive_on_is_no_exit(self):
        parse = installer().parse_exit_names
        self.assertEqual(parse('wg7, wg7 loop10', {'wg7': [], 'loop10': []}, {}), ['wg7', 'loop10'])
        with self.assertRaisesRegex(ValueError, '客户端所在'):
            parse('loop200', {'loop200': []}, {'loop200': []})
        with self.assertRaisesRegex(ValueError, '客户端所在'):
            self.generate(None, [], lan_prefix=['10.61.30.0/24'], upstream='10.61.20.2', vpp_exit=['loop200=10.61.30.9'])
        with self.assertRaisesRegex(ValueError, '客户端所在'):
            self.generate(None, [self.address('n1-lan', '10.61.30.2')], lan_prefix=['10.61.30.0/24'],
                          upstream='10.61.20.2', linux_exit=['n1-lan'])

    def test_an_exit_is_picked_by_number_name_or_address(self):
        parse = installer().parse_exit_names
        known = {'eth0.100': ['10.61.20.253/24'], 'loop200': ['10.61.30.1/24'], 'wg7': ['10.62.30.2/24', 'fd00::2/64']}
        clients = {'loop200': []}
        self.assertEqual(parse('2,1', known, clients), ['wg7', 'eth0.100'])
        self.assertEqual(parse('wg7', known, clients), ['wg7'])
        self.assertEqual(parse('10.61.20.253', known, clients), ['eth0.100'])
        self.assertEqual(parse('10.61.20.253/24，fd00::2', known, clients), ['eth0.100', 'wg7'])
        with self.assertRaisesRegex(ValueError, '没有序号 3'):
            parse('3', known, clients)
        with self.assertRaisesRegex(ValueError, '客户端所在'):
            parse('10.61.30.1', known, clients)

    def test_the_listing_numbers_what_can_be_picked(self):
        known = {'eth0.100': ['10.61.20.253/24'], 'loop200': ['10.61.30.1/24'], 'wg7': ['10.62.30.2/24']}
        text = installer().listing(known, {'loop200': []})
        self.assertIn('1. eth0.100  10.61.20.253/24', text)
        self.assertIn('2. wg7  10.62.30.2/24', text)
        self.assertRegex(text, r'-  loop200  10.61.30.1/24.*不能作为出口')
        self.assertIn('直接填接口名', installer().listing({}, {}))

    def test_names_are_checked_only_against_a_vpp_that_answered(self):
        parse = installer().parse_exit_names
        with self.assertRaisesRegex(ValueError, '列表里没有'):
            parse('wg9', {'wg7': []}, {})
        self.assertEqual(parse('wg9', {}, {}), ['wg9'])

    def test_vias(self):
        parse = installer().parse_vias
        self.assertEqual(parse('10.61.50.1, fd00::1', True), ['10.61.50.1', 'fd00::1'])
        for text, use_ipv6, message in (('', True, '下一跳'), ('10.0.0.1 10.0.0.2', True, '各填一个'),
                                        ('fd00::1', False, '没有 IPv6')):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                parse(text, use_ipv6)

    def test_gateways(self):
        parse = installer().parse_gateways
        self.assertEqual(parse('', False), {'gateways': [], 'gateway6': None, 'ipv6': False})
        self.assertEqual(parse('ipv6', True), {'gateways': [], 'gateway6': None, 'ipv6': True})
        self.assertEqual(parse('192.0.2.1 fe80::1', True), {'gateways': ['192.0.2.1'], 'gateway6': 'fe80::1', 'ipv6': True})
        for text, use_ipv6 in (('fe80::1 fe80::2', True), ('ipv6', False), ('fe80::1', False), ('ipv6 192.0.2.1', True),
                               ('192.0.2.1 192.0.2.2 fe80::1', True), ('nonsense', True)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse(text, use_ipv6)

    def test_interface_listings(self):
        module = installer()
        self.assertEqual(module.parse_vpp_interfaces(self.VPP)['loop200'], ['10.61.30.1/24', 'fd99:77::1/64'])
        self.assertNotIn('local0', module.parse_vpp_interfaces(self.VPP))
        links = [self.address('lo', '127.0.0.1', link_type='loopback'), self.address('wg0', '10.9.0.2'),
                 self.address('down0', '10.9.0.3', flags=()), self.address('tap-wg1', '172.30.10.2'), link('empty0', addrs=())]
        self.assertEqual(module.linux_interfaces(links), {'wg0': ['10.9.0.2']})

    def test_nat_as_an_output_feature_changes_nothing_stated(self):
        (document, _, vpp, notes), _ = self.generate(
            None, [self.address('n1-lan', '10.61.30.2')], lan_prefix=['10.61.30.0/24'], upstream='10.61.20.2', vpp_exit=['wg7=10.62.30.1'])
        self.assertEqual(vpp, ['wg7'])
        self.assertEqual(document['hijack_vpp'], [{'interface': 'loop200', 'via': ['10.61.30.2'], 'sources': ['10.61.30.0/24']}])
        self.assertEqual(notes, ['LAN 客户端的 DNS 查询都会经过 Gate，不管发给哪个地址'])

    def test_the_proxy_client_is_asked_where_it_listens(self):
        (document, _, _, _), prompts = self.generate(['10.61.30.0/24', '10.61.20.2', '', ''], proxy=['127.0.0.1:7893', '127.0.0.1:7874'])
        proxy = document['routes'][-1]
        self.assertEqual((proxy['tproxy_address'], proxy['tproxy_port'], proxy['dns_upstream']), ('127.0.0.1', 7893, ['127.0.0.1', 7874]))
        explained = ''.join(prompts)
        for text in ('mihomo', 'TPROXY 入站', 'Fake-IP 网段设成 198.18.0.0/15', '127.0.0.1:5354'):
            self.assertIn(text, explained)
        # Listening on every address names no address.
        (document, _, _, _), _ = self.generate(['10.61.30.0/24', '10.61.20.2', '', ''], proxy=['[::]:7893', ''])
        self.assertEqual(document['routes'][-1]['tproxy_port'], 7893)
        self.assertNotIn('tproxy_address', document['routes'][-1])
        # A bad answer is asked again.
        (document, _, _, _), _ = self.generate(['10.61.30.0/24', '10.61.20.2', '', ''],
                                               proxy=['::1:7893', '70000', '7893', '0.0.0.0:5354', '127.0.0.1:1053', '[::1]:53'])
        self.assertEqual(document['routes'][-1]['dns_upstream'], ['::1', 53])

    def test_proxy_flags(self):
        flags = {'lan_prefix': ['10.61.30.0/24', 'fd99:77::/64'], 'upstream': '10.61.20.2'}
        (document, _, _, _), _ = self.generate(None, tproxy='127.0.0.1:7893,[::1]:7893', fake_dns='[::1]:7874', **flags)
        proxy = document['routes'][-1]
        self.assertEqual(proxy['tproxy_address'], ['127.0.0.1', '::1'])
        self.assertEqual(proxy['fakeip_range'], ['198.18.0.0/15', '2001:2::/48'])
        self.assertEqual(proxy['dns_upstream'], ['::1', 7874])
        for tproxy, fake_dns, message in (('127.0.0.1:7893', '127.0.0.1:5354', 'IPv4 和 IPv6 地址各填一个'),
                                          ('127.0.0.1:7893,[::1]:7894', '127.0.0.1:5354', '同一个端口'),
                                          ('5354', '127.0.0.1:5354', '同一个端口')):
            with self.subTest(tproxy=tproxy), self.assertRaisesRegex(ValueError, message):
                self.generate(None, tproxy=tproxy, fake_dns=fake_dns, **flags)
        # Without a terminal, the usual values.
        (document, _, _, _), _ = self.generate(None, lan_prefix=['10.61.30.0/24'], upstream='10.61.20.2')
        self.assertEqual({k: document['routes'][-1].get(k) for k in ('tproxy_port', 'tproxy_address', 'dns_upstream')},
                         {'tproxy_port': 2082, 'tproxy_address': None, 'dns_upstream': ['127.0.0.1', 5354]})

    def test_public_dns_hijack_is_asked_explained_and_on_by_default(self):
        lan = [self.address('n1-lan', '10.61.30.2')]
        (document, _, _, _), prompts = self.generate(['10.61.30.0/24', '10.61.20.2', '', '', ''], lan)
        self.assertEqual(document['hijack_vpp'], [{'interface': 'loop200', 'via': ['10.61.30.2'], 'sources': ['10.61.30.0/24']}])
        explained = ''.join(prompts)
        for text in ('8.8.8.8', '本机 LAN', 'DoH、DoT', 'acl、abf', 'ACL 匹配', '不再起作用', '[Y/n]'):
            self.assertIn(text, explained)
        (document, _, _, notes), _ = self.generate(['10.61.30.0/24', '10.61.20.2', 'maybe', 'n', '', ''], lan)
        self.assertNotIn('hijack_vpp', document)
        self.assertIn('不会', notes[-1])

    def test_dns_sent_to_this_machine_always_goes_through_gate(self):
        lan = [self.address('n1-lan', '10.61.30.2')]
        flags = {'lan_prefix': ['10.61.30.0/24'], 'upstream': '10.61.20.2'}
        for public_dns in (True, False, None):
            with self.subTest(public_dns=public_dns):
                (document, _, _, _), _ = self.generate(None, lan, hijack_public_dns=public_dns, **flags)
                self.assertTrue(document['hijack_dns'])
                self.assertEqual(document['hijack_interfaces'], ['n1-lan'])
                self.assertEqual(document['listen'], [['127.0.0.1', 1053], ['10.61.30.2', 1053]])
                self.assertEqual('hijack_vpp' in document, public_dns is not False)
        # A client network on no VPP interface has nothing for VPP to send.
        _, prompts = self.generate(['', ''], lan, vpp='', **flags)
        self.assertNotIn('公网 DNS？', ''.join(prompts))
        with self.assertRaisesRegex(ValueError, '--hijack-public-dns'):
            self.generate(None, lan, vpp='', hijack_public_dns=True, **flags)

    def test_gate_listens_on_the_port_given(self):
        lan = [self.address('n1-lan', '10.61.30.2')]
        flags = {'lan_prefix': ['10.61.30.0/24'], 'upstream': '10.61.20.2'}
        (document, _, _, _), _ = self.generate(None, lan, listen_port=10053, **flags)
        self.assertEqual(document['listen'], [['127.0.0.1', 10053], ['10.61.30.2', 10053]])
        # Without hijacking, the default port leaves listen to Gate's own default.
        (document, _, _, _), _ = self.generate(None, listen_port=10053, **flags)
        self.assertEqual(document['listen'], [['127.0.0.1', 10053]])
        (document, _, _, _), _ = self.generate(None, **flags)
        self.assertNotIn('listen', document)
        with self.assertRaisesRegex(ValueError, 'Gate 的 DNS'):
            self.generate(None, listen_port=10053, tproxy='10053', fake_dns='127.0.0.1:5354', **flags)
        for bad in ('53', '0', '70000', 'x'):
            with self.subTest(port=bad), self.assertRaises(installer().argparse.ArgumentTypeError):
                installer().listen_port(bad)

    def test_no_public_dns_question_without_an_interface_on_the_client_network(self):
        _, prompts = self.generate(['10.61.30.0/24', '10.61.20.2', '', ''], [self.address('wg0', '10.9.0.2')])
        self.assertNotIn('公网 DNS？', ''.join(prompts))

    def test_a_network_on_no_vpp_interface_is_pointed_out(self):
        (_, _, _, notes), _ = self.generate(None, [], lan_prefix=['192.168.9.0/24'], upstream='10.61.20.2')
        self.assertIn('192.168.9.0/24 不在任何 VPP 接口上', notes[0])
        (_, _, _, notes), _ = self.generate(None, [], vpp='', lan_prefix=['192.168.9.0/24'], upstream='10.61.20.2')
        self.assertEqual(notes, [])


class FailedInstallTests(unittest.TestCase):
    def install(self, root, binary, foreign=False):
        """Run main() as root against a temporary tree. Only the binary's dry run really executes."""
        module = installer()
        real_run = module.run
        module.os = types.SimpleNamespace(geteuid=lambda: 0)
        module.DOMAIN_DIR = root / 'etc/gate'
        config = root / 'etc/egress-gate.json'
        document = {'vpp_service': 'vpp.service', 'lan_prefixes': ['10.77.0.0/24'], 'routes': [{'domain_files': ['new.domains']}, {'domain_files': ['kept.domains']}]}
        module.generate_config = lambda args: (document, [], [], [])
        unit = root / 'units/gate.service'
        module.install_files = lambda service, config: {unit: module.MARKER}
        if foreign:
            unit.parent.mkdir()
            unit.write_text('# mine\n')
        module.BINARY = root / 'installed'
        module.run = lambda *args: real_run(*args) if args[0] == str(binary) else ''
        cli = root / 'cli'
        cli.touch()
        argv = ['install.py', '--config', str(config), '--binary', str(binary), '--vpp-cli-file', str(cli)]
        with unittest.mock.patch.object(sys, 'argv', argv):
            module.main()

    def check_nothing_generated_is_left(self, root):
        self.assertFalse((root / 'etc/egress-gate.json').exists())
        self.assertFalse((root / 'etc/gate').exists())
        self.assertFalse((root / 'installed').exists())

    def test_binary_of_another_architecture_leaves_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            binary = root / 'gate'
            binary.write_bytes(b'\x7fELF not for this machine')
            binary.chmod(0o755)
            with self.assertRaises(OSError):
                self.install(root, binary)
            self.check_nothing_generated_is_left(root)

    def test_rejected_configuration_leaves_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            binary = root / 'gate'
            binary.write_text('#!/bin/sh\nexit 1\n')
            binary.chmod(0o755)
            with self.assertRaises(RuntimeError):
                self.install(root, binary)
            self.check_nothing_generated_is_left(root)

    def test_rollback_keeps_what_was_there(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            kept = root / 'etc/gate/kept.domains'
            kept.parent.mkdir(parents=True)
            kept.write_text('example.org\n')
            binary = root / 'gate'
            binary.write_text('#!/bin/sh\nexit 1\n')
            binary.chmod(0o755)
            with self.assertRaises(RuntimeError):
                self.install(root, binary)
            self.assertEqual(kept.read_text(), 'example.org\n')
            self.assertFalse((root / 'etc/gate/new.domains').exists())
            self.assertFalse((root / 'etc/egress-gate.json').exists())

    def test_foreign_file_stops_before_anything_is_generated(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            binary = root / 'gate'
            binary.write_text('#!/bin/sh\nexit 0\n')
            binary.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'refusing to overwrite'):
                self.install(root, binary, foreign=True)
            self.check_nothing_generated_is_left(root)


class InstallerTests(unittest.TestCase):
    def test_links_unit_is_independent_of_vpp(self):
        result = render({'upstream': ['127.0.0.1', 53], 'vpp_service': 'n1-vpp.service', 'routes': []})
        unit = result['files']['/etc/systemd/system/vpp-egress-gate-links.service']
        self.assertNotIn('n1-vpp', unit)
        self.assertNotIn('DefaultDependencies', unit)
        self.assertIn('Before=vpp-egress-gate.service\n', unit)
        self.assertIn('Type=oneshot\nRemainAfterExit=yes\n', unit)
        self.assertIn('ExecStart=/usr/local/bin/vpp-egress-gate --setup-links\n', unit)
        # It reads the journal alone, so a half-edited configuration cannot affect a boot.
        self.assertNotIn(result['config'], unit)

    def test_gate_waits_for_the_links_and_reads_the_generated_configuration(self):
        result = render({'upstream': ['127.0.0.1', 53], 'vpp_service': 'n1-vpp.service', 'routes': []})
        unit = result['files']['/etc/systemd/system/vpp-egress-gate.service']
        self.assertIn('--config /var/lib/vpp-egress-gate/gate.json\n', unit)
        self.assertIn('Requires=vpp-egress-gate-links.service\n', unit)
        self.assertIn('After=n1-vpp.service vpp-egress-gate-links.service\n', unit)
        self.assertNotRegex(unit, r'(?m)^Requires=.*n1-vpp')
        self.assertIn('StartLimitIntervalSec=0', unit)
        self.assertIn('RestartSec=5', unit)

    def test_a_restart_applies_the_configuration_first(self):
        result = render({'upstream': ['127.0.0.1', 53], 'routes': []})
        unit = result['files']['/etc/systemd/system/vpp-egress-gate.service']
        # A failure must not stop Gate, or a typing error would cost DNS.
        self.assertIn(f"ExecStartPre=-/usr/local/bin/vpp-egress-gate --config {result['config']} --sync-on-start\n", unit)
        self.assertLess(unit.index('ExecStartPre='), unit.index('ExecStart='))

    def test_a_configuration_path_survives_systemd(self):
        unit = installer().gate_unit('vpp.service', Path('/etc/my gate/100%.json'))
        self.assertIn("--config '/etc/my gate/100%%.json' --sync-on-start", unit)

    def test_the_links_unit_does_not_read_the_configuration(self):
        unit = render()['files']['/etc/systemd/system/vpp-egress-gate-links.service']
        self.assertNotIn('sync', unit)

    def test_lan_interfaces_find_where_clients_arrive(self):
        def lan_link(name, *addresses, **options):
            found = link(name, **options)
            found['addr_info'] = [{'scope': scope, 'local': local} for scope, local in addresses]
            return found
        links = [
            lan_link('lo', ('host', '127.0.0.1'), link_type='loopback'),
            lan_link('n1-lan', ('global', '10.61.30.2'), ('global', '10.62.10.1'), ('link', 'fe80::1')),
            lan_link('wlan0', ('global', '10.61.20.208')),
            lan_link('down0', ('global', '10.61.30.9'), flags=()),
            lan_link('tap-wg1', ('global', '10.61.30.10')),
            lan_link('v6lan', ('global', 'fd00::2')),
        ]
        find = installer().lan_interfaces
        self.assertEqual(find(links, ['10.61.30.0/24']), (['n1-lan'], ['10.61.30.2', '10.62.10.1']))
        self.assertEqual(find(links, ['10.61.30.0/24', 'fd00::/64']), (['n1-lan', 'v6lan'], ['10.61.30.2', '10.62.10.1', 'fd00::2']))
        self.assertEqual(find(links, ['172.16.0.0/24']), ([], []))
        # Privacy and deprecated addresses change when the interface is made again.
        tap = lan_link('vpp-host', ('global', '10.61.30.2'), ('global', 'fd00::66:1bff:fee1:fa4c'))
        tap['addr_info'] += [{'scope': 'global', 'local': 'fd00::52fc:d6d3:1a0d:ead', 'temporary': True, 'dynamic': True},
                             {'scope': 'global', 'local': 'fd00::dead', 'deprecated': True}]
        self.assertEqual(find([tap], ['10.61.30.0/24', 'fd00::/64']), (['vpp-host'], ['10.61.30.2', 'fd00::66:1bff:fee1:fa4c']))

    def test_vpp_hijack_entries_need_linux_on_the_client_network(self):
        entries = installer().vpp_hijack_entries
        self.assertEqual(entries({'loop200': ['10.61.30.0/24', 'fd00::/64'], 'loop201': ['10.0.0.0/24']}, ['10.61.30.2', '10.61.30.3', '172.16.0.1']),
                         [{'interface': 'loop200', 'via': ['10.61.30.2'], 'sources': ['10.61.30.0/24']}])
        self.assertEqual(entries({'loop200': ['10.61.30.0/24', 'fd00::/64']}, ['10.61.30.2', 'fd00::2']),
                         [{'interface': 'loop200', 'via': ['10.61.30.2', 'fd00::2'], 'sources': ['10.61.30.0/24', 'fd00::/64']}])
        self.assertEqual(entries({'loop200': ['10.0.0.0/24']}, ['10.61.30.2']), [])

    def test_vpp_interfaces_are_found_by_address_whatever_nat_does(self):
        addresses = ('eth0 (up):\n  L2 bridge bd-id 200 idx 1 shg 0\neth0.100 (up):\n  L3 10.61.20.253/24\n'
                     'local0 (dn):\nloop200 (up):\n  L2 bridge bd-id 200 idx 1 shg 0 bvi\n  L3 10.61.30.1/24\n  L3 fd00::1/64\n')
        self.assertEqual(installer().vpp_interfaces_on(['10.61.30.0/24', 'fd00::/64'], addresses),
                         {'loop200': ['10.61.30.0/24', 'fd00::/64']})
        self.assertEqual(installer().vpp_interfaces_on(['10.0.0.0/24'], addresses), {})

    def test_nat_on_ip4_input_reads_only_that_arc(self):
        check = installer().nat_on_ip4_input
        self.assertTrue(check('ip4-unicast:\n  ip4-sv-reassembly-feature\n  nat44-ei-in2out\n\nl2-output-nonip:\n  none configured\n'))
        self.assertFalse(check('ip4-unicast:\n  none configured\n\nip4-output:\n  nat44-ei-in2out-output\n'))
        self.assertFalse(check(''))

    def test_listen_note_only_when_clients_cannot_reach_gate(self):
        note = installer().listen_note
        path = Path('/etc/vpp/egress-gate.json')
        for document in ({}, {'listen': [['127.0.0.1', 1053]]}, {'listen': [['127.0.0.1', 53], ['::1', 53]]}):
            with self.subTest(document=document):
                self.assertIn('LAN clients cannot reach it', note(document, path))
        self.assertIn('127.0.0.1:1053', note({}, path))
        self.assertIn(str(path), note({}, path))
        for document in ({'listen': [['10.61.20.2', 53]]}, {'listen': [['127.0.0.1', 53], ['10.61.20.2', 53]]},
                         {'listen': [['127.0.0.1', 1053]], 'hijack_dns': True}, {'listen': []}, {'listen': [['gate.lan', 53]]}):
            with self.subTest(document=document):
                self.assertIsNone(note(document, path))

    def test_relative_binary_is_not_looked_up_in_path(self):
        source = (GATE / 'install.py').read_text()
        self.assertIn('binary = args.binary.resolve()', source)
        self.assertNotIn('run(str(args.binary)', source)

    def test_install_applies_the_users_configuration_once(self):
        source = (GATE / 'install.py').read_text()
        self.assertIn("run(str(BINARY), '--config', str(config), '--sync-devices')", source)

    def test_vpp_service_comes_from_the_split_runtime_file(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp).resolve() / 'runtime.json'
            runtime.write_text(json.dumps({'vpp_service': 'other.service'}))
            result = render({'upstream': ['127.0.0.1', 53], 'route_config': str(runtime), 'routes': []})
        self.assertIn('other.service', result['files']['/etc/systemd/system/vpp-egress-gate.service'])

    def test_default_vpp_service(self):
        self.assertIn('After=vpp.service ', render()['files']['/etc/systemd/system/vpp-egress-gate.service'])

    def test_vpp_startup_only_gains_one_exec_line(self):
        self.assertEqual(render()['vpp_append'], 'exec /var/lib/vpp-egress-gate/vpp-devices.cli\n')

    def test_network_managers_leave_every_device_alone(self):
        files = render()['files']
        self.assertIn('unmanaged-devices=interface-name:tap-*;interface-name:gw-*;interface-name:gm-*;interface-name:gate-tproxy\n',
                      files['/etc/NetworkManager/conf.d/90-vpp-egress-gate.conf'])
        self.assertIn('Name=tap-* gw-* gm-* gate-tproxy\n[Link]\nUnmanaged=yes\n',
                      files['/etc/systemd/network/10-vpp-egress-gate.network'])

    def test_networkd_keeps_gate_rules_and_routes(self):
        conf = render()['files']['/etc/systemd/networkd.conf.d/90-vpp-egress-gate.conf']
        self.assertIn('ManageForeignRoutes=no\n', conf)
        self.assertIn('ManageForeignRoutingPolicyRules=no\n', conf)

    def test_no_network_service_is_required_or_restarted_unconditionally(self):
        source = (GATE / 'install.py').read_text()
        self.assertNotIn('/etc/nftables.conf', source)
        self.assertNotIn('networkctl', source)
        self.assertIn("if service_active('systemd-networkd'):\n", source)

    def test_installer_never_restarts_vpp(self):
        source = (GATE / 'install.py').read_text()
        self.assertNotRegex(source, r"'(restart|stop)',\s*vpp_service")
        # Generating only reads from VPP; --sync-devices is what changes it.
        for word in ("'create'", "'delete'", "'set'"):
            self.assertNotIn(word, source)

    def test_refusals(self):
        for document in ({'vpp_service': 'bad name', 'routes': []},):
            with self.subTest(document=document), self.assertRaises(subprocess.CalledProcessError):
                render(document)

    def test_readme_example_is_a_complete_gate_input(self):
        blocks = re.findall(r'```json\n(.*?)```', (GATE / 'README.md').read_text(), re.S)
        documents = [json.loads(block) for block in blocks if '"linux_exit"' in block]
        source = documents[0]
        self.assertIn('lan_prefixes', source)
        self.assertIn('upstream', source)
        for route in source['routes']:
            self.assertNotIn('interface', route)
            self.assertNotIn('via', route)


if __name__ == '__main__':
    unittest.main()
