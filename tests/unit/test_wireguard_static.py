import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

m = runpy.run_path(str(Path(__file__).parents[2] / 'tools/vpp-wireguard-static.py'))

CONFIG = '''wireguard create instance 0 listen-port 42008 private-key SECRET src 10.61.10.4
set interface ip address wg0 10.62.10.1/24
wireguard peer add wg0 public-key PUBLIC endpoint 0.0.0.0 dst-port 0 allowed-ip 10.62.10.2/32
ip route add 10.62.10.2/32 via 10.62.10.2 wg0
set interface state wg0 up
'''


class StaticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        (self.directory / 'wg0.conf').write_text(CONFIG)
        self.exists = False
        self.executed = []
        self.commands = []
        self.peers = '[0] endpoint:[10.61.10.4:42008->0.0.0.0:0] wg0 keep-alive:25\n public-key PUBLIC\n'
        self.helpers = dict(cli=self.cli, execute=self.execute, command=self.command,
                            peer_cleanup=lambda i: [], identity_cleanup=lambda *args: [])

    def command(self, args):
        self.commands.append(args)
        return 'a' * 32 if args[0] == 'systemctl' else ''

    def cli(self, line):
        if line == 'show interface':
            return 'wg0 1 up\n' if self.exists else ''
        if line == 'show interface address':
            return 'wg0 (up):\n L3 10.62.10.1/24\n' if self.exists else ''
        if line == 'show nat44 ei addresses':
            return ''
        if line == 'show wireguard peer':
            return self.peers
        raise AssertionError('Unexpected runtime dependency: ' + line)

    def execute(self, lines):
        self.executed.append(lines)
        self.exists = True

    def load(self, **kwargs):
        m['load']('wg0', self.helpers, self.directory, self.directory, **kwargs)

    def test_load_without_wan_or_linux_wireguard_configuration(self):
        self.load()
        self.assertEqual(self.executed, [CONFIG.splitlines()])
        state = json.loads((self.directory / 'wg0-static.json').read_text())
        self.assertNotIn('SECRET', json.dumps(state))
        self.assertEqual(state['route_cleanup'], ['ip route del 10.62.10.2/32 via 10.62.10.2 wg0'])

    def test_repeated_start_does_not_rebuild(self):
        self.load()
        self.executed.clear()
        self.load()
        self.assertEqual(self.executed, [])

    def test_changed_file_requires_explicit_replace(self):
        self.load()
        (self.directory / 'wg0.conf').write_text(CONFIG + '# changed\n')
        self.executed.clear()
        with self.assertRaises(RuntimeError):
            self.load()
        self.assertEqual(self.executed, [])

    def test_replace_is_explicit_and_removes_old_host_routes(self):
        self.load()
        (self.directory / 'wg0.conf').write_text(CONFIG + '# changed\n')
        self.executed.clear()
        self.load(replace=True)
        self.assertEqual(len(self.executed), 2)
        self.assertIn('wireguard delete wg0', self.executed[0])
        self.assertIn('ip route del 10.62.10.2/32 via 10.62.10.2 wg0', self.executed[0])

    def test_adopt_preserves_live_interface(self):
        self.exists = True
        self.load(adopt=True)
        self.assertEqual(self.executed, [])

    def test_wg0_replace_detaches_nat66_before_delete_and_reattaches(self):
        self.load()
        (self.directory / 'wg0.conf').write_text(CONFIG + '# changed\n')
        self.executed.clear()
        exists = Path.exists
        with patch.object(Path, 'exists', lambda p: str(p) == '/etc/vpp/wg0-nat66.conf' or exists(p)):
            self.load(replace=True)
        cleanup = self.executed[0]
        self.assertLess(cleanup.index('set interface nat66 in wg0 del'), cleanup.index('wireguard delete wg0'))
        self.assertEqual(self.executed[-1], ['set interface nat66 in wg0'])

    def test_adopt_rejects_different_peers(self):
        self.exists = True
        self.peers = ''
        with self.assertRaises(RuntimeError):
            self.load(adopt=True)
        self.assertFalse((self.directory / 'wg0-static.json').exists())

    def test_wrong_instance_rejected_before_commands(self):
        (self.directory / 'wg0.conf').write_text(CONFIG.replace('instance 0', 'instance 1'))
        with self.assertRaises(RuntimeError):
            self.load()
        self.assertEqual(self.executed, [])


if __name__ == '__main__':
    unittest.main()
