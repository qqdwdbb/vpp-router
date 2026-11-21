"""Check what uninstall.py removes, and above all what it leaves alone."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest

GATE = Path(__file__).resolve().parents[2] / 'tools/vpp-egress-gate'
EXEC = 'exec /var/lib/vpp-egress-gate/vpp-devices.cli'


def load():
    sys.path.insert(0, str(GATE))
    try:
        spec = importlib.util.spec_from_file_location('gate_uninstall', GATE / 'uninstall.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class FakeIP:
    """Answers ip's listings and logs everything that is run."""

    def __init__(self, rules=(), routes=(), links=()):
        self.rules, self.routes, self.links, self.log = list(rules), list(routes), list(links), []

    def __call__(self, *args):
        text = ' '.join(args)
        self.log.append(text)
        if 'rule show' in text:
            return json.dumps(self.rules)
        if 'table all' in text:
            return json.dumps(self.routes)
        if 'link show' in text:
            return json.dumps(self.links)
        return ''

    def changes(self):
        return [line for line in self.log if ' show' not in line]


class Uninstall(unittest.TestCase):
    def setUp(self):
        self.module = load()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def fake(self, **kwargs):
        fake = FakeIP(**kwargs)
        self.module.run = fake
        self.module.ip_json = lambda *args: json.loads(fake('ip', '-j', *args) or '[]')
        return fake

    def test_only_the_exec_line_leaves_the_cli_file(self):
        cli = self.root / 'router.cli'
        cli.write_text(f'one\n{EXEC}\ntwo\n')
        cli.chmod(0o640)
        self.module.remove_exec_line(cli)
        self.assertEqual(cli.read_text(), 'one\ntwo\n')
        self.assertEqual(cli.stat().st_mode & 0o777, 0o640)
        self.assertEqual([path.name for path in self.root.iterdir()], ['router.cli'])

    def test_backup_goes_only_when_nothing_changed(self):
        notes = []
        cli = self.root / 'router.cli'
        backup = self.root / 'router.cli.gate-backup'
        cli.write_text('one\n')
        backup.write_text('one')
        self.module.remove_backup(cli, notes)
        self.assertFalse(backup.exists())
        self.assertEqual(notes, [])
        backup.write_text('one\n')
        cli.write_text('one\nedited later\n')
        self.module.remove_backup(cli, notes)
        self.assertTrue(backup.exists())
        self.assertIn('kept', notes[0])

    def test_refuses_a_file_that_does_not_run_the_devices(self):
        marker = self.root / 'vpp-devices.cli'
        marker.touch()
        self.module.DEVICE_CLI = marker
        cli = self.root / 'other.cli'
        cli.write_text('one\n')
        with self.assertRaisesRegex(ValueError, '--vpp-cli-file'):
            self.module.check_cli_file(cli)
        with self.assertRaisesRegex(ValueError, '--vpp-cli-file'):
            self.module.check_cli_file(self.root / 'absent.cli')

    def test_a_retry_after_the_line_went_is_accepted(self):
        marker = self.root / 'vpp-devices.cli'
        marker.touch()
        self.module.DEVICE_CLI = marker
        cli = self.root / 'router.cli'
        cli.write_text('one\n')
        (self.root / 'router.cli.gate-backup').write_text('one\n')
        self.module.check_cli_file(cli)

    def test_rules_of_others_stay(self):
        fake = self.fake(rules=[
            {'priority': 0, 'table': '255'},
            {'priority': 11101, 'iif': 'tap-wg1', 'fwmark': '0x65', 'table': '1101'},
            {'priority': 11101, 'iif': 'lo', 'fwmark': '0x65', 'table': '1101'},
            {'priority': 12101, 'iif': 'wg1', 'table': '2101'},
            {'priority': 12101, 'iif': 'eth5', 'table': '777'},
            {'priority': 32766, 'table': '254'},
        ])
        self.module.remove_rules({11101, 12101}, {1101, 2101})
        changes = [line for line in fake.changes() if line.startswith('ip -4')]
        self.assertEqual(changes, [
            'ip -4 rule del priority 11101 iif tap-wg1 fwmark 0x65 lookup 1101',
            'ip -4 rule del priority 11101 iif lo fwmark 0x65 lookup 1101',
            'ip -4 rule del priority 12101 iif wg1 lookup 2101'])

    def test_an_empty_table_is_not_flushed(self):
        # Some kernels report flushing a table without routes as an error.
        fake = self.fake(routes=[{'dst': 'default', 'table': '1101'}, {'dst': 'default', 'table': '999'}, {'dst': '10.0.0.0/8'}])
        self.module.remove_tables({1101, 2101})
        self.assertEqual(fake.changes(), ['ip -4 route flush table 1101', 'ip -6 route flush table 1101'])

    def test_device_tables(self):
        self.assertEqual(self.module.device_tables({'host': 'tap-wg1', 'table': 1101, 'priority': 11101, 'return_table': 2101, 'return_priority': 12101}),
                         ({11101, 12101}, {1101, 2101}))
        self.assertEqual(self.module.device_tables({'host': 'gw-eth1', 'shared_tap': True}), (set(), set()))
        self.assertEqual(self.module.device_tables({'host': 'gate-tproxy'}), ({11002}, {1002}))

    def test_a_held_device_is_reported_and_stays(self):
        fake = self.fake(links=[{'ifname': 'tap-wg1', 'linkinfo': {'info_kind': 'tun', 'info_data': {'numqueues': 4}}}])
        self.assertEqual(self.module.remove_links([{'host': 'tap-wg1'}], []), ['tap-wg1'])
        self.assertEqual(fake.changes(), [])

    def test_a_link_of_another_kind_stays(self):
        fake = self.fake(links=[{'ifname': 'tap-wg1', 'linkinfo': {'info_kind': 'bridge'}}])
        notes = []
        self.assertEqual(self.module.remove_links([{'host': 'tap-wg1'}], notes), [])
        self.assertEqual(fake.changes(), [])
        self.assertIn('stays', notes[0])

    def test_children_go_before_their_tap(self):
        fake = self.fake(links=[{'ifname': 'gw-eth1', 'linkinfo': {'info_kind': 'tun', 'info_data': {'numqueues': 0}}},
                                {'ifname': 'gm-a', 'linkinfo': {'info_kind': 'macvlan'}}])
        self.module.remove_links([{'host': 'gw-eth1', 'shared_tap': True}, {'host': 'gm-a', 'parent': 'gw-eth1'}], [])
        self.assertEqual(fake.changes(), ['ip link delete dev gm-a', 'ip link delete dev gw-eth1'])

    def write_settings(self, *settings):
        path = self.root / 'host-settings.json'
        path.write_text(json.dumps({'settings': list(settings)}))
        self.module.HOST_SETTINGS = path
        self.module.SYSCTL_ROOT = self.root / 'sys'

    def sysctl(self, name, value):
        path = self.root / 'sys' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + '\n')
        return path

    def test_settings_go_back_unless_something_else_changed_them(self):
        self.write_settings({'name': 'ip_forward', 'was': '0', 'set': '1'}, {'name': 'rp', 'was': '2', 'set': '0'},
                            {'name': 'gone', 'was': '2', 'set': '0'}, {'name': 'same', 'was': '2', 'set': '0'})
        forward, rp, same = self.sysctl('ip_forward', '1'), self.sysctl('rp', '1'), self.sysctl('same', '2')
        notes = []
        self.module.restore_host_settings(True, notes)
        self.assertEqual(forward.read_text(), '0\n')
        self.assertEqual(rp.read_text(), '1\n')
        self.assertEqual(same.read_text(), '2\n')
        self.assertEqual(len(notes), 1)
        self.assertIn('rp stays at 1', notes[0])

    def test_settings_go_back_in_reverse_order(self):
        self.write_settings({'name': 'accept_ra', 'was': '1', 'set': '2'}, {'name': 'forwarding', 'was': '0', 'set': '1'})
        order = []
        for name, value in (('accept_ra', '2'), ('forwarding', '1')):
            self.sysctl(name, value)
        real = Path.write_text
        def spy(path, text, *args, **kwargs):
            order.append(path.name)
            return real(path, text, *args, **kwargs)
        Path.write_text = spy
        self.addCleanup(setattr, Path, 'write_text', real)
        self.module.restore_host_settings(True, [])
        self.assertEqual(order, ['forwarding', 'accept_ra'])

    def test_older_installs_say_nothing_can_be_restored(self):
        self.module.HOST_SETTINGS = self.root / 'absent.json'
        notes = []
        self.module.restore_host_settings(False, notes)
        self.assertEqual(notes, [])
        self.module.restore_host_settings(True, notes)
        self.assertIn('ip_forward', notes[0])

    def test_files_of_others_stay(self):
        ours, theirs = self.root / 'd/ours.conf', self.root / 'd/theirs.conf'
        ours.parent.mkdir()
        ours.write_text(self.module.MARKER + 'x\n')
        theirs.write_text('# mine\n')
        self.module.install_files = lambda service: {ours: '', theirs: ''}
        self.fake()
        self.module.service_active = lambda name: False
        notes = []
        self.module.remove_install_files(notes)
        self.assertFalse(ours.exists())
        self.assertEqual(theirs.read_text(), '# mine\n')
        self.assertIn('kept', notes[0])

    def test_the_rules_are_not_listed_for_removal(self):
        for path in self.module.install_files('vpp.service'):
            self.assertNotIn('egress-gate.json', str(path))
        source = (GATE / 'uninstall.py').read_text()
        self.assertNotIn('rmtree(DOMAIN_DIR', source)
        self.assertNotIn('USER_CONFIG.unlink', source)

    def test_vpp_is_never_restarted(self):
        source = (GATE / 'uninstall.py').read_text()
        for word in ("'restart', vpp", "'stop', vpp", 'reboot'):
            self.assertNotIn(word, source)


if __name__ == '__main__':
    unittest.main()
