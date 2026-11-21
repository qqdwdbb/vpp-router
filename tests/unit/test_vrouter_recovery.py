import contextlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'vrouter_recovery', Path(__file__).parents[2]/'deploy/install/recovery.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(recovery, 'BASELINE', {'files': {}}))
        for name, relative in (('STATE', 'state'), ('STORE', 'state/recovery'),
                               ('RUNTIME', 'runtime'), ('CONFIG', 'config'),
                               ('SYSTEMD', 'units'), ('LATCH', 'state/linux/active')):
            self.stack.enter_context(patch.object(recovery, name, self.root/relative))
        (recovery.STORE/'generations').mkdir(parents=True)
        (recovery.STATE/'baseline').mkdir()
        recovery.RUNTIME.mkdir()
        (recovery.RUNTIME/'router').write_bytes(b'current-code')
        (recovery.STATE/'installation.json').write_text(json.dumps(
            dict(phase='confirmed', units=['vrouter-vpp.service'],
                 recovery_bundle='/old/pre-fhs', previous_bundle='/old/trial')))

    def generation(self):
        generation = recovery.STORE/'generations/accepted'
        tree = generation/'tree'
        destination = tree/str(recovery.RUNTIME).lstrip('/')
        destination.parent.mkdir(parents=True)
        recovery.copy_snapshot(recovery.RUNTIME, destination)
        manifest = dict(kernel=recovery.platform.release(), architecture=recovery.platform.machine(),
                        roots=[str(recovery.RUNTIME)], files=recovery.inventory(tree), units=[])
        recovery.write_json(generation/'manifest.json', manifest)
        (recovery.STORE/'current').symlink_to('generations/accepted')
        return generation

    def snapshot_mocks(self, health=None):
        self.stack.enter_context(patch.object(recovery, 'health', side_effect=health))
        self.stack.enter_context(patch.object(recovery, 'runtime_baseline', return_value=
                                             dict(links={'br0': {'mac': '02:00:00:00:00:01'}}, routes4=[])))
        self.stack.enter_context(patch.object(recovery, 'scopes', return_value=[recovery.RUNTIME]))
        self.stack.enter_context(patch.object(recovery, 'run', return_value='current'))

    def test_missing_live_files_can_be_recovered_from_verified_snapshot(self):
        generation = self.generation()
        (recovery.RUNTIME/'router').unlink()
        recovery.RUNTIME.rmdir()
        self.assertEqual(recovery.verify()[0], generation)

    def test_corrupted_snapshot_is_rejected_before_stopping_services(self):
        generation = self.generation()
        (generation/'tree'/str(recovery.RUNTIME/'router').lstrip('/')).write_bytes(b'bad')
        with patch.object(recovery, 'run') as command:
            with self.assertRaisesRegex(ValueError, 'content differs'):
                recovery.restore()
            command.assert_not_called()

    def test_internally_valid_old_baseline_is_rejected_before_stopping_services(self):
        generation = self.generation()
        manifest = json.loads((generation/'manifest.json').read_text())
        name = str(recovery.RUNTIME/'router').lstrip('/')
        for files in ({name: 'different-accepted-hash'}, {'missing-plugin.so': 'required-hash'}):
            with self.subTest(files=files), patch.object(recovery, 'BASELINE', {'files': files}), \
                    patch.object(recovery, 'run') as command:
                with self.assertRaisesRegex(ValueError, 'accepted baseline'):
                    recovery.restore()
                command.assert_not_called()
        with patch.object(recovery, 'BASELINE', {'files': {name: manifest['files'][name]['sha256']}}):
            recovery.verify()

    def test_payload_members_cannot_escape_or_traverse_symlinks(self):
        tree = self.root/'payload'
        tree.mkdir()
        (tree/'link').symlink_to(self.root)
        for name in ('../outside', '/etc/passwd', 'link/outside'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                recovery.member(tree, name)

    def test_manifest_cannot_replace_unmanaged_system_directories(self):
        self.assertFalse(recovery.permitted_root('/etc'))
        self.assertFalse(recovery.permitted_root('/usr'))
        self.assertFalse(recovery.permitted_root(str(recovery.SYSTEMD/'vrouter-test/../../etc')))
        self.assertTrue(recovery.permitted_root(str(recovery.SYSTEMD/'vrouter-vpp.service.d')))

    def test_restore_removes_later_dropins_but_keeps_unmanaged_neighbours(self):
        source, destination = self.root/'saved', self.root/'live'
        source.mkdir(); destination.mkdir()
        (source/'accepted.conf').write_text('good')
        (destination/'accepted.conf').write_text('changed')
        (destination/'failed-upgrade.conf').write_text('bad')
        neighbour = self.root/'unmanaged.conf'
        neighbour.write_text('keep')
        recovery.restore_path(source, destination)
        self.assertEqual((destination/'accepted.conf').read_text(), 'good')
        self.assertFalse((destination/'failed-upgrade.conf').exists())
        self.assertEqual(neighbour.read_text(), 'keep')

    def test_atomic_file_restore_keeps_existing_open_inode_valid(self):
        source, destination = self.root/'saved', self.root/'live'
        source.write_bytes(b'accepted'); source.chmod(0o600)
        destination.write_bytes(b'old')
        with destination.open('rb') as old:
            recovery.restore_path(source, destination)
            self.assertEqual(old.read(), b'old')
        self.assertEqual(destination.read_bytes(), b'accepted')
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_symlink_restore_does_not_overwrite_its_old_target(self):
        source, destination = self.root/'saved', self.root/'live'
        target = self.root/'other'; target.write_text('keep')
        destination.symlink_to(target)
        source.write_text('new')
        recovery.restore_path(source, destination)
        self.assertFalse(destination.is_symlink())
        self.assertEqual(target.read_text(), 'keep')

    def test_snapshot_failure_does_not_replace_the_accepted_generation(self):
        accepted = self.generation()
        self.snapshot_mocks(health=[None, RuntimeError('unhealthy')])
        with self.assertRaisesRegex(RuntimeError, 'unhealthy'):
            recovery.snapshot()
        self.assertEqual((recovery.STORE/'current').resolve(), accepted)
        self.assertEqual(list((recovery.STORE/'generations').iterdir()), [accepted])

    def test_snapshot_replaces_legacy_record_only_after_verification(self):
        accepted = self.generation()
        self.snapshot_mocks()
        recovery.snapshot()
        record = json.loads((recovery.STATE/'installation.json').read_text())
        self.assertNotIn('recovery_bundle', record)
        self.assertNotIn('previous_bundle', record)
        self.assertEqual(record['recovery'], str(recovery.STORE/'current'))
        self.assertFalse(accepted.exists())
        self.assertEqual(len(list((recovery.STORE/'generations').iterdir())), 1)
        recovery.verify()

    def test_linux_fallback_cannot_be_saved_as_a_healthy_vpp_baseline(self):
        recovery.LATCH.parent.mkdir(); recovery.LATCH.touch()
        with patch.object(recovery, 'health') as check:
            with self.assertRaisesRegex(RuntimeError, 'Linux fallback'):
                recovery.snapshot()
            check.assert_not_called()

    def test_zero_gateway_replies_are_not_accepted_as_health(self):
        with patch.object(recovery, 'run', return_value='3 sent, 0 received, 100% packet loss'):
            with self.assertRaisesRegex(RuntimeError, 'WAN gateway'):
                recovery.health(units=[], wan_timeout=0)

    def test_restore_reconciles_explicit_boot_enablement(self):
        with patch.object(recovery, 'run') as command:
            recovery.restore_enabled({'router.service': 'enabled', 'dns.service': 'disabled',
                                      'helper.service': 'static'})
        self.assertEqual([c.args for c in command.call_args_list],
                         [('systemctl', 'enable', 'router.service'),
                          ('systemctl', 'disable', 'dns.service')])
