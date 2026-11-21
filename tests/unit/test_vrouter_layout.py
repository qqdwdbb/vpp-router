import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'vrouter_layout', Path(__file__).parents[2]/'deploy/install/layout.py')
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)


def elf_fixture():
    data = bytearray(512)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<Q', data, 40, 64)
    struct.pack_into('<HHH', data, 58, 64, 3, 1)
    struct.pack_into('<IIQQQQIIQQ', data, 128, 1, 3, 0, 0, 256, 17, 0, 0, 1, 0)
    struct.pack_into('<IIQQQQIIQQ', data, 192, 11, 1, 6, 0, 300, 4, 0, 0, 4, 0)
    data[256:273] = b'\0.shstrtab\0.text\0\0'
    data[300:304] = b'code'
    return bytes(data)


class LayoutTests(unittest.TestCase):
    def test_private_strongswan_mount_needs_absolute_installed_library_path(self):
        rpath = layout.runtime_rpath(layout.RUNTIME/'ipsec-plugins/kernel.so')
        self.assertNotIn('$ORIGIN', rpath)
        self.assertIn('/usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu', rpath)
        self.assertIn('/usr/lib/ipsec', rpath)

    def test_rpath_resolves_each_runtime_directory_without_build_or_current_directory(self):
        paths = [layout.RUNTIME/'bin/vpp', layout.RUNTIME/'plugins/dpdk_plugin.so',
                 layout.RUNTIME/'lib/aarch64-linux-gnu/libvnet.so',
                 layout.RUNTIME/'lib/aarch64-linux-gnu/vpp_crypto_engines/native.so',
                 layout.DPDK/'dpdk/pmds-26.1/librte_net_r8169.so.26.1']
        for path in paths:
            with self.subTest(path=path):
                rpath = layout.runtime_rpath(path)
                self.assertNotIn('/opt/', rpath)
                self.assertNotIn('', rpath.split(':'))
        self.assertEqual(layout.runtime_rpath(paths[-1]), '$ORIGIN/../..')

    def test_atomic_relocation_preserves_mapped_inode_and_executable_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'vpp'
            path.write_bytes(elf_fixture())
            path.chmod(0o755)
            original_inode = path.stat().st_ino
            def command(*args):
                if args[1] == '--print-rpath':
                    return '/opt/old'
                temporary = Path(args[-1])
                self.assertNotEqual(temporary, path)
                self.assertEqual(path.stat().st_ino, original_inode)
                data = bytearray(temporary.read_bytes())
                data[400:404] = b'path'
                temporary.write_bytes(data)
                return ''
            before = layout.text_digest(path)
            with patch.object(layout, 'runtime_rpath', return_value='$ORIGIN'), \
                    patch.object(layout, 'run', side_effect=command):
                self.assertTrue(layout.repair_elf(path))
            self.assertNotEqual(path.stat().st_ino, original_inode)
            self.assertEqual(layout.text_digest(path), before)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)

    def test_failed_code_integrity_check_keeps_original_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'vpp'
            original = elf_fixture()
            path.write_bytes(original)
            def command(*args):
                if args[1] == '--print-rpath':
                    return '/opt/old'
                temporary = Path(args[-1])
                data = bytearray(temporary.read_bytes())
                data[300] = 0
                temporary.write_bytes(data)
                return ''
            with patch.object(layout, 'runtime_rpath', return_value='$ORIGIN'), \
                    patch.object(layout, 'run', side_effect=command):
                with self.assertRaisesRegex(ValueError, 'code changed'):
                    layout.repair_elf(path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_already_relocated_binary_is_not_rewritten(self):
        with patch.object(layout, 'runtime_rpath', return_value='$ORIGIN'), \
                patch.object(layout, 'run', return_value='$ORIGIN'), \
                patch.object(layout, 'text_digest') as digest:
            self.assertFalse(layout.repair_elf(Path('/unused')))
            digest.assert_not_called()

    def test_migration_does_not_overwrite_existing_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory)/'old', Path(directory)/'archive'
            source.write_text('source')
            destination.write_text('existing')
            with self.assertRaisesRegex(ValueError, 'already exists'):
                layout.move_tree(source, destination)
            self.assertEqual(source.read_text(), 'source')
            self.assertEqual(destination.read_text(), 'existing')

    def test_core_policy_uses_system_handler_and_bounded_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            handler = root/'usr/lib/systemd/systemd-coredump'
            handler.parent.mkdir(parents=True)
            handler.touch()
            old = root/'etc/sysctl.d/99-vpp-core.conf'
            old.parent.mkdir(parents=True)
            old.write_text('kernel.core_pattern = /var/lib/vpp-vrouter/core/core.%e.%p.%t\n')
            def local_path(value):
                return root/str(value).lstrip('/')
            with patch.object(layout, 'Path', side_effect=local_path), \
                    patch.object(layout, 'run') as command:
                layout.configure_core()
            self.assertFalse(old.exists())
            policy = (root/'etc/systemd/coredump.conf.d/60-local-limits.conf').read_text()
            self.assertIn('Storage=external\n', policy)
            self.assertIn('MaxUse=512M\n', policy)
            self.assertIn('KeepFree=1G\n', policy)
            self.assertIn('legacy-vpp 0700 root root 7d',
                          (root/'etc/tmpfiles.d/vpp-vrouter.conf').read_text())
            command.assert_any_call('sysctl', '-p', '/usr/lib/sysctl.d/50-coredump.conf')
