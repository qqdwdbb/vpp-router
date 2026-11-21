import os
from pathlib import Path
import runpy
import tempfile
import unittest

m = runpy.run_path(str(Path(__file__).parents[2] / 'tools/install-wireguard.py'))


class InstallerTests(unittest.TestCase):
    def test_boot_block_preserves_existing_configuration(self):
        text = 'nat44 plugin enable sessions 65536\n'
        updated = m['block'](text, 'VPP WIREGUARD', ['exec /etc/vpp/wireguard/wg0.conf'])
        self.assertTrue(updated.startswith(text))
        self.assertEqual(updated.count('exec /etc/vpp/wireguard/wg0.conf'), 1)
        self.assertEqual(m['block'](updated, 'VPP WIREGUARD', ['exec /etc/vpp/wireguard/wg0.conf']), updated)

    def test_block_update_replaces_only_owned_content(self):
        old = m['block']('before\n', 'VPP WIREGUARD', ['old']) + 'after\n'
        new = m['block'](old, 'VPP WIREGUARD', ['new'])
        self.assertNotIn('\nold\n', new)
        self.assertIn('\nnew\n', new)
        self.assertTrue(new.startswith('before\n'))
        self.assertTrue(new.endswith('after\n'))

    def test_incomplete_block_rejected(self):
        with self.assertRaises(RuntimeError):
            m['block']('# BEGIN VPP WIREGUARD\n', 'VPP WIREGUARD', ['new'])

    def test_write_preserves_mode_and_does_not_follow_existing_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'configuration'
            m['write'](path, 'value', 0o600)
            self.assertEqual(path.read_text(), 'value')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.with_name(path.name + '.new').symlink_to(path)
            with self.assertRaises(FileExistsError):
                m['write'](path, 'replacement', 0o600)
            self.assertEqual(path.read_text(), 'value')

    def test_source_is_explicit_or_from_installed_file_without_wan_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wg0.conf'
            with self.assertRaises(RuntimeError):
                m['source_address'](None, path, None, 'wg0')
            self.assertEqual(m['source_address']('10.61.10.4', path, None, 'wg0'), '10.61.10.4')
            path.write_text('configuration')
            describe = lambda text, interface: ([], {'source': '192.0.2.1'})
            self.assertEqual(m['source_address'](None, path, describe, 'wg0'), '192.0.2.1')


if __name__ == '__main__':
    unittest.main()
