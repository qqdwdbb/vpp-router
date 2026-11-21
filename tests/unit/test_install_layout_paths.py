"""Installed paths must not follow the repository layout."""
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('stage_source', ROOT / 'deploy/install/stage-source.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class InstalledPaths(unittest.TestCase):
    def test_runtime_references_use_installed_layout(self):
        for name in ('recovery.py', 'activate.py'):
            text = (ROOT / 'deploy/install' / name).read_text()
            self.assertIsNone(re.search(r"(RUNTIME|HERE\.parent)/'deploy/", text), name)
            self.assertIn("scripts/vrouter/", text, name)
        self.assertIn("SOURCE.glob('scripts/**/*')", (ROOT / 'deploy/cutover/prepare.py').read_text())

    def test_stage_creates_installed_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            output = stage.stage(Path(directory) / 'source')
            self.assertTrue((output / 'scripts/vrouter/cutover/prepare.py').is_file())
            self.assertTrue((output / 'scripts/vrouter/install/recovery.py').is_file())
            self.assertTrue((output / 'scripts/ipsec/ipsec-prefix-sync.py').is_file())
            self.assertTrue((output / 'plugins/nat-ei-context/nat_ei_context.c').is_file())
            with self.assertRaises(SystemExit):
                stage.stage(output)

    def test_stage_excludes_local_files_and_renders_requested_benchmarks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repo'
            output = Path(directory) / 'source'
            for name in ('deploy', 'tools', 'plugins', 'patches', 'platforms', 'benchmarks'):
                (root / name).mkdir(parents=True)
            (root / 'deploy' / 'router.json').write_text('{"interface": "nic0"}')
            (root / 'deploy' / 'private.profile.json').write_text('{"replace": {"nic0": "port0"}}')
            (root / 'deploy' / 'host.key').touch()
            (root / 'tools' / 'dist').mkdir()
            (root / 'tools' / 'dist' / 'local-build').touch()
            (root / 'tools' / 'linked-key').symlink_to(root / 'deploy' / 'host.key')
            (root / 'benchmarks' / 'bench.sh').write_text('ip link show nic0\n')

            stage.stage(output, root=root, profile={'replace': {'nic0': 'port0'}}, with_benchmarks=True)

            self.assertEqual((output / 'scripts/vrouter/router.json').read_text(), '{"interface": "port0"}')
            self.assertEqual((output / 'benchmarks/bench.sh').read_text(), 'ip link show port0\n')
            for name in ('scripts/vrouter/private.profile.json', 'scripts/vrouter/host.key',
                         'scripts/dist', 'scripts/linked-key'):
                self.assertFalse((output / name).exists())
