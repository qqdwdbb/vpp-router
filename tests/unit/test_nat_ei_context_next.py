"""Exercise the real context node code with invalid feature next indices."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ContextNextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        repo = Path(__file__).resolve().parents[2]
        source = (repo / 'plugins/nat-ei-context/nat_ei_context.c').read_text()
        # Compile the production guard, both node functions and registrations.
        # The shim supplies only VPP's external APIs, without a running router.
        nodes = source[source.index('typedef enum'):source.index('VNET_FEATURE_INIT')]
        (root / 'nat_ei_context_nodes.inc').write_text(nodes)
        cls.binary = root / 'test-context-next'
        result = subprocess.run([
            shutil.which('cc') or 'cc', '-std=c11', '-O2', '-g',
            '-Wall', '-Wextra', '-Werror', '-Wno-sign-compare',
            '-fsanitize=address,undefined',
            '-fno-omit-frame-pointer', '-I', str(root),
            str(Path(__file__).with_suffix('.c')), '-o', str(cls.binary),
        ], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def test_invalid_next_handling(self):
        for case in ('full-frame', 'mixed', 'no-truncation',
                     'cursor-and-context', 'cursor-mismatch-valid-next',
                     'cursor-match', 'enter', 'no-worker-invalid',
                     'unmanaged-exit', 'rate-limit',
                     'return-to-rx', 'return-full-or-off',
                     'out2in-return'):
            with self.subTest(case=case):
                result = subprocess.run([str(self.binary), case],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip(), 'PASS')


if __name__ == '__main__':
    unittest.main()
