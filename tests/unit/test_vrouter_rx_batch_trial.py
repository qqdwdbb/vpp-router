import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import vrouter_rx_batch_trial as trial


class BatchTrialTests(unittest.TestCase):
    def test_restore_preserves_operator_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);build=root/'build';build.mkdir()
            pmd=root/'pmd';plugin=root/'plugin'
            pmd.write_bytes(b'operator replacement');plugin.write_bytes(b'original plugin')
            (root/'pmd.original').write_bytes(b'original pmd');(root/'plugin.original').write_bytes(b'original plugin')
            variants={}
            for name in ['read','rearm2','rearm8']:
                candidate=build/name;candidate.write_bytes(name.encode())
                variants[name]=dict(pmd=str(candidate),pmd_sha=trial.sha(candidate.read_bytes()))
            plugin64=build/'plugin64';plugin64.write_bytes(b'64')
            (build/'manifest.json').write_text(json.dumps(dict(variants=variants,plugin64=dict(path=str(plugin64),sha=trial.sha(b'64')))))
            with patch.object(trial,'ROOT',root),patch.object(trial,'BUILD',build),patch.object(trial,'PMD',pmd),patch.object(trial,'PLUGIN',plugin):
                with self.assertRaises(RuntimeError):trial.restore({})
            self.assertEqual(pmd.read_bytes(),b'operator replacement')
            self.assertEqual(plugin.read_bytes(),b'original plugin')


if __name__=='__main__':unittest.main()
