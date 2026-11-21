import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import vrouter_rx_ring_trial as trial
from vrouter_rx_ring_trial import render


class RingTrialTests(unittest.TestCase):
    def test_only_target_ring_changes(self):
        baseline=b'''buffers { buffers-per-numa 8192 }
dev 0000:02:00.0 { name nic1-dpdk num-rx-queues 1 num-tx-queues 2 }
dev 0000:01:00.0 { name nic0-dpdk num-rx-queues 1 num-tx-queues 2 rss { ipv4 ipv6 } }
'''
        self.assertEqual(render(baseline,1024),baseline)
        for ring in (2048,4096):
            changed=render(baseline,ring)
            self.assertEqual(changed.replace(f' num-rx-desc {ring}'.encode(),b''),baseline)
            self.assertEqual(changed.count(b'num-rx-desc'),1)
        for bad in [baseline+baseline,baseline.replace(b'buffers-per-numa 8192',b'buffers-per-numa 16384'),
                    baseline.replace(b' rss',b' num-rx-desc 2048 rss')]:
            with self.assertRaises(ValueError):
                render(bad,2048)
        with self.assertRaises(ValueError):
            render(baseline,8192)

    def test_restore_preserves_external_changes(self):
        baseline=b'buffers { buffers-per-numa 8192 }\nname nic0-dpdk num-rx-queues 1 num-tx-queues 2 rss { ipv4 ipv6 }\n'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'startup.conf'
            (root/'startup.original').write_bytes(baseline)
            external=baseline+b'# changed by operator\n';config.write_bytes(external)
            with patch.object(trial,'ROOT',root),patch.object(trial,'CONFIG',config):
                with self.assertRaises(RuntimeError):
                    trial.restore(dict(original_sha=trial.sha(baseline)))
            self.assertEqual(config.read_bytes(),external)


if __name__=='__main__':
    unittest.main()
