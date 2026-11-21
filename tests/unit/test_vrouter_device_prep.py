import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[2]/'deploy/startup'
spec = importlib.util.spec_from_file_location('device_prep', ROOT/'vrouter-vpp-device-prep.py')
device = importlib.util.module_from_spec(spec)
spec.loader.exec_module(device)


class DevicePrepTests(unittest.TestCase):
    def fixture(self, root):
        pci = root/'0000:01:00.0'
        pci.mkdir()
        (pci/'vendor').write_text('0x10ec\n')
        (pci/'device').write_text('0x8125\n')
        (pci/'driver').symlink_to(root/'uio_pci_generic')
        (pci/'net').mkdir()
        (pci/'net/nic0').touch()
        return pci

    def test_kernel_initializes_only_link_before_returning_to_uio(self):
        with tempfile.TemporaryDirectory() as directory:
            pci = self.fixture(Path(directory))
            with patch.object(device, 'run') as run, patch.object(device, 'bind') as bind, \
                    patch.object(device.time, 'sleep'):
                device.prepare(pci)
                self.assertEqual([call.args for call in bind.call_args_list],
                                 [(pci, 'r8125'), (pci, 'uio_pci_generic')])
                self.assertEqual([call.args for call in run.call_args_list],
                                 [('modprobe', 'r8125'), ('ip', 'link', 'set', 'nic0', 'up')])

    def test_failure_returns_device_to_uio(self):
        with tempfile.TemporaryDirectory() as directory:
            pci = self.fixture(Path(directory))
            with patch.object(device, 'run', side_effect=[None, RuntimeError('link failed')]), \
                    patch.object(device, 'bind') as bind:
                with self.assertRaisesRegex(RuntimeError, 'link failed'):
                    device.prepare(pci)
                self.assertEqual(bind.call_args.args, (pci, 'uio_pci_generic'))

    def test_unexpected_device_is_not_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            pci = self.fixture(Path(directory))
            (pci/'vendor').write_text('0x1234')
            with patch.object(device, 'run') as run, patch.object(device, 'bind') as bind:
                with self.assertRaisesRegex(RuntimeError, 'Unexpected WAN PCI'):
                    device.prepare(pci)
                run.assert_not_called()
                bind.assert_not_called()
