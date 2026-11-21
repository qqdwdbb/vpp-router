import runpy
import base64
import sys
import tempfile
from unittest.mock import patch
import unittest
from pathlib import Path


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.helpers = runpy.run_path(str(Path(__file__).parents[2] / 'tools/import-wireguard.py'))

    def display(self, function, value):
        function.__globals__['cli'] = lambda unused: value

    def test_missing_identity_after_dhcp_pool_change(self):
        f = self.helpers['identity_cleanup']
        self.display(f, '')
        self.assertEqual(f('host-vpp-wan', 42008, ('192.0.2.68', '192.0.2.4')), [])

    def test_identity_cleanup_matches_only_requested_port(self):
        f = self.helpers['identity_cleanup']
        self.display(f, 'identity mapping UDP 192.0.2.4:42008\n')
        self.assertEqual(len(f('host-vpp-wan', 42008, ('192.0.2.4',))), 1)
        self.assertEqual(f('host-vpp-wan', 3388, ('192.0.2.4',)), [])

    def test_peer_cleanup_is_scoped_to_interface(self):
        f = self.helpers['peer_cleanup']
        self.display(f, '[24] endpoint:[192.0.2.68:42008->0.0.0.0:0] wg0 keep-alive:25\n'
                        '[15] endpoint:[192.0.2.4:31000->198.51.100.3:32000] wg1 keep-alive:15\n')
        self.assertEqual(f('wg0'), ['wireguard peer remove 24'])


class ConverterTests(unittest.TestCase):
    def test_export_only_does_not_query_wan_or_apply_commands(self):
        helpers = runpy.run_path(str(Path(__file__).parents[2] / 'tools/import-wireguard.py'))
        main = helpers['main']
        def unexpected(unused):
            self.fail('Converter must not query VPP or apply runtime commands')
        main.__globals__['cli'] = unexpected
        main.__globals__['execute'] = unexpected
        def command(args):
            self.assertEqual(args, ['wg', 'show', 'interfaces'])
            return ''
        main.__globals__['command'] = command
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'wg0.conf'
            target = Path(directory) / 'vpp-wg0.conf'
            private = base64.b64encode(bytes([1]) * 32).decode()
            public = base64.b64encode(bytes([2]) * 32).decode()
            source.write_text('[Interface]\nPrivateKey = ' + private +
                              '\nAddress = 10.62.10.1/24\nListenPort = 42008\n' +
                              '[Peer]\nPublicKey = ' + public + '\nAllowedIPs = 10.62.10.2/32\n')
            main.__globals__['SOURCE'] = source
            with patch.object(sys, 'argv', ['converter', '--export', str(target), '--source-address', '192.0.2.1']):
                main()
            text = target.read_text()
            self.assertIn('src 192.0.2.1', text)
            self.assertIn('ip route add 10.62.10.2/32 via 10.62.10.2 wg0', text)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
