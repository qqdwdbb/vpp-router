import importlib.util
import base64
from pathlib import Path
from unittest.mock import patch
import unittest


PATH = Path(__file__).parents[2] / 'tools/vpp-wg-syncconf.py'
SPEC = importlib.util.spec_from_file_location('wireguard_syncconf', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def peer(key, address, keepalive=25):
    return {
        'public_key': key,
        'preshared_key': None,
        'endpoint': '0.0.0.0',
        'port': 0,
        'allowed': (address,),
        'keepalive': keepalive,
    }


class SyncconfTests(unittest.TestCase):
    def test_hostname_endpoint_is_resolved_when_source_is_parsed(self):
        private = base64.b64encode(bytes([1]) * 32).decode()
        public = base64.b64encode(bytes([2]) * 32).decode()
        source = ('[Interface]\nPrivateKey = ' + private +
                  '\nAddress = 10.62.30.2/24\nListenPort = 42006\n' +
                  '[Peer]\nPublicKey = ' + public +
                  '\nAllowedIPs = 0.0.0.0/0\n' +
                  'Endpoint = vpn.example.com:51820\n' +
                  'PersistentKeepalive = 30\n')
        with patch.object(MODULE.socket, 'getaddrinfo', return_value=[
                (MODULE.socket.AF_INET, MODULE.socket.SOCK_DGRAM, 17, '',
                 ('198.51.100.10', 51820))]):
            config, peers = MODULE.parse_wireguard(source, 'wg1')
        self.assertEqual(config['port'], 42006)
        self.assertEqual(peers[0]['endpoint'], '198.51.100.10')
        self.assertEqual(peers[0]['port'], 51820)
        self.assertEqual(peers[0]['keepalive'], 30)

    def test_unchanged_peers_are_not_touched(self):
        a = peer('A', '10.62.10.2/32')
        b = peer('B', '10.62.10.3/32')
        desired = ({}, [a, b])
        installed = ({}, {'A': a, 'B': b})
        commands, added, removed, _ = MODULE.plan(
            'wg0', desired, installed, {'A': 4, 'B': 7})
        self.assertEqual(commands, [])
        self.assertEqual((added, removed), (0, 0))

    def test_only_changed_peer_is_replaced_and_routes_follow_it(self):
        old = peer('A', '10.62.10.2/32')
        new = peer('A', '10.62.10.22/32', keepalive=10)
        commands, added, removed, _ = MODULE.plan(
            'wg0', ({}, [new]), ({}, {'A': old}), {'A': 4})
        self.assertEqual((added, removed), (1, 1))
        self.assertEqual(commands[0], 'ip route del 10.62.10.2/32 via 10.62.10.2 wg0')
        self.assertEqual(commands[1], 'wireguard peer remove 4')
        self.assertIn('wireguard peer add wg0 public-key A', commands[2])
        self.assertEqual(commands[3], 'ip route add 10.62.10.22/32 via 10.62.10.22 wg0')

    def test_interface_change_is_rejected(self):
        desired = {'private_key': 'new', 'port': 42008, 'mtu': 1420, 'addresses': ()}
        installed = {'private_key': 'old', 'port': 42008, 'mtu': 1420, 'addresses': ()}
        self.assertEqual(MODULE.interface_changed(desired, installed), ['private_key'])

    def test_live_drift_is_rejected(self):
        a = peer('A', '10.62.10.2/32')
        with self.assertRaises(RuntimeError):
            MODULE.plan('wg0', ({}, [a]), ({}, {'A': a}), {'B': 4})

if __name__ == '__main__':
    unittest.main()
