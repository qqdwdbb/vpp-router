import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('egress_nat', Path(__file__).parents[2] / 'tools/vpp-egress-nat.py')
nat = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = nat
SPEC.loader.exec_module(nat)


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state.json'
        self.generation = 'a' * 32
        self.pools = {}
        self.commands = []
        self.wan = '192.0.2.68'
        self.present_wg = True
        self.identity_ports = []
        self.identities = set()
        self.helpers = {'cli': self.cli, 'command': lambda c: self.generation, 'execute': self.execute}

    def cli(self, line):
        if line == 'show interface address':
            return f'host-vpp-wan (up):\n L3 {self.wan}/24\n' + ('wg1 (up):\n L3 10.62.30.2/24\n' if self.present_wg else '')
        if line == 'show nat44 ei interfaces':
            return ' host-vpp-wan output-feature in out\n wg1 output-feature in out\n'
        if line == 'show nat44 ei addresses':
            return ''.join(f'{ip}\n  tenant VRF: {vrf}\n' for ip, vrf in self.pools.items())
        if line == 'show nat44 ei static mappings':
            return (''.join(f'udp local 0.0.0.0:{port} external host-vpp-wan:{port} vrf -1\n'
                            for port in self.identity_ports)
                    + ''.join(f'identity mapping udp {ip}:{port} vrf 0\n' for ip, port in self.identities))
        raise AssertionError(line)

    def execute(self, lines):
        self.commands.extend(lines)
        for line in lines:
            words = line.split()
            if words[3:5] == ['identity', 'mapping']:
                item = (words[5], int(words[7]))
                if words[-1] == 'del':
                    self.identities.remove(item)
                else:
                    self.identities.add(item)
                continue
            if words[-1] == 'del':
                self.pools.pop(words[4])
            else:
                self.pools[words[4]] = int(words[-1])

    def test_add_and_idempotence(self):
        nat.reconcile(self.helpers, self.path)
        self.assertEqual(self.pools, {'10.62.30.2': 101, '192.0.2.68': 0})
        self.commands.clear()
        nat.reconcile(self.helpers, self.path)
        self.assertFalse(self.commands)

    def test_pending_identity_is_resolved_after_dhcp_and_tracks_address(self):
        self.identity_ports = [500, 4500]
        nat.reconcile(self.helpers, self.path)
        self.assertEqual(self.identities, {(self.wan, 500), (self.wan, 4500)})
        self.wan = '10.61.20.69'
        nat.reconcile(self.helpers, self.path)
        self.assertEqual(self.identities, {(self.wan, 500), (self.wan, 4500)})

    def test_dhcp_change_removes_only_owned_old_address(self):
        self.pools['198.51.100.1'] = 7
        nat.reconcile(self.helpers, self.path)
        self.wan = '10.61.20.69'
        nat.reconcile(self.helpers, self.path)
        self.assertNotIn('192.0.2.68', self.pools)
        self.assertEqual(self.pools['10.61.20.69'], 0)
        self.assertEqual(self.pools['198.51.100.1'], 7)

    def test_conflicting_vrf_aborts_before_any_mutation(self):
        self.pools['10.62.30.2'] = 3
        with self.assertRaises(RuntimeError):
            nat.reconcile(self.helpers, self.path)
        self.assertFalse(self.commands)

    def test_restart_does_not_delete_old_unowned_pool(self):
        nat.reconcile(self.helpers, self.path)
        self.generation = 'b' * 32
        self.present_wg = False
        nat.reconcile(self.helpers, self.path)
        self.assertIn('10.62.30.2', self.pools)
        self.assertEqual(json.loads(self.path.read_text())['addresses'], ['192.0.2.68'])


if __name__ == '__main__':
    unittest.main()
