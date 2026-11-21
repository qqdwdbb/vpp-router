"""pktgen-net.sh against stub system commands; touches no real interface."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'benchmarks/pktgen/pktgen-net.sh'
STUB = r'''#!/bin/bash
echo "$(basename "$0") $*" >> "$STUB_LOG"
case "$(basename "$0") $*" in
  "id -u") echo 0 ;;
  "ip route get "*) echo "10.9.9.9 via 192.0.2.1 dev lan0 src 192.0.2.5" ;;
  "ss -Htn state established") echo "0 0 ${SS_LOCAL:-192.0.2.5:22} 10.9.9.9:50000" ;;
  "ip -o addr show to 192.0.2.5") echo "3: lan0 inet 192.0.2.5/24 scope global lan0" ;;
  "ip -4 route show default") echo "default via 192.0.2.1 dev lan0" ;;
  "ip -4 -o addr show dev wan0 scope global") echo "2: wan0 inet 10.0.0.9/24 scope global" ;;
  "ip -4 -o addr show dev lan0 scope global") echo "3: lan0 inet 192.0.2.5/24 scope global" ;;
  "nmcli -t -f RUNNING general") echo running ;;
  "nmcli -t -f DEVICE,STATE device") printf 'wan0:connected\nlan0:connected\n' ;;
  "ethtool -a wan0") printf 'Autonegotiate:\ton\nRX:\t\ton\nTX:\t\ton\n' ;;
esac
exit 0
'''
CONF = '''INTERFACES=("wan0 10.0.0.7/24" "lan0 192.0.2.5/24,192.0.2.6/24")
PAUSE_OFF=(wan0)
TTL_MINUTES=5
'''


class PktgenNet(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        stubs = self.dir / 'bin'
        stubs.mkdir()
        for name in ('ip', 'nmcli', 'ethtool', 'systemctl', 'systemd-run', 'pgrep', 'id', 'ss'):
            path = stubs / name
            path.write_text(STUB)
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
        (self.dir / 'conf').write_text(CONF)
        self.log = self.dir / 'log'
        self.state = self.dir / 'state'
        self.env = dict(os.environ, PATH=f'{stubs}:{os.environ["PATH"]}', STUB_LOG=str(self.log),
                        PKTGEN_NET_CONF=str(self.dir / 'conf'), PKTGEN_NET_STATE=str(self.state),
                        SSH_CONNECTION='')

    def run_script(self, *args, check=True):
        return subprocess.run(['bash', str(SCRIPT), *args], env=self.env, text=True,
                              capture_output=True, check=check)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_up_protects_ssh_interface_and_arms_restore(self):
        self.run_script('up')
        calls = self.calls()
        self.assertIn('ip -4 addr flush dev wan0 scope global', calls)
        self.assertIn('nmcli device set wan0 managed no', calls)
        self.assertNotIn('ip -4 addr flush dev lan0 scope global', calls)
        self.assertNotIn('nmcli device set lan0 managed no', calls)
        self.assertIn('ip addr replace 192.0.2.6/24 dev lan0', calls)
        self.assertIn('ethtool -A wan0 autoneg off rx off tx off', calls)
        self.assertTrue(any(c.startswith('systemd-run') and '--on-active=5min' in c for c in calls))

    def test_down_restores_saved_state(self):
        self.run_script('up')
        self.log.unlink()
        self.run_script('down')
        calls = self.calls()
        self.assertIn('ip addr replace 10.0.0.9/24 dev wan0', calls)
        self.assertIn('nmcli device set wan0 managed yes', calls)
        self.assertIn('ip addr del 192.0.2.6/24 dev lan0', calls)
        self.assertNotIn('ip addr del 192.0.2.5/24 dev lan0', calls)
        self.assertNotIn('ip -4 addr flush dev lan0 scope global', calls)
        self.assertIn('ethtool -A wan0 autoneg on rx on tx on', calls)
        self.assertIn('ip route replace default via 192.0.2.1 dev lan0', calls)
        self.assertFalse(self.state.exists())

    def test_up_twice_refused_and_down_idempotent(self):
        self.run_script('up')
        self.assertNotEqual(self.run_script('up', check=False).returncode, 0)
        self.run_script('down')
        self.assertEqual(self.run_script('down').returncode, 0)

    def test_protection_survives_sudo_dropping_environment(self):
        self.env.pop('SSH_CONNECTION')
        self.run_script('up')
        self.assertNotIn('ip -4 addr flush dev lan0 scope global', self.calls())

    def test_down_from_timer_keeps_protection_without_ssh(self):
        self.run_script('up')
        self.log.unlink()
        self.env['SS_LOCAL'] = '192.0.2.5:443'
        self.run_script('down')
        self.assertNotIn('ip -4 addr flush dev lan0 scope global', self.calls())
        self.assertNotIn('nmcli device set lan0 managed yes', self.calls())

    def test_conf_option(self):
        self.env.pop('PKTGEN_NET_CONF')
        self.run_script('--conf', str(self.dir / 'conf'), 'up')
        self.assertIn('ip -4 addr flush dev wan0 scope global', self.calls())

    def test_bad_ttl_changes_nothing(self):
        self.assertNotEqual(self.run_script('up', '--ttl', 'x', check=False).returncode, 0)
        self.assertFalse(any('flush' in c for c in self.calls()))
