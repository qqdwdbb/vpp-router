"""The LAN dnsmasq configuration: managed lines edited in place, and the import of the system dnsmasq."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).parents[2] / 'deploy/install/dnsmasq-lan.py'
LAN = '10.61.30.1/24'
SET = ['--listen', '10.61.30.2', '--range', '10.61.30.100,10.61.30.200,255.255.255.0,12h',
       '--router', '10.61.30.1']


class DnsmasqLanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.conf = self.root / 'etc-vpp/dnsmasq.conf'
        self.hosts = self.root / 'etc-vpp/dhcp-hosts'
        self.leases = self.root / 'state/dnsmasq.leases'

    def tearDown(self):
        self.temp.cleanup()

    def run_tool(self, *args, check=True):
        # Without dnsmasq on PATH the --test step is skipped, so the tests do not depend on it.
        env = dict(os.environ, PATH='/usr/bin:/bin')
        result = subprocess.run([sys.executable, '-I', str(SCRIPT), *args], capture_output=True, text=True, env=env)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def set(self, *extra):
        return self.run_tool('set', '--conf', str(self.conf), '--hostsfile', str(self.hosts),
                             '--leasefile', str(self.leases), *SET, *extra)

    def test_a_new_file_holds_the_managed_lines_and_a_hosts_file(self):
        self.set()
        lines = self.conf.read_text().splitlines()
        for line in ('interface=vpp-host', 'bind-interfaces', 'listen-address=10.61.30.2',
                     'dhcp-range=10.61.30.100,10.61.30.200,255.255.255.0,12h', 'dhcp-option=option:router,10.61.30.1',
                     'dhcp-option=option:dns-server,10.61.30.2', f'dhcp-hostsfile={self.hosts}', 'cache-size=1000'):
            self.assertIn(line, lines)
        self.assertTrue(self.hosts.exists())

    def test_set_repairs_hosts_access_after_dnsmasq_drops_privileges(self):
        self.hosts.parent.mkdir(parents=True, mode=0o700)
        self.hosts.write_text("02:00:00:00:10:01,10.61.30.20,nas\n")
        self.hosts.chmod(0o600)
        secret = self.hosts.parent / "secret"
        secret.write_text("private")
        secret.chmod(0o600)
        self.set()
        self.assertEqual(self.hosts.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.hosts.parent.stat().st_mode & 0o777, 0o701)
        self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
        self.assertIn("10.61.30.20", self.hosts.read_text())

    def test_managed_lines_change_in_place_and_others_stay(self):
        self.conf.parent.mkdir(parents=True)
        self.conf.write_text('# mine\nlocal=/lan/\ndhcp-range=10.61.30.50,10.61.30.60,1h\n'
                             'dhcp-option=tag:phones,option:dns-server,10.61.30.9\n'
                             'dhcp-range=::,constructor:vpp-host,ra-stateless\n'
                             'dhcp-option=6,1.1.1.1\nbind-dynamic\naddress=/nas.lan/10.61.30.20\n')
        self.set()
        lines = self.conf.read_text().splitlines()
        self.assertEqual(lines[:2], ['# mine', 'local=/lan/'])
        self.assertEqual(lines[2], 'interface=vpp-host')
        for kept in ('dhcp-option=tag:phones,option:dns-server,10.61.30.9', 'dhcp-range=::,constructor:vpp-host,ra-stateless',
                     'address=/nas.lan/10.61.30.20'):
            self.assertIn(kept, lines)
        for gone in ('dhcp-range=10.61.30.50,10.61.30.60,1h', 'dhcp-option=6,1.1.1.1', 'bind-dynamic'):
            self.assertNotIn(gone, lines)
        self.assertEqual(sum(l.startswith('dhcp-range=10.') for l in lines), 1)
        before = self.conf.read_text()
        self.set()
        self.assertEqual(self.conf.read_text(), before)

    def test_the_panel_script_is_managed_only_when_given(self):
        self.conf.parent.mkdir(parents=True)
        self.conf.write_text('dhcp-script=/usr/local/bin/mine\n')
        self.set()
        self.assertIn('dhcp-script=/usr/local/bin/mine', self.conf.read_text())
        self.set('--script', '/usr/local/bin/vpp-interfaces')
        lines = self.conf.read_text().splitlines()
        self.assertIn('dhcp-script=/usr/local/bin/vpp-interfaces', lines)
        self.assertNotIn('dhcp-script=/usr/local/bin/mine', lines)
        # Without dnsmasq on PATH its support for script-on-renewal is unknown, so it is left out.
        self.assertNotIn('script-on-renewal', lines)

    def test_the_old_generated_header_is_replaced(self):
        self.conf.parent.mkdir(parents=True)
        self.conf.write_text('# 由 vpp-router-install.sh 生成；只在 vpp-host 上提供 DHCP 和 DNS\n'
                             'interface=vpp-host\ndhcp-range=10.61.30.100,10.61.30.200,255.255.255.0,12h\ncache-size=1000\n'
                             '# 由 vpp-router-install.sh 生成；只在 vpp-host 上提供 DHCP 和 DNS\n')
        self.set()
        lines = self.conf.read_text().splitlines()
        self.assertTrue(lines[0].startswith('# VPP 路由器 LAN 的 dnsmasq'))
        self.assertEqual(lines.count('# 由 vpp-router-install.sh 生成；只在 vpp-host 上提供 DHCP 和 DNS'), 1)
        self.assertEqual(lines[2], 'interface=vpp-host')
        before = self.conf.read_text()
        self.set()
        self.assertEqual(self.conf.read_text(), before)

    def test_range_is_read_back_for_the_next_run(self):
        self.set()
        self.assertEqual(self.run_tool('range', '--conf', str(self.conf)).stdout.split(),
                         ['10.61.30.100', '10.61.30.200', '255.255.255.0', '12h'])
        self.conf.write_text('dhcp-range=set:vpp-lan,10.61.30.10,10.61.30.20\n')
        self.assertEqual(self.run_tool('range', '--conf', str(self.conf)).stdout.split(),
                         ['10.61.30.10', '10.61.30.20', '-', '1h'])
        self.assertEqual(self.run_tool('range', '--conf', str(self.root / 'none')).stdout, '')

    def test_bad_values_are_refused(self):
        result = self.run_tool('set', '--conf', str(self.conf), '--hostsfile', str(self.hosts), '--listen', '10.61.30.2',
                               '--range', '10.61.30.100,10.61.30.200,255.255.255.0,soon', '--router', '10.61.30.1', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('租期', result.stderr)
        self.assertFalse(self.conf.exists())

    def system(self):
        """A system dnsmasq: a main file, a conf-dir, a hosts file and a lease file."""
        sysdir = self.root / 'etc'
        (sysdir / 'dnsmasq.d').mkdir(parents=True)
        lease = self.root / 'misc.leases'
        (sysdir / 'hosts.dhcp').write_text('02:00:00:00:20:02,10.61.30.21,printer\n02:00:00:00:20:03,10.9.9.9,away\n')
        (sysdir / 'dnsmasq.conf').write_text(
            'interface=eth1\nlisten-address=192.168.55.1\nbind-interfaces\n'
            'dhcp-range=10.61.30.50,10.61.30.150,255.255.255.0,6h\n'
            'dhcp-option=option:router,192.168.55.1\n'
            f'dhcp-leasefile={lease}\ndhcp-hostsfile={sysdir / "hosts.dhcp"}\n'
            f'conf-dir={sysdir / "dnsmasq.d"}\ncache-size=5000\n')
        (sysdir / 'dnsmasq.d/local.conf').write_text(
            'dhcp-host=02:00:00:00:20:01,10.61.30.20,nas\naddress=/nas.lan/10.61.30.20\n'
            'dhcp-option=42,10.61.30.1\nenable-ra\n')
        lease.write_text('1800000000 02:00:00:00:20:01 10.61.30.20 nas *\n'
                         '1800000000 02:00:00:00:20:09 192.168.55.7 old *\n')
        return ['--lan', LAN, '--conf', str(self.conf), '--system-conf', str(sysdir / 'dnsmasq.conf')]

    def test_scan_sorts_what_can_be_imported(self):
        args = self.system()
        result = json.loads(self.run_tool('scan', '--json', *args).stdout)
        self.assertEqual(sorted(result['hosts']), ['02:00:00:00:20:01,10.61.30.20,nas', '02:00:00:00:20:02,10.61.30.21,printer'])
        self.assertEqual((result['range']['start'], result['range']['end'], result['range']['lease']),
                         ('10.61.30.50', '10.61.30.150', '6h'))
        self.assertEqual(result['lines'], ['address=/nas.lan/10.61.30.20', 'dhcp-option=42,10.61.30.1', 'cache-size=5000'])
        skipped = {s['text']: s['reason'] for s in result['skipped']}
        for text in ('interface=eth1', 'listen-address=192.168.55.1', 'enable-ra', 'dhcp-option=option:router,192.168.55.1',
                     'dhcp-host=02:00:00:00:20:03,10.9.9.9,away'):
            self.assertIn(text, skipped)
        self.assertEqual(result['leases_in_lan'], 1)
        self.assertEqual(self.run_tool('scan', '--range-only', *args).stdout.split(),
                         ['10.61.30.50', '10.61.30.150', '255.255.255.0', '6h'])

    def test_import_adds_once_and_keeps_this_instances_leases(self):
        args = self.system()
        self.set()
        self.hosts.write_text('02:00:00:00:20:01,10.61.30.20,nas-already\n')
        self.run_tool('import', *args, '--hosts', str(self.hosts), '--leases', str(self.leases))
        self.assertEqual(self.hosts.read_text().splitlines(),
                         ['02:00:00:00:20:01,10.61.30.20,nas-already', '02:00:00:00:20:02,10.61.30.21,printer'])
        text = self.conf.read_text()
        self.assertIn('address=/nas.lan/10.61.30.20', text)
        self.assertIn('cache-size=5000', text)
        self.assertNotIn('cache-size=1000', text)
        self.assertEqual(self.leases.read_text(), '1800000000 02:00:00:00:20:01 10.61.30.20 nas *\n')
        # A second import changes nothing, and a lease file of this instance is never replaced.
        self.leases.write_text('mine\n')
        self.run_tool('import', *args, '--hosts', str(self.hosts), '--leases', str(self.leases))
        self.assertEqual(self.conf.read_text(), text)
        self.assertEqual(self.leases.read_text(), 'mine\n')
        self.assertEqual(len(self.hosts.read_text().splitlines()), 2)

    def test_legacy_changes_to_the_system_configuration_are_undone(self):
        state = self.root / 'state'
        original = self.root / 'etc/dnsmasq.conf'
        original.parent.mkdir(parents=True)
        original.write_text('#vpp-router# interface=eth1\n')
        created = self.root / 'etc/dnsmasq.d/vpp.conf'
        created.parent.mkdir()
        created.write_text('conf-file=/etc/vpp/dnsmasq.conf\n')
        backup = state / 'dnsmasq-orig'
        (backup / 'files' / str(original).lstrip('/')).parent.mkdir(parents=True)
        (backup / 'files' / str(original).lstrip('/')).write_text('interface=eth1\n')
        (backup / 'manifest.json').write_text(json.dumps({'backed_up': [str(original)], 'created': [str(created)]}))
        self.run_tool('restore-legacy', '--state', str(state))
        self.assertEqual(original.read_text(), 'interface=eth1\n')
        self.assertFalse(created.exists())
        self.assertFalse(backup.exists())
        self.assertIn('无需恢复', self.run_tool('restore-legacy', '--state', str(state)).stdout)


if __name__ == '__main__':
    unittest.main()
