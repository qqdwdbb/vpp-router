#!/usr/bin/env python3
"""Private systemd lifecycle scenario for the existing VROUTER IPsec fixture."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


def properties(unit):
    p = subprocess.run(['systemctl', 'show', unit, '--property=MainPID,ActiveState,NRestarts,ActiveEnterTimestampMonotonic,ExecMainStartTimestampMonotonic'],
                       capture_output=True, text=True, timeout=5)
    return dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)


def ready(unit, socket):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        pid = int(properties(unit).get('MainPID', '0'))
        if pid:
            status = subprocess.run(['nsenter', '-t', str(pid), '-m', '-n',
                                     '/usr/lib/ipsec/stroke', 'statusall'],
                                    capture_output=True, text=True, timeout=5)
            clients = subprocess.run(['/opt/vpp-nic1-test/vpp/bin/vppctl', '-s', socket,
                                      'show api clients'], capture_output=True, text=True, timeout=5)
            if (status.returncode == clients.returncode == 0 and
                    re.search(r'loaded plugins:.*\bkernel-vpp\b', status.stdout) and
                    re.search(r'(?m)^\s*lab:', status.stdout) and 'strongswan' in clients.stdout):
                return
        time.sleep(.1)
    raise RuntimeError('Private systemd IPsec readiness failed')


def rebuild(root):
    manifest = json.loads((root/'rebuild.json').read_text())
    socket = str(root/'cli.sock')
    deadline = time.monotonic() + 15
    while True:
        p = subprocess.run(['/opt/vpp-nic1-test/vpp/bin/vppctl', '-s', socket, 'show version'],
                           capture_output=True, text=True, timeout=5)
        if p.returncode == 0:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('Restarted VPP API did not become ready')
        time.sleep(.1)
    for command in manifest['vpp_commands']:
        p = subprocess.run(['/opt/vpp-nic1-test/vpp/bin/vppctl', '-s', socket, command],
                           capture_output=True, text=True, timeout=10)
        if p.returncode or re.search(r'unknown input|error:|failed|invalid', p.stdout, re.I):
            raise RuntimeError('Private VPP topology rebuild failed; output suppressed')
    for args in manifest['linux_commands']:
        p = subprocess.run(args, capture_output=True, text=True, timeout=10)
        if p.returncode:
            raise RuntimeError('Private Linux TAP rebuild failed; output suppressed')
    # The alias-bound IKE socket must not depend on cold neighbor discovery.
    if manifest['outer6']:
        p = subprocess.run(['/opt/vpp-nic1-test/vpp/bin/vppctl', '-s', socket,
                            'show hardware-interfaces tap3961'],
                           capture_output=True, text=True, check=True, timeout=5)
        mac = re.search(r'Ethernet address ([0-9a-f:]{17})', p.stdout)
        if not mac:
            raise RuntimeError('Rebuilt private control TAP has no MAC')
        subprocess.run(['ip', '-n', manifest['server_namespace'], '-6', 'neigh', 'replace',
                        'fd76:7070:3961::1', 'lladdr', mac[1], 'nud', 'permanent',
                        'dev', 'tap3960'], check=True, capture_output=True, timeout=5)
    (root/'rebuild-ready').write_text(str(time.monotonic()))


class UnitProcess:
    def __init__(self, unit):
        self.unit = unit

    @property
    def pid(self):
        return int(properties(self.unit).get('MainPID', '0'))

    def poll(self):
        state = properties(self.unit).get('ActiveState')
        return None if state in ('active', 'activating', 'reloading') else 0


class Lifecycle:
    def __init__(self, root, env, run, wait):
        self.root, self.env, self.run, self.wait = root, env, run, wait
        self.vpp_unit = 'vrouter-ipsec-life-vpp-' + str(os.getpid()) + '.service'
        self.server_unit = 'vrouter-ipsec-life-ike-' + str(os.getpid()) + '.service'
        self.units = []
        self.dropin = None
        self.runtime_after_rebuild = None

    def start(self, args, server=False):
        unit = self.server_unit if server else self.vpp_unit
        command = ['systemd-run', '--unit=' + unit, '--collect',
                   '--property=RuntimeMaxSec=240', '--property=KillMode=control-group',
                   '--property=TimeoutStopSec=15', '--property=Restart=on-failure',
                   '--property=RestartSec=1']
        if server:
            command += ['--property=Requires=' + self.vpp_unit,
                        '--property=After=' + self.vpp_unit,
                        '--property=PartOf=' + self.vpp_unit,
                        '--property=TimeoutStartSec=35',
                        '--property=ExecReload=/bin/kill -HUP $MAINPID',
                        '--property=ExecStartPost=/usr/bin/python3 ' + str(Path(__file__).resolve()) +
                        ' --ready ' + unit + ' ' + str(self.root/'cli.sock')]
        for key in ('PATH', 'LD_LIBRARY_PATH'):
            command.append('--setenv=' + key + '=' + self.env[key])
        self.units.append(unit)
        self.run(*command, *args, timeout=45)
        process = UnitProcess(unit)
        self.wait(lambda: process.pid > 0 and properties(unit).get('ActiveState') == 'active',
                  'Private systemd unit did not become ready', 35)
        return process

    def prepare_rebuild(self, commands, names, outer6, mtu):
        linux = []
        def ip(role, *args):
            linux.append(['ip', '-n', names[role], *args])
        if outer6:
            ip('wire', 'link', 'set', 'mgmt0', 'master', 'br-wire')
            ip('wire', 'link', 'set', 'mgmt0', 'up')
            ip('wire', 'link', 'set', 'mgmt0', 'mtu', str(mtu))
        ip('server', 'addr', 'replace', '198.18.60.1/32', 'dev', 'tap3960')
        ip('server', 'route', 'replace', 'default', 'via', '172.31.246.1')
        if outer6:
            ip('server', '-6', 'addr', 'replace', 'fd76:7070:3961::2/64', 'dev', 'tap3960', 'nodad')
            ip('server', '-6', 'addr', 'replace', '2001:db8:60::1/128', 'dev', 'tap3960', 'nodad')
            ip('server', '-6', 'route', 'replace', 'default', 'via', 'fd76:7070:3961::1')
        ip('client', '-6', 'addr', 'replace', '2001:db8:60::2/64', 'dev', 'mgmt0', 'nodad')
        ip('client', '-6', 'route', 'replace', '2001:db8:62::/64', 'via', '2001:db8:60::1')
        ip('client', 'route', 'replace', '10.254.62.0/24', 'via', '198.18.60.1')
        ip('lan', '-6', 'addr', 'replace', '2001:db8:62::2/64', 'dev', 'mgmt0', 'nodad')
        ip('lan', '-6', 'route', 'replace', 'default', 'via', '2001:db8:62::1')
        ip('lan', 'route', 'replace', 'default', 'via', '10.254.62.1')
        (self.root/'rebuild.json').write_text(json.dumps({'vpp_commands': commands,
            'linux_commands': linux, 'outer6': outer6, 'server_namespace': names['server']}))
        dropin = Path('/run/systemd/system')/(self.vpp_unit+'.d')
        dropin.mkdir(mode=0o700)
        self.dropin = dropin
        (self.dropin/'rebuild.conf').write_text('[Service]\nExecStartPost=/usr/bin/python3 '+
            str(Path(__file__).resolve())+' --rebuild '+str(self.root)+'\n')
        self.run('systemctl', 'daemon-reload')

    def verify(self, daemons, cli, status, exchange):
        server = daemons['server']
        old_pid = server.pid
        old_child = (self.root/'server/run/charon.pid').read_text().strip()
        self.run('systemctl', 'restart', self.server_unit, timeout=45)
        self.wait(lambda: server.pid != old_pid and server.pid > 0,
                  'Private starter was not replaced')
        self.wait(lambda: not re.findall(r'(?m)^\[', cli('show ipsec sa')),
                  'Old VPP SAs remained after graceful control restart')
        new_child = (self.root/'server/run/charon.pid').read_text().strip()
        assert new_child != old_child, 'charon did not restart'
        self.run('nsenter', '-t', str(daemons['client'].pid), '-m', '-n',
                 '/usr/lib/ipsec/stroke', 'down', 'lab')
        self.run('nsenter', '-t', str(daemons['client'].pid), '-m', '-n',
                 '/usr/lib/ipsec/stroke', 'up', 'lab')
        self.wait(lambda: 'INSTALLED, TUNNEL' in status(),
                  'Client failed to reconnect after control restart', 35)
        exchange()
        pid = server.pid
        ike = re.findall(r'lab\[(\d+)\]:.*ESTABLISHED', status())
        self.run('systemctl', 'reload', self.server_unit)
        self.wait(lambda: 'INSTALLED, TUNNEL' in status(), 'Reload removed the CHILD')
        assert server.pid == pid, 'Reload restarted starter'
        assert re.findall(r'lab\[(\d+)\]:.*ESTABLISHED', status()) == ike, 'Reload replaced IKE'
        exchange()
        crashed_pid = server.pid
        self.run('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', self.server_unit)
        self.wait(lambda: server.pid > 0 and server.pid != crashed_pid and
                  properties(self.server_unit).get('ActiveState') == 'active',
                  'systemd did not recover the failed private starter', 40)
        assert int(properties(self.server_unit).get('NRestarts', '0')) >= 1
        self.wait(lambda: not re.findall(r'(?m)^\[', cli('show ipsec sa')),
                  'VPP SAs remained after starter failure')
        self.run('nsenter', '-t', str(daemons['client'].pid), '-m', '-n',
                 '/usr/lib/ipsec/stroke', 'down', 'lab')
        self.run('nsenter', '-t', str(daemons['client'].pid), '-m', '-n',
                 '/usr/lib/ipsec/stroke', 'up', 'lab')
        self.wait(lambda: 'INSTALLED, TUNNEL' in status(),
                  'Client failed to reconnect after starter failure', 35)
        exchange()
        old_charon = int((self.root/'server/run/charon.pid').read_text().strip())
        starter_pid = server.pid
        os.kill(old_charon, signal.SIGKILL)
        self.wait(lambda: (self.root/'server/run/charon.pid').exists() and
                  int((self.root/'server/run/charon.pid').read_text().strip()) != old_charon and
                  server.pid == starter_pid,
                  'starter did not restart killed charon child', 35)
        ready(self.server_unit, str(self.root/'cli.sock'))
        self.run('nsenter', '-t', str(daemons['client'].pid), '-m', '-n',
                 '/usr/lib/ipsec/stroke', 'down-nb', 'lab')
        time.sleep(0.5)
        self.run('nsenter', '-t', str(daemons['client'].pid), '-m', '-n',
                 '/usr/lib/ipsec/stroke', 'up', 'lab')
        self.wait(lambda: 'INSTALLED, TUNNEL' in status(),
                  'Client failed to reconnect after charon child recovery', 35)
        exchange()
        def tap_macs():
            return {name: re.search(r'Ethernet address ([0-9a-f:]{17})',
                    cli('show hardware-interfaces '+name))[1]
                    for name in ('tap3960','tap3961','tap3962')}
        original_macs = tap_macs()
        old_vpp = int(properties(self.vpp_unit)['MainPID'])
        old_server = server.pid
        manifest = json.loads((self.root/'rebuild.json').read_text())
        server_ns = manifest['server_namespace']
        old_link = json.loads(self.run('ip','-n',server_ns,'-j','link','show','tap3960'))[0]['ifindex']
        self.run('systemctl', 'restart', self.vpp_unit, timeout=60)
        self.wait(lambda: int(properties(self.vpp_unit).get('MainPID', '0')) not in (0, old_vpp)
                  and server.pid not in (0, old_server) and
                  properties(self.server_unit).get('ActiveState') == 'active',
                  'VPP restart did not rebuild and restart private IKE', 40)
        assert (self.root/'rebuild-ready').exists(), 'VPP topology rebuild hook did not finish'
        new_link = json.loads(self.run('ip','-n',server_ns,'-j','link','show','tap3960'))[0]['ifindex']
        assert new_link != old_link, 'Control TAP was not recreated'
        assert tap_macs() == original_macs, 'Rebuild changed TAP MACs and invalidated cached neighbors'
        assert not re.findall(r'(?m)^\[', cli('show ipsec sa')), 'New VPP unexpectedly retained old SAs'
        self.runtime_after_rebuild = cli('show runtime')
        self.run('nsenter', '-t', str(daemons['client'].pid), '-m', '-n',
                 '/usr/lib/ipsec/stroke', 'down', 'lab')
        self.run('nsenter', '-t', str(daemons['client'].pid), '-m', '-n',
                 '/usr/lib/ipsec/stroke', 'up', 'lab')
        self.wait(lambda: 'INSTALLED, TUNNEL' in status(),
                  'Client failed to reconnect after VPP rebuild', 35)
        exchange()
        return {'systemd_readiness': True, 'graceful_starter_restart': True,
                'old_sas_removed': True, 'client_reconnect': True,
                'dual_stack_tcp_after_restart_and_reload': True,
                'reload_preserves_starter_and_ike': True,
                'starter_sigkill_systemd_recovery': True,
                'charon_sigkill_starter_recovery': True,
                'dual_stack_tcp_after_starter_failure': True,
                'vpp_restart_rebuild': True, 'control_tap_recreated': True,
                'tap_macs_preserved': True,
                'dependent_control_restarted': True, 'dual_stack_tcp_after_vpp_restart': True}

    def stop_dependency(self):
        self.run('systemctl', 'stop', self.vpp_unit, timeout=30)
        self.wait(lambda: properties(self.server_unit).get('ActiveState') not in
                  ('active', 'activating', 'reloading', 'deactivating'),
                  'Private IKE unit did not stop with VPP')
        return True

    def close(self):
        for unit in reversed(self.units):
            subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=30)
        if self.dropin:
            (self.dropin/'rebuild.conf').unlink()
            self.dropin.rmdir()
            self.run('systemctl', 'daemon-reload')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--ready':
        ready(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == '--rebuild':
        rebuild(Path(sys.argv[2]))
    else:
        raise SystemExit('Use integration_vrouter_ipsec.py --lifecycle')
