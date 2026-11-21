#!/usr/bin/env python3
"""Activate installed units with rollback to the accepted current router version."""
import argparse
import fcntl
import re
import json
from pathlib import Path
import shutil
import subprocess
import time

STATE = Path('/var/lib/vpp-vrouter')
HERE = Path(__file__).resolve().parent


def run(*args, check=True, timeout=150, env=None):
    result = subprocess.run(list(map(str,args)), capture_output=True, text=True, timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError('Command failed: '+str(args[0]))
    return result.stdout


def health(units, wan_timeout=0):
    for unit in units:
        if run('systemctl','is-active',unit).strip() != 'active':
            raise RuntimeError('Inactive service: '+unit)
    run('/usr/local/bin/vppctl','show version')
    run('ping','-c','2','-W','2','10.61.20.1')
    deadline = time.monotonic()+wan_timeout
    while True:
        output = run('/usr/local/bin/vppctl','ping 10.61.10.1 repeat 2 source nic0-dpdk.100')
        received = re.search(r'(\d+) received', output)
        if received and int(received[1]) > 0:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('WAN gateway did not answer VPP probes')
        time.sleep(1)


def activate(action):
    record = json.loads((STATE/'installation.json').read_text())
    units = record['units']
    helper = HERE/'recovery.py'
    if action == 'linux':
        print(run('python3', helper, 'linux', timeout=240))
        return
    if action == 'confirm':
        if record.get('phase') != 'awaiting-confirmation':
            raise ValueError('No pending installation')
        health(units)
        # Explicit acceptance replaces the recovery baseline only after health checks.
        print(run('python3', helper, 'snapshot', timeout=300))
        run('systemctl', 'stop', record['rollback_unit']+'.timer')
        return
    if action == 'rollback':
        if record.get('phase') in ('confirmed', 'rolled-back'):
            return
        print(run('python3', helper, 'restore', timeout=300))
        return
    if record.get('phase') not in (None, 'rolled-back'):
        raise ValueError('This staged installation has already been activated')
    # Never change a deployment without a verified, self-contained recovery point.
    run('python3', helper, 'verify')
    route = json.loads(run('ip', '-j', 'route', 'get', '10.61.60.2'))[0]
    if route.get('dev') != 'mgmt0' or route.get('prefsrc') != '10.61.60.1':
        raise ValueError('Independent management route unavailable')
    record['rollback_unit'] = 'vrouter-current-rollback-'+str(time.time_ns())
    run('systemd-run', '--unit='+record['rollback_unit'], '--on-active=300s',
        '/usr/bin/python3', HERE/'activate.py', 'rollback')
    record['phase'] = 'switching'
    (STATE/'installation.json').write_text(json.dumps(record, indent=2)+'\n')
    run('systemctl', 'stop', *units, check=False)
    for name in units:
        shutil.copy2(STATE/'units'/name, Path('/etc/systemd/system')/name)
        (Path('/run/systemd/system')/name).unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'reset-failed', *units, check=False)
    latch = STATE/'linux-fallback/active'
    if latch.exists():
        run('python3', HERE.parent/'scripts/vrouter/startup/vrouter-linux-fallback.py', 'resume')
    run('systemctl', 'start', *units)
    health(units, wan_timeout=120)
    record['phase'] = 'awaiting-confirmation'
    (STATE/'installation.json').write_text(json.dumps(record, indent=2)+'\n')
    print(record['phase'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('apply','confirm','rollback','linux'))
    args = parser.parse_args()
    with (STATE/'activation.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        activate(args.action)
