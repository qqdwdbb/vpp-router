#!/usr/bin/env python3
"""Temporary ACL-only trial with independent timed restoration; no promotion."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time

TARGET = Path('/usr/local/lib/vpp-vrouter/plugins/acl_plugin.so')
WORK = Path('/usr/local/src/vpp-vrouter/maintenance/acl-permit-frame-cache-v3')
STATE = Path('/var/lib/vpp-vrouter/acl-cache-trial')
POLICY = Path('/sys/devices/system/cpu/cpufreq/policy4')
TIMER = 'vrouter-acl-cache-restore'
ORIGINAL_SHA = 'bf80de2d141ed49b0ae4f96a4a3387ed0612d7b508eb26afc66aaee04cd52383'
CANDIDATE_SHA = '9c126c015d5e530b9b436afcdc74cb94cc925f1b1f4a34264ffffd12a87322e0'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args, timeout=180):
    return subprocess.check_output(list(map(str, args)), text=True, stderr=subprocess.STDOUT, timeout=timeout)


def save(record):
    path = STATE / 'state.json'
    temporary = path.with_suffix('.new')
    temporary.write_text(json.dumps(record, indent=2) + '\n')
    temporary.replace(path)


def replace(source):
    temporary = TARGET.with_name('acl_plugin.so.trial-new')
    shutil.copy2(source, temporary)
    temporary.replace(TARGET)


def health():
    spec = importlib.util.spec_from_file_location('recovery', '/usr/local/lib/vpp-vrouter/install/recovery.py')
    recovery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recovery)
    for _ in range(45):
        statuses = subprocess.run(['systemctl', 'is-active', *recovery.REQUIRED],
                                  text=True, capture_output=True).stdout.splitlines()
        if len(statuses) == len(recovery.REQUIRED) and all(x == 'active' for x in statuses):
            recovery.health(wan_timeout=45)
            return
        time.sleep(2)
    raise RuntimeError('dependent services did not become ready')


def restore(record, finish=True):
    if record.get('accepted') or record.get('status') == 'accepted':
        raise RuntimeError('Trial was accepted; use the current production recovery baseline')
    if sha(STATE / 'original-acl_plugin.so') != ORIGINAL_SHA:
        raise RuntimeError('restore backup mismatch')
    if sha(TARGET) != ORIGINAL_SHA:
        replace(STATE / 'original-acl_plugin.so')
        run('systemctl', 'restart', 'vrouter-vpp.service')
    if finish:
        for f in ('scaling_max_freq', 'scaling_min_freq', 'scaling_governor'):
            (POLICY / f).write_text(record['policy'][f])
    health()
    record.update(status='restored' if finish else 'original-active', restored_at=time.time(), restored_sha256=sha(TARGET))
    save(record)
    if finish:
        run('systemctl', 'stop', TIMER + '.timer')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('arm', 'apply', 'restore-original', 'restore', 'status'))
    args = parser.parse_args()
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'arm':
            if (STATE / 'state.json').exists():
                raise RuntimeError('trial state already exists')
            if sha(TARGET) != ORIGINAL_SHA or sha(WORK / 'acl_plugin.so') != CANDIDATE_SHA:
                raise RuntimeError('trial binaries changed')
            health()
            shutil.copy2(TARGET, STATE / 'original-acl_plugin.so')
            shutil.copy2(TARGET, WORK / 'original-acl_plugin.so')
            record = {'status': 'armed', 'armed_at': time.time(),
                      'policy': {f: (POLICY / f).read_text().strip() for f in
                                 ('scaling_governor', 'scaling_min_freq', 'scaling_max_freq')},
                      'original_sha256': ORIGINAL_SHA, 'candidate_sha256': CANDIDATE_SHA,
                      'startup_sha256': sha(Path('/etc/vpp/startup.conf'))}
            save(record)
            run('systemd-run', '--unit=' + TIMER, '--on-active=25m',
                '/usr/bin/python3', str(Path(__file__).resolve()), 'restore')
        else:
            record = json.loads((STATE / 'state.json').read_text())
            if args.action == 'apply':
                if record['status'] != 'armed' or sha(TARGET) != ORIGINAL_SHA:
                    raise RuntimeError('unexpected original state')
                if sha(WORK / 'acl_plugin.so') != CANDIDATE_SHA:
                    raise RuntimeError('candidate changed')
                if sha(Path('/etc/vpp/startup.conf')) != record['startup_sha256']:
                    raise RuntimeError('startup configuration changed')
                record['status'] = 'applying'
                save(record)
                try:
                    replace(WORK / 'acl_plugin.so')
                    run('systemctl', 'restart', 'vrouter-vpp.service')
                    health()
                    record.update(status='candidate-active', applied_at=time.time())
                    save(record)
                except Exception:
                    restore(record)
                    raise
            elif args.action in ('restore', 'restore-original'):
                restore(record, finish=args.action == 'restore')
        print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
