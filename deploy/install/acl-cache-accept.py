#!/usr/bin/env python3
"""Promote the tested ACL binary and installation/recovery inputs on VROUTER."""
import datetime
import fcntl
import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.path.insert(0, '/usr/local/lib/vpp-vrouter/install')
import recovery

WORK = Path('/usr/local/src/vpp-vrouter/maintenance/acl-permit-frame-cache-v3')
STATE = recovery.STATE/'acl-cache-accept'
TARGET = recovery.RUNTIME/'plugins/acl_plugin.so'
INPUT = Path('/usr/local/src/vpp-vrouter/migration/plugins/acl_plugin.so')
TRIAL = recovery.STATE/'acl-cache-trial/state.json'
TIMER = 'vrouter-acl-cache-accept-rollback'
OLD = 'bf80de2d141ed49b0ae4f96a4a3387ed0612d7b508eb26afc66aaee04cd52383'
NEW = '9c126c015d5e530b9b436afcdc74cb94cc925f1b1f4a34264ffffd12a87322e0'
UNITS = recovery.REQUIRED+('gost-tunnel.service',)


def sha(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy(source, target):
    temporary = target.with_name(target.name+'.accept-new')
    recovery.copy_snapshot(source, temporary)
    temporary.replace(target)


def save(record):
    recovery.write_json(STATE/'state.json', record)


def health():
    for attempt in range(45):
        if all(recovery.run('systemctl', 'is-active', unit, check=False) == 'active' for unit in UNITS):
            recovery.health(UNITS, wan_timeout=45)
            return
        time.sleep(2)
    raise RuntimeError('Dependent services did not become ready')


def loaded(expected):
    assert sha(TARGET) == expected
    pid = recovery.run('pidof', 'vpp').split()[0]
    entries = [line for line in Path('/proc/'+pid+'/maps').read_text().splitlines() if str(TARGET) in line]
    assert entries and all(int(line.split()[4]) == TARGET.stat().st_ino for line in entries)
    return int(pid)


def rollback(record):
    if record['status'] in ('accepted', 'restored'):
        return
    history = Path(record['archive'])
    assert sha(history/'acl_plugin.so') == OLD
    copy(history/'acl_plugin.input.so', INPUT)
    copy(history/'acl_plugin.so', TARGET)
    old = Path(record['previous_generation'])
    if not old.exists():
        recovery.copy_snapshot(history/'recovery-generation', old)
    link = recovery.STORE/'current.acl-rollback'
    link.unlink(missing_ok=True)
    link.symlink_to(old.relative_to(recovery.STORE))
    link.replace(recovery.STORE/'current')
    for name, target in [('installation.json', recovery.STATE/'installation.json'),
                         ('linux-state.json', recovery.STATE/'baseline/linux-state.json'),
                         ('promotion.json', recovery.STATE/'accepted-baseline-promotion.json'),
                         ('trial-state.json', TRIAL)]:
        copy(history/name, target)
    recovery.run('systemctl', 'restart', 'vrouter-vpp.service')
    health()
    loaded(OLD)
    recovery.verify()
    record['status'] = 'restored'
    save(record)
    recovery.run('systemctl', 'stop', TIMER+'.timer')


def accept():
    if (STATE/'state.json').exists():
        raise RuntimeError('Acceptance state already exists; inspect it before retrying')
    assert sha(TARGET) == OLD and sha(WORK/'acl_plugin.so') == NEW
    loaded(OLD)
    health()
    old, manifest = recovery.verify()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    history = recovery.STATE/'history'/('acl-cache-'+stamp+'-'+uuid.uuid4().hex[:6])
    history.mkdir(mode=0o700, parents=True)
    recovery.copy_snapshot(old, history/'recovery-generation')
    assert recovery.inventory(history/'recovery-generation/tree') == manifest['files']
    for source, name in [(TARGET, 'acl_plugin.so'), (INPUT, 'acl_plugin.input.so'),
                         (recovery.STATE/'installation.json', 'installation.json'),
                         (recovery.STATE/'baseline/linux-state.json', 'linux-state.json'),
                         (recovery.STATE/'accepted-baseline-promotion.json', 'promotion.json'),
                         (TRIAL, 'trial-state.json')]:
        recovery.copy_snapshot(source, history/name)
    protected = [Path('/etc/vpp/startup.conf'), recovery.RUNTIME/'plugins/dpdk_plugin.so',
                 Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')]
    hashes = {str(p): sha(p) for p in protected}
    policy = Path('/sys/devices/system/cpu/cpufreq/policy4')
    frequencies = {name: (policy/name).read_text() for name in
                   ('scaling_governor', 'scaling_min_freq', 'scaling_max_freq')}
    record = dict(status='armed', archive=str(history), previous_generation=str(old))
    save(record)
    recovery.run('systemd-run', '--unit='+TIMER, '--on-active=12m',
                 '/usr/bin/python3', str(Path(__file__).resolve()), 'rollback')
    try:
        copy(WORK/'acl_plugin.so', TARGET)
        recovery.run('systemctl', 'restart', 'vrouter-vpp.service')
        health()
        pid = loaded(NEW)
        copy(WORK/'acl_plugin.so', INPUT)
        assert sha(INPUT) == NEW
        result = recovery.snapshot()
        generation, current = recovery.verify()
        relative = str(TARGET).lstrip('/')
        assert current['files'][relative]['sha256'] == sha(generation/'tree'/relative) == NEW
        assert {str(p): sha(p) for p in protected} == hashes
        assert {name: (policy/name).read_text() for name in frequencies} == frequencies
        assert loaded(NEW) == pid
        health()
        promotion = json.loads((history/'promotion.json').read_text())
        promotion.update(acl_plugin_sha256=NEW, acl_cache='frame-local-gated-permit-v3',
                         accepted_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         recovery_generation=str(generation), previous_baseline_archive=str(history),
                         vpp_pid=pid, installer_input_verified=True, recovery_verified=True,
                         snapshot_files=result['files'], services=len(UNITS), health='passed',
                         loaded_inodes_match=True, restore_drill_performed=False)
        recovery.write_json(recovery.STATE/'accepted-baseline-promotion.json', promotion)
        trial = json.loads(TRIAL.read_text())
        trial.update(accepted=True, status='accepted', recovery_generation=str(generation))
        recovery.write_json(TRIAL, trial)
        record.update(status='accepted', **{k: v for k, v in promotion.items() if k != 'status'})
        save(record)
    except Exception:
        rollback(record)
        raise
    recovery.run('systemctl', 'stop', TIMER+'.timer')
    output = Path('/tmp/vrouter-acl-cache-accepted.json')
    recovery.write_json(output, record)
    output.chmod(0o644)
    print(json.dumps(record, indent=2), flush=True)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run on VROUTER as root')
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE/'lock').open('w') as lock, (recovery.STORE/'lock').open('w') as recovery_lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        fcntl.flock(recovery_lock, fcntl.LOCK_EX)
        if sys.argv[1:] == ['accept']:
            accept()
        elif sys.argv[1:] == ['rollback']:
            rollback(json.loads((STATE/'state.json').read_text()))
        else:
            raise ValueError('Expected accept or rollback')


if __name__ == '__main__':
    main()
