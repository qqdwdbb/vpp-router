#!/usr/bin/env python3
"""Replace only the installed TAP plugin, with an independent timed rollback."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

STATE = Path('/var/lib/vpp-vrouter')
RECORD = STATE/'tap-refill-upgrade.json'
PLUGIN = Path('/usr/local/lib/vpp-vrouter/plugins/tap_plugin.so')


def run(*args, check=True, timeout=150):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('Command failed: '+str(args[0]))
    return p.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(record):
    temporary = RECORD.with_suffix('.tmp')
    temporary.write_text(json.dumps(record, indent=2)+'\n')
    temporary.chmod(0o600)
    temporary.replace(RECORD)


def replace_plugin(source):
    temporary = PLUGIN.with_suffix('.upgrade')
    shutil.copy2(source, temporary)
    temporary.replace(PLUGIN)


def health(record):
    for unit in record['units']:
        if run('systemctl', 'is-active', unit).strip() != 'active':
            raise RuntimeError('Inactive: '+unit)
    run('ping', '-c', '3', '-W', '2', '10.61.20.1')
    deadline = time.monotonic()+120
    while True:
        reply = run('/usr/local/bin/vppctl', 'ping 10.61.10.1 repeat 2')
        if '0 received' not in reply and ' received' in reply:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('WAN probe failed')
        time.sleep(1)
    nodes = run('/usr/local/bin/vppctl', 'show node tap-refill-retry')
    if 'tap-refill-retry' not in nodes or 'unknown' in nodes.lower():
        raise RuntimeError('Retry node missing')
    run('curl', '-4', '--fail', '-sS', '-m', '15', '-o', '/dev/null', 'https://www.baidu.com')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'rollback', 'confirm'))
    parser.add_argument('--candidate', type=Path)
    args = parser.parse_args()
    if args.action == 'apply':
        if RECORD.exists():
            raise RuntimeError('An upgrade record already exists')
        route = json.loads(run('ip', '-j', 'route', 'get', '10.61.60.2'))[0]
        assert route['dev'] == 'mgmt0' and route['prefsrc'] == '10.61.60.1'
        candidate = args.candidate.resolve(strict=True)
        assert candidate.is_file() and PLUGIN.is_file()
        if b'test tap-refill-fail' in candidate.read_bytes():
            raise RuntimeError('Fault injection build cannot be deployed')
        installation = json.loads((STATE/'installation.json').read_text())
        assert installation['phase'] == 'confirmed'
        backup = STATE/'backups'/('tap-refill-'+str(time.time_ns()))
        backup.mkdir(mode=0o700)
        shutil.copy2(PLUGIN, backup/'tap_plugin.so')
        record = dict(phase='armed', units=installation['units'], backup=str(backup/'tap_plugin.so'),
                      old_sha256=digest(PLUGIN), candidate_sha256=digest(candidate),
                      timer='vrouter-tap-refill-rollback-'+str(time.time_ns()))
        save(record)
        run('systemd-run', '--unit='+record['timer'], '--on-active=300s',
            '/usr/bin/python3', Path(__file__).resolve(), 'rollback')
        run('systemctl', 'stop', *record['units'])
        replace_plugin(candidate)
        run('systemctl', 'start', *record['units'])
        health(record)
        record['phase'] = 'awaiting-confirmation'
        save(record)
    else:
        record = json.loads(RECORD.read_text())
        if args.action == 'rollback':
            if record['phase'] in ('confirmed', 'rolled-back'):
                return
            assert digest(Path(record['backup'])) == record['old_sha256']
            run('systemctl', 'stop', *record['units'], check=False)
            replace_plugin(Path(record['backup']))
            run('systemctl', 'reset-failed', *record['units'], check=False)
            run('systemctl', 'start', *record['units'])
            record['phase'] = 'rolled-back'
        else:
            assert record['phase'] == 'awaiting-confirmation'
            assert digest(PLUGIN) == record['candidate_sha256']
            health(record)
            run('systemctl', 'stop', record['timer']+'.timer')
            record['phase'] = 'confirmed'
        save(record)
    print(record['phase'])


if __name__ == '__main__':
    main()
