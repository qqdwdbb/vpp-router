#!/usr/bin/env python3
"""Temporary VROUTER VPP CPU binding trial with exact restoration."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/var/lib/vpp-vrouter/cpu-binding-trial')
CONFIG = Path('/etc/vpp/startup.conf')
PMD = Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')
PMD_SHA = '8881ceabf6690006c3cdeb62510a19560b23d6d03778fdbc3683c0eab53a80e8'
BASE_CPU = 'cpu { main-core 4 corelist-workers 5 }'
SMALL_CPU = 'cpu { main-core 0 corelist-workers 1 }'
UNIT = 'vrouter-cpu-binding-rollback'


def run(*args, check=True, timeout=180):
    cp = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and cp.returncode:
        raise RuntimeError('command failed: ' + ' '.join(args) + '\n' + cp.stderr[-1200:])
    return cp.stdout.strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(state):
    tmp = ROOT / 'state.json.new'
    tmp.write_text(json.dumps(state, indent=2) + '\n')
    tmp.chmod(0o600)
    tmp.replace(ROOT / 'state.json')


def render(original, binding):
    text = original.decode()
    if text.count(BASE_CPU) != 1:
        raise RuntimeError('unexpected CPU configuration')
    if binding not in ('baseline', 'small'):
        raise ValueError(binding)
    return original if binding == 'baseline' else text.replace(BASE_CPU, SMALL_CPU).encode()


def replace(data, mode):
    tmp = CONFIG.with_name('startup.conf.cpu-binding-new')
    tmp.write_bytes(data)
    tmp.chmod(mode)
    tmp.replace(CONFIG)


def ready():
    sys.path.insert(0, '/usr/local/lib/vpp-vrouter/install')
    import recovery
    units = recovery.REQUIRED + ('gost-tunnel.service',)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if all(run('systemctl', 'is-active', u, check=False) == 'active' for u in units):
            recovery.health(units, wan_timeout=30)
            return
        time.sleep(2)
    raise RuntimeError('VPP dependent services did not become ready')


def stop_timer():
    run('systemctl', 'stop', UNIT + '.timer', check=False)


def arm():
    stop_timer()
    run('systemd-run', '--unit=' + UNIT, '--on-active=10m', '/usr/bin/python3',
        str(Path(__file__).resolve()), 'restore')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('prepare', 'apply', 'restore', 'status'))
    parser.add_argument('--binding', choices=('baseline', 'small'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('must run as root on VROUTER')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (ROOT / 'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state_path = ROOT / 'state.json'
        if args.action == 'prepare':
            if state_path.exists():
                raise RuntimeError('existing trial state')
            original = CONFIG.read_bytes()
            if sha(PMD.read_bytes()) != PMD_SHA:
                raise RuntimeError('unexpected PMD baseline')
            render(original, 'small')
            (ROOT / 'startup.original').write_bytes(original)
            state = {'original_sha': sha(original), 'mode': CONFIG.stat().st_mode & 0o7777,
                     'binding': 'baseline', 'events': [], 'restored': True}
            state['events'].append({'action': 'prepare', 'time': time.time()})
            save(state)
        else:
            state = json.loads(state_path.read_text())
            original = (ROOT / 'startup.original').read_bytes()
            if sha(original) != state['original_sha']:
                raise RuntimeError('saved startup configuration changed')
            if args.action == 'status':
                print(json.dumps(state, indent=2))
                return
            if args.action == 'restore':
                allowed = {render(original, 'baseline'), render(original, 'small')}
                if CONFIG.read_bytes() not in allowed:
                    raise RuntimeError('configuration changed outside this trial')
                changed = CONFIG.read_bytes() != original
                replace(original, state['mode'])
                if changed:
                    run('systemctl', 'restart', 'vrouter-vpp.service')
                ready()
                state['binding'] = 'baseline'
                state['restored'] = True
                state['events'].append({'action': 'restore', 'time': time.time(),
                                        'restarted': changed})
                save(state)
                stop_timer()
            elif args.action == 'apply':
                if args.binding is None:
                    parser.error('apply requires --binding')
                expected = render(original, state['binding'])
                if CONFIG.read_bytes() != expected:
                    raise RuntimeError('configuration changed outside this trial')
                new = render(original, args.binding)
                arm()
                replace(new, state['mode'])
                if new != expected:
                    try:
                        run('systemctl', 'restart', 'vrouter-vpp.service')
                        ready()
                    except Exception:
                        replace(original, state['mode'])
                        run('systemctl', 'restart', 'vrouter-vpp.service')
                        ready()
                        raise
                state['binding'] = args.binding
                state['restored'] = args.binding == 'baseline'
                state['events'].append({'action': 'apply', 'binding': args.binding,
                                        'time': time.time()})
                save(state)
        print(json.dumps({'binding': state['binding'], 'restored': state['restored'],
                          'events': len(state['events'])}))


if __name__ == '__main__':
    main()
