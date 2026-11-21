#!/usr/bin/env python3
"""Compare the deployed NAT path at locked VROUTER worker CPU frequencies."""
import argparse
import getpass
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time


BASE = Path(__file__).resolve().parents[2]
ROUTER = '10.61.20.1'
SOCKET = '/tmp/vrouter-bench-router.sock'
POLICY = '/sys/devices/system/cpu/cpufreq/policy4'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rates', default='1400000,1600000,1700000,1800000,2000000')
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--output', type=Path,
                        default=BASE / 'artifacts/vrouter/nat-cpu-frequency-20261030.json')
    parser.add_argument('--password-stdin', action='store_true')
    args = parser.parse_args()
    rates = [int(x) for x in args.rates.split(',')]
    if any(r < 1000 or r > 2500000 or r * args.seconds > 30000000 for r in rates):
        parser.error('bounded rate/count exceeded')
    password = sys.stdin.readline().rstrip('\n') if args.password_stdin else getpass.getpass(
        'Remote sudo password: ')

    def remote(command, timeout=45):
        argv = ['ssh', '-S', SOCKET, '-o', 'BatchMode=yes', 'vpp-operator@' + ROUTER,
                'sudo -S -p "" sh -c ' + shlex.quote(command)]
        cp = subprocess.run(argv, input=password + '\n', capture_output=True,
                            text=True, timeout=timeout)
        if cp.returncode:
            raise RuntimeError(cp.stderr[-1200:] + cp.stdout[-1200:])
        return cp.stdout

    def policy_state():
        text = remote(
            'for f in related_cpus scaling_governor scaling_min_freq scaling_max_freq '
            'cpuinfo_cur_freq; do printf "%s=" "$f"; cat ' + POLICY + '/$f; done')
        state = {}
        for line in text.splitlines():
            key, value = line.split('=', 1)
            state[key] = value.strip()
        return state

    def set_frequency(freq_khz):
        remote('echo performance > ' + POLICY + '/scaling_governor; '
               'echo ' + str(freq_khz) + ' > ' + POLICY + '/scaling_max_freq; '
               'echo ' + str(freq_khz) + ' > ' + POLICY + '/scaling_min_freq; sleep 1')
        state = policy_state()
        if state.get('scaling_min_freq') != str(freq_khz) or state.get('scaling_max_freq') != str(freq_khz):
            raise RuntimeError('failed to lock policy4 to ' + str(freq_khz) + ': ' + repr(state))
        return state

    def restore(state):
        remote('echo ' + state['scaling_max_freq'] + ' > ' + POLICY + '/scaling_max_freq; '
               'echo ' + state['scaling_min_freq'] + ' > ' + POLICY + '/scaling_min_freq; '
               'echo ' + state['scaling_governor'] + ' > ' + POLICY + '/scaling_governor')

    targets = (('1800MHz', 1800000), ('2016MHz', 2016000), ('2208MHz', 2208000))
    original = policy_state()
    result = {'started_at': time.time(), 'policy': POLICY, 'policy_before': original,
              'rates': rates, 'seconds': args.seconds, 'frequencies': []}
    try:
        for index, (label, freq_khz) in enumerate(targets):
            locked = set_frequency(freq_khz)
            output = args.output.with_name('nat-cpu-' + label + '-20261030.json')
            command = [sys.executable, str(BASE / 'benchmarks/vrouter_path_compare.py'),
                       '--modes', 'nat', '--rates', ','.join(str(x) for x in rates),
                       '--seconds', str(args.seconds), '--run-base', str(700000 + index * 10000),
                       '--output', str(output), '--password-stdin']
            print('testing ' + label, flush=True)
            cp = subprocess.run(command, input=password + '\n', text=True,
                                capture_output=True, timeout=len(rates) * (args.seconds + 45) + 180)
            if cp.returncode:
                raise RuntimeError(label + ' failed:\n' + cp.stdout[-2000:] + cp.stderr[-2000:])
            item = {'label': label, 'target_khz': freq_khz, 'locked_policy': locked,
                    'path_compare': str(output), 'result': json.loads(output.read_text())}
            result['frequencies'].append(item)
            result['last_output'] = cp.stdout[-1000:]
            args.output.write_text(json.dumps(result, indent=2) + '\n')
    finally:
        restore(original)
        result['policy_after_restore'] = policy_state()
        result['finished_at'] = time.time()
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
