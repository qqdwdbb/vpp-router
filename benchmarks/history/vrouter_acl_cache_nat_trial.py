#!/usr/bin/env python3
"""Fixed-frequency original/candidate/original NAT test, ending in restoration."""
import getpass
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[2]
ART = BASE / 'artifacts/vrouter'
SOCKET = '/tmp/vrouter-acl-router.sock'
LINUX_SOCKET = '/tmp/vrouter-acl-linux.sock'
WORK = '/usr/local/src/vpp-vrouter/maintenance/acl-permit-frame-cache-v3'
CONTROL = WORK + '/acl-cache-trial.py'
POLICY = '/sys/devices/system/cpu/cpufreq/policy4'


def main():
    password = getpass.getpass('Remote sudo password: ')
    result = {'started_at': time.time(), 'frequency_khz': 2208000, 'runs': []}

    def remote(command, timeout=60):
        cp = subprocess.run(['ssh', '-S', SOCKET, '-o', 'BatchMode=yes', 'vpp-operator@10.61.20.1',
                             'sudo -S -p "" sh -c ' + shlex.quote(command)],
                            input=password + '\n', text=True, capture_output=True, timeout=timeout)
        if cp.returncode:
            raise RuntimeError(cp.stderr[-1800:] + cp.stdout[-1800:])
        return cp.stdout

    def save():
        (ART / 'acl-cache-nat-trial-20261030.json').write_text(json.dumps(result, indent=2) + '\n')

    def control(action):
        unit = 'vrouter-acl-trial-' + action
        remote('systemd-run --unit=' + unit + ' --property=RuntimeMaxSec=240 '
               '/usr/bin/python3 ' + CONTROL + ' ' + action)
        deadline = time.monotonic() + 230
        while time.monotonic() < deadline:
            state = remote('systemctl show ' + unit + ' -p ActiveState -p SubState -p Result')
            if 'ActiveState=failed' in state:
                raise RuntimeError('independent controller failed: ' + remote('journalctl -u ' + unit + ' -n 35 --no-pager'))
            if 'ActiveState=inactive' in state:
                data = json.loads(remote('python3 ' + CONTROL + ' status'))
                result[action] = data
                save()
                return
            time.sleep(2)
        raise RuntimeError('independent controller did not finish')

    def bench(tag, rates, seconds, flows, run_base, profile=False):
        print('testing ' + tag, flush=True)
        output = ART / ('acl-cache-nat-' + tag + '-20261030.json')
        command = [sys.executable, str(BASE / 'benchmarks/vrouter_path_compare.py'), '--modes', 'nat',
                   '--router-socket', SOCKET, '--linux-socket', LINUX_SOCKET,
                   '--rates', rates, '--seconds', str(seconds), '--flows', str(flows),
                   '--run-base', str(run_base), '--sample-rx-status', '--output', str(output),
                   '--password-stdin']
        if profile:
            command.append('--sample-worker')
        cp = subprocess.run(command, input=password + '\n', text=True,
                            timeout=len(rates.split(',')) * (seconds + 40) + 90)
        if cp.returncode:
            raise RuntimeError('benchmark failed: ' + tag)
        data = json.loads(output.read_text())
        result['runs'].append({'tag': tag, 'flows': flows, 'path': str(output)})
        save()
        if profile:
            flat = ART / ('acl-cache-nat-' + tag + '-profile-raw-20261030.json')
            flat.write_text(json.dumps({'phases': [p for m in data['modes'] for p in m['phases']]}) + '\n')
            elf = WORK + ('/acl_plugin.so' if tag.startswith('candidate') else '/original-acl_plugin.so')
            subprocess.run([sys.executable, str(BASE / 'benchmarks/vrouter_perf_ip_report.py'), str(flat),
                            '--router-socket', SOCKET, '--trim-start', '3', '--trim-end', '2',
                            '--elf-override', '/usr/local/lib/vpp-vrouter/plugins/acl_plugin.so=' + elf,
                            '--output', str(ART / ('acl-cache-nat-' + tag + '-symbols-20261030.json'))],
                           check=True, timeout=90)

    armed = False
    try:
        remote('cp /tmp/acl-cache-trial.py ' + CONTROL)
        if '45996' in remote("vppctl 'show nat44 ei static mappings'"):
            raise RuntimeError('test NAT port already in use')
        result['arm'] = json.loads(remote('python3 ' + CONTROL + ' arm'))
        armed = True
        remote('echo performance > ' + POLICY + '/scaling_governor\n'
               'echo 2208000 > ' + POLICY + '/scaling_max_freq\n'
               'echo 2208000 > ' + POLICY + '/scaling_min_freq')
        assert remote('cat ' + POLICY + '/cpuinfo_cur_freq').strip() == '2208000'
        for index, version in enumerate(('baseline', 'candidate')):
            if version == 'candidate':
                print('applying candidate', flush=True)
                control('apply')
            bench(version + '-profile', '1400000', 20, 1, 820000 + index * 10000, True)
            bench(version + '-single', '1600000,1700000,1800000,2000000,1800000,2000000',
                  10, 1, 840000 + index * 10000)
            bench(version + '-20k', '1500000,1600000,1800000,1600000,1800000',
                  10, 20000, 860000 + index * 10000)
        print('restoring original for final control', flush=True)
        control('restore-original')
        bench('baseline-repeat', '1800000,2000000,1800000,2000000', 10, 1, 880000)
    finally:
        if armed:
            control('restore')
        result['finished_at'] = time.time()
        save()
    print(ART / 'acl-cache-nat-trial-20261030.json')


if __name__ == '__main__':
    main()
