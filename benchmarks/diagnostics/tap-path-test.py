#!/usr/bin/env python3
"""Bounded TAP route/NAT integrity test; never loads DPDK or binds a NIC."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

BASE = Path('/opt/vpp-vrouter-migration')
VPP = Path('/opt/vpp-nic1-test/vpp')
ENV = dict(os.environ, LD_LIBRARY_PATH='/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:' +
           str(VPP / 'lib/aarch64-linux-gnu'))


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT,
                                   timeout=20, env=ENV)


def restore(runtime):
    state = runtime / 'state.json'
    if state.exists():
        for name in json.loads(state.read_text())['namespaces']:
            if name in run('ip', 'netns', 'list').split():
                run('ip', 'netns', 'delete', name)
        state.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('route', 'nat'), required=True)
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--restore', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 7200:
        parser.error('seconds must be 1..7200')
    runtime = Path(f'/run/vpp-vrouter-tap-{args.mode}')
    if args.restore:
        restore(runtime)
        return
    assert os.geteuid() == 0
    for filename in ('nic1_soak.py', 'udp-echo.py'):
        assert (BASE / 'scripts' / filename).is_file(), f'Missing test program: {filename}'
    assert not (runtime / 'state.json').exists(), 'Restore previous test first'
    names = [f'vrouter-{args.mode}-lan', f'vrouter-{args.mode}-wan']
    assert not any(name in run('ip', 'netns', 'list').split() for name in names)
    runtime.mkdir(exist_ok=True, mode=0o700)
    logdir = BASE / 'logs' / f'tap-{args.mode}-{time.time_ns()}'
    logdir.mkdir(mode=0o700)
    (runtime / 'state.json').write_text(json.dumps(dict(namespaces=names)))
    children = []
    process = None
    report = dict(mode=args.mode, path='Linux -> TAP -> VPP -> TAP -> Linux',
                  dpdk_loaded=False, seconds=args.seconds, logdir=str(logdir), passed=False)
    kernel_start = int(time.time())

    def cli(command):
        output = run(str(VPP / 'bin/vppctl'), '-s', str(runtime / 'cli.sock'), command)
        with (logdir / 'cli.log').open('a') as log:
            log.write(command + '\n' + output + '\n')
        if re.search(r'unknown input|unknown interface|failed|invalid argument|error:', output, re.I):
            raise RuntimeError(command + ': ' + output)
        return output

    def stop(*unused):
        raise RuntimeError('Interrupted; restoring isolated TAP test')

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    try:
        for name in names:
            run('ip', 'netns', 'add', name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        config = f'''
unix {{ nodaemon runtime-dir {runtime} cli-listen {runtime}/cli.sock }}
api-segment {{ prefix vrouter-tap-{args.mode} }}
socksvr {{ socket-name {runtime}/api.sock }}
statseg {{ socket-name {runtime}/stats.sock }}
cpu {{ main-core {5 if args.mode == 'route' else 6} }}
memory {{ main-heap-size 128M }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
plugins {{ path {BASE}/plugins
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin nat44_ei_plugin.so {{ enable }}
plugin nat_ei_context_plugin.so {{ enable }}
}}
'''
        (runtime / 'startup.conf').write_text(config)
        (logdir / 'startup.conf').write_text(config)
        with (logdir / 'vpp.log').open('w') as log:
            process = subprocess.Popen([str(VPP / 'bin/vpp'), '-c', str(runtime / 'startup.conf')],
                                       stdout=log, stderr=log, env=ENV)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('VPP startup failed: ' + (logdir / 'vpp.log').read_text()[-2000:])
            if (runtime / 'cli.sock').exists():
                try:
                    cli('show interface')
                    break
                except subprocess.CalledProcessError:
                    pass
            time.sleep(.1)
        else:
            raise RuntimeError('VPP startup timeout')
        assert 'dpdk_plugin.so' not in cli('show plugins'), 'Unexpected DPDK plugin'
        for index, name in enumerate(names):
            address = '10.252.12.2' if index == 0 else '192.0.2.134'
            gateway = '10.252.12.1' if index == 0 else '192.0.2.250'
            tap = 3301 + index
            cli(f'create tap id {tap} host-ns {name} host-if-name mgmt0 host-ip4-addr {address}/24')
            cli(f'set interface ip address tap{tap} {gateway}/24')
            cli(f'set interface state tap{tap} up')
            cli(f'set interface rx-mode tap{tap} interrupt')
        run('ip', '-n', names[0], 'route', 'add', 'default', 'via', '10.252.12.1')
        run('ip', '-n', names[1], 'route', 'add', '10.252.12.0/24', 'via', '192.0.2.250')
        for index in range(1, 4):
            run('ip', '-n', names[0], 'address', 'add', f'10.252.12.{index + 2}/24', 'dev', 'mgmt0')
        if args.mode == 'nat':
            cli('nat44 ei plugin enable sessions 4096')
            cli('nat44 ei output-chain tap3302')
            cli('set interface nat44 ei out tap3302 output-feature')
            cli('nat44 ei add address 192.0.2.250 tenant-vrf 0')
            for index in range(4):
                cli(f'set interface ip address tap3302 192.0.2.{160 + index}/24')
                cli(f'nat44 ei add static mapping local 10.252.12.{index + 2} external 192.0.2.{160 + index}')
        with (logdir / 'echo.log').open('w') as log:
            children.append(subprocess.Popen(['ip', 'netns', 'exec', names[1], 'taskset', '-c', '3',
                'python3', '-u', str(BASE / 'tools/udp-echo.py'), '--bind', '192.0.2.134',
                '--seconds', str(args.seconds + 90)], stdout=log, stderr=log))
        time.sleep(.3)
        for last in range(2, 6):
            run('ip', 'netns', 'exec', names[0], 'ping', '-I', f'10.252.12.{last}',
                '-c', '2', '-W', '2', '192.0.2.134')
        run('ip', 'netns', 'exec', names[0], 'python3', str(BASE / 'tools/nic1_soak.py'),
            '--probe', '192.0.2.134')
        cli('clear errors')
        cli('clear trace')
        cli('pcap trace drop max 64 file vrouter-tap-' + args.mode + '-drops.pcap max-bytes-per-pkt 2048')
        for index, name in enumerate(names):
            (logdir / f'snmp-{index}-before.txt').write_text(
                run('ip', 'netns', 'exec', name, 'cat', '/proc/net/snmp'))
        verifiers = []
        started = time.monotonic()
        for transport in ('icmp', 'udp'):
            with (logdir / f'{transport}-result.json').open('w') as log:
                child = subprocess.Popen(['ip', 'netns', 'exec', names[0], 'taskset', '-c',
                    '1' if args.mode == 'route' else '2', 'python3', str(BASE / 'tools/nic1_soak.py'),
                    transport, str(args.seconds), '192.0.2.134', str(logdir / f'{transport}-progress.json')],
                    stdout=log, stderr=log)
                children.append(child)
                verifiers.append(child)
        snapshots = []
        while time.monotonic() - started < args.seconds:
            assert process.poll() is None, 'VPP exited'
            assert all(child.poll() is None for child in children), 'Test process exited early'
            status = Path(f'/proc/{process.pid}/status').read_text()
            snapshots.append(dict(elapsed_seconds=time.monotonic() - started,
                memory_kib=dict((key, int(value)) for key, value in
                    re.findall(r'^(VmRSS|VmSize|VmData):\s+(\d+) kB', status, re.M))))
            (logdir / 'vpp-progress.json').write_text(json.dumps(snapshots[-1]))
            cli('show interface')
            cli('show errors')
            time.sleep(min(30, max(0, args.seconds - (time.monotonic() - started))))
        for child in verifiers:
            child.wait(timeout=8)
        for transport in ('icmp', 'udp'):
            report[transport] = json.loads((logdir / f'{transport}-result.json').read_text())
        for index, name in enumerate(names):
            (logdir / f'snmp-{index}-after.txt').write_text(
                run('ip', 'netns', 'exec', name, 'cat', '/proc/net/snmp'))
        report['memory_samples'] = snapshots
        kernel = run('journalctl', '-k', '--since', f'@{kernel_start}', '--no-pager')
        (logdir / 'kernel.log').write_text(kernel)
        report['kernel_fault'] = bool(re.search(
            r'BUG:|Oops:|Call Trace:|Out of memory|NETDEV WATCHDOG|SError|AER:.*(?:fatal|error)', kernel, re.I))
        report['passed'] = not report['kernel_fault'] and all(
            report[transport].get('passed', False) for transport in ('icmp', 'udp'))
        cli('show errors')
        cli('pcap trace off')
        (logdir / 'final-interfaces.txt').write_text(cli('show hardware-interfaces'))
    except Exception as exc:
        report['error'] = str(exc) + (': ' + exc.output[-2000:] if isinstance(exc, subprocess.CalledProcessError) else '')
        raise
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        restore(runtime)
        (logdir / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
