#!/usr/bin/env python3
"""Reproduce an empty interrupt RX ring under deterministic allocation failure.

Requires root and an isolated, fault-injection TAP build from build-tap-refill.py.
Never attaches a physical interface or changes production VPP state.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugins', type=Path, required=True)
    parser.add_argument('--workers', type=int, choices=(0, 2), required=True)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    runtime = Path('/usr/local/lib/vpp-vrouter')
    env = dict(os.environ, LD_LIBRARY_PATH='/usr/local/lib/aarch64-linux-gnu:'+str(runtime/'lib/aarch64-linux-gnu'))

    def run(*command, timeout=15):
        result = subprocess.run(list(map(str, command)), text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout, env=env)
        if result.returncode:
            raise RuntimeError(' '.join(map(str, command))+': '+result.stdout)
        return result.stdout

    with tempfile.TemporaryDirectory(prefix='tap-refill-', dir='/run') as temporary:
        root = Path(temporary)
        namespace = root.name
        plugin_dir = root/'plugins'
        plugin_dir.mkdir()
        (plugin_dir/'tap_plugin.so').symlink_to(args.plugins.resolve()/'tap_plugin.so')
        (plugin_dir/'ping_plugin.so').symlink_to(runtime/'plugins/ping_plugin.so')
        config = root/'startup.conf'
        config.write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {namespace} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
cpu {{ {'workers 2' if args.workers else ''} }}
memory {{ main-heap-size 128M }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
plugins {{ path {plugin_dir}
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
}}
''')
        log = (root/'vpp.log').open('w')
        process = subprocess.Popen([str(runtime/'bin/vpp'), '-c', str(config)], env=env,
                                   stdout=log, stderr=log)

        def cli(command):
            text = run(runtime/'bin/vppctl', '-s', root/'cli.sock', command)
            if not command.startswith('show ') and re.search(r'unknown|failed|invalid|error:', text, re.I):
                raise RuntimeError(text)
            return text

        def ring():
            match = re.search(r'Virtqueue \(RX\) 0\s+qsz \d+, last_used_idx \d+, desc_next \d+, desc_in_use (\d+)', cli('show tap'))
            assert match
            return int(match[1])

        report = dict(workers=args.workers, baseline=args.baseline, cycles=[])
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((root/'vpp.log').read_text()[-3000:])
                if (root/'cli.sock').exists():
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('VPP startup timeout')
            run('ip', 'netns', 'add', namespace)
            run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
            cli(f'create tap id 3999 host-ns {namespace} host-if-name test0 host-ip4-addr 198.18.99.2/24')
            run('ip', '-n', namespace, 'link', 'set', 'test0', 'up')
            run('ip', 'netns', 'exec', namespace, 'ethtool', '-K', 'test0', 'tx', 'off')
            cli('set interface ip address tap3999 198.18.99.1/24')
            cli('set interface state tap3999 up')
            cli('set interface rx-mode tap3999 interrupt')
            run('ip', 'netns', 'exec', namespace, 'ping', '-c', '2', '-W', '1', '198.18.99.1')
            for cycle in range(3):
                cli('test tap-refill-fail 1')
                run('ip', 'netns', 'exec', namespace, 'python3', '-c',
                    'import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
                    '[(s.sendto(b"x"*64,("198.18.99.1",45000)),time.sleep(.0005)) for _ in range(700)]')
                assert ring() == 0, 'Fault did not drain the RX descriptors'
                cli('test tap-refill-fail 0')
                # No new host traffic or polling-mode toggle: buffer recovery
                # alone must refill a queue that cannot generate completions.
                deadline = time.monotonic()+1
                restored = 0
                while time.monotonic() < deadline:
                    restored = ring()
                    if restored:
                        break
                    time.sleep(.02)
                assert bool(restored) != args.baseline, (args.baseline, restored)
                report['cycles'].append(dict(drained=True, automatic_refill=bool(restored)))
                if args.baseline:
                    cli('set interface rx-mode tap3999 polling')
                    time.sleep(.1)
                    cli('set interface rx-mode tap3999 interrupt')
                run('ip', 'netns', 'exec', namespace, 'ping', '-c', '3', '-W', '1', '198.18.99.1')
            report['errors'] = cli('show errors')
            # Destroy an interface with a pending retry; no retained queue
            # pointer/index may survive deletion in the process scan.
            cli('test tap-refill-fail 1')
            run('ip', 'netns', 'exec', namespace, 'python3', '-c',
                'import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
                '[(s.sendto(b"x",("198.18.99.1",45000)),time.sleep(.0005)) for _ in range(700)]')
            assert ring() == 0
            cli('delete tap tap3999')
            cli('test tap-refill-fail 0')
            time.sleep(.1)
            cli('show version')
            report['delete_pending_passed'] = True
            report['passed'] = True
            args.report.write_text(json.dumps(report, indent=2)+'\n')
            print(json.dumps(report))
        except Exception:
            if (root/'cli.sock').exists() and process.poll() is None:
                print(cli('show tap'))
                print(cli('show interface address'))
                print(cli('show errors'))
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            subprocess.run(['ip', 'netns', 'delete', namespace], capture_output=True)
            log.close()


if __name__ == '__main__':
    main()
