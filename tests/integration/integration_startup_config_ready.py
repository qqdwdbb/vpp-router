#!/usr/bin/env python3
"""Check startup-config ordering and latency in isolated VPP instances.

Uses no physical interfaces. Run as root with a candidate libvlib; tests both
zero and one worker. The default latency limit rejects the old fixed delay.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--vpp', default='/usr/local/bin/vpp')
    parser.add_argument('--vppctl', default='/usr/local/bin/vppctl')
    parser.add_argument('--max-startup-seconds', type=float, default=1.8)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    results = []
    for workers in (0, 1):
        with ExitStack() as contexts:
            directory = contexts.enter_context(
                tempfile.TemporaryDirectory(prefix='startup-ready-', dir='/run'))
            library_directory = contexts.enter_context(
                tempfile.TemporaryDirectory(prefix='startup-ready-lib-', dir=args.library.resolve().parent))
            root = Path(directory)
            # /run can be mounted noexec; only sockets and configs belong there.
            library = Path(library_directory) / 'libvlib.so.26.06.0'
            shutil.copyfile(args.library, library)
            startup = root / 'startup.vpp'
            startup.write_text('create loopback interface instance 989\n'
                               'set interface state loop989 up\n')
            config = root / 'startup.conf'
            config.write_text(f'''unix {{ nodaemon nosyslog runtime-dir {root}
cli-listen {root}/cli.sock startup-config {startup} }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
cpu {{ workers {workers} }}
memory {{ main-heap-size 128M }}
buffers {{ buffers-per-numa 1024 page-size 4k }}
plugins {{ plugin default {{ disable }} }}
''')
            env = dict(os.environ)
            env['LD_LIBRARY_PATH'] = str(library.parent) + ':' + env.get('LD_LIBRARY_PATH', '')
            with (root / 'vpp.log').open('w') as log:
                started = time.monotonic()
                process = subprocess.Popen([args.vpp, '-c', str(config)], env=env,
                                           stdout=log, stderr=log)
                try:
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError((root / 'vpp.log').read_text())
                        result = subprocess.run(
                            [args.vppctl, '-s', str(root / 'cli.sock'), 'show interface'],
                            capture_output=True, text=True, timeout=5)
                        elapsed = time.monotonic() - started
                        if result.returncode == 0 and 'loop989' in result.stdout:
                            break
                        if elapsed > 8:
                            raise RuntimeError('startup configuration did not create loop989')
                        time.sleep(0.02)
                    results.append(dict(workers=workers, startup_seconds=elapsed))
                    if elapsed >= args.max_startup_seconds:
                        raise AssertionError(f'startup still delayed: {elapsed:.3f}s')
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    args.report.write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results))


if __name__ == '__main__':
    main()
