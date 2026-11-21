#!/usr/bin/env python3
"""Router/root: exercise path-list copies after interface deletion in isolated VPP."""
import argparse
import os
from pathlib import Path
import resource
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library-dir', type=Path)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryDirectory(prefix='vpp-fib-copy-') as directory:
        root = Path(directory)
        sock = root / 'cli.sock'
        config = root / 'startup.conf'
        config.write_text(f'''unix {{ nodaemon runtime-dir {root}/run cli-listen {sock} }}
api-segment {{ prefix fib-copy-{os.getpid()} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock size 16M page-size 4k }}
memory {{ main-heap-size 128M main-heap-page-size 4k }}
buffers {{ buffers-per-numa 1024 page-size 4k }}
plugins {{ plugin default {{ disable }} }}
''')
        env = dict(os.environ)
        env['LD_LIBRARY_PATH'] = ':'.join(str(p) for p in (
            args.library_dir or Path('/usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu'),
            Path('/usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu'),
            Path('/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu')))
        with (root / 'vpp.log').open('w') as log:
            process = subprocess.Popen(['/usr/local/lib/vpp-vrouter/bin/vpp', '-c', str(config)],
                                       env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((root / 'vpp.log').read_text())
                if sock.exists():
                    break
                time.sleep(.1)

            def cli(command):
                result = subprocess.run(['/usr/local/lib/vpp-vrouter/bin/vppctl', '-s', str(sock), command],
                                        env=env, text=True, capture_output=True, timeout=10)
                if result.returncode or process.poll() is not None:
                    raise RuntimeError(f'{command}: VPP failed ({process.poll()})\n' +
                                       (root / 'vpp.log').read_text()[-1500:])
                assert not any(word in result.stdout.lower() for word in
                               ('unknown', 'failed', 'error')), (command, result.stdout)
                return result.stdout

            for family, address, prefix, next_hop in (
                (4, '192.0.2.1/24', '198.51.100.1/32', '192.0.2.2'),
                (6, '2001:db8:1::1/64', '2001:db8:2::1/128', '2001:db8:1::2')):
                cli('create loopback interface instance 901')
                cli('create loopback interface instance 902')
                cli(f'set interface ip address loop901 {address}')
                cli('set interface state loop901 up')
                cli('set interface state loop902 up')
                cli(f'ip route add {prefix} via {next_hop} loop901')
                cli('delete loopback interface intfc loop901')
                # Reuse the freed interface index. The old path must stay
                # poisoned rather than forward through this unrelated device.
                cli('create loopback interface instance 903')
                cli('set interface state loop903 up')
                # Copy the original path-list while adding a healthy path.
                cli(f'ip route add {prefix} via {next_hop} loop902')
                fib = cli(f'show ip{"6" if family == 6 else ""} fib {prefix}')
                assert 'loop903' not in fib, fib
                cli(f'ip route del {prefix}')
                cli('delete loopback interface intfc loop902')
                cli('delete loopback interface intfc loop903')
                print(f'PASS IPv{family}: deleted-interface path-list copy', flush=True)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
