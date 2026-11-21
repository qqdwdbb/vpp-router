"""Router/root only: local-output ICMP regression in an isolated VPP instance."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=20).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugins', type=Path, required=True)
    parser.add_argument('--workers', default='1')
    args = parser.parse_args()
    namespace = f'ei-ping-{os.getpid()}'
    process = None
    with tempfile.TemporaryDirectory(prefix='ei-local-ping-') as tmp:
        root = Path(tmp)
        sock = str(root / 'cli.sock')
        plugins = root / 'plugins'
        plugins.mkdir()
        for name in ('nat44_ei', 'nat_ei_context', 'tap', 'ping'):
            filename = name + '_plugin.so'
            parent = args.plugins if name in ('nat44_ei', 'nat_ei_context') else Path('/usr/local/lib/vpp-vrouter/plugins')
            (plugins / filename).symlink_to(parent / filename)

        def cli(command):
            text = run('vppctl', '-s', sock, *command.split()).strip()
            assert not any(s in text.lower() for s in ('unknown input', 'failed', 'returned')), (command, text)
            return text

        workers = '' if args.workers == '0' else f'corelist-workers {args.workers}'
        config = root / 'startup.conf'
        config.write_text(f'''unix {{ nodaemon runtime-dir {root}/run cli-listen {sock} }}
api-segment {{ prefix ei-local-{os.getpid()} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock size 16M page-size 4k }}
cpu {{ main-core 0 {workers} }}
memory {{ main-heap-size 256M main-heap-page-size 4k }}
buffers {{ buffers-per-numa 2048 page-size 4k }}
plugins {{ path {plugins}
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
plugin nat44_ei_plugin.so {{ enable }}
plugin nat_ei_context_plugin.so {{ enable }}
}}
''')
        try:
            run('ip', 'netns', 'add', namespace)
            run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
            with (root / 'vpp.log').open('w') as log:
                process = subprocess.Popen(['/usr/local/lib/vpp-vrouter/bin/vpp', '-c', str(config)],
                                           stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((root / 'vpp.log').read_text())
                if Path(sock).exists():
                    break
                time.sleep(.1)
            cli(f'create tap id 1 host-ns {namespace} host-if-name ei-out host-ip4-addr 10.254.242.2/24')
            run('ip', '-n', namespace, 'link', 'set', 'ei-out', 'up')
            run('ip', 'netns', 'exec', namespace, 'ethtool', '-K', 'ei-out',
                'tx', 'off', 'gro', 'off', 'gso', 'off', 'tso', 'off')
            cli('set interface ip address tap1 10.254.242.1/24')
            cli('set interface state tap1 up')
            mac = json.loads(run('ip', '-n', namespace, '-j', 'link', 'show', 'ei-out'))[0]['address']
            cli(f'set ip neighbor tap1 10.254.242.2 {mac}')
            cli('ip table add 101')
            cli('create loopback interface instance 101')
            cli('set interface ip table loop101 101')
            cli('set interface state loop101 up')
            cli('ip route add 0.0.0.0/0 table 101 via ip4-lookup-in-table 0')
            cli('nat44 ei plugin enable sessions 256 users 64 user-sessions 256')
            cli('nat44 ei add address 10.254.242.1 tenant-vrf 101')
            cli('set interface nat44 ei out tap1 output-feature')
            cli('nat44 ei context tap1 loop101')
            cli('trace add tap-input 50')
            for source in ('', ' source tap1 table-id 0'):
                for _ in range(3):
                    text = cli(f'ping 10.254.242.2{source} repeat 3 interval 0.2 verbose')
                    assert '3 received' in text, (text, cli('show errors'), cli('show trace'))
                    assert process.poll() is None
            features = cli('show interface features tap1')
            if args.workers != '0':
                assert 'nat44-ei-out2in-worker-handoff' in features, features
                assert 'nat44-ei-in2out-output-worker-handoff' in features, features
            cli('set interface nat44 ei out tap1 output-feature del')
            assert process.poll() is None
            print(f'PASS workers={args.workers}: default/explicit-source local ICMP, NAT output context, interface deletion', flush=True)
        except Exception:
            if process and process.poll() is None and Path(sock).exists():
                print(cli('show errors'), flush=True)
                print(cli('show trace'), flush=True)
            raise
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            subprocess.run(['ip', 'netns', 'delete', namespace], capture_output=True)


if __name__ == '__main__':
    main()
