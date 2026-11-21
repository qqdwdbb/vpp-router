#!/usr/bin/env python3
"""Load a built candidate in an isolated VPP; never change the production VPP.

Run as root on Linux: python3 integration_napt66_cli.py --plugin-dir DIR
DIR must contain a matching-ABI napt66_plugin.so.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin-dir', type=Path, required=True)
    parser.add_argument('--vpp', default='vpp')
    args = parser.parse_args()
    plugin_dir = args.plugin_dir.resolve()
    if not (plugin_dir / 'napt66_plugin.so').is_file():
        raise RuntimeError('candidate plugin missing')
    with tempfile.TemporaryDirectory(prefix='napt66-cli-') as directory:
        root = Path(directory)
        config = root / 'startup.conf'
        config.write_text(f'unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}\n'
                          f'plugins {{ path {plugin_dir} plugin default {{ disable }} '
                          'plugin napt66_plugin.so { enable } }\n')
        with (root / 'log').open('w+') as log:
            process = subprocess.Popen([args.vpp, '-c', str(config)], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if (root / 'cli.sock').exists():
                        break
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    time.sleep(.1)
                def cli(command):
                    return subprocess.check_output(['vppctl', '-s', str(root / 'cli.sock'), command],
                                                   text=True, timeout=10)
                for i in range(3):
                    cli(f'create loopback interface instance {i}')
                valid = ('napt66 inside loop0 prefix fd00::/64 inside loop1 prefix fd42:1111:2222:90::/64 '
                         'outside loop2 external 2001:db8::1')
                assert not cli(valid).strip()
                show = cli('show napt66')
                assert 'inside loop0' in show and 'inside loop1' in show
                for name in ('loop0', 'loop1', 'loop2'):
                    assert '\n  napt66' in cli('show interface features ' + name)
                assert 'disjoint' in cli(valid.replace('fd42:1111:2222:90::/64', 'fd00::/65'))
                assert 'inside loop1' in cli('show napt66')
                assert not cli('delete loopback interface intfc loop1').strip()
                show = cli('show napt66')
                assert 'inside loop0' in show and 'inside loop1' not in show
                assert not cli('napt66 disable').strip()
                assert 'disabled' in cli('show napt66')
                for name in ('loop0', 'loop2'):
                    assert '\n  napt66' not in cli('show interface features ' + name)
            finally:
                process.terminate()
                process.wait(timeout=10)
    print('PASS isolated VPP multi-inside CLI')


if __name__ == '__main__':
    main()
