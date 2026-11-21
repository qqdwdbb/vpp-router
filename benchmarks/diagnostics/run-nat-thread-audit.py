#!/usr/bin/env python3
"""Compile the test-only injector and run the isolated NAT ownership matrix.

Run as root on the VROUTER with the VPP source/build trees available. Production
services and plugins are not changed. Individual fixtures remove their netns.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--plugins', type=Path, default=Path('/usr/local/lib/vpp-vrouter/plugins'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--thread-control', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path('/opt/vpp-nic1-test/src/vpp-stable-2606/src')
    generated = Path('/opt/vpp-nic1-test/vpp-build/CMakeFiles')
    reports = []
    with tempfile.TemporaryDirectory(prefix='ei-audit-helper-') as temporary:
        helper = Path(temporary) / 'nat_thread_audit_inject_plugin.so'
        subprocess.run(['gcc', '-shared', '-fPIC', '-g', '-O2', '-Werror', '-Wall',
                        '-march=armv8-a+crc', '-I' + str(source), '-I' + str(generated),
                        '-o', str(helper), str(args.repo / 'tests/integration/fixtures/nat_thread_audit_inject.c')], check=True)
        for mode in ('output', 'input'):
            for count, workers in ((0, '0'), (1, '1'), (2, '1,2')):
                output = args.output / f'thread-audit-{mode}-{count}.json'
                command = ['python3', str(args.repo / 'tests/integration/integration_nat44_ei_thread_audit.py'),
                           '--plugins', str(args.plugins), '--inject-plugin', str(helper),
                           '--workers', workers, '--mode', mode, '--result', str(output)]
                if args.thread_control:
                    command.append('--thread-control')
                result = subprocess.run(command, timeout=180)
                reports.append({'mode': mode, 'workers': count, 'exit_code': result.returncode,
                                'result': str(output)})
    (args.output / 'matrix.json').write_text(json.dumps(reports, indent=2) + '\n')
    if any(item['exit_code'] for item in reports):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
