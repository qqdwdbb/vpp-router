#!/usr/bin/env python3
"""Build EI single-worker handoff fixes, preserving the deployed expiry fixes.

Builds candidates only; does not install or restart VPP.
"""
import argparse
from pathlib import Path
import shlex
import subprocess


def main():
    base = Path('/opt/vpp-vrouter-migration')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=base / 'nat44-ei-expiry')
    parser.add_argument('--output-dir', type=Path, default=base / 'nat44-ei-single-worker')
    parser.add_argument('--context-source', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    build = Path('/opt/vpp-nic1-test/vpp-build')
    source = (args.source_dir / 'nat44_ei.c').read_text()
    # Main-thread local output exists even with exactly one worker. Both
    # directions must select the session owner before using a per-thread pool.
    assert source.count('nm->num_workers > 1') == 11
    assert source.count('nm->num_workers < 2') == 1
    source = source.replace('nm->num_workers > 1', 'nm->num_workers > 0')
    source = source.replace('nm->num_workers < 2', 'nm->num_workers < 1')
    target = output / 'nat44_ei.c'
    target.write_text(source)
    template = shlex.split((base / 'baseline/nat44-ei-compile-command.txt').read_text())

    def compile_one(src, obj):
        command = template.copy()
        for flag in ('-o', '-MF', '-MT', '-MQ'):
            if flag in command:
                command[command.index(flag) + 1] = str(obj) + ('.d' if flag == '-MF' else '')
        command[command.index('-c') + 1] = str(src)
        subprocess.run(command, cwd=build, check=True)

    obj = output / 'nat44_ei.c.o'
    compile_one(target, obj)
    prefix = 'CMakeFiles/plugins/nat/CMakeFiles/nat44_ei_plugin.dir/nat44-ei/'
    replacements = {
        prefix + 'nat44_ei.c.o': str(obj),
        prefix + 'nat44_ei_cli.c.o': str(args.source_dir / 'nat44_ei_cli.c.o'),
        prefix + 'nat44_ei_in2out.c.o': str(base / 'nat-resource-fix-20261019/nat44_ei_in2out.c.o'),
    }
    line = (base / 'baseline/nat44-ei-link-command.txt').read_text().strip()
    command = shlex.split(line.removeprefix(': && ').removesuffix(' && :'))
    assert all(key in command for key in replacements)
    command = [replacements.get(token, token) for token in command]
    command[command.index('-o') + 1] = str(output / 'nat44_ei_plugin.so')
    subprocess.run(command, cwd=build, check=True)
    context_obj = output / 'nat_ei_context.c.o'
    compile_one(args.context_source, context_obj)
    subprocess.run(['gcc', '-shared', '-o', str(output / 'nat_ei_context_plugin.so'),
                    str(context_obj)], cwd=build, check=True)
    print(output)


if __name__ == '__main__':
    main()
