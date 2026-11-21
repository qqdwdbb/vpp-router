#!/usr/bin/env python3
"""Rebuild only the isolated EI plugin with input reassembly before handoff."""
from pathlib import Path
import argparse
import shlex
import subprocess

base = Path('/opt/vpp-vrouter-migration')
build = Path('/opt/vpp-nic1-test/vpp-build')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, default=base / 'source/nat44-ei-handoff/src/plugins/nat/nat44-ei/nat44_ei.c')
parser.add_argument('--output-dir', type=Path, default=base / 'nat44-ei-handoff')
args = parser.parse_args()
source = args.source
output = args.output_dir
output.mkdir(exist_ok=True)
obj = str(output / 'nat44_ei.c.o')
original = 'CMakeFiles/plugins/nat/CMakeFiles/nat44_ei_plugin.dir/nat44-ei/nat44_ei.c.o'
command = shlex.split((base / 'baseline/nat44-ei-compile-command.txt').read_text())
for flag in ('-o', '-MF', '-MT', '-MQ'):
    if flag in command:
        command[command.index(flag) + 1] = obj + ('.d' if flag == '-MF' else '')
command[command.index('-c') + 1] = str(source)
subprocess.run(command, cwd=build, check=True)
line = (base / 'baseline/nat44-ei-link-command.txt').read_text().strip()
command = shlex.split(line.removeprefix(': && ').removesuffix(' && :'))
assert not any(token in ('&&', ';', '|') for token in command)
command[command.index('-o') + 1] = str(output / 'nat44_ei_plugin.so')
assert original in command
command = [obj if token == original else token for token in command]
subprocess.run(command, cwd=build, check=True)
