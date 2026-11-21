#!/usr/bin/env python3
"""Relink an isolated WireGuard plugin; leave the original build untouched."""
from pathlib import Path
import shlex
import shutil
import subprocess

base = Path('/opt/vpp-vrouter-migration')
build = Path('/opt/vpp-nic1-test/vpp-build')
source = base / 'source/wireguard-interface-peer/src'
original_source_tree = Path('/opt/vpp-nic1-test/src/vpp-stable-2606')
patch = base / 'source/plugins/wireguard-interface-peer.patch'
if not source.exists():
    shutil.copytree(original_source_tree / 'src/plugins/wireguard', source / 'plugins/wireguard')
    subprocess.run(['patch', '-p1', '--batch', '-i', str(patch)], cwd=source.parent, check=True)
subprocess.run(['patch', '-R', '--dry-run', '-p1', '--batch', '-i', str(patch)],
               cwd=source.parent, check=True, stdout=subprocess.DEVNULL)
output = base / 'wireguard-interface-peer'
output.mkdir(exist_ok=True)
target = 'lib/aarch64-linux-gnu/vpp_plugins/wireguard_plugin.so'
lines = subprocess.check_output(['ninja', '-t', 'commands', target], cwd=build, text=True).splitlines()
link = shlex.split(lines[-1].removeprefix(': && ').removesuffix(' && :'))
assert not any(token in ('&&', ';', '|') for token in link)
objects = [token for token in link if token.endswith('.o')]
replacements = {}
for original in objects:
    command_line = subprocess.check_output(['ninja', '-t', 'commands', original],
                                           cwd=build, text=True).splitlines()[-1]
    command = shlex.split(command_line)
    original_source = Path(command[command.index('-c') + 1])
    relative = original_source.relative_to('/opt/vpp-nic1-test/src/vpp-stable-2606/src')
    obj = output / original
    obj.parent.mkdir(parents=True, exist_ok=True)
    command.insert(1, '-I' + str(source))
    command.insert(2, '-I' + str(source / 'plugins'))
    for flag in ('-o', '-MF', '-MT', '-MQ'):
        if flag in command:
            command[command.index(flag) + 1] = str(obj) + ('.d' if flag == '-MF' else '')
    command[command.index('-c') + 1] = str(source / relative)
    subprocess.run(command, cwd=build, check=True)
    replacements[original] = str(obj)
link = [replacements.get(token, token) for token in link]
link[link.index('-o') + 1] = str(output / 'wireguard_plugin.so')
subprocess.run(link, cwd=build, check=True)
print('Built', output / 'wireguard_plugin.so')
