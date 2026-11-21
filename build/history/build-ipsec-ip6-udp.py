#!/usr/bin/env python3
"""Build a candidate libvnet for IPv6 ESP UDP checksums, retaining the PD fix.

Does not install or restart VPP. Validate in isolation before selecting this lib.
"""
from pathlib import Path
import hashlib
import shlex
import shutil
import subprocess

base = Path('/opt/vpp-vrouter-migration')
build = Path('/opt/vpp-nic1-test/vpp-build')
original_source = Path('/opt/vpp-nic1-test/src/vpp-stable-2606')
output = base / 'ipsec-ip6-udp'
relative = 'src/vnet/ipsec/esp_encrypt.c'
source = output / relative
pd_object = base / 'ipv6-pd/ip6_ra.c.o'
if not pd_object.is_file():
    raise RuntimeError('Build the isolated PD fix first')
source.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(original_source / relative, source)
subprocess.run(['patch', '--fuzz=0', '-p1', '-i',
                str(base / 'source/plugins/ipsec-ip6-udp-family-flags.patch')],
               cwd=output, check=True)
original_object = 'CMakeFiles/vnet/CMakeFiles/vnet_objs.dir/ipsec/esp_encrypt.c.o'
lines = subprocess.check_output(['ninja', '-t', 'commands', original_object],
                                cwd=build, text=True).splitlines()
line = next(line for line in lines if ' -c ' in line and line.endswith('/esp_encrypt.c'))
command = shlex.split(line)
obj = str(output / 'esp_encrypt.c.o')
for flag in ('-o', '-MF', '-MT', '-MQ'):
    if flag in command:
        command[command.index(flag)+1] = obj + ('.d' if flag == '-MF' else '')
command[command.index('-c')+1] = str(source)
subprocess.run(command, cwd=build, check=True)
lines = subprocess.check_output(['ninja', '-t', 'commands', 'vnet'],
                                cwd=build, text=True).splitlines()
line = next(line for line in lines if ' -o lib/aarch64-linux-gnu/libvnet.so.' in line)
command = shlex.split(line.removeprefix(': && ').removesuffix(' && :'))
assert not any(x in command for x in ('&&', ';', '|'))
library = output / 'lib/libvnet.so.26.06.0'
library.parent.mkdir(exist_ok=True)
command[command.index('-o')+1] = str(library)
pd_original = 'CMakeFiles/vnet/CMakeFiles/vnet_objs.dir/ip6-nd/ip6_ra.c.o'
assert original_object in command and pd_original in command
command = [obj if word == original_object else str(pd_object) if word == pd_original else word
           for word in command]
subprocess.run(command, cwd=build, check=True)
link = library.parent / 'libvnet.so'
if not link.exists():
    link.symlink_to(library.name)
print('candidate libvnet sha256=' + hashlib.sha256(library.read_bytes()).hexdigest())
