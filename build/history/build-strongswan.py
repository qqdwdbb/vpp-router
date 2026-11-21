#!/usr/bin/env python3
"""Build only the strongSwan 5.9.8 VPP IPsec backend, outside system plugins."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess

base = Path('/opt/vpp-vrouter-migration')
strongswan = base/'strongswan-build/strongswan-5.9.8'
assert (strongswan/'config.h').exists(), 'Configure strongSwan 5.9.8 source headers first'
source = base/'strongswan-build/vpp-sswan-5.9'
source.mkdir(exist_ok=True)
original = Path('/opt/vpp-nic1-test/src/vpp-stable-2606/extras/strongswan/vpp_sswan')
for path in original.glob('*'):
    if path.is_file():
        shutil.copy2(path, source/path.name)
for name in ('strongswan-6-vpp-26.patch',
             'strongswan-5.9-vrouter.patch',
             'strongswan-ipv6-outer-policy.patch'):
    subprocess.run(['patch','--batch','-p1','-i',str(base/'source/plugins/strongswan-vpp'/name)],cwd=source,check=True)
messages = {}
for path in Path('/opt/vpp-nic1-test/vpp/share/vpp/api').rglob('*.api.json'):
    for message in json.loads(path.read_text()).get('messages',[]):
        if isinstance(message[-1],dict) and 'crc' in message[-1]:
            messages[message[0]] = message[-1]['crc'].removeprefix('0x')
for name in ('kernel_vpp_ipsec.c','kernel_vpp_shared.c'):
    path = source/name
    path.write_text(re.sub(r'"([a-z0-9_]+)_[0-9a-f]{8}"',
                           lambda match: '"'+match[1]+'_'+messages[match[1]]+'"',path.read_text()))
include = Path('/opt/vpp-nic1-test/vpp/include')
libraries = Path('/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu')
for unit in ('ipsec','shared','plugin'):
    subprocess.run(['gcc','-O2','-g','-Wall','-Wextra','-fPIC','-include',str(strongswan/'config.h'),
                    '-I'+str(strongswan/'src/libstrongswan'),'-I'+str(strongswan/'src/libcharon'),
                    '-I'+str(include),'-c',f'kernel_vpp_{unit}.c'],cwd=source,check=True)
plugin = source/'libstrongswan-kernel-vpp.so'
subprocess.run(['gcc','-shared','-o',str(plugin),'kernel_vpp_ipsec.o','kernel_vpp_shared.o','kernel_vpp_plugin.o',
                '-L'+str(libraries),'-Wl,-rpath,'+str(libraries),
                '-lvppinfra','-lvlibmemoryclient','-lvlibapi','-lsvm','-lvppapiclient'],cwd=source,check=True)
print('VROUTER backend sha256='+hashlib.sha256(plugin.read_bytes()).hexdigest())
