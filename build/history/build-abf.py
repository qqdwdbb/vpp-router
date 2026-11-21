#!/usr/bin/env python3
"""Build stock ABF in a private tree using the installed VPP ABI libraries."""
from pathlib import Path
import hashlib
import json
import shlex
import subprocess

base = Path('/opt/vpp-vrouter-migration')
source = Path('/opt/vpp-nic1-test/src/vpp-stable-2606/src')
original = Path('/opt/vpp-nic1-test/vpp-build')
build = base / 'abf-build'
installed = Path('/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu')
subprocess.run(['cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja',
                '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=gcc',
                '-DCMAKE_INSTALL_PREFIX=' + str(base/'abf-runtime'),
                '-DVPP_PLUGINS=acl,abf', '-DVPP_BUILD_NATIVE_ONLY=ON', '-DVPP_NO_TESTS=ON'], check=True)
target = 'lib/aarch64-linux-gnu/vpp_plugins/abf_plugin.so'
outputs = subprocess.check_output(['ninja','-t','targets','all'],cwd=build,text=True).splitlines()
headers = [line.split(': ',1)[0] for line in outputs
           if '/abf/' in line and line.split(': ',1)[0].endswith('.h')]
assert headers
api_json = 'CMakeFiles/plugins/abf/abf.api.json'
subprocess.run(['ninja', *headers, api_json],cwd=build,check=True)
# This checkout's generated API C references a JSON header not wired in CMake.
(build/'CMakeFiles/plugins/abf/abf.api_json.h').write_text(
    'const char *json_api_repr_abf = ' + json.dumps((build/api_json).read_text()) + ';\n')
lines = subprocess.check_output(['ninja','-t','commands',target],cwd=build,text=True).splitlines()
link = shlex.split(lines[-1].removeprefix(': && ').removesuffix(' && :'))
assert not any(word in ('&&',';','|') for word in link)
objects = [word for word in link if word.endswith('.o')]
for obj in objects:
    line = subprocess.check_output(['ninja','-t','commands',obj],cwd=build,text=True).splitlines()[-1]
    command = shlex.split(line)
    command.insert(1, '-I'+str(original/'CMakeFiles'))
    command.insert(2, '-I'+str(original/'CMakeFiles/plugins'))
    subprocess.run(command,cwd=build,check=True)
for i,word in enumerate(link):
    if word.startswith('lib/') and '.so.' in word:
        library = installed / Path(word).name
        assert library.exists(), library.name
        link[i] = str(library)
subprocess.run(link,cwd=build,check=True)
plugin = build / target
print('ABF built sha256='+hashlib.sha256(plugin.read_bytes()).hexdigest())
