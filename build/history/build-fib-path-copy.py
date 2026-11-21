#!/usr/bin/env python3
"""Build an isolated libvnet with the deleted-interface path-copy fix."""
import argparse
import hashlib
from pathlib import Path
import shlex
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--patch', type=Path, required=True)
    args = parser.parse_args()
    build = Path('/opt/vpp-nic1-test/vpp-build')
    original = Path('/opt/vpp-nic1-test/src/vpp-stable-2606')
    output = args.output.resolve()
    relative = 'src/vnet/fib/fib_path.c'
    source = output / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(original / relative, source)
    subprocess.run(['patch', '--fuzz=0', '-p1', '-i', str(args.patch.resolve())],
                   cwd=output, check=True)
    target = 'CMakeFiles/vnet/CMakeFiles/vnet_objs.dir/fib/fib_path.c.o'
    commands = subprocess.check_output(['ninja', '-t', 'commands', target], cwd=build, text=True)
    command = shlex.split(next(line for line in commands.splitlines()
                              if ' -c ' in line and line.endswith('/fib_path.c')))
    obj = str(output / 'fib_path.c.o')
    for flag in ('-o', '-MF', '-MT', '-MQ'):
        if flag in command:
            command[command.index(flag) + 1] = obj + ('.d' if flag == '-MF' else '')
    command[command.index('-c') + 1] = str(source)
    subprocess.run(command, cwd=build, check=True)
    commands = subprocess.check_output(['ninja', '-t', 'commands', 'vnet'], cwd=build, text=True)
    line = next(line for line in commands.splitlines() if ' -o lib/aarch64-linux-gnu/libvnet.so.' in line)
    command = shlex.split(line.removeprefix(': && ').removesuffix(' && :'))
    assert not any(token in ('&&', ';', '|') for token in command)
    library = output / 'lib/libvnet.so.26.06.0'
    library.parent.mkdir(exist_ok=True)
    command[command.index('-o') + 1] = str(library)
    # Retain both fixes in the currently deployed libvnet. Re-link that
    # baseline first and refuse a candidate if its provenance does not match.
    replacements = {
        'CMakeFiles/vnet/CMakeFiles/vnet_objs.dir/ip6-nd/ip6_ra.c.o':
            '/opt/vpp-vrouter-migration/ipv6-pd/ip6_ra.c.o',
        'CMakeFiles/vnet/CMakeFiles/vnet_objs.dir/ipsec/esp_encrypt.c.o':
            '/opt/vpp-vrouter-migration/ipsec-ip6-udp/esp_encrypt.c.o',
    }
    assert target in command and all(key in command for key in replacements)
    command = [replacements.get(token, token) for token in command]
    baseline = output / 'baseline.so'
    command[command.index('-o') + 1] = str(baseline)
    subprocess.run(command, cwd=build, check=True)
    installed = Path('/usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu/libvnet.so.26.06.0')
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    if digest(baseline) != digest(installed):
        raise RuntimeError('Re-linked baseline differs from installed libvnet')
    command[command.index('-o') + 1] = str(library)
    command = [obj if token == target else token for token in command]
    subprocess.run(command, cwd=build, check=True)
    print(library)


if __name__ == '__main__':
    main()
