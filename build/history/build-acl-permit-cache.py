#!/usr/bin/env python3
"""Build an isolated ACL candidate, verifying the retained original link first."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tree', type=Path,
                        default=Path('/usr/local/src/vpp-vrouter/nic1-test'))
    args = parser.parse_args()
    build = args.tree / 'vpp-build'
    src = args.tree / 'src/vpp-stable-2606'
    installed = Path('/usr/local/lib/vpp-vrouter/plugins/acl_plugin.so')
    output = args.output
    output.mkdir(parents=True, exist_ok=False)

    def run(argv):
        return subprocess.check_output(argv, cwd=build, text=True)

    def relocate(token):
        return token.replace('/opt/vpp-nic1-test', str(args.tree))

    target = 'lib/aarch64-linux-gnu/vpp_plugins/acl_plugin.so'
    line = run(['ninja', '-t', 'commands', target]).splitlines()[-1]
    link = [relocate(t) for t in shlex.split(line.removeprefix(': && ').removesuffix(' && :'))]
    assert not any(t in ('&&', ';', '|') for t in link)
    baseline = link.copy()
    baseline[baseline.index('-o') + 1] = str(output / 'baseline-acl_plugin.so')
    subprocess.run(baseline, cwd=build, check=True)
    # Installed files have a relocated RUNPATH added by the installer. Compare
    # the executable/constant/data/unwind sections rather than container bytes.
    section_hashes = {}
    with tempfile.TemporaryDirectory(prefix='acl-link-verify-') as tmp:
        for section in ('.text', '.rodata', '.data', '.eh_frame'):
            hashes = []
            for index, binary in enumerate((output / 'baseline-acl_plugin.so', installed)):
                dump = Path(tmp) / (section + str(index))
                subprocess.run(['objcopy', '--dump-section', section + '=' + str(dump),
                                str(binary), str(Path(tmp) / ('copy' + str(index)))], check=True)
                hashes.append(sha(dump))
            if hashes[0] != hashes[1]:
                raise RuntimeError('installed ACL section differs from retained build: ' + section)
            section_hashes[section] = hashes[0]

    node = Path('src/plugins/acl/dataplane_node.c')
    dest = output / 'source' / node
    dest.parent.mkdir(parents=True)
    shutil.copy2(src / node, dest)
    shutil.copy2(args.assets / 'acl-permit-frame-cache.h', dest.parent)
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i',
                    str(args.assets / 'acl-permit-frame-cache.patch')],
                   cwd=output / 'source', check=True)
    original_obj = 'CMakeFiles/plugins/acl/CMakeFiles/acl_plugin.dir/dataplane_node.c.o'
    command = [relocate(t) for t in shlex.split(
        run(['ninja', '-t', 'commands', original_obj]).splitlines()[-1])]
    obj = output / 'dataplane_node.c.o'
    for flag in ('-o', '-MF', '-MT', '-MQ'):
        if flag in command:
            command[command.index(flag) + 1] = str(obj) + ('.d' if flag == '-MF' else '')
    command[command.index('-c') + 1] = str(dest)
    subprocess.run(command, cwd=build, check=True)
    candidate_link = [str(obj) if t == original_obj else t for t in link]
    candidate_link[candidate_link.index('-o') + 1] = str(output / 'acl_plugin.so')
    subprocess.run(candidate_link, cwd=build, check=True)
    rpath = run(['patchelf', '--print-rpath', str(installed)]).strip()
    subprocess.run(['patchelf', '--set-rpath', rpath, str(output / 'acl_plugin.so')], check=True)
    result = {'installed_sha256': sha(installed), 'baseline_sha256': sha(output / 'baseline-acl_plugin.so'),
              'candidate_sha256': sha(output / 'acl_plugin.so'), 'compile': command,
              'link': candidate_link, 'source_sha256': sha(dest),
              'verified_baseline_sections': section_hashes}
    (output / 'build.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
