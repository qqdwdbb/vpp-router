#!/usr/bin/env python3
"""Build tally DMA fix on top of the deployed TX-reclaim PMD source and objects.

Run on VROUTER with --assets pointing to this patch and both regression scripts.
Does not install the library or restart services.
"""
import argparse
import hashlib
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path('/usr/local/src/vpp-vrouter')
BASE = ROOT / 'maintenance/tx-reclaim'
OUTPUT = ROOT / 'maintenance/tally-sync'
BUILD = ROOT / 'nic1-test/dpdk-build'


def command(path):
    text = path.read_text().splitlines()[0]
    text = text.replace('/opt/vpp-nic1-test', str(ROOT / 'nic1-test'))
    text = text.replace('/opt/vpp-vrouter-migration', str(ROOT / 'migration'))
    return shlex.split(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--expected-installed', type=Path)
    args = parser.parse_args()
    deployed = Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')
    expected = args.expected_installed or BASE / deployed.name
    if hashlib.sha256(deployed.read_bytes()).digest() != hashlib.sha256(expected.read_bytes()).digest():
        raise RuntimeError('Retained base PMD does not match installed PMD')
    output = args.output
    source = output / 'source'
    if source.exists():
        raise RuntimeError('Candidate source already exists; inspect it before rebuilding')
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(BASE / 'source', source)
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p4', '-i',
                    str(args.assets / 'r8169-tally-dma-sync.patch')], cwd=source, check=True)
    subprocess.run(['python3', str(args.assets / 'integration_r8169_tally_dma.py'),
                    '--source', str(source / 'r8169_hw.c')], check=True)
    subprocess.run(['python3', str(args.assets / 'integration_r8169_tx_reclaim.py'),
                    '--source', str(source / 'r8169_rxtx.c')], check=True)
    objects = {}
    template = command(ROOT / 'migration/baseline/rxtx-build-commands.txt')
    for name in ['r8169_rxtx', 'r8169_hw', 'r8169_ethdev']:
        obj = output / (name + '.o')
        compile_command = template.copy()
        for flag in ('-o', '-MF', '-MQ'):
            compile_command[compile_command.index(flag) + 1] = str(obj) + ('.d' if flag == '-MF' else '')
        compile_command[-1] = str(source / (name + '.c'))
        subprocess.run(compile_command, cwd=BUILD, check=True)
        objects[name] = obj
    link = command(ROOT / 'migration/baseline/r8169-link-command.txt')
    library = output / deployed.name
    link[link.index('-o') + 1] = str(library)
    for i, value in enumerate(link):
        for name, obj in objects.items():
            if value.endswith('/net_r8169_' + name + '.c.o'):
                link[i] = str(obj)
    subprocess.run(link, cwd=BUILD, check=True)
    subprocess.run(['patchelf', '--set-rpath', '$ORIGIN/../..', str(library)], check=True)
    print('Candidate:', library, hashlib.sha256(library.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
