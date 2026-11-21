#!/usr/bin/env python3
"""Build a candidate RTL8125 PMD on VROUTER, retaining its noncoherent DMA patch.

Uses the retained Ninja compile/link commands and objects. Does not install
or restart VPP. Run integration_r8169_tx_reclaim.py against the copied source.
"""
from pathlib import Path
import argparse
import shlex
import shutil
import subprocess

ARTIFACTS = Path('/usr/local/src/vpp-vrouter')
MIGRATION = ARTIFACTS/'migration'
OUTPUT = ARTIFACTS/'maintenance/tx-reclaim'
BUILD = ARTIFACTS/'nic1-test/dpdk-build'


def command(path):
    text = path.read_text().splitlines()[0]
    text = text.replace('/opt/vpp-nic1-test', str(ARTIFACTS/'nic1-test'))
    text = text.replace('/opt/vpp-vrouter-migration', str(MIGRATION))
    return shlex.split(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    output = args.output
    source = MIGRATION/'source/dma-r8169'
    assert 'R8169_DMA_NONCOHERENT' in (source/'r8169_rxtx.c').read_text()
    output.mkdir(parents=True, exist_ok=True)
    candidate = output/'source'
    if candidate.exists():
        raise RuntimeError('Candidate source exists; inspect it before rebuilding')
    shutil.copytree(source, candidate)
    subprocess.run(['patch', '--batch', '--fuzz=0', '-p4', '-i',
                    str(OUTPUT/'r8169-tx-reclaim.patch')], cwd=candidate, check=True)
    subprocess.run(['python3', str(OUTPUT/'test.py'), '--source',
                    str(candidate/'r8169_rxtx.c')], check=True)
    obj = output/'r8169_rxtx.o'
    compile_command = command(MIGRATION/'baseline/rxtx-build-commands.txt')
    for flag in ('-o', '-MF', '-MQ'):
        compile_command[compile_command.index(flag)+1] = str(obj)+('.d' if flag == '-MF' else '')
    compile_command[-1] = str(candidate/'r8169_rxtx.c')
    subprocess.run(compile_command, cwd=BUILD, check=True)
    link_command = command(MIGRATION/'baseline/r8169-link-command.txt')
    library = output/'librte_net_r8169.so.26.1'
    link_command[link_command.index('-o')+1] = str(library)
    link_command = [str(obj) if value.endswith('/net_r8169_r8169_rxtx.c.o') else value
                    for value in link_command]
    subprocess.run(link_command, cwd=BUILD, check=True)
    subprocess.run(['patchelf', '--set-rpath', '$ORIGIN/../..', str(library)], check=True)
    print('Candidate ready:', library)


if __name__ == '__main__':
    main()
