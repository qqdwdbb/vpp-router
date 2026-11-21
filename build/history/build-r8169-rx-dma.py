#!/usr/bin/env python3
"""Build staged r8169 DMA, RX rearm, scalar-cost and allocation optimizations.

Run on VROUTER. Assets contain the selected patch and r8169 regression scripts.
Does not install a library or restart VPP.
"""
import argparse
import hashlib
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path('/usr/local/src/vpp-vrouter')
BASE = ROOT / 'maintenance/tally-verified'
OUTPUT = ROOT / 'maintenance/rx-dma-batch'
TX_OUTPUT = ROOT / 'maintenance/tx-dma-batch'
BUILD = ROOT / 'nic1-test/dpdk-build'
DEPLOYED = Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')


def command(path):
    text = path.read_text().splitlines()[0]
    text = text.replace('/opt/vpp-nic1-test', str(ROOT / 'nic1-test'))
    text = text.replace('/opt/vpp-vrouter-migration', str(ROOT / 'migration'))
    return shlex.split(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    stages = parser.add_mutually_exclusive_group()
    stages.add_argument('--rx-rearm', action='store_true', help='Group four RX descriptor lines on the TX-batched base')
    stages.add_argument('--tx-dma', action='store_true', help='Add TX batching to the RX-batched base')
    stages.add_argument('--rx-scalar', action='store_true', help='Reduce scalar RX overhead on the four-line rearm base')
    stages.add_argument('--rx-alloc', action='store_true', help='Add scalar RX changes and bounded raw bulk allocation')
    args = parser.parse_args()
    allocation_stage = args.rx_scalar or args.rx_alloc
    base = ROOT / 'maintenance/rx-rearm-batch' if allocation_stage else (
        TX_OUTPUT if args.rx_rearm else (OUTPUT if args.tx_dma else BASE))
    output = args.output or (ROOT / 'maintenance/rx-rearm-batch' if args.rx_rearm else
                             (TX_OUTPUT if args.tx_dma else OUTPUT))
    if allocation_stage and args.output is None:
        output = ROOT / ('maintenance/rx-alloc-bulk' if args.rx_alloc else
                         'maintenance/rx-scalar-cost')
    baseline = base / DEPLOYED.name
    if hashlib.sha256(DEPLOYED.read_bytes()).digest() != hashlib.sha256(baseline.read_bytes()).digest():
        raise RuntimeError('Verified base PMD does not match installed PMD')
    # Refuse to overwrite a prior build or user changes.
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'
    shutil.copytree(base / 'source', source)
    stage = 'tx' if args.tx_dma else 'rx'
    subprocess.run(['python3', str(args.assets / f'integration_r8169_{stage}_dma.py'),
                    '--source', str(source / 'r8169_rxtx.c'),
                    *([] if args.rx_rearm or allocation_stage else ['--baseline'])], check=True)
    patches = [('r8169-rx-rearm-batch.patch' if args.rx_rearm else
                f'r8169-{stage}-dma-batch.patch')]
    if allocation_stage:
        patches = ['r8169-rx-scalar-cost.patch']
        if args.rx_alloc:
            patches.append('r8169-rx-alloc-bulk.patch')
    checks = [('rx_dma', 'rxtx'), ('tx_reclaim', 'rxtx'), ('tally_dma', 'hw')]
    if args.tx_dma or args.rx_rearm or allocation_stage:
        checks.append(('tx_dma', 'rxtx'))
    for patch in patches:
        subprocess.run(['patch', '--batch', '--fuzz=0', '-p4', '-i',
                        str(args.assets / patch)], cwd=source, check=True)
        for test, target in checks:
            subprocess.run(['python3', str(args.assets / f'integration_r8169_{test}.py'),
                            '--source', str(source / f'r8169_{target}.c')], check=True)
        if allocation_stage:
            for count in (12, 16):
                subprocess.run(['python3', str(args.assets / 'integration_r8169_rx_dma.py'),
                                '--source', str(source / 'r8169_rxtx.c'),
                                '--ring-size', str(count), '--sanitize'], check=True)
    template = command(ROOT / 'migration/baseline/rxtx-build-commands.txt')
    objects = {}
    for name in ['r8169_rxtx', 'r8169_hw', 'r8169_ethdev']:
        obj = output / (name + '.o')
        compile_command = template.copy()
        for flag in ('-o', '-MF', '-MQ'):
            compile_command[compile_command.index(flag) + 1] = str(obj) + ('.d' if flag == '-MF' else '')
        compile_command[-1] = str(source / (name + '.c'))
        subprocess.run(compile_command, cwd=BUILD, check=True)
        objects[name] = obj
    link = command(ROOT / 'migration/baseline/r8169-link-command.txt')
    library = output / DEPLOYED.name
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
