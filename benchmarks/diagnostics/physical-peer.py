#!/usr/bin/env python3
"""Run on the independent Linux peer, while nic1 is isolated in VPP."""
import argparse
import json
from pathlib import Path
import subprocess
import time

from nic1_soak import datagram_integrity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--source', default='10.61.20.134')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 7200:
        parser.error('seconds must be 1..7200')
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    targets = [f'10.61.20.{last}' for last in range(160, 240)]
    deadline = time.monotonic() + 300
    for target in targets:
        while True:
            probe = subprocess.run(['ping', '-I', args.source, '-c', '1', '-W', '1', target],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            if probe.returncode == 0:
                break
            if time.monotonic() > deadline:
                raise RuntimeError(f'Native VPP echo not ready: {target}')
            time.sleep(.5)
    (args.output / 'ready.json').write_text(json.dumps(dict(targets=targets)))
    result = dict(path='physical NIC <-> VPP native ICMP echo; no TAP/NAT',
                  targets=targets)
    (args.output / 'snmp-before.txt').write_text(Path('/proc/net/snmp').read_text())
    datagram_integrity([args.source] * len(targets), args.seconds, targets, result,
        transport='icmp', progress=args.output / 'progress.json')
    (args.output / 'snmp-after.txt').write_text(Path('/proc/net/snmp').read_text())
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result.get('passed') else 1)


if __name__ == '__main__':
    main()
