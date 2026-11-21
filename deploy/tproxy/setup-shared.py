#!/usr/bin/env python3
"""One-time local TPROXY policy; reuse the existing LAN/DNS bridge."""
import argparse
import json
from pathlib import Path
import subprocess


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise RuntimeError('TPROXY setup failed: ' + result.stderr.strip()[:400])
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rules-file', type=Path, required=True)
    args = parser.parse_args()
    run('nft', '-c', '-f', str(args.rules_file))
    for family in ('-4', '-6'):
        rules = json.loads(run('ip', '-j', family, 'rule', 'show'))
        reserved = [r for r in rules if r.get('priority') == 12080]
        if any(str(r.get('table')) != '2080' or str(r.get('fwmark')) not in ('8320', '0x2080')
               or str(r.get('fwmask', '0xffff')) not in ('65535', '0xffff') for r in reserved):
            raise RuntimeError('Policy priority 12080 is already used')
    for family, prefix in (('-4', '0.0.0.0/0'), ('-6', '::/0')):
        run('ip', family, 'route', 'replace', 'local', prefix, 'dev', 'lo', 'table', '2080')
        rules = json.loads(run('ip', '-j', family, 'rule', 'show'))
        if not any(r.get('priority') == 12080 for r in rules):
            run('ip', family, 'rule', 'add', 'priority', '12080', 'fwmark', '0x2080/0xffff', 'lookup', '2080')
    run('nft', '-f', str(args.rules_file))
    print('Shared LAN TAP TPROXY ready; replies use normal LAN routes')


if __name__ == '__main__':
    main()
