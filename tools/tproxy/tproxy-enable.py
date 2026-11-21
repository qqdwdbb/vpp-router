#!/usr/bin/env python3
"""Explicitly enable/disable the proxylist/proxylist6 TPROXY mappings."""
import argparse
from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('enable', 'disable'))
    parser.add_argument('--set', dest='set_name', choices=('proxylist', 'proxylist6', 'all'), default='all')
    args = parser.parse_args()
    if args.action == 'enable':
        # Verify SOCKS5 itself, rather than treating an open TCP port as readiness.
        with socket.create_connection(('127.0.0.1', 1080), timeout=3) as peer:
            peer.sendall(b'\x05\x01\x00')
            reply = b''
            while len(reply) < 2:
                data = peer.recv(2 - len(reply))
                if not data:
                    break
                reply += data
            if reply != b'\x05\x00':
                raise RuntimeError('127.0.0.1:1080 must provide SOCKS5 without authentication')
        for unit in ('vpp-tproxy.service', 'ipt2socks-vpp.service'):
            subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
    path = Path('/etc/vpp/nftset-route-sync.json')
    with ExitStack() as stack:
        for name in ('vpp-wireguard-client-import', 'vpp-wireguard-import'):
            lock = stack.enter_context(open('/run/lock/' + name + '.lock', 'a+'))
            fcntl.flock(lock, fcntl.LOCK_EX)
        config = json.loads(path.read_text())
        targets = {'proxylist': '10.63.50.2', 'proxylist6': 'fd76:7070:2080::2'}
        if args.set_name != 'all':
            targets = {args.set_name: targets[args.set_name]}
        selected = []
        for name, gateway in targets.items():
            matches = [mapping for mapping in config['mappings'] if
                       (mapping['family'], mapping['table'], mapping['set']) == ('inet', 'mangle', name)]
            if len(matches) != 1 or matches[0]['interface'] != 'tap2080' or matches[0]['via'] != gateway:
                raise RuntimeError('Expected exactly one ' + name + ' mapping to tap2080 via ' + gateway)
            selected.append(matches[0])
        for mapping in selected:
            mapping['enabled'] = args.action == 'enable'
        temporary = path.with_suffix('.tproxy-new')
        with open(temporary, 'x') as stream:
            os.chmod(temporary, path.stat().st_mode & 0o777)
            stream.write(json.dumps(config, indent=2) + '\n')
        temporary.replace(path)
    subprocess.run(['systemctl', 'restart', 'vpp-dns-route-gate.service'], check=True)
    print(args.set_name + ' TPROXY mapping ' + args.action + 'd')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('TPROXY mapping update failed: ' + str(error))
