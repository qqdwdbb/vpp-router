#!/usr/bin/env python3
"""Install VPP WireGuard interfaces from /etc/wireguard, without daemons."""
import argparse
from contextlib import ExitStack
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import time

UNITS = ('vpp-wireguard-import.service', 'vpp-wireguard-client-import.service',
         'vpp-wireguard-import.timer', 'vpp-wireguard-client-import.timer')


def block(text, name, lines):
    begin, end = '# BEGIN ' + name, '# END ' + name
    pattern = re.compile(r'(?m)^' + re.escape(begin) + r'\n.*?^' + re.escape(end) + r'\n?', re.S)
    if text.count(begin) != text.count(end) or text.count(begin) > 1:
        raise RuntimeError('Invalid existing managed configuration block')
    replacement = begin + '\n' + '\n'.join(lines) + '\n' + end + '\n'
    return pattern.sub(lambda unused: replacement, text) if begin in text else text.rstrip() + '\n\n' + replacement


def write(path, text, mode):
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError('Installation command failed: ' + Path(args[0]).name + '; details suppressed')


def source_address(explicit, target, describe, interface):
    if explicit:
        return str(ipaddress.IPv4Address(explicit))
    if target.exists():
        return describe(target.read_text(), interface)[1]['source']
    raise RuntimeError('First installation requires --source-address for the VPP create command')


def install(interfaces, source):
    directory = Path('/etc/vpp/wireguard')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    static = runpy.run_path('/usr/local/sbin/vpp-wireguard-static', run_name='static_install')
    helpers = runpy.run_path('/usr/local/sbin/vpp-import-wireguard', run_name='install_helpers')
    nat = Path('/etc/vpp/nat.conf')
    prepare = Path('/usr/local/sbin/vpp-net-prepare')
    # Verify required boot files before applying any WireGuard changes.
    nat.read_text()
    prepare.read_text()
    Path('/root/vpp-nat-backup').mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix='wireguard-install-', dir='/root/vpp-nat-backup'))
    paths = [nat, prepare] + list(directory.glob('wg*.conf'))
    paths += [Path('/etc/systemd/system') / name for name in UNITS]
    paths += [Path('/etc/systemd/system') / name for name in ('vpp-dns-route-gate.service', 'vpp-nft-route-sync.service')]
    for path in paths:
        if path.exists():
            shutil.copy2(path, backup / path.name)
    with tempfile.TemporaryDirectory(prefix='.install-', dir=directory) as staging:
        # Render and validate every requested interface before changing live state.
        descriptions = {}
        for interface in interfaces:
            target = directory / (interface + '.conf')
            src = source_address(source, target, static['describe'], interface)
            exporter = 'vpp-import-wireguard' + ('-client' if interface == 'wg1' else '')
            staged = Path(staging) / target.name
            run(['/usr/local/sbin/' + exporter, '--export', str(staged), '--source-address', src])
            descriptions[interface] = static['describe'](staged.read_text(), interface)
        for interface in interfaces:
            target = directory / (interface + '.conf')
            exists = bool(re.search(r'^' + interface + r'\s', helpers['cli']('show interface'), re.M))
            if exists:
                # Native VPP startup does not write Python state. Validate the
                # previously installed file before allowing an explicit update.
                if not target.exists():
                    raise RuntimeError('Existing interface has no installed static configuration')
                static['load'](interface, helpers, adopt=True)
            lines, unused = descriptions[interface]
            previous = static['describe'](target.read_text(), interface)[0] if target.exists() else None
            if previous != lines:
                write(target, (Path(staging) / target.name).read_text(), 0o600)
            static['load'](interface, helpers, replace=exists)
    configs = [interface for interface in ('wg0', 'wg1') if (directory / (interface + '.conf')).exists()]
    boot = ['exec ' + str(directory / (interface + '.conf')) for interface in configs]
    write(nat, block(nat.read_text(), 'VPP WIREGUARD', boot), nat.stat().st_mode & 0o777)
    host_routes = []
    for interface in configs:
        description = static['describe']((directory / (interface + '.conf')).read_text(), interface)[1]
        for network in sorted({str(ipaddress.ip_interface(address).network) for address in description['addresses']}):
            ipv6 = ipaddress.ip_network(network).version == 6
            host_routes.append('ip ' + ('-6' if ipv6 else '-4') + ' route replace ' + network +
                               ' via ' + ('fe80::76:70ff:fe70:801' if ipv6 else '10.61.30.1') + ' dev br-vpp-lan')
    write(prepare, block(prepare.read_text(), 'VPP WIREGUARD HOST ROUTES', host_routes), prepare.stat().st_mode & 0o777)
    for unit in UNITS:
        path = Path('/etc/systemd/system') / unit
        if path.exists():
            run(['systemctl', 'disable', '--now', unit])
            path.unlink()
    for unit in ('vpp-dns-route-gate.service', 'vpp-nft-route-sync.service'):
        path = Path('/etc/systemd/system') / unit
        if path.exists():
            text = path.read_text().replace(' vpp-wireguard-client-import.service', '')
            write(path, text, path.stat().st_mode & 0o777)
    run(['systemctl', 'daemon-reload'])
    print('Installed ' + ', '.join(interfaces) + '; native VPP startup configured; backup: ' + str(backup))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('interface', choices=('wg0', 'wg1', 'all'))
    parser.add_argument('--source-address', help='Explicit VPP outer source; defaults to the installed static value')
    args = parser.parse_args()
    os.umask(0o077)
    interfaces = ('wg0', 'wg1') if args.interface == 'all' else (args.interface,)
    # Same order as NAT reconciliation: no exporter/loader runs outside these locks.
    with ExitStack() as stack:
        for interface in sorted(interfaces, reverse=True):
            suffix = '-client' if interface == 'wg1' else ''
            lock = stack.enter_context(open('/run/lock/vpp-wireguard' + suffix + '-import.lock', 'a+'))
            fcntl.flock(lock, fcntl.LOCK_EX)
            lock.seek(0)
            lock.truncate()
            lock.write(str(time.time_ns()) + '\n')
            lock.flush()
        install(interfaces, args.source_address)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('WireGuard installation failed: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
