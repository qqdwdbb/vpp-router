#!/usr/bin/env python3
"""Remove the retired local VPP wg2/UK WireGuard path from an VROUTER host."""

import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


BACKUP_ROOT = Path('/root')
VPPCTL = '/usr/local/bin/vppctl'
VPP_SOCKET = '/run/vpp/cli.sock'

FILES = (
    Path('/etc/vpp/topology.vpp'),
    Path('/etc/vpp/dns-route-domains.json'),
    Path('/etc/vpp/nftset-route-sync.json'),
    Path('/etc/vpp/host.nft'),
    Path('/etc/nftables.conf'),
    Path('/etc/vpp/uk.vpp'),
    Path('/etc/vpp/uk.domains'),
    Path('/etc/wireguard/uk.conf'),
    Path('/etc/systemd/system/vpp-wireguard-uk-endpoint-refresh.service'),
    Path('/etc/systemd/system/vpp-wireguard-uk-endpoint-refresh.timer'),
    Path('/usr/local/sbin/vpp-wireguard-endpoint-refresh-loop.sh'),
    Path('/run/vpp/wg2-endpoint-refresh.json'),
    Path('/run/lock/vpp-wireguard-uk-import.lock'),
)


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if check and result.returncode:
        raise RuntimeError('command failed: ' + str(args[0]))
    return result


def backup(paths):
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    root = BACKUP_ROOT / ('vpp-remove-wg2-' + stamp)
    root.mkdir(mode=0o700)
    manifest = []
    for source in paths:
        if not source.exists():
            continue
        target = root / source.relative_to('/')
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if source.is_file():
            shutil.copy2(source, target)
        manifest.append(str(source))
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    os.chmod(root / 'manifest.json', 0o600)
    return root


def atomic_json(path, document):
    mode = path.stat().st_mode & 0o777
    fd, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(document, stream, indent=2)
            stream.write('\n')
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def remove_route_config(path, predicate):
    document = json.loads(path.read_text())
    routes = document['routes']
    removed = [route for route in routes if predicate(route)]
    if len(removed) != 1:
        raise RuntimeError('expected exactly one wg2 route in ' + str(path))
    document['routes'] = [route for route in routes if not predicate(route)]
    atomic_json(path, document)


def remove_mapping(path):
    document = json.loads(path.read_text())
    mappings = document['mappings']
    removed = [mapping for mapping in mappings
               if mapping.get('set') == 'uk' or mapping.get('interface') == 'wg2']
    if len(removed) != 1:
        raise RuntimeError('expected exactly one wg2 mapping in ' + str(path))
    document['mappings'] = [mapping for mapping in mappings
                            if not (mapping.get('set') == 'uk' or
                                    mapping.get('interface') == 'wg2')]
    atomic_json(path, document)


def remove_nft_uk_members(path):
    original = path.read_text()
    text = re.sub(r'(?ms)^[ \t]*set uk \{\n.*?^[ \t]*\}\n?', '', original)
    lines = text.splitlines(keepends=True)
    changed = text != original
    result = []
    for line in lines:
        if '"uk"' in line and ('oifname' in line or 'iifname' in line):
            line = line.replace('"uk", ', '').replace(', "uk"', '')
            changed = True
        result.append(line)
    if changed:
        path.write_text(''.join(result)
                        if result and result[-1].endswith('\n') else ''.join(result) + '\n')


def vpp(command):
    result = run(VPPCTL, '-s', VPP_SOCKET, command, check=False)
    output = result.stdout + result.stderr
    if result.returncode or re.search(
            r'unknown input|error|failed|invalid|not found|not exist', output, re.I):
        raise RuntimeError('VPP command failed: ' + command)


def remove_runtime_interface():
    status = run(VPPCTL, '-s', VPP_SOCKET, 'show interface', check=False)
    if status.returncode or not re.search(r'(?m)^wg2\s', status.stdout):
        return False
    for command in (
            'nat44 ei context wg2 loop103 del',
            'set interface nat44 ei out wg2 output-feature del',
            'ip route del 10.14.0.1/32 via 10.14.0.1 wg2',
            'ip route del 0.0.0.0/0 table 103 via ip4-lookup-in-table 0',
            'set interface state loop103 down',
            'delete loopback interface intfc loop103',
            'nat44 ei add address 10.14.0.2 tenant-vrf 103 del',
            'ip table del 103',
            'wireguard delete wg2'):
        vpp(command)
    return True


def main():
    if os.geteuid() != 0:
        raise SystemExit('run as root')
    backup_path = backup(FILES)
    gate_active = run('systemctl', 'is-active', '--quiet',
                      'vrouter-dns-route-gate.service', check=False).returncode == 0
    run('systemctl', 'disable', '--now',
        'vpp-wireguard-uk-endpoint-refresh.timer', check=False)
    run('systemctl', 'disable', '--now',
        'vpp-wireguard-uk-endpoint-refresh.service', check=False)
    if gate_active:
        run('systemctl', 'stop', 'vrouter-dns-route-gate.service')
    try:
        remove_route_config(
            Path('/etc/vpp/dns-route-domains.json'),
            lambda route: route.get('name') == 'uk' and route.get('interface') == 'wg2')
        remove_mapping(Path('/etc/vpp/nftset-route-sync.json'))
        for path in (Path('/etc/vpp/host.nft'), Path('/etc/nftables.conf')):
            if path.exists():
                remove_nft_uk_members(path)
        remove_runtime_interface()
        for path in FILES:
            if path.exists() and path.name not in ('topology.vpp',
                                                    'dns-route-domains.json',
                                                    'nftset-route-sync.json',
                                                    'host.nft', 'nftables.conf'):
                path.unlink()
        topology = Path('/etc/vpp/topology.vpp')
        text = topology.read_text()
        updated = re.sub(r'(?m)^# UK WireGuard egress\nexec /etc/vpp/uk\.vpp\n?', '', text)
        if updated == text:
            raise RuntimeError('UK WireGuard topology include not found')
        topology.write_text(updated)
        run('systemctl', 'daemon-reload')
    finally:
        if gate_active:
            run('systemctl', 'start', 'vrouter-dns-route-gate.service', check=False)
    print(str(backup_path))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('wg2 removal failed: ' + str(error))
        raise SystemExit(1)
