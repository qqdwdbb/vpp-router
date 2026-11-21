#!/usr/bin/env python3
"""Install runtime search paths and migrate the deployed VROUTER filesystem layout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

RUNTIME = Path('/usr/local/lib/vpp-vrouter')
DPDK = Path('/usr/local/lib/aarch64-linux-gnu')
STATE = Path('/var/lib/vpp-vrouter')
CONFIG = Path('/etc/vpp')
SOURCE = Path('/usr/local/src/vpp-vrouter')


def run(*args):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, check=True)
    return result.stdout.strip()


def text_digest(path):
    """Hash executable code independently of modified ELF dynamic metadata."""
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected a little-endian ELF64 file: '+str(path))
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset+i*size) for i in range(count)]
    names = sections[names_index]
    strings = data[names[4]:names[4]+names[5]]
    for section in sections:
        name = strings[section[0]:].split(b'\0', 1)[0]
        if name == b'.text':
            return hashlib.sha256(data[section[4]:section[4]+section[5]]).hexdigest()
    raise ValueError('ELF has no .text section: '+str(path))


def runtime_rpath(path):
    if path.is_relative_to(DPDK):
        return '$ORIGIN/../..' if path.parent.name.startswith('pmds-') else '$ORIGIN'
    relative = path.relative_to(RUNTIME)
    if relative.parts[0] == 'ipsec-plugins':
        # strongSwan exposes these plugins through a private /usr/lib bind mount.
        return str(RUNTIME/'lib/aarch64-linux-gnu')+':/usr/lib/ipsec:'+str(DPDK)
    if relative.parts[0] in ('bin', 'plugins'):
        return '$ORIGIN/../lib/aarch64-linux-gnu:'+str(DPDK)
    if relative.parent.name == 'vpp_crypto_engines':
        return '$ORIGIN/..:'+str(DPDK)
    return '$ORIGIN:'+str(DPDK)


def repair_elf(path):
    desired = runtime_rpath(path)
    if run('patchelf', '--print-rpath', path) == desired:
        return False
    before = text_digest(path)
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    os.close(fd)
    temporary = Path(temporary)
    try:
        shutil.copy2(path, temporary)
        run('patchelf', '--set-rpath', desired, temporary)
        if text_digest(temporary) != before:
            raise ValueError('ELF code changed during relocation: '+str(path))
        # Do not rewrite an inode currently mapped by a running daemon.
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def normalize_elf():
    changed = []
    for root in (RUNTIME, DPDK):
        for path in sorted(root.rglob('*')):
            if path.is_symlink() or not path.is_file() or '.bak' in path.name:
                continue
            if root == DPDK and not path.name.startswith('librte_'):
                continue
            with path.open('rb') as stream:
                if stream.read(4) != b'\x7fELF':
                    continue
            if repair_elf(path):
                changed.append(str(path))
    return changed


def write_config(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o644)


def configure_core():
    if not Path('/usr/lib/systemd/systemd-coredump').exists():
        raise RuntimeError('Install systemd-coredump before configuring core handling')
    write_config(Path('/etc/systemd/coredump.conf.d/60-local-limits.conf'),
                 '[Coredump]\nStorage=external\nCompress=yes\nProcessSizeMax=2G\n'
                 'ExternalSizeMax=2G\nMaxUse=512M\nKeepFree=1G\n')
    write_config(Path('/etc/tmpfiles.d/vpp-vrouter.conf'),
                 'd /var/cache/vpp-vrouter 0700 root root -\n'
                 'd /var/cache/vpp-vrouter/python 0700 root root -\n'
                 'd /var/lib/systemd/coredump/legacy-vpp 0700 root root 7d\n')
    run('systemd-tmpfiles', '--create', '/etc/tmpfiles.d/vpp-vrouter.conf')
    old = Path('/etc/sysctl.d/99-vpp-core.conf')
    if old.exists():
        expected = 'kernel.core_pattern = /var/lib/vpp-vrouter/core/core.%e.%p.%t'
        if expected not in old.read_text():
            raise ValueError('Unexpected administrator core policy')
        old.unlink()
    run('sysctl', '-p', '/usr/lib/sysctl.d/50-coredump.conf')


def move_tree(source, destination):
    if not source.exists():
        return
    if destination.exists():
        raise ValueError('Migration destination already exists: '+str(destination))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))


def migrate():
    # Select the library actually used by the healthy running deployment.
    pid = run('systemctl', 'show', 'vrouter-vpp', '-p', 'MainPID', '--value')
    maps = Path('/proc', pid, 'maps').read_text()
    sources = set(re.findall(r'(/[^\s]+/libvnet\.so\.26\.06\.0)', maps))
    if len(sources) != 1:
        raise ValueError('Cannot identify the active libvnet')
    source = Path(sources.pop())
    target = RUNTIME/'lib/aarch64-linux-gnu/libvnet.so.26.06.0'
    if source != target:
        temporary = target.with_name(target.name+'.layout-new')
        shutil.copy2(source, temporary)
        if temporary.read_bytes() != source.read_bytes():
            raise ValueError('Active libvnet copy differs')
        temporary.replace(target)
    # Archive obsolete plugin copies outside the loader directory.
    for directory in (RUNTIME/'plugins', RUNTIME/'ipsec-plugins'):
        for path in directory.glob('*.bak*'):
            move_tree(path, STATE/'history'/directory.name/path.name)
    changed = normalize_elf()
    env = CONFIG/'runtime.env'
    values = env.read_text().splitlines()
    values = [line for line in values if not line.startswith(('LD_LIBRARY_PATH=', 'PYTHONPYCACHEPREFIX='))]
    values += ['LD_LIBRARY_PATH='+str(DPDK)+':'+str(RUNTIME/'lib/aarch64-linux-gnu'),
               'PYTHONPYCACHEPREFIX=/var/cache/vpp-vrouter/python']
    env.write_text('\n'.join(values)+'\n')
    configure_core()
    move_tree(STATE/'build', SOURCE/'maintenance')
    move_tree(STATE/'core', Path('/var/lib/systemd/coredump/legacy-vpp/router'))
    cache = CONFIG/'__pycache__'
    if cache.exists():
        for path in cache.iterdir():
            if path.is_file() and not path.is_symlink() and path.suffix == '.pyc':
                path.unlink()
        cache.rmdir()
    # Preserve build inputs as sources, outside the production runtime layout.
    move_tree(Path('/opt/vpp-nic1-test'), SOURCE/'nic1-test')
    move_tree(Path('/opt/vpp-vrouter-migration'), SOURCE/'migration')
    installation = STATE/'installation.json'
    if installation.exists():
        record = json.loads(installation.read_text())
        previous = record.get('previous_bundle', '')
        if previous.startswith('/opt/vpp-vrouter-migration/'):
            record['previous_bundle'] = str(SOURCE/'migration')+previous[len('/opt/vpp-vrouter-migration'):]
            installation.write_text(json.dumps(record, indent=2)+'\n')
    return dict(active_libvnet_source=str(source), normalized_elf=changed,
                libvnet_text_sha256=text_digest(target))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('elf', 'core', 'migrate'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run on VROUTER as root')
    result = migrate() if args.action == 'migrate' else normalize_elf() if args.action == 'elf' else configure_core()
    print(json.dumps(result, indent=2))
