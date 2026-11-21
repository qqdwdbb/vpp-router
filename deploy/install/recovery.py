#!/usr/bin/env python3
"""Capture and restore the healthy installed VROUTER router, without trial bundles."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time

STATE = Path('/var/lib/vpp-vrouter')
STORE = STATE/'recovery'
RUNTIME = Path('/usr/local/lib/vpp-vrouter')
CONFIG = Path('/etc/vpp')
DPDK = Path('/usr/local/lib/aarch64-linux-gnu')
SYSTEMD = Path('/etc/systemd/system')
FALLBACK = RUNTIME/'scripts/vrouter/startup/vrouter-linux-fallback.py'
BASELINE = json.loads(Path(__file__).with_name('baseline.json').read_text())
LATCH = STATE/'linux-fallback/active'
REQUIRED = ('vrouter-vpp.service', 'vrouter-network-prep.service', 'vrouter-firewall.service',
            'vrouter-dnsmasq.service', 'vrouter-dns-route-gate.service', 'vrouter-host-services.service',
            'vrouter-fakeip.service', 'vrouter-pd-sync.service', 'vrouter-strongswan.service',
            'vrouter-coturn.service', 'vrouter-ike-addresses.service', 'vrouter-namespace.service')


def run(*args, timeout=120, check=True):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Configuration-bearing tool diagnostics are deliberately not printed.
        raise RuntimeError('Command failed: '+str(args[0]))
    return result.stdout.strip()


def write_json(path, value):
    temporary = path.with_name(path.name+'.new')
    temporary.write_text(json.dumps(value, indent=2)+'\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def health(units=REQUIRED, wan_timeout=30):
    for unit in units:
        if run('systemctl', 'is-active', unit) != 'active':
            raise RuntimeError('Inactive service: '+unit)
    deadline = time.monotonic()+wan_timeout
    while True:
        reply = run('/usr/local/bin/vppctl', 'ping 10.61.10.1 repeat 3 source nic0-dpdk.100')
        match = re.search(r'(\d+) received', reply)
        if match and int(match[1]) > 0:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('WAN gateway did not answer VPP probes')
        time.sleep(1)
    if not run('dig', '+short', '+time=3', '+tries=1', '@127.0.0.1', 'www.baidu.com'):
        raise RuntimeError('Local DNS did not answer')
    code = run('curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}',
               '--connect-timeout', '5', '--max-time', '15', 'https://www.baidu.com')
    if code != '200':
        raise RuntimeError('HTTPS readiness check failed')


def fixed_scopes():
    return [RUNTIME, CONFIG, Path('/usr/local/share/vpp-vrouter'), DPDK/'dpdk',
             STATE/'baseline', STATE/'host-routing.json',
             Path('/usr/local/bin/vppctl'), Path('/usr/local/sbin/vpp'),
             Path('/usr/local/bin/sing-box'), Path('/usr/local/bin/gost'),
             Path('/usr/local/bin/smartdns'), Path('/etc/smartdns'),
             Path('/etc/nftables.conf'), Path('/etc/nftables.d'), Path('/etc/dnsmasq.d'),
             Path('/etc/network/interfaces'), Path('/etc/network/interfaces.d'),
             Path('/etc/ipsec.secrets'), Path('/etc/ipsec.d'), Path('/etc/coturn'),
             Path('/lib/modules')/platform.release()/'updates/vpp/uio_pci_generic.ko',
             SYSTEMD/'gost-tunnel.service', SYSTEMD/'gost-tunnel.service.d']


def scopes():
    paths = fixed_scopes()
    paths += list(DPDK.glob('librte_*'))
    paths += list(SYSTEMD.glob('vrouter-*'))
    return sorted({p for p in paths if p.exists() or p.is_symlink()})


def permitted_root(root):
    path = Path(root)
    if not path.is_absolute() or '..' in path.parts or str(path) != root:
        return False
    return (path in fixed_scopes()
            or (path.parent == DPDK and path.name.startswith('librte_'))
            or (path.parent == SYSTEMD and path.name.startswith('vrouter-')))


def describe(path):
    stat = path.lstat()
    result = dict(mode=stat.st_mode & 0o7777, uid=stat.st_uid, gid=stat.st_gid)
    if path.is_symlink():
        return dict(result, kind='link', target=os.readlink(path))
    if path.is_dir():
        return dict(result, kind='directory')
    if not path.is_file():
        raise ValueError('Unexpected special file: '+str(path))
    return dict(result, kind='file', sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def inventory(tree):
    return {str(p.relative_to(tree)): describe(p) for p in sorted(tree.rglob('*'))}


def member(tree, name):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts or not relative.parts:
        raise ValueError('Invalid snapshot member')
    path = tree/relative
    for parent in path.parents:
        if parent == tree:
            break
        if parent.is_symlink():
            raise ValueError('Snapshot member traverses a symlink')
    return path


def verify(generation=None):
    generation = generation or (STORE/'current').resolve(strict=True)
    if generation.parent.resolve() != (STORE/'generations').resolve():
        raise ValueError('Recovery generation is outside the recovery store')
    manifest = json.loads((generation/'manifest.json').read_text())
    if manifest['kernel'] != platform.release() or manifest['architecture'] != platform.machine():
        raise ValueError('Recovery kernel or architecture differs')
    tree = generation/'tree'
    for name in manifest['files']:
        member(tree, name)
    if inventory(tree) != manifest['files']:
        raise ValueError('Recovery snapshot content differs from its manifest')
    for name, expected in BASELINE['files'].items():
        if manifest['files'].get(name, {}).get('sha256') != expected:
            raise ValueError('Recovery snapshot differs from accepted baseline: '+name)
    # A manifest cannot authorize an arbitrary system directory for replacement.
    for root in manifest['roots']:
        if not permitted_root(root):
            raise ValueError('Unexpected recovery root: '+root)
        if root.lstrip('/') not in manifest['files']:
            raise ValueError('Recovery root missing from manifest')
    return generation, manifest


def copy_owner(source, destination):
    stat = source.lstat()
    os.chown(destination, stat.st_uid, stat.st_gid, follow_symlinks=False)


def copy_snapshot(source, destination):
    if source.is_symlink():
        destination.symlink_to(os.readlink(source))
    elif source.is_dir():
        destination.mkdir()
        for child in source.iterdir():
            if child.name != '__pycache__' and child.suffix != '.pyc':
                copy_snapshot(child, destination/child.name)
        shutil.copystat(source, destination, follow_symlinks=False)
    else:
        shutil.copy2(source, destination)
    copy_owner(source, destination)


def runtime_baseline():
    rows = json.loads(run('ip', '-j', 'link', 'show', 'br0'))
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
    return dict(captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                purpose='installed-router-runtime', links={'br0': {'mac': rows[0]['address']}},
                routes4=[r for r in routes if r.get('dev') == 'nebula'])


def restore_enabled(states):
    for unit, state in states.items():
        if state in ('enabled', 'disabled'):
            run('systemctl', 'enable' if state == 'enabled' else 'disable', unit)


def snapshot():
    if LATCH.exists():
        raise RuntimeError('Cannot capture a Linux fallback deployment as the VPP baseline')
    health()
    # Only the bridge MAC and current Nebula routes are consumed by runtime.py.
    write_json(STATE/'baseline/linux-state.json', runtime_baseline())
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    (STORE/'generations').mkdir(mode=0o700, exist_ok=True)
    generation = Path(tempfile.mkdtemp(prefix='current-', dir=STORE/'generations'))
    tree = generation/'tree'
    tree.mkdir(mode=0o700)
    try:
        roots = scopes()
        for root in roots:
            destination = tree/str(root).lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            copy_snapshot(root, destination)
        enabled = {}
        for unit in REQUIRED+('vrouter-linux-fallback.service', 'gost-tunnel.service'):
            enabled[unit] = run('systemctl', 'is-enabled', unit, check=False)
        units = list(REQUIRED)
        if run('systemctl', 'is-active', 'gost-tunnel.service', check=False) == 'active':
            units.append('gost-tunnel.service')
        manifest = dict(schema=1, created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        kernel=platform.release(), architecture=platform.machine(),
                        roots=list(map(str, roots)), units=units, enabled=enabled,
                        version=run('/usr/local/bin/vppctl', 'show version'), files=inventory(tree))
        write_json(generation/'manifest.json', manifest)
        verify(generation)
        health(units)
        new_link = STORE/'current.new'
        new_link.unlink(missing_ok=True)
        new_link.symlink_to(generation.relative_to(STORE))
        new_link.replace(STORE/'current')
    except Exception:
        shutil.rmtree(generation)
        raise
    # Keep exactly the explicitly accepted healthy generation.
    for old in (STORE/'generations').iterdir():
        if old != generation and old.is_dir() and not old.is_symlink():
            shutil.rmtree(old)
    record = json.loads((STATE/'installation.json').read_text())
    for key in ('previous_bundle', 'recovery_bundle', 'rollback_unit', 'from_linux', 'source'):
        record.pop(key, None)
    record.update(phase='confirmed', recovery=str(STORE/'current'), recovery_schema=1)
    write_json(STATE/'installation.json', record)
    return dict(generation=generation.name, version=manifest['version'], files=len(manifest['files']))


def remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def restore_path(source, destination):
    """Reconcile only a managed root; keep atomic replacement for mapped files."""
    if source.is_dir() and not source.is_symlink():
        if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
            remove(destination)
        destination.mkdir(parents=True, exist_ok=True)
        names = {p.name for p in source.iterdir()}
        for extra in destination.iterdir():
            if extra.name not in names:
                remove(extra)
        for item in source.iterdir():
            restore_path(item, destination/item.name)
        shutil.copystat(source, destination, follow_symlinks=False)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name('.'+destination.name+'.recover-new')
        if temporary.exists() or temporary.is_symlink():
            remove(temporary)
        if source.is_symlink():
            temporary.symlink_to(os.readlink(source))
        else:
            shutil.copy2(source, temporary)
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        temporary.replace(destination)
    stat = source.lstat()
    os.chown(destination, stat.st_uid, stat.st_gid, follow_symlinks=False)


def restore():
    generation, manifest = verify()
    route = json.loads(run('ip', '-j', 'route', 'get', '10.61.60.2'))[0]
    if route.get('dev') != 'mgmt0' or route.get('prefsrc') != '10.61.60.1':
        raise RuntimeError('Independent management route unavailable')
    units = manifest['units']
    run('systemctl', 'stop', *units)
    try:
        # Remove only currently owned host routes before restoring their journal.
        routing_path = generation/'tree'/str(RUNTIME/'scripts/vrouter/host-services/host-routing.py').lstrip('/')
        routing = {}
        exec(compile(routing_path.read_text(), str(routing_path), 'exec'), routing)
        routing['remove'](lambda *a: run(*a), STATE/'host-routing.json')
        for root in manifest['roots']:
            restore_path(member(generation/'tree', root.lstrip('/')), Path(root))
        for path in SYSTEMD.glob('vrouter-*'):
            if str(path) not in manifest['roots']:
                remove(path)
        run('depmod', '-a', platform.release())
        run('systemctl', 'daemon-reload')
        run('systemctl', 'reset-failed', *units, check=False)
        restore_enabled(manifest['enabled'])
        if LATCH.exists():
            run('python3', FALLBACK, 'resume')
        run('systemctl', 'start', *units)
        health(units, wan_timeout=60)
    except Exception:
        run('python3', FALLBACK, 'fallback', check=False)
        raise
    result = dict(generation=generation.name, restored_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='healthy', version=run('/usr/local/bin/vppctl', 'show version'))
    write_json(STORE/'last-restore.json', result)
    record_path = STATE/'installation.json'
    record = json.loads(record_path.read_text()) if record_path.exists() else {}
    record.update(phase='confirmed', units=units, recovery=str(STORE/'current'), recovery_schema=1)
    record.pop('rollback_unit', None)
    write_json(record_path, record)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('snapshot', 'verify', 'restore', 'linux'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root on VROUTER')
    os.umask(0o077)
    STORE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STORE/'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'snapshot':
            result = snapshot()
        elif args.action == 'verify':
            generation, manifest = verify()
            result = dict(generation=generation.name, files=len(manifest['files']), status='verified')
        elif args.action == 'linux':
            run('python3', FALLBACK, 'fallback')
            result = dict(status='linux')
        else:
            result = restore()
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
