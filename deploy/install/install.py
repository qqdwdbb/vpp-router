#!/usr/bin/env python3
"""Install an already validated VROUTER deployment in the local FHS hierarchy.

Stages files without restarting services. Activation is a separate, timed operation.
Private configurations and rollback material never leave the target device.
"""
import argparse
import json
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time

RUNTIME = Path('/usr/local/lib/vpp-vrouter')
CONFIG = Path('/etc/vpp')
STATE = Path('/var/lib/vpp-vrouter')
SHARE = Path('/usr/local/share/vpp-vrouter')
ARTIFACTS = Path('/usr/local/src/vpp-vrouter')
BASE = ARTIFACTS/'migration'
VPP = ARTIFACTS/'nic1-test/vpp'
DPDK = ARTIFACTS/'nic1-test/dpdk'
UIO_MODULE = ARTIFACTS/'nic1-test/src/uio/uio_pci_generic.ko'
DPDK_LIB = Path('/usr/local/lib/aarch64-linux-gnu')
BASELINE = json.loads(Path(__file__).with_name('baseline.json').read_text())
SCRIPTS = (
    'vrouter/tproxy-path.py',
    'vrouter/dns-intercept/intercept.py',
    'dns-route-gate.py', 'nftset-route-sync.py', 'vpp-egress-nat.py',
    'ipsec/ipsec-prefix-sync.py',
    'vrouter/cutover/runtime.py', 'vrouter/cutover/transition.py',
    'vrouter/cutover/linux-recovery-audit.py', 'vrouter/restore-nic0.sh',
    'vrouter/startup/vrouter-vpp-ready.py', 'vrouter/startup/vrouter-strongswan-ready.py',
    'vrouter/startup/vrouter-network-prep.py', 'vrouter/firewall/vrouter-firewall.py',
    'vrouter/startup/vrouter-vpp-device-prep.py', 'vrouter/firewall/persistent-rules.py',
    'vrouter/firewall/vrouter-firewall.nft', 'vrouter/ipv6/pd-sync.py',
    'vrouter/host-services/host-path.py', 'vrouter/host-services/host-routing.py',
    'vrouter/host-services/service-ports.py',
)


def run(*args, **kwargs):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError('Command failed: '+str(args[0]))
    return result.stdout


def write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def rewrite(text, replacements):
    # Longest match first: never replace a bundle root before its config path.
    for old, new in sorted(replacements.items(), key=lambda item: -len(item[0])):
        text = text.replace(str(old), str(new))
    return text


def runtime_environment():
    return dict(PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                LD_LIBRARY_PATH=str(DPDK_LIB)+':'+str(RUNTIME/'lib/aarch64-linux-gnu'),
                DPDK_PLUGIN_PATH=str(DPDK_LIB/'dpdk/pmds-26.1'),
                R8169_DMA_NONCOHERENT='1',
                PYTHONPYCACHEPREFIX='/var/cache/vpp-vrouter/python',
                PYTHONPATH=str(RUNTIME/'python'), VPP_API_DIR=str(SHARE/'api'),
                VROUTER_CONFIG_DIRECTORY=str(CONFIG), VROUTER_RUNTIME_DIRECTORY=str(RUNTIME),
                VROUTER_VPPCTL='/usr/local/bin/vppctl')


def wrapper(binary):
    libraries = shlex.quote(runtime_environment()['LD_LIBRARY_PATH'])
    return ('#!/bin/sh\n'
            f'export LD_LIBRARY_PATH={libraries}\n'
            f'exec {shlex.quote(str(RUNTIME/"bin"/binary))} "$@"\n')


def service_unit(text, replacements, name):
    text = rewrite(text, replacements)
    common_keys = tuple('Environment='+key+'=' for key in runtime_environment())
    text = '\n'.join(line for line in text.splitlines() if not line.startswith(common_keys))+'\n'
    text = text.replace('[Service]\n', '[Service]\nEnvironmentFile=/etc/vpp/runtime.env\n', 1)
    return text


def validate_links(root):
    root = root.resolve()
    broken = [str(p.relative_to(root)) for p in root.rglob('*')
              if p.is_symlink() and (not p.exists() or not p.resolve().is_relative_to(root))]
    if broken:
        raise ValueError('Broken or external runtime symlinks: '+', '.join(broken))


def install_uio_module():
    release = run('uname','-r').strip()
    source = UIO_MODULE
    if not run('modinfo','-F','vermagic',source).startswith(release+' '):
        raise ValueError('UIO module does not match the running kernel')
    target = Path('/lib/modules')/release/'updates/vpp/uio_pci_generic.ko'
    if target.exists() and hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
        raise ValueError('Refusing to replace a different installed UIO module')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source,target)
    target.chmod(0o644)
    run('depmod','-a',release)


def rtl8125_pmd():
    # The ordinary DPDK build lacks the cache maintenance required on VROUTER.
    # Relocation must preserve the PMD used by the validated deployment.
    source = BASE/'dma-pmd/librte_net_r8169.so.26.1'
    if b'R8169_DMA_NONCOHERENT\0' not in source.read_bytes():
        raise ValueError('RTL8125 PMD lacks non-coherent DMA support')
    return source


def validate_baseline(bundle):
    """Reject stale bundle plugins or a different PMD before staging any files."""
    inputs = {
        'usr/local/lib/vpp-vrouter/plugins/acl_plugin.so': bundle/'plugins/acl_plugin.so',
        'usr/local/lib/vpp-vrouter/plugins/dpdk_plugin.so': bundle/'plugins/dpdk_plugin.so',
        'usr/local/lib/vpp-vrouter/plugins/nat44_ei_plugin.so': bundle/'plugins/nat44_ei_plugin.so',
        'usr/local/lib/vpp-vrouter/plugins/nat_ei_context_plugin.so': bundle/'plugins/nat_ei_context_plugin.so',
        'usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1': rtl8125_pmd(),
        'usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu/libvnet.so.26.06.0': BASE/'ipsec-ip6-udp/lib/libvnet.so.26.06.0',
    }
    for name, path in inputs.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != BASELINE['files'][name]:
            raise ValueError('Installation input differs from accepted baseline: '+str(path))


def stage(source, bundle):
    if os.geteuid() != 0:
        raise ValueError('Run on VROUTER as root')
    if not shutil.which('patchelf') or not Path('/usr/lib/systemd/systemd-coredump').exists():
        raise ValueError('Install patchelf and systemd-coredump first')
    if json.loads((bundle/'state.json').read_text())['phase'] != 'confirmed':
        raise ValueError('Install only the currently confirmed deployment')
    validate_baseline(bundle)
    for path in (RUNTIME, CONFIG, STATE, SHARE, Path('/usr/local/bin/vppctl'), Path('/usr/local/sbin/vpp')):
        if path.exists() or path.is_symlink():
            raise ValueError('Destination already exists: '+str(path))
    units = sorted((bundle/'units').glob('*.service'))
    for unit in units:
        if (Path('/etc/systemd/system')/unit.name).exists():
            raise ValueError('Persistent unit already exists: '+unit.name)
    os.umask(0o077)
    dma_pmd = rtl8125_pmd()
    install_uio_module()
    STATE.mkdir(parents=True, mode=0o700)
    backup = STATE/'backups/pre-fhs'
    backup.mkdir(parents=True)
    shutil.copytree(bundle, backup/'bundle', symlinks=True)
    recovery_state = json.loads((backup/'bundle/state.json').read_text())
    recovery_state['source'] = str(RUNTIME)
    write(backup/'bundle/state.json',json.dumps(recovery_state,indent=2)+'\n')
    shutil.copytree('/run/systemd/system', backup/'systemd',
                    ignore=lambda directory, names: [n for n in names if not n.startswith('vrouter-')])
    RUNTIME.mkdir(parents=True, mode=0o755)
    (RUNTIME/'bin').mkdir(mode=0o755)
    for name in ('vpp', 'vppctl'):
        shutil.copy2(VPP/'bin'/name, RUNTIME/'bin'/name)
    lib = RUNTIME/'lib/aarch64-linux-gnu'
    shutil.copytree(VPP/'lib/aarch64-linux-gnu', lib, symlinks=True,
                    ignore=lambda directory, names: [n for n in names if n in
                        ('vpp_plugins','vat2_plugins','vpp_api_test_plugins')])
    DPDK_LIB.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(DPDK/'lib/aarch64-linux-gnu', DPDK_LIB, symlinks=True)
    shutil.copy2(dma_pmd, DPDK_LIB/'dpdk/pmds-26.1'/dma_pmd.name)
    # Private patched vnet must win over stock libvnet.
    for item in (BASE/'ipsec-ip6-udp/lib').iterdir():
        target = lib/item.name
        if target.exists() or target.is_symlink(): target.unlink()
        if item.is_symlink(): target.symlink_to(os.readlink(item))
        else: shutil.copy2(item, target)
    shutil.copytree(bundle/'plugins', RUNTIME/'plugins', symlinks=True)
    shutil.copytree(bundle/'lib/aarch64-linux-gnu/vpp_crypto_engines', lib/'vpp_crypto_engines', dirs_exist_ok=True)
    shutil.copytree(bundle/'ipsec-plugins', RUNTIME/'ipsec-plugins', symlinks=True)
    shutil.copytree(BASE/'runtime/python', RUNTIME/'python', symlinks=True)
    shutil.copytree(VPP/'share/vpp/api', SHARE/'api')
    previous_source = Path(json.loads((bundle/'state.json').read_text())['source'])
    replacements = {
        str(previous_source/'scripts'): str(RUNTIME/'scripts'),
        str(bundle/'config'): str(CONFIG), str(bundle/'plugins'): str(RUNTIME/'plugins'),
        str(bundle/'ipsec-plugins'): str(RUNTIME/'ipsec-plugins'),
        str(source/'scripts'): str(RUNTIME/'scripts'),
        str(BASE/'source/scripts'): str(RUNTIME/'scripts'),
        str(VPP/'bin/vppctl'): '/usr/local/bin/vppctl',
        str(VPP/'share/vpp/api'): str(SHARE/'api'),
        str(BASE/'runtime/python'): str(RUNTIME/'python'),
        str(BASE/'ipsec-ip6-udp/lib'): str(lib),
        str(DPDK/'lib/aarch64-linux-gnu'): str(DPDK_LIB),
        str(VPP/'lib/aarch64-linux-gnu'): str(lib),
        '/opt/vpp-nic1-test/vpp/bin/vpp': str(RUNTIME/'bin/vpp'),
        '/opt/vpp-nic1-test/vpp/bin/vppctl': '/usr/local/bin/vppctl',
        '/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu': str(lib),
        '/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu': str(DPDK_LIB),
        '/opt/vpp-vrouter-migration/ipsec-ip6-udp/lib': str(lib),
        str(bundle): str(STATE),
    }
    for name in SCRIPTS:
        text = rewrite((source/'scripts'/name).read_text(), replacements)
        write(RUNTIME/'scripts'/name, text, 0o644)
    for item in Path(__file__).parent.glob('*.py'):
        write(RUNTIME/'install'/item.name, item.read_text(), 0o644)
    write(RUNTIME/'install/baseline.json', json.dumps(BASELINE, indent=2)+'\n', 0o644)
    CONFIG.mkdir(mode=0o750)
    for item in (bundle/'config').iterdir():
        if item.is_file(): write(CONFIG/item.name, rewrite(item.read_text(), replacements))
    shutil.copy2(bundle/'profile.json', CONFIG/'profile.json')
    shutil.copytree(bundle/'baseline', STATE/'baseline')
    pd = json.loads((CONFIG/'vrouter-pd-sync.json').read_text())
    # The generated IPsec configuration is an administrator-managed runtime
    # configuration under /etc; PD updates its dynamic address pool in place.
    pd['ipsec_config'] = str(CONFIG/'ipsec.conf')
    write(CONFIG/'vrouter-pd-sync.json', json.dumps(pd, indent=2)+'\n')
    env = runtime_environment()
    write(CONFIG/'runtime.env', ''.join(k+'='+v+'\n' for k,v in env.items()))
    unitdir = STATE/'units';unitdir.mkdir()
    for item in units:
        text = service_unit(item.read_text(), replacements, item.name)
        write(unitdir/item.name, text, 0o644)
    for binary, path in (('vppctl',Path('/usr/local/bin/vppctl')),('vpp',Path('/usr/local/sbin/vpp'))):
        write(path, wrapper(binary), 0o755)
    # All runtime software must be readable/executable; no secrets live here.
    for directory, dirs, files in os.walk(RUNTIME):
        Path(directory).chmod(0o755)
        for name in files:
            path = Path(directory)/name
            if not path.is_symlink(): path.chmod(0o755 if '.so' in name or path.parent == RUNTIME/'bin' else 0o644)
    validate_links(RUNTIME)
    validate_links(DPDK_LIB)
    run('python3', Path(__file__).with_name('layout.py'), 'elf')
    for name, expected in BASELINE['files'].items():
        if hashlib.sha256(Path('/'+name).read_bytes()).hexdigest() != expected:
            raise ValueError('Installed binary differs from accepted baseline: '+name)
    run('python3', Path(__file__).with_name('layout.py'), 'core')
    for directory, dirs, files in os.walk(SHARE):
        Path(directory).chmod(0o755)
        for name in files: (Path(directory)/name).chmod(0o644)
    manifest = dict(source=str(source), previous_bundle=str(bundle), recovery_bundle=str(backup/'bundle'), units=[p.name for p in units],
                    runtime=str(RUNTIME), config=str(CONFIG), state=str(STATE), staged_at=time.time())
    write(STATE/'installation.json', json.dumps(manifest,indent=2)+'\n')
    run('systemd-analyze','verify',*[str(p) for p in unitdir.glob('*.service')],env={**os.environ,**env})
    print('Staged FHS installation; services have not been restarted')


def main():
    global BASE, VPP, DPDK, UIO_MODULE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--artifacts',type=Path,default=ARTIFACTS,
                        help='Build artifacts containing migration/ and nic1-test/')
    args = parser.parse_args()
    artifacts = args.artifacts.resolve()
    BASE, VPP, DPDK = artifacts/'migration', artifacts/'nic1-test/vpp', artifacts/'nic1-test/dpdk'
    UIO_MODULE = artifacts/'nic1-test/src/uio/uio_pci_generic.ko'
    stage(args.source.resolve(),args.bundle.resolve())


if __name__ == '__main__':
    main()
