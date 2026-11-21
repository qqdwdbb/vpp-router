#!/usr/bin/env python3
"""Accept the tested read-batched, 64-call, eight-line VROUTER deployment."""
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import uuid

sys.path.insert(0, '/usr/local/lib/vpp-vrouter/install')
import recovery

BUILD = Path('/usr/local/src/vpp-vrouter/maintenance/rx-batch-experiment')
INPUTS = Path('/usr/local/src/vpp-vrouter/migration/dma-pmd')
PLUGIN_INPUT = INPUTS.parent/'plugins/dpdk_plugin.so'
PMD = Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')
PLUGIN = Path('/usr/local/lib/vpp-vrouter/plugins/dpdk_plugin.so')
TRIAL = Path('/var/lib/vpp-vrouter/rx-batch-trial')
CONFIG = Path('/etc/vpp/startup.conf')
EXPECTED_PMD = '8881ceabf6690006c3cdeb62510a19560b23d6d03778fdbc3683c0eab53a80e8'
EXPECTED_PLUGIN = '7b3210e628b23b5fdf28dd9ab91e9a501d36189191214115411dc08fcef9016d'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_copy(source, target):
    temporary = target.with_name(target.name+'.accept-new')
    recovery.copy_snapshot(source, temporary)
    temporary.replace(target)


def check_loaded():
    pid = recovery.run('pidof', 'vpp').split()[0]
    maps = Path('/proc/'+pid+'/maps').read_text().splitlines()
    for target, expected in [(PMD, EXPECTED_PMD), (PLUGIN, EXPECTED_PLUGIN)]:
        assert sha(target) == expected
        entries = [line for line in maps if str(target) in line]
        assert entries and all(int(line.split()[4]) == target.stat().st_ino for line in entries)
    return int(pid)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run on VROUTER as root')
    os.umask(0o077)
    manifest = json.loads((BUILD/'manifest.json').read_text())
    variant = manifest['variants']['rearm8']
    assert variant['pmd_sha'] == sha(Path(variant['pmd'])) == EXPECTED_PMD
    assert manifest['plugin64']['sha'] == sha(Path(manifest['plugin64']['path'])) == EXPECTED_PLUGIN
    assert sha(BUILD/'rearm8/source/r8169_rxtx.c') == variant['source_sha']
    assert sha(PMD) == manifest['baseline_pmd'] and sha(PLUGIN) == manifest['baseline_plugin']
    trial = json.loads((TRIAL/'state.json').read_text())
    assert trial['restored'] and trial['active'] == 'baseline'
    assert sha(CONFIG) == trial['config_sha']
    config_sha = sha(CONFIG)
    units = recovery.REQUIRED+('gost-tunnel.service',)
    recovery.health(units)
    with (recovery.STORE/'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        old, old_manifest = recovery.verify()
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        history = recovery.STATE/'history'/('rx-batches-'+stamp+'-'+uuid.uuid4().hex[:6])
        history.mkdir(mode=0o700, parents=True)
        recovery.copy_snapshot(old, history/'recovery-generation')
        assert recovery.inventory(history/'recovery-generation/tree') == old_manifest['files']
        recovery.copy_snapshot(INPUTS, history/'installation-input')
        recovery.copy_snapshot(PLUGIN_INPUT, history/'dpdk_plugin.input.so')
        recovery.copy_snapshot(recovery.STATE/'installation.json', history/'installation.json')
        recovery.copy_snapshot(recovery.STATE/'baseline/linux-state.json', history/'linux-state.json')
        names = [PMD.name, 'r8169_rxtx.o', 'r8169_rxtx.o.d']
        try:
            recovery.run('python3', '/run/vrouter_rx_batch_trial.py', 'apply', '--arm', 'rearm8', timeout=300)
            pid = check_loaded()
            for name in names:
                atomic_copy(BUILD/'rearm8'/name, INPUTS/name)
            atomic_copy(Path(manifest['plugin64']['path']), PLUGIN_INPUT)
            spec = importlib.util.spec_from_file_location('installed_installer',
                '/usr/local/lib/vpp-vrouter/install/install.py')
            installer = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(installer)
            assert sha(installer.rtl8125_pmd()) == EXPECTED_PMD
            # install.stage copies bundle/plugins directly; this is its accepted bundle input.
            assert PLUGIN_INPUT == installer.BASE/'plugins/dpdk_plugin.so'
            assert sha(PLUGIN_INPUT) == EXPECTED_PLUGIN
            recovery.health(units)
            result = recovery.snapshot()
            generation, current = recovery.verify()
            for target, expected in [(PMD, EXPECTED_PMD), (PLUGIN, EXPECTED_PLUGIN)]:
                relative = str(target).lstrip('/')
                assert current['files'][relative]['sha256'] == sha(generation/'tree'/relative) == expected
            assert sha(CONFIG) == config_sha == current['files']['etc/vpp/startup.conf']['sha256']
            assert check_loaded() == pid
            recovery.health(units)
        except Exception:
            for name in names+['accepted-baseline.json']:
                atomic_copy(history/'installation-input'/name, INPUTS/name)
            atomic_copy(history/'dpdk_plugin.input.so', PLUGIN_INPUT)
            recovery.run('python3', '/run/vrouter_rx_batch_trial.py', 'restore', timeout=300)
            # snapshot() may have published before a later validation failed.
            if not old.exists():
                recovery.copy_snapshot(history/'recovery-generation', old)
            link = recovery.STORE/'current.accept-rollback'
            link.symlink_to(old.relative_to(recovery.STORE));link.replace(recovery.STORE/'current')
            atomic_copy(history/'installation.json', recovery.STATE/'installation.json')
            atomic_copy(history/'linux-state.json', recovery.STATE/'baseline/linux-state.json')
            recovery.verify()
            raise
        recovery.run('systemctl', 'stop', 'vrouter-rx-batch-rollback.timer')
        record = dict(status='accepted', accepted_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            read_batch=True, pmd_call_limit=64, rearm_lines=8, rx_ring=1024, tx_ring=1024,
            pmd_sha256=EXPECTED_PMD, plugin_sha256=EXPECTED_PLUGIN, source_sha256=variant['source_sha'],
            maintenance=str(BUILD/'rearm8'), plugin_maintenance=str(BUILD/'call64'),
            recovery_generation=str(generation), previous_baseline_archive=str(history),
            startup_sha256=config_sha, vpp_pid=pid, loaded_inodes_match=True, services=len(units),
            health='passed', snapshot_files=result['files'], recovery_verified=True,
            installer_input_verified=True, restore_drill_performed=False)
        recovery.write_json(INPUTS/'accepted-baseline.json', record)
        recovery.write_json(recovery.STATE/'accepted-baseline-promotion.json', record)
        # Preserve experiment history, but distinguish this explicit acceptance from a pending trial.
        with (TRIAL/'lock').open('w') as trial_lock:
            fcntl.flock(trial_lock, fcntl.LOCK_EX)
            trial = json.loads((TRIAL/'state.json').read_text())
            trial['accepted'] = True
            trial['events'].append(dict(action='accept', recovery_generation=str(generation)))
            recovery.write_json(TRIAL/'state.json', trial)
        output = Path('/tmp/vrouter-rx-batches-accepted.json')
        recovery.write_json(output, record);output.chmod(0o644)
        print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
