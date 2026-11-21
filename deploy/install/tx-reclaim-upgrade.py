#!/usr/bin/env python3
"""Install the tested TX reclaim PMD from an independent systemd job.

Restores the previous library on startup/readiness failure. Retains the running
binary's original inode until VPP stops; no live library is truncated.
"""
import hashlib
import argparse
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import time

CANDIDATE = Path('/usr/local/src/vpp-vrouter/maintenance/tx-reclaim/librte_net_r8169.so.26.1')
TARGET = Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')
RESULT = Path('/var/lib/vpp-vrouter/tx-reclaim-upgrade.json')
CONFIG = Path('/etc/vpp/startup.conf')


def replace(data, target=TARGET, mode=0o755):
    temporary = target.with_name(target.name+'.new')
    temporary.write_bytes(data)
    temporary.chmod(mode)
    temporary.replace(target)


def ready(recovery):
    # VPP's Wants= services finish asynchronously after its own start job.
    deadline = time.monotonic()+90
    while True:
        statuses = subprocess.run(['systemctl', 'is-active', *recovery.REQUIRED],
                                  capture_output=True, text=True).stdout.splitlines()
        if len(statuses) == len(recovery.REQUIRED) and all(s == 'active' for s in statuses):
            recovery.health(wan_timeout=45)
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('Dependent services did not become ready: '+repr(statuses))
        time.sleep(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, default=CANDIDATE)
    parser.add_argument('--result', type=Path, default=RESULT)
    ring_options = parser.add_mutually_exclusive_group()
    ring_options.add_argument('--tx-descriptors', type=int, choices=[4096])
    ring_options.add_argument('--restore-ring-defaults', action='store_true')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('recovery',
        '/usr/local/lib/vpp-vrouter/install/recovery.py')
    recovery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recovery)
    recovery.verify()
    recovery.health()
    original = TARGET.read_bytes()
    candidate = args.candidate.read_bytes()
    original_config = CONFIG.read_bytes()
    config_mode = CONFIG.stat().st_mode & 0o7777
    new_config = original_config
    if args.tx_descriptors:
        text = original_config.decode()
        old = 'name nic0-dpdk num-rx-queues 1 num-tx-queues 2 rss'
        assert text.count(old) == 1
        assert text.count('buffers-per-numa 8192') == 1
        text = text.replace(old, 'name nic0-dpdk num-rx-queues 1 num-tx-queues 2 num-tx-desc 4096 rss')
        text = text.replace('buffers-per-numa 8192', 'buffers-per-numa 32768')
        new_config = text.encode()
    elif args.restore_ring_defaults:
        text = original_config.decode()
        assert text.count(' num-tx-desc 4096') == 1
        assert text.count('buffers-per-numa 32768') == 1
        text = text.replace(' num-tx-desc 4096', '')
        text = text.replace('buffers-per-numa 32768', 'buffers-per-numa 8192')
        new_config = text.encode()
    assert original != candidate or new_config != original_config
    ring = re.search(r'name nic0-dpdk[^\n]*num-tx-desc (\d+)', new_config.decode())
    result = {'before': hashlib.sha256(original).hexdigest(),
              'after': hashlib.sha256(candidate).hexdigest(),
              'tx_descriptors': int(ring.group(1)) if ring else 1024,
              'config_before': hashlib.sha256(original_config).hexdigest(),
              'config_after': hashlib.sha256(new_config).hexdigest()}
    replace(candidate)
    replace(new_config, CONFIG, config_mode)
    try:
        subprocess.run(['systemctl', 'restart', 'vrouter-vpp.service'], check=True, timeout=150)
        ready(recovery)
    except Exception:
        replace(original)
        replace(original_config, CONFIG, config_mode)
        subprocess.run(['systemctl', 'restart', 'vrouter-vpp.service'], check=True, timeout=150)
        result['status'] = 'rolled-back'
        args.result.write_text(json.dumps(result, indent=2)+'\n')
        ready(recovery)
        raise
    result['status'] = 'active'
    args.result.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
