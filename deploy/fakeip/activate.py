#!/usr/bin/env python3
"""Install a checked Fake-IP plan on VROUTER; retain root-private rollback files."""
import argparse
from datetime import datetime
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

from native import disable_program, publish, probe

HERE = Path(__file__).resolve().parent


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--expected-gate-sha', required=True)
    parser.add_argument('--expected-sync-sha', required=True)
    parser.add_argument('--trojan-config', type=Path, default=Path('/etc/trojan/trojan.json'))
    parser.add_argument('--resume-backup', type=Path,
                        help='Resume a pre-publication install whose reviewed sources are still unchanged')
    args = parser.parse_args()
    sources = HERE.parents[1]
    spec = importlib.util.spec_from_file_location('fakeip_prepare', HERE / 'prepare.py')
    prepare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare)
    frontend = prepare.frontend(prepare.trojan_outbound(json.loads(args.trojan_config.read_text())),
                                prepare.wireguard_domains())
    gate = Path('/usr/local/lib/vpp-vrouter/scripts/dns-route-gate.py')
    sync = gate.with_name('nftset-route-sync.py')
    for path, expected in ((gate, args.expected_gate_sha), (sync, args.expected_sync_sha)):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Live source differs from reviewed baseline: ' + str(path))
    new_paths = [Path('/usr/local/bin/sing-box'), Path('/etc/vpp/sing-box-fakeip.json'),
                 Path('/etc/systemd/system/vrouter-fakeip.service'),
                 Path('/etc/systemd/system/vrouter-dns-route-gate.service.d/fakeip.conf')]
    if args.resume_backup:
        for path in (gate, sync):
            if path.read_bytes() != (args.resume_backup / path.name).read_bytes():
                raise ValueError('Cannot resume after DNS configuration was published')
        if json.loads(new_paths[1].read_text()) != frontend:
            raise ValueError('Existing frontend configuration differs from this plan')
    elif any(path.exists() for path in new_paths):
        raise ValueError('Fake-IP install targets already exist; inspect before updating')
    if not args.resume_backup and (':5354 ' in run('ss', '-lnut') or ':2082 ' in run('ss', '-lnut')):
        raise ValueError('Fake-IP ports already in use')
    # Existing routes, including static ranges, must not claim these pools.
    for family, pool in (('ip', prepare.POOL4), ('ip6', prepare.POOL6)):
        for prefix in re.findall(r'(?m)^([0-9a-fA-F:.]+/\d+)\b',
                                 run('vppctl', 'show', family, 'fib', 'table', '0')):
            net = ipaddress.ip_network(prefix)
            if net.prefixlen and net.overlaps(ipaddress.ip_network(pool)):
                raise ValueError('Existing VPP prefix overlaps Fake-IP: ' + prefix)
    domains_path = Path('/etc/vpp/dns-route-domains.json')
    routes_path = Path('/etc/vpp/nftset-route-sync.json')
    nft_path = Path('/etc/vpp/dns-route-gate.nft')
    fakeip_paths = [Path('/etc/vpp') / name for name in prepare.FAKEIP_FILES.values()]
    domains, routes, nft = prepare.configure(json.loads(domains_path.read_text()),
        json.loads(routes_path.read_text()), nft_path.read_text())
    backup = args.resume_backup or Path('/root/vrouter-fakeip-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    if not args.resume_backup:
        backup.mkdir(mode=0o700)
        for path in (gate, sync, domains_path, routes_path, nft_path):
            shutil.copy2(path, backup / path.name)
        for path in fakeip_paths:
            if path.exists():
                shutil.copy2(path, backup / path.name)
    else:
        for path in (domains_path, routes_path, nft_path):
            if path.read_bytes() != (backup / path.name).read_bytes():
                raise ValueError('Live configuration changed since interrupted installation')
    config = backup / 'sing-box.json'
    config.write_text(json.dumps(frontend, indent=2) + '\n')
    candidate = backup / 'candidate.nft'
    candidate.write_text(nft)
    run(str(args.binary), 'check', '-c', str(config))
    run('nft', '-c', '-f', str(candidate))
    # Install the frontend before publishing any Fake-IP DNS answers.
    run('install', '-m', '755', str(args.binary), str(new_paths[0]))
    run('install', '-m', '600', str(config), str(new_paths[1]))
    run('install', '-m', '644', str(HERE / 'vrouter-fakeip.service'), str(new_paths[2]))
    run('systemctl', 'daemon-reload')
    legacy = {name: Path('/etc/supervisor/conf.d', name + '.conf')
              for name in ('trojan', 'ipt2socks')}
    disabled = {name: disable_program(file.read_text(), name) for name, file in legacy.items()}
    for name, file in legacy.items():
        shutil.copy2(file, backup / (name + '.conf'))
    try:
        run('supervisorctl', 'stop', 'ipt2socks', 'trojan')
        for name, file in legacy.items():
            publish(file, disabled[name])
        run('supervisorctl', 'reread')
        run('supervisorctl', 'update', 'ipt2socks', 'trojan')
        run('systemctl', 'start', 'vrouter-fakeip.service')
        probe(1080)
    except Exception:
        subprocess.run(['systemctl', 'stop', 'vrouter-fakeip.service'], capture_output=True)
        for name, file in legacy.items():
            publish(file, (backup / (name + '.conf')).read_text())
        run('supervisorctl', 'reread')
        run('supervisorctl', 'update', 'ipt2socks', 'trojan')
        subprocess.run(['supervisorctl', 'start', 'trojan', 'ipt2socks'], capture_output=True)
        raise RuntimeError('Frontend start failed; original proxy processes restored') from None
    for kind, prefix in (('A', '198.18.'), ('AAAA', '2001:2:')):
        for _ in range(5):
            try:
                answer = run('dig', '@127.0.0.1', '-p', '5354', 'www.google.com', kind,
                             '+short', '+time=1', '+tries=1').strip()
                if answer.startswith(prefix):
                    break
            except subprocess.CalledProcessError:
                answer = 'not ready'
            time.sleep(.2)
        else:
            raise ValueError('Frontend DNS readiness failed: ' + answer)
    # Exact sources were checked above; preserve their deployed mode.
    shutil.copyfile(sources / 'dns-route-gate.py', gate)
    shutil.copyfile(sources / 'nftset-route-sync.py', sync)
    domains_path.write_text(json.dumps(domains, indent=2) + '\n')
    routes_path.write_text(json.dumps(routes, indent=2) + '\n')
    nft_path.write_text(nft)
    for source in (HERE / prepare.FAKEIP_FILES[4], HERE / prepare.FAKEIP_FILES[6]):
        target = Path('/etc/vpp') / source.name
        shutil.copyfile(source, target)
        target.chmod(0o644)
    new_paths[3].parent.mkdir(exist_ok=True)
    new_paths[3].write_text('[Unit]\nWants=vrouter-fakeip.service\nAfter=vrouter-fakeip.service\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', 'vrouter-fakeip.service')
    run('systemctl', 'restart', 'vrouter-dns-route-gate.service')
    run('systemctl', 'is-active', 'vrouter-dns-route-gate.service')
    print(json.dumps({'backup': str(backup), 'frontend': 'sing-box 1.14.3',
                      'dns_port': prepare.DNS_PORT, 'tproxy_port': prepare.TPROXY_PORT}))


if __name__ == '__main__':
    main()
