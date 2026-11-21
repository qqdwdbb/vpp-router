#!/usr/bin/env python3
"""Migrate the deployed Fake-IP frontend from local SOCKS to native Trojan."""
import argparse
import copy
from datetime import datetime
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

from prepare import trojan_outbound


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=35)
    if result.returncode:
        # Never print configuration content or a tool's credential-bearing diagnostics.
        raise RuntimeError('Command failed: ' + args[0])
    return result.stdout


def disable_program(text, name):
    pattern = re.compile(r'(?ms)^\[program:' + re.escape(name) + r'\]\s*\n(.*?)(?=^\[|\Z)')
    match = pattern.search(text)
    if not match:
        raise ValueError('Missing supervisor program: ' + name)
    body = match[1]
    for field in ('autostart', 'autorestart'):
        line = re.compile(r'(?m)^\s*' + field + r'\s*=.*$')
        body = line.sub(field + '=false', body) if line.search(body) else body.rstrip() + '\n' + field + '=false\n'
    return text[:match.start(1)] + body + text[match.end(1):]


def native_config(current, trojan):
    outbounds = current.get('outbounds', [])
    if (len(outbounds) != 1 or outbounds[0].get('type') != 'socks'
            or outbounds[0].get('server') != '127.0.0.1'
            or outbounds[0].get('server_port') != 1080):
        raise ValueError('Expected the reviewed local Trojan SOCKS outbound')
    config = copy.deepcopy(current)
    outbound = trojan_outbound(trojan)
    config['outbounds'] = [outbound]
    config['route']['final'] = outbound['tag']
    ports = {i['listen_port'] for i in config['inbounds']}
    if 1080 in ports or 2080 in ports:
        raise ValueError('Legacy listener ports are already configured')
    if trojan['local_port'] != 1080:
        raise ValueError('Expected the existing SOCKS frontend on port 1080')
    config['inbounds'] += [
        {'type': 'socks', 'tag': 'lan-socks', 'listen': trojan['local_addr'], 'listen_port': 1080},
        {'type': 'tproxy', 'tag': 'real-tproxy', 'listen': '::', 'listen_port': 2080}]
    return config


def publish(path, data):
    temporary = path.with_name(path.name + '.native-new')
    with temporary.open('x') as out:
        temporary.chmod(path.stat().st_mode & 0o777)
        out.write(data)
    temporary.replace(path)


def probe(port):
    for _ in range(5):
        try:
            code = run('curl', '--noproxy', '', '--socks5-hostname', f'127.0.0.1:{port}',
                       '-sS', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '5',
                       'https://www.google.com')
            if code == '200':
                return
        except RuntimeError:
            pass
        time.sleep(.2)
    raise RuntimeError('Native Trojan HTTPS readiness check failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trojan-config', type=Path, default=Path('/etc/trojan/trojan.json'))
    args = parser.parse_args()
    path = Path('/etc/vpp/sing-box-fakeip.json')
    current = json.loads(path.read_text())
    trojan = json.loads(args.trojan_config.read_text())
    config = native_config(current, trojan)
    nft_path = Path('/etc/vpp/dns-route-gate.nft')
    nft = nft_path.read_text()
    unit_path = Path('/etc/systemd/system/vrouter-fakeip.service')
    supervisor = {name: Path('/etc/supervisor/conf.d', name + '.conf')
                  for name in ('trojan', 'ipt2socks')}
    disabled = {name: disable_program(file.read_text(), name) for name, file in supervisor.items()}
    # These ports exist only during the bounded native-outbound probe.
    listeners = run('ss', '-lnut')
    if any(':' + str(port) + ' ' in listeners for port in (1081, 2083, 2084, 5356)):
        raise ValueError('Candidate probe ports are in use')
    backup = Path('/root/vrouter-native-trojan-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700)
    shutil.copy2(path, backup / path.name)
    shutil.copy2(nft_path, backup / nft_path.name)
    shutil.copy2(unit_path, backup / unit_path.name)
    for name, file in supervisor.items():
        shutil.copy2(file, backup / (name + '.conf'))
    candidate = backup / 'candidate.json'
    candidate.write_text(json.dumps(config, indent=2) + '\n')
    candidate.chmod(0o600)
    run('/usr/local/bin/sing-box', 'check', '-c', str(candidate))
    nft_candidate = backup / 'candidate.nft'
    nft_candidate.write_text(nft)
    run('nft', '-c', '-f', str(nft_candidate))
    trial = copy.deepcopy(config)
    for inbound in trial['inbounds']:
        inbound['listen_port'] = {1080: 1081, 2080: 2083, 2082: 2084, 5354: 5356}[inbound['listen_port']]
        inbound['listen'] = '127.0.0.1'
    trial['experimental']['cache_file']['path'] = str(backup / 'probe-cache.db')
    trial_path = backup / 'probe.json'
    trial_path.write_text(json.dumps(trial, indent=2) + '\n')
    trial_path.chmod(0o600)
    try:
        run('systemd-run', '--unit=vrouter-native-probe', '--collect',
            '--property=RuntimeMaxSec=120', '--property=UMask=0077',
            '/usr/local/bin/sing-box', 'run', '-c', str(trial_path))
        probe(1081)
    finally:
        subprocess.run(['systemctl', 'stop', 'vrouter-native-probe.service'], capture_output=True)
    # The production cache path is deliberately unchanged.
    dropin = Path('/etc/systemd/system/vrouter-fakeip.service.d/native.conf')
    if dropin.exists():
        raise ValueError('Existing native drop-in requires review')
    try:
        run('supervisorctl', 'stop', 'ipt2socks', 'trojan')
        for name, file in supervisor.items():
            publish(file, disabled[name])
        run('supervisorctl', 'reread')
        run('supervisorctl', 'update', 'ipt2socks', 'trojan')
        publish(path, candidate.read_text())
        publish(nft_path, nft)
        publish(unit_path, Path(__file__).with_name('vrouter-fakeip.service').read_text())
        dropin.parent.mkdir(exist_ok=True)
        # This device already uses heproxy as its Happy Eyeballs TCP transport.
        if trojan['remote_addr'] == '127.0.0.1' and trojan['remote_port'] == 1443:
            run('systemctl', 'is-active', 'heproxy.service')
            dropin.write_text('[Unit]\nWants=heproxy.service\nAfter=heproxy.service\n')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'restart', 'vrouter-fakeip.service')
        run('nft', '-f', str(nft_path))
        probe(1080)
    except Exception:
        # Release migrated ports before restarting their original owners.
        subprocess.run(['systemctl', 'stop', 'vrouter-fakeip.service'], capture_output=True)
        publish(path, (backup / path.name).read_text())
        publish(nft_path, (backup / nft_path.name).read_text())
        publish(unit_path, (backup / unit_path.name).read_text())
        run('nft', '-f', str(nft_path))
        for name, file in supervisor.items():
            publish(file, (backup / (name + '.conf')).read_text())
        if dropin.exists():
            dropin.unlink()
        run('systemctl', 'daemon-reload')
        run('supervisorctl', 'reread')
        run('supervisorctl', 'update', 'ipt2socks', 'trojan')
        subprocess.run(['supervisorctl', 'start', 'trojan', 'ipt2socks'], capture_output=True)
        run('systemctl', 'start', 'vrouter-fakeip.service')
        raise RuntimeError('Native migration failed; original services restored; backup: ' + str(backup)) from None
    print(json.dumps({'backup': str(backup), 'native_trojan_https': 200,
                      'listeners': [1080, 2080, 2082, 5354], 'cache_preserved': True,
                      'disabled_supervisor_programs': list(supervisor)}))


if __name__ == '__main__':
    main()
