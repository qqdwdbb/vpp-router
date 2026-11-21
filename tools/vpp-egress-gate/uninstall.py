#!/usr/bin/env python3
"""Undo install.py and what Gate did since, without restarting VPP.

The configuration and its list files stay, as they are the user's. Running it again is
safe, and a run that stopped partway finishes the rest.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
from install import (BINARY, DEVICE_CLI, DOMAIN_DIR, EXEC_LINE, GATE_UNIT, GENERATED_CONFIG, LINKS_UNIT, MARKER, install_files,
                     load_document, parse_startup, run, service_active, vpp_service_of, vpp_startup_file)

STATE_DIR = DEVICE_CLI.parent
DEVICE_JOURNAL = STATE_DIR / 'devices.json'
HOST_SETTINGS = STATE_DIR / 'host-settings.json'
SYSCTL_ROOT = Path('/proc/sys')
LOCK = Path('/run/lock/vpp-egress-gate.lock')
RUNTIME_DIR = Path('/run/vpp-egress-gate')
USER_CONFIG = Path('/etc/vpp/egress-gate.json')
DEFAULT_VPP_SOCKET = '/run/vpp/cli.sock'
# Only Gate uses these tables. The forward guard goes after the devices it guards.
NFT_TABLES = ('egress_gate', 'egress_gate_linux', 'gate_fixed')
# Device sync's TPROXY device, which has no table of its own in the journal.
PROXY_HOST = 'gate-tproxy'
PROXY_PRIORITY = 11002
PROXY_TABLE = 1002
FAMILIES = ('-4', '-6')


def succeeds(*args):
    return subprocess.run(args, capture_output=True).returncode == 0


def ip_json(*args):
    return json.loads(run('ip', '-j', *args) or '[]')


def load_runtime():
    """What Gate was told: the VPP socket and where its state lives."""
    if not GENERATED_CONFIG.is_file():
        return {}
    document = load_document(GENERATED_CONFIG)
    if 'route_config' in document and Path(document['route_config']).is_file():
        document = {**document, **load_document(Path(document['route_config']))}
    return document


def load_devices():
    if not DEVICE_JOURNAL.is_file():
        return []
    return list(load_document(DEVICE_JOURNAL).get('devices', {}).values())


def find_cli_file(args, runtime):
    """The file holding the exec line, which must go before the file it names does."""
    if args.vpp_cli_file:
        return args.vpp_cli_file
    service = vpp_service_of(GENERATED_CONFIG) if GENERATED_CONFIG.is_file() else 'vpp.service'
    startup_file = vpp_startup_file(service)
    found = parse_startup(startup_file.read_text()).get('cli_file') if startup_file and startup_file.is_file() else None
    if found:
        return Path(found)
    if DEVICE_CLI.exists():
        raise ValueError(f'cannot find the startup CLI file of {service}, which executes {DEVICE_CLI}; use --vpp-cli-file')
    return None


def backup_of(cli_file):
    return cli_file.with_name(cli_file.name + '.gate-backup')


def without_exec_line(text):
    return ''.join(line for line in text.splitlines(keepends=True) if line.strip() != EXEC_LINE.strip())


def check_cli_file(cli_file):
    """Installing with --vpp-cli-file leaves the line elsewhere, and VPP would go on reading it."""
    if cli_file is None or not DEVICE_CLI.exists():
        return
    if not cli_file.is_file():
        raise ValueError(f'VPP startup CLI file does not exist: {cli_file}; use --vpp-cli-file')
    if EXEC_LINE.strip() not in cli_file.read_text().splitlines() and not backup_of(cli_file).exists():
        raise ValueError(f'{cli_file} does not execute {DEVICE_CLI}; name the file that does with --vpp-cli-file')


def remove_exec_line(cli_file):
    if cli_file is None or not cli_file.is_file():
        return
    text = cli_file.read_text()
    kept = without_exec_line(text)
    if kept == text:
        return
    temporary = cli_file.with_name(cli_file.name + '.gate-new')
    temporary.write_text(kept)
    shutil.copymode(cli_file, temporary)
    temporary.replace(cli_file)


def remove_backup(cli_file, notes):
    """The backup goes only when it says nothing the file does not."""
    if cli_file is None or not backup_of(cli_file).exists():
        return
    if backup_of(cli_file).read_text().rstrip('\n') == cli_file.read_text().rstrip('\n'):
        backup_of(cli_file).unlink()
    else:
        notes.append(f'{backup_of(cli_file)} kept: {cli_file} has changed since it was made')


def stop_units():
    for unit in (GATE_UNIT, LINKS_UNIT):
        if (Path('/etc/systemd/system') / unit).exists():
            run('systemctl', 'disable', '--now', unit)


def vpp_running(socket):
    return shutil.which('vppctl') is not None and Path(socket).exists() and succeeds('vppctl', '-s', socket, 'show', 'version')


def device_tables(device):
    """Rule priorities and routing tables a journal entry owns."""
    if device['host'] == PROXY_HOST:
        return {PROXY_PRIORITY}, {PROXY_TABLE}
    pairs = ((device.get('priority'), device.get('table')), (device.get('return_priority'), device.get('return_table')))
    return {p for p, _ in pairs if p}, {t for _, t in pairs if t}


def number(value):
    return int(str(value), 0)


def remove_rules(priorities, tables):
    for family in FAMILIES:
        for rule in ip_json('-N', family, 'rule', 'show'):
            if rule.get('priority') not in priorities or number(rule.get('table', 0)) not in tables:
                continue
            command = [family, 'rule', 'del', 'priority', str(rule['priority'])]
            if 'iif' in rule:
                command += ['iif', rule['iif']]
            if 'fwmark' in rule:
                command += ['fwmark', rule['fwmark']]
            run('ip', *command, 'lookup', str(number(rule['table'])))


def remove_tables(tables):
    for family in FAMILIES:
        present = {number(route['table']) for route in ip_json('-N', family, 'route', 'show', 'table', 'all') if 'table' in route}
        for table in sorted(tables & present):
            run('ip', family, 'route', 'flush', 'table', str(table))


def remove_main_routes(host, present):
    if host not in present:
        return
    for family in FAMILIES:
        for route in ip_json(family, 'route', 'show', 'dev', host):
            if route.get('protocol') != 'kernel':
                run('ip', family, 'route', 'del', route['dst'], 'dev', host)


def remove_forward_rules(host):
    """What Gate adds so that a default-drop FORWARD chain does not stop an exit."""
    rules = (['-i', host, '-j', 'ACCEPT'], ['-o', host, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
    for tool in ('iptables', 'ip6tables'):
        if shutil.which(tool) is None:
            continue
        for rule in rules:
            while succeeds(tool, '-w', '2', '-C', 'FORWARD', *rule):
                run(tool, '-w', '2', '-D', 'FORWARD', *rule)


def release_from_vpp(device, socket, notes):
    """A TAP in VPP's hands cannot go. Gate's routes through it went with the flush."""
    if device.get('parent'):
        return
    name = f"tap{device['id']}"
    if name not in run('vppctl', '-s', socket, 'show', 'interface').split():
        return
    run('vppctl', '-s', socket, 'delete', 'tap', name)
    if name in run('vppctl', '-s', socket, 'show', 'interface').split():
        notes.append(f'VPP still holds {name}')


def links_by_name():
    return {link['ifname']: link for link in ip_json('-d', 'link', 'show')}


def remove_links(devices, notes):
    """Children go first. Returns the devices left, which VPP still holds."""
    held = []
    for device in sorted(devices, key=lambda d: not d.get('parent')):
        host = device['host']
        link = links_by_name().get(host)
        if link is None:
            continue
        info = link.get('linkinfo', {})
        if info.get('info_kind') not in ('tun', 'macvlan'):
            notes.append(f'{host} is no longer a device of this program, so it stays')
            continue
        if info.get('info_data', {}).get('numqueues', 0) > 0:
            held.append(host)
            continue
        run('ip', 'link', 'delete', 'dev', host)
    return held


def remove_nft_tables():
    if shutil.which('nft') is None:
        return
    present = [line.split() for line in run('nft', 'list', 'tables').splitlines()]
    for table in NFT_TABLES:
        if ['table', 'inet', table] in present:
            run('nft', 'delete', 'table', 'inet', table)


def restore_host_settings(devices_existed, notes):
    """Later changes have the last word: a value nobody else touched goes back."""
    if not HOST_SETTINGS.is_file():
        if devices_existed:
            notes.append('no record of the previous sysctl values, as an older version made the changes; '
                         'net.ipv4.ip_forward and net.ipv4.conf.all.rp_filter stay as they are')
        return
    for entry in reversed(load_document(HOST_SETTINGS).get('settings', [])):
        path = SYSCTL_ROOT / entry['name']
        if not path.exists():
            continue
        current = path.read_text().strip()
        if current == entry['set']:
            path.write_text(entry['was'] + '\n')
        elif current != entry['was']:
            notes.append(f"{entry['name']} stays at {current}: it was {entry['was']}, and something else changed it after Gate set {entry['set']}")


def remove_install_files(notes):
    files = install_files('vpp.service')
    for path in files:
        if not path.exists():
            continue
        if path.read_text().startswith(MARKER):
            path.unlink()
        else:
            notes.append(f'{path} kept: it was not written by the installer')
    for path in files:
        if path.parent.name == 'networkd.conf.d' and path.parent.is_dir() and not any(path.parent.iterdir()):
            path.parent.rmdir()
    run('systemctl', 'daemon-reload')
    if service_active('NetworkManager'):
        run('systemctl', 'reload', 'NetworkManager')
    if service_active('systemd-networkd'):
        run('systemctl', 'restart', 'systemd-networkd')


def remove_state(runtime):
    """State named by the configuration can live outside the state directory."""
    for key in ('state_file', 'lease_file'):
        if runtime.get(key):
            Path(runtime[key]).unlink(missing_ok=True)
    if runtime.get('state_file'):
        Path(runtime['state_file'] + '.linux-exits.json').unlink(missing_ok=True)
    for directory in (STATE_DIR, RUNTIME_DIR):
        if directory.exists():
            shutil.rmtree(directory)
    LOCK.unlink(missing_ok=True)
    BINARY.unlink(missing_ok=True)
    BINARY.with_name(BINARY.name + '.new').unlink(missing_ok=True)


def installed():
    return STATE_DIR.exists() or BINARY.exists() or any(path.exists() for path in install_files('vpp.service'))


def plan(cli_file, devices, socket):
    settings = load_document(HOST_SETTINGS).get('settings', []) if HOST_SETTINGS.is_file() else []
    return {'vpp_cli_file': str(cli_file) if cli_file else None, 'remove_line': EXEC_LINE,
            'stop_units': [GATE_UNIT, LINKS_UNIT], 'flush_routes': vpp_running(socket),
            'devices': [device['host'] for device in devices], 'nft_tables': list(NFT_TABLES),
            'restore_sysctls': [{'name': s['name'], 'to': s['was']} for s in settings],
            'remove_files': [str(path) for path in install_files('vpp.service')] + [str(STATE_DIR), str(BINARY)],
            'keep': [str(USER_CONFIG), str(DOMAIN_DIR)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vpp-cli-file', type=Path, help='CLI file holding the exec line, if install.py was given one; detected if omitted')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('run as root')
    runtime = load_runtime()
    socket = runtime.get('vpp_socket', DEFAULT_VPP_SOCKET)
    devices = load_devices()
    cli_file = find_cli_file(args, runtime)
    check_cli_file(cli_file)
    if args.dry_run:
        print(json.dumps(plan(cli_file, devices, socket), indent=2))
        return
    if not installed():
        print('Nothing is installed.')
        return
    notes = []
    # First, so that a run that stops here leaves a VPP that still starts.
    remove_exec_line(cli_file)
    stop_units()
    live = vpp_running(socket)
    if live and GENERATED_CONFIG.is_file() and BINARY.is_file():
        run(str(BINARY), '--config', str(GENERATED_CONFIG), '--flush')
    priorities, tables = set(), set()
    for device in devices:
        owned_priorities, owned_tables = device_tables(device)
        priorities |= owned_priorities
        tables |= owned_tables
    remove_rules(priorities, tables)
    remove_tables(tables)
    present = links_by_name()
    for device in devices:
        remove_main_routes(device['host'], present)
        remove_forward_rules(device['host'])
    if live:
        for device in devices:
            release_from_vpp(device, socket, notes)
    held = remove_links(devices, notes)
    if held:
        # Everything needed to finish stays, so that a later run can.
        for note in notes:
            print(f'gate uninstall: {note}', file=sys.stderr)
        raise ValueError(f'VPP still holds {", ".join(held)}; restart VPP and run this again')
    remove_nft_tables()
    restore_host_settings(bool(devices), notes)
    remove_install_files(notes)
    remove_backup(cli_file, notes)
    remove_state(runtime)
    for note in notes:
        print(f'gate uninstall: {note}', file=sys.stderr)
    print(f'Uninstalled. {USER_CONFIG} and {DOMAIN_DIR} stay; delete them if the rules are no longer wanted.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f'gate uninstall: {exc}', file=sys.stderr)
        sys.exit(1)
