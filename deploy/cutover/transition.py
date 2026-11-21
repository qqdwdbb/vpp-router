#!/usr/bin/env python3
"""Transactional VROUTER cutover. Default is read-only; --apply uses systemd recovery."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
UNITS = ('vrouter-coturn', 'vrouter-host-services', 'vrouter-ike-addresses', 'vrouter-pd-sync', 'vrouter-dns-route-gate', 'vrouter-strongswan',
         'vrouter-dnsmasq', 'vrouter-firewall', 'vrouter-network-prep', 'vrouter-vpp', 'vrouter-namespace')
STOP_LINUX = ('miniupnpd.service', 'dhcpcd-prefix-refresh.service', 'dhcpcd.service',
              'dnsmasq.service', 'strongswan-starter.service')


def run(*args, check=True, timeout=60):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        err = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Command failed ({' '.join(map(str, args))}): {err}")
    return result.stdout


def load(root):
    return json.loads((root/'state.json').read_text())


def save(root, state, phase):
    state['phase'] = phase
    temporary = root/'state.tmp'
    temporary.write_text(json.dumps(state, indent=2)+'\n')
    temporary.chmod(0o600)
    temporary.replace(root/'state.json')


def audit_module():
    spec = importlib.util.spec_from_file_location('linux_audit', HERE/'linux-recovery-audit.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def management(p, connection):
    fields = connection.split()
    if len(fields) != 4 or fields[0] != p['management']['peer'] or fields[2] != p['management']['address']:
        raise ValueError('Use the independent mgmt0 SSH connection, preserving SSH_CONNECTION through sudo')
    iface = p['management']['interface']
    if Path('/sys/class/net', iface, 'master').exists():
        raise ValueError('Management interface is enslaved')
    route = json.loads(run('ip', '-j', 'route', 'get', fields[0]))[0]
    if route.get('dev') != iface or route.get('prefsrc') != fields[2]:
        raise ValueError('Management return route is not independent')


def verify_manifest(root):
    manifest = json.loads((root/'manifest.json').read_text())
    for name, digest in manifest.items():
        path = root/name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Bundle modified; prepare a new release')


def preflight(root, p):
    verify_manifest(root)
    state = load(root)
    if state['phase'] not in ('prepared', 'linux'):
        raise ValueError('Deployment is not in Linux/prepared state')
    report = json.loads((root/'validation.json').read_text())
    if not report.get('passed') or report.get('manifest_sha256') != hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest():
        raise ValueError('Current bundle has not passed isolated validation')
    if subprocess.run(['pgrep','-x','vpp'],capture_output=True).returncode == 0:
        raise ValueError('A VPP process is already running')
    pci = Path('/sys/bus/pci/devices', p['pci'])
    if pci.resolve().name != '0000:01:00.0' or (pci/'driver').resolve().name != 'r8125':
        raise ValueError('Unexpected PCI owner')
    audit = audit_module()
    differences = audit.compare(json.loads((root/'baseline/linux-state.json').read_text()), audit.capture())
    if differences:
        raise ValueError('Linux baseline changed: '+', '.join(differences))
    for name in UNITS:
        for directory in ('/etc/systemd/system', '/run/systemd/system'):
            if Path(directory, name+'.service').exists():
                raise ValueError('Reserved service already exists: '+name)
    for name, digest in json.loads((root/'input-hashes.json').read_text()).items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise ValueError('Production configuration changed; prepare again')
    run('nft','-c','-f',root/'baseline/restore-firewall.nft')


def route_command(family, row):
    """Recreate static routes only; RA/DHCP/kernel routes are relearned."""
    if row.get('protocol') in ('kernel','ra','dhcp') or row.get('table') == 'local' or 'cache' in row:
        return None
    if not row.get('dev') and not row.get('gateway'):
        return None
    command = ['ip','-'+family,'route','replace']
    if row.get('type') and row['type'] != 'unicast':
        command.append(row['type'])
    command.append(row.get('dst','default'))
    for field, flag in (('gateway','via'),('dev','dev'),('prefsrc','src'),('metric','metric'),('mtu','mtu'),('table','table')):
        if field in row:
            command += [flag, str(row[field])]
    if 'onlink' in row.get('flags',[]):
        command.append('onlink')
    return command


def restore_linux(root, state):
    if state['phase'] in ('prepared','linux'):
        return
    save(root, state, 'rolling-back')
    errors = []
    def attempt(*args, **kwargs):
        try:
            return run(*args, **kwargs)
        except Exception:
            errors.append(str(args[0])+' failed')
    # Stop all owned dependents even when activation only completed halfway.
    owned = state.get('installed_units', [])
    for unit in (name+'.service' for name in UNITS):
        if unit in owned:
            attempt('systemctl','stop',unit)
    if subprocess.run(['pgrep','-x','vpp'],capture_output=True).returncode == 0:
        raise RuntimeError('VPP still running; refusing driver unbind')
    if (root/'host-routing.json').exists():
        spec = importlib.util.spec_from_file_location('host_routing', HERE.parent/'host-services/host-routing.py')
        routing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(routing)
        # Remove policy before deleting the TAP, including partial startup.
        routing.remove(run, root/'host-routing.json')
    # Remove only links created by this transaction; management is never touched.
    for dev in ('vpp-lan','vrouter-vps','vpp-wg-proxy','vpp-hostsvc'):
        if Path('/sys/class/net',dev).exists():
            attempt('ip','link','delete',dev)
    if Path('/sys/class/net/br-mgmt').exists():
        attempt('ip','link','set','nic1','nomaster')
        attempt('ip','link','delete','br-mgmt')
    attempt('sh',HERE.parent/'restore-nic0.sh','--force')
    attempt('ip','addr','del','10.62.10.1/32','dev','lo',check=False)
    record = root/'host-prefix.json'
    if record.exists():
        address = json.loads(record.read_text()).get('address')
        if address:
            attempt('ip','-6','addr','del',address+'/128','dev','lo')
        record.unlink()
    baseline = json.loads((root/'baseline/linux-state.json').read_text())
    for name in ('nic0','wan','vps','lan','br0','nic1','wg0','wg1','sg'):
        value = baseline['links'].get(name)
        if not value:
            continue
        if value.get('mac'):
            attempt('ip','link','set',name,'address',value['mac'])
        attempt('ip','link','set',name,'mtu',str(value['mtu']))
        if value.get('master'):
            attempt('ip','link','set',name,'master',value['master'])
        attempt('ip','link','set',name,'up' if value['up'] else 'down')
        for address in baseline['addresses'].get(name,[]):
            args = ['ip', '-6' if ':' in address else '-4', 'addr','replace',address,'dev',name]
            if ':' in address:
                args.append('nodad')
            attempt(*args)
    for family in ('4','6'):
        for row in baseline['routes'+family]:
            command = route_command(family,row)
            if command:
                attempt(*command)
    # Baseline rules remain intact; only owned host-service rules were removed.
    attempt('nft','-f',root/'baseline/restore-firewall.nft')
    for unit in STOP_LINUX + (('coturn.service',) if (root/'config/turnserver.conf').exists() else ()):
        if baseline['services'].get(unit) == 'active':
            attempt('systemctl','start',unit)
    attempt('dhcpcd','--rebind','wan')
    for unit in owned:
        path = Path('/run/systemd/system',unit)
        # Avoid removing a file replaced by another administrator.
        source = root/'units'/unit
        if path.exists() and source.exists() and path.read_bytes() == source.read_bytes():
            path.unlink()
    attempt('systemctl','daemon-reload')
    for _ in range(20):
        differences = audit_module().compare(baseline,audit_module().capture())
        if not differences:
            save(root,state,'linux')
            active = Path('/run/vrouter-cutover-active')
            if active.exists() and active.read_text().strip() == str(root):
                active.unlink()
            run('systemctl','stop','vrouter-cutover-rollback.timer',check=False)
            run('systemctl','reset-failed','vrouter-cutover-rollback.timer','vrouter-cutover-activate.service','vrouter-cutover-manual-rollback.service',check=False)
            print('Linux baseline restored and verified')
            return
        if differences == ['service: miniupnpd.service is not active']:
            attempt('systemctl','restart','miniupnpd.service')
        time.sleep(3)
    state['recovery_errors'] = errors
    state['differences'] = differences
    save(root,state,'recovery-failed')
    raise RuntimeError('Linux recovery incomplete; inspect private state.json')


def activate(root,state,p):
    def log(msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

    log("1/7 Recording intent: switching phase...")
    save(root,state,'switching')
    log("2/7 Installing VPP systemd units to /run/systemd/system...")
    for source in (root/'units').glob('*.service'):
        state.setdefault('installed_units',[]).append(source.name)
        save(root,state,'switching')
        shutil.copy2(source, Path('/run/systemd/system')/source.name)
    run('systemctl','daemon-reload')
    log("3/7 Stopping conflicting Linux services (miniupnpd, dhcpcd, dnsmasq, strongswan)...")
    for unit in STOP_LINUX + (('coturn.service',) if p.get('host_service_path') else ()):
        if json.loads((root/'baseline/linux-state.json').read_text())['services'].get(unit) == 'active':
            run('systemctl','stop',unit)
    baseline = json.loads((root/'baseline/linux-state.json').read_text())
    log("4/7 Flushing Linux WG interfaces & IP addresses...")
    for name in ('wg0','wg1','sg','lan'):
        if name != 'lan':
            run('ip','link','set',name,'down')
        run('ip','addr','flush','dev',name,'scope','global')
    log("5/7 Binding nic0 (0000:01:00.0) to uio_pci_generic...")
    run('modprobe','uio')
    run('modprobe','uio_pci_generic')
    pci = Path('/sys/bus/pci/devices',p['pci'])
    (pci/'driver_override').write_text('uio_pci_generic')
    (pci/'driver/unbind').write_text(p['pci'])
    Path('/sys/bus/pci/drivers_probe').write_text(p['pci'])
    if (pci/'driver').resolve().name != 'uio_pci_generic':
        raise RuntimeError('DPDK driver binding failed')
    log("6/7 Starting VPP router core and dependent services...")
    run('systemctl','start','vrouter-pd-sync.service','vrouter-dns-route-gate.service','vrouter-ike-addresses.service',timeout=120)
    if p.get('host_service_path'):
        run('systemctl', 'start', 'vrouter-host-services.service')
        if (root/'config/turnserver.conf').exists():
            run('systemctl', 'start', 'vrouter-coturn.service')
    log("7/7 Verifying VPP active status & running gateway ping check...")
    check_vpp(root)
    save(root,state,'awaiting-confirmation')
    log("==> VPP cutover ACTIVE! 600s rollback timer running. Awaiting confirmation.")


def check_vpp(root):
    for name in UNITS:
        if name == 'vrouter-host-services' and not (root/'config/host-services.json').exists():
            continue
        if name == 'vrouter-coturn' and not (root/'config/turnserver.conf').exists():
            continue
        status = run('systemctl','is-active',name+'.service',check=False).strip()
        if status != 'active':
            raise RuntimeError(f'Deployment service not active: {name} (status={status})')
        print(f"  [OK] service {name} is active", flush=True)
    print("  [PING] checking LAN gateway (10.61.20.1)...", flush=True)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        res = subprocess.run(['ping', '-c', '1', '-W', '1', '10.61.20.1'], capture_output=True)
        if res.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('LAN gateway (10.61.20.1) unreachable')
    print("  [OK] LAN gateway (10.61.20.1) is reachable", flush=True)

    print("  [PING] waiting for WAN gateway (10.61.10.1) and carrier...", flush=True)
    deadline = time.monotonic() + 25
    start_t = time.monotonic()
    last_err = ""
    while time.monotonic() < deadline:
        res = subprocess.run(['ping', '-c', '1', '-W', '1', '10.61.10.1'], capture_output=True, text=True)
        if res.returncode == 0:
            print(f"  [OK] WAN gateway reachable in {time.monotonic() - start_t:.1f}s", flush=True)
            break
        last_err = res.stderr.strip() or res.stdout.strip()
        time.sleep(1)
    else:
        vpp_ping = run('/usr/local/bin/vppctl', '-s', '/run/vpp/cli.sock', 'ping 10.61.10.1 repeat 2 source nic0-dpdk.100', check=False).strip()
        vpp_hw = run('/usr/local/bin/vppctl', '-s', '/run/vpp/cli.sock', 'show hardware-interfaces nic0-dpdk', check=False).strip()
        raise RuntimeError(f'WAN gateway (10.61.10.1) unreachable after 25s ({last_err}); vpp_ping: {vpp_ping}; hw: {vpp_hw[:160]}')
    print("  [OK] All connectivity and gateway checks passed!", flush=True)


def follow_service(unit_name, root, target_phase, fail_phase, timeout=120):
    print(f"Watching {unit_name} progress (Ctrl+C will NOT interrupt background process):", flush=True)
    proc = subprocess.Popen(['journalctl', '-u', unit_name, '-f', '-n', '0'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    deadline = time.monotonic() + timeout
    try:
        import select
        while time.monotonic() < deadline:
            r, _, _ = select.select([proc.stdout], [], [], 0.5)
            if r:
                line = proc.stdout.readline()
                if line:
                    print(line.rstrip(), flush=True)
            phase = load(root).get('phase')
            if phase in (target_phase, fail_phase):
                break
            out = run('systemctl', 'show', unit_name + '.service', '--property=ActiveState,SubState', '--value', check=False).splitlines()
            if len(out) >= 2 and out[0] in ('inactive', 'failed'):
                time.sleep(1)
                break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()

    phase = load(root).get('phase')
    if phase == target_phase:
        if target_phase == 'awaiting-confirmation':
            print(f"\n[SUCCESS] VPP is fully active! 600s rollback timer running.\nConfirm when ready with:\n  sudo env SSH_CONNECTION=\"$SSH_CONNECTION\" python3 {HERE/'transition.py'} commit --bundle {root}\n", flush=True)
        elif target_phase == 'linux':
            print("\n[SUCCESS] Linux baseline restored and verified.\n", flush=True)
    else:
        print(f"\n[INFO] Transition finished with phase: '{phase}'. Inspect logs with:\n  sudo journalctl -u {unit_name} --no-pager -n 50\n", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target',choices=('vpp','linux','recover','activate','failure','status','commit'))
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--automatic',action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root')
    os.umask(0o077)
    root = args.bundle.resolve()
    if root.stat().st_uid != 0 or root.stat().st_mode & 0o077:
        raise ValueError('Bundle must be root-owned and private')
    p = json.loads((root/'profile.json').read_text())
    state = load(root)
    if args.target == 'status':
        print(json.dumps({'phase':state['phase'],'bundle':str(root)}))
        return
    with open('/run/lock/vrouter-cutover.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        state = load(root)
        active = Path('/run/vrouter-cutover-active')
        if active.exists() and active.read_text().strip() != str(root):
            raise ValueError('Another deployment owns the active transaction')
        if args.target == 'failure':
            if os.environ.get('SERVICE_RESULT') == 'success':
                return
            restore_linux(root,state)
        elif args.target == 'linux':
            if args.automatic and state['phase'] in ('confirmed','linux','prepared'):
                return
            if not args.automatic:
                management(p,os.environ.get('SSH_CONNECTION',''))
            if args.automatic:
                restore_linux(root,state)
            elif args.apply:
                run('systemctl','reset-failed','vrouter-cutover-manual-rollback.service',check=False)
                run('systemd-run','--no-block','--unit=vrouter-cutover-manual-rollback','--service-type=oneshot',
                    '--property=TimeoutStartSec=240','--setenv=VROUTER_CUTOVER_BUNDLE='+str(root),
                    '/usr/bin/python3',str(HERE/'transition.py'),'recover','--bundle',str(root))
                print('Linux recovery dispatched independently of SSH')
            else:
                print('Read-only: Linux recovery would stop owned VPP units and restore this bundle baseline')
        elif args.target == 'recover':
            if os.environ.get('VROUTER_CUTOVER_BUNDLE') != str(root):
                raise ValueError('Recovery must be dispatched by switch-to-linux')
            restore_linux(root,state)
        elif args.target == 'activate':
            # Internal mode is valid only in the unit created by the controller.
            if os.environ.get('VROUTER_CUTOVER_BUNDLE') != str(root) or state['phase'] != 'armed':
                raise ValueError('Activation must be dispatched by switch-to-vpp')
            activate(root,state,p)
        elif args.target == 'commit':
            management(p,os.environ.get('SSH_CONNECTION',''))
            if state['phase'] != 'awaiting-confirmation':
                raise ValueError('No pending VPP trial')
            check_vpp(root)
            save(root,state,'confirmed')
            run('systemctl','stop','vrouter-cutover-rollback.timer')
            print('VPP trial confirmed; boot configuration is unchanged')
        else:
            management(p,os.environ.get('SSH_CONNECTION',''))
            preflight(root,p)
            if not args.apply:
                print('Read-only preflight passed; no NIC/service changed')
                return
            active.write_text(str(root)+'\n')
            save(root,state,'armed')
            script = str(HERE/'transition.py')
            # Timer is outside the activation cgroup and survives SSH loss.
            try:
                run('systemctl','stop','vrouter-cutover-rollback.timer',check=False)
                run('systemctl','reset-failed','vrouter-cutover-rollback.timer','vrouter-cutover-activate.service',check=False)
                run('systemd-run','--unit=vrouter-cutover-rollback','--on-active='+str(p['rollback_seconds'])+'s',
                    '/usr/bin/python3',script,'linux','--automatic','--bundle',str(root))
                run('systemd-run','--no-block','--unit=vrouter-cutover-activate','--service-type=oneshot',
                    '--property=TimeoutStartSec=180','--property=TimeoutStopSec=150',
                    '--property=ExecStopPost=/usr/bin/python3 '+script+' failure --bundle '+str(root),
                    '--setenv=VROUTER_CUTOVER_BUNDLE='+str(root),
                    '/usr/bin/python3',script,'activate','--bundle',str(root))
            except Exception:
                restore_linux(root,state)
                raise
            print('Cutover dispatched with independent timed Linux rollback')

    if args.apply and args.target in ('vpp', 'linux'):
        unit = 'vrouter-cutover-activate' if args.target == 'vpp' else 'vrouter-cutover-manual-rollback'
        target_phase = 'awaiting-confirmation' if args.target == 'vpp' else 'linux'
        fail_phase = 'linux' if args.target == 'vpp' else 'recovery-failed'
        follow_service(unit, root, target_phase, fail_phase)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Transition failed: '+(str(error) if isinstance(error,(ValueError,RuntimeError)) else type(error).__name__),file=sys.stderr)
        sys.exit(1)
