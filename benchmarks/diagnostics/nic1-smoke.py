#!/usr/bin/env python3
"""Bounded nic1-only physical smoke test, with restore after VPP exits."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time

BASE = Path('/opt/vpp-vrouter-migration')
RUNTIME = Path('/run/vpp-vrouter-nic1')
STATE = RUNTIME / 'restore.json'
PCI = Path('/sys/bus/pci/devices/0000:02:00.0')
PRODUCTION = Path('/sys/bus/pci/devices/0000:01:00.0')
VPP = Path('/opt/vpp-nic1-test/vpp')
NS = 'vrouter-smoke-lan'
ENV = dict(os.environ, LD_LIBRARY_PATH='/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:' + str(VPP / 'lib/aarch64-linux-gnu'))

def run(*args, timeout=15):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT,
                                   timeout=timeout, env=ENV)

def driver(path):
    return (path / 'driver').resolve().name if (path / 'driver').exists() else None

def restore():
    if not STATE.exists():
        return
    state = json.loads(STATE.read_text())
    devices = {str(Path('/dev') / p.name) for p in (PCI / 'uio').glob('uio*')}
    busy = set()
    for proc in Path('/proc').glob('[0-9]*'):
        for fd in (proc / 'fd').glob('*'):
            try:
                if os.readlink(fd) in devices:
                    busy.add(int(proc.name))
            except OSError:
                pass
    if busy:
        raise RuntimeError(f'nic1 UIO owners still running: {sorted(busy)}')
    if driver(PCI) != 'r8125':
        if (PCI / 'driver').exists():
            (PCI / 'driver/unbind').write_text(PCI.name)
        (PCI / 'driver_override').write_text('r8125')
        Path('/sys/bus/pci/drivers_probe').write_text(PCI.name)
    (PCI / 'driver_override').write_text('\n')
    for _ in range(50):
        if Path('/sys/class/net/nic1').exists():
            break
        time.sleep(.1)
    run('ip', 'link', 'set', 'nic1', 'down')
    run('ip', 'link', 'set', 'nic1', 'address', state['mac'])
    run('ip', 'link', 'set', 'nic1', 'mtu', str(state['mtu']))
    run('ip', 'link', 'set', 'nic1', 'master', state['master'])
    if state['up']:
        run('ip', 'link', 'set', 'nic1', 'up')
    if state.get('namespace') and NS in run('ip', 'netns', 'list').split():
        run('ip', 'netns', 'delete', NS)
    if state.get('management_tap') and Path('/sys/class/net/vrouter-mgmt').exists():
        run('ip', 'link', 'delete', 'vrouter-mgmt')
    if state.get('management_tap'):
        for name in ('management-ready.json', 'management-done'):
            (RUNTIME / name).unlink(missing_ok=True)
    huge = RUNTIME / 'hugepages'
    if os.path.ismount(huge):
        run('umount', str(huge))
    Path('/proc/sys/vm/nr_hugepages').write_text(str(state['hugepages']))
    if driver(PRODUCTION) != state['production_driver']:
        raise RuntimeError('Production driver changed outside this test')
    STATE.unlink()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--restore', action='store_true')
    parser.add_argument('--workers', type=int, choices=(0, 2), default=0)
    parser.add_argument('--rx-queues', type=int, choices=(1, 4), default=4)
    parser.add_argument('--soak-seconds', type=int, default=0)
    parser.add_argument('--soak-udp', action='store_true')
    parser.add_argument('--physical-only-seconds', type=int, default=0)
    parser.add_argument('--vlan-management-seconds', type=int, default=0)
    parser.add_argument('--peer-ip', type=ipaddress.IPv4Address, default=ipaddress.IPv4Address('10.61.20.134'))
    args = parser.parse_args()
    peer_last = int(str(args.peer_ip).split('.')[-1])
    if (args.peer_ip not in ipaddress.IPv4Network('10.61.20.0/24') or
            peer_last in (0, 1, 250, 255) or 160 <= peer_last < 240):
        parser.error('--peer-ip must be on the test subnet and outside harness addresses')
    if args.soak_seconds < 0 or args.soak_seconds > 7200:
        parser.error('--soak-seconds must be between 0 and 7200')
    if not 0 <= args.physical_only_seconds <= 7200 or (args.physical_only_seconds and args.soak_seconds):
        parser.error('physical-only must be 1..7200 seconds and excludes the NAT soak')
    if (not 0 <= args.vlan_management_seconds <= 300 or
            (args.vlan_management_seconds and (args.soak_seconds or args.physical_only_seconds))):
        parser.error('VLAN/management window must be 1..300 seconds and excludes soak modes')
    if args.soak_seconds and (args.workers or args.rx_queues != 4):
        parser.error('soak currently requires --workers 0 --rx-queues 4')
    if os.geteuid():
        raise RuntimeError('root required')
    if args.restore:
        restore()
        return
    assert not STATE.exists(), 'Restore unfinished test first'
    assert driver(PCI) == driver(PRODUCTION) == 'r8125'
    info = json.loads(run('ip', '-j', 'address', 'show', 'nic1'))[0]
    assert info.get('master') == 'lan'
    assert not any(a['family'] == 'inet' for a in info['addr_info'])
    assert NS not in run('ip', 'netns', 'list').split()
    if args.vlan_management_seconds:
        assert not Path('/sys/class/net/vrouter-mgmt').exists()
        assert not run('ip', 'route', 'show', '10.61.40.0/24').strip(), 'Test subnet already routed'
    # Peer ICMP filtering must not prevent starting a diagnostic test.
    # Actual peer reachability is checked after VPP has acquired the port.
    assert 'LOWER_UP' in info['flags'], 'nic1 has no physical link'
    RUNTIME.mkdir(mode=0o700, exist_ok=True)
    logdir = BASE / 'logs' / f'nic1-workers{args.workers}-{time.time_ns()}'
    logdir.mkdir(mode=0o700)
    state = dict(mac=info['address'], mtu=info['mtu'], master=info['master'],
                 up='UP' in info['flags'], production_driver=driver(PRODUCTION),
                 hugepages=int(Path('/proc/sys/vm/nr_hugepages').read_text()), namespace=False)
    STATE.write_text(json.dumps(state))
    STATE.chmod(0o600)
    process = None
    report = {'workers': args.workers, 'rx_queues': args.rx_queues,
              'peer_ip': str(args.peer_ip),
              'passed': False, 'logdir': str(logdir)}

    def cli(command):
        out = run(str(VPP / 'bin/vppctl'), '-s', str(RUNTIME / 'cli.sock'), command, timeout=20)
        with (logdir / 'cli.log').open('a') as f:
            f.write(command + '\n' + out + '\n')
        if re.search(r"unknown input|unknown interface|failed|not supported|doesn't support|invalid argument|create tap:|error:", out, re.I):
            raise RuntimeError(command + ': ' + out)
        return out

    def interrupted(*unused):
        raise RuntimeError('Test interrupted; restoring nic1')

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    try:
        run('modprobe', 'uio')
        if not Path('/sys/bus/pci/drivers/uio_pci_generic').exists():
            run('insmod', '/opt/vpp-nic1-test/src/uio/uio_pci_generic.ko')
        Path('/proc/sys/vm/nr_hugepages').write_text(str(max(state['hugepages'], 128)))
        huge = RUNTIME / 'hugepages'
        huge.mkdir(exist_ok=True)
        run('mount', '-t', 'hugetlbfs', 'none', str(huge))
        run('ip', 'link', 'set', 'nic1', 'nomaster')
        run('ip', 'link', 'set', 'nic1', 'down')
        (PCI / 'driver_override').write_text('uio_pci_generic')
        (PCI / 'driver/unbind').write_text(PCI.name)
        Path('/sys/bus/pci/drivers_probe').write_text(PCI.name)
        assert driver(PCI) == 'uio_pci_generic' and driver(PRODUCTION) == 'r8125'
        # Create the netns mount before cloning VPP's private mount namespace.
        run('ip', 'netns', 'add', NS)
        state['namespace'] = True
        STATE.write_text(json.dumps(state))
        run('ip', '-n', NS, 'link', 'set', 'lo', 'up')
        workers = 'corelist-workers 5-6' if args.workers else ''
        config = f'''
unix {{ nodaemon runtime-dir {RUNTIME} cli-listen {RUNTIME}/cli.sock }}
api-segment {{ prefix vrouter-smoke }}
socksvr {{ socket-name {RUNTIME}/api.sock }}
statseg {{ socket-name {RUNTIME}/stats.sock }}
cpu {{ main-core 4 {workers} }}
memory {{ main-heap-size 128M }}
buffers {{ buffers-per-numa 8192 }}
plugins {{ path {BASE}/plugins
plugin default {{ disable }}
plugin dpdk_plugin.so {{ enable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
plugin nat44_ei_plugin.so {{ enable }}
plugin nat_ei_context_plugin.so {{ enable }}
}}
dpdk {{ uio-driver uio_pci_generic
dev {PCI.name} {{ name nic1-dpdk num-rx-queues {args.rx_queues} num-tx-queues {2 if args.workers else 1} rss {{ ipv4 ipv6 }} }}
iova-mode pa huge-dir {huge} file-prefix vrouter-smoke no-multi-seg }}
'''
        (RUNTIME / 'startup.conf').write_text(config)
        with (logdir / 'vpp.log').open('w') as log:
            command = [str(VPP / 'bin/vpp'), '-c', str(RUNTIME / 'startup.conf')]
            process = subprocess.Popen(command,
                                       stdout=log, stderr=log, env=ENV)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('VPP exited: ' + (logdir / 'vpp.log').read_text()[-2000:])
            if (RUNTIME / 'cli.sock').exists():
                try:
                    if 'nic1-dpdk' in cli('show interface'):
                        break
                except subprocess.CalledProcessError:
                    pass
            time.sleep(.1)
        else:
            raise RuntimeError('VPP startup timeout')
        cli(f'set interface mac address nic1-dpdk {state["mac"]}')
        cli('set interface mtu packet 1500 nic1-dpdk')
        cli('set interface state nic1-dpdk up')
        if args.vlan_management_seconds:
            state['management_tap'] = True
            STATE.write_text(json.dumps(state))
            cli('set interface promiscuous on nic1-dpdk')
            cli('create sub-interface nic1-dpdk 100 dot1q 100 exact-match')
            cli('create sub-interface nic1-dpdk 10 dot1q 10 exact-match')
            cli('set interface state nic1-dpdk.100 up')
            cli('set interface state nic1-dpdk.10 up')
            cli('set interface ip address nic1-dpdk.100 192.0.2.250/24')
            cli('create loopback interface instance 3200')
            cli('set interface state loop3200 up')
            cli('set interface l2 bridge nic1-dpdk 3200')
            cli('set interface l2 bridge loop3200 3200 bvi')
            cli('set interface ip address loop3200 10.61.40.1/24')
            cli('create tap id 3201 host-if-name vrouter-mgmt host-ip4-addr 10.61.40.2/24')
            cli('set interface state tap3201 up')
            cli('set interface rx-mode tap3201 interrupt')
            cli('set interface l2 bridge tap3201 3200')
            cli(f'create tap id 3202 host-ns {NS} host-if-name mgmt0 host-ip4-addr 198.18.10.250/24')
            cli('set interface state tap3202 up')
            cli('set interface rx-mode tap3202 interrupt')
            cli('set interface l2 bridge nic1-dpdk.10 3210')
            cli('set interface l2 tag-rewrite nic1-dpdk.10 pop 1')
            cli('set interface l2 bridge tap3202 3210')
            cli('trace add dpdk-input 128')
            cli('trace add tap-input 128')
            time.sleep(15)
            cli('ping 192.0.2.134 repeat 2 interval 0.1')
            out = cli('ping 192.0.2.134 repeat 5 interval 0.1')
            assert '5 received, 0% packet loss' in out, out
            report['vlan100'] = out
            run('ip', 'netns', 'exec', NS, 'ping', '-c', '2', '-W', '2', '198.18.10.134')
            vps = run('ip', 'netns', 'exec', NS, 'ping', '-c', '5', '-W', '2', '198.18.10.134')
            assert '5 received, 0% packet loss' in vps, vps
            report['vlan10_l2'] = vps
            cli('show bridge-domain 3200 detail')
            cli('clear trace')
            cli('trace add dpdk-input 64')
            cli('trace add tap-input 64')
            run('ping', '-I', 'vrouter-mgmt', '-c', '2', '-W', '2', '10.61.40.134')
            management = run('ping', '-I', 'vrouter-mgmt', '-c', '5', '-W', '2', '10.61.40.134')
            assert '5 received, 0% packet loss' in management, management
            with socket.create_connection(('10.61.40.134', 22), timeout=3) as sock:
                banner = sock.recv(256).decode(errors='replace').strip()
            assert banner.startswith('SSH-2.0-'), banner
            report['vlan_management'] = dict(vlan100=out, vlan10_l2=vps,
                management_tap=management, peer_ssh_banner=banner,
                linux_management_ip='10.61.40.2', gateway='10.61.40.1')
            ready = RUNTIME / 'management-ready.json'
            done = RUNTIME / 'management-done'
            done.unlink(missing_ok=True)
            ready.write_text(json.dumps(report['vlan_management']))
            deadline = time.monotonic() + args.vlan_management_seconds
            while not done.exists() and time.monotonic() < deadline:
                assert process.poll() is None
                assert driver(PRODUCTION) == 'r8125'
                time.sleep(.5)
            cli('show bridge-domain 3200 detail')
            cli('show bridge-domain 3210 detail')
            cli('show hardware-interfaces nic1-dpdk')
            ready.unlink(missing_ok=True)
            done.unlink(missing_ok=True)
            report['passed'] = True
            return
        cli('set interface ip address nic1-dpdk 10.61.20.250/24')
        cli('trace add dpdk-input 64')
        time.sleep(15)
        cli(f'ping {args.peer_ip} repeat 2 interval 0.1')
        out = cli(f'ping {args.peer_ip} repeat 5 interval 0.1')
        assert '5 received, 0% packet loss' in out, out
        report['physical_ping'] = True
        report['physical_ping_rtt_ms'] = list(map(float, re.findall(r'time=([\d.]+) ms', out)))
        if args.physical_only_seconds:
            for last in range(160, 240):
                cli(f'set interface ip address nic1-dpdk 10.61.20.{last}/24')
            cli('clear trace')
            cli('clear errors')
            cli('trace add dpdk-input 4096')
            started = time.monotonic()
            samples = []
            while time.monotonic() - started < args.physical_only_seconds + 180:
                assert process.poll() is None, 'VPP exited during physical-only test'
                assert driver(PRODUCTION) == 'r8125'
                status = Path(f'/proc/{process.pid}/status').read_text()
                samples.append(dict(elapsed_seconds=time.monotonic() - started,
                    memory_kib=dict((key, int(value)) for key, value in
                        re.findall(r'^(VmRSS|VmSize|VmData):\s+(\d+) kB', status, re.M))))
                (logdir / 'physical-progress.json').write_text(json.dumps(samples[-1]))
                cli('show interface')
                cli('show errors')
                time.sleep(min(30, max(0, args.physical_only_seconds + 180 -
                                       (time.monotonic() - started))))
            trace = cli('show trace max 4096')
            queues = sorted(set(map(int, re.findall(r'nic1-dpdk rx queue\s+(\d+)', trace))))
            report['physical_only'] = dict(rx_queues_observed=queues, memory_samples=samples,
                no_tap_or_nat=True, peer_validation_required=True,
                local_checks_passed=queues == list(range(args.rx_queues)))
            report['validation_status'] = 'Peer integrity result must be merged separately'
            report['passed'] = None
            assert report['physical_only']['local_checks_passed'], 'Native echo did not cover every RX queue'
            return
        cli('clear trace')
        cli('trace add dpdk-input 1024')
        current = '10.61.20.250'
        for last in range(160, 240):
            address = f'10.61.20.{last}'
            cli(f'set interface ip address del nic1-dpdk {current}/24')
            cli(f'set interface ip address nic1-dpdk {address}/24')
            cli(f'ping {args.peer_ip} repeat 2 interval 0.02')
            out = cli(f'ping {args.peer_ip} repeat 2 interval 0.05')
            assert '2 received, 0% packet loss' in out, out
            current = address
        trace = cli('show trace max 1024')
        queues = sorted(set(map(int, re.findall(r'nic1-dpdk rx queue\s+(\d+)', trace))))
        report['rx_queues_observed'] = queues
        assert queues == list(range(args.rx_queues)), f'Not all RX queues observed: {queues}'
        queue_targets = {}
        for packet in re.split(r'\nPacket \d+\n', trace):
            queue = re.search(r'nic1-dpdk rx queue\s+(\d+)', packet)
            target = re.search(r'ICMP: ' + re.escape(str(args.peer_ip)) + r' -> (' + re.escape('10.61.20.') + r'(\d+))', packet)
            if queue and target and 160 <= int(target[2]) < 240:
                queue_targets.setdefault(int(queue[1]), target[1])
        report['rss_target_by_queue'] = queue_targets
        cli(f'set interface ip address del nic1-dpdk {current}/24')
        cli('set interface ip address nic1-dpdk 10.61.20.250/24')
        cli(f'create tap id 3201 host-ns {NS} host-if-name mgmt0 host-ip4-addr 10.252.12.2/24')
        cli('set interface ip address tap3201 10.252.12.1/24')
        cli('set interface state tap3201 up')
        cli('set interface rx-mode tap3201 interrupt')
        run('ip', '-n', NS, 'route', 'add', 'default', 'via', '10.252.12.1')
        cli('nat44 ei plugin enable sessions 4096')
        cli('nat44 ei output-chain nic1-dpdk')
        cli('set interface nat44 ei out nic1-dpdk output-feature')
        cli('nat44 ei add address 10.61.20.250 tenant-vrf 0')
        report['physical_nat_warmup'] = run('ip', 'netns', 'exec', NS, 'ping', '-c', '2', '-W', '2', str(args.peer_ip))
        out = run('ip', 'netns', 'exec', NS, 'ping', '-c', '5', '-W', '2', str(args.peer_ip))
        assert '5 received, 0% packet loss' in out, out
        report['physical_nat_icmp'] = True
        report['physical_nat_rtt_ms'] = list(map(float, re.findall(r'time=([\d.]+) ms', out)))
        if args.workers:
            run('ip', '-n', NS, 'address', 'add', '10.252.12.3/24', 'dev', 'mgmt0')
            report['physical_nat_by_source'] = {}
            for source in ('10.252.12.2', '10.252.12.3'):
                warmup = run('ip', 'netns', 'exec', NS, 'ping', '-I', source,
                             '-c', '2', '-W', '2', str(args.peer_ip))
                out = run('ip', 'netns', 'exec', NS, 'ping', '-I', source,
                          '-c', '5', '-W', '2', str(args.peer_ip))
                assert '5 received, 0% packet loss' in out, out
                report['physical_nat_by_source'][source] = dict(warmup=warmup,
                    rtt_ms=list(map(float, re.findall(r'time=([\d.]+) ms', out))))
            sessions = cli('show nat44 ei sessions detail')
            owners = {int(thread): int(count) for thread, count in re.findall(
                r'thread (\d+) [^:]+: (\d+) sessions', sessions) if int(count)}
            assert set(owners) == {1, 2}, f'Both workers must own NAT sessions: {owners}'
            report['nat_worker_session_counts'] = owners
        if args.soak_seconds:
            from nic1_soak import run_soak
            assert sorted(queue_targets) == [0, 1, 2, 3], queue_targets
            report['soak'] = run_soak(cli, run, logdir, args.soak_seconds,
                                      [queue_targets[i] for i in range(4)], args.soak_udp,
                                      process.pid, str(args.peer_ip))
            assert report['soak']['passed'], 'Long-running stability checks failed'
        for command in ('show hardware-interfaces nic1-dpdk', 'show interface rx-placement', 'show errors'):
            cli(command)
        report['passed'] = True
    except Exception as exc:
        report['error'] = str(exc) + (': ' + exc.output[-2000:] if isinstance(exc, subprocess.CalledProcessError) else '')
        if process and process.poll() is None:
            for command in ('show hardware-interfaces', 'show interface',
                            'show ip neighbors', 'show errors', 'show l2fib verbose', 'show trace max 512'):
                try:
                    output = cli(command)
                    if command == 'show errors':
                        match = re.search(r'(\d+)\s+ip4-icmp-input\s+echo replies sent', output)
                        report['peer_echo_requests_replied'] = int(match[1]) if match else 0
                except Exception:
                    pass
        raise
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        restore()
        (logdir / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report), flush=True)

if __name__ == '__main__':
    main()
