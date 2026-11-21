#!/usr/bin/env python3
"""Compare RX/drop, routed VLAN-to-VLAN, and current NAT paths."""
import argparse
import concurrent.futures
import getpass
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[2]
HOSTS = {'router': '10.61.20.1', 'linux': '10.61.20.134'}
SOCKETS = {'router': '/tmp/vrouter-bench-router.sock', 'linux': '/tmp/vrouter-bench-linux.sock'}
VPP = '/usr/local/bin/vppctl'
RX_IP = '10.61.20.198'
PORT = 45996
OUT = BASE / 'artifacts/vrouter/path-compare-20261030.json'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--rates', default='1000,1400000,1500000,1600000,1800000')
    p.add_argument('--seconds', type=int, default=15)
    p.add_argument('--run-base', type=int, default=500000)
    p.add_argument('--output', type=Path, default=OUT)
    p.add_argument('--modes', default='drop,vlan,nat',
                   help='comma-separated subset of drop,vlan,forward,nat')
    p.add_argument('--password-stdin', action='store_true')
    p.add_argument('--sample-worker', action='store_true')
    p.add_argument('--sample-rx-status', action='store_true')
    p.add_argument('--flows', type=int, default=1)
    p.add_argument('--router-socket', default=SOCKETS['router'])
    p.add_argument('--linux-socket', default=SOCKETS['linux'])
    args = p.parse_args()
    SOCKETS.update(router=args.router_socket, linux=args.linux_socket)
    if not 1 <= args.flows <= 20000:
        p.error('--flows must be 1..20000')
    rates = [int(x) for x in args.rates.split(',')]
    modes = tuple(x.strip() for x in args.modes.split(',') if x.strip())
    if not modes or any(x not in ('drop', 'vlan', 'forward', 'nat') for x in modes):
        p.error('--modes must contain only drop,vlan,forward,nat')
    if any(r < 1000 or r > 2500000 or r * args.seconds > 30000000 for r in rates):
        p.error('bounded rate/count exceeded')
    password = sys.stdin.readline().rstrip('\n') if args.password_stdin else getpass.getpass('Remote sudo password: ')

    def remote(host, command, timeout=45):
        cp = SOCKETS[host]
        cmd = ['ssh', '-S', cp, '-o', 'BatchMode=yes', 'vpp-operator@' + HOSTS[host],
               'sudo -S -p "" sh -c ' + shlex.quote(command)]
        out = subprocess.run(cmd, input=password + '\n', capture_output=True,
                             text=True, timeout=timeout)
        if out.returncode:
            raise RuntimeError(host + ': ' + out.stderr[-1200:] + out.stdout[-1200:])
        return out.stdout

    def cli(command):
        out = remote('router', VPP + ' ' + shlex.quote(command))
        if command.startswith('show ') and re.search(r'unknown input', out, re.I):
            raise RuntimeError('VPP rejected ' + command + ': ' + out[:800])
        if not command.startswith('show ') and re.search(r'unknown input|error:|failed|invalid', out, re.I):
            raise RuntimeError('VPP rejected ' + command + ': ' + out[:800])
        return out

    def cli_tolerate_vpp_message(command):
        """Run a VPP command whose plugin may print a false failure message."""
        out = remote('router', VPP + ' ' + shlex.quote(command))
        if re.search(r'unknown input|error:', out, re.I):
            raise RuntimeError('VPP rejected ' + command + ': ' + out[:800])
        return out

    def save(data):
        args.output.write_text(json.dumps(data, indent=2) + '\n')

    def snapshot():
        return {
            'interfaces': cli('show interface'),
            'hardware': cli('show hardware-interfaces nic0-dpdk detail'),
            'runtime': cli('show runtime'),
            'errors': cli('show errors'),
        }

    def worker_samples(seconds):
        program = '''import json, os, pathlib, subprocess, tempfile, time
os.sched_setaffinity(0, {0})
pid = subprocess.check_output(['pidof', 'vpp'], text=True).split()[0]
tasks = pathlib.Path('/proc/' + pid + '/task')
tid = next(t.name for t in tasks.iterdir() if (t / 'comm').read_text().strip() == 'vpp_wk_0')
maps = pathlib.Path('/proc/' + pid + '/maps').read_text()
output = tempfile.TemporaryFile(mode='w+')
child = subprocess.Popen(['/tmp/vrouter-perf-cycle-sample', tid, str(SECONDS)], stdout=output, text=True)
telemetry = []
while child.poll() is None:
    telemetry.append({'monotonic_ns': time.monotonic_ns(),
        'frequency_khz': int(pathlib.Path('/sys/devices/system/cpu/cpufreq/policy4/cpuinfo_cur_freq').read_text()),
        'temperatures': {p.parent.name: p.read_text().strip() for p in pathlib.Path('/sys/class/thermal').glob('thermal_zone*/temp')}})
    time.sleep(0.2)
if child.returncode:
    raise RuntimeError('worker sampler failed')
output.seek(0)
data = json.load(output)
data['maps'] = maps
data['telemetry'] = telemetry
print(json.dumps(data))
'''.replace('SECONDS', str(seconds + 3))
        return json.loads(remote('router', 'python3 -c ' + shlex.quote(program), timeout=seconds + 20))

    def nat_packets():
        text = cli('show nat44 ei sessions detail')
        total = 0
        for block in re.split(r'(?=    i2o )', text):
            if re.search(r'i2o ' + re.escape(RX_IP) + r' proto udp port ' + str(PORT) + r'\b', block):
                m = re.search(r'total pkts (\d+)', block)
                if m:
                    total += int(m.group(1))
        return total

    def rx_status_samples(seconds):
        program = (BASE / 'benchmarks/vrouter_trex_rx_status_sampler.py').read_text()
        return json.loads(remote('router', 'python3 -c ' + shlex.quote(program) +
                                 ' --seconds ' + str(seconds + 3), timeout=seconds + 20))

    phase_script = (BASE / 'benchmarks/vrouter_trex_sequence_phase.py').read_text()
    trex_config = (BASE / 'benchmarks/vrouter_trex_mlx5.yaml').read_text().replace(
        'threads: [2, 3, 4, 5]', 'threads: [2]')
    result = {'started_at': time.time(), 'rates': rates, 'seconds': args.seconds,
              'modes': [], 'flows': args.flows, 'receiver': 'DPDK_MLX5_EXACT_FLOW'}
    pause_original = remote('linux', 'ethtool -a enp3s0f0')
    pause_values = {name: re.search(r'\b' + name + r':\s+(on|off)', pause_original)[1]
                    for name in ('Autonegotiate', 'RX', 'TX')}

    def prepare_trex():
        remote('linux', 'systemctl stop vrouter-path-trex.service vrouter-path-cleanup.timer 2>/dev/null || true; '
               'systemctl reset-failed vrouter-path-trex.service vrouter-path-cleanup.timer 2>/dev/null || true; '
               'systemctl daemon-reload')
        cleanup = ('systemctl stop vrouter-path-trex.service; '
                   'ethtool -A enp3s0f0 autoneg on rx on tx on')
        remote('linux', 'systemd-run --unit=vrouter-path-cleanup --on-active=20m /bin/sh -c ' +
               shlex.quote(cleanup))
        remote('linux',
               "cat > /run/vrouter-path-phase.py <<'PYEOF'\n" + phase_script +
               '\nPYEOF\ncat > /run/vrouter-path.yaml <<\'YAMLEOF\'\n' +
               trex_config + '\nYAMLEOF\n' +
               'ethtool -A enp3s0f0 autoneg off rx off tx off\n' +
               'systemd-run --unit=vrouter-path-trex --property=RuntimeMaxSec=1200 '
               '--property=WorkingDirectory=/var/tmp/vrouter-trex/v3.08 '
               '/var/tmp/vrouter-trex/v3.08/t-rex-64 -i --cfg /run/vrouter-path.yaml '
               '--no-scapy-server --no-watchdog --no-hw-flow-stat --software --no-ofed-check -c 1')
        time.sleep(3)

    def stop_trex():
        remote('linux', 'systemctl stop vrouter-path-trex.service vrouter-path-cleanup.timer || true', timeout=30)
        remote('linux', 'ethtool -A enp3s0f0 autoneg ' + pause_values['Autonegotiate'] +
               ' rx ' + pause_values['RX'] + ' tx ' + pause_values['TX'], timeout=30)

    def receiver_start(path, selector):
        remote('linux', 'systemctl stop vrouter-path-rx.service 2>/dev/null || true; '
               'systemctl reset-failed vrouter-path-rx.service 2>/dev/null || true; '
               'systemctl daemon-reload')
        remote('linux', 'rm -f ' + shlex.quote(str(path)) + ' ' + shlex.quote(str(path) + '.stop'))
        cmd = ('systemd-run --unit=vrouter-path-rx --property=RuntimeMaxSec=1200 '
               '/usr/sbin/ip netns exec vrouter-nat-rx taskset -c 4 '
               '/tmp/vrouter-dpdk-sequence-capture-all -l 4 -a 0000:b0:00.1 --no-huge -m 128 '
               '--file-prefix=vrouter-path-rx --no-telemetry -- '
               + shlex.quote(str(path)) + ' 1200 ' + RX_IP +
               ((' ' + selector) if selector is not None else ''))
        remote('linux', cmd)
        for _ in range(20):
            text = remote('linux', 'journalctl -u vrouter-path-rx --no-pager -n 8', timeout=20)
            if 'READY DPDK_MLX5' in text:
                return
            time.sleep(.5)
        raise RuntimeError('DPDK receiver did not become ready')

    def receiver_read(path):
        raw = remote('linux', 'test -s ' + shlex.quote(str(path)) + ' && cat ' + shlex.quote(str(path)))
        return json.loads(raw)

    def receiver_stop():
        remote('linux', 'systemctl stop vrouter-path-rx.service 2>/dev/null || true; '
               'systemctl reset-failed vrouter-path-rx.service 2>/dev/null || true; '
               'systemctl daemon-reload', timeout=30)

    def restart_baseline():
        active = remote('router', 'systemctl is-active vrouter-vpp.service || true').strip()
        if active == 'active':
            return
        remote('router', 'systemctl reset-failed vrouter-vpp.service; systemctl start vrouter-vpp.service', timeout=60)
        for _ in range(30):
            try:
                text = cli('show interface')
                if 'nic0-dpdk.100' in text and 'up' in text:
                    return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError('VPP did not return to baseline')

    def detach_production():
        """Remove deployed WAN hooks for the RX-only and pure-VLAN controls."""
        cli('set acl-plugin interface nic0-dpdk.100 input acl 2 del')
        cli('set acl-plugin interface nic0-dpdk.100 output acl 3 del')
        cli_tolerate_vpp_message(
            'set interface nat44 ei in nic0-dpdk.100 out nic0-dpdk.100 output-feature del')
        acl_state = cli('show acl-plugin interface')
        nat_state = cli('show nat44 ei interfaces')
        if re.search(r'input acl\(s\): 2|output acl\(s\): 3', acl_state):
            raise RuntimeError('production ACLs remain attached to nic0-dpdk.100')
        if 'nic0-dpdk.100' in nat_state:
            raise RuntimeError('production NAT remains attached to nic0-dpdk.100')

    def setup_mode(mode):
        if mode == 'forward':
            # Match the NAT egress topology, changing only ingress hooks and
            # the pre-translation destination address.
            detach_production()
            return RX_IP
        if mode == 'drop':
            detach_production()
            cli('ip route add 198.18.0.1/32 via drop')
            return '198.18.0.1'
        if mode == 'vlan':
            # Keep the production WAN VLAN intact; route to a temporary VLAN 11 L3 subinterface.
            detach_production()
            if 'nic0-dpdk.11' in cli('show interface'):
                cli('delete sub-interface nic0-dpdk.11')
            cli('create sub-interface nic0-dpdk 11 dot1q 11 exact-match')
            cli('set interface state nic0-dpdk.11 up')
            cli('set interface ip address nic0-dpdk.11 10.61.80.1/24')
            cli('set ip neighbor nic0-dpdk.11 10.61.80.2 02:00:00:00:10:04')
            return '10.61.80.2'
        if mode == 'nat':
            cli('nat44 ei add static mapping udp local ' + RX_IP + ' ' + str(PORT) +
                ' external 10.61.10.2 ' + str(PORT) + ' vrf 0')
            # A VPP restart clears LAN adjacency. Resolve it while the Linux
            # kernel still owns the receive port, before enabling DPDK isolate.
            warmup = cli('ping ' + RX_IP + ' repeat 3 source loop200')
            received = re.search(r'(\d+) received', warmup)
            if not received or int(received[1]) < 2:
                raise RuntimeError('NAT receiver adjacency did not warm up: ' + warmup)
            return '10.61.10.2'
        raise ValueError(mode)

    def restore_production():
        """Restore the deployed WAN ACL/NAT hooks after the pure VLAN run."""
        cli('set acl-plugin interface nic0-dpdk.100 input acl 2')
        cli('set acl-plugin interface nic0-dpdk.100 output acl 3')
        cli_tolerate_vpp_message(
            'set interface nat44 ei in nic0-dpdk.100 out nic0-dpdk.100 output-feature')
        acl_state = cli('show acl-plugin interface')
        nat_state = cli('show nat44 ei interfaces')
        if not re.search(r'input acl\(s\): 2', acl_state) or not re.search(
                r'output acl\(s\): 3', acl_state):
            raise RuntimeError('failed to restore production ACLs')
        if 'nic0-dpdk.100 output-feature in out' not in nat_state:
            raise RuntimeError('failed to restore production NAT')

    def run_mode(mode, index):
        dst_ip = setup_mode(mode)
        rx_path = Path('/tmp/vrouter-path-' + mode + '.json')
        if mode != 'drop':
            receiver_start(rx_path, '11' if mode == 'vlan' else None)
        prepare_trex()
        record = {'mode': mode, 'destination_ip': dst_ip, 'phases': []}
        result['modes'].append(record)
        for offset, pps in enumerate(rates, 1):
            count = pps * args.seconds
            run = args.run_base + index * 10000 + offset
            before = snapshot()
            before_rx = receiver_read(rx_path) if mode != 'drop' else None
            before_nat = nat_packets() if mode == 'nat' else None
            remote_cmd = ('/var/tmp/vrouter-trex/venv/bin/python /run/vrouter-path-phase.py '
                          '--trex /var/tmp/vrouter-trex/v3.08 --pps ' + str(pps) +
                          ' --count ' + str(count) + ' --run ' + str(run) +
                          ' --dst-ip ' + dst_ip + ' --flows ' + str(args.flows))
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                profile = pool.submit(worker_samples, args.seconds) if args.sample_worker else None
                rx_status = pool.submit(rx_status_samples, args.seconds) if args.sample_rx_status else None
                remote('router', 'python3 /tmp/vrouter-burst-port-counter.py start')
                sent = json.loads(remote('linux', remote_cmd, timeout=args.seconds + 30).strip().splitlines()[-1])
                counts = json.loads(remote('router', 'python3 /tmp/vrouter-burst-port-counter.py stop'))
                worker_profile = profile.result() if profile else None
                status_profile = rx_status.result() if rx_status else None
            time.sleep(.5)
            after = snapshot()
            after_rx = receiver_read(rx_path) if mode != 'drop' else None
            after_nat = nat_packets() if mode == 'nat' else None
            phase = {'run': run, 'pps': pps, 'expected': count, 'sender': sent,
                     'before': before, 'after': after,
                     'before_receiver': before_rx, 'after_receiver': after_rx,
                     'before_nat_packets': before_nat, 'after_nat_packets': after_nat}
            phase['burst_observe'] = counts
            if worker_profile is not None:
                phase['worker_samples'] = worker_profile
                phase['duration_s'] = args.seconds
                phase['mode'] = mode
            if status_profile is not None:
                phase['rx_status_samples'] = status_profile
            record['phases'].append(phase)
            save(result)
        stop_trex()
        if mode != 'drop':
            receiver_stop()
            record['receiver_final'] = receiver_read(rx_path)
        if mode == 'drop':
            cli('ip route del 198.18.0.1/32 via drop')
            restore_production()
        elif mode == 'forward':
            restore_production()
        elif mode == 'vlan':
            cli('set interface ip address del nic0-dpdk.11 10.61.80.1/24')
            cli('delete sub-interface nic0-dpdk.11')
            restore_production()
        else:
            cli('nat44 ei add static mapping udp local ' + RX_IP + ' ' + str(PORT) +
                ' external 10.61.10.2 ' + str(PORT) + ' vrf 0 del')
        save(result)

    try:
        restart_baseline()
        for index, mode in enumerate(modes):
            run_mode(mode, index)
    finally:
        try:
            remote('linux', 'systemctl stop vrouter-path-rx.service vrouter-path-trex.service vrouter-path-cleanup.timer || true', timeout=30)
            remote('linux', 'ethtool -A enp3s0f0 autoneg ' + pause_values['Autonegotiate'] +
                   ' rx ' + pause_values['RX'] + ' tx ' + pause_values['TX'], timeout=30)
        finally:
            restart_baseline()
            result['finished_at'] = time.time()
            save(result)
    print(args.output)


if __name__ == '__main__':
    main()
