#!/usr/bin/env python3
"""Run bounded TRex NAT bursts to a Mac or isolated Linux receiver.

Requires authenticated SSH control sockets, remote sudo password entered at the
prompt, and a locally compiled vrouter_trex_sequence_sink.c. No credentials are saved.
"""
import concurrent.futures
import argparse
import getpass
import ipaddress
import json
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time

BASE = Path(__file__).resolve().parent.parent
OUT = BASE / 'artifacts/vrouter/trex-sequence-nat-20261030.json'
HOSTS = {'router': '10.61.20.1', 'linux': '10.61.20.134'}
SOCKETS = {'router': '/tmp/vrouter-bench-router.sock', 'linux': '/tmp/vrouter-bench-linux.sock'}
PORT = 45996
VPP = '/usr/local/bin/vppctl'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-json', type=Path)
    parser.add_argument('--receiver-ip', default='10.61.20.100')
    parser.add_argument('--linux-rx-namespace', help='Capture JSON resides on Linux in this receiver namespace')
    parser.add_argument('--linux-dpdk', action='store_true', help='Use the isolated mlx5 DPDK sequence receiver')
    parser.add_argument('--rates', default='1000,100000,500000,750000,800000,850000,900000,1000000,1500000,2000000')
    parser.add_argument('--run-base', type=int, default=203000)
    parser.add_argument('--output', type=Path, default=OUT)
    parser.add_argument('--seconds', type=int, default=3)
    parser.add_argument('--flows', type=int, default=1,
                        help='Number of concurrent source-port flows (1..20000)')
    parser.add_argument('--stop-capture', action='store_true')
    parser.add_argument('--sample-hardware', action='store_true')
    parser.add_argument('--sample-rx-status', action='store_true')
    parser.add_argument('--sample-worker', action='store_true')
    args = parser.parse_args()
    receiver_ip = str(ipaddress.IPv4Address(args.receiver_ip))
    if args.linux_rx_namespace and (not args.capture_json or not re.fullmatch(r'[A-Za-z0-9_-]+', args.linux_rx_namespace)):
        parser.error('Linux namespace requires capture JSON and a valid namespace name')
    if args.linux_dpdk and not args.linux_rx_namespace:
        parser.error('DPDK receiver requires Linux namespace mode')
    rates = [int(rate) for rate in args.rates.split(',')]
    if any(not 1000 <= rate <= 3700000 for rate in rates):
        parser.error('rate outside test bounds')
    if not 1 <= args.seconds <= 30 or any(rate * args.seconds > 60000000 for rate in rates):
        parser.error('duration/count outside bounded test limits')
    if not 1 <= args.flows <= 20000:
        parser.error('flows outside test bounds')
    if args.capture_json and not args.linux_rx_namespace:
        json.loads(args.capture_json.read_text())
    password = getpass.getpass('Remote sudo password: ')
    result = {'started_at': time.time(), 'phases': [],
              'topology': ('mlx5 WAN -> VROUTER static NAT -> isolated Linux mlx5 LAN' if args.linux_rx_namespace else
                           'mlx5 10G -> WAN VLAN100 -> static NAT -> Mac en5 2.5G'),
              'receiver_ip': receiver_ip, 'receiver_namespace': args.linux_rx_namespace,
              'frame_bytes_with_fcs': 64, 'single_tx_worker': True,
              'single_flow': args.flows == 1, 'flow_count': args.flows,
              'pause_sender': 'off',
              'receiver_mode': ('DPDK_MLX5' if args.linux_dpdk else 'AF_PACKET_TPACKET_V3' if args.linux_rx_namespace else
                                ('BPF' if args.capture_json else 'UDP socket'))}

    def remote(host, command, root=True, timeout=45):
        argv = ['ssh', '-S', SOCKETS[host], '-o', 'BatchMode=yes',
                'vpp-operator@' + HOSTS[host]]
        argv.append(('sudo -S -p "" sh -c ' if root else 'sh -c ') + shlex.quote(command))
        p = subprocess.run(argv, input=(password + '\n') if root else None,
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode:
            raise RuntimeError(f'{host}: {command}: {p.stderr[-1500:]} {p.stdout[-1500:]}')
        return p.stdout

    def capture_stats():
        if args.linux_rx_namespace:
            program = ('import json,pathlib,time; p=pathlib.Path(' + repr(str(args.capture_json)) + '); '
                       'assert time.time()-p.stat().st_mtime<5, "Receiver stopped publishing"; '
                       'print(p.read_text())')
            data = json.loads(remote('linux', 'python3 -c ' + shlex.quote(program)))
            expected_method = 'DPDK_MLX5' if args.linux_dpdk else 'AF_PACKET_TPACKET_V3'
            if data.get('method') != expected_method:
                raise RuntimeError('Receiver method does not match requested mode')
            return data
        if time.time() - args.capture_json.stat().st_mtime > 5:
            raise RuntimeError('BPF receiver stopped publishing statistics')
        return json.loads(args.capture_json.read_text())

    def cli(command):
        output = remote('router', VPP + ' ' + shlex.quote(command))
        # `show errors` legitimately contains reasons such as "Failed during
        # decryption". Only CLI parse failures invalidate read-only commands.
        pattern = r'unknown input' if command.startswith('show ') else r'unknown input|error:|failed|invalid'
        if re.search(pattern, output, re.I):
            raise RuntimeError('VPP rejected ' + command + ': ' + output[:500])
        return output

    def local_stats():
        if args.linux_rx_namespace:
            prefix = 'ip netns exec ' + shlex.quote(args.linux_rx_namespace) + ' '
            return {'linux_receiver': remote('linux', prefix + 'ip -s -j link show dev enp3s0f1'),
                    'hardware': remote('linux', prefix + 'ethtool -S enp3s0f1')}
        return {name: subprocess.check_output(cmd, text=True) for name, cmd in {
            'en5': ['netstat', '-ibnI', 'en5'],
            'udp': ['netstat', '-s', '-p', 'udp']}.items()}

    def router_stats():
        sessions = cli('show nat44 ei sessions detail')
        selected = []
        for block in re.split(r'(?=    i2o )', sessions):
            if re.search(r'i2o ' + re.escape(receiver_ip) + r' proto udp port ' + str(PORT) + r'\b', block):
                match = re.search(r'total pkts (\d+), total bytes (\d+)', block)
                selected.append({'packets': int(match[1]) if match else None,
                                 'bytes': int(match[2]) if match else None,
                                 'raw': block[:700]})
        return {'time': time.time(), 'test_sessions': selected,
                'binaries': remote('router', 'sha256sum /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1 /usr/local/lib/vpp-vrouter/plugins/dpdk_plugin.so'),
                'interfaces': cli('show interface'),
                'hardware_wan': cli('show hardware-interfaces nic0-dpdk detail'),
                'hardware_lan': cli('show hardware-interfaces nic1-dpdk detail'),
                'buffers': cli('show buffers'),
                'errors': cli('show errors'), 'runtime': cli('show runtime')}

    def linux_stats():
        return remote('linux', 'ethtool -S enp3s0f0; ethtool -a enp3s0f0')

    def hardware_samples(seconds):
        program = (BASE / 'benchmarks/vrouter_trex_hardware_sampler.py').read_text()
        command = 'python3 -c ' + shlex.quote(program) + ' --seconds ' + str(seconds + 5)
        return json.loads(remote('router', command, timeout=seconds + 20))

    def rx_status_samples(seconds):
        program = (BASE / 'benchmarks/vrouter_trex_rx_status_sampler.py').read_text()
        command = 'python3 -c ' + shlex.quote(program) + ' --seconds ' + str(seconds + 5)
        return json.loads(remote('router', command, timeout=seconds + 20))

    def worker_samples(seconds):
        program = '''import json, pathlib, subprocess, time
pid = subprocess.check_output(['pidof', 'vpp'], text=True).split()[0]
tasks = pathlib.Path('/proc/' + pid + '/task')
tid = next(t.name for t in tasks.iterdir() if (t / 'comm').read_text().strip() == 'vpp_wk_0')
started = time.time()
data = json.loads(subprocess.check_output(['/tmp/vrouter-perf-ip-sample', tid, SECONDS], text=True))
data['started_at'] = started
data['maps'] = pathlib.Path('/proc/' + pid + '/maps').read_text()
print(json.dumps(data))
'''.replace('SECONDS', repr(str(seconds + 5)))
        return json.loads(remote('router', 'python3 -c ' + shlex.quote(program), timeout=seconds + 20))

    def save():
        args.output.write_text(json.dumps(result, indent=2) + '\n')

    owned_mapping = False
    sender_prepared = False
    sink = None
    guard = None
    try:
        if args.capture_json and not args.linux_rx_namespace:
            # Keep UDP port open so ICMP port-unreachable replies do not inflate
            # NAT's bidirectional session counter. BPF remains the receiver.
            guard = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            guard.bind((receiver_ip, PORT))
        # A VPP restart clears the receiver adjacency. Resolve it before counting
        # test packets so an initial ARP/glean drop is not a throughput result.
        result['receiver_warmup'] = cli('ping ' + receiver_ip + ' repeat 3 source loop200')
        received = re.search(r'(\d+) received', result['receiver_warmup'])
        if not received or int(received[1]) < 2:
            raise RuntimeError('Receiver adjacency did not warm up')
        result['baseline'] = {'router': router_stats(), 'linux': linux_stats(),
                              ('receiver' if args.linux_rx_namespace else 'mac'): local_stats(),
                              'startup_sha': remote('router', 'sha256sum /etc/vpp/startup.conf')}
        pause = remote('linux', 'ethtool -a enp3s0f0')
        result['pause_before'] = pause
        rx = re.search(r'RX:\s+(on|off)', pause)[1]
        tx = re.search(r'TX:\s+(on|off)', pause)[1]
        autoneg = re.search(r'Autonegotiate:\s+(on|off)', pause)[1]
        if re.search(r'\b' + str(PORT) + r'\b', cli('show nat44 ei static mappings')):
            raise RuntimeError('test mapping port already in use')
        if remote('linux', 'pgrep -a _t-rex-64 || true').strip():
            raise RuntimeError('TRex already running')
        cleanup = (f'{VPP} nat44 ei add static mapping udp local {receiver_ip} {PORT} '
                   f'external 10.61.10.2 {PORT} vrf 0 del\n')
        remote('router', "cat > /run/vrouter-sequence-cleanup.sh <<'EOF'\n#!/bin/sh\n" + cleanup + 'EOF\n' +
               'chmod 700 /run/vrouter-sequence-cleanup.sh\n' +
               'systemd-run --unit=vrouter-sequence-cleanup --on-active=15m /bin/sh /run/vrouter-sequence-cleanup.sh')
        owned_mapping = True
        cli(f'nat44 ei add static mapping udp local {receiver_ip} {PORT} external 10.61.10.2 {PORT} vrf 0')
        script = (BASE / 'benchmarks/vrouter_trex_sequence_phase.py').read_text()
        config = (BASE / 'benchmarks/vrouter_trex_mlx5.yaml').read_text().replace('threads: [2, 3, 4, 5]', 'threads: [2]')
        sender_prepared = True
        sender_cleanup = ('systemctl stop vrouter-sequence-trex.service\n' +
                          f'ethtool -A enp3s0f0 autoneg {autoneg} rx {rx} tx {tx}\n')
        remote('linux', "cat > /run/vrouter-sequence-cleanup.sh <<'EOF'\n#!/bin/sh\n" + sender_cleanup + 'EOF\n' +
               'chmod 700 /run/vrouter-sequence-cleanup.sh\n' +
               'systemd-run --unit=vrouter-sequence-cleanup --on-active=15m /bin/sh /run/vrouter-sequence-cleanup.sh\n' +
               "cat > /run/vrouter-sequence-phase.py <<'PYEOF'\n" + script + '\nPYEOF\n' +
               "cat > /run/vrouter-sequence.yaml <<'YAMLEOF'\n" + config + '\nYAMLEOF\n' +
               'ethtool -A enp3s0f0 autoneg off rx off tx off\n' +
               'systemd-run --unit=vrouter-sequence-trex --property=RuntimeMaxSec=840 ' +
               '--property=WorkingDirectory=/var/tmp/vrouter-trex/v3.08 ' +
               '/var/tmp/vrouter-trex/v3.08/t-rex-64 -i --cfg /run/vrouter-sequence.yaml ' +
               '--no-scapy-server --no-watchdog --no-hw-flow-stat --software --no-ofed-check -c 1')
        time.sleep(3)
        result['trex_startup'] = remote('linux', 'journalctl -u vrouter-sequence-trex --no-pager -n 45')
        save()
        for index, pps in enumerate(rates, 1):
            seconds = 1 if pps == 1000 else args.seconds
            count = pps * seconds
            batch = args.run_base + index
            phase = {'run': batch, 'pps': pps, 'expected_packets': count, 'duration_s': seconds}
            with concurrent.futures.ThreadPoolExecutor(3) as pool:
                frouter = pool.submit(router_stats)
                flinux = pool.submit(linux_stats)
                phase['before_receiver' if args.linux_rx_namespace else 'before_mac'] = local_stats()
                phase['before_router'] = frouter.result()
                phase['before_linux'] = flinux.result()
            if args.capture_json:
                phase['before_capture'] = capture_stats()
            else:
                sink = subprocess.Popen(['/tmp/vrouter-sequence-sink', receiver_ip, str(PORT),
                                         str(batch), str(count), str(seconds + 12)], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
                phase['sink_ready'] = json.loads(sink.stdout.readline())
            with concurrent.futures.ThreadPoolExecutor(3) as pool:
                sampler = pool.submit(hardware_samples, seconds) if args.sample_hardware else None
                rx_sampler = pool.submit(rx_status_samples, seconds) if args.sample_rx_status else None
                worker_sampler = pool.submit(worker_samples, seconds) if args.sample_worker else None
                sent = remote('linux', '/var/tmp/vrouter-trex/venv/bin/python /run/vrouter-sequence-phase.py ' +
                              f'--trex /var/tmp/vrouter-trex/v3.08 --pps {pps} --count {count} '
                              f'--run {batch} --flows {args.flows}', timeout=seconds + 25)
                if sampler is not None:
                    phase['hardware_samples'] = sampler.result()
                if rx_sampler is not None:
                    phase['rx_status_samples'] = rx_sampler.result()
                if worker_sampler is not None:
                    phase['worker_samples'] = worker_sampler.result()
            phase['sender'] = json.loads(sent.strip().splitlines()[-1])
            if args.capture_json:
                time.sleep(3)
                phase['after_capture'] = capture_stats()
                matches = [b for b in phase['after_capture']['batches'] if b['run'] == batch]
                phase['receiver'] = matches[0] if matches else dict(unique=0, missing=count)
            else:
                rest, err = sink.communicate(timeout=16)
                if sink.returncode:
                    raise RuntimeError('receiver failed: ' + err)
                phase['receiver'] = json.loads(rest.strip().splitlines()[-1])
                sink = None
            time.sleep(0.3)
            with concurrent.futures.ThreadPoolExecutor(3) as pool:
                frouter = pool.submit(router_stats)
                flinux = pool.submit(linux_stats)
                phase['after_receiver' if args.linux_rx_namespace else 'after_mac'] = local_stats()
                phase['after_router'] = frouter.result()
                phase['after_linux'] = flinux.result()
            old = sum(s['packets'] or 0 for s in phase['before_router']['test_sessions'])
            new = sum(s['packets'] or 0 for s in phase['after_router']['test_sessions'])
            phase['nat_session_packets_delta'] = new - old
            result['phases'].append(phase)
            save()
            print(json.dumps({'pps': pps, 'count': count, 'nat_packets': new - old,
                              'receiver': phase['receiver'],
                              'sender_elapsed_s': phase['sender']['elapsed_s'],
                              'queue_full': phase['sender']['stats']['global'].get('queue_full')}), flush=True)
            if index == 1 and pps <= 100000 and phase['receiver']['unique'] != count:
                raise RuntimeError('low-rate path or sequence verification failed')
    except (Exception, KeyboardInterrupt) as exc:
        result['error'] = str(exc)
        print('ERROR: ' + str(exc), flush=True)
    finally:
        if sink is not None:
            sink.terminate()
            sink.communicate(timeout=3)
        result['cleanup'] = {}
        if sender_prepared:
            try:
                remote('linux', '/bin/sh /run/vrouter-sequence-cleanup.sh\n'
                       'systemctl stop vrouter-sequence-cleanup.timer\n')
                result['cleanup']['linux'] = remote('linux', 'ethtool -a enp3s0f0; '
                       'pgrep -a _t-rex-64 || true; ip -br addr show enp3s0f0; '
                       'ping -c 2 -W 1 -I enp3s0f0 10.61.10.1')
            except Exception as exc:
                result['cleanup']['linux_error'] = str(exc)
        if owned_mapping:
            try:
                remote('router', '/bin/sh /run/vrouter-sequence-cleanup.sh\n'
                       'systemctl stop vrouter-sequence-cleanup.timer\n')
                result['cleanup']['router_mappings'] = cli('show nat44 ei static mappings')
                result['cleanup']['startup_sha'] = remote('router', 'sha256sum /etc/vpp/startup.conf')
                result['cleanup']['router_final'] = router_stats()
                if re.search(r'\b' + str(PORT) + r'\b', result['cleanup']['router_mappings']):
                    raise RuntimeError('temporary mapping still present')
            except Exception as exc:
                result['cleanup']['router_error'] = str(exc)
        result['ended_at'] = time.time()
        if guard is not None:
            guard.close()
        if args.stop_capture and args.capture_json:
            if args.linux_rx_namespace:
                remote('linux', 'touch ' + shlex.quote(str(args.capture_json) + '.stop'))
            else:
                Path(str(args.capture_json) + '.stop').touch()
        save()
        print('RESULT: ' + str(args.output), flush=True)


if __name__ == '__main__':
    main()
