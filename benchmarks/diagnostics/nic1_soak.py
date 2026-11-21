"""Bounded integrity/latency workload for the isolated nic1 harness."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import struct
import subprocess
import time


def latency_add(stats, value):
    stats['samples'] += 1
    stats['max_ms'] = max(stats['max_ms'], value)
    stats['histogram'][int(value * 10)] += 1


def latency_report(stats):
    result = {k: v for k, v in stats.items() if k != 'histogram'}
    for label, fraction in (('p50_ms_upper', .5), ('p99_ms_upper', .99)):
        total = 0
        result[label] = None
        for bucket, count in sorted(stats['histogram'].items()):
            total += count
            if total >= stats['samples'] * fraction:
                result[label] = (bucket + 1) / 10
                break
    return result


def probe_udp(sources, target):
    for index, source in enumerate(sources):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((source, 46100 + index))
            sock.connect((target, 46090))
            sock.settimeout(1)
            packet = b'VRS-PROBE-' + os.urandom(1400)
            for _ in range(3):
                sock.send(packet)
                try:
                    if sock.recv(65535) == packet:
                        break
                except socket.timeout:
                    pass
            else:
                raise RuntimeError(f'UDP echo unavailable or corrupt for source {source}')


def checksum(packet):
    if len(packet) % 2:
        packet += b'\0'
    value = sum(struct.unpack(f'!{len(packet) // 2}H', packet))
    value = (value & 65535) + (value >> 16)
    value = (value & 65535) + (value >> 16)
    return ~value & 65535


def datagram_integrity(sources, seconds, target, output, transport='udp', progress=None):
    """Compare every echo with its sent bytes, sequence and timestamp."""
    targets = [target] * len(sources) if isinstance(target, str) else target
    if len(targets) != len(sources):
        raise ValueError('Each source needs one target')
    selector = selectors.DefaultSelector()
    flows = []
    start = time.monotonic()
    deadline = start + seconds
    interval = .01 if transport == 'icmp' else .005
    last_progress = start - 30
    sizes = (64, 65, 127, 128, 511, 512, 1400, 1472)
    try:
        for index, source in enumerate(sources):
            sock = socket.socket(socket.AF_INET,
                socket.SOCK_RAW if transport == 'icmp' else socket.SOCK_DGRAM,
                socket.IPPROTO_ICMP if transport == 'icmp' else 0)
            sock.bind((source, 0 if transport == 'icmp' else 46100 + index))
            sock.connect((targets[index], 0 if transport == 'icmp' else 46090))
            if transport == 'icmp':
                # Linux raw ICMP workloads run inside the test namespace.
                sock.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_MTU_DISCOVER, DO
            sock.setblocking(False)
            flow = dict(source=source, sent=0, received=0, lost=0,
                        corrupt=0, unexpected=0, send_errors=0,
                        samples=0, max_ms=0.0, histogram=Counter(),
                        loss_examples=[],
                        pending={}, next_send=start, socket=sock, identifier=46100 + index,
                        target=targets[index], payload_size=(56, 512, 1400, 1472)[index % 4])
            flows.append(flow)
            selector.register(sock, selectors.EVENT_READ, flow)
        sequence = 0
        while time.monotonic() < deadline + 2.5:
            now = time.monotonic()
            # Stop sending at deadline, then drain replies for 2.5 seconds.
            for flow in flows:
                if now < deadline and now >= flow['next_send']:
                    burst = min(16, 1 + int((now - flow['next_send']) / interval))
                    for _ in range(burst):
                        sequence += 1
                        size = flow['payload_size'] if transport == 'icmp' else sizes[sequence % len(sizes)]
                        sent_ns = time.monotonic_ns()
                        header = struct.pack('!8sQQ', b'VRSDMA01', sequence, sent_ns)
                        packet = header + hashlib.shake_256(header).digest(size - len(header))
                        wire_packet = packet
                        if transport == 'icmp':
                            icmp = struct.pack('!BBHHH', 8, 0, 0, flow['identifier'], sequence & 65535) + packet
                            wire_packet = icmp[:2] + struct.pack('!H', checksum(icmp)) + icmp[4:]
                        try:
                            flow['socket'].send(wire_packet)
                        except OSError:
                            flow['send_errors'] += 1
                            continue
                        flow['pending'][sequence] = (sent_ns, packet)
                        flow['sent'] += 1
                    flow['next_send'] = max(flow['next_send'] + burst * interval, now)
                expired = [seq for seq, (sent, _) in flow['pending'].items()
                           if time.monotonic_ns() - sent > 2_000_000_000]
                for seq in expired:
                    sent_ns, packet = flow['pending'].pop(seq)
                    if len(flow['loss_examples']) < 8:
                        flow['loss_examples'].append(dict(sequence=seq,
                            elapsed_seconds=now - start, payload_bytes=len(packet),
                            timeout_ms=(time.monotonic_ns() - sent_ns) / 1e6))
                    flow['lost'] += 1
            for key, _ in selector.select(.001):
                flow = key.data
                while True:
                    try:
                        packet = key.fileobj.recv(65535)
                    except BlockingIOError:
                        break
                    except OSError:
                        flow['unexpected'] += 1
                        break
                    received_ns = time.monotonic_ns()
                    if transport == 'icmp':
                        if len(packet) < 28 or packet[0] >> 4 != 4:
                            flow['corrupt'] += 1
                            continue
                        icmp = packet[(packet[0] & 15) * 4:]
                        if len(icmp) < 8 or icmp[0] != 0 or struct.unpack_from('!H', icmp, 4)[0] != flow['identifier']:
                            continue  # Unrelated ICMP is not part of this flow.
                        if checksum(icmp):
                            flow['corrupt'] += 1
                            continue
                        packet = icmp[8:]
                    if len(packet) < 24 or packet[:8] != b'VRSDMA01':
                        flow['corrupt'] += 1
                        continue
                    sequence_received = struct.unpack_from('!Q', packet, 8)[0]
                    expected = flow['pending'].pop(sequence_received, None)
                    if expected is None:
                        flow['unexpected'] += 1
                    elif packet != expected[1]:
                        flow['corrupt'] += 1
                    else:
                        flow['received'] += 1
                        latency_add(flow, (received_ns - expected[0]) / 1e6)
            if progress and now - last_progress >= 30:
                summary = dict(elapsed_seconds=now - start,
                    flows=[latency_report({k: v for k, v in f.items()
                        if k not in ('socket', 'pending', 'next_send')}) for f in flows])
                temporary = Path(str(progress) + '.tmp')
                temporary.write_text(json.dumps(summary))
                temporary.replace(progress)
                last_progress = now
        output['flows'] = [latency_report({k: v for k, v in flow.items()
                           if k not in ('socket', 'pending', 'next_send')}) for flow in flows]
        output['duration_seconds'] = time.monotonic() - start
        output['transport'] = transport
        output['passed'] = all(flow['sent'] >= seconds / interval * .5 and
                               not any(flow[k] for k in ('lost', 'corrupt', 'unexpected', 'send_errors'))
                               and flow['sent'] == flow['received']
                               and flow['max_ms'] < 100 for flow in flows)
    except Exception as exc:
        output.update(passed=False, error=str(exc))
    finally:
        for flow in flows:
            flow['socket'].close()
        selector.close()


def run_soak(cli, run, logdir, seconds, mappings, udp=False, vpp_pid=None, target='10.61.20.134'):
    sources = [f'10.252.12.{index + 2}' for index in range(4)]
    processes = []
    capture = None
    udp_result = {}
    started = time.monotonic()
    kernel_start = int(time.time())

    try:
        for index, (source, external) in enumerate(zip(sources, mappings)):
            if index:
                run('ip', '-n', 'vrouter-smoke-lan', 'address', 'add', source + '/24', 'dev', 'mgmt0')
            cli(f'set interface ip address nic1-dpdk {external}/24')
            cli(f'nat44 ei add static mapping local {source} external {external}')
            run('ip', 'netns', 'exec', 'vrouter-smoke-lan', 'ping', '-I', source,
                '-c', '3', '-W', '2', target)
        cli('clear trace')
        cli('clear errors')
        if udp:
            run('ip', 'netns', 'exec', 'vrouter-smoke-lan', 'python3',
                str(Path(__file__).resolve()), '--probe', target)
        baseline = cli('show hardware-interfaces nic1-dpdk')
        (logdir / 'soak-hardware-before.txt').write_text(baseline)
        rx_ring = re.search(r'rx: [^\n]*desc (\d+)', baseline)
        tx_ring = re.search(r'tx: [^\n]*desc (\d+)', baseline)
        if not rx_ring or not tx_ring:
            raise RuntimeError('Cannot establish hardware descriptor ring sizes')
        rx_descriptors, tx_descriptors = int(rx_ring[1]), int(tx_ring[1])
        started = time.monotonic()
        if udp:
            with (logdir / 'udp-capture.jsonl').open('w') as log:
                capture = subprocess.Popen(['ip', 'netns', 'exec', 'vrouter-smoke-lan',
                    'taskset', '-c', '0', 'python3',
                    str(Path(__file__).with_name('udp-capture.py')), '--peer', target,
                    '--seconds', str(seconds + 4)], stdout=log, stderr=subprocess.STDOUT)
            (logdir / 'namespace-snmp-before.txt').write_text(
                run('ip', 'netns', 'exec', 'vrouter-smoke-lan', 'cat', '/proc/net/snmp'))
        for transport in (('icmp', 'udp') if udp else ('icmp',)):
            with (logdir / f'{transport}-result.json').open('w') as log:
                verifier = subprocess.Popen(['ip', 'netns', 'exec', 'vrouter-smoke-lan',
                    'python3', str(Path(__file__).resolve()), transport, str(seconds), target,
                    str(logdir / f'{transport}-progress.json')], stdout=log, stderr=subprocess.STDOUT)
            processes.append(verifier)
        while time.monotonic() - started < seconds:
            if any(process.poll() is not None for process in processes):
                raise RuntimeError('A soak workload exited before the deadline')
            if capture is not None and capture.poll() is not None:
                raise RuntimeError('The diagnostic capture exited before the deadline')
            snapshot = dict(elapsed_seconds=round(time.monotonic() - started, 1))
            for transport in ('icmp', 'udp'):
                progress = logdir / f'{transport}-progress.json'
                if progress.exists():
                    snapshot[transport] = json.loads(progress.read_text())
            if vpp_pid:
                status = Path(f'/proc/{vpp_pid}/status').read_text()
                snapshot['vpp_memory_kib'] = dict((name, int(value)) for name, value in
                    re.findall(r'^(VmRSS|VmSize|VmData):\s+(\d+) kB', status, re.M))
            with (logdir / 'soak-progress.jsonl').open('a') as log:
                log.write(json.dumps(snapshot) + '\n')
            cli('show interface')
            cli('show errors')
            if Path('/sys/bus/pci/devices/0000:01:00.0/driver').resolve().name != 'r8125':
                raise RuntimeError('Production driver changed')
            time.sleep(min(30, max(0, seconds - (time.monotonic() - started))))
        for process in processes:
            process.wait(timeout=8)
        icmp_result = json.loads((logdir / 'icmp-result.json').read_text())
        if udp:
            udp_result = json.loads((logdir / 'udp-result.json').read_text())
            if capture.wait(timeout=8):
                raise RuntimeError('The diagnostic capture failed')
            (logdir / 'namespace-snmp-after.txt').write_text(
                run('ip', 'netns', 'exec', 'vrouter-smoke-lan', 'cat', '/proc/net/snmp'))
        kernel = run('journalctl', '-k', '--since', f'@{kernel_start}', '--no-pager')
        (logdir / 'soak-kernel.log').write_text(kernel)
        kernel_fault = bool(re.search(r'BUG:|Oops:|Call Trace:|Out of memory|NETDEV WATCHDOG|SError|AER:.*(?:fatal|error)', kernel, re.I))
        result = dict(duration_seconds=time.monotonic() - started,
                      mode='single-main-thread, four RX queues, one TX queue',
                      mappings=list(zip(sources, mappings)),
                      icmp=icmp_result, udp=udp_result,
                      kernel_fault=kernel_fault)
        progress = [json.loads(line) for line in (logdir / 'soak-progress.jsonl').read_text().splitlines()]
        rss = [sample['vpp_memory_kib']['VmRSS'] for sample in progress if 'vpp_memory_kib' in sample]
        result['vpp_rss_kib'] = dict(first=rss[0], last=rss[-1], minimum=min(rss), maximum=max(rss)) if rss else None
        result['icmp_rx_ring_wraps_lower_bound_by_queue'] = [
            s['received'] // rx_descriptors for s in icmp_result.get('flows', [])]
        result['rx_ring_descriptors'] = rx_descriptors
        result['tx_ring_descriptors'] = tx_descriptors
        result['ring_wrap_method'] = 'successful ICMP replies / reported RX ring size, fixed RSS mapping'
        result['passed'] = (not kernel_fault and icmp_result.get('passed', False)
            and (not udp or udp_result.get('passed', False)))
        (logdir / 'soak-result.json').write_text(json.dumps(result, indent=2) + '\n')
        cli('show hardware-interfaces nic1-dpdk')
        cli('show errors')
        return result
    finally:
        if capture is not None:
            processes.append(capture)
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


if __name__ == '__main__':
    import sys
    result = {}
    sources = [f'10.252.12.{i}' for i in range(2, 6)]
    if sys.argv[1] == '--probe':
        probe_udp(sources, sys.argv[2])
        print('UDP echo ready for all four sources')
        sys.exit(0)
    datagram_integrity(sources, int(sys.argv[2]), sys.argv[3], result,
                       transport=sys.argv[1], progress=Path(sys.argv[4]))
    print(json.dumps(result), flush=True)
    sys.exit(0 if result.get('passed') else 1)
