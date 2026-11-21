#!/usr/bin/env python3
"""Differential ACL tests in private VPP/PG instances; no production interfaces."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=20)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def packet(proto=17, flags=2, dport=45996, sport=40000, src='203.0.113.10',
           dst='10.241.0.2', fragment=0, ip6=False):
    transport = (struct.pack('!HHHH', sport, dport, 26, 0) if proto == 17 else
                 struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 80, flags, 8192, 0, 0))
    payload = transport + b'x' * 18
    if ip6:
        ip = struct.pack('!IHBB16s16s', 6 << 28, len(payload), proto, 64,
                         ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
        ethertype = 0x86dd
    else:
        ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(payload), 1, fragment,
                         64, proto, 0, ipaddress.ip_address(src).packed,
                         ipaddress.ip_address(dst).packed)
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
        ethertype = 0x0800
    # Both PG ports use this destination MAC; source is distinct.
    return (bytes.fromhex('000400050006020000000001') +
            struct.pack('!H', ethertype) + ip + payload).ljust(60, b'\0')


def pcap(path, packets):
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for data in packets:
            out.write(struct.pack('<IIII', 0, 0, len(data), len(data)) + data)


def error_count(text, reason):
    return sum(int(m[1]) for m in re.finditer(
        r'^\s*(\d+)\s+.*?\b' + re.escape(reason) + r'\s+(?:error|info)\s*$', text, re.M))


def exercise(plugin, benchmark_packets=0):
    process = None
    with tempfile.TemporaryDirectory(prefix='acl-cache-', dir='/run') as directory:
        root = Path(directory)
        plugins = root / 'plugins'
        plugins.mkdir()
        (plugins / 'acl_plugin.so').symlink_to(plugin)
        config = root / 'startup.conf'
        config.write_text(f'''unix {{ nodaemon runtime-dir {root}/run cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock size 16M page-size 4k }}
cpu {{ main-core 6 }}
memory {{ main-heap-size 256M main-heap-page-size 4k }}
buffers {{ buffers-per-numa 4096 page-size 4k }}
plugins {{ path {plugins}
plugin default {{ disable }}
plugin acl_plugin.so {{ enable }}
}}
''')
        def cli(command):
            text = run('vppctl', '-s', str(root / 'cli.sock'), command)
            if not command.startswith('show ') and re.search(r'unknown input|error:|failed|invalid', text, re.I):
                raise RuntimeError(command + ': ' + text)
            return text

        results = {}
        try:
            with (root / 'vpp.log').open('w') as log:
                process = subprocess.Popen(['/usr/local/lib/vpp-vrouter/bin/vpp', '-c', str(config)],
                                           stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((root / 'vpp.log').read_text())
                if (root / 'cli.sock').exists():
                    break
                time.sleep(.1)
            for idx in (0, 1):
                cli(f'create packet-generator interface pg{idx}')
                cli(f'set interface state pg{idx} up')
                cli(f'set interface mac address pg{idx} 00:04:00:05:00:06')
            cli('set interface ip address pg0 10.240.0.1/24')
            cli('set interface ip address pg1 10.241.0.1/24')
            cli('set interface ip address pg0 2001:db8:10::1/64')
            cli('set interface ip address pg1 2001:db8:11::1/64')
            cli('set ip neighbor pg1 10.241.0.2 02:00:00:00:01:02')
            cli('set ip neighbor pg1 2001:db8:11::2 02:00:00:00:01:02')
            cli('set ip neighbor pg0 10.240.0.2 02:00:00:00:01:03')
            cli('ip route add 203.0.113.10/32 via 10.240.0.2 pg0')
            permit = ('permit src 203.0.113.10/32 dst 10.241.0.2/32 proto 17 dport 45996, '
                      'permit src 203.0.113.10/32 dst 10.241.0.2/32 proto 6 dport 45996 tcpflags 2 mask 18, '
                      'permit src 2001:db8:10::/64 dst 2001:db8:11::/64 proto 17 dport 45996, '
                      'deny src 0.0.0.0/0 dst 0.0.0.0/0, deny src ::/0 dst ::/0')
            cli('set acl-plugin acl tag cache-test ' + permit)
            cli('set acl-plugin acl tag reverse-deny deny src 0.0.0.0/0 dst 0.0.0.0/0')
            cli('set acl-plugin interface pg0 input acl 0')
            cli('set acl-plugin interface pg1 input acl 1')

            def case(name, packets, expected=None, interface='pg0', output='pg1', total=None):
                total = len(packets) if total is None else total
                path = root / (name + '.pcap')
                pcap(path, packets)
                cli('clear interfaces')
                cli('clear errors')
                cli('clear runtime')
                cli('packet-generator new { name ' + name + ' limit ' + str(total) +
                    ' maxframe 256 interface ' + interface + ' node ethernet-input pcap ' + str(path) + ' }')
                cli('packet-generator enable-stream ' + name)
                time.sleep(.3)
                deadline = time.monotonic() + 15
                while error_count(cli('show errors'), 'checked packets') < total:
                    if time.monotonic() > deadline:
                        raise RuntimeError('PG did not finish: ' + name)
                    time.sleep(.05)
                interfaces = cli('show interface ' + output)
                match = re.search(r'\btx packets\s+(\d+)', interfaces)
                received = int(match[1]) if match else 0
                errors = cli('show errors')
                hits = error_count(errors, 'frame permit cache hits')
                new = error_count(errors, 'new sessions added')
                checked = error_count(errors, 'checked packets')
                permitted = error_count(errors, 'ACL permit packets') + new + error_count(
                    errors, 'existing session packets')
                if expected is not None:
                    assert permitted == expected, (name, permitted, expected, errors, cli('show trace'))
                    # PG interfaces can also transmit IPv6 control packets.
                    assert expected <= received <= expected + 8, (name, received, expected, errors)
                assert checked == total, (name, checked, total, errors)
                results[name] = {'forwarded': permitted, 'tx_including_control': received, 'cache_hits': hits,
                                 'new_sessions': new, 'checked': checked, 'errors': errors,
                                 'runtime': cli('show runtime')}
                if benchmark_packets:
                    freq = int(Path('/sys/devices/system/cpu/cpufreq/policy6/cpuinfo_cur_freq').read_text())
                    assert freq == 2208000, (name, freq)
                    results[name]['frequency_khz'] = freq
                cli('packet-generator delete ' + name)
                return results[name]

            case('udp', [packet()] * 512, 512)
            case('reverse', [packet(src='10.241.0.2', dst='203.0.113.10', sport=45996, dport=40000)] * 512,
                 0, interface='pg1', output='pg0')
            case('tcp-flags', [packet(proto=6, flags=f) for f in (2, 2, 16, 16) * 128], 256)
            case('udp-ports', [packet(dport=p) for p in (45996, 45996, 45997, 45997) * 128], 256)
            case('ip6', [packet(ip6=True, src='2001:db8:10::2', dst='2001:db8:11::2')] * 512, 512)
            case('fragment-mixed', [packet(fragment=f) for f in (0, 2) * 256])
            cli('set acl-plugin acl index 0 tag cache-test deny src 0.0.0.0/0 dst 0.0.0.0/0, deny src ::/0 dst ::/0')
            case('policy-deny', [packet()] * 512, 0)
            cli('set acl-plugin acl index 0 tag cache-test ' + permit)
            case('policy-permit', [packet()] * 512, 512)
            if benchmark_packets:
                for repeat in range(2):
                    case('bench-single-' + str(repeat), [packet()] * 512,
                         benchmark_packets, total=benchmark_packets)
                    case('bench-multi-' + str(repeat),
                         [packet(sport=40000 + i) for i in range(20000)],
                         benchmark_packets, total=benchmark_packets)
            cli('trace add pg-input 512')
            case('trace', [packet()] * 512, 512)
            cli('clear trace')
            cli('set acl-plugin acl index 0 tag cache-test permit+reflect src 203.0.113.10/32 dst 10.241.0.2/32 proto 17, deny src 0.0.0.0/0 dst 0.0.0.0/0')
            case('reflect', [packet()] * 512, 512)
            assert results['udp']['new_sessions'] == 0
            assert results['reflect']['new_sessions'] > 0
            return results
        except Exception:
            print((root / 'vpp.log').read_text()[-3000:])
            raise
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--benchmark-packets', type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.benchmark_packets <= 2000000:
        parser.error('benchmark packet limit exceeded')
    production_pid = run('systemctl', 'show', '-p', 'MainPID', '--value', 'vrouter-vpp.service').strip()
    policy = Path('/sys/devices/system/cpu/cpufreq/policy6')
    original = {f: (policy / f).read_text().strip() for f in
                ('scaling_governor', 'scaling_min_freq', 'scaling_max_freq')}
    try:
        if args.benchmark_packets:
            (policy / 'scaling_governor').write_text('performance')
            (policy / 'scaling_max_freq').write_text('2208000')
            (policy / 'scaling_min_freq').write_text('2208000')
            assert (policy / 'cpuinfo_cur_freq').read_text().strip() == '2208000'
        baseline = exercise(Path('/usr/local/lib/vpp-vrouter/plugins/acl_plugin.so'), args.benchmark_packets)
        candidate = exercise(args.candidate, args.benchmark_packets)
    finally:
        for f in ('scaling_max_freq', 'scaling_min_freq', 'scaling_governor'):
            (policy / f).write_text(original[f])
    for name in baseline:
        for key in ('forwarded', 'new_sessions', 'checked'):
            assert baseline[name][key] == candidate[name][key], (name, key, baseline[name], candidate[name])
    assert candidate['udp']['cache_hits'] >= 400, candidate['udp']
    assert candidate['ip6']['cache_hits'] >= 400, candidate['ip6']
    assert candidate['policy-deny']['cache_hits'] == 0
    assert candidate['trace']['cache_hits'] == 0
    assert candidate['reflect']['cache_hits'] == 0
    assert run('systemctl', 'show', '-p', 'MainPID', '--value', 'vrouter-vpp.service').strip() == production_pid
    args.output.write_text(json.dumps({'baseline': baseline, 'candidate': candidate,
        'production_pid_unchanged': production_pid, 'policy6_original': original,
        'policy6_restored': {f: (policy / f).read_text().strip() for f in original}}, indent=2) + '\n')
    for name in candidate:
        print(name, {k: v for k, v in candidate[name].items() if k not in ('errors', 'runtime')}, flush=True)


if __name__ == '__main__':
    main()
