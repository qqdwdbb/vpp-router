#!/usr/bin/env python3
"""Targeted PTB and IPv4 MSS drop-node diagnostics for the isolated IPsec lab."""
import json
import os
import re
import signal
import socket
import struct
import subprocess
from pathlib import Path


TRACE_NODES = (
    'tap-input', 'virtio-input',
    'ip6-input', 'ip6-lookup', 'ip6-local', 'ip6-icmp-input', 'ip6-punt', 'ip6-punt-redirect',
    'ip6-icmp-error', 'ip4-icmp-error', 'ip4-input', 'ip4-lookup', 'ip4-local', 'ip4-unicast',
    'tcp-mss-clamping-ip4-in', 'tcp-mss-clamping-ip4-out',
    'tcp-mss-clamping-ip6-in', 'tcp-mss-clamping-ip6-out',
    'nat44-ei-out2in', 'nat44-ei-in2out-output',
    'nat44-ei-out2in-worker-handoff', 'nat44-ei-in2out-output-worker-handoff',
    'ipsec-cleartext-input', 'ipsec4-output-feature', 'ipsec6-output-feature',
    'ipsec-ptb-input', 'ipsec4-pmtu-check', 'ipsec6-pmtu-check',
    'esp6-encrypt', 'esp6-decrypt', 'esp4-encrypt', 'error-drop', 'ip4-drop', 'ip6-drop',
)
RUNTIME_NODES = TRACE_NODES + ('ip6-frag', 'null-node', 'esp6-decrypt-post', 'esp4-decrypt')
HANDSHAKE_PORTS = {49876, 49877}
TRACE_LINE = re.compile(r'^\d+:\d+:\d+:\d+: (\S+)')
ERROR_LINE = re.compile(r'^\s+(\d+)\s+(\S+)\s+(.+?)\s+(error|info|warn)\s*$')
RUNTIME_LINE = re.compile(r'^(\S+)\s+\S+\s+\d+\s+(\d+)\s+')
FEATURE_ARC = re.compile(r'^arc:\s+(\S+)')
FEATURE_NODE = re.compile(r'^(?:\[\s*\d+\]:\s*)?(\S+)$')


def parse_trace(text):
    packets, current = [], None
    for line in text.splitlines():
        if line.startswith('Packet '):
            current = {'index': line.split()[1], 'nodes': [], 'hints': []}
            packets.append(current)
            continue
        if current is None:
            continue
        match = TRACE_LINE.match(line)
        if match:
            current['nodes'].append(match.group(1))
            continue
        stripped = line.strip()
        if stripped and any(word in stripped.lower() for word in (
                'unknown type', 'packet too big', 'mss', 'clamped', 'punt',
                'no translation', 'icmp', 'tcp', 'spi', 'drop')):
            if len(current['hints']) < 12:
                current['hints'].append(stripped[:200])
    return packets


def parse_errors(text):
    rows = []
    for line in text.splitlines():
        match = ERROR_LINE.match(line)
        if match:
            rows.append({'count': int(match.group(1)), 'node': match.group(2),
                         'reason': match.group(3).strip(), 'severity': match.group(4)})
    return rows


def error_delta(before, after):
    previous = {(row['node'], row['reason']): row['count'] for row in parse_errors(before)}
    delta = []
    for row in parse_errors(after):
        change = row['count'] - previous.get((row['node'], row['reason']), 0)
        if change:
            delta.append({**row, 'count': change})
    return delta


def parse_runtime(text):
    counts = {}
    for line in text.splitlines():
        match = RUNTIME_LINE.match(line)
        if match:
            counts[match.group(1)] = counts.get(match.group(1), 0) + int(match.group(2))
    return counts


def runtime_delta(before, after, nodes=RUNTIME_NODES):
    previous, current = parse_runtime(before), parse_runtime(after)
    return {node: current.get(node, 0) - previous.get(node, 0)
            for node in nodes if current.get(node, 0) - previous.get(node, 0)}


def feature_order(text, arc):
    nodes, wanted = [], False
    for line in text.splitlines():
        heading = FEATURE_ARC.match(line.strip())
        if heading:
            wanted = heading.group(1) == arc
            continue
        if not wanted:
            continue
        if not line.strip():
            if nodes:
                break
            continue
        match = FEATURE_NODE.match(line.strip())
        if match:
            nodes.append(match.group(1))
    return nodes


def tcp_option_mss(header):
    end = min(len(header), (header[12] >> 4) * 4)
    cursor = 20
    while cursor < end:
        kind = header[cursor]
        if kind == 0:
            break
        if kind == 1:
            cursor += 1
            continue
        if cursor + 2 > end:
            break
        length = header[cursor + 1]
        if length < 2 or cursor + length > end:
            break
        if kind == 2 and length == 4:
            return struct.unpack_from('!H', header, cursor + 2)[0]
        cursor += length
    return None


def decode_frame(frame, ports=HANDSHAKE_PORTS):
    if len(frame) < 34:
        return None
    ether = struct.unpack_from('!H', frame, 12)[0]
    if ether == 0x0800:
        family, protocol, offset = 4, frame[23], 14 + (frame[14] & 15) * 4
        src, dst = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
        ip_checksum = struct.unpack_from('!H', frame, 24)[0]
        l3 = struct.unpack_from('!H', frame, 16)[0]
    elif ether == 0x86dd and len(frame) >= 54:
        family, protocol, offset = 6, frame[20], 54
        src = socket.inet_ntop(socket.AF_INET6, frame[22:38])
        dst = socket.inet_ntop(socket.AF_INET6, frame[38:54])
        ip_checksum, l3 = None, 40 + struct.unpack_from('!H', frame, 18)[0]
    else:
        return None
    record = {'family': family, 'src': src, 'dst': dst, 'protocol': protocol,
              'l3_bytes': l3, 'ip_checksum': ip_checksum}
    if protocol in (1, 58) and len(frame) >= offset + 8:
        kind, code = frame[offset], frame[offset + 1]
        if (protocol == 58 and kind < 128) or (protocol == 1 and kind in (3, 11, 12)):
            record['kind'] = 'icmp'
            record['icmp_type'], record['icmp_code'] = kind, code
            if protocol == 58 and kind == 2:
                record['advertised_mtu'] = struct.unpack_from('!I', frame, offset + 4)[0]
                if len(frame) >= offset + 16:
                    record['quoted_next_header'] = frame[offset + 8 + 6]
                    record['quoted_src'] = socket.inet_ntop(socket.AF_INET6, frame[offset + 16:offset + 32]) if len(frame) >= offset + 48 else None
                    record['quoted_dst'] = socket.inet_ntop(socket.AF_INET6, frame[offset + 32:offset + 48]) if len(frame) >= offset + 48 else None
            if protocol == 1 and kind == 3:
                record['advertised_mtu'] = struct.unpack_from('!H', frame, offset + 6)[0]
                quoted = offset + 8
                if len(frame) >= quoted + 20 and frame[quoted] >> 4 == 4:
                    qihl = (frame[quoted] & 15) * 4
                    record['quoted_protocol'] = frame[quoted + 9]
                    record['quoted_src'] = socket.inet_ntoa(frame[quoted + 12:quoted + 16])
                    record['quoted_dst'] = socket.inet_ntoa(frame[quoted + 16:quoted + 20])
                    if record['quoted_protocol'] in (6, 17) and len(frame) >= quoted + qihl + 4:
                        record['quoted_sport'], record['quoted_dport'] = struct.unpack_from(
                            '!HH', frame, quoted + qihl)
            return record
    if protocol == 6 and len(frame) >= offset + 20:
        flags = frame[offset + 13]
        sport, dport = struct.unpack_from('!HH', frame, offset)
        if flags & 2 and {sport, dport} & ports:
            header = frame[offset:]
            record.update(kind='tcp', syn_ack=bool(flags & 16), sport=sport, dport=dport,
                          mss=tcp_option_mss(header), tcp_checksum=struct.unpack_from('!H', header, 16)[0],
                          seq=struct.unpack_from('!I', header, 4)[0], flags=flags)
            return record
    return None


def capture_path(root, iface, stem, ports=None):
    """Record ICMP errors and TCP handshake fields on one TAP. Snapshot on SIGUSR1."""
    records = []
    wanted = set(ports or HANDSHAKE_PORTS)
    def snapshot(*unused):
        temp = root / (stem + '.tmp')
        temp.write_text(json.dumps(records))
        temp.replace(root / (stem + '.json'))
    signal.signal(signal.SIGUSR1, snapshot)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind((iface, 0))
        (root / (stem + '-ready')).touch()
        while True:
            frame = sock.recv(65536)
            record = decode_frame(frame, wanted)
            if record and record not in records and len(records) < 64:
                records.append(record)


def _route_get(run, ns, dest):
    try:
        return run('ip', '-n', ns, '-6', 'route', 'get', dest)[-800:]
    except Exception as exc:
        return str(exc)


def classify_ptb(packets, errors, control, lan):
    nodes = [node for packet in packets for node in packet['nodes']]
    punted = 'ip6-punt' in nodes or 'ip6-punt-redirect' in nodes
    dropped = 'error-drop' in nodes or 'ip6-drop' in nodes
    unknown = any(row['node'] == 'ip6-icmp-input' and 'unknown' in row['reason'].lower()
                  for row in errors)
    control_ptb = [row for row in control if row.get('kind') == 'icmp' and row.get('icmp_type') == 2]
    lan_inner = [row for row in lan if row.get('kind') == 'icmp']
    associated = any(node in nodes for node in (
        'ipsec-ptb-input', 'ipsec4-pmtu-check', 'ipsec6-pmtu-check'))
    if lan_inner:
        fate = 'inner-icmp'
    elif associated and not punted:
        fate = 'associated-sa'
    elif punted or control_ptb:
        fate = 'punt-to-control-tap'
    elif dropped and not punted:
        fate = 'dropped'
    elif unknown:
        fate = 'icmp-unknown-type'
    else:
        fate = 'unclassified'
    return {
        'fate': fate,
        'associated_with_sa': associated or bool(lan_inner),
        'inner_feedback_on_lan': bool(lan_inner),
        'control_tap_ptb': len(control_ptb),
        'trace_contains_ip6_icmp_input': 'ip6-icmp-input' in nodes,
        'trace_contains_ip6_punt': 'ip6-punt' in nodes,
        'unknown_type_counter': unknown,
    }


def first_tcp_drop(sends, handshake, clamp_in, clamp_out):
    if not handshake.get('connected'):
        return {'stage': 'handshake', 'detail': handshake}
    for send in sends:
        if not send.get('ok'):
            return {'stage': 'payload', 'bytes': send.get('bytes'), 'detail': send,
                    'syn_clamped': clamp_out > 0, 'synack_clamped': clamp_in > 0}
    return {'stage': None, 'syn_clamped': clamp_out > 0, 'synack_clamped': clamp_in > 0}


def diagnose_drop_nodes(root, names, source4, source6, native, run, cli, wait, start, script):
    def soft(command):
        try:
            return cli(command)
        except Exception:
            return ''

    def snap(proc, stem):
        path = root / (stem + '.json')
        path.unlink(missing_ok=True)
        os.kill(proc.pid, signal.SIGUSR1)
        wait(lambda: path.exists(), stem + ' snapshot missing')
        return json.loads(path.read_text())

    features = soft('show features verbose')
    unicast = feature_order(features, 'ip4-unicast')
    try:
        mss_before_nat = unicast.index('tcp-mss-clamping-ip4-in') < unicast.index('nat44-ei-out2in')
    except ValueError:
        mss_before_nat = None
    report = {
        'feature_arcs': {
            'ip4-unicast': unicast,
            'ip4-output': feature_order(features, 'ip4-output'),
            'ip6-unicast': feature_order(features, 'ip6-unicast'),
        },
        'mss_clamp_in_before_nat44_ei_out2in': mss_before_nat,
        'features_verbose': features[-12000:],
        'punt_redirect': {'ip6': soft('show ip6 punt redirect'), 'ip4': soft('show ip punt redirect')},
        'interfaces': {name: soft('show interface ' + name)[-4000:] for name in ('tap3960', 'tap3961', 'tap3962')},
    }
    lan_cap = start(['ip', 'netns', 'exec', names['lan'], 'python3', str(script),
                     '--capture-path', str(root), 'mgmt0', 'lan-path'], 'lan-path.log')
    control_cap = start(['ip', 'netns', 'exec', names['server'], 'python3', str(script),
                         '--capture-path', str(root), 'tap3960', 'control-path'], 'control-path.log')
    wait(lambda: (root / 'lan-path-ready').exists() and (root / 'control-path-ready').exists(),
         'Path captures missing')
    added = []
    soft('clear trace')
    for node in TRACE_NODES:
        text = soft('trace add %s 32' % node)
        if 'unknown' not in text.lower() and 'failed' not in text.lower():
            added.append(node)
    before_errors, before_runtime = cli('show errors'), cli('show runtime')
    probe = subprocess.run(['ip', 'netns', 'exec', names['lan'], 'ping', '-6', '-I', '2001:db8:62::2',
                            '-n', '-c', '3', '-i', '.3', '-W', '1', '-M', 'do', '-s', '1300', source6],
                           capture_output=True, text=True, timeout=6)
    lan_packets = snap(lan_cap, 'lan-path')
    control_packets = snap(control_cap, 'control-path')
    after_errors, after_runtime = cli('show errors'), cli('show runtime')
    trace = soft('show trace max 64')
    packets = parse_trace(trace)
    errors = error_delta(before_errors, after_errors)
    report['ptb'] = {
        'probe_success': probe.returncode == 0,
        'probe_feedback': (probe.stdout + probe.stderr)[-1200:],
        'trace_nodes_enabled': added,
        'packets': [{'nodes': p['nodes'], 'hints': p['hints']} for p in packets[:12]],
        'errors_delta': errors,
        'runtime_delta': runtime_delta(before_runtime, after_runtime),
        'lan_inner_icmp': [p for p in lan_packets if p.get('kind') == 'icmp'],
        'control_tap': [p for p in control_packets if p.get('kind') == 'icmp'],
        'linux_server_route': _route_get(run, names['server'], '2001:db8:60::2'),
        'linux_client_route': _route_get(run, names['client'], '2001:db8:60::1'),
        'classification': classify_ptb(packets, errors, control_packets, lan_packets),
    }
    path_limit = ((1280 - (72 if native else 80)) // 4) * 4 - 2
    mss4, mss6 = path_limit - 40, path_limit - 60
    cli('set interface tcp-mss-clamp tap3962 ip4 enable ip4-mss %d ip6 enable ip6-mss %d' % (mss4, mss6))
    echo = '''import socket,threading,sys
from pathlib import Path
def serve(family,host,port):
 s=socket.socket(family,socket.SOCK_STREAM)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((host,port));s.listen(1)
 Path(sys.argv[1]+str(port)).touch()
 c,a=s.accept()
 Path(sys.argv[1]+str(port)+"-source").write_text(a[0])
 with c:
  while True:
   d=c.recv(16384)
   if not d:break
   c.sendall(d)
 s.close()
a=threading.Thread(target=serve,args=(socket.AF_INET,'10.254.62.2',49876));a.start()
serve(socket.AF_INET6,'2001:db8:62::2',49877);a.join()
'''
    start(['ip', 'netns', 'exec', names['lan'], 'python3', '-u', '-c', echo, str(root / 'diag-echo-')],
          'diag-echo.log')
    wait(lambda: all((root / ('diag-echo-' + str(port))).exists() for port in (49876, 49877)),
         'Diagnostic TCP listeners missing')
    client = '''import socket,sys,json
s=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(4);s.bind((sys.argv[1],0))
info={"connected":False,"sends":[]}
try:
 s.connect((sys.argv[2],int(sys.argv[3])))
 info["connected"]=True
 info["effective_mss"]=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_MAXSEG)
 for n in map(int,sys.argv[4].split(",")):
  try:
   s.sendall(b"x"*n);got=0
   while got<n:
    d=s.recv(n-got)
    if not d:break
    got+=len(d)
   info["sends"].append({"bytes":n,"echoed":got,"ok":got==n})
   if got!=n:break
  except Exception as exc:
   info["sends"].append({"bytes":n,"ok":False,"error":str(exc)});break
except Exception as exc:
 info["error"]=str(exc)
print(json.dumps(info));s.close()
'''
    tcp = {}
    for family, source, destination, port in (
            (4, source4, '10.254.62.2', 49876), (6, source6, '2001:db8:62::2', 49877)):
        soft('clear trace')
        for node in TRACE_NODES:
            soft('trace add %s 32' % node)
        before_errors, before_runtime = cli('show errors'), cli('show runtime')
        probe = subprocess.run(['ip', 'netns', 'exec', names['client'], 'python3', '-c', client,
                                source, destination, str(port), '1,512,1200,2000'],
                               capture_output=True, text=True, timeout=25)
        lan_packets = snap(lan_cap, 'lan-path')
        handshake = json.loads(probe.stdout) if probe.stdout.strip().startswith('{') else {
            'connected': False, 'error': (probe.stdout + probe.stderr)[-1200:], 'sends': []}
        after_errors, after_runtime = cli('show errors'), cli('show runtime')
        handshake_packets = [p for p in lan_packets if p.get('kind') == 'tcp' and p.get('family') == family]
        vectors = runtime_delta(before_runtime, after_runtime)
        tcp[str(family)] = {
            'handshake': handshake,
            'lan_packets': handshake_packets,
            'errors_delta': error_delta(before_errors, after_errors),
            'runtime_delta': vectors,
            'packets': [{'nodes': p['nodes'], 'hints': p['hints']} for p in parse_trace(soft('show trace max 64'))[:12]],
            'mss_clamp': {'ip4': mss4, 'ip6': mss6},
            'first_drop': first_tcp_drop(
                handshake.get('sends', []), handshake,
                vectors.get('tcp-mss-clamping-ip4-in' if family == 4 else 'tcp-mss-clamping-ip6-in', 0),
                vectors.get('tcp-mss-clamping-ip4-out' if family == 4 else 'tcp-mss-clamping-ip6-out', 0)),
        }
    cli('set interface tcp-mss-clamp tap3962 ip4 disable ip6 disable')
    report['tcp'] = tcp
    report['mss_candidates_isolation_only'] = {'ip4': mss4, 'ip6': mss6}
    (root / 'pmtu-diagnose.log').write_text(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--capture-path':
        capture_path(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        raise SystemExit('usage: integration_vrouter_ipsec_diagnose.py --capture-path ROOT IFACE STEM')
