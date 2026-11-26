"""Root only: NAT44 checksums, hairpinning and ABF order (patches 0037-0042).

An isolated VPP gets two TAPs with checksum offload, one per network
namespace, and NAT44-ED (`--nat ed`) or NAT44-EI (`--nat ei`) between them.
Linux on both sides sends with checksum offload, so its TCP and UDP reach VPP
with an L4 checksum field that holds only the pseudo-header sum. The traffic
covers every kind of rewrite:

- inside to outside through static mappings that change the source port, with
  MSS clamping lowering the SYN's MSS (in2out);
- the replies, whose destination address and port go back (out2in);
- with an inside interface (in/out and mixed modes), inside to the router's
  outside address and a mapped port that leads back to an inside service,
  where both source and destination are rewritten (hairpinning, which needs
  0039 for EI and 0040 for ED).

- a query to 198.51.100.53:53 that an ABF policy on the inside interface
  redirects to a third namespace (as Gate's DNS hijack does): it must arrive
  from the client's own address, which needs 0041/0042 whenever there is an
  inside interface, because in2out would otherwise rewrite the source first
  and the policy would no longer match.

Modes: `inout` (inside and outside interfaces), `output` (output feature on
the outside interface only, as the installer configures it, where VPP cannot
hairpin), `mixed` (output feature plus the inside interface) and `hairpin`
(output feature plus `hairpinning` on the inside interface, patches
0043/0044: only packets that hairpinning resolves go through in2out).

`pcap trace rx tx` records each packet as VPP receives it and again as it
sends it, before the TAP rewrites the field, so the capture shows what NAT
left there. Linux makes most but not all of its packets partial (some pure
ACKs carry a complete checksum), so each sent packet is judged by its
received copy: partial in, the field must be the pseudo-header sum of the
translated packet; complete in, a complete checksum. Every mode runs with
Linux checksum offload on and then off, where complete checksums must stay
complete. A plugin without 0037/0038 fails on the first checked partial
packet, one without 0039/0040 fails to hairpin and one without 0041/0042
fails the ABF check whenever there is an inside interface.
"""
import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

INSIDE, OUTSIDE = '10.254.243.2', '10.254.244.2'
VPP_IN, VPP_OUT = '10.254.243.1', '10.254.244.1'
TCP_LOCAL, TCP_EXTERNAL, TCP_SERVER = 5001, 6001, 7000
UDP_LOCAL, UDP_EXTERNAL, UDP_SERVER = 5002, 6002, 7001
HP_TCP, HP_TCP_EXTERNAL = 5003, 6003
HP_UDP, HP_UDP_EXTERNAL = 5004, 6004
MSS_CLAMP = 1200
GATE_NS_ADDR, VPP_GATE = '10.254.245.2', '10.254.245.1'
ABF_DST = '198.51.100.53'

CLI = {
    'ed': {
        'plugin': 'nat_plugin.so',
        'enable': 'nat44 plugin enable sessions 1024',
        'address': 'nat44 add interface address tap2',
        'inout': 'set interface nat44 in tap1 out tap2',
        'output': 'set interface nat44 out tap2 output-feature',
        'inside': 'set interface nat44 in tap1',
        'hairpin': 'set interface nat44 hairpinning tap1',
        'static': 'nat44 add static mapping',
        'mss': f'nat mss-clamping {MSS_CLAMP}',
    },
    'ei': {
        'plugin': 'nat44_ei_plugin.so',
        'enable': 'nat44 ei plugin enable sessions 1024',
        'address': 'nat44 ei add interface address tap2',
        'inout': 'set interface nat44 ei in tap1 out tap2',
        'output': 'set interface nat44 ei out tap2 output-feature',
        'inside': 'set interface nat44 ei in tap1',
        'hairpin': 'set interface nat44 ei hairpinning tap1',
        'static': 'nat44 ei add static mapping',
        'mss': f'nat44 ei mss-clamping {MSS_CLAMP}',
    },
}


def run(*args, timeout=20):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=timeout).stdout


def fold(value):
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return value


def ones_sum(data):
    if len(data) % 2:
        data += b'\0'
    return fold(sum(struct.unpack(f'!{len(data) // 2}H', data)))


def pcap_frames(path):
    data = path.read_bytes()
    magic = struct.unpack('<I', data[:4])[0]
    endian = '<' if magic in (0xa1b2c3d4, 0xa1b23c4d) else '>'
    offset = 24
    while offset + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + 'IIII', data[offset:offset + 16])
        offset += 16
        yield data[offset:offset + incl]
        offset += incl


def l4_packets(path):
    """Yield (ip header, l4 bytes, proto, field offset, field, pseudo sum)."""
    for frame in pcap_frames(path):
        if len(frame) < 34 or frame[12:14] != b'\x08\x00':
            continue
        ip = frame[14:]
        ihl, proto = (ip[0] & 0xf) * 4, ip[9]
        if proto not in (6, 17):
            continue
        total = struct.unpack('!H', ip[2:4])[0]
        l4 = ip[ihl:total]
        assert len(l4) == total - ihl, 'capture truncated'
        at = 16 if proto == 6 else 6
        field = struct.unpack('!H', l4[at:at + 2])[0]
        pseudo = fold(ones_sum(ip[12:20]) + proto + total - ihl)
        yield ip, l4, proto, at, field, pseudo


def complete(l4, at, pseudo):
    return 0xffff - fold(pseudo + ones_sum(l4[:at] + b'\0\0' + l4[at + 2:]))


def dump_capture(path):
    for ip, l4, proto, at, field, pseudo in l4_packets(path):
        print(socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20]),
              struct.unpack('!HH', l4[:4]), 'len', len(l4), 'field', hex(field),
              'pseudo', hex(pseudo), 'full', hex(complete(l4, at, pseudo)))


def syn_mss(l4):
    options = l4[20:(l4[12] >> 4) * 4]
    i = 0
    while i < len(options) and options[i] != 0:
        if options[i] == 1:
            i += 1
            continue
        if options[i] == 2:
            return struct.unpack('!H', options[i + 2:i + 4])[0]
        i += options[i + 1]
    return None


def packet_key(ip, l4, proto):
    """What NAT leaves alone: the IP ID, the length and the L4 bytes past the
    ports (TCP: sequence numbers, flags, window and payload)."""
    total = struct.unpack('!H', ip[2:4])[0]
    if proto == 6:
        rest = l4[4:16] + l4[(l4[12] >> 4) * 4:]
    else:
        rest = l4[8:]
    return ip[4:6], proto, total, rest


def check_capture(path, partial, hairpin):
    """Pair each packet VPP sent with the one it received, assert the field of
    the sent one and return how many of each kind came in partial."""
    kinds = ['out-tcp', 'out-udp', 'out-syn', 'back-tcp', 'back-udp', 'abf-udp']
    if hairpin:
        kinds += ['hairpin-tcp', 'hairpin-udp']
    seen = dict.fromkeys(kinds, 0)
    complete_in = 0
    out, inside = socket.inet_aton(VPP_OUT), socket.inet_aton(INSIDE)
    received = {}
    for ip, l4, proto, at, field, pseudo in l4_packets(path):
        key = packet_key(ip, l4, proto)
        if key not in received:
            # rx: Linux left either the pseudo-header sum or a complete checksum
            received[key] = field == pseudo and field != complete(l4, at, pseudo)
            continue
        was_partial = received.pop(key)
        src, dst = ip[12:16], ip[16:20]
        sport, dport = struct.unpack('!HH', l4[:4])
        name = 'tcp' if proto == 6 else 'udp'
        if socket.inet_aton(ABF_DST) in (src, dst):
            # redirected by ABF to the gate namespace: never translated
            assert socket.inet_aton(INSIDE) in (src, dst), (src, dst)
            kind = 'abf-' + name
        elif src == out and dst == socket.inet_aton(OUTSIDE):
            assert sport == (TCP_EXTERNAL if proto == 6 else UDP_EXTERNAL), sport
            kind = 'out-' + name
            if proto == 6 and l4[13] & 0x02:
                assert syn_mss(l4) == MSS_CLAMP, syn_mss(l4)
                kind = 'out-syn'
        elif src == socket.inet_aton(OUTSIDE):
            assert dst == inside, dst
            assert dport == (TCP_LOCAL if proto == 6 else UDP_LOCAL), dport
            kind = 'back-' + name
        else:
            # hairpinned: from the outside address, back to the inside
            assert hairpin and src == out and dst == inside, (src, dst)
            assert dport in (HP_TCP, HP_UDP) or sport in (HP_TCP_EXTERNAL, HP_UDP_EXTERNAL), (sport, dport)
            kind = 'hairpin-' + name
        if was_partial:
            want = pseudo
        elif kind == 'hairpin-udp' and field == 0:
            want = 0  # EI hairpinning clears a complete UDP checksum on a port change
        else:
            want = complete(l4, at, pseudo)
        # 0 and 0xffff are the same one's-complement value
        assert field == want or {field, want} == {0, 0xffff}, (
            'partial' if was_partial else 'complete', 'checksum field after NAT',
            kind, sport, dport, hex(field), hex(want))
        if was_partial:
            seen[kind] += 1
        else:
            complete_in += 1
    assert partial or not any(seen.values()), ('partial packets with offload off', seen)
    return seen, complete_in


OUTSIDE_SERVER = f'''
import socket
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(("{OUTSIDE}", {TCP_SERVER})); t.listen(1)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("{OUTSIDE}", {UDP_SERVER}))
print("ready", flush=True)
c, peer = t.accept(); got = b""
while len(got) < 3000:
    d = c.recv(65536)
    if not d: break
    got += d
c.sendall(b"r" * 2000)
d, upeer = u.recvfrom(2048)
u.sendto(b"s" * 900, upeer)
print(peer[0], peer[1], len(got), upeer[0], upeer[1], len(d), flush=True)
c.close()
'''

INSIDE_CLIENT = f'''
import socket, sys
def step(name):
    print(name, file=sys.stderr, flush=True)
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind(("{INSIDE}", {TCP_LOCAL})); t.settimeout(5)
step("tcp"); t.connect(("{OUTSIDE}", {TCP_SERVER}))
for _ in range(3): t.sendall(b"x" * 1000)
got = b""
while len(got) < 2000:
    got += t.recv(65536)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("{INSIDE}", {UDP_LOCAL}))
u.settimeout(5)
step("udp"); u.sendto(b"y" * 1200, ("{OUTSIDE}", {UDP_SERVER}))
reply = u.recv(2048)
t.close()
print(len(got), len(reply))
'''

GATE_SERVER = f'''
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("{ABF_DST}", 53))
print("ready", flush=True)
d, a = u.recvfrom(2048); u.sendto(("peer=%s" % a[0]).encode(), a)
'''

ABF_CLIENT = f'''
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(5)
u.sendto(b"q" * 60, ("{ABF_DST}", 53)); print(u.recv(100).decode())
'''

HAIRPIN_CLIENT = f'''
import socket, sys, threading
def step(name):
    print(name, file=sys.stderr, flush=True)
result = {{}}
def tcp_service():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("{INSIDE}", {HP_TCP})); s.listen(1); ready.set()
    c, peer = s.accept(); got = b""
    while len(got) < 1500:
        d = c.recv(65536)
        if not d: break
        got += d
    c.sendall(b"h" * 700); c.close()
    result["tcp"] = (peer[0], len(got))
ready = threading.Event()
th = threading.Thread(target=tcp_service, daemon=True); th.start(); ready.wait()
hu = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); hu.bind(("{INSIDE}", {HP_UDP}))
hu.settimeout(5)
h = socket.socket(); h.settimeout(5)
step("hairpin tcp"); h.connect(("{VPP_OUT}", {HP_TCP_EXTERNAL}))
h.sendall(b"z" * 1500)
hgot = b""
while len(hgot) < 700:
    hgot += h.recv(65536)
h.close(); th.join(5)
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(5)
step("hairpin udp"); c.sendto(b"w" * 800, ("{VPP_OUT}", {HP_UDP_EXTERNAL}))
d, peer = hu.recvfrom(2048)
hu.sendto(b"v" * 600, peer)
back, src = c.recvfrom(2048)
print(result["tcp"][0], result["tcp"][1], len(hgot), peer[0], len(d), src[0], src[1], len(back))
'''


def case(args, mode, partial):
    pid = os.getpid()
    ns_in, ns_out, ns_gate = f'nat44cs-in-{pid}', f'nat44cs-out-{pid}', f'nat44cs-gw-{pid}'
    pcap_name = f'nat44cs-{pid}.pcap'
    cmd = CLI[args.nat]
    process = server = gate = None
    with tempfile.TemporaryDirectory(prefix='nat44-partial-csum-') as tmp:
        root = Path(tmp)
        sock = str(root / 'cli.sock')
        plugins = root / 'plugins'
        plugins.mkdir()
        (plugins / cmd['plugin']).symlink_to(args.plugins / cmd['plugin'])
        for name in ('tap', 'acl', 'abf'):
            (plugins / f'{name}_plugin.so').symlink_to(args.system_plugins / f'{name}_plugin.so')

        def cli(command):
            text = run('vppctl', '-s', sock, *command.split()).strip()
            assert not any(s in text.lower() for s in ('unknown input', 'failed', 'returned')), (command, text)
            return text

        config = root / 'startup.conf'
        config.write_text(f'''unix {{ nodaemon runtime-dir {root}/run cli-listen {sock} }}
api-segment {{ prefix nat44cs-{pid} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock size 16M page-size 4k }}
cpu {{ main-core 0 }}
memory {{ main-heap-size 256M main-heap-page-size 4k }}
buffers {{ buffers-per-numa 4096 page-size 4k }}
plugins {{ path {plugins}
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin acl_plugin.so {{ enable }}
plugin abf_plugin.so {{ enable }}
plugin {cmd['plugin']} {{ enable }}
}}
''')
        try:
            for ns in (ns_in, ns_out, ns_gate):
                run('ip', 'netns', 'add', ns)
                run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
            with (root / 'vpp.log').open('w') as log:
                process = subprocess.Popen([str(args.vpp), '-c', str(config)], stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError((root / 'vpp.log').read_text())
                if Path(sock).exists():
                    break
                time.sleep(.1)
            time.sleep(.5)
            cli(f'create tap id 1 host-ns {ns_in} host-if-name nat44cs-in host-ip4-addr {INSIDE}/24 csum-offload')
            cli(f'create tap id 2 host-ns {ns_out} host-if-name nat44cs-out host-ip4-addr {OUTSIDE}/24 csum-offload')
            for ns, dev, gw in ((ns_in, 'nat44cs-in', VPP_IN), (ns_out, 'nat44cs-out', None)):
                run('ip', '-n', ns, 'link', 'set', dev, 'up')
                # Linux checksum offload on: its TCP and UDP reach VPP partial
                run('ip', 'netns', 'exec', ns, 'ethtool', '-K', dev, 'tx', 'on' if partial else 'off')
                features = run('ip', 'netns', 'exec', ns, 'ethtool', '-k', dev)
                assert f"tx-checksumming: {'on' if partial else 'off'}" in features, features
                if gw:
                    run('ip', '-n', ns, 'route', 'add', 'default', 'via', gw)
            cli(f'create tap id 3 host-ns {ns_gate} host-if-name nat44cs-gw host-ip4-addr {GATE_NS_ADDR}/24')
            run('ip', '-n', ns_gate, 'link', 'set', 'nat44cs-gw', 'up')
            run('ip', '-n', ns_gate, 'addr', 'add', f'{ABF_DST}/32', 'dev', 'lo')
            run('ip', '-n', ns_gate, 'route', 'add', 'default', 'via', VPP_GATE)
            cli(f'set interface ip address tap3 {VPP_GATE}/24')
            cli('set interface state tap3 up')
            # everything else leaves through the outside, so in2out would translate
            # the redirected query if it ran before ABF
            cli(f'ip route add 0.0.0.0/0 via {OUTSIDE} tap2')
            cli(f'set acl-plugin acl permit src {INSIDE.rsplit(".", 1)[0]}.0/24 dst {ABF_DST}/32 proto 17 dport 53')
            cli(f'abf policy add id 1 acl 0 via {GATE_NS_ADDR} tap3')
            cli('abf attach ip4 policy 1 tap1')
            cli(f'set interface ip address tap1 {VPP_IN}/24')
            cli(f'set interface ip address tap2 {VPP_OUT}/24')
            cli('set interface state tap1 up')
            cli('set interface state tap2 up')
            cli(cmd['enable'])
            cli(cmd['address'])
            if mode == 'inout':
                cli(cmd['inout'])
            else:
                cli(cmd['output'])
                if mode == 'mixed':
                    cli(cmd['inside'])
                elif mode == 'hairpin':
                    cli(cmd['hairpin'])
            hairpin = mode != 'output'
            for proto, local, external in (('tcp', TCP_LOCAL, TCP_EXTERNAL), ('udp', UDP_LOCAL, UDP_EXTERNAL),
                                           ('tcp', HP_TCP, HP_TCP_EXTERNAL), ('udp', HP_UDP, HP_UDP_EXTERNAL)):
                cli(f"{cmd['static']} {proto} local {INSIDE} {local} external {VPP_OUT} {external}")
            cli(cmd['mss'])
            if args.dump:
                cli(f'pcap trace rx tx max 2000 max-bytes-per-pkt 2000 file {pcap_name}')
            else:
                # rx and tx: the received copy tells whether Linux left the sum partial
                cli(f'pcap trace rx tx max 4000 max-bytes-per-pkt 2000 file {pcap_name}')

            gate = subprocess.Popen(['ip', 'netns', 'exec', ns_gate, 'python3', '-c', GATE_SERVER],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert gate.stdout.readline().strip() == 'ready'
            abf = subprocess.run(['ip', 'netns', 'exec', ns_in, 'python3', '-c', ABF_CLIENT],
                                 capture_output=True, text=True, timeout=15)
            server = subprocess.Popen(['ip', 'netns', 'exec', ns_out, 'python3', '-c', OUTSIDE_SERVER],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            assert server.stdout.readline().strip() == 'ready'
            try:
                client = subprocess.run(['ip', 'netns', 'exec', ns_in, 'python3', '-c', INSIDE_CLIENT],
                                        capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired as e:
                if not args.dump:
                    raise AssertionError(f'client hung after: {e.stderr}') from None
                client = subprocess.CompletedProcess([], 1, '', e.stderr)
            out, err = server.communicate(timeout=10)
            hp = None
            if hairpin:
                try:
                    hp = subprocess.run(['ip', 'netns', 'exec', ns_in, 'python3', '-c', HAIRPIN_CLIENT],
                                        capture_output=True, text=True, timeout=30)
                except subprocess.TimeoutExpired as e:
                    if not args.dump:
                        raise AssertionError(f'hairpin client hung after: {e.stderr}') from None
                    hp = subprocess.CompletedProcess([], 1, '', e.stderr)
            cli('pcap trace off')
            if args.dump:
                print(client.stdout, client.stderr)
                if hp:
                    print(hp.stdout, hp.stderr)
                print(cli('show errors'))
                dump_capture(Path('/tmp') / pcap_name)
                return
            # the policy matched the client's own address and sent it to the gate
            assert abf.stdout.strip() == f'peer={INSIDE}', ('ABF redirect', abf.stdout, abf.stderr)
            assert client.returncode == 0, client.stderr
            assert out.split() == [VPP_OUT, str(TCP_EXTERNAL), '3000', VPP_OUT, str(UDP_EXTERNAL), '1200'], (out, err)
            assert client.stdout.split() == ['2000', '900'], client.stdout
            if hairpin:
                assert hp.returncode == 0, hp.stderr
                # the inside service sees the outside address; the client gets
                # the UDP answer from the mapped port, not the inside one
                assert hp.stdout.split() == [VPP_OUT, '1500', '700', VPP_OUT, '800',
                                             VPP_OUT, str(HP_UDP_EXTERNAL), '600'], hp.stdout

            seen, complete_in = check_capture(Path('/tmp') / pcap_name, partial, hairpin)
            if partial:
                assert all(seen.values()), seen
            print(f'{args.nat} {mode}, Linux checksum offload {"on" if partial else "off"}: '
                  f'all fields correct after NAT; partial on input: '
                  + ', '.join(f'{k} {v}' for k, v in seen.items())
                  + f'; complete on input: {complete_in}')
        finally:
            for p in (server, gate):
                if p and p.poll() is None:
                    p.kill()
            if process and process.poll() is not None:
                print('VPP exited early:', (root / 'vpp.log').read_text()[-3000:])
            if process:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
            for ns in (ns_in, ns_out, ns_gate):
                subprocess.run(['ip', 'netns', 'del', ns], capture_output=True)
            Path('/tmp', pcap_name).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nat', choices=('ed', 'ei'), required=True)
    parser.add_argument('--plugins', type=Path, required=True,
                        help='directory with the NAT plugin under test')
    parser.add_argument('--system-plugins', type=Path,
                        default=Path('/usr/local/lib/vpp-router/vpp_plugins'))
    parser.add_argument('--vpp', type=Path, default=Path('/usr/local/bin/vpp'))
    parser.add_argument('--dump', action='store_true',
                        help='print every TCP/UDP packet in and out instead of checking')
    parser.add_argument('--mode', choices=('inout', 'output', 'mixed', 'hairpin'), action='append',
                        help='run only these NAT interface modes (default all)')
    parser.add_argument('--offload', choices=('on', 'off'), action='append',
                        help='run only with Linux checksum offload on or off (default both)')
    args = parser.parse_args()
    for partial in [o == 'on' for o in args.offload or ('on', 'off')]:
        for mode in args.mode or ('inout', 'output', 'mixed', 'hairpin'):
            case(args, mode, partial)


if __name__ == '__main__':
    main()
