"""EI/destination-routing checks inside the isolated loopback WG fixture."""
import json
import re
import socket
import subprocess
import threading
import time

from integration_wireguard_interface_peer import run


UDP_SERVER = '''import base64,json,socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ADDR,49400))
READY.touch()
while True:
 d,p=s.recvfrom(65535);s.sendto(json.dumps({'source':p,'payload':base64.b64encode(d).decode()}).encode(),p)
'''
HTTP_SERVER = '''from http.server import BaseHTTPRequestHandler,HTTPServer
import socket
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  d=bytes(range(256))*256
  self.send_response(200);self.send_header('Content-Length',str(len(d)))
  self.send_header('X-Source-IP',self.client_address[0]);self.end_headers();self.wfile.write(d)
 def log_message(self,*args):pass
server=HTTPServer((ADDR,49401),Handler);READY.touch();server.serve_forever()
'''


class EgressCheck:
    def __init__(self, root, cli, execute, vpn_server, nft_table, workers):
        self.root, self.cli, self.execute = root, cli, execute
        self.vpn_server, self.nft_table, self.workers = vpn_server, nft_table, workers
        self.names = ('wg-ei-lan-test', 'wg-ei-wan-test')
        self.servers, self.created, self.addresses = [], [], []
        self.stop = threading.Event()
        self.capture = None
        self.syn_mss = []

    def __enter__(self):
        try:
            self.setup()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def setup(self):
        for name in self.names:
            assert name not in run('ip', 'netns', 'list'), 'Test namespace exists'
        for i, name in enumerate(self.names):
            run('ip', 'netns', 'add', name)
            self.created.append(name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
            tap = 3910 + i
            for line in (f'create tap id {tap} host-ns {name} host-if-name mgmt0 host-ip4-addr 10.250.{i}.2/24',
                         f'set interface ip address tap{tap} 10.250.{i}.1/24',
                         f'set interface state tap{tap} up',
                         f'set interface rx-mode tap{tap} interrupt'):
                self.execute(line)
        run('ip', '-n', self.names[0], 'address', 'add', '10.250.0.3/24', 'dev', 'mgmt0')
        run('ip', '-n', self.names[0], 'route', 'add', 'default', 'via', '10.250.0.1')
        # Resolve the WAN neighbor before enabling inbound NAT, which would
        # reject an unsolicited WAN-local ping reply without a translation.
        self.cli('ping 10.250.1.2 repeat 2 interval 0.1')
        text = self.cli('ping 10.250.1.2 repeat 1')
        if '1 sent, 1 received' not in text:
            raise RuntimeError('WAN neighbor warmup failed')
        self.wan = ('198.18.200.1', '198.18.200.2')
        self.vpn = ('198.18.100.1', '198.19.100.1')
        for address in self.wan:
            run('ip', '-n', self.names[1], 'address', 'add', address + '/32', 'dev', 'lo')
        for address in self.vpn:
            run('ip', 'address', 'add', address + '/32', 'dev', self.vpn_server)
            self.addresses.append(address)
        for line in ('nat44 ei plugin enable sessions 4096',
                     'ip table add 101', 'create loopback interface instance 101',
                     'set interface ip table loop101 101', 'set interface state loop101 up',
                     'ip route add 0.0.0.0/0 table 101 via ip4-lookup-in-table 0',
                     'set interface nat44 ei out tap3911 output-feature',
                     'nat44 ei output-chain tap3911',
                     'set interface nat44 ei out wg1 output-feature',
                     'nat44 ei context wg1 loop101',
                     'nat44 ei add address 10.250.1.1 tenant-vrf 0',
                     'nat44 ei add address 10.253.95.2 tenant-vrf 101',
                     'set interface tcp-mss-clamp wg1 ip4 enable ip4-mss 1240 ip6 disable',
                     'ip route add 0.0.0.0/0 via 10.250.1.2 tap3911',
                     'ip route add 198.18.100.0/24 via 10.253.95.1 wg1',
                     'ip route add 198.19.100.0/24 via 10.253.95.1 wg1'):
            self.execute(line)
        for source in ('10.250.0.2', '10.250.0.3'):
            run('ip', 'netns', 'exec', self.names[0], 'ping', '-n', '-I', source,
                '-c', '2', '-W', '1', '10.250.0.1')
        ready_files = []
        for address in self.wan + self.vpn:
            prefix = ['ip', 'netns', 'exec', self.names[1]] if address in self.wan else []
            for program in (UDP_SERVER, HTTP_SERVER):
                ready = self.root / ('endpoint-ready-' + str(len(ready_files)))
                ready_files.append(ready)
                self.servers.append(subprocess.Popen(prefix + ['python3', '-u', '-c',
                    'from pathlib import Path\nREADY=Path(' + repr(str(ready)) + ')\nADDR=' + repr(address) + '\n' + program], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL))
        deadline = time.monotonic() + 5
        while not all(path.exists() for path in ready_files):
            if any(process.poll() is not None for process in self.servers) or time.monotonic() > deadline:
                raise RuntimeError('Test endpoints did not become ready')
            time.sleep(.02)
        self.raw = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
        self.raw.bind((self.vpn_server, 0))
        self.raw.settimeout(.1)
        def capture():
            while not self.stop.is_set():
                try:
                    packet = self.raw.recv(65535)
                except socket.timeout:
                    continue
                ihl = (packet[0] & 15) * 4
                if len(packet) < ihl + 20 or packet[9] != 6:
                    continue
                if socket.inet_ntoa(packet[12:16]) != '10.253.95.2' or packet[ihl+13] & 0x12 != 2:
                    continue
                end = ihl + (packet[ihl+12] >> 4) * 4
                cursor = ihl + 20
                while cursor < min(end, len(packet)):
                    kind = packet[cursor]
                    if kind == 0:
                        break
                    if kind == 1:
                        cursor += 1
                        continue
                    if cursor + 1 >= end:
                        break
                    size = packet[cursor+1]
                    if size < 2 or cursor + size > end:
                        break
                    if kind == 2 and size == 4:
                        self.syn_mss.append(int.from_bytes(packet[cursor+2:cursor+4], 'big'))
                    cursor += size
        self.capture = threading.Thread(target=capture)
        self.capture.start()

    def client(self, program, *args):
        return run('ip', 'netns', 'exec', self.names[0], 'python3', '-c', program, *args)

    def verify(self):
        # Readiness checks do not create transit translations or mask RPC loss.
        for process in self.servers:
            if process.poll() is not None:
                raise RuntimeError('Test endpoint failed to start')
        udp = '''import socket,json,base64,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],40123));s.settimeout(3)
targets=json.loads(sys.argv[2]);seen=[]
for i,address in enumerate(targets):
 payload=bytes(range(256))*4+str(i).encode();s.sendto(payload,(address,49400))
 data=json.loads(s.recvfrom(65535)[0]);assert base64.b64decode(data['payload'])==payload
 seen.append(data['source'])
assert [p[0] for p in seen]==['10.250.1.1','10.253.95.2','10.250.1.1','10.253.95.2'],seen
assert seen[0]==seen[2] and seen[1]==seen[3],seen
print(json.dumps(seen))
'''
        targets = [self.wan[0], self.vpn[0], self.wan[1], self.vpn[1]]
        observed = {}
        for source in ('10.250.0.2', '10.250.0.3'):
            observed[source] = json.loads(self.client(udp, source, json.dumps(targets)))
            for address in targets:
                text = run('ip', 'netns', 'exec', self.names[0], 'ping', '-n', '-I', source,
                           '-c', '3', '-i', '.1', '-W', '1', address)
                if '3 packets transmitted, 3 received' not in text:
                    raise RuntimeError('Translated ICMP return path failed')
                expected = '10.250.1.1' if address in self.wan else '10.253.95.2'
                program = '''import http.client,sys
c=http.client.HTTPConnection(sys.argv[2],49401,timeout=5,source_address=(sys.argv[1],0))
c.request('GET','/');r=c.getresponse();assert r.status==200
assert r.getheader('X-Source-IP')==sys.argv[3]
assert r.read()==bytes(range(256))*256;c.close()
'''
                self.client(program, source, address, expected)
        if len(self.syn_mss) < 4 or any(value != 1240 for value in self.syn_mss):
            raise RuntimeError('Plaintext TCP SYN MSS was not clamped before WG encryption')
        # Only this test TAP is blocked; ordinary WAN traffic must keep working
        # and VPN destinations must not silently fall back to the WAN.
        run('nft', '-f', '-', input=f'''add chain ip {self.nft_table} outage {{ type filter hook input priority -10; policy accept; }}
add rule ip {self.nft_table} outage iifname "vrouter-wg-proxy" udp dport 49342 counter drop
''')
        outage = '''import socket,json,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.250.0.2',40124));s.settimeout(1)
s.sendto(b'outage-vpn',('198.18.100.1',49400))
try:s.recvfrom(65535)
except socket.timeout:pass
else:raise AssertionError('VPN replied while transport was blocked')
s.sendto(b'outage-wan',('198.18.200.1',49400));d=json.loads(s.recvfrom(65535)[0])
assert d['source'][0]=='10.250.1.1'
'''
        try:
            self.client(outage)
        finally:
            run('nft', 'flush', 'chain', 'ip', self.nft_table, 'outage')
            run('nft', 'delete', 'chain', 'ip', self.nft_table, 'outage')
        recovery = '''import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.250.0.2',40124));s.settimeout(3)
s.sendto(b'recovery',('198.18.100.1',49400));d=json.loads(s.recvfrom(65535)[0])
assert d['source'][0]=='10.253.95.2'
'''
        self.client(recovery)
        sessions = self.cli('show nat44 ei sessions detail')
        owners = {int(thread) for thread, count in re.findall(
            r'thread (\d+) [^:]+: (\d+) sessions', sessions) if int(count)}
        if self.workers and owners != {1, 2}:
            raise RuntimeError('Both NAT workers must own sessions')
        return {'destination_split': True, 'udp_endpoint_independence': observed,
                'tcp_64k_integrity': True, 'icmp_return': True,
                'plaintext_syn_mss': list(self.syn_mss), 'session_owner_threads': sorted(owners),
                'vpn_outage_wan_survives_and_vpn_recovers': True}

    def __exit__(self, *unused):
        self.stop.set()
        if self.capture is not None:
            self.capture.join(timeout=2)
        if hasattr(self, 'raw'):
            self.raw.close()
        for process in self.servers:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=3)
        for address in self.addresses:
            run('ip', 'address', 'del', address + '/32', 'dev', self.vpn_server)
        for name in self.created:
            run('ip', 'netns', 'delete', name)
