"""Root/server-only: production LAN -> WAN / temporary wg1 peer EI test."""
import argparse
import ipaddress
from pathlib import Path
import json
import os
import re
import runpy
import subprocess
import tempfile
import time


def run(*args, input_text=None):
    result = subprocess.run(args, input=input_text, capture_output=True, text=True, timeout=20)
    if result.returncode:
        detail = re.sub(r'[A-Za-z0-9+/]{40,}={0,2}', '[redacted]', result.stderr[-600:])
        raise RuntimeError('test command failed: ' + args[0] + ': ' + detail + '\n' + result.stdout[-700:])
    return result.stdout


def probe_address(namespace, device, address):
    program = '''import socket,struct,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x806));s.bind((DEVICE,0));s.settimeout(.2);mac=s.getsockname()[4];target=socket.inet_aton(ADDRESS)
frame=b'\\xff'*6+mac+b'\\x08\\x06'+struct.pack('!HHBBH',1,0x800,6,4,1)+mac+b'\\0'*4+b'\\0'*6+target
for i in range(3):
 s.send(frame);end=time.monotonic()+.4
 while time.monotonic()<end:
  try:d=s.recv(2048)
  except socket.timeout:continue
  if len(d)>=42 and d[28:32]==target:raise RuntimeError('test address occupied')
'''
    run('ip', 'netns', 'exec', namespace, 'python3', '-c',
        'DEVICE=' + repr(device) + ';ADDRESS=' + repr(address) + '\n' + program)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lan-bridge', required=True)
    parser.add_argument('--lan-client', required=True, type=ipaddress.IPv4Interface)
    parser.add_argument('--lan-gateway', required=True)
    parser.add_argument('--wan-parent', required=True, help='Linux parent interface for the WAN test macvlan')
    parser.add_argument('--wan-interface', required=True, help='VPP WAN interface')
    parser.add_argument('--wan-client', required=True, type=ipaddress.IPv4Interface)
    parser.add_argument('--wan-address', required=True, help='Expected VPP WAN NAT address')
    parser.add_argument('--wg-endpoint', required=True, help='WireGuard endpoint as ADDRESS:PORT')
    parser.add_argument('--wg-address', required=True, help='Expected VPP WireGuard NAT address')
    parser.add_argument('--wg-next-hop', required=True, help='Existing WireGuard route next hop')
    parser.add_argument('--wg-client', required=True, help='Temporary WireGuard peer IPv4 address')
    parser.add_argument('--wg-client-port', required=True, type=int)
    args = parser.parse_args()
    lan_client, wan_client = str(args.lan_client.ip), str(args.wan_client.ip)
    os.umask(0o077)
    lan, wan = 'ei-live-lan', 'ei-live-wan'
    helper = runpy.run_path('/usr/local/sbin/vpp-import-wireguard')
    gate = runpy.run_path('/usr/local/sbin/vpp-dns-route-gate')
    sync = gate['load_sync']('/usr/local/sbin/vpp-nft-route-sync')
    config = sync.load_config('/etc/vpp/nftset-route-sync.json')
    backend = sync.Backend(config)
    target = sync.Route(0, '198.18.1.1/32', args.wg_next_hop, 'wg1')
    direct = sync.Route(0, '198.18.1.2/32', wan_client, args.wan_interface)
    assert not backend.lookup([target, direct]), 'test routes in use'
    assert lan not in run('ip', 'netns', 'list') and wan not in run('ip', 'netns', 'list')
    peer = None
    keyfile = None
    servers = []
    added_set = False
    try:
        for name in (lan, wan):
            run('ip', 'netns', 'add', name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', 'ei-live-mac', 'link', args.wan_parent, 'address', '02:76:70:70:cc:0c', 'type', 'macvlan', 'mode', 'bridge')
        run('ip', 'link', 'set', 'ei-live-mac', 'netns', wan)
        run('ip', '-n', wan, 'link', 'set', 'ei-live-mac', 'up')
        probe_address(wan, 'ei-live-mac', wan_client)
        run('ip', '-n', wan, 'addr', 'add', str(args.wan_client), 'dev', 'ei-live-mac')
        run('ip', 'netns', 'exec', wan, 'tc', 'qdisc', 'add', 'dev', 'ei-live-mac', 'clsact')
        run('ip', 'netns', 'exec', wan, 'tc', 'filter', 'add', 'dev', 'ei-live-mac', 'egress', 'protocol', 'ip', 'matchall', 'action', 'csum', 'iph', 'udp', 'tcp')
        run('ip', 'link', 'add', 'ei-live-br', 'type', 'veth', 'peer', 'name', 'ei-live-cli')
        run('ip', 'link', 'set', 'ei-live-cli', 'netns', lan)
        run('ip', 'link', 'set', 'ei-live-br', 'master', args.lan_bridge)
        run('ip', 'link', 'set', 'ei-live-br', 'up')
        run('ip', '-n', lan, 'link', 'set', 'ei-live-cli', 'up')
        run('ethtool', '-K', 'ei-live-br', 'tx', 'off', 'gro', 'off', 'gso', 'off', 'tso', 'off')
        run('ip', 'netns', 'exec', lan, 'ethtool', '-K', 'ei-live-cli', 'tx', 'off', 'gro', 'off', 'gso', 'off', 'tso', 'off')
        probe_address(lan, 'ei-live-cli', lan_client)
        run('ip', '-n', lan, 'addr', 'add', str(args.lan_client), 'dev', 'ei-live-cli')
        run('ip', '-n', lan, 'route', 'add', 'default', 'via', args.lan_gateway)
        private = run('wg', 'genkey').strip()
        public = run('wg', 'pubkey', input_text=private + '\n').strip()
        server_private = re.search(r'(?mi)^PrivateKey\s*=\s*(\S+)', Path('/etc/wireguard/wg1.conf').read_text())[1]
        server_public = run('wg', 'pubkey', input_text=server_private + '\n').strip()
        fd, keyfile = tempfile.mkstemp(dir='/etc/wireguard', prefix='ei-live-', suffix='.conf')
        with os.fdopen(fd, 'w') as stream:
            stream.write(f'[Interface]\nPrivateKey = {private}\nListenPort = {args.wg_client_port}\n'
                         f'[Peer]\nPublicKey = {server_public}\nEndpoint = {args.wg_endpoint}\n'
                         f'AllowedIPs = {args.wg_address}/32\nPersistentKeepalive = 1\n')
        run('ip', '-n', wan, 'link', 'add', 'wgtest', 'type', 'wireguard')
        run('ip', 'netns', 'exec', wan, 'wg', 'setconf', 'wgtest', keyfile)
        run('ip', '-n', wan, 'addr', 'add', f'{args.wg_client}/32', 'dev', 'wgtest')
        run('ip', '-n', wan, 'link', 'set', 'wgtest', 'mtu', '1280', 'up')
        run('ip', '-n', wan, 'route', 'add', f'{args.wg_address}/32', 'dev', 'wgtest')
        for address in ('198.18.1.1', '198.18.1.2'):
            run('ip', '-n', wan, 'addr', 'add', address + '/32', 'dev', 'lo')
        helper['execute']([f'wireguard peer add wg1 public-key {public} endpoint {wan_client} '
                           f'dst-port {args.wg_client_port} allowed-ip 198.18.1.1/32 '
                           f'allowed-ip {args.wg_next_hop}/32 allowed-ip {args.wg_client}/32 '
                           'persistent-keepalive 1'])
        for block in re.split(r'(?m)(?=^\[\d+\])', helper['cli']('show wireguard peer')):
            if '198.18.1.1/32' in block:
                peer = re.match(r'^\[(\d+)\]', block)[1]
        assert peer is not None
        for _ in range(100):
            handshakes = run('ip', 'netns', 'exec', wan, 'wg', 'show', 'wgtest', 'latest-handshakes')
            if any(int(line.split()[-1]) > 0 for line in handshakes.splitlines()):
                break
            time.sleep(.05)
        else:
            raise RuntimeError('temporary WireGuard handshake was not established')
        time.sleep(.2)
        backend.apply([direct.command('add')])
        run('nft', 'add', 'element', 'inet', 'mangle', 'altroute', '{', '198.18.1.1', '}')
        added_set = True
        for _ in range(200):
            if sync.matches(target, backend.lookup([target])):
                break
            time.sleep(.02)
        assert sync.matches(target, backend.lookup([target]))
        udp = 'import socket,json; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("0.0.0.0",40000))\nwhile True:\n d,p=s.recvfrom(4096);s.sendto(json.dumps(p).encode(),p)'
        http = '''from http.server import BaseHTTPRequestHandler,HTTPServer
import json
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(json.dumps(self.client_address).encode())
 def log_message(self,*args):pass
HTTPServer(('0.0.0.0',40001),H).serve_forever()
'''
        for program in (udp, http):
            servers.append(subprocess.Popen(['ip', 'netns', 'exec', wan, 'python3', '-u', '-c', program]))
        time.sleep(.5)
        client = '''import socket,json,sys,urllib.request
lan_client,wan_address,wg_address=sys.argv[1:]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((lan_client,40123));s.settimeout(5)
observed=[]
for target in ('198.18.1.2','198.18.1.1','198.18.1.2','198.18.1.1'):
 print('UDP target',target,flush=True)
 s.sendto(b'test',(target,40000));d,_=s.recvfrom(4096);observed.append(json.loads(d))
assert [x[0] for x in observed]==[wan_address,wg_address,wan_address,wg_address],observed
assert observed[0]==observed[2] and observed[1]==observed[3],observed
print('PASS live WAN/wg1 EI, same source UDP port and independent mappings:',observed)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
for address,expected in (('198.18.1.2',wan_address),('198.18.1.1',wg_address)):
 data=json.load(opener.open('http://'+address+':40001',timeout=5));assert data[0]==expected,data;print('PASS live TCP HTTP source:',data)
'''
        try:
            print(run('ip', 'netns', 'exec', lan, 'python3', '-c', client, lan_client, args.wan_address, args.wg_address))
        except Exception:
            handshakes = run('ip', 'netns', 'exec', wan, 'wg', 'show', 'wgtest', 'latest-handshakes')
            print('temporary peer handshakes:', [int(line.split()[-1]) > 0 for line in handshakes.splitlines()], flush=True)
            print(helper['cli'](f'show nat44 ei sessions detail filter saddr {lan_client}'), flush=True)
            print('holding failed test for 10 seconds', flush=True)
            time.sleep(10)
            raise
        print(run('ip', 'netns', 'exec', lan, 'ping', '-c', '2', '-W', '2', '198.18.1.1'))
    finally:
        if added_set:
            subprocess.run(['nft', 'delete', 'element', 'inet', 'mangle', 'altroute', '{', '198.18.1.1', '}'], capture_output=True)
        for server in servers:
            server.terminate()
            server.wait(timeout=3)
        if peer is not None:
            helper['execute'](['wireguard peer remove ' + peer])
        # Stop before removing only this test prefix from the in-memory ledger.
        run('systemctl', 'stop', 'vpp-dns-route-gate')
        try:
            for path in (Path(config['state_file']), Path('/var/lib/vpp-nft-route-sync/dns-leases.json')):
                data = sync.read_json(path, [])
                if isinstance(data, dict):
                    for field in ('owned', 'pending_add'):
                        data[field] = [item for item in data.get(field, []) if item.get('prefix') != target.prefix]
                else:
                    data = [item for item in data if item.get('prefix') != target.prefix]
                sync.atomic_json(path, data)
            for route in (target, direct):
                if route.key in backend.lookup([route]):
                    backend.apply([route.command('del')])
        finally:
            run('systemctl', 'start', 'vpp-dns-route-gate')
            for name in (lan, wan):
                subprocess.run(['ip', 'netns', 'delete', name], capture_output=True)
            subprocess.run(['ip', 'link', 'delete', 'ei-live-br'], capture_output=True)
            if keyfile:
                Path(keyfile).unlink(missing_ok=True)


if __name__ == '__main__':
    main()
