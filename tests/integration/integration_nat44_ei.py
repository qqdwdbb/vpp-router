"""Root/server-only: isolated VPP, two EI egresses and same-source UDP flows."""
import json
import argparse
import importlib.util
import re
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def run(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        print(exc.output, flush=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin-path', default='/usr/lib/x86_64-linux-gnu/vpp_plugins')
    parser.add_argument('--workers', type=int, choices=(0, 2), default=0)
    parser.add_argument('--wan-identity', choices=('none','address','ports'), default='none')
    parser.add_argument('--nat-sessions', type=int, default=4096)
    parser.add_argument('--port-rollback-check', action='store_true')
    parser.add_argument('--reinit-nat', action='store_true')
    parser.add_argument('--host-fallback', action='store_true')
    parser.add_argument('--host-policy-source', type=Path)
    parser.add_argument('--shared-host-pool', action='store_true')
    args = parser.parse_args()
    if args.shared_host_pool and (args.host_fallback or not args.host_policy_source):
        parser.error('--shared-host-pool requires --host-policy-source and excludes --host-fallback')
    wan_pool = '10.250.1.4' if args.host_fallback else '10.250.1.1'
    names = ['ei-test-lan', 'ei-test-wan1', 'ei-test-wan2']
    if args.host_fallback or args.shared_host_pool:
        names.append('ei-test-host')
    servers = []
    process = None
    runtime = Path('/run/vpp-ei-test')
    assert not runtime.exists(), 'isolated runtime already exists'
    for name in names:
        assert name not in run('ip', 'netns', 'list'), 'test namespace already exists'
    try:
        for name in names:
            run('ip', 'netns', 'add', name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        runtime.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix='vpp-ei-test-') as directory:
            root = Path(directory)
            commands = []
            for i, name in enumerate(names):
                tap = 3101 + i
                commands += [f'create tap id {tap} host-ns {name} host-if-name mgmt0 host-ip4-addr 10.250.{i}.2/24',
                    f'set interface ip address tap{tap} 10.250.{i}.1/24',
                    f'set interface state tap{tap} up', f'set interface rx-mode tap{tap} interrupt']
            commands += [f'nat44 ei plugin enable sessions {args.nat_sessions}' +
                         (' users 1 user-sessions 128' if args.port_rollback_check else ''),
                'ip table add 101', 'create loopback interface instance 101',
                'set interface ip table loop101 101', 'set interface state loop101 up',
                'ip route add 0.0.0.0/0 table 101 via ip4-lookup-in-table 0',
                'set interface nat44 ei out tap3102 output-feature',
                'nat44 ei output-chain tap3102',
                'set interface nat44 ei out tap3103 output-feature',
                f'nat44 ei add address {wan_pool} tenant-vrf 0',
                'nat44 ei add address 10.250.2.1 tenant-vrf 101',
                'nat44 ei context tap3103 loop101',
                'ip route add 198.18.0.1/32 via 10.250.1.2 tap3102',
                'ip route add 198.18.0.3/32 via 10.250.1.2 tap3102',
                'ip route add 198.18.0.2/32 via 10.250.2.2 tap3103']
            if args.host_fallback:
                commands.append('nat44 ei add address 10.250.1.1 tenant-vrf 4094')
            if args.wan_identity == 'address':
                commands.append('nat44 ei add identity mapping external tap3102')
            elif args.wan_identity == 'ports':
                commands += [f'nat44 ei add identity mapping external tap3102 udp {port}'
                             for port in (500,4500,42008,42007,42006)]
            host_commands = ([
                f'nat44 ei pool receive {wan_pool} tap3102',
                'nat44 ei add static mapping local 10.250.3.2 external 10.250.1.1',
                'nat44 ei add static mapping local 10.250.0.2 60000 external 10.250.1.1 60000 udp',
            ] if args.host_fallback else [])
            if args.shared_host_pool:
                spec = importlib.util.spec_from_file_location('host_path', args.host_policy_source/'host-path.py')
                host_path = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(host_path)
                config = json.loads((args.host_policy_source/'services.json').read_text())
                config.update(gateway='10.250.3.1', host='10.250.3.2', wan_address=wan_pool,
                              wan_backend='10.250.4.2', wan_interface='tap3102')
                # This fixture tests VPP reservation/translation. Real cgroup
                # enforcement is exercised by integration_vrouter_turn_admission.
                for service in config['services']:
                    service.pop('owner_unit', None)
                config['services'].append(dict(name='fixed-fixture', protocol='udp', ports=[20267, 20268], wan=True))
                inventory = []
                mappings = host_path.static_mappings(config, [500, 4500, 42008, 42001, 42007, 42006])
                assert len(mappings) == 1007, len(mappings)
                pools = [line for line in commands if line.startswith(('nat44 ei add address ', 'nat44 ei add identity '))]
                commands = [line for line in commands if line not in pools]
                position = commands.index('set interface nat44 ei out tap3102 output-feature')
                commands[position:position] = pools+host_path.mapping_commands(config, mappings)
                commands += ['create tap id 3105 host-ns ei-test-host host-if-name vpp-hostsvc host-mac-addr 02:76:70:31:05:02 host-ip4-addr 10.250.4.2/30',
                             'set interface mac address tap3105 02:76:70:31:05:01',
                             'set interface ip address tap3105 10.250.4.1/30',
                             'set interface state tap3105 up', 'set interface rx-mode tap3105 interrupt',
                             'set ip neighbor tap3105 10.250.4.2 02:76:70:31:05:02',
                             f'nat44 ei pool receive {wan_pool} tap3102']
            (root / 'commands.conf').write_text('\n'.join(commands) + '\n')
            (root / 'startup.conf').write_text(f'''
unix {{ nodaemon runtime-dir {runtime} cli-listen {runtime}/cli.sock exec {root}/commands.conf }}
api-segment {{ prefix ei-test }}
socksvr {{ socket-name {runtime}/api.sock }}
statseg {{ socket-name {runtime}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
{'cpu { main-core 4 corelist-workers 5-6 }' if args.workers else ''}
plugins {{ path {args.plugin_path}
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
plugin nat44_ei_plugin.so {{ enable }}
plugin nat_ei_context_plugin.so {{ enable }}
plugin acl_plugin.so {{ enable }}
plugin dhcp_plugin.so {{ enable }}
plugin wireguard_plugin.so {{ enable }}
plugin mss_clamp_plugin.so {{ enable }}
plugin wg_nat_order_plugin.so {{ enable }}
plugin ipsec_ike_punt_plugin.so {{ enable }}
}}
''')
            with (root / 'vpp.log').open('w+') as log:
                process = subprocess.Popen(['vpp', '-c', str(root / 'startup.conf')], stdout=log, stderr=log)
                for _ in range(100):
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read()[-5000:])
                    if (runtime / 'cli.sock').exists():
                        try:
                            if 'tap3103' in run('vppctl', '-s', str(runtime / 'cli.sock'), 'show interface'):
                                break
                        except subprocess.CalledProcessError:
                            pass
                    time.sleep(.1)
                else:
                    log.seek(0)
                    raise RuntimeError('test interfaces not ready: ' + log.read()[-5000:])
                run('ip', '-n', names[0], 'route', 'add', 'default', 'via', '10.250.0.1')
                run('ip', '-n', names[0], 'address', 'add', '10.250.0.3/24', 'dev', 'mgmt0')
                for name, addresses in ((names[1], ['198.18.0.1', '198.18.0.3']), (names[2], ['198.18.0.2'])):
                    for address in addresses:
                        run('ip', '-n', name, 'address', 'add', address + '/32', 'dev', 'lo')
                    if args.shared_host_pool:
                        program = '''import socket,json,selectors
poll=selectors.DefaultSelector()
for address in ADDRESSES:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((address,40000));poll.register(s,selectors.EVENT_READ)
while True:
 for key,_ in poll.select():
  d,p=key.fileobj.recvfrom(4096);key.fileobj.sendto(json.dumps(p).encode(),p)
'''.replace('ADDRESSES', repr(addresses))
                    else:
                        program = 'import socket,json; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",40000))\nwhile True:\n d,p=s.recvfrom(4096); s.sendto(json.dumps(p).encode(),p)'
                    servers.append(subprocess.Popen(['ip', 'netns', 'exec', name, 'python3', '-u', '-c', program]))
                    http = '''from http.server import BaseHTTPRequestHandler,HTTPServer
import json
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  data=json.dumps(self.client_address).encode();self.send_response(200);self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
HTTPServer(('0.0.0.0',40001),Handler).serve_forever()
'''
                    servers.append(subprocess.Popen(['ip', 'netns', 'exec', name, 'python3', '-u', '-c', http]))
                # Resolve both directions before checking a one-shot UDP RPC.
                # With worker RX, learning from the first ARP request is async;
                # its immediate NAT reply can otherwise hit an unresolved glean.
                for source in ('10.250.0.2', '10.250.0.3'):
                    run('ip', 'netns', 'exec', names[0], 'ping', '-I', source,
                        '-c', '2', '-W', '2', '10.250.0.1')
                time.sleep(.2)
                if args.port_rollback_check:
                    probe = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind((sys.argv[1],0));s.settimeout(2)
s.sendto(b'probe',('198.18.0.1',40000))
if sys.argv[2]=='reply':
 assert s.recvfrom(100)[0], 'first NAT user did not receive a reply'
'''
                    run('ip', 'netns', 'exec', names[0], 'python3', '-c', probe,
                        '10.250.0.2', 'reply')
                    def busy_udp():
                        output = run('vppctl', '-s', str(runtime / 'cli.sock'),
                                     'show nat44 ei addresses')
                        section = output.split('10.250.1.1', 1)[1].split('10.250.2.1', 1)[0]
                        return int(re.search(r'(\d+) busy udp ports', section)[1])
                    before = busy_udp()
                    for _ in range(32):
                        run('ip', 'netns', 'exec', names[0], 'python3', '-c', probe,
                            '10.250.0.3', 'drop')
                    after = busy_udp()
                    errors = run('vppctl', '-s', str(runtime / 'cli.sock'), 'show errors')
                    assert 'cannot create NAT user' in errors, errors
                    assert before == after, f'failed users leaked UDP ports: {before} -> {after}'
                    print(f'PASS 32 rejected NAT users left busy UDP ports at {after}')
                    return
                if args.shared_host_pool:
                    run('ip', '-n', names[3], 'link', 'set', 'mgmt0', 'down')
                    run('ip', '-n', names[3], 'link', 'set', 'mgmt0', 'name', 'br-mgmt')
                    run('ip', '-n', names[3], 'link', 'set', 'br-mgmt', 'up')
                    run('ip', '-n', names[3], 'route', 'add', 'default', 'via', '10.250.3.1')
                    run('ip', '-n', names[3], 'neigh', 'replace', '10.250.4.1', 'lladdr', '02:76:70:31:05:01',
                        'nud', 'permanent', 'dev', 'vpp-hostsvc')
                    run('ip', 'netns', 'exec', names[3], 'sysctl', '-w', 'net.ipv4.conf.all.rp_filter=0',
                        'net.ipv4.conf.vpp-hostsvc.rp_filter=0')
                    def host_run(*command, **kwargs):
                        result = subprocess.run(['ip', 'netns', 'exec', names[3], *command],
                                                capture_output=True, text=True, **kwargs)
                        result.check_returncode()
                        return result.stdout
                    host_path.routing.install(config, host_run, root/'host-routing.json')
                    host_run('nft', '-f', '-', input=host_path.nft(config, inventory, owners={}))
                    echo = '''import socket,selectors
poll=selectors.DefaultSelector()
for port in (20267,42004,55000):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.250.3.2',port));poll.register(s,selectors.EVENT_READ)
while True:
 for key,_ in poll.select():
  data,peer=key.fileobj.recvfrom(4096);key.fileobj.sendto(b'host',peer)
'''
                    servers.append(subprocess.Popen(['ip', 'netns', 'exec', names[3], 'python3', '-u', '-c', echo]))
                    fw_spec = importlib.util.spec_from_file_location('shared_fw', args.host_policy_source.parent/'firewall/vrouter-firewall.py')
                    fw = importlib.util.module_from_spec(fw_spec);fw_spec.loader.exec_module(fw)
                    acl = fw.generate_vpp_acls({'vpp': dict(host_service_path=True, wan_ipv4=wan_pool, wan_gateway4='10.250.1.2')})['wan_in']
                    result = run('vppctl', '-s', str(runtime/'cli.sock'), 'set acl-plugin acl tag shared-nat-in '+acl)
                    index = re.search(r'ACL index:\s*(\d+)', result)[1]
                    run('vppctl', '-s', str(runtime/'cli.sock'), f'set acl-plugin interface tap3102 input acl {index}')
                    run('ip', 'netns', 'exec', names[3], 'ping', '-c', '2', '-W', '2', '10.250.3.1')
                    time.sleep(.2)
                    def check_shared_host():
                        inbound = '''import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.18.0.1',0));s.settimeout(3)
for port in (20267,42004,55000):
 print('PROBE fixed port',port,flush=True)
 s.sendto(b'probe',('10.250.1.1',port));data,peer=s.recvfrom(4096)
 assert data==b'host' and peer==('10.250.1.1',port),(data,peer)
print('PASS ordinary host and TURN fixed incoming ports on shared WAN')
'''
                        try:
                            print(run('ip', 'netns', 'exec', names[1], 'python3', '-c', inbound))
                        except subprocess.CalledProcessError:
                            for command in ('show errors', 'show interface address', 'show nat44 ei interfaces', 'show nat44 ei addresses',
                                            'show nat44 ei sessions detail'):
                                print(run('vppctl', '-s', str(runtime/'cli.sock'), command), flush=True)
                            print(run('ip', 'netns', 'exec', names[3], 'nft', 'list', 'table', 'ip', 'vrouter_host_path'))
                            print(run('ip', '-n', names[3], '-4', 'route', 'show', 'table', 'all'))
                            print(run('ip', '-n', names[3], '-4', 'addr', 'show'))
                            log.seek(0);print(log.read()[-3000:])
                            raise
                        active = '''import socket,json,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.250.3.2',int(sys.argv[1])));s.settimeout(3)
s.sendto(b'active',('198.18.0.1',40000));data,peer=s.recvfrom(4096);seen=json.loads(data)
assert seen[0]=='10.250.1.1',seen
if int(sys.argv[1]) in (20268,55001): assert seen[1]==int(sys.argv[1]),seen
print('PASS host active UDP source',sys.argv[1],seen)
'''
                        for port in (20268, 55001, 40125, 36145, 36146):
                            print(run('ip', 'netns', 'exec', names[3], 'python3', '-c', active, str(port)))
                        # Dynamic LAN sockets may use reserved local ports;
                        # only their external ports must avoid the reservations.
                        dynamic = '''import socket,json,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],int(sys.argv[2])));s.settimeout(3)
s.sendto(b'client',('198.18.0.1',40000));data,_=s.recvfrom(4096);seen=json.loads(data)
assert seen[0]=='10.250.1.1' and seen[1] not in (20267,20268,42004,42005) and not 49152<=seen[1]<=50151,seen
print(json.dumps(seen),flush=True)
data,peer=s.recvfrom(4096);assert data==b'new-peer' and peer[0]=='198.18.0.3',(data,peer)
print('PASS independent new UDP peer reaches existing client mapping',flush=True)
'''
                        for source, port in (('10.250.0.2', 20267), ('10.250.0.3', 55000)):
                            child = subprocess.Popen(['ip', 'netns', 'exec', names[0], 'python3', '-u', '-c', dynamic, source, str(port)],
                                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                            try:
                                first = child.stdout.readline()
                                if not first.startswith('['):
                                    remainder = child.stdout.read()
                                    child.wait(timeout=5)
                                    print(run('vppctl', '-s', str(runtime/'cli.sock'), 'show nat44 ei addresses'))
                                    static = run('vppctl', '-s', str(runtime/'cli.sock'), 'show nat44 ei static mappings')
                                    print('static mapping lines', len(static.splitlines()))
                                    log.seek(0);print(log.read()[-2000:])
                                    raise AssertionError(first+remainder)
                                seen=json.loads(first)
                                send = f'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("198.18.0.3",49999));s.sendto(b"new-peer",({seen[0]!r},{seen[1]}))'
                                run('ip', 'netns', 'exec', names[1], 'python3', '-c', send)
                                remainder = child.communicate(timeout=5)[0]
                                assert child.returncode == 0, remainder
                                print(remainder)
                            finally:
                                if child.poll() is None:
                                    child.kill();child.wait()
                    check_shared_host()
                client = '''import socket,json,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],40123));s.settimeout(3)
seen=[]
for address in ('198.18.0.1','198.18.0.2','198.18.0.3','198.18.0.2'):
 s.sendto(b'test',(address,40000));data,_=s.recvfrom(4096);seen.append(json.loads(data))
assert [p[0] for p in seen]==[sys.argv[2],'10.250.2.1',sys.argv[2],'10.250.2.1'],seen
assert seen[0]==seen[2] and seen[1]==seen[3],seen
print('PASS separate EI pools, return paths, same source port, per-domain endpoint independence:',sys.argv[1],seen)
print(json.dumps(seen))
'''
                before_mapping = {}
                if args.host_fallback:
                    # EI registers pool receive routes on every outside port;
                    # the last egress otherwise captures the WAN pool's ARP.
                    result = run('vppctl', '-s', str(runtime/'cli.sock'), host_commands[0])
                    assert not result.strip(), result
                    # No secondary WAN interface address or preinstalled neighbor:
                    # return traffic must resolve the unassigned pool address.
                    addresses = run('vppctl', '-s', str(runtime/'cli.sock'), 'show interface address')
                    assert wan_pool not in addresses, 'pool must not be a VPP interface address'
                    run('ip', '-n', names[1], 'neigh', 'flush', 'to', wan_pool, 'dev', 'mgmt0')
                    for source in ('10.250.0.2', '10.250.0.3'):
                        try:
                            output = run('ip', 'netns', 'exec', names[0], 'python3', '-c', client, source, wan_pool)
                        except subprocess.CalledProcessError:
                            for command in ('show errors', 'show ip fib 10.250.1.4/32', 'show nat44 ei addresses', 'show ip neighbors'):
                                print(run('vppctl', '-s', str(runtime/'cli.sock'), command), flush=True)
                            print(run('ip', '-n', names[1], 'neigh', 'show'), flush=True)
                            log.seek(0)
                            print(log.read()[-5000:], flush=True)
                            raise
                        before_mapping[source] = json.loads(output.splitlines()[-1])
                    neighbors = json.loads(run('ip', '-j', '-n', names[1], 'neigh', 'show', 'to', wan_pool, 'dev', 'mgmt0'))
                    assert len(neighbors) == 1 and neighbors[0].get('lladdr'), neighbors
                    assert not set(neighbors[0].get('state', [])) & {'FAILED', 'INCOMPLETE', 'PERMANENT'}, neighbors
                    owner = json.loads(run('ip', '-j', '-n', names[1], 'neigh', 'show', 'to', '10.250.1.1', 'dev', 'mgmt0'))
                    assert len(owner) == 1 and owner[0].get('lladdr') == neighbors[0]['lladdr'], (owner, neighbors)
                    fib = run('vppctl', '-s', str(runtime/'cli.sock'), f'show ip fib {wan_pool}/32')
                    assert f'dpo-receive: {wan_pool} on tap3102' in fib, fib
                    route = json.loads(run('ip', '-j', '-n', names[1], 'route', 'get', wan_pool))[0]
                    assert route['dev'] == 'mgmt0' and 'gateway' not in route, route
                    # Install the host fallback AFTER both workers own dynamic
                    # translations, then require the same external tuples below.
                    for command in host_commands[1:]:
                        result = run('vppctl', '-s', str(runtime/'cli.sock'), command)
                        assert not result.strip(), result
                    print('PASS separate non-interface NAT pool, on-link upstream ARP, existing sessions before host mapping')
                if args.host_fallback:
                    run('ip', '-n', names[3], 'route', 'add', 'default', 'via', '10.250.3.1')
                    same_port = before_mapping['10.250.0.2'][0][1]
                    for name, label, port in ((names[3], 'host', 60111), (names[0], 'native', 60000),
                                              (names[3], 'dns', 53), (names[3], 'dynamic', 40055),
                                              (names[3], 'same-port-host', same_port)):
                        program = f'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("0.0.0.0",{port}))\nwhile True:\n d,p=s.recvfrom(4096);s.sendto({label.encode()!r},p)'
                        servers.append(subprocess.Popen(['ip', 'netns', 'exec', name, 'python3', '-u', '-c', program]))
                    run('ip', 'netns', 'exec', names[3], 'ping', '-c', '2', '-W', '2', '10.250.3.1')
                    time.sleep(.2)
                    probe = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
for port,expected in ((60111,b'host'),(60000,b'native'),(60111,b'host')):
 s.sendto(b'probe',('10.250.1.1',port));data,peer=s.recvfrom(4096)
 assert data==expected and peer==('10.250.1.1',port),(data,peer)
 print('PASS host port',port,flush=True)
print('PASS address fallback, unchanged ports, exact mapping precedence')
s.sendto(b'same-port-different-external-address',('10.250.1.1',int(sys.argv[2])))
data,peer=s.recvfrom(4096)
assert data==b'same-port-host' and peer==('10.250.1.1',int(sys.argv[2])),(data,peer)
print('PASS identical external port on distinct host and client-pool addresses')
s.settimeout(.5);s.sendto(b'pool-must-not-reach-host',(sys.argv[1],60111))
try:
 s.recvfrom(4096)
 raise AssertionError('client pool forwarded an unsolicited host-service packet')
except TimeoutError:pass
print('PASS unsolicited host port on client pool is not forwarded')
'''
                    try:
                        print(run('ip', 'netns', 'exec', names[1], 'python3', '-c', probe, wan_pool, str(same_port)))
                    except subprocess.CalledProcessError:
                        for command in ('show errors', 'show nat44 ei static mappings', 'show nat44 ei sessions detail', 'show interface address'):
                            print(run('vppctl', '-s', str(runtime/'cli.sock'), command), flush=True)
                        log.seek(0)
                        print(log.read()[-5000:], flush=True)
                        raise
                    if args.host_policy_source:
                        spec = importlib.util.spec_from_file_location('host_path', args.host_policy_source/'host-path.py')
                        host_path = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(host_path)
                        config = json.loads((args.host_policy_source/'services.json').read_text())
                        config.update(gateway='10.250.0.1', host='10.250.3.3', wan_address='10.250.1.1',
                                      nat_pool='10.250.1.4', wan_backend='10.250.3.2')
                        run('ip', '-n', names[3], 'link', 'set', 'mgmt0', 'down')
                        run('ip', '-n', names[3], 'link', 'set', 'mgmt0', 'name', 'vpp-hostsvc')
                        run('ip', '-n', names[3], 'link', 'set', 'vpp-hostsvc', 'up')
                        run('ip', '-n', names[3], 'route', 'replace', 'default', 'via', '10.250.3.1')
                        run('ip', '-n', names[3], 'addr', 'add', '10.250.3.3/32', 'dev', 'lo')
                        # Production's default uses br-mgmt's host address (.2),
                        # not the dedicated ingress TAP address. Model that for
                        # wildcard UDP sockets, which select a source on send.
                        run('ip', '-n', names[3], 'route', 'replace', 'default', 'via', '10.250.3.1', 'src', '10.250.3.3')
                        def apply_policy(inventory):
                            subprocess.run(['ip', 'netns', 'exec', names[3], 'nft', '-f', '-'],
                                           input=host_path.nft(config, inventory), text=True, check=True)
                        def check_port(port, allowed):
                            code = f'''import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.5)
s.sendto(b'policy',('10.250.1.1',{port}))
try:
 data,peer=s.recvfrom(4096)
 assert {allowed!r},'unexpected WAN admission'
 assert peer==('10.250.1.1',{port}),peer
except TimeoutError:
 assert not {allowed!r},'unexpected WAN denial'
'''
                            run('ip', 'netns', 'exec', names[1], 'python3', '-c', code)
                        apply_policy([])
                        # This echo server is not in the coturn cgroup. A port
                        # inside the relay range must no longer admit it.
                        check_port(60111, False)
                        check_port(53, False)
                        check_port(40055, False)
                        apply_policy([dict(protocol='udp', port=40055, addresses=['0.0.0.0'], processes=['nebula'])])
                        check_port(40055, True)
                        apply_policy([])
                        check_port(40055, False)
                        print('PASS WAN DNAT/reverse path, private DNS and unowned TURN-range socket blocked, dynamic admission/revocation')
                if args.workers:
                    run('vppctl', '-s', str(runtime / 'cli.sock'), 'trace add tap-input 64')
                try:
                    for source in ('10.250.0.2', '10.250.0.3'):
                        output = run('ip', 'netns', 'exec', names[0], 'python3', '-c', client, source, wan_pool)
                        if before_mapping:
                            assert json.loads(output.splitlines()[-1]) == before_mapping[source], 'host mapping changed existing NAT tuples'
                        print(output)
                except subprocess.CalledProcessError:
                    for command in ('show errors', 'show interface', 'show threads',
                                    'show nat44 ei interfaces', 'show nat44 ei addresses',
                                    'show nat44 ei sessions detail',
                                    'show nat44 ei hash tables detail', 'show trace'):
                        print(run('vppctl', '-s', str(runtime / 'cli.sock'), command), flush=True)
                    raise
                for source in ('10.250.0.2', '10.250.0.3'):
                    for address, expected in (('198.18.0.1', wan_pool), ('198.18.0.2', '10.250.2.1')):
                        run('ip', 'netns', 'exec', names[0], 'ping', '-I', source, '-c', '2', '-W', '2', address)
                        code = f'import http.client,json; c=http.client.HTTPConnection("{address}",40001,timeout=3,source_address=("{source}",0)); c.request("GET","/"); data=json.loads(c.getresponse().read()); assert data[0]=="{expected}",data; c.close(); print("PASS TCP and ICMP", "{source}", data)'
                        print(run('ip', 'netns', 'exec', names[0], 'python3', '-c', code))
                if args.reinit_nat:
                    # Exercise live pool reinitialization without restarting VPP,
                    # interfaces, namespace services or either egress context.
                    run('vppctl', '-s', str(runtime / 'cli.sock'), 'nat44 ei plugin disable')
                    nat_commands = [command for command in commands+host_commands
                                    if command.startswith(('nat44 ei ', 'set interface nat44 ei '))]
                    if args.shared_host_pool:
                        path = root/'nat-reinit.conf';path.write_text('\n'.join(nat_commands)+'\n')
                        result = run('vppctl', '-s', str(runtime/'cli.sock'), 'exec '+str(path))
                        assert not result.strip(), result
                    else:
                        for command in nat_commands:
                            result = run('vppctl', '-s', str(runtime / 'cli.sock'), command)
                            assert not result.strip(), result
                    try:
                        for source in ('10.250.0.2', '10.250.0.3'):
                            print(run('ip', 'netns', 'exec', names[0], 'python3', '-c', client, source, wan_pool))
                            for address in ('198.18.0.1','198.18.0.2'):
                                run('ip', 'netns', 'exec', names[0], 'ping', '-I', source, '-c', '2', '-W', '2', address)
                    except subprocess.CalledProcessError:
                        for command in ('show errors', f'show ip fib {wan_pool}/32', 'show nat44 ei addresses', 'show nat44 ei interfaces', 'show nat44 ei sessions detail'):
                            print(run('vppctl', '-s', str(runtime/'cli.sock'), command), flush=True)
                        raise
                    print('PASS NAT pool reinitialization with both workers and egress contexts')
                    if args.shared_host_pool:
                        check_shared_host()
                sessions = run('vppctl', '-s', str(runtime / 'cli.sock'), 'show nat44 ei sessions detail')
                if args.workers:
                    owners = {int(thread) for thread, count in re.findall(
                        r'thread (\d+) [^:]+: (\d+) sessions', sessions) if int(count)}
                    assert owners == {1, 2}, f'Both workers must own sessions: {owners}'
                print(sessions, flush=True)
    finally:
        for server in servers:
            server.terminate()
            server.wait(timeout=3)
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        for name in names:
            subprocess.run(['ip', 'netns', 'delete', name], capture_output=True)
        if runtime.exists():
            for path in runtime.iterdir():
                if path.is_file() or path.is_socket():
                    path.unlink()
            runtime.rmdir()


if __name__ == '__main__':
    main()
