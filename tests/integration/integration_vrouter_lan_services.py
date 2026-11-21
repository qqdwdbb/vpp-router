#!/usr/bin/env python3
"""Isolated VPP LAN gateway + Linux TAP DHCP/DNS + EI WAN test."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

from integration_wireguard_interface_peer import run
from integration_vrouter_dns_route_gate import wait_for


def child_server(role, root):
    if role == 'upstream':
        gate = runpy.run_path('/opt/vpp-vrouter-migration/source/scripts/dns-route-gate.py')
        def answer(query):
            ident, _, _, _ = gate['decode'](query)
            name, end = gate['name_at'](query, 12)
            qtype = struct.unpack_from('!H', query, end)[0]
            if qtype == 28:
                ip = '2001:db8:2080::78' if name.startswith('tcp.') else '2001:db8:2080::77'
                packed = socket.inet_pton(socket.AF_INET6, ip)
            else:
                ip = '198.51.100.77' if name.endswith('altroute.test') else '198.51.100.80'
                packed = socket.inet_aton(ip)
            return (struct.pack('!6H', ident, 0x8180, 1, 1, 0, 0) + query[12:end+4] +
                    b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 60, len(packed)) + packed)
        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                query, sock = self.request
                sock.sendto(answer(query), self.client_address)
        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                size = struct.unpack('!H', gate['read_exact'](self.request, 2))[0]
                packet = answer(gate['read_exact'](self.request, size))
                self.request.sendall(struct.pack('!H', len(packet)) + packet)
        with socketserver.ThreadingUDPServer(('127.0.0.1', 5354), UDP) as udp:
            with socketserver.ThreadingTCPServer(('127.0.0.1', 5354), TCP) as tcp:
                threading.Thread(target=udp.serve_forever, daemon=True).start()
                (root / 'upstream-ready').touch()
                tcp.serve_forever()
    else:
        from http.server import BaseHTTPRequestHandler, HTTPServer
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                data = json.dumps({'source': self.client_address[0]}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args):
                pass
        with HTTPServer(('0.0.0.0', 49401), Handler) as server:
            (root / 'wan-ready').touch()
            server.serve_forever()


QUERY = '''import socket,struct,json,sys
name=sys.argv[1];tcp=sys.argv[2]=='tcp';expect_failure=sys.argv[3]=='fail'
host=sys.argv[4] if len(sys.argv)>4 else '198.18.44.2';qtype=int(sys.argv[5]) if len(sys.argv)>5 else 1
q=struct.pack('!6H',1234,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+bytes([0])+struct.pack('!HH',qtype,1)
def exact(s,n):
 d=b''
 while len(d)<n:
  x=s.recv(n-len(d))
  if not x:raise OSError('closed')
  d+=x
 return d
try:
 with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,type=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
  s.settimeout(3);s.connect((host,53))
  if tcp:
   s.sendall(struct.pack('!H',len(q))+q);data=exact(s,struct.unpack('!H',exact(s,2))[0])
  else:s.send(q);data=s.recv(65535)
 rcode=struct.unpack_from('!H',data,2)[0]&15
 if expect_failure:assert rcode!=0,'DNS bypassed stopped gate'
 else:
  assert rcode==0
  if qtype==28:
   assert socket.inet_ntop(socket.AF_INET6,data[-16:])==('2001:db8:2080::78' if name.startswith('tcp.') else '2001:db8:2080::77')
  else:assert socket.inet_ntoa(data[-4:])=='198.51.100.77'
except OSError:
 if not expect_failure:raise
print(json.dumps({'tcp':tcp,'blocked':expect_failure}))
'''


def main(workers, tproxy=False, ipv6=False, nat66=False, recovery=False, vpn_dns_policy=None):
    assert not recovery or (ipv6 and not tproxy and not nat66), "Recovery requires a separate IPv6 LAN scenario"
    base = Path('/opt/vpp-vrouter-migration')
    script = base / 'source/tests/integration_vrouter_lan_services.py'
    names = ('vrouter-lan-client', 'vrouter-linux-dns', 'vrouter-lan-wan')
    assert all(name not in run('ip', 'netns', 'list') for name in names)
    unit = 'vrouter-lan-vpp-' + str(os.getpid())
    env = dict(os.environ, PATH='/opt/vpp-nic1-test/vpp/bin:' + os.environ['PATH'],
               LD_LIBRARY_PATH=(str(base / 'ipv6-pd/lib') + ':' if ipv6 else '') + '/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:'
               '/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu',
               PYTHONPATH=str(base / 'runtime/python'),
               VPP_API_DIR='/opt/vpp-nic1-test/vpp/share/vpp/api')
    os.environ.update(env)
    sys.path.insert(0, env['PYTHONPATH'])
    os.umask(0o077)
    children, created = [], []
    recovery_scenario = None
    with tempfile.TemporaryDirectory(prefix='vrouter-lan-', dir='/run') as directory, ExitStack() as stack:
        root = Path(directory)
        try:
            for name in names:
                run('ip', 'netns', 'add', name)
                created.append(name)
                run('ip', '-n', name, 'link', 'set', 'lo', 'up')
            plugins = ['wireguard_plugin.so', 'tap_plugin.so', 'ping_plugin.so',
                       'nat44_ei_plugin.so', 'nat_ei_context_plugin.so', 'acl_plugin.so',
                       'dhcp_plugin.so', 'wg_nat_order_plugin.so', 'mss_clamp_plugin.so']
            binary = '/opt/vpp-nic1-test/vpp/bin/vpp'
            if nat66:
                runtime = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='lan-nat66-', dir=base/'wireguard-interface-peer')))
                (runtime/'bin').mkdir()
                shutil.copy2(binary, runtime/'bin/vpp')
                shutil.copytree(base/'crypto_engines', runtime/'lib/aarch64-linux-gnu/vpp_crypto_engines')
                binary = str(runtime/'bin/vpp')
                plugins.append('nat66_plugin.so')
            (root / 'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
{'cpu { main-core 4 corelist-workers 5-6 }' if workers else ''}
plugins {{ path {base}/plugins
plugin default {{ disable }}
{chr(10).join('plugin ' + name + ' { enable }' for name in plugins)}
}}
''')
            run('systemd-run', '--unit=' + unit, '--property=RuntimeMaxSec=' + ('240' if ipv6 else '150'),
                '--property=KillMode=control-group', '--setenv=LD_LIBRARY_PATH=' + env['LD_LIBRARY_PATH'],
                binary, '-c', str(root / 'startup.conf'))
            wait_for(lambda: (root / 'cli.sock').exists(), 'VPP did not start')
            if ipv6:
                vpp_pid = run('systemctl', 'show', unit, '--property=MainPID', '--value').strip()
                assert str(base / 'ipv6-pd/lib/libvnet.so.26.06.0') in Path('/proc', vpp_pid, 'maps').read_text()
            rebuild_commands = []
            def cli(command):
                text = run('vppctl', '-s', str(root / 'cli.sock'), command)
                if any(word in text.lower() for word in ('error:', 'failed', 'unknown input', 'invalid')):
                    raise RuntimeError('VPP LAN fixture command failed; output suppressed')
                if recovery and not command.startswith(('show ', 'ping ', 'exec ')):
                    rebuild_commands.append(command)
                return text
            def execute(lines):
                (root / 'commands.conf').write_text('\n'.join(lines) + '\n')
                result = cli('exec ' + str(root / 'commands.conf'))
                if recovery:rebuild_commands.extend(lines)
                return result
            commands = ['create bridge-domain 3950', 'create loopback interface instance 3950',
                        'set interface ip address loop3950 198.18.44.1/24',
                        'set interface state loop3950 up', 'set interface l2 bridge loop3950 3950 bvi']
            for i, name in enumerate(names):
                address = '' if i == 0 else ' host-ip4-addr ' + ('198.18.44.2/24' if i == 1 else '198.18.45.2/24')
                commands += [f'create tap id {3950+i} host-ns {name} host-if-name mgmt0{address}',
                             f'set interface state tap{3950+i} up',
                             f'set interface rx-mode tap{3950+i} interrupt']
                if i < 2:
                    commands.append(f'set interface l2 bridge tap{3950+i} 3950')
            commands += ['set interface ip address tap3952 198.18.45.1/24',
                         f'wireguard create instance 1 listen-port 49916 private-key {run("wg", "genkey").strip()} src 192.0.2.250',
                         'set interface ip address wg1 10.62.30.2/24', 'set interface state wg1 up']
            execute(commands)
            if vpn_dns_policy:
                execute(['set interface ip address wg1 10.62.10.1/24',
                         'set punt udp 53', 'set punt tcp all',
                         'ip punt redirect rx loop3950 via 198.18.44.2 loop3950'])
            run('ip', '-n', names[1], 'link', 'add', 'br-mgmt', 'type', 'bridge')
            run('ip', '-n', names[1], 'link', 'set', 'mgmt0', 'master', 'br-mgmt')
            run('ip', '-n', names[1], 'address', 'del', '198.18.44.2/24', 'dev', 'mgmt0')
            run('ip', '-n', names[1], 'address', 'add', '198.18.44.2/24', 'dev', 'br-mgmt')
            run('ip', '-n', names[1], 'link', 'set', 'br-mgmt', 'up')
            run('ip', '-n', names[1], 'route', 'add', 'default', 'via', '198.18.44.1')
            cli('ping 198.18.45.2 repeat 2 interval 0.1')
            execute(['nat44 ei plugin enable sessions 4096',
                     'set interface nat44 ei out tap3952 output-feature',
                     'nat44 ei output-chain tap3952', 'nat44 ei add address 198.18.45.1 tenant-vrf 0',
                     'ip route add 0.0.0.0/0 via 198.18.45.2 tap3952'])
            def nsrun(name, *args, input=None):
                result = subprocess.run(['ip', 'netns', 'exec', name, *args], input=input,
                                        capture_output=True, text=True, timeout=15)
                if result.returncode:
                    raise RuntimeError('Isolated namespace command failed: ' + result.stderr[-1500:])
                return result.stdout
            nsrun(names[1], 'nft', '-f', '-', input='''table inet vrouter_lan_dns {
set altroute { type ipv4_addr; }
chain prerouting {
type nat hook prerouting priority dstnat; policy accept;
iifname "br-mgmt" ip daddr 198.18.44.2 meta l4proto { tcp, udp } th dport 53 counter redirect to :1053
}
}
''')
            if vpn_dns_policy:
                policy = vpn_dns_policy.read_text().replace('10.61.20.2', '198.18.44.2')
                nsrun(names[1], 'nft', '-f', '-', input=policy)
            if ipv6:
                nsrun(names[1], 'sysctl', '-qw', 'net.ipv6.conf.br-mgmt.accept_ra=0',
                      'net.ipv6.conf.br-mgmt.autoconf=0')
                nsrun(names[1], 'ip', '-6', 'address', 'add', 'fd42:1111:2222:10::2/64', 'dev', 'br-mgmt', 'nodad')
                nsrun(names[1], 'ip', '-6', 'route', 'replace', 'default', 'via', 'fd42:1111:2222:10::1')
                nsrun(names[1], 'nft', '-f', '-', input='''add set inet vrouter_lan_dns proxylist6 { type ipv6_addr; }
add rule inet vrouter_lan_dns prerouting iifname "br-mgmt" ip6 daddr fd42:1111:2222:10::2 meta l4proto { tcp, udp } th dport 53 counter redirect to :1053
''')
            rules = root / 'rules'
            rules.mkdir()
            (rules / 'altroute.conf').write_text('nftset=/altroute.test/4#inet#vrouter_lan_dns#altroute\n')
            if ipv6:
                (rules / 'proxylist6.conf').write_text('nftset=/six.test/6#inet#vrouter_lan_dns#proxylist6\n')
            ipv6_dns_config = '''listen-address=fd42:1111:2222:10::2
enable-ra
dhcp-range=::,constructor:br-mgmt,ra-stateless,ra-names,5m
ra-param=br-mgmt,4,0
dhcp-option=option6:dns-server,[fd42:1111:2222:10::2]
conf-file={rules}/proxylist6.conf
'''.format(rules=rules) if ipv6 else ''
            (root / 'dnsmasq.conf').write_text(f'''interface=br-mgmt
listen-address=198.18.44.2
bind-interfaces
no-resolv
no-hosts
server=127.0.0.1#5354
cache-size=0
dhcp-authoritative
dhcp-range=198.18.44.100,198.18.44.120,255.255.255.0,5m
dhcp-option=3,198.18.44.1
dhcp-option=6,198.18.44.2
conf-file={rules}/altroute.conf
{ipv6_dns_config}''')
            config = {'vpp_socket': str(root / 'cli.sock'), 'api_socket': str(root / 'api.sock'),
                      'vpp_service': unit, 'state_file': str(root / 'state.json'),
                      'state_socket': str(root / 'state.sock'), 'lock_files': [str(root / 'import.lock')],
                      'mappings': [{'family': 'inet', 'table': 'vrouter_lan_dns', 'set': 'altroute',
                                    'interface': 'wg1', 'via': '10.62.30.1', 'fib_table': 0}]}
            if ipv6:
                config['mappings'].append({'family': 'inet', 'table': 'vrouter_lan_dns', 'set': 'proxylist6',
                                           'interface': 'loop3950', 'via': 'fd42:1111:2222:10::2', 'fib_table': 0})
            (root / 'routes.json').write_text(json.dumps(config))
            (root / 'gate.json').write_text(json.dumps({
                'sync_program': str(base / 'source/scripts/nftset-route-sync.py'),
                'route_config': str(root / 'routes.json'), 'rules_directory': str(rules),
                'lease_file': str(root / 'seen.json'), 'upstream': ['198.18.44.2', 53],
                'listen': [['198.18.44.2', 1053]] + ([['fd42:1111:2222:10::2', 1053]] if ipv6 else [])}))
            log = stack.enter_context((root / 'processes.log').open('w+'))
            def spawn(name, *args):
                child = subprocess.Popen(['ip', 'netns', 'exec', name, *args], env=env, stdout=log, stderr=log)
                children.append(child)
                return child
            spawn(names[1], 'python3', str(script), '--server', 'upstream', '--root', str(root))
            spawn(names[2], 'python3', str(script), '--server', 'wan', '--root', str(root))
            wait_for(lambda: (root / 'upstream-ready').exists() and (root / 'wan-ready').exists(), 'Test servers not ready')
            dnsmasq = spawn(names[1], 'dnsmasq', '--keep-in-foreground', '--user=root',
                            '--conf-file=' + str(root / 'dnsmasq.conf'),
                            '--dhcp-leasefile=' + str(root / 'dhcp.leases'), '--pid-file=' + str(root / 'dnsmasq.pid'),
                            '--log-facility=-')
            gate = spawn(names[1], 'python3', str(base / 'source/scripts/dns-route-gate.py'),
                         '--config', str(root / 'gate.json'))
            def ready():
                if gate.poll() is not None or dnsmasq.poll() is not None:
                    raise RuntimeError('LAN service exited')
                result = subprocess.run(['ip', 'netns', 'exec', names[1], 'python3', '-c',
                    'import socket; s=socket.create_connection(("198.18.44.2",1053),.2);s.close()'], capture_output=True)
                return result.returncode == 0
            wait_for(ready, 'DNS gate did not start')
            lease = json.loads(nsrun(names[0], 'python3', str(base / 'source/tests/vrouter_dhcp_client.py')))
            nsrun(names[0], 'ping', '-n', '-c', '2', '-W', '1', lease['gateway'])
            ping = nsrun(names[0], 'ping', '-n', '-c', '3', '-i', '.1', '-W', '1', lease['gateway'])
            assert '3 packets transmitted, 3 received' in ping
            for mode in ('udp', 'tcp'):
                nsrun(names[0], 'python3', '-c', QUERY, 'a.altroute.test', mode, 'ok')
                if vpn_dns_policy:
                    nsrun(names[0], 'python3', '-c', QUERY, 'a.altroute.test', mode, 'ok', '10.62.10.1')
            assert '198.51.100.77/32' in cli('show ip fib table 0 198.51.100.77/32')
            assert 'wg1' in cli('show ip fib table 0 198.51.100.77/32')
            nsrun(names[0], 'ping', '-n', '-c', '2', '-W', '1', '198.18.45.2')
            data = nsrun(names[0], 'python3', '-c',
                'import urllib.request,json;print(urllib.request.urlopen("http://198.18.45.2:49401",timeout=3).read().decode())')
            assert json.loads(data)['source'] == '198.18.45.1'
            ipv6_result = None
            if ipv6:
                from integration_vrouter_ipv6_pd import check as check_ipv6
                nat66_check = None
                if nat66:
                    from integration_vrouter_nat66 import Check
                    nat66_check = Check(root, names, created, cli, spawn, nsrun, wait_for)
                pd_runtime = {} if recovery else None
                ipv6_result = check_ipv6(root, names, nsrun, cli, spawn, wait_for, nat66_check, pd_runtime, prepare_recovery=recovery)
                from integration_vrouter_ipv6_dns import check as check_dns6
                ipv6_result['dns'] = check_dns6(root, names, nsrun, cli, wait_for, QUERY)
                if recovery:
                    from integration_vrouter_lan_recovery import Recovery
                    recovery_scenario = Recovery(root,names,unit,run,nsrun,cli,spawn,wait_for,
                                                 rebuild_commands,lease,QUERY)
                    ipv6_result['joint_recovery'] = recovery_scenario.verify(pd_runtime,gate,dnsmasq)
            proxy_result = None
            if tproxy:
                from integration_vrouter_shared_tproxy import check
                proxy_result = check(root, names, nsrun, cli, spawn, wait_for, config)
                renewed = json.loads(nsrun(names[0], 'python3', str(base / 'source/tests/vrouter_dhcp_client.py')))
                assert renewed['address'] == lease['address'] and renewed['renewal']
                proxy_result['dhcp_after_tproxy'] = True
                for mode in ('udp', 'tcp'):
                    nsrun(names[0], 'python3', '-c', QUERY, 'a.altroute.test', mode, 'ok')
                data = nsrun(names[0], 'python3', '-c',
                    'import urllib.request;print(urllib.request.urlopen("http://198.18.45.2:49401",timeout=3).read().decode())')
                assert json.loads(data)['source'] == '198.18.45.1'
            gate.terminate()
            gate.wait(timeout=8)
            for mode in ('udp', 'tcp'):
                nsrun(names[0], 'python3', '-c', QUERY, 'bypass.test', mode, 'fail')
                if vpn_dns_policy:
                    nsrun(names[0], 'python3', '-c', QUERY, 'bypass.test', mode, 'fail', '10.62.10.1')
            if ipv6:
                for mode in ('udp', 'tcp'):
                    nsrun(names[0], 'python3', '-c', QUERY, 'bypass.test', mode, 'fail', 'fd42:1111:2222:10::2', '28')
                ipv6_result['dns']['gate_stopped_no_bypass'] = True
            result = {'workers': workers, 'dhcp': lease, 'gateway_in_vpp': True,
                      'linux_address_on_bridge': True,
                      'linux_dns_over_l2_tap': True, 'udp_tcp_dns_barrier': True,
                      'dns_route_via_binary_api': True, 'wan_nat44_ei': True,
                      'gate_stopped_no_dns_bypass': True, 'production_network_changed': False}
            if ipv6_result is not None:
                result['ipv6'] = ipv6_result
            if proxy_result is not None:
                result['tproxy'] = proxy_result
            if vpn_dns_policy:
                result['vpn_dns'] = {'frontend': '10.62.10.1:53', 'tcp_udp': True,
                                     'gate_listener_dnat': True, 'gate_stopped_no_bypass': True,
                                     'encrypted_wireguard_client': False}
            (base / f'logs/lan-services-workers{workers}{"-ipv6" if ipv6 else ""}{"-recovery" if recovery else ""}{"-vpn-dns" if vpn_dns_policy else ""}.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result))
        except Exception:
            if recovery:
                diagnostic = {}
                for name in ('ra-events.jsonl','pd-events.jsonl','pd-state.json','recovery-wan4-ping.log','recovery-wan6-ping.log','rebuild.json'):
                    path = root/name
                    if path.exists():diagnostic[name] = path.read_text()
                diagnostic['client_ipv6_addresses'] = run('ip','-n',names[0],'-j','-6','address','show')
                diagnostic['client_addresses'] = run('ip','-n',names[0],'-j','address','show')
                diagnostic['wan_addresses'] = run('ip','-n',names[2],'-j','address','show')
                for role in (0,2):
                    for kind in ('route','neigh'):
                        diagnostic[names[role]+'-'+kind] = run('ip','-n',names[role],'-j','-6',kind,'show')
                        diagnostic[names[role]+'-'+kind+'-v4'] = run('ip','-n',names[role],'-j',kind,'show')
                for command in ('show ip6 fib','show ip6 neighbors','show ip fib','show ip neighbors','show nat44 ei sessions','show nat44 ei interfaces','show error','show interface address'):
                    try:diagnostic[command] = cli(command)
                    except (RuntimeError,OSError):pass
                (base/'logs/lan-recovery-failure.json').write_text(json.dumps(diagnostic,indent=2)+'\n')
            if 'log' in locals():
                log.flush()
                print((root / 'processes.log').read_text()[-5000:], flush=True)
            raise
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=3)
            subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=20)
            if recovery_scenario:
                recovery_scenario.close()
            for name in created:
                subprocess.run(['ip', 'netns', 'delete', name], capture_output=True, timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, choices=(0, 2), default=0)
    parser.add_argument('--nat66', action='store_true')
    parser.add_argument('--ipv6', action='store_true')
    parser.add_argument('--tproxy', action='store_true')
    parser.add_argument('--recovery', action='store_true')
    parser.add_argument('--vpn-dns-policy', type=Path)
    parser.add_argument('--server', choices=('upstream', 'wan'))
    parser.add_argument('--root', type=Path)
    args = parser.parse_args()
    if args.nat66 and not args.ipv6:
        parser.error('--nat66 requires --ipv6')
    child_server(args.server, args.root) if args.server else main(args.workers, args.tproxy, args.ipv6, args.nat66, args.recovery, args.vpn_dns_policy)
