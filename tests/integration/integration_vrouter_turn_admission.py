#!/usr/bin/env python3
"""VROUTER/root: socket-cgroup admission with same-UID UDP port takeover."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time


def run(*args, input=None):
    result = subprocess.run(list(map(str, args)), input=input, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('TURN admission test command failed: '+str(args[0])+': '+result.stderr[-1000:])
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on VROUTER')
    spec = importlib.util.spec_from_file_location('turn_host_path', args.source/'host-path.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    config = json.loads((args.source/'services.json').read_text())
    config['dynamic_services'][0]['dedicated_ingress'] = True
    client, server = 'vrouter-turn-client', 'vrouter-turn-server'
    client_link, server_link = 'vrouter-turn-cli', 'vrouter-turn-srv'
    unit = 'vrouter-turn-admission-'+str(os.getpid())+'.service'
    unit_path = Path('/run/systemd/system', unit)
    program_path = Path('/run', unit+'.py')
    for name in (client, server):
        if name in run('ip', 'netns', 'list').split():
            raise ValueError('reserved test namespace exists')
    for name in (client_link, server_link):
        if Path('/sys/class/net', name).exists():
            raise ValueError('reserved test link exists')
    if unit_path.exists():
        raise ValueError('reserved test unit exists')
    if program_path.exists():
        raise ValueError('reserved test program exists')
    for service in config['services']:
        if service.get('owner_unit'):
            service['owner_unit'] = unit
    processes, created = [], []
    def ns(name, *command, input=None):
        return run('ip', 'netns', 'exec', name, *command, input=input)
    def wait_socket(port, tcp=False):
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            if any(row.split()[3].endswith(':'+str(port)) for row in ns(server, 'ss', '-H', '-lnt' if tcp else '-lnu').splitlines()):
                return
            time.sleep(.05)
        raise RuntimeError('test UDP listener not ready')
    def query(port, allowed, destination='10.63.20.2'):
        program = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',40123));s.settimeout(.4)
s.connect((sys.argv[1],int(sys.argv[2])));s.send(b'probe')
try:
 data=s.recv(4096)
 assert sys.argv[3]=='yes' and data in (b'turn',b'private'),data
except (TimeoutError,ConnectionRefusedError):
 assert sys.argv[3]=='no','expected a reply'
'''
        ns(server if destination == '127.0.0.1' else client, 'python3', '-c', program,
           destination, str(port), 'yes' if allowed else 'no')
    def query_tcp(allowed, destination='10.63.20.2'):
        program = '''import socket,sys
try:
 with socket.create_connection((sys.argv[1],42004),.4) as s:
  s.settimeout(.4);data=s.recv(4096)
  assert sys.argv[2]=='yes' and data in (b'turn',b'private'),data
except (TimeoutError,ConnectionRefusedError):
 assert sys.argv[2]=='no','expected TCP reply'
'''
        ns(server if destination == '127.0.0.1' else client, 'python3', '-c', program,
           destination, 'yes' if allowed else 'no')
    def query_active(protocol):
        program = '''import json,socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
s.sendto(('active-'+sys.argv[1]).encode(),('10.63.20.2',50000))
peer=json.loads(s.recv(4096));assert peer[0]=='10.63.20.2',peer
'''
        ns(client, 'python3', '-c', program, protocol)
    def private_echo(ports):
        program = '''import os,pwd,socket,selectors
account=pwd.getpwnam('turnserver');os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
poll=selectors.DefaultSelector()
for port in PORTS:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',port));poll.register(s,selectors.EVENT_READ)
while True:
 for key,_ in poll.select():
  data,peer=key.fileobj.recvfrom(4096);key.fileobj.sendto(b'private',peer)
'''.replace('PORTS', repr(ports))
        process = subprocess.Popen(['ip', 'netns', 'exec', server, 'python3', '-c', program])
        processes.append(process)
        for port in ports:
            wait_socket(port)
            query(port, True, '127.0.0.1')
        return process
    def apply(owners=None, inventory=None):
        text = host.nft(config, inventory or [], owners=owners)
        # Keep the host cgroup2 mount: ip netns exec remounts /sys and hides it.
        run('nsenter', '--net=/run/netns/'+server, '--', 'nft', '-f', '-', input=text)
        return text
    try:
        for name in (client, server):
            run('ip', 'netns', 'add', name)
            created.append(name)
            run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', client_link, 'type', 'veth', 'peer', 'name', server_link)
        run('ip', 'link', 'set', client_link, 'netns', client)
        run('ip', 'link', 'set', server_link, 'netns', server)
        run('ip', '-n', client, 'addr', 'add', '10.63.20.1/30', 'dev', client_link)
        run('ip', '-n', server, 'link', 'set', server_link, 'name', 'vpp-hostsvc')
        run('ip', '-n', server, 'addr', 'add', '10.63.20.2/30', 'dev', 'vpp-hostsvc')
        run('ip', '-n', server, 'addr', 'add', '10.61.20.2/32', 'dev', 'lo')
        run('ip', '-n', client, 'link', 'set', client_link, 'up')
        run('ip', '-n', server, 'link', 'set', 'vpp-hostsvc', 'up')
        # Force replies from wildcard sockets to use the DNAT destination.
        run('ip', '-n', server, 'route', 'replace', '10.63.20.1/32', 'dev', 'vpp-hostsvc', 'src', '10.61.20.2')
        private_echo([55000, 58000])
        initial = apply(owners={})
        assert '49152-50151' not in initial
        query(55000, False)
        echo = '''import socketserver,threading,json
class U(socketserver.BaseRequestHandler):
 def handle(self): self.request[1].sendto(json.dumps(self.client_address).encode(),self.client_address)
class T(socketserver.BaseRequestHandler):
 def handle(self): self.request.sendall(json.dumps(self.client_address).encode())
threading.Thread(target=socketserver.UDPServer(('10.63.20.1',40124),U).serve_forever,daemon=True).start()
socketserver.TCPServer(('10.63.20.1',40124),T).serve_forever()
'''
        processes.append(subprocess.Popen(['ip', 'netns', 'exec', client, 'python3', '-c', echo]))
        deadline = time.monotonic()+5
        while len([line for line in ns(client, 'ss', '-H', '-lnut').splitlines() if ':40124 ' in line]) < 2:
            if time.monotonic() > deadline:
                raise RuntimeError('active egress echo fixture not ready')
            time.sleep(.05)
        program_path.write_text('''import socketserver,threading,socket
class U(socketserver.BaseRequestHandler):
 def handle(self):
  data,reply=self.request
  if data in (b'active-udp',b'active-tcp'):
   udp=data==b'active-udp'
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
    s.settimeout(2);s.bind(('10.61.20.2',45001 if udp else 45002));s.connect(('10.63.20.1',40124))
    if udp: s.send(b'active')
    data=s.recv(4096)
  else: data=b'turn'
  reply.sendto(data,self.client_address)
class T(socketserver.BaseRequestHandler):
 def handle(self): self.request.sendall(b'turn')
class S(socketserver.TCPServer): allow_reuse_address=True
threading.Thread(target=socketserver.UDPServer(('0.0.0.0',50000),U).serve_forever,daemon=True).start()
S(('0.0.0.0',42004),T).serve_forever()
''')
        program_path.chmod(0o644)
        unit_path.write_text(f'''[Unit]
Description=Isolated TURN socket owner test
[Service]
Type=simple
User=turnserver
Group=turnserver
NetworkNamespacePath=/run/netns/{server}
ExecStart=/usr/bin/python3 -u {program_path}
''')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', unit)
        wait_socket(50000)
        wait_socket(42004, tcp=True)
        query(50000, True, '127.0.0.1')
        before = host.owner_cgroups(config)
        assert unit in before
        active = apply()
        assert 'socket cgroupv2' in active and '49152-50151' in active
        query(50000, True)
        query_tcp(True)
        query_active('udp')
        query_active('tcp')
        query(55000, False)
        query(58000, False)
        apply(inventory=[dict(protocol='udp', port=58000, addresses=['0.0.0.0'], processes=['nebula'])])
        query(58000, True)
        config['dynamic_services'][0]['wan'] = False
        apply(inventory=[dict(protocol='udp', port=58000, addresses=['0.0.0.0'], processes=['nebula'])])
        query(58000, False)
        config['dynamic_services'][0]['wan'] = True
        apply()
        query(58000, False)
        run('systemctl', 'stop', unit)
        # Reuse the exact outbound UDP tuple with the same UID and stale rules.
        # A SNAT conntrack entry must not bypass the socket owner check.
        ns(server, 'python3', '-c', '''import os,pwd,socket
a=pwd.getpwnam('turnserver');os.setgroups([]);os.setgid(a.pw_gid);os.setuid(a.pw_uid)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.61.20.2',45001));s.settimeout(.5)
s.connect(('10.63.20.1',40124));s.send(b'takeover')
try:
 s.recv(4096)
 raise AssertionError('old outbound conntrack admitted another socket owner')
except TimeoutError: pass
''')
        takeover = private_echo([50000])
        # Keep the old rule AND same client tuple: stale admission/conntrack
        # must not admit a same-UID process that takes over coturn's UDP port.
        query(50000, False)
        takeover.terminate()
        takeover.wait(timeout=5)
        run('systemctl', 'start', unit)
        wait_socket(50000)
        wait_socket(42004, tcp=True)
        after = host.owner_cgroups(config)
        if before != after:
            query(50000, False)
            assert host.nft(config, []) != active
        apply()
        query(50000, True)
        query_tcp(True)
        print(json.dumps({'turn_range': '49152-50151', 'guard':'socket-cgroupv2',
                          'same_uid_private_55000_blocked':True, 'owned_50000_allowed':True,
                          'same_port_takeover_blocked_without_rule_refresh':True,
                          'tcp_control_static_port_policy_verified':True,
                          'owned_active_tcp_udp_backend_source':True,
                          'outbound_conntrack_same_uid_takeover_blocked':True,
                          'explicit_nebula_58000_allowed_and_revoked':True,
                          'wan_false_nebula_inside_range_blocked':True,
                          'owner_restart_refresh':True, 'production_changed':False}))
    finally:
        if unit_path.exists():
            subprocess.run(['systemctl', 'stop', unit], capture_output=True)
            unit_path.unlink()
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
            subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True)
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        program_path.unlink(missing_ok=True)
        for name in reversed(created):
            subprocess.run(['ip', 'netns', 'delete', name], capture_output=True)
        for name in (client_link, server_link):
            if Path('/sys/class/net', name).exists():
                subprocess.run(['ip', 'link', 'delete', name], capture_output=True)


if __name__ == '__main__':
    main()
