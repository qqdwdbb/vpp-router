"""Root/router only: isolated NAT ownership, ICMP errors and mapping lifecycle.

The injection helper is loaded only by the temporary VPP. It emits local
IPv4 packets from thread 0; TAP receive queues run on the configured workers.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import socket
import struct
import subprocess
import tempfile
import time


def checksum(data):
    data += b'\0' * (len(data) % 2)
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return ~value & 65535


def packet(protocol, source, destination, sport, dport):
    src, dst = socket.inet_aton(source), socket.inet_aton(destination)
    if protocol == 17:
        body = struct.pack('!HHHH', sport, dport, 13, 0) + b'audit'
    else:
        body = struct.pack('!HHIIBBHHH', sport, dport, 1234, 0, 80, 2, 8192, 0, 0)
    csum = checksum(src + dst + struct.pack('!BBH', 0, protocol, len(body)) + body)
    offset = 6 if protocol == 17 else 16
    body = body[:offset] + struct.pack('!H', csum) + body[offset + 2:]
    header = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(body), 123, 0, 64, protocol, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + body


def run(*args, timeout=20):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout


def disable_test_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugins', type=Path, required=True)
    parser.add_argument('--inject-plugin', type=Path, required=True)
    parser.add_argument('--workers', default='1')
    parser.add_argument('--mode', choices=('input', 'output'), default='output')
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--thread-control', action='store_true')
    args = parser.parse_args()
    names = [f'ei-audit-{os.getpid()}-{i}' for i in range(2)]
    processes, created, results = [], [], []
    vpp = None
    report = {'workers': args.workers, 'mode': args.mode, 'checks': results}
    with tempfile.TemporaryDirectory(prefix='ei-thread-audit-') as temporary:
        root = Path(temporary)
        plugins = root / 'plugins'
        plugins.mkdir()
        sock = str(root / 'cli.sock')
        for name in ('nat44_ei', 'nat_ei_context', 'tap', 'ping'):
            file = name + '_plugin.so'
            parent = args.plugins if name in ('nat44_ei', 'nat_ei_context') else Path('/usr/local/lib/vpp-vrouter/plugins')
            (plugins / file).symlink_to(parent / file)
        (plugins / 'nat_thread_audit_inject_plugin.so').symlink_to(args.inject_plugin)
        workers = '' if args.workers == '0' else f'corelist-workers {args.workers}'
        (root / 'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {root}/run cli-listen {sock} }}
api-segment {{ prefix ei-audit-{os.getpid()} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock size 16M page-size 4k }}
cpu {{ main-core 0 {workers} }}
memory {{ main-heap-size 256M main-heap-page-size 4k }}
buffers {{ buffers-per-numa 2048 page-size 4k }}
plugins {{ path {plugins}
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
plugin nat44_ei_plugin.so {{ enable }}
plugin nat_ei_context_plugin.so {{ enable }}
plugin nat_thread_audit_inject_plugin.so {{ enable }}
}}
''')

        def cli(command):
            text = run('vppctl', '-s', sock, command)
            assert not any(x in text.lower() for x in ('unknown input', 'failed', 'returned', 'not enabled')), (command, text)
            return text

        def check(name, function):
            try:
                detail = function()
                assert vpp.poll() is None
                results.append({'name': name, 'status': 'pass', 'detail': detail})
                print('PASS', name, flush=True)
            except Exception as error:
                results.append({'name': name, 'status': 'fail', 'detail': str(error)[:3000]})
                print('FAIL', name, str(error)[:600], flush=True)

        def ns(index, *command):
            return run('ip', 'netns', 'exec', names[index], *command)

        def rpc(index, address, port, tcp=False, source=None):
            program = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if sys.argv[3]=='tcp' else socket.SOCK_DGRAM)
s.settimeout(2)
if sys.argv[4]!='-':s.bind((sys.argv[4],0))
s.connect((sys.argv[1],int(sys.argv[2])));s.send(b'audit');assert s.recv(100)==b'audit'
'''
            return ns(index, 'python3', '-c', program, address, str(port), 'tcp' if tcp else 'udp', source or '-')

        try:
            for name in names:
                run('ip', 'netns', 'add', name)
                created.append(name)
                run('ip', '-n', name, 'link', 'set', 'lo', 'up')
            with (root / 'vpp.log').open('w') as log:
                vpp = subprocess.Popen(['/usr/local/lib/vpp-vrouter/bin/vpp', '-c', str(root / 'startup.conf')],
                                       stdout=log, stderr=log, preexec_fn=disable_test_core)
            for _ in range(100):
                if vpp.poll() is not None:
                    raise RuntimeError((root / 'vpp.log').read_text())
                if Path(sock).exists():
                    break
                time.sleep(.1)
            for i, name in enumerate(names):
                subnet = 243 + i
                cli(f'create tap id {i+1} host-ns {name} host-if-name mgmt0 host-ip4-addr 10.254.{subnet}.2/24')
                run('ip', '-n', name, 'link', 'set', 'mgmt0', 'up')
                ns(i, 'ethtool', '-K', 'mgmt0', 'tx', 'off', 'gro', 'off', 'gso', 'off', 'tso', 'off')
                cli(f'set interface ip address tap{i+1} 10.254.{subnet}.1/24')
                cli(f'set interface state tap{i+1} up')
                mac = json.loads(run('ip', '-n', name, '-j', 'link', 'show', 'mgmt0'))[0]['address']
                cli(f'set ip neighbor tap{i+1} 10.254.{subnet}.2 {mac}')
                run('ip', '-n', name, 'route', 'add', 'default', 'via', f'10.254.{subnet}.1')
            run('ip', '-n', names[0], 'addr', 'add', '10.254.243.3/24', 'dev', 'mgmt0')
            mac = json.loads(run('ip', '-n', names[0], '-j', 'link', 'show', 'mgmt0'))[0]['address']
            cli(f'set ip neighbor tap1 10.254.243.3 {mac}')
            cli('nat44 ei plugin enable sessions 1024 users 128 user-sessions 512')
            cli('nat44 ei add address 10.254.244.1')
            if args.mode == 'output':
                cli('set interface nat44 ei out tap2 output-feature')
                cli('nat44 ei output-chain tap2')
            else:
                cli('set interface nat44 ei in tap1 out tap2')
            server = '''import socket,threading
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',49000))
 while True:
  d,p=s.recvfrom(4096);s.sendto(d,p)
def conn(c):
 with c:
  while True:
   d=c.recv(4096)
   if not d:return
   c.sendall(d)
threading.Thread(target=udp,daemon=True).start()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',49001));s.listen()
open(READY,'w').close()
while True:
 c,_=s.accept();threading.Thread(target=conn,args=(c,),daemon=True).start()
'''
            for i in range(2):
                ready = root / f'ready{i}'
                processes.append(subprocess.Popen(['ip', 'netns', 'exec', names[i], 'python3', '-u', '-c', 'READY=' + repr(str(ready)) + '\n' + server]))
            for _ in range(100):
                if all((root / f'ready{i}').exists() for i in range(2)):
                    break
                time.sleep(.05)
            check('forwarded UDP/TCP', lambda: (rpc(0, '10.254.244.2', 49000), rpc(0, '10.254.244.2', 49001, tcp=True)))

            def local(protocol, dport, sport):
                cli('clear trace')
                cli('trace add tap-input 40')
                text = cli('test nat-thread inject ' + packet(protocol, '10.254.244.1', '10.254.244.2', sport, dport).hex())
                assert 'injected thread 0' in text, text
                time.sleep(.3)
                trace = cli('show trace')
                assert '10.254.244.2 -> 10.254.244.1' in trace, trace
                assert 'nat44-ei-out2in' in trace, trace
                assert '-> 0.0.0.0' not in trace, trace
                assert f'{dport} -> {sport}' in trace, trace
                sessions = cli('show nat44 ei sessions detail')
                assert f'port {sport} fib 0' in sessions, sessions
                if args.workers != '0':
                    main = sessions.split('-------- thread 1')[0]
                    assert f'port {sport} fib 0' not in main, sessions
                return {'source_thread': 0, 'restored_destination_port': sport,
                        'return_trace': trace[:16000]}

            if args.mode == 'output':
                check('main-thread local UDP echo + return ownership', lambda: local(17, 49000, 42000))
                check('main-thread local TCP SYN + return ownership', lambda: local(6, 49001, 42001))

            def icmp_closed_port():
                text = ns(0, 'python3', '-c', '''import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.connect(('10.254.244.2',49998));s.send(b'audit')
try:s.recv(100)
except ConnectionRefusedError:print('ICMP destination-unreachable delivered')
''')
                assert 'destination-unreachable delivered' in text, text
                return text
            check('ICMP destination-unreachable with quoted UDP', icmp_closed_port)

            # A second Linux routing hop generates real ICMP errors quoting
            # translated packets, including a fragmentation-needed MTU value.
            ns(1, 'ip', 'link', 'add', 'audit-sink', 'type', 'dummy')
            ns(1, 'ip', 'link', 'set', 'audit-sink', 'mtu', '1280', 'up')
            ns(1, 'ip', 'addr', 'add', '198.18.250.1/24', 'dev', 'audit-sink')
            ns(1, 'sysctl', '-w', 'net.ipv4.ip_forward=1')
            cli('ip route add 198.18.250.0/24 via 10.254.244.2 tap2')

            def icmp_error(ttl, size, expected_type, expected_code):
                program = '''import socket,struct,json,sys,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
s.setsockopt(socket.SOL_IP,11,1)
s.setsockopt(socket.SOL_IP,10,2)
s.setsockopt(socket.SOL_IP,socket.IP_TTL,int(sys.argv[1]))
s.connect(('198.18.250.2',49997));s.send(b'x'*int(sys.argv[2]))
end=time.monotonic()+3
while time.monotonic()<end:
 try:
  _,anc,_,_=s.recvmsg(2048,512,socket.MSG_ERRQUEUE)
  for level,kind,data in anc:
   if level==socket.SOL_IP and kind==11:
    errno,origin,typ,code,pad,info,other=struct.unpack('=IBBBBII',data[:16])
    assert origin==2 and typ==int(sys.argv[3]) and code==int(sys.argv[4]),(errno,origin,typ,code,info)
    if typ==3 and code==4:assert info==1280,info
    print(json.dumps({'type':typ,'code':code,'mtu':info}));sys.exit(0)
 except BlockingIOError:time.sleep(.05)
raise RuntimeError('No translated ICMP error delivered')
'''
                return ns(0, 'python3', '-c', program, str(ttl), str(size), str(expected_type), str(expected_code))
            check('ICMP time-exceeded with quoted UDP', lambda: icmp_error(2, 32, 11, 0))
            check('ICMP fragmentation-needed with MTU 1280', lambda: icmp_error(64, 1400, 3, 4))

            def static_mapping(tcp):
                proto, port, localport = ('tcp', 49101, 49001) if tcp else ('udp', 49100, 49000)
                command = f'nat44 ei add static mapping {proto} local 10.254.243.2 {localport} external 10.254.244.1 {port}'
                cli(command)
                rpc(1, '10.254.244.1', port, tcp=tcp)
                cli(command + ' del')
                rpc(0, '10.254.244.2', 49000)
            check('static UDP inbound/create/delete', lambda: static_mapping(False))
            check('static TCP inbound/create/delete', lambda: static_mapping(True))

            def hairpin():
                # Output NAT alone does not enable LAN ip4-local hairpinning.
                if args.mode == 'output':
                    cli('set interface nat44 ei in tap1')
                command = 'nat44 ei add static mapping udp local 10.254.243.2 49000 external 10.254.244.1 49100'
                cli(command)
                try:
                    rpc(0, '10.254.244.1', 49100, source='10.254.243.3')
                finally:
                    cli(command + ' del')
                    if args.mode == 'output':
                        cli('set interface nat44 ei in tap1 del')
            check('UDP hairpin via static mapping', hairpin)

            def lifecycle():
                for _ in range(5):
                    rpc(0, '10.254.244.2', 49000)
                    cli('nat44 ei del user 10.254.243.2 fib 0')
                    rpc(0, '10.254.244.2', 49001, tcp=True)
                return 'five delete/recreate cycles'
            check('targeted user delete/recreate', lifecycle)

            def delete_session():
                program = '''import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.bind(('10.254.243.2',43000))
s.sendto(b'audit',('10.254.244.2',49000));assert s.recv(100)==b'audit'
'''
                ns(0, 'python3', '-c', program)
                cli('nat44 ei del session in 10.254.243.2:43000 udp vrf 0')
                ns(0, 'python3', '-c', program)
                return 'session deleted by global hash owner and recreated'
            check('targeted session delete/recreate', delete_session)

            def concurrent_updates():
                progress = root / 'active-progress'
                program = '''import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.254.243.3',43001));s.settimeout(2)
count=0
while True:
 s.sendto(b'audit',('10.254.244.2',49000));assert s.recv(100)==b'audit'
 count+=1;open(PROGRESS,'w').write(str(count));time.sleep(.02)
'''.replace('PROGRESS', repr(str(progress)))
                client = subprocess.Popen(['ip', 'netns', 'exec', names[0], 'python3', '-u', '-c', program])
                processes.append(client)
                try:
                    for _ in range(50):
                        if progress.exists() and progress.read_text().strip():
                            break
                        time.sleep(.05)
                    for _ in range(5):
                        static_mapping(False)
                        cli('nat44 ei del user 10.254.243.2 fib 0')
                        time.sleep(.1)
                    assert client.poll() is None
                    assert int(progress.read_text()) >= 10
                    return 'active foreign user survived five mapping and user deletion cycles'
                finally:
                    client.terminate()
                    client.wait(timeout=5)
                    processes.remove(client)
            check('active traffic during static/user configuration updates', concurrent_updates)

            def interface_cycle():
                if args.mode == 'output':
                    cli('set interface nat44 ei out tap2 output-feature del')
                    cli('set interface nat44 ei out tap2 output-feature')
                else:
                    cli('set interface nat44 ei out tap2 del')
                    cli('set interface nat44 ei out tap2')
                rpc(0, '10.254.244.2', 49000)
                rpc(0, '10.254.244.2', 49001, tcp=True)
            check('NAT interface detach/reattach', interface_cycle)
            if args.thread_control:
                from nat_thread_control_checks import run_checks
                run_checks(cli, ns, check, sock, args.workers, args.mode)
            report['errors'] = cli('show errors')
            report['vpp_survived'] = vpp.poll() is None
        finally:
            for p in processes:
                p.terminate()
                p.wait(timeout=5)
            if vpp and vpp.poll() is None:
                vpp.terminate()
                vpp.wait(timeout=10)
            for name in reversed(created):
                run('ip', 'netns', 'delete', name)
            args.result.write_text(json.dumps(report, indent=2) + '\n')
    if any(item['status'] != 'pass' for item in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
