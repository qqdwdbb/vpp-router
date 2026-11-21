"""Root/router only: test candidate plugin in an isolated VPP, no physical NICs."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import tempfile
import time


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=20).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugin', type=Path, required=True)
    parser.add_argument('--workers', default='1')
    parser.add_argument('--sessions', type=int, default=64)
    args = parser.parse_args()
    lan, wan = 'ei-expiry-lan', 'ei-expiry-wan'
    assert lan not in run('ip', 'netns', 'list') and wan not in run('ip', 'netns', 'list')
    processes = []
    vpp = None
    with tempfile.TemporaryDirectory(prefix='vpp-ei-expiry-') as tmp:
        root = Path(tmp)
        plugins = root / 'plugins'
        plugins.mkdir()
        (plugins / 'nat44_ei_plugin.so').symlink_to(args.plugin.resolve())
        (plugins / 'tap_plugin.so').symlink_to('/usr/local/lib/vpp-vrouter/plugins/tap_plugin.so')
        sock = str(root / 'cli.sock')

        def cli(command):
            result = run('vppctl', '-s', sock, *command.split()).strip()
            assert not any(word in result.lower() for word in ('unknown input', 'failed', 'returned')), (command, result)
            return result

        config = root / 'startup.conf'
        config.write_text(f'''unix {{ nodaemon runtime-dir {root}/run cli-listen {sock} }}
api-segment {{ prefix ei-expiry-{os.getpid()} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock size 32M page-size 4k }}
cpu {{ main-core 0 corelist-workers {args.workers} }}
memory {{ main-heap-size 256M main-heap-page-size 4k }}
buffers {{ buffers-per-numa 2048 page-size 4k }}
plugins {{ path {plugins}
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin nat44_ei_plugin.so {{ enable }}
}}
''')
        try:
            for ns in (lan, wan):
                run('ip', 'netns', 'add', ns)
                run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
            with (root / 'vpp.log').open('w') as log:
                vpp = subprocess.Popen(['/usr/local/lib/vpp-vrouter/bin/vpp', '-c', str(config)], stdout=log, stderr=log)
            for _ in range(150):
                if vpp.poll() is not None:
                    raise RuntimeError((root / 'vpp.log').read_text()[-5000:])
                if Path(sock).exists():
                    break
                time.sleep(.1)
            cli(f'create tap id 1 host-ns {lan} host-if-name ei-in host-ip4-addr 10.254.240.2/24')
            cli(f'create tap id 2 host-ns {wan} host-if-name ei-out host-ip4-addr 10.254.241.2/24')
            run('ip', '-n', lan, 'link', 'set', 'ei-in', 'up')
            run('ip', '-n', wan, 'link', 'set', 'ei-out', 'up')
            for ns, dev in ((lan, 'ei-in'), (wan, 'ei-out')):
                run('ip', 'netns', 'exec', ns, 'ethtool', '-K', dev,
                    'tx', 'off', 'gro', 'off', 'gso', 'off', 'tso', 'off')
            for name, address in (('tap1', '10.254.240.1/24'), ('tap2', '10.254.241.1/24')):
                cli(f'set interface ip address {name} {address}')
                cli(f'set interface state {name} up')
            for address in ('10.254.240.3', '10.254.240.4'):
                run('ip', '-n', lan, 'addr', 'add', address + '/24', 'dev', 'ei-in')
            run('ip', '-n', lan, 'route', 'add', 'default', 'via', '10.254.240.1')
            run('ip', '-n', wan, 'route', 'add', '10.254.241.100/32', 'via', '10.254.241.1')
            cli(f'nat44 ei plugin enable sessions {args.sessions} users 64 user-sessions {args.sessions}')
            cli('nat44 ei add address 10.254.241.100')
            cli('set interface nat44 ei in tap1 out tap2')
            cli('set nat44 ei timeout udp 3 tcp-established 5 tcp-transitory 3 icmp 2')
            # An unrelated mapping must survive session expiration.
            cli('nat44 ei add static mapping tcp local 10.254.240.4 49999 external 10.254.241.100 49999')
            mac = json.loads(run('ip', '-n', lan, '-j', 'link', 'show', 'ei-in'))[0]['address']
            for address in ('10.254.240.2', '10.254.240.3', '10.254.240.4'):
                cli(f'set ip neighbor tap1 {address} {mac}')
            mac = json.loads(run('ip', '-n', wan, '-j', 'link', 'show', 'ei-out'))[0]['address']
            cli(f'set ip neighbor tap2 10.254.241.2 {mac}')
            cli('trace add tap-input 40')
            server = '''import socket,threading
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',49000))
 while True:
  d,p=s.recvfrom(100);s.sendto(d,p)
def conn(c):
 while True:
  d=c.recv(100)
  if not d:return
  c.sendall(d)
threading.Thread(target=udp,daemon=True).start()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',49001));s.listen()
while True:
 c,_=s.accept();threading.Thread(target=conn,args=(c,),daemon=True).start()
'''
            processes.append(subprocess.Popen(['ip', 'netns', 'exec', wan, 'python3', '-u', '-c', server]))
            time.sleep(.4)
            # Keep UDP and TCP sessions alive longer than their configured timeout.
            client = '''import socket,time,json,sys
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('10.254.240.3',41000));u.settimeout(2)
t=socket.socket();t.bind(('10.254.240.4',41001));t.settimeout(2);t.connect(('10.254.241.2',49001))
count=0
while True:
 u.sendto(b'x',('10.254.241.2',49000));assert u.recv(10)==b'x'
 t.sendall(b'y');assert t.recv(10)==b'y'
 count+=1
 open(sys.argv[1],'w').write(json.dumps({'ok':count}))
 time.sleep(.2)
'''
            progress = root / 'progress.json'
            processes.append(subprocess.Popen(['ip', 'netns', 'exec', lan, 'python3', '-u', '-c', client, str(progress)]))
            for _ in range(40):
                if progress.exists():
                    break
                time.sleep(.1)
            if not progress.exists():
                print(cli('show interface'), flush=True)
                print(cli('show errors'), flush=True)
                print(cli('show trace'), flush=True)
                print(cli('show runtime'), flush=True)
                print(cli('show nat44 ei sessions detail'), flush=True)
                print(run('ip', '-n', lan, 'addr'), flush=True)
                raise AssertionError('active clients failed')
            burst = '''import socket
for p in range(20000,BURST_END):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.254.240.2',p));s.sendto(b'z',('10.254.241.2',49000));s.close()
'''.replace('BURST_END', str(20000 + args.sessions + 236))
            run('ip', 'netns', 'exec', lan, 'python3', '-c', burst)
            time.sleep(.5)
            before = cli('show nat44 ei sessions')
            assert '10.254.240.2:' in before, before
            errors = cli('show errors')
            assert 'maximum sessions exceeded' in errors, errors
            print('PASS capacity reached in isolated instance', flush=True)
            time.sleep(5)
            # A one-packet ICMP flow must also expire.
            run('ip', 'netns', 'exec', lan, 'ping', '-c', '1', '-W', '2', '-I', '10.254.240.2', '10.254.241.2')
            time.sleep(6)
            after = cli('show nat44 ei sessions')
            assert '10.254.240.2:' not in after, after
            for address in ('10.254.240.3', '10.254.240.4'):
                assert address + ':' in after, after
            assert 'expired sessions reclaimed' in cli('show errors')
            assert '49999' in cli('show nat44 ei static mappings')
            assert all(p.poll() is None for p in processes)
            print('PASS idle UDP/ICMP expire; active UDP/TCP and static mapping survive', flush=True)
            # Refill and check targeted deletion with populated foreign workers.
            run('ip', 'netns', 'exec', lan, 'python3', '-c', burst.replace(str(20000 + args.sessions + 236), '20012'))
            time.sleep(.3)
            assert '10.254.240.2:' in cli('show nat44 ei sessions')
            cli('nat44 ei del user 10.254.240.2 fib 0')
            after = cli('show nat44 ei sessions')
            assert '10.254.240.2:' not in after, after
            for address in ('10.254.240.3', '10.254.240.4'):
                assert address + ':' in after, after
            time.sleep(1)
            assert all(p.poll() is None for p in processes)
            assert json.loads(progress.read_text())['ok'] > 20
            assert vpp.poll() is None
            print('PASS targeted user deletion preserves other clients and VPP process', flush=True)
            # Once refresh stops, established TCP must expire as well.
            processes[-1].terminate()
            processes[-1].wait(timeout=5)
            time.sleep(7)
            after = cli('show nat44 ei sessions')
            assert 'dynamic translations' not in after, after
            print('PASS idle established TCP expires; all test sessions reclaimed', flush=True)
            print(cli('show errors'), flush=True)
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
            if vpp and vpp.poll() is None:
                vpp.terminate()
                vpp.wait(timeout=10)
            for ns in (lan, wan):
                subprocess.run(['ip', 'netns', 'delete', ns], capture_output=True)


if __name__ == '__main__':
    main()
