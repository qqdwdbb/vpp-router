#!/usr/bin/env python3
"""Linux/root: dual-interface host replies, active SNAT, and LAN isolation.

Uses three temporary namespaces; does not touch production links or services.
The outer VPP static mapping is covered by integration_nat44_ei.py.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def run(*args, input=None, check=True):
    result = subprocess.run(list(map(str, args)), input=input, text=True,
                            capture_output=True, timeout=10)
    if check and result.returncode:
        raise RuntimeError('Host egress test failed: '+result.stderr[-1500:])
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root on Linux')
    spec = importlib.util.spec_from_file_location('host_path', args.source/'host-path.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    config = json.loads((args.source/'services.json').read_text())
    config['services'].append(dict(name='dedicated-udp-fixture', protocol='udp',
                                   ports=[58000, 58001], wan=True, dedicated_ingress=True))
    # No systemd services/cgroups needed for the fixed/dynamic port tests.
    server, wan, lan = [prefix+str(os.getpid()) for prefix in ('hps-', 'hpw-', 'hpl-')]
    created, children = [], []
    def ns(name, *command, **kwargs):
        return run('ip', 'netns', 'exec', name, *command, **kwargs)
    def execute(*command, **kwargs):
        return ns(server, *command, **kwargs)
    echo = '''import json,socketserver,threading,sys
from pathlib import Path
class UDP(socketserver.BaseRequestHandler):
 def handle(self): self.request[1].sendto(json.dumps(self.client_address).encode(),self.client_address)
class TCP(socketserver.BaseRequestHandler):
 def handle(self): self.request.sendall(json.dumps(self.client_address).encode())
for address in json.loads(sys.argv[2]):
 for port in map(int,sys.argv[3:]):
  for cls,handler in ((socketserver.UDPServer,UDP),(socketserver.TCPServer,TCP)):
   s=cls((address,port),handler)
   threading.Thread(target=s.serve_forever,daemon=True).start()
Path(sys.argv[1]).touch()
threading.Event().wait()
'''
    probe = '''import json,socket,sys
proto,source,port,destination,target,expected=sys.argv[1:]
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM)
s.settimeout(2);s.bind((source,int(port)));s.connect((destination,int(target)))
if proto=='udp': s.send(b'probe')
peer=json.loads(s.recv(4096));assert peer[0]==expected,(peer,expected)
s.close()
'''
    with tempfile.TemporaryDirectory(prefix='host-egress-') as directory:
        root = Path(directory)
        def start(name, ports, addresses=('0.0.0.0',)):
            ready = root/(name+'.ready')
            child = subprocess.Popen(['ip', 'netns', 'exec', name, 'python3', '-c', echo,
                                      str(ready), json.dumps(addresses), *map(str, ports)])
            children.append(child)
            deadline = time.monotonic()+5
            while not ready.exists():
                if child.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Host egress echo fixture failed to start')
                time.sleep(.05)
        try:
            for name in (server, wan, lan):
                if name in run('ip', 'netns', 'list').split():
                    raise ValueError('Test namespace already exists')
                run('ip', 'netns', 'add', name)
                created.append(name)
                run('ip', '-n', name, 'link', 'set', 'lo', 'up')
            for peer, interface, address, peer_address in (
                    (wan, 'vpp-hostsvc', '10.63.20.2/30', '10.63.20.1/30'),
                    (lan, 'br-mgmt', '10.61.20.2/24', '10.61.20.10/24')):
                # Create inside the owned namespace: no host-interface changes.
                run('ip', '-n', server, 'link', 'add', interface, 'type', 'veth', 'peer', 'name', 'peer0')
                run('ip', '-n', server, 'link', 'set', 'peer0', 'netns', peer)
                run('ip', '-n', server, 'addr', 'add', address, 'dev', interface)
                run('ip', '-n', server, 'link', 'set', interface, 'up')
                run('ip', '-n', peer, 'addr', 'add', peer_address, 'dev', 'peer0')
                run('ip', '-n', peer, 'link', 'set', 'peer0', 'up')
            execute('sysctl', '-w', 'net.ipv4.conf.all.rp_filter=0',
                    'net.ipv4.conf.vpp-hostsvc.rp_filter=0')
            run('ip', '-n', wan, 'addr', 'add', '198.18.0.1/32', 'dev', 'lo')
            run('ip', '-n', lan, 'addr', 'add', '10.64.20.10/32', 'dev', 'lo')
            execute('ip', 'route', 'add', '10.64.20.0/24', 'via', '10.61.20.10')
            execute('ip', 'route', 'add', 'default', 'via', '10.61.20.10')
            host.routing.install(config, execute, root/'routing.json')
            inventory = [dict(protocol='udp', port=port, addresses=['0.0.0.0'], processes=['nebula'])
                         for port in (58000, 58001)]
            execute('nft', '-f', '-', input=host.nft(config, inventory, owners={}))
            execute('nft', '-f', args.source.parent/'dns-route-gate/dns-route-gate.nft')
            start(server, [58000, 42004, 1053])
            # Bind each alias explicitly so wildcard UDP source selection does
            # not make an echo reply look like traffic from a different peer.
            start(wan, [40000], ['198.18.0.1'])
            start(lan, [40000], ['10.61.20.10', '10.64.20.10'])
            for proto, target in (('udp', 58000), ('tcp', 42004)):
                # With the wrong return interface, the WAN peer cannot reply:
                # its source is only reachable through the host-service TAP.
                ns(wan, 'python3', '-c', probe, proto, '198.18.0.1', '0',
                   '10.63.20.2', str(target), '198.18.0.1')
                ns(lan, 'python3', '-c', probe, proto, '10.61.20.10', '0',
                   '10.61.20.2', str(target), '10.61.20.10')
            for proto, port in (('udp', 58001), ('tcp', 42005)):
                execute('python3', '-c', probe, proto, '10.61.20.2', str(port),
                        '198.18.0.1', '40000', '10.63.20.2')
            # Model VPP punt: preserve the gateway IP, deliver the frame to
            # br-mgmt. All three DNS frontends must reach the gate on 1053.
            for destination in ('10.61.20.1', '10.62.10.1'):
                run('ip', '-n', lan, 'route', 'add', destination+'/32', 'via', '10.61.20.2')
            for destination in ('10.61.20.1', '10.61.20.2', '10.62.10.1'):
                for proto in ('tcp', 'udp'):
                    ns(lan, 'python3', '-c', probe, proto, '10.61.20.10', '0',
                       destination, '53', '10.61.20.10')
            # A marked service still uses connected and explicit inner routes.
            for destination in ('10.61.20.10', '10.64.20.10'):
                execute('python3', '-c', probe, 'udp', '10.61.20.2', '58001',
                        destination, '40000', '10.61.20.2')
            route = execute('ip', 'route', 'get', '198.18.0.1', 'from', '10.61.20.2')
            assert 'br-mgmt' in route, route  # Unmarked traffic is unchanged.
            # A policy refresh must not disturb existing marked connections.
            execute('nft', '-f', '-', input=host.nft(config, inventory, owners={}))
            execute('python3', '-c', probe, 'udp', '10.61.20.2', '58001',
                    '198.18.0.1', '40000', '10.63.20.2')
            # Losing the usable TAP route must not fall through to br-mgmt.
            execute('ip', '-4', 'route', 'del', *host.routing.route_plan(config)[1])
            unreachable = subprocess.run(['ip', 'netns', 'exec', server, 'ip', '-4',
                                          'route', 'get', '198.18.0.1', 'from', '10.61.20.2',
                                          'mark', host.routing.OUTBOUND], capture_output=True, timeout=10)
            assert unreachable.returncode != 0, 'marked flow fell through to main default'
            host.routing.remove(execute, root/'routing.json')
            assert not any(row.get('priority') in (90, 91, 92)
                           for row in json.loads(execute('ip', '-j', '-4', 'rule', 'show')))
            assert not any(str(row.get('table')) == '2480'
                           for row in json.loads(execute('ip', '-j', '-4', 'route', 'show', 'table', 'all')))
            print(json.dumps(dict(wan_tcp_udp_reply=True, active_tcp_udp_snat=True,
                                  lan_reply=True, specific_routes_preserved=True,
                                  unmarked_route_preserved=True, policy_refresh=True,
                                  gateway_host_vpn_dns_gate_tcp_udp=True,
                                  missing_tap_route_fails_closed=True,
                                  routing_cleanup=True, production_changed=False)))
        finally:
            for child in children:
                child.terminate()
            for child in children:
                child.wait(timeout=5)
            for name in reversed(created):
                run('ip', 'netns', 'del', name, check=False)


if __name__ == '__main__':
    main()
