#!/usr/bin/env python3
"""VROUTER/root: disposable VPP-side client verifies the dedicated proxy TAP."""
import argparse
import importlib.util
import ipaddress
import json
import re
import subprocess
import sys
import time
from pathlib import Path


def run(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=25).strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(exc.output) from None


def cli(command):
    result = run('/usr/local/bin/vppctl', '-s', '/run/vpp/cli.sock', command)
    if re.search(r'unknown|failed|error|invalid', result, re.I):
        raise RuntimeError(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dns-host', required=True, help='LAN DNS Gate address')
    parser.add_argument('--proxy-next-hop', required=True, help='Linux address on the proxy TAP')
    parser.add_argument('--proxy-interface', default='tap2490', help='VPP interface for the proxy TAP')
    parser.add_argument('--overlay-host', required=True, help='Overlay test host with an SSH listener')
    args = parser.parse_args()
    namespace = 'vrouter-tproxy-test'
    assert not Path('/run/netns', namespace).exists()
    assert not Path('/sys/class/net/vrouter-tproxy-test').exists()
    spec = importlib.util.spec_from_file_location('route_sync', '/usr/local/lib/vpp-vrouter/scripts/nftset-route-sync.py')
    sync = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = sync
    spec.loader.exec_module(sync)
    added_route = None
    tap_created = False
    run('ip', 'netns', 'add', namespace)
    try:
        cli('create tap id 2491 host-ns ' + namespace + ' host-if-name mgmt0 host-ip4-addr 10.1.249.2/30 host-ip6-addr fd76:7070:2491::2/64')
        tap_created = True
        cli('set interface ip address tap2491 10.1.249.1/30')
        cli('set interface ip address tap2491 fd76:7070:2491::1/64')
        cli('set interface state tap2491 up')
        run('ip', '-n', namespace, 'link', 'set', 'mgmt0', 'up')
        run('ip', '-n', namespace, 'route', 'add', 'default', 'via', '10.1.249.1')
        run('ip', '-n', namespace, '-6', 'route', 'add', 'default', 'via', 'fd76:7070:2491::1')
        # The freshly assigned IPv6 address is not usable until DAD completes.
        for _ in range(40):
            addresses = json.loads(run('ip', '-n', namespace, '-j', '-6', 'addr', 'show', 'dev', 'mgmt0'))
            if not any(a.get('tentative', False) or 'tentative' in a.get('flags', [])
                       for row in addresses for a in row['addr_info']):
                break
            time.sleep(.1)
        else:
            raise RuntimeError('Test-client IPv6 DAD did not complete')
        for family, pool in (('A', '198.18.0.0/15'), ('AAAA', '2001:2::/48')):
            answers = run('dig', '@' + args.dns_host, '-p', '1053', 'www.google.com', family, '+short').splitlines()
            address = next(x for x in answers if ipaddress.ip_address(x) in ipaddress.ip_network(pool))
            destination = '['+address+']' if ':' in address else address
            code = run('ip', 'netns', 'exec', namespace, 'curl', '--noproxy', '*', '-sS',
                       '--max-time', '20', '--resolve', 'www.google.com:443:'+destination,
                       '-o', '/dev/null', '-w', '%{http_code}', 'https://www.google.com')
            assert code == '200', (family, code)
            print('PASS Fake-IP', family, 'HTTPS', code, flush=True)
        answers = run('dig', '@127.0.0.1', '-p', '54', 'www.google.com', 'A', '+short').splitlines()
        address = next(x for x in answers if re.fullmatch(r'[0-9.]+', x))
        prefix = address + '/32'
        paths = sync.parse_fib(cli('show ip fib table 0'), 0).get((0, prefix))
        if paths is None:
            cli(f'ip route add {prefix} via {args.proxy_next_hop} {args.proxy_interface}')
            added_route = prefix
        else:
            assert paths == frozenset({(args.proxy_next_hop, args.proxy_interface)}), paths
        code = run('ip', 'netns', 'exec', namespace, 'curl', '--noproxy', '*', '-sS',
                   '--max-time', '20', '--resolve', 'www.google.com:443:'+address,
                   '-o', '/dev/null', '-w', '%{http_code}', 'https://www.google.com')
        assert code == '200', code
        print('PASS real-IP HTTPS', code, flush=True)
        print(run('ip', 'netns', 'exec', namespace, 'ping', '-c', '2', '-W', '2', args.overlay_host), flush=True)
        banner = run('ip', 'netns', 'exec', namespace, 'python3', '-c',
                     'import socket,sys;s=socket.create_connection((sys.argv[1],22),5);print(s.recv(256).decode());s.close()',
                     args.overlay_host)
        assert banner.startswith('SSH-'), banner
        print('PASS Nebula direct TCP/22', flush=True)
    except Exception:
        print(run('ip', '-n', namespace, '-6', 'addr'), flush=True)
        print(run('ip', '-n', namespace, '-6', 'route'), flush=True)
        raise
    finally:
        if added_route:
            cli(f'ip route del {added_route} via {args.proxy_next_hop} {args.proxy_interface}')
        if tap_created:
            cli('delete tap tap2491')
        run('ip', 'netns', 'del', namespace)


if __name__ == '__main__':
    main()
