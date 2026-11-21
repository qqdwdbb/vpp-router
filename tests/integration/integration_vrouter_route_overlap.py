#!/usr/bin/env python3
"""VROUTER/root: ordered sets and DNS barrier against a separate VPP instance."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time


def run(*args, input=None):
    p = subprocess.run(list(map(str, args)), input=input, capture_output=True, text=True, timeout=20)
    if p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr[:200]}')
    return p.stdout


def main():
    source = Path(__file__).resolve().parents[2]
    os.umask(0o077)
    os.environ['VPP_API_DIR'] = '/opt/vpp-nic1-test/vpp/share/vpp/api'
    os.environ['PATH'] = '/opt/vpp-nic1-test/vpp/bin:' + os.environ['PATH']
    sys.path.insert(0, '/opt/vpp-vrouter-migration/runtime/python')
    gate = runpy.run_path(str(source/'tools/dns-route-gate.py'))
    sync = gate['load_sync'](source/'tools/nftset-route-sync.py')
    unit = 'vrouter-overlap-test-' + str(os.getpid())
    table = 'vrouter_overlap_' + str(os.getpid())
    with tempfile.TemporaryDirectory(prefix='vrouter-overlap-', dir='/run') as directory:
        root = Path(directory)
        try:
            (root/'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 4096 page-size 4k }}
plugins {{ plugin default {{ disable }} }}
''')
            run('systemd-run', '--unit='+unit, '--property=RuntimeMaxSec=120',
                '--setenv=LD_LIBRARY_PATH=/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu',
                '/opt/vpp-nic1-test/vpp/bin/vpp', '-c', root/'startup.conf')
            deadline = time.monotonic()+15
            while not (root/'cli.sock').exists():
                if time.monotonic()>deadline: raise RuntimeError('isolated VPP unavailable')
                time.sleep(.1)
            def cli(cmd): return run('vppctl', '-s', root/'cli.sock', cmd)
            for cmd in ['create loopback interface instance 901', 'create loopback interface instance 902',
                        'set interface state loop901 up', 'set interface state loop902 up',
                        'set interface ip address loop901 10.250.1.2/24',
                        'set interface ip address loop902 10.250.2.2/24',
                        'set ip neighbor static loop901 10.250.1.1 02:00:00:00:09:01',
                        'set ip neighbor static loop902 10.250.2.1 02:00:00:00:09:02']:
                out=cli(cmd)
                if any(w in out.lower() for w in ['unknown', 'error', 'failed']): raise RuntimeError('fixture rejected')
            run('nft', '-f', '-', input=f'table inet {table} {{ set high {{ type ipv4_addr; flags interval; }}\nset low {{ type ipv4_addr; flags interval; }}\n}}\n')
            high={'family':'inet','table':table,'set':'high','via':'10.250.1.1','interface':'loop901','fib_table':0}
            low={**high,'set':'low','via':'10.250.2.1','interface':'loop902'}
            config={'overlap_policy':'first','mappings':[high,low],'lock_files':[], 'exclude_prefixes':[],
                    'max_routes':100,'fib_audit_seconds':0,'state_file':str(root/'state.json'),
                    'vpp_socket':str(root/'cli.sock'),'api_socket':str(root/'api.sock'),'vpp_service':unit}
            (root/'config.json').write_text(json.dumps(config))
            config=sync.load_config(root/'config.json'); backend=sync.Backend(config)
            prefix='198.51.100.77/32'
            hi=sync.Route(0,prefix,high['via'],high['interface']);lo=sync.Route(0,prefix,low['via'],low['interface'])
            run('nft','add','element','inet',table,'low','{ 198.51.100.77 }')
            sync.sync(config,backend);assert sync.matches(lo,backend.lookup([lo]))
            run('nft','add','element','inet',table,'high','{ 198.51.100.77 }')
            sync.add_routes(config,backend,[hi]);assert sync.matches(hi,backend.lookup([hi]))
            # A later lower-priority event must neither fail nor add an ECMP path.
            sync.add_routes(config,backend,[lo]);assert sync.matches(hi,backend.lookup([hi]))
            run('nft','delete','element','inet',table,'high','{ 198.51.100.77 }')
            sync.sync(config,backend);assert sync.matches(lo,backend.lookup([lo]))
            (root/'rules.conf').write_text(f'nftset=/overlap.test/4#inet#{table}#high,4#inet#{table}#low\n')
            controller=gate['Controller'](sync,root/'config.json',lambda:[root/'rules.conf'],root/'seen.json')
            controller.reconcile([('overlap.test','198.51.100.77',60)],('overlap.test',1,1))
            assert sync.matches(hi,backend.lookup([hi]))
            controller.reconcile_event([(low,prefix)]);assert sync.matches(hi,backend.lookup([hi]))
            controller.reconcile();assert sync.matches(hi,backend.lookup([hi]))
            print(json.dumps({'isolated_vpp':True,'binary_api':True,'background_overlap':True,
                              'direct_event_priority':True,'expiry_fallback':True,'dns_barrier':True,
                              'single_next_hop':True,'production_changed':False}))
        finally:
            if sync.Backend._api_client is not None: sync.Backend._api_client.disconnect()
            subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=20)
            subprocess.run(['nft','delete','table','inet',table],capture_output=True,timeout=10)


if __name__=='__main__': main()
