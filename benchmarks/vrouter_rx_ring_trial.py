#!/usr/bin/env python3
"""Bounded VROUTER nic0 RX-ring trial, with independent exact-config restoration."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path('/var/lib/vpp-vrouter/rx-ring-trial')
CONFIG=Path('/etc/vpp/startup.conf')
PMD=Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')
EXPECTED='f89a9e9d5210046d5b8a5dc7960e2b0ec3bd0f6bc99cf1cf787d4ffcd8da97a8'
UNIT='vrouter-rx-ring-rollback'
TOKEN='name nic0-dpdk num-rx-queues 1 num-tx-queues 2 rss'


def render(original, ring):
    if ring not in (1024,2048,4096):
        raise ValueError('Unsupported ring size')
    text=original.decode()
    if text.count(TOKEN)!=1 or 'num-rx-desc' in text or text.count('buffers-per-numa 8192')!=1:
        raise ValueError('Unexpected baseline; inspect configuration first')
    if ring==1024:
        return original
    return text.replace(TOKEN,TOKEN.replace(' rss',f' num-rx-desc {ring} rss')).encode()


def run(*args, check=True, timeout=150):
    p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('Command failed: '+str(args[0]))
    return p.stdout.strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(state):
    p=ROOT/'state.json';t=p.with_suffix('.new')
    t.write_text(json.dumps(state,indent=2)+'\n');t.chmod(0o600);t.replace(p)


def replace(data, mode):
    tmp=CONFIG.with_name('startup.conf.rx-ring-new')
    tmp.write_bytes(data);tmp.chmod(mode);tmp.replace(CONFIG)


def ready():
    import recovery
    deadline=time.monotonic()+100
    units=recovery.REQUIRED+('gost-tunnel.service',)
    while time.monotonic()<deadline:
        s=run('systemctl','is-active',*units,check=False).splitlines()
        if len(s)==len(units) and all(x=='active' for x in s):
            recovery.health(units,wan_timeout=30)
            return
        time.sleep(2)
    raise RuntimeError('Dependent service readiness timeout')


def snapshot():
    return dict(config_sha=sha(CONFIG.read_bytes()),pmd_sha=sha(PMD.read_bytes()),
                service=run('systemctl','show','vrouter-vpp.service','-p','MainPID','-p','NRestarts'),
                hardware=run('/usr/local/bin/vppctl','show hardware-interfaces nic0-dpdk detail'),
                buffers=run('/usr/local/bin/vppctl','show buffers'))


def verify(state, ring):
    result=snapshot()
    assert result['pmd_sha']==state['pmd_sha']==EXPECTED
    assert result['config_sha']==sha(render((ROOT/'startup.original').read_bytes(),ring))
    assert re.search(r'rx: queues 1 .*?desc '+str(ring)+r'\b',result['hardware'])
    assert re.search(r'tx: queues 2 .*?desc 1024\b',result['hardware'])
    return result


def disarm():
    run('systemctl','stop',UNIT+'.timer',check=False)


def arm():
    disarm()
    run('systemd-run','--unit='+UNIT,'--on-active=8m','/usr/bin/python3',
        str(Path(__file__).resolve()),'restore')


def restore(state):
    original=(ROOT/'startup.original').read_bytes()
    assert sha(original)==state['original_sha']
    if CONFIG.read_bytes() not in {render(original,n) for n in (1024,2048,4096)}:
        raise RuntimeError('Refusing to overwrite configuration changed outside this trial')
    changed=CONFIG.read_bytes()!=original
    replace(original,state['mode'])
    if changed:
        run('systemctl','restart','vrouter-vpp.service',timeout=180)
    ready()
    state['restored']=True;state['current_ring']=1024
    state['events'].append(dict(action='restore',time=time.time(),restarted=changed,result=verify(state,1024)))
    save(state)
    disarm()
    return state


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','apply','restore','status'])
    parser.add_argument('--ring',type=int,choices=[1024,2048,4096])
    args=parser.parse_args()
    if os.geteuid()!=0:
        parser.error('Run as root on VROUTER')
    sys.path.insert(0,'/usr/local/lib/vpp-vrouter/install')
    os.umask(0o077)
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/'lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        path=ROOT/'state.json'
        if args.action=='prepare':
            if path.exists():
                raise RuntimeError('Existing trial state; inspect before starting another')
            import recovery
            recovery.verify();ready()
            original=CONFIG.read_bytes();render(original,4096)
            assert sha(PMD.read_bytes())==EXPECTED
            (ROOT/'startup.original').write_bytes(original)
            state=dict(original_sha=sha(original),pmd_sha=EXPECTED,mode=CONFIG.stat().st_mode&0o7777,
                       current_ring=1024,restored=False,events=[])
            state['events'].append(dict(action='prepare',time=time.time(),result=verify(state,1024)))
            save(state)
        else:
            state=json.loads(path.read_text())
            if args.action=='restore':
                state=restore(state)
            elif args.action=='apply':
                if args.ring is None:
                    parser.error('apply requires --ring')
                original=(ROOT/'startup.original').read_bytes()
                assert sha(original)==state['original_sha']
                expected=render(original,state['current_ring'])
                if CONFIG.read_bytes()!=expected:
                    raise RuntimeError('Configuration changed outside this trial')
                new=render(original,args.ring)
                arm()
                try:
                    changed=CONFIG.read_bytes()!=new
                    replace(new,state['mode'])
                    if changed:
                        run('systemctl','restart','vrouter-vpp.service',timeout=180)
                    ready()
                    state['current_ring']=args.ring;state['restored']=False
                    state['events'].append(dict(action='apply',ring=args.ring,time=time.time(),
                                                restarted=changed,result=verify(state,args.ring)))
                    save(state)
                except Exception:
                    restore(state)
                    raise
        print(json.dumps(dict(current_ring=state['current_ring'],restored=state['restored'],
                              events=len(state['events']),original_sha=state['original_sha'])))


if __name__=='__main__':
    main()
