#!/usr/bin/env python3
"""Trial staged RX batching binaries, always retaining exact accepted originals."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import time
from vrouter_rx_ring_trial import ready,run,sha

ROOT=Path('/var/lib/vpp-vrouter/rx-batch-trial')
CONFIG=Path('/etc/vpp/startup.conf')
PMD=Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')
PLUGIN=Path('/usr/local/lib/vpp-vrouter/plugins/dpdk_plugin.so')
BUILD=Path('/usr/local/src/vpp-vrouter/maintenance/rx-batch-experiment')
UNIT='vrouter-rx-batch-rollback'
ARMS=('baseline','read','call64','rearm2','rearm8','rearm8-32')


def save(state):
    t=ROOT/'state.new';t.write_text(json.dumps(state,indent=2)+'\n');t.chmod(0o600);t.replace(ROOT/'state.json')


def targets(arm):
    if arm not in ARMS:raise ValueError('Unsupported arm')
    manifest=json.loads((BUILD/'manifest.json').read_text())
    result={PMD:ROOT/'pmd.original',PLUGIN:ROOT/'plugin.original'}
    if arm!='baseline':
        name='rearm8' if arm=='rearm8-32' else arm
        variant=manifest['variants'][name if name in ('rearm2','rearm8') else 'read']
        result[PMD]=Path(variant['pmd'])
        assert sha(result[PMD].read_bytes())==variant['pmd_sha']
    if arm in ('call64','rearm2','rearm8'):
        result[PLUGIN]=Path(manifest['plugin64']['path'])
        assert sha(result[PLUGIN].read_bytes())==manifest['plugin64']['sha']
    return result


def atomic_copy(source,target,mode):
    t=target.with_name(target.name+'.rx-batch-new');t.write_bytes(source.read_bytes());t.chmod(mode);t.replace(target)


def snapshot(state,arm):
    result=dict(time=time.time(),arm=arm,config_sha=sha(CONFIG.read_bytes()),
        service=run('systemctl','show','vrouter-vpp.service','-p','MainPID','-p','NRestarts'),
        hardware=run('/usr/local/bin/vppctl','show hardware-interfaces nic0-dpdk detail'),
        buffers=run('/usr/local/bin/vppctl','show buffers'),hashes={})
    assert result['config_sha']==state['config_sha']
    assert re.search(r'rx: queues 1 .*?desc 1024\b',result['hardware'])
    assert re.search(r'tx: queues 2 .*?desc 1024\b',result['hardware'])
    pid=run('pidof','vpp').split()[0];maps=Path('/proc/'+pid+'/maps').read_text().splitlines()
    for target,source in targets(arm).items():
        digest=sha(target.read_bytes());assert digest==sha(source.read_bytes())
        entries=[s for s in maps if str(target) in s]
        assert entries and all(int(s.split()[4])==target.stat().st_ino for s in entries)
        result['hashes'][str(target)]=digest
    return result


def disarm():run('systemctl','stop',UNIT+'.timer',check=False)


def arm_timer():
    disarm()
    run('systemd-run','--unit='+UNIT,'--on-active=9m','/usr/bin/python3',str(Path(__file__).resolve()),'restore')


def restore(state):
    # Never overwrite a binary changed by an unrelated operator.
    allowed={target:{sha(paths[target].read_bytes()) for paths in [targets(a) for a in ARMS]} for target in [PMD,PLUGIN]}
    for target in [PMD,PLUGIN]:
        if sha(target.read_bytes()) not in allowed[target]:raise RuntimeError('Binary changed outside trial: '+str(target))
    changed=False
    for target,source in targets('baseline').items():
        if target.read_bytes()!=source.read_bytes():
            atomic_copy(source,target,state['modes'][str(target)]);changed=True
    if changed:run('systemctl','restart','vrouter-vpp.service',timeout=180)
    ready();state['active']='baseline';state['restored']=True
    state['events'].append(dict(action='restore',restarted=changed,result=snapshot(state,'baseline')))
    save(state);disarm()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','apply','restore','status'])
    parser.add_argument('--arm',choices=ARMS)
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('Run as root on VROUTER')
    sys.path.insert(0,'/usr/local/lib/vpp-vrouter/install');os.umask(0o077)
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (ROOT/'lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action=='prepare':
            if (ROOT/'state.json').exists():raise RuntimeError('Existing trial; inspect first')
            import recovery
            recovery.verify();ready()
            assert sha(PMD.read_bytes())=='f89a9e9d5210046d5b8a5dc7960e2b0ec3bd0f6bc99cf1cf787d4ffcd8da97a8'
            manifest=json.loads((BUILD/'manifest.json').read_text())
            assert sha(PLUGIN.read_bytes())==manifest['baseline_plugin']
            (ROOT/'pmd.original').write_bytes(PMD.read_bytes());(ROOT/'plugin.original').write_bytes(PLUGIN.read_bytes())
            state=dict(active='baseline',restored=False,config_sha=sha(CONFIG.read_bytes()),
                       modes={str(p):p.stat().st_mode&0o7777 for p in [PMD,PLUGIN]},events=[])
            state['events'].append(dict(action='prepare',result=snapshot(state,'baseline')));save(state)
        else:
            state=json.loads((ROOT/'state.json').read_text())
            if args.action=='restore':restore(state)
            elif args.action=='apply':
                if args.arm is None:parser.error('apply requires --arm')
                snapshot(state,state['active']);arm_timer()
                try:
                    for target,source in targets(args.arm).items():
                        if target.read_bytes()!=source.read_bytes():atomic_copy(source,target,state['modes'][str(target)])
                    run('systemctl','restart','vrouter-vpp.service',timeout=180);ready()
                    state['active']=args.arm;state['restored']=False
                    state['events'].append(dict(action='apply',result=snapshot(state,args.arm)));save(state)
                except Exception:
                    restore(state);raise
        print(json.dumps(dict(active=state['active'],restored=state['restored'],events=len(state['events']))))


if __name__=='__main__':main()
