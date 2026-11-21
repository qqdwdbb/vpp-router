import hashlib,os,shutil,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/usr/local/lib/vpp-vrouter/install')
import recovery
D=Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')
B=Path('/var/lib/vpp-vrouter/tx-clean-index-20261101'); C=Path('/usr/local/src/vpp-vrouter/maintenance/tx-clean-index-20261101')/D.name
BASE='8881ceabf6690006c3cdeb62510a19560b23d6d03778fdbc3683c0eab53a80e8'; CAND='2e81a8d2ca42f16348081b5bd08612965248947b281761b2726ef89b70fb9468'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def replace(source):
 t=D.with_name(D.name+'.burst-new');shutil.copy2(source,t);t.replace(D)
def health():
 for n in range(40):
  try:recovery.health(recovery.REQUIRED+('gost-tunnel.service',),wan_timeout=10);return
  except Exception:time.sleep(2)
 raise RuntimeError('health failed')
def restore():
 if sha(B/'original.so')!=BASE:raise RuntimeError('original mismatch')
 if sha(D)!=BASE:
  replace(B/'original.so');recovery.run('systemctl','restart','vrouter-vpp.service',timeout=120)
 health();recovery.run('systemctl','stop','vrouter-tx-index-restore.timer',check=False)
 print('restored',sha(D),flush=True)
if sys.argv[1]=='restore':restore()
elif sys.argv[1]=='apply':
 assert sha(D)==BASE and sha(C)==CAND
 B.mkdir(mode=0o700,exist_ok=False);shutil.copy2(D,B/'original.so')
 recovery.run('systemd-run','--unit=vrouter-tx-index-restore','--on-active=18m','/usr/bin/python3',str(Path(__file__).resolve()),'restore')
 try:
  replace(C);recovery.run('systemctl','restart','vrouter-vpp.service',timeout=120);health()
  pid=recovery.run('pidof','vpp').split()[0]; lines=Path('/proc/'+pid+'/maps').read_text().splitlines()
  maps=[l for l in lines if str(D) in l];assert maps and all(int(l.split()[4])==D.stat().st_ino for l in maps)
  print('candidate active',pid,sha(D),flush=True)
 except BaseException:
  restore();raise
else:raise ValueError('expected apply or restore')
