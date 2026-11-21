import argparse,importlib.util,hashlib,json,shutil,subprocess
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--source',type=Path,required=True)
parser.add_argument('--output',type=Path,default=Path('/usr/local/src/vpp-vrouter/maintenance/rx-empty-fast-20261031'))
args=parser.parse_args()
r=Path('/usr/local/src/vpp-vrouter');base=r/'maintenance/rx-batch-experiment/rearm8';out=args.output;out.mkdir()
src=out/'source';shutil.copytree(base/'source',src)
shutil.copy2(args.source, src/'r8169_rxtx.c')
spec=importlib.util.spec_from_file_location('build',r/'maintenance/rx-alloc-bulk/assets/build-r8169-rx-dma.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
template=mod.command(r/'migration/baseline/rxtx-build-commands.txt');objs={}
for stem in ['r8169_rxtx','r8169_hw','r8169_ethdev']:
 obj=out/(stem+'.o');cmd=template.copy()
 for flag in ['-o','-MF','-MQ']:cmd[cmd.index(flag)+1]=str(obj)+('.d' if flag=='-MF' else '')
 cmd[-1]=str(src/(stem+'.c'));subprocess.run(cmd,cwd=r/'nic1-test/dpdk-build',check=True);objs[stem]=obj
link=mod.command(r/'migration/baseline/r8169-link-command.txt');lib=out/'librte_net_r8169.so.26.1';link[link.index('-o')+1]=str(lib)
for i,v in enumerate(link):
 for stem,obj in objs.items():
  if v.endswith('/net_r8169_'+stem+'.c.o'):link[i]=str(obj)
subprocess.run(link,cwd=r/'nic1-test/dpdk-build',check=True);subprocess.run(['patchelf','--set-rpath','$ORIGIN/../..',str(lib)],check=True)
print(json.dumps({'library':str(lib),'sha256':hashlib.sha256(lib.read_bytes()).hexdigest()}))
