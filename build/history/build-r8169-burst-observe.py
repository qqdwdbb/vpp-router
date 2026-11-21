import importlib.util,hashlib,json,shutil,subprocess
from pathlib import Path
r=Path('/usr/local/src/vpp-vrouter');base=r/'maintenance/rx-batch-experiment/rearm8';out=r/'maintenance/rx-burst-port-observe-20261031';out.mkdir()
src=out/'source';shutil.copytree(base/'source',src)
p=src/'r8169_rxtx.c';s=p.read_text();mark='rtl_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)';i=s.index(mark);pos=s.rfind('static ',0,i)
assert s[pos:i].startswith('static ')
s=s[:pos]+'''/* Single-worker diagnostic counters, off until explicitly enabled. */
struct rtl_rx_observe_counts { volatile unsigned long long calls, packets, bins[65]; };
struct rtl_rx_observe { volatile unsigned long long enabled; struct rtl_rx_observe_counts port[16]; };
__attribute__((used, visibility("default"))) struct rtl_rx_observe rtl_rx_observe;

'''+s[pos:]
a=s.index(mark);b=s.index('\n\treturn nb_rx;',a);s=s[:b]+'''
	if (__builtin_expect(rtl_rx_observe.enabled != 0 && rxq->port_id < 16, 0)) {
		rtl_rx_observe.port[rxq->port_id].calls++;
		rtl_rx_observe.port[rxq->port_id].packets += nb_rx;
		rtl_rx_observe.port[rxq->port_id].bins[nb_rx < 64 ? nb_rx : 64]++;
	}
'''+s[b:];p.write_text(s)
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
print(json.dumps({'library':str(lib),'sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'symbols':subprocess.check_output(['nm','-S',str(lib)],text=True).split('rtl_rx_observe')[0].splitlines()[-1]}))
