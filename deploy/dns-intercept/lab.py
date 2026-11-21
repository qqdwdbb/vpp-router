import os,sys,subprocess,time,tempfile,re,json,signal
from pathlib import Path
ENV=dict(os.environ,LD_LIBRARY_PATH='/usr/local/lib/aarch64-linux-gnu:/usr/local/lib/vpp-vrouter/lib/aarch64-linux-gnu')
def run(*a,input=None):
 p=subprocess.run(a,input=input,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=ENV,timeout=20)
 if p.returncode:raise RuntimeError(str(a)+': '+p.stdout)
 return p.stdout
if len(sys.argv)>1 and sys.argv[1]=='server':
 import socket,threading
 def serve(fam,port):
  addr='0.0.0.0' if fam==socket.AF_INET else '::'
  def udp():
   s=socket.socket(fam,socket.SOCK_DGRAM)
   if fam==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
   s.bind((addr,port))
   while True:
    b,a=s.recvfrom(4096);s.sendto((sys.argv[2]+':').encode()+b,a)
  def tcp():
   s=socket.socket(fam,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
   if fam==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
   s.bind((addr,port));s.listen()
   while True:
    c,a=s.accept();b=c.recv(4096);c.sendall((sys.argv[2]+':').encode()+b);c.close()
  threading.Thread(target=udp,daemon=True).start();threading.Thread(target=tcp,daemon=True).start()
 for f in (socket.AF_INET,socket.AF_INET6):
  for p in (53,1053,5353):serve(f,p)
 while True:time.sleep(60)
if len(sys.argv)>1 and sys.argv[1]=='probe':
 import socket
 for ip in ('203.0.113.53','2001:db8:9::53'):
  for typ in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
   for port in (53,5353):
    with socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET,typ) as s:
     s.settimeout(3)
     if sys.argv[2]=='vpn':s.bind(('2001:db8:354::10' if ':' in ip else '198.51.100.10',0))
     s.connect((ip,port));s.sendall(b'probe');reply=s.recv(256).decode()
     expected=('gate' if sys.argv[2]=='client' and port==53 else 'upstream')+':probe'
     assert reply==expected,(ip,typ,port,reply,expected)
 print('PASS '+sys.argv[2]+' IPv4/IPv6 UDP/TCP DNS and non-DNS',flush=True);sys.exit()
names=['drg-lab-client','drg-lab-gate','drg-lab-out'];created=[];children=[];vpp=None
root=Path(tempfile.mkdtemp(prefix='drg-lab-',dir='/run'))
def cli(s):
 out=run('/usr/local/lib/vpp-vrouter/bin/vppctl','-s',str(root/'cli.sock'),s)
 if re.search('unknown|failed|invalid|error:|already',out,re.I):raise RuntimeError(s+': '+out)
 return out
try:
 for ns in names:
  run('ip','netns','add',ns);created.append(ns);run('ip','-n',ns,'link','set','lo','up')
 (root/'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
cpu {{ main-core 0 }}
memory {{ main-heap-size 128M }}
buffers {{ buffers-per-numa 2048 page-size 4k }}
plugins {{ path /usr/local/lib/vpp-vrouter/plugins
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin acl_plugin.so {{ enable }}
plugin abf_plugin.so {{ enable }}
plugin dns_intercept_plugin.so {{ enable }}
}}
''')
 log=(root/'vpp.log').open('w');vpp=subprocess.Popen(['/usr/local/lib/vpp-vrouter/bin/vpp','-c',str(root/'startup.conf')],stdout=log,stderr=log,env=ENV)
 for i in range(100):
  if vpp.poll() is not None:raise RuntimeError((root/'vpp.log').read_text())
  if (root/'cli.sock').exists():break
  time.sleep(.1)
 cli('create loopback interface instance 353');cli('set interface ip address loop353 192.0.2.1/24');cli('set interface ip address loop353 2001:db8:353::1/64');cli('set interface state loop353 up');cli('set interface l2 bridge loop353 353 bvi')
 for i,ns in enumerate(names):
  id=3531+i
  cli(f'create tap id {id} host-ns {ns} host-if-name mgmt0')
  cli(f'set interface state tap{id} up');cli(f'set interface rx-mode tap{id} interrupt')
  if i<2:
   cli(f'set interface l2 bridge tap{id} 353')
   a='10' if i==0 else '2'
   run('ip','-n',ns,'addr','add','192.0.2.'+a+'/24','dev','mgmt0');run('ip','-n',ns,'-6','addr','add','2001:db8:353::'+a+'/64','dev','mgmt0','nodad')
   run('ip','-n',ns,'route','add','default','via','192.0.2.1');run('ip','-n',ns,'-6','route','add','default','via','2001:db8:353::1')
  else:
   cli(f'set interface ip address tap{id} 203.0.113.1/24');cli(f'set interface ip address tap{id} 2001:db8:9::1/64')
   run('ip','-n',ns,'addr','add','203.0.113.53/24','dev','mgmt0');run('ip','-n',ns,'-6','addr','add','2001:db8:9::53/64','dev','mgmt0','nodad')
   run('ip','-n',ns,'route','add','default','via','203.0.113.1');run('ip','-n',ns,'-6','route','add','default','via','2001:db8:9::1')
  run('ip','-n',ns,'link','set','mgmt0','up')
 run('ip','-n',names[0],'addr','add','198.51.100.10/32','dev','lo')
 run('ip','-n',names[0],'-6','addr','add','2001:db8:354::10/128','dev','lo','nodad')
 cli('ip route add 198.51.100.10/32 via 192.0.2.10 loop353')
 cli('ip route add 2001:db8:354::10/128 via 2001:db8:353::10 loop353')
 # Exercise the production helper against this isolated VPP, including reapply.
 import importlib.util
 spec=importlib.util.spec_from_file_location('intercept',Path(__file__).with_name('intercept.py'))
 intercept=importlib.util.module_from_spec(spec);spec.loader.exec_module(intercept)
 intercept.cli=lambda command: cli(command.replace('loop200','loop353').replace('10.61.20.2','192.0.2.2').replace('fd42:1111:2222:10::2','2001:db8:353::2'))
 intercept.INTERFACES=('loop353',)
 for version,anynet,gateway,source in [(4,'0.0.0.0/0','203.0.113.53',620),(6,'::/0','2001:db8:9::53',621)]:
  source_net='192.0.2.10/32' if version==4 else '2001:db8:353::10/128'
  result=cli(f'set acl-plugin acl tag other-{version} permit src {source_net} dst {anynet}')
  index=re.search(r'ACL index:\s*(\d+)',result)[1]
  cli(f'abf policy add id {source} acl {index} via {gateway} tap3533')
  cli(f'abf attach ip{version} policy {source} priority 0 loop353')
 addresses={4:{'192.0.2.2'},6:{'2001:db8:353::2'}}
 prefixes={4:['192.0.2.0/24'],6:['2001:db8:353::/64']}
 # Give the lab's source policies their intended priority explicitly.
 for version,source in [(4,620),(6,621)]:
  cli(f'abf attach ip{version} del policy {source} loop353')
  cli(f'abf attach ip{version} policy {source} priority 100 loop353')
 # The ABF policy an older helper left behind; apply() must retire it.
 for version,policy,anynet,via in [(4,530,'0.0.0.0/0','192.0.2.2'),(6,531,'::/0','2001:db8:353::2')]:
  result=cli(f'set acl-plugin acl permit src {anynet} dst {anynet} proto 17 dport 53 tag vrouter-dns-intercept{version}')
  cli(f'abf policy add id {policy} acl '+re.search(r'ACL index:\s*(\d+)',result)[1]+f' via {via} loop353')
  cli(f'abf attach ip{version} policy {policy} priority 0 loop353')
 intercept.apply(addresses,prefixes);intercept.apply(addresses,prefixes)
 attached=cli('show abf attach loop353');policies=cli('show abf policy');acls=cli('show acl-plugin acl')
 assert 'policy:530' not in attached+policies and 'policy:531' not in attached+policies,attached+policies
 assert 'vrouter-dns-intercept' not in acls,acls
 assert 'policy:620' in attached and 'policy:621' in attached,attached
 print(cli('show dns intercept'),flush=True)
 nft='table inet gate { chain pre { type nat hook prerouting priority dstnat; policy accept; meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 dnat ip to 192.0.2.2:1053; meta nfproto ipv6 meta l4proto { tcp, udp } th dport 53 dnat ip6 to [2001:db8:353::2]:1053; }; }'
 run('ip','netns','exec',names[1],'nft','-f','-',input=nft)
 for ns,role in [(names[1],'gate'),(names[2],'upstream')]:children.append(subprocess.Popen(['ip','netns','exec',ns,'python3',__file__,'server',role],env=ENV))
 time.sleep(.5)
 for ns,role in [(names[0],'client'),(names[1],'host'),(names[0],'vpn')]:print(run('ip','netns','exec',ns,'python3',__file__,'probe',role),flush=True)
 print('LAB PASSED '+str(root),flush=True)
finally:
 for c in children:c.terminate();c.wait(timeout=5)
 if vpp and vpp.poll() is None:vpp.terminate();vpp.wait(timeout=10)
 for ns in created:subprocess.run(['ip','netns','delete',ns],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
