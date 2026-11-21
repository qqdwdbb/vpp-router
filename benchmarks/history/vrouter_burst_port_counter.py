import json,os,pathlib,struct,subprocess,sys,time
pmd='/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1'
pid=subprocess.check_output(['pidof','vpp'],text=True).split()[0]
maps=pathlib.Path('/proc/'+pid+'/maps').read_text().splitlines()
m=next(l.split() for l in maps if pmd in l and int(l.split()[2],16)==0)
base=int(m[0].split('-')[0],16)
rows=subprocess.check_output(['nm','-S',pmd],text=True).splitlines()
line=next(x.split() for x in rows if x.endswith(' rtl_rx_observe'))
addr=base+int(line[0],16);size=(1+16*67)*8
fd=os.open('/proc/'+pid+'/mem',os.O_RDWR)
try:
 if sys.argv[1]=='start':
  os.pwrite(fd,bytes(size),addr);os.pwrite(fd,struct.pack('<Q',1),addr)
 else:
  os.pwrite(fd,struct.pack('<Q',0),addr);time.sleep(.02)
  vals=struct.unpack('<1073Q',os.pread(fd,size,addr))
  ports=[]
  for i in range(16):
   v=vals[1+i*67:1+(i+1)*67];ports.append({'port':i,'calls':v[0],'packets':v[1],'bins':list(v[2:])})
  print(json.dumps({'pid':pid,'ports':ports}))
finally:os.close(fd)
