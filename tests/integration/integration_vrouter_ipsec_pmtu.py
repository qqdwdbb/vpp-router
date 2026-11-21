#!/usr/bin/env python3
"""Bounded bidirectional size probes; observations are not PMTUD acceptance."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def verify(root, names, source4, source6, mtu, native, run, cli, capture, wait, start, echo, tcp_client, diagnose=False):
    # AES-GCM16: IPv6(40), UDP(0/8), ESP header(8), IV(8), ICV(16),
    # then inner packet plus pad length / next header rounded to four bytes.
    fixed = 72 + (0 if native else 8)
    boundary = ((mtu-fixed)//4)*4-2
    probes = []
    def snapshot():
        path = root/'outer-capture.json'
        for attempt in range(5):
            path.unlink(missing_ok=True)
            try:
                os.kill(capture.pid, signal.SIGUSR1)
            except ProcessLookupError as exc:
                raise RuntimeError('PMTU capture process died') from exc
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if path.exists():
                    return json.loads(path.read_text())
                time.sleep(.05)
        raise RuntimeError('PMTU capture snapshot missing')
    for role in ('client','lan'):
        for family, source, destination in ((4,source4,'10.254.62.2'),(6,source6,'2001:db8:62::2')):
            if role=='lan':
                source,destination=destination,source
            for length in sorted({boundary-1,boundary,boundary+1,1280,1500}):
                before=snapshot()
                args=['ip','netns','exec',names[role],'ping','-'+str(family),'-I',source,
                      '-n','-c','1','-W','1','-M','do','-s',str(length-(28 if family==4 else 48)),destination]
                probe=subprocess.run(args,capture_output=True,text=True,timeout=4)
                after=snapshot()
                observed={}
                for direction in after:
                    observed[direction]={}
                    for field in ('lengths','icmp_errors','ptb_mtu'):
                        observed[direction][field]={k:v-before[direction][field].get(k,0)
                            for k,v in after[direction][field].items() if v-before[direction][field].get(k,0)>0}
                    for field in ('outer_fragments','first_fragments','nonfirst_fragments'):
                        observed[direction][field]=after[direction][field]-before[direction][field]
                output=probe.stdout+probe.stderr
                probes.append({'sender':role,'inner_family':family,'inner_l3_bytes':length,
                    'unfragmented_outer_l3_bytes':fixed+((length+2+3)//4)*4,
                    'success':probe.returncode==0,'feedback':output[-1600:],'wire_delta':observed})
    extension_probes=[]
    extension_client = """import socket,struct,sys,json
s=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6)
s.settimeout(1);s.bind((sys.argv[1],0))
s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_HOPOPTS,bytes([58,0,1,4,0,0,0,0]))
s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_DONTFRAG,1)
packet=struct.pack('!BBHHH',128,0,0,31961,1)+bytes(int(sys.argv[3])-56)
try:
 s.sendto(packet,(sys.argv[2],0))
 while True:
  data,peer=s.recvfrom(65536)
  if len(data)>=8 and data[0]==129 and struct.unpack_from('!H',data,4)[0]==31961:
   print(json.dumps({'success':True}));break
except OSError as exc:
 print(json.dumps({'success':False,'errno':exc.errno,'reason':str(exc)}))
"""
    if not diagnose:
        for role,source,destination in (('client',source6,'2001:db8:62::2'),('lan','2001:db8:62::2',source6)):
            for length in (boundary,boundary+1):
                probe=subprocess.run(['ip','netns','exec',names[role],'python3','-c',extension_client,
                    source,destination,str(length)],capture_output=True,text=True,timeout=4)
                extension_probes.append({'sender':role,'inner_l3_bytes':length,'extension':'hop-by-hop-padn',
                    'result':json.loads(probe.stdout) if probe.returncode==0 else {'error':'probe process failed'}})
    routed = None
    if mtu==1500:
        # Replace only the disposable bridge with a real IPv6 router. Both
        # tunnel endpoints keep a 1500 link; the router egress is 1280.
        wire=names['wire']
        for device in ('mgmt0','to-client'):
            run('ip','-n',wire,'link','set',device,'nomaster')
        for device,addr,peer in (('mgmt0','2001:db8:60::fe','2001:db8:60::1'),
                                  ('to-client','2001:db8:60::fd','2001:db8:60::2')):
            run('ip','-n',wire,'-6','addr','add',addr+'/128','dev',device,'nodad')
            run('ip','-n',wire,'-6','route','add',peer+'/128','dev',device)
        run('ip','netns','exec',wire,'sysctl','-qw','net.ipv6.conf.all.forwarding=1')
        run('ip','-n',names['client'],'-6','route','add','2001:db8:60::1/128',
            'via','2001:db8:60::fd','dev','mgmt0','onlink')
        cli('ip route add 2001:db8:60::2/128 via 2001:db8:60::fe tap3960')
        run('ip','-n',names['client'],'-6','neigh','replace','2001:db8:60::fd',
            'lladdr',json.loads(run('ip','-n',wire,'-j','link','show','to-client'))[0]['address'],
            'nud','permanent','dev','mgmt0')
        mac=json.loads(run('ip','-n',wire,'-j','link','show','mgmt0'))[0]['address']
        cli('set ip neighbor tap3960 2001:db8:60::fe '+mac)
        for source,destination in ((source4,'10.254.62.2'),(source6,'2001:db8:62::2')):
            warm=subprocess.run(['ip','netns','exec',names['client'],'ping','-I',source,
                '-n','-c','3','-i','.2','-W','1','-s','32',destination],capture_output=True,text=True,timeout=5)
            assert warm.returncode==0, 'Routed PMTU topology failed small-packet control'
        routed={'router_egress_mtu':1280,'router_egress_interface':'to-client','reverse_egress_mtu':1500,'endpoint_link_mtu':1500,'probes':[]}
        # Keep the VPP-facing TAP at 1500: lowering its host-side MTU
        # would introduce a local TAP limit before the routed bottleneck.
        run('ip','-n',wire,'link','set','to-client','mtu','1280')
        # Repeated packets distinguish one PTB from actual convergence.
        for role,source,destination in (('client',source4,'10.254.62.2'),
                                        ('lan','10.254.62.2',source4),
                                        ('client',source6,'2001:db8:62::2'),
                                        ('lan','2001:db8:62::2',source6)):
            before=snapshot()
            probe=subprocess.run(['ip','netns','exec',names[role],'ping','-I',source,
                '-n','-c','3','-i','.3','-W','1','-M','do','-s','1300',destination],
                capture_output=True,text=True,timeout=6)
            after=snapshot()
            routed['probes'].append({'sender':role,'family':6 if ':' in source else 4,
                'success':probe.returncode==0,'feedback':(probe.stdout+probe.stderr)[-2000:],
                'ptb_to_vpp':after['client_to_server']['icmp_errors'].get('6:2:0',0)-before['client_to_server']['icmp_errors'].get('6:2:0',0),
                'advertised_ptb_mtu':after['client_to_server']['ptb_mtu'],
                'wire_after':after})
        # Client XFRM ENOBUFS on large inner IPv4, and ICMP echo to the EI
        # outside address is local to VPP. Create a UDP mapping, then send a
        # DF 1200-byte datagram from LAN to the mapped outside 5-tuple so
        # out2in translates and VPP encrypts the oversized inner IPv4 packet.
        lan_udp='''import json,socket,sys,threading
from pathlib import Path
root=Path(sys.argv[1])
frames=[]
stop=threading.Event()
def sniff():
 try:
  p=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
  p.bind(("mgmt0",0));p.settimeout(.2)
  (root/"ipv4-udp-sniff-ready").touch()
  while not stop.is_set():
   try:
    frame=p.recv(65536)
   except socket.timeout:
    continue
   if len(frame)>=34 and frame[12:14]==b"\\x08\\x00" and frame[23]==1 and len(frames)<16:
    frames.append(frame.hex())
  p.close()
 except Exception as exc:
  (root/"ipv4-udp-sniff-error").write_text(str(exc))
threading.Thread(target=sniff,daemon=True).start()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.setsockopt(socket.IPPROTO_IP,getattr(socket,"IP_MTU_DISCOVER",10),getattr(socket,"IP_PMTUDISC_DO",2))
s.setsockopt(socket.IPPROTO_IP,getattr(socket,"IP_RECVERR",11),1)
s.bind(("10.254.62.2",49880));s.settimeout(3)
(root/"ipv4-udp-ready").touch()
info={"recv":0}
def errqueue():
 try:
  s.recvmsg(256,256,getattr(socket,"MSG_ERRQUEUE",0x2000))
  return True
 except OSError:
  return False
try:
 data,peer=s.recvfrom(65536)
 info={"recv":len(data),"peer":list(peer)}
 try:
  s.sendto(bytes(1200),peer);info["sent"]=1200
  s.settimeout(1.5)
  try:
   extra,who=s.recvfrom(65536);info["extra"]=len(extra)
  except socket.timeout:
   info["reply_timeout"]=True
  info["errqueue"]=errqueue()
  try:
   s.sendto(bytes(1200),peer);info["second_sent"]=1200
  except OSError as exc:
   info["second_errno"]=exc.errno;info["second_error"]=str(exc)
 except OSError as exc:
  info["errno"]=exc.errno;info["error"]=str(exc)
except OSError as exc:
 info={"errno":exc.errno,"error":str(exc)}
stop.set()
info["icmp_frames"]=frames
(root/"ipv4-udp-lan.json").write_text(json.dumps(info))
'''
        start(['ip','netns','exec',names['lan'],'python3','-c',lan_udp,str(root)],'ipv4-udp-lan.log')
        wait(lambda:(root/'ipv4-udp-ready').exists() and (root/'ipv4-udp-sniff-ready').exists(),
             'IPv4 mapped UDP listener missing')
        ipv4_before=cli('show errors')
        ipv4_runtime_before=cli('show runtime')
        client_udp=subprocess.run(['ip','netns','exec',names['client'],'python3','-c',
            'import json,socket,sys\n'
            's=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],0));s.settimeout(2)\n'
            's.sendto(b"x"*32,("10.254.62.2",49880))\n'
            'try:\n d,p=s.recvfrom(65536);print(json.dumps({"recv":len(d),"peer":list(p)}))\n'
            'except Exception as exc:\n print(json.dumps({"recv":0,"error":str(exc),"errno":getattr(exc,"errno",None)}))\n',
            source4],capture_output=True,text=True,timeout=6)
        wait(lambda:(root/'ipv4-udp-lan.json').exists(),'IPv4 mapped UDP result missing')
        lan_udp_result=json.loads((root/'ipv4-udp-lan.json').read_text())
        ipv4_after=cli('show errors')
        def error_count(text, reason):
            for line in text.splitlines():
                if reason in line:
                    return int(line.split()[0])
            return 0
        ipv4_icmp=error_count(ipv4_after,'inner ICMPv4 fragmentation-needed')>error_count(ipv4_before,'inner ICMPv4 fragmentation-needed')
        lan_emsgsize=90 in (lan_udp_result.get('errno'),lan_udp_result.get('second_errno'))
        from integration_vrouter_ipsec_diagnose import decode_frame
        lan_icmp=[]
        for hex_frame in lan_udp_result.get('icmp_frames') or []:
            try:
                decoded=decode_frame(bytes.fromhex(hex_frame))
            except ValueError:
                decoded=None
            if decoded:
                lan_icmp.append(decoded)
        lan_frag=[p for p in lan_icmp if p.get('icmp_type')==3 and p.get('icmp_code')==4]
        quoted_outside=any(p.get('quoted_dst')=='10.254.62.1' for p in lan_frag)
        routed['ipv4_return_pmtu']={
            'success':bool(ipv4_icmp and (lan_emsgsize or quoted_outside)),
            'method':'mapped-udp-df-1200','lan':lan_udp_result,
            'client':json.loads(client_udp.stdout) if client_udp.stdout.strip().startswith('{') else {
                'error':(client_udp.stdout+client_udp.stderr)[-800:]},
            'vpp_inner_icmp4':bool(ipv4_icmp),'lan_emsgsize':lan_emsgsize,
            'lan_type3_code4':bool(lan_frag),'quoted_outside':quoted_outside,
            'lan_icmp':lan_icmp,'pmtu_table':cli('show ipsec pmtu'),
            'errors_before':ipv4_before,'errors_after':ipv4_after,
            'runtime_before':ipv4_runtime_before,'runtime_after':cli('show runtime')}
        routed['tcp']=[]
        if not diagnose:
            start(['ip','netns','exec',names['lan'],'python3','-u','-c',echo,str(root/'routed-echo-')], 'routed-echo.log')
            wait(lambda:all((root/f'routed-echo-{port}').exists() for port in (49870,49871)),
                 'Routed TCP listeners missing')
            for source,destination,port in ((source4,'10.254.62.2',49870),(source6,'2001:db8:62::2',49871)):
                try:
                    probe=subprocess.run(['ip','netns','exec',names['client'],'python3','-c',tcp_client,
                        source,destination,str(port),'262144'],capture_output=True,text=True,timeout=20)
                    metric={'family':6 if ':' in source else 4,'success':probe.returncode==0}
                    if probe.returncode==0:
                        metric['client']=json.loads(probe.stdout)
                        wait(lambda:(root/f'routed-echo-{port}-tcp').exists(),'Routed TCP server metrics missing')
                        metric['server']=json.loads((root/f'routed-echo-{port}-tcp').read_text())
                    else:
                        metric['error']='TCP exchange failed or timed out'
                        metric['diagnostic']=probe.stderr[-1200:]
                except subprocess.TimeoutExpired:
                    metric={'family':6 if ':' in source else 4,'success':False,'error':'20 second timeout'}
                routed['tcp'].append(metric)
        routed['small_packet_controls']=[]
        for source,destination in ((source4,'10.254.62.2'),(source6,'2001:db8:62::2')):
            small=subprocess.run(['ip','netns','exec',names['client'],'ping','-I',source,
                '-n','-c','3','-i','.2','-W','1','-s','32',destination],capture_output=True,text=True,timeout=5)
            routed['small_packet_controls'].append({'family':6 if ':' in source else 4,
                'success':small.returncode==0,'feedback':(small.stdout+small.stderr)[-1200:]})
        if diagnose:
            from integration_vrouter_ipsec_diagnose import diagnose_drop_nodes
            routed['drop_nodes']=diagnose_drop_nodes(
                root, names, source4, source6, native, run, cli, wait, start,
                Path(__file__).resolve().parent/'integration_vrouter_ipsec_diagnose.py')
        if not diagnose and any(not p['success'] for p in routed['tcp']) and all(p['success'] for p in routed['small_packet_controls']):
            path_limit=((1280-fixed)//4)*4-2
            mss4,mss6=path_limit-40,path_limit-60
            cli(f'set interface tcp-mss-clamp tap3962 ip4 enable ip4-mss {mss4} ip6 enable ip6-mss {mss6}')
            routed['mss_mitigation']={'interface':'tap3962','ip4_mss':mss4,'ip6_mss':mss6,'tcp':[]}
            clamp_echo=echo.replace('49870','49874').replace('49871','49875')
            start(['ip','netns','exec',names['lan'],'python3','-u','-c',clamp_echo,str(root/'clamp-echo-')], 'clamp-echo.log')
            wait(lambda:all((root/f'clamp-echo-{port}').exists() for port in (49874,49875)),
                 'Clamped TCP listeners missing')
            for source,destination,port in ((source4,'10.254.62.2',49874),(source6,'2001:db8:62::2',49875)):
                try:
                    probe=subprocess.run(['ip','netns','exec',names['client'],'python3','-c',tcp_client,
                        source,destination,str(port),'262144'],capture_output=True,text=True,timeout=20)
                    metric={'family':6 if ':' in source else 4,'success':probe.returncode==0}
                    if probe.returncode:
                        metric['diagnostic']=probe.stderr[-1200:]
                    if probe.returncode==0:
                        metric['client']=json.loads(probe.stdout)
                        wait(lambda:(root/f'clamp-echo-{port}-tcp').exists(),'Clamped TCP metrics missing')
                        metric['server']=json.loads((root/f'clamp-echo-{port}-tcp').read_text())
                except subprocess.TimeoutExpired:
                    metric={'family':6 if ':' in source else 4,'success':False,'error':'20 second timeout'}
                routed['mss_mitigation']['tcp'].append(metric)
            cli('set interface tcp-mss-clamp tap3962 ip4 disable ip6 disable')
        routed['vpp_errors']=cli('show errors')
        routed['pmtu_table']=cli('show ipsec pmtu')
        # Restore the isolated bridge so normal rekey/cleanup remains exercised.
        run('ip','-n',names['client'],'-6','neigh','del','2001:db8:60::fd','dev','mgmt0')
        cli('set ip neighbor del tap3960 2001:db8:60::fe '+mac)
        run('ip','-n',names['client'],'-6','route','del','2001:db8:60::1/128')
        cli('ip route del 2001:db8:60::2/128 via 2001:db8:60::fe tap3960')
        for device,addr,peer in (('mgmt0','2001:db8:60::fe','2001:db8:60::1'),
                                  ('to-client','2001:db8:60::fd','2001:db8:60::2')):
            run('ip','-n',wire,'-6','route','del',peer+'/128','dev',device)
            run('ip','-n',wire,'-6','addr','del',addr+'/128','dev',device)
            run('ip','-n',wire,'link','set',device,'mtu','1500')
            run('ip','-n',wire,'link','set',device,'master','br-wire')
    def inner_icmp_feedback(text):
        t = (text or '').lower()
        return any(s in t for s in ('packet too big', 'frag needed', 'message too long'))
    ptb_blackhole = bool(routed and all(p['success'] for p in routed['small_packet_controls']) and any(
        p['sender']=='lan' and p['ptb_to_vpp']>0 and not p['success'] and not inner_icmp_feedback(p['feedback'])
        for p in routed['probes']))
    result={'ptb_blackhole_observed':ptb_blackhole,'inner_extension_probes':extension_probes,'routed_bottleneck':routed,'link_mtu':mtu,'unfragmented_inner_limit':boundary,'mss_clamp_added':bool(routed and 'mss_mitigation' in routed),
            'probes':probes,'acceptance':'diagnostic' if diagnose else ('failed' if ptb_blackhole else 'incomplete'),
            'remaining':['deliberate outer extension-header and fragment-boundary injection beyond hop-by-hop PadN']}
    (root/'pmtu-counters.log').write_text(json.dumps(result,indent=2))
    return result


def capture_syn(root):
    """Record only handshake MSS on the isolated cleartext LAN TAP."""
    import socket
    import struct
    records=[]
    def snapshot(*unused):
        temp=root/'tcp-syn.tmp'
        temp.write_text(json.dumps(records))
        temp.replace(root/'tcp-syn.json')
    signal.signal(signal.SIGUSR1,snapshot)
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as sock:
        sock.bind(('mgmt0',0))
        (root/'tcp-syn-ready').touch()
        while True:
            frame=sock.recv(65536)
            if len(frame)<54:
                continue
            ether=struct.unpack_from('!H',frame,12)[0]
            if ether==0x0800:
                family,protocol,offset=4,frame[23],14+(frame[14]&15)*4
            elif ether==0x86dd:
                family,protocol,offset=6,frame[20],54
            else:
                continue
            if protocol!=6 or len(frame)<offset+20:
                continue
            flags=frame[offset+13]
            if not flags&2:
                continue
            sport,dport=struct.unpack_from('!HH',frame,offset)
            if not {sport,dport}&{49870,49871,49874,49875}:
                continue
            end=min(len(frame),offset+(frame[offset+12]>>4)*4)
            cursor=offset+20
            mss=None
            while cursor<end:
                kind=frame[cursor]
                if kind==0:break
                if kind==1:
                    cursor+=1
                    continue
                if cursor+2>end:break
                length=frame[cursor+1]
                if length<2 or cursor+length>end:break
                if kind==2 and length==4:
                    mss=struct.unpack_from('!H',frame,cursor+2)[0]
                cursor+=length
            record={'family':family,'syn_ack':bool(flags&16),'mss':mss}
            if record not in records and len(records)<32:
                records.append(record)


if __name__=='__main__':
    import sys
    capture_syn(Path(sys.argv[1]))
