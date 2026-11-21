#!/usr/bin/env python3
"""Rewrite disposable encrypted frames in memory on the isolated wire bridge."""
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time


def outer_header(frame, protocol, payload):
    header=bytearray(frame[:54])
    struct.pack_into('!H',header,18,len(payload))
    header[20]=protocol
    return bytes(header)+payload


def rewrite(frame, mode, mtu, ident):
    """Keep ESP/UDP bytes untouched; change only the unauthenticated outer IPv6."""
    protocol=frame[20]
    payload=frame[54:54+struct.unpack_from('!H',frame,18)[0]]
    if mode=='plain':
        return [frame[:54+len(payload)]]
    if mode in ('hop','dest','hop-dest'):
        ext=bytes([protocol,0,1,4,0,0,0,0])
        if mode=='hop-dest':
            return [outer_header(frame,0,bytes([60,0,1,4,0,0,0,0])+ext+payload)]
        return [outer_header(frame,0 if mode=='hop' else 60,ext+payload)]
    if mode=='atomic':
        return [outer_header(frame,44,struct.pack('!BBHI',protocol,0,0,ident)+payload)]
    # IPv6 fragments have an eight-byte header; non-final lengths are /8.
    split=8 if mode=='frag-first8' else ((mtu-48)//8)*8
    assert 0<split<len(payload) and split%8==0
    first=outer_header(frame,44,struct.pack('!BBHI',protocol,0,1,ident)+payload[:split])
    last=outer_header(frame,44,struct.pack('!BBHI',protocol,0,split,ident)+payload[split:])
    if mode=='frag-reverse':
        return [last,first]
    if mode=='frag-orphan':
        return [last]
    if mode=='frag-overlap':
        # Deliberate overlap by 8 bytes. Receiver must not deliver the packet.
        last=outer_header(frame,44,struct.pack('!BBHI',protocol,0,split-8,ident)+payload[split-8:])
    if mode=='frag-short-first':
        first=outer_header(frame,44,struct.pack('!BBHI',protocol,0,1,ident)+payload[:4])
    return [first,last]


def worker(root, native, mtu):
    src=socket.inet_pton(socket.AF_INET6,'2001:db8:60::2')
    dst=socket.inet_pton(socket.AF_INET6,'2001:db8:60::1')
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as rx, \
         socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd)) as tx:
        rx.bind(('to-client',0));tx.bind(('mgmt0',0))
        (root/'inject-ready').touch()
        done=set()
        while True:
            frame,address=rx.recvfrom(65536)
            if address[2]==4 or len(frame)<62 or frame[22:38]!=src or frame[38:54]!=dst:
                continue
            if native:
                if frame[20]!=50:continue
            else:
                if frame[20]!=17 or len(frame)<66:continue
                if struct.unpack_from('!H',frame,56)[0]!=4500 or frame[62:66]==b'\0'*4:continue
            request=json.loads((root/'inject-request.json').read_text())
            number=request['id']
            if number in done:continue
            packets=rewrite(frame,request['mode'],mtu,0x76000000+number)
            assert all(len(p)-14<=mtu for p in packets), 'Injector exceeded configured MTU'
            for packet in packets:
                tx.send(packet)
                if len(packets)>1:time.sleep(.01)
            done.add(number)
            result={'id':number,'mode':request['mode'],'original_l3':len(frame)-14,
                    'injected_l3':[len(p)-14 for p in packets],
                    'fragment_offsets':[struct.unpack_from('!H',p,56)[0]&0xfff8 for p in packets] if packets[0][20]==44 else []}
            temp=root/'inject-result.tmp';temp.write_text(json.dumps(result));temp.replace(root/'inject-result.json')


def checksum(data):
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535


def quote_cases(spi,native):
    esp=struct.pack('!II',spi,1)
    transport=esp if native else struct.pack('!HHHH',4500,4500,16,1)+esp
    protocol=50 if native else 17
    def ip(next_header,body):
        return struct.pack('!IHBB16s16s',6<<28,len(body),next_header,64,
            socket.inet_pton(socket.AF_INET6,'2001:db8:60::1'),
            socket.inet_pton(socket.AF_INET6,'2001:db8:60::2'))+body
    ext=bytes([protocol,0,1,4,0,0,0,0])
    frag=lambda bits:struct.pack('!BBHI',protocol,0,bits,42)
    short=bytearray(ip(protocol,transport));struct.pack_into('!H',short,4,3)
    return [
        ('plain',ip(protocol,transport),True),
        ('hop',ip(0,ext+transport),True),
        ('dest',ip(60,ext+transport),True),
        ('hop-dest',ip(0,bytes([60,0,1,4,0,0,0,0])+ext+transport),True),
        ('atomic',ip(44,frag(0)+transport),True),
        ('first-fragment',ip(44,frag(1)+transport),True),
        ('nonfirst-spi-lookalike',ip(44,frag(8)+transport),False),
        ('truncated-extension',ip(60,bytes([protocol,255])+b'\0'*6+transport),False),
        ('truncated-spi',ip(protocol,transport[:-5]),False),
        ('declared-payload-short',bytes(short),False),
        ('zero-marker',ip(17,struct.pack('!HHHH',4500,4500,16,1)+b'\0'*8),False),
    ]


def verify_quotes(names,root,mtu,native,run,cli):
    import re
    # SA text contains keys; restrict derived data to the header SPI integers.
    headers=re.findall(r'(?m)^\[.*$',cli('show ipsec sa'))
    spis=[int(re.search(r'\bspi (\d+)',h)[1]) for h in headers]
    assert len(spis)==2, 'Expected exactly one temporary SA pair'
    def count():
        for line in cli('show errors').splitlines():
            if 'outer PTB bound to outbound SPI' in line:
                return int(line.split()[0])
        return 0
    neigh=json.loads(run('ip','-n',names['client'],'-j','-6','neigh','show','to','2001:db8:60::1'))
    dst_mac=bytes.fromhex(neigh[0]['lladdr'].replace(':',''))
    src_mac=bytes.fromhex(json.loads(run('ip','-n',names['wire'],'-j','link','show','mgmt0'))[0]['address'].replace(':',''))
    src=socket.inet_pton(socket.AF_INET6,'2001:db8:60::fe')
    dst=socket.inet_pton(socket.AF_INET6,'2001:db8:60::1')
    results=[]
    for index,(name,unused,expected) in enumerate(quote_cases(spis[0],native)):
        before=count()
        for spi in spis:
            quoted=quote_cases(spi,native)[index][1]
            icmp=struct.pack('!BBHI',2,0,0,mtu)+quoted
            pseudo=src+dst+struct.pack('!I3xB',len(icmp),58)
            icmp=icmp[:2]+struct.pack('!H',checksum(pseudo+icmp))+icmp[4:]
            packet=dst_mac+src_mac+b'\x86\xdd'+struct.pack('!IHBB16s16s',6<<28,len(icmp),58,64,src,dst)+icmp
            subprocess.run(['ip','netns','exec',names['wire'],'python3',str(Path(__file__).resolve()),'--send'],
                input=packet,capture_output=True,check=True,timeout=4)
        time.sleep(.15)
        learned=count()-before
        results.append({'case':name,'expected_association':expected,'learned_delta':learned,
                        'passed':(learned==1 if expected else learned==0)})
    return {'cases':results,'passed':all(r['passed'] for r in results),
            'quote_payloads_saved':False,'outer_ptb_mtu':mtu}


def verify(root,names,source6,mtu,native,run,wait,start,cli):
    path=Path(__file__).resolve()
    # Block the original ESP on bridge forward; AF_PACKET sees it before the
    # drop. Only rewritten ciphertext is sent toward VPP, once per sequence.
    match='ip6 nexthdr 50' if native else 'ip6 nexthdr 17 udp dport 4500 @th,64,32 != 0'
    rules='table bridge vrouter_ipsec_inject { chain forward { type filter hook forward priority -300; policy accept; '+\
          'iifname "to-client" ether type ip6 ip6 saddr 2001:db8:60::2 ip6 daddr 2001:db8:60::1 '+match+' counter drop; }\n}\n'
    root.joinpath('inject-request.json').write_text(json.dumps({'id':0,'mode':'plain'}))
    process=start(['ip','netns','exec',names['wire'],'python3',str(path),'--worker',str(root),str(int(native)),str(mtu)],'inject.log')
    wait(lambda:(root/'inject-ready').exists(),'Ciphertext injector did not start')
    installed=False
    results=[]
    modes=('plain','hop','dest','hop-dest','atomic','frag-boundary','frag-reverse','frag-first8',
           'frag-orphan','frag-overlap','frag-short-first')
    try:
        nft=subprocess.run(['ip','netns','exec',names['wire'],'nft','-f','-'],input=rules+'\n',text=True,
                           capture_output=True,timeout=5)
        if nft.returncode:
            raise RuntimeError('Isolated bridge rule rejected: '+nft.stderr[-1200:])
        installed=True
        fixed=72+(0 if native else 8)
        for number,mode in enumerate(modes,1):
            extra=16 if mode=='hop-dest' else (8 if mode in ('hop','dest','atomic') else 0)
            inner=((mtu-extra-fixed)//4)*4-2
            request=root/'inject-request.tmp';request.write_text(json.dumps({'id':number,'mode':mode}));request.replace(root/'inject-request.json')
            (root/'inject-result.json').unlink(missing_ok=True)
            before=cli('show errors')
            probe=subprocess.run(['ip','netns','exec',names['client'],'ping','-6','-I',source6,'-n',
                '-c','1','-W','1','-M','do','-s',str(inner-48),'2001:db8:62::2'],capture_output=True,text=True,timeout=4)
            wait(lambda:(root/'inject-result.json').exists(),'No ciphertext was intercepted for '+mode)
            record=json.loads((root/'inject-result.json').read_text())
            record.update({'inner_l3':inner,'delivered':probe.returncode==0,
                'expected_delivery':mode not in ('frag-orphan','frag-overlap','frag-short-first'),
                'errors_before':before,'errors_after':cli('show errors')})
            record['passed']=record['delivered']==record['expected_delivery']
            results.append(record)
        # A normal fresh ESP sequence must work after every malformed case.
    finally:
        if installed:
            run('ip','netns','exec',names['wire'],'nft','delete','table','bridge','vrouter_ipsec_inject')
        process.terminate();process.wait(timeout=5)
    control=subprocess.run(['ip','netns','exec',names['client'],'ping','-6','-I',source6,'-n',
        '-c','3','-i','.1','-W','1','2001:db8:62::2'],capture_output=True,text=True,timeout=5)
    quotes=verify_quotes(names,root,mtu,native,run,cli)
    return {'ptb_quotes':quotes,'cases':results,'post_injection_control':control.returncode==0,
            'passed':all(r['passed'] for r in results) and control.returncode==0 and quotes['passed'],
            'ciphertext_saved':False,'nft_table_removed':True,'mss_clamp_enabled':False}


if __name__=='__main__':
    import sys
    if sys.argv[1]=='--send':
        with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd)) as sock:
            sock.bind(('mgmt0',0));sock.send(sys.stdin.buffer.read())
    elif sys.argv[1]=='--worker':
        worker(Path(sys.argv[2]),bool(int(sys.argv[3])),int(sys.argv[4]))
