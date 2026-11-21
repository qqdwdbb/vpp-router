#!/usr/bin/env python3
"""Count outer IPsec packets in memory; write snapshots only on SIGUSR1."""
import ipaddress
import json
from pathlib import Path
import signal
import socket
import struct
import sys


def capture(root, mtu=1500, interface='mgmt0'):
    fields = ('ike_udp500','ike_udp4500','esp_udp4500','esp_native','ipv4_ipsec','plaintext_leak','max_l3_bytes','oversize_l3','outer_fragments','first_fragments','nonfirst_fragments','extension_headers')
    counts = {direction:dict.fromkeys(fields,0) for direction in ('client_to_server','server_to_client')}
    for counters in counts.values():
        counters['lengths']={}
        counters['icmp_errors']={}
        counters['ptb_mtu']={}
    endpoints = {'2001:db8:60::1','2001:db8:60::2'}
    pools = {4:ipaddress.ip_network('10.254.61.0/24'),6:ipaddress.ip_network('2001:db8:61::/64')}
    targets = {'10.254.62.2','2001:db8:62::2'}
    def snapshot(*unused):
        path = root/'outer-capture.json'
        temp = path.with_suffix('.tmp')
        temp.write_text(json.dumps(counts))
        temp.replace(path)
    signal.signal(signal.SIGUSR1,snapshot)
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as sock:
        sock.bind((interface,0))
        (root/'outer-capture-ready').touch()
        while True:
            frame=sock.recv(131072)
            if len(frame)<34:
                continue
            ether=struct.unpack_from('!H',frame,12)[0]
            if ether==0x86dd and len(frame)>=54:
                src=socket.inet_ntop(socket.AF_INET6,frame[22:38])
                dst=socket.inet_ntop(socket.AF_INET6,frame[38:54])
                protocol, offset=frame[20],54
                is6=True
            elif ether==0x0800:
                src=socket.inet_ntoa(frame[26:30]);dst=socket.inet_ntoa(frame[30:34])
                protocol, offset=frame[23],14+(frame[14]&15)*4
                is6=False
            else:
                continue
            pool=pools[6 if is6 else 4]
            if dst in targets and ipaddress.ip_address(src) in pool:
                counts['client_to_server']['plaintext_leak']+=1
            if src in targets and ipaddress.ip_address(dst) in pool:
                counts['server_to_client']['plaintext_leak']+=1
            if is6:
                if {src,dst}==endpoints:
                    direction='client_to_server' if src.endswith('::2') else 'server_to_client'
                elif protocol==58 and src in {'2001:db8:60::fd','2001:db8:60::fe'} and dst in endpoints:
                    direction='client_to_server' if dst.endswith('::1') else 'server_to_client'
                else:
                    continue
            else:
                if {src,dst}!={'198.18.60.1','198.18.60.2'}:
                    continue
                direction='client_to_server' if src.endswith('.2') else 'server_to_client'
            size = (40+struct.unpack_from('!H',frame,18)[0]) if is6 else struct.unpack_from('!H',frame,16)[0]
            counts[direction]['max_l3_bytes']=max(counts[direction]['max_l3_bytes'],size)
            lengths=counts[direction]['lengths']
            lengths[str(size)]=lengths.get(str(size),0)+1
            if size>mtu:counts[direction]['oversize_l3']+=1
            if is6:
                end = min(len(frame),14+size)
                for _ in range(16):
                    if protocol not in (0,43,44,51,60):
                        break
                    if offset+8>end:
                        protocol=None
                        break
                    counts[direction]['extension_headers']+=1
                    following=frame[offset]
                    if protocol==44:
                        counts[direction]['outer_fragments']+=1
                        fragment=struct.unpack_from('!H',frame,offset+2)[0]
                        counts[direction]['nonfirst_fragments' if fragment & 0xfff8 else 'first_fragments']+=1
                        if fragment & 0xfff8:
                            protocol=None
                            break
                        length=8
                    else:
                        length=(frame[offset+1]+(2 if protocol==51 else 1))*(4 if protocol==51 else 8)
                    if offset+length>end:
                        protocol=None
                        break
                    protocol,offset=following,offset+length
            if protocol in (1,58) and len(frame)>=offset+8 and ((protocol==58 and frame[offset]<128) or (protocol==1 and frame[offset] in (3,11,12))):
                key=f'{6 if is6 else 4}:{frame[offset]}:{frame[offset+1]}'
                errors=counts[direction]['icmp_errors']
                errors[key]=errors.get(key,0)+1
                if protocol==58 and frame[offset]==2:
                    advertised=str(struct.unpack_from('!I',frame,offset+4)[0])
                    mtus=counts[direction]['ptb_mtu']
                    mtus[advertised]=mtus.get(advertised,0)+1
            kind=None
            if protocol==50 and len(frame)>=offset+8:
                kind='esp_native'
            elif protocol==17 and len(frame)>=offset+8:
                sport,dport=struct.unpack_from('!HH',frame,offset)
                if sport==dport==500:
                    kind='ike_udp500'
                elif sport==dport==4500 and len(frame)>=offset+12:
                    marker=struct.unpack_from('!I',frame,offset+8)[0]
                    kind='ike_udp4500' if marker==0 else 'esp_udp4500'
            if kind:
                counts[direction][kind if is6 else 'ipv4_ipsec']+=1


if __name__=='__main__':
    capture(Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv)>2 else 1500,
            sys.argv[3] if len(sys.argv)>3 else 'mgmt0')
