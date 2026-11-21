#!/usr/bin/env python3
"""Minimal raw DHCP DORA/renew probe, run only in an isolated client netns."""
import json
import os
import socket
import struct
import subprocess
import time


def main(expected_gateway='198.18.44.1', expected_dns='198.18.44.2', pool_end=120):
    interface = 'mgmt0'
    link = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'dev', interface], text=True))[0]
    mac = bytes.fromhex(link['address'].replace(':', ''))
    xid = int.from_bytes(os.urandom(4), 'big')
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.bind((interface, 0))
    sock.settimeout(.2)

    def send(kind, requested=None, server=None, ciaddr='0.0.0.0'):
        renewal = ciaddr != '0.0.0.0'
        bootp = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', 1, 1, 6, 0, xid, 0,
                            0 if renewal else 0x8000, socket.inet_aton(ciaddr), b'\0'*4,
                            b'\0'*4, b'\0'*4, mac.ljust(16, b'\0'), b'\0'*64, b'\0'*128)
        options = b'\x63\x82\x53\x63\x35\x01' + bytes([kind]) + b'\x37\x03\x01\x03\x06'
        if requested:
            options += b'\x32\x04' + socket.inet_aton(requested)
        if server and not renewal:
            options += b'\x36\x04' + socket.inet_aton(server)
        payload = (bootp + options + b'\xff').ljust(300, b'\0')
        if renewal:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind((ciaddr, 68))
            udp_socket.sendto(payload, (server, 67))
            return udp_socket
        udp = struct.pack('!HHHH', 68, 67, 8+len(payload), 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), 0, 0, 64, 17, 0,
                         socket.inet_aton(ciaddr), socket.inet_aton(server if renewal else '255.255.255.255'))
        total = sum(struct.unpack('!10H', ip))
        while total >> 16:
            total = (total & 65535) + (total >> 16)
        ip = ip[:10] + struct.pack('!H', (~total) & 65535) + ip[12:]
        sock.send(b'\xff'*6 + mac + b'\x08\x00' + ip + udp)

    def receive(kind):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            try:
                packet = sock.recv(4096)
            except socket.timeout:
                continue
            if len(packet) < 14+20+8+240 or packet[12:14] != b'\x08\x00':
                continue
            ip = packet[14:]
            ihl = (ip[0] & 15)*4
            if ip[9] != 17 or struct.unpack('!HH', ip[ihl:ihl+4]) != (67, 68):
                continue
            bootp = ip[ihl+8:]
            if bootp[0] != 2 or int.from_bytes(bootp[4:8], 'big') != xid:
                continue
            if bootp[236:240] != b'\x63\x82\x53\x63':
                continue
            options, pos = {}, 240
            while pos < len(bootp):
                code = bootp[pos]
                pos += 1
                if code == 255:
                    break
                if code == 0:
                    continue
                length = bootp[pos]
                pos += 1
                options[code] = bootp[pos:pos+length]
                pos += length
            if options.get(53) == bytes([kind]):
                return socket.inet_ntoa(bootp[16:20]), options
        raise RuntimeError('DHCP reply timed out')

    with sock:
        send(1)
        address, offer = receive(2)
        server = socket.inet_ntoa(offer[54])
        send(3, address, server)
        assigned, ack = receive(5)
        assert assigned == address
        assert socket.inet_ntoa(ack[1]) == '255.255.255.0'
        gateway, dns = socket.inet_ntoa(ack[3]), socket.inet_ntoa(ack[6])
        assert gateway == expected_gateway and dns == expected_dns and server == dns
        assert 100 <= int(address.rsplit('.', 1)[1]) <= pool_end
        subprocess.run(['ip', 'address', 'replace', address+'/24', 'dev', interface], check=True)
        subprocess.run(['ip', 'route', 'replace', 'default', 'via', gateway], check=True)
        with send(3, server=server, ciaddr=address):
            renewed, renew = receive(5)
        assert renewed in (address, '0.0.0.0') and renew[3] == ack[3] and renew[6] == ack[6]
        print(json.dumps({'address': address, 'gateway': gateway, 'dns': dns,
                          'dhcp_server': server, 'renewal': True}))


if __name__ == '__main__':
    main()
