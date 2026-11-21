#!/usr/bin/env python3
"""Inspect test UDP replies before the Linux UDP checksum check (Linux/root)."""
import argparse
import hashlib
import json
import socket
import struct
import time

from nic1_soak import checksum


def inspect(frame, peer):
    if len(frame) < 42 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    if ip[0] >> 4 != 4 or ihl < 20 or len(ip) < ihl + 8 or ip[9] != 17:
        return None
    if ip[12:16] != socket.inet_aton(peer):
        return None
    total = struct.unpack_from('!H', ip, 2)[0]
    if total < ihl + 8:
        return None
    udp = ip[ihl:total]
    source, destination, length, wire_checksum = struct.unpack_from('!HHHH', udp)
    if source != 46090 or not 46100 <= destination <= 46103:
        return None
    payload = udp[8:]
    pseudo = ip[12:20] + struct.pack('!BBH', 0, 17, length)
    valid_payload = (len(payload) >= 24 and payload[:8] == b'VRSDMA01'
        and payload[24:] == hashlib.shake_256(payload[:24]).digest(len(payload) - 24))
    result = dict(source_port=source, destination_port=destination,
        udp_length=length, ip_checksum_valid=checksum(ip[:ihl]) == 0,
        udp_checksum_valid=not wire_checksum or checksum(pseudo + udp) == 0,
        payload_valid=valid_payload, lengths_valid=length == len(udp) and total <= len(ip))
    if len(payload) >= 24:
        result['sequence'] = struct.unpack_from('!Q', payload, 8)[0]
    if not all(result[key] for key in ('ip_checksum_valid', 'udp_checksum_valid',
                                      'payload_valid', 'lengths_valid')):
        result['frame_hex'] = frame.hex()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', default='mgmt0')
    parser.add_argument('--peer', default='10.61.20.134')
    parser.add_argument('--seconds', type=int, default=2400)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 7204:
        parser.error('seconds must be 1..7204')
    start = time.monotonic()
    last = start
    summary = dict(datagrams=0, invalid_checksums=0, invalid_payloads=0)
    examples = 0
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind((args.interface, 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.settimeout(.5)
        while time.monotonic() - start < args.seconds:
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            result = inspect(frame, args.peer)
            if result is not None:
                summary['datagrams'] += 1
                summary['invalid_checksums'] += not result['udp_checksum_valid']
                summary['invalid_payloads'] += not result['payload_valid']
                if 'frame_hex' in result and examples < 8:
                    examples += 1
                    print(json.dumps(dict(elapsed_seconds=time.monotonic() - start,
                                          anomaly=result)), flush=True)
            if time.monotonic() - last >= 30:
                print(json.dumps(dict(elapsed_seconds=time.monotonic() - start,
                                      **summary)), flush=True)
                last = time.monotonic()
        packets, drops = struct.unpack('=II', sock.getsockopt(263, 6, 8))
        summary.update(socket_packets=packets, socket_drops=drops)
    print(json.dumps(dict(elapsed_seconds=time.monotonic() - start, **summary)), flush=True)


if __name__ == '__main__':
    main()
