#!/usr/bin/env python3
"""Run on the independent test computer; stop with Ctrl+C."""
import argparse
import json
import socket
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bind', default='10.61.20.134')
parser.add_argument('--seconds', type=int, default=7200)
args = parser.parse_args()
started = time.monotonic()
received = 0
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((args.bind, 46090))
    sock.settimeout(1)
    print(json.dumps(dict(ready=True, address=args.bind, port=46090)), flush=True)
    try:
        while time.monotonic() - started < args.seconds:
            try:
                packet, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            if packet.startswith((b'VRSDMA01', b'VRS-PROBE-')):
                sock.sendto(packet, address)
                received += 1
    except KeyboardInterrupt:
        pass
print(json.dumps(dict(echoed=received, seconds=time.monotonic() - started)), flush=True)
