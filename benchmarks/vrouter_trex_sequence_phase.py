#!/usr/bin/env python3
"""Finite single-worker 64-byte NAT burst with payload sequence IDs."""
import argparse
import json
from pathlib import Path
import struct
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trex', type=Path, required=True)
    parser.add_argument('--pps', type=int, required=True)
    parser.add_argument('--count', type=int, required=True)
    parser.add_argument('--run', type=int, required=True)
    parser.add_argument('--port', type=int, default=45996)
    parser.add_argument('--dst-ip', default='10.61.10.2')
    parser.add_argument('--flows', type=int, default=1)
    args = parser.parse_args()
    if not 1000 <= args.pps <= 3700000 or not 1 <= args.count <= 60000000:
        parser.error('bounded rate/count limits exceeded')
    if not 1 <= args.flows <= 20000:
        parser.error('flows outside test bounds')
    sys.path.insert(0, str(args.trex / 'automation/trex_control_plane/interactive'))
    from trex.stl.api import (STLClient, Ether, IP, UDP, STLPktBuilder,
                              STLStream, STLTXSingleBurst, STLVM)
    packet = (Ether(src='02:00:00:00:10:03', dst='02:00:00:00:10:01') /
              IP(src='203.0.113.10', dst=args.dst_ip, ttl=64) /
              UDP(sport=40000, dport=args.port, chksum=0) /
              (b'VRS2' + struct.pack('!III', args.run, 0, args.count) + b'TT'))
    assert len(bytes(packet)) == 60
    vm = STLVM()
    vm.var(name='flow', min_value=40000, max_value=40000 + args.flows - 1, size=2, op='inc')
    vm.write(fv_name='flow', pkt_offset=34)
    vm.var(name='seq', min_value=0, max_value=args.count - 1, size=4, op='inc')
    vm.write(fv_name='seq', pkt_offset=50)
    client = STLClient()
    try:
        client.connect()
        client.reset(ports=[0])
        info = client.get_port_info(ports=[0])
        if len(info[0]['cores']) != 1:
            raise RuntimeError('sequence test requires exactly one TX worker')
        client.add_streams(STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
                          mode=STLTXSingleBurst(total_pkts=args.count, pps=args.pps)),
                          ports=[0])
        client.clear_stats(ports=[0])
        start = time.monotonic()
        client.start(ports=[0])
        client.wait_on_traffic(ports=[0], timeout=args.count / args.pps + 15)
        elapsed = time.monotonic() - start
        time.sleep(0.2)
        print(json.dumps(dict(run=args.run, requested_pps=args.pps, count=args.count,
                              flows=args.flows,
                              elapsed_s=elapsed, port_info=info,
                              stats=client.get_stats(ports=[0]))), flush=True)
    finally:
        if client.is_connected():
            try:
                client.stop(ports=[0])
            finally:
                client.disconnect()


if __name__ == '__main__':
    main()
