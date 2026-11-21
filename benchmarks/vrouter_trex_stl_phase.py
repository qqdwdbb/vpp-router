#!/usr/bin/env python3
"""One bounded STL phase inside the temporary nic1 WAN namespace.

Requires the official TRex client and a running local TRex server. The router
fixture must track the static UDP mapping before this script sends traffic.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trex', type=Path, required=True)
    parser.add_argument('--pps', type=int, required=True)
    parser.add_argument('--seconds', type=int, default=8)
    args = parser.parse_args()
    if not 1000 <= args.pps <= 4000000 or not 1 <= args.seconds <= 30:
        parser.error('rate or duration outside bounded benchmark limits')
    sys.path.insert(0, str(args.trex/'automation/trex_control_plane/interactive'))
    from trex.stl.api import (STLClient, Ether, IP, UDP, STLPktBuilder,
                              STLStream, STLTXCont)

    def link():
        return json.loads(subprocess.check_output(
            ['ip', '-s', '-j', 'link', 'show', 'eno1'], text=True))

    def driver():
        return subprocess.check_output(['ethtool', '-S', 'eno1'], text=True)

    client = STLClient()
    try:
        client.connect()
        client.reset(ports=[0])
        packet = Ether(src='02:00:00:00:10:06', dst='02:00:00:00:10:05') / \
            IP(src='172.31.246.2', dst='172.31.246.1') / \
            UDP(sport=50000, dport=45999) / (b'T' * 18)
        assert len(bytes(packet)) == 60  # FCS supplied by the NIC: 64 bytes.
        client.add_streams(STLStream(packet=STLPktBuilder(pkt=packet),
                           mode=STLTXCont(pps=args.pps)), ports=[0])
        client.clear_stats(ports=[0])
        result = dict(target_pps=args.pps, duration=args.seconds, frame_bytes=64,
                      before_link=link(), before_driver=driver(),
                      version=client.get_server_version(),
                      port_info=client.get_port_info(ports=[0]))
        start = time.monotonic()
        result['start'] = time.time()
        # Bound by wall clock even when AF_PACKET cannot meet the requested PPS.
        # A TRex duration may finish late while the TX path is backpressured.
        client.start(ports=[0])
        samples = []
        for _ in range(args.seconds):
            time.sleep(1)
            samples.append(client.get_stats(ports=[0]))
        client.stop(ports=[0])
        client.wait_on_traffic(ports=[0], timeout=10)
        result.update(elapsed=time.monotonic()-start, end=time.time(),
                      stats=client.get_stats(ports=[0]), samples=samples,
                      after_link=link(), after_driver=driver())
        path = Path('/var/tmp')/f'vrouter-trex-{args.pps}-{int(result["start"])}.json'
        path.write_text(json.dumps(result, indent=2)+'\n')
        print('TREX_RESULT'+json.dumps(result), flush=True)
    finally:
        if client.is_connected():
            try:
                client.stop(ports=[0])
            finally:
                client.disconnect()


if __name__ == '__main__':
    main()
