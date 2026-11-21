#!/usr/bin/env python3
"""Inside the temporary WAN namespace: bounded 64-byte wire-frame source.

skb size 60 + Ethernet FCS 4 = 64 bytes, 84 bytes including preamble and IFG.
Uses one dedicated namespace-local pktgen thread, not the host's generators.
"""
import json
from pathlib import Path
import sys
import time


def main():
    pps = int(sys.argv[1])
    assert 10000 <= pps <= 2000000
    root = Path('/proc/net/pktgen')
    thread = root/'kpktgend_2'
    assert 'Running: \n' in thread.read_text()

    def set_value(path, text):
        path.write_text(text+'\n')

    set_value(thread, 'rem_device_all')
    set_value(thread, 'add_device eno1@2')
    device = root/'eno1@2'
    try:
        for value in [f'count {pps*3}', 'pkt_size 60', 'clone_skb 10000', 'burst 64',
                      'queue_map_min 0', 'queue_map_max 0', 'dst 172.31.246.1',
                      'dst_mac 02:00:00:00:10:05', 'src_min 172.31.246.2',
                      'src_max 172.31.246.2', 'udp_src_min 50000', 'udp_src_max 50031',
                      'flag UDPSRC_RND', 'udp_dst_min 45999', 'udp_dst_max 45999',
                      f'ratep {pps}']:
            set_value(device, value)
            if 'Result: ERROR:' in device.read_text():
                raise RuntimeError(device.read_text())
        start = time.time()
        set_value(root/'pgctrl', 'start')
        result = dict(target_pps=pps, start=start, end=time.time(), skb_bytes=60,
                      wire_frame_bytes=64, nat_mappings=1, report=device.read_text())
        print('PKTGEN_RESULT'+json.dumps(result), flush=True)
    finally:
        set_value(thread, 'rem_device_all')


if __name__ == '__main__':
    main()
