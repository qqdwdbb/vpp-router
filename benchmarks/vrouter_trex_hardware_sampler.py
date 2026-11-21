#!/usr/bin/env python3
"""Bounded VROUTER WAN tally sampler, including RTL8125 extended DMA counters."""
import argparse
import json
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 40:
        parser.error('sample duration outside bounds')
    samples = []
    start = time.monotonic()
    while time.monotonic() - start < args.seconds:
        before = time.monotonic()
        text = subprocess.check_output(['/usr/local/bin/vppctl',
                    'show hardware-interfaces nic0-dpdk detail'], text=True, timeout=3)
        counters = {name: int(value) for name, value in re.findall(
            r'^\s*(rx_good_packets|tx_good_packets|rx_missed_errors|rx_errors|tx_errors|rx_mbuf_allocation_errors|rx_mac_missed|rx_tcam_dropped|rx_mac_error|rx_frame_too_long|rx_runt|rx_pause_on|rx_pause_off|rx_pause_all|tx_pause_on|tx_pause_off|tx_pause_all|rx_octets|tx_octets|rdu|tdu)\s+(\d+)\s*$', text, re.M)}
        if not {'rx_good_packets', 'tx_good_packets', 'rx_missed_errors', 'rx_errors',
                'tx_errors', 'rx_mbuf_allocation_errors'} <= counters.keys():
            raise RuntimeError('missing hardware counters')
        samples.append(dict(time=time.time(), elapsed_s=time.monotonic() - start,
                            read_duration_s=time.monotonic() - before, **counters))
        time.sleep(max(0, 0.05 - (time.monotonic() - before)))
    print(json.dumps(dict(interval_s=0.05, missed_counter_bits=16, samples=samples)))


if __name__ == '__main__':
    main()
