#!/usr/bin/env python3
"""Read-only RTL8125 ISR sampling; never acknowledges or changes NIC registers.

Run on a spare CPU on VROUTER. Positive RDU/FIFO observations are evidence of the
condition, not counts of dropped packets; the PMD independently clears RDU.
"""
import argparse
import json
import mmap
import os
from pathlib import Path
import struct
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=float, required=True)
    args = parser.parse_args()
    if not 0 < args.seconds <= 40:
        parser.error('duration must be in (0, 40]')
    os.sched_setaffinity(0, {0})
    path = '/sys/bus/pci/devices/0000:01:00.0/resource2'
    started = time.monotonic()
    result = {'started_at': time.time(), 'read_only': True, 'cpu': 0,
              'register_offset': 0x3c, 'requested_sleep_us': 25, 'bins': []}
    freq = Path('/sys/devices/system/cpu/cpu5/cpufreq/scaling_cur_freq')
    with open(path, 'rb', buffering=0) as f:
        with mmap.mmap(f.fileno(), 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ) as mm:
            while time.monotonic() - started < args.seconds:
                begin = time.monotonic()
                item = {'elapsed_s': begin - started, 'samples': 0, 'rdu_samples': 0,
                        'fifo_samples': 0, 'rx_error_samples': 0, 'status_or': 0,
                        'worker_freq_khz': int(freq.read_text())}
                while time.monotonic() - begin < 0.1 and time.monotonic() - started < args.seconds:
                    status = struct.unpack_from('<I', mm, 0x3c)[0]
                    item['samples'] += 1
                    item['status_or'] |= status
                    item['rdu_samples'] += bool(status & 0x10)
                    item['fifo_samples'] += bool(status & 0x40)
                    item['rx_error_samples'] += bool(status & 0x02)
                    time.sleep(0.000025)
                item['duration_s'] = time.monotonic() - begin
                result['bins'].append(item)
    result['duration_s'] = time.monotonic() - started
    print(json.dumps(result))


if __name__ == '__main__':
    main()
