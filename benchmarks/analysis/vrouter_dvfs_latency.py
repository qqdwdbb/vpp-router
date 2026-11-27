#!/usr/bin/env python3
"""Correlate `show dpdk dvfs` with a mono-clock power:cpu_frequency trace."""
import argparse
import bisect
import csv
from decimal import Decimal
from pathlib import Path
import re
import sys


def requests(text):
    keys = ('id', 'trigger_ns', 'wake_us', 'write_begin_us', 'write_end_us',
            'hold_us', 'error')
    result = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == len(keys) and fields[0].isdigit():
            row = dict(zip(keys, fields))
            result.append(row)
    return result


def frequency_events(text, cpu):
    pattern = re.compile(r'\s(\d+\.\d+):\s+(?:power:)?cpu_frequency: '
                         r'state=(\d+) cpu_id=(\d+)')
    events = []
    for match in pattern.finditer(text):
        if int(match[3]) == cpu:
            events.append((int(Decimal(match[1]) * 1000000000), int(match[2])))
    return sorted(events)


def correlate(rows, events, target):
    times = [t for t, _ in events]
    boosted = [t for t, khz in events if khz >= target]
    result = []
    for row in rows:
        trigger = int(row['trigger_ns'])
        index = bisect.bisect_right(times, trigger) - 1
        before = events[index][1] if index >= 0 else None
        index = bisect.bisect_left(boosted, trigger)
        event = boosted[index] if index < len(boosted) else None
        # The boost lease lasts at least 100 ms from the first request.
        if event is not None and event - trigger > 100000000:
            event = None
        write = trigger + int(Decimal(row['write_begin_us']) * 1000)
        if before is not None and before >= target:
            status, event = 'already_high', None
        elif event is None:
            status = 'not_observed'
        elif before is None:
            status = 'unknown_baseline'
        else:
            status = 'before_write' if event < write else 'after_write'
        result.append(dict(id=int(row['id']), trigger_ns=trigger, before_khz=before,
                           frequency_ns=event,
                           frequency_us=(event - trigger) / 1000 if event is not None else None,
                           wake_us=row['wake_us'], write_begin_us=row['write_begin_us'],
                           write_end_us=row['write_end_us'], hold_us=row['hold_us'],
                           status=status, error=int(row['error'])))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--requests', type=Path, required=True)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--cpu', type=int, default=0, help='CPUFreq policy representative CPU')
    parser.add_argument('--target', type=int, default=1800000, help='target kHz')
    args = parser.parse_args()
    rows = correlate(requests(args.requests.read_text()),
                     frequency_events(args.trace.read_text(), args.cpu), args.target)
    if not rows:
        parser.error('no completed DVFS request records')
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)


if __name__ == '__main__':
    main()
