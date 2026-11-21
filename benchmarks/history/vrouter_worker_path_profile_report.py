#!/usr/bin/env python3
"""Aggregate exclusive worker IP samples; never treat them as call-stack totals."""
from collections import Counter, defaultdict
import argparse
import json
from pathlib import Path
import re

BASE = Path(__file__).resolve().parents[2]
ART = BASE / 'artifacts/vrouter'


def category(row):
    module, fn = row['module'], row['function']
    if module.startswith('librte_net_r8169'):
        return 'PMD'
    if module == 'acl_plugin.so':
        return 'ACL'
    if module == 'nat44_ei_plugin.so':
        return 'NAT'
    if module.startswith('libvlib') or 'enqueue' in fn or fn in (
            'vlib_get_next_frame_internal', 'vlib_put_next_frame'):
        return 'graph_runtime'
    if any(x in fn for x in ('vlib_buffer_', 'vlib_get_buffer', 'dpdk_mbuf_init',
                              'dpdk_validate_rte_mbuf', 'dpdk_prefetch_buffer',
                              'rte_mempool', 'rte_mbuf')):
        return 'buffer_visible'
    if module == 'dpdk_plugin.so':
        return 'dpdk_adapter'
    return 'other'


def counter(text, iface, key):
    block = re.search(r'(?ms)^' + re.escape(iface) + r'\s+.*?(?=^\S|\Z)', text)
    found = re.search(r'\b' + re.escape(key) + r'\s+(\d+)', block[0]) if block else None
    return int(found[1]) if found else 0


def runtime(text):
    rows = {}
    worker = False
    for line in text.splitlines():
        if line.startswith('Thread '):
            worker = 'vpp_wk_0' in line
        if not worker:
            continue
        match = re.match(r'^([\w-]+)\s+(?:active|polling)\s+(\d+)\s+(\d+)', line)
        if match:
            rows[match[1]] = {'calls': int(match[2]), 'vectors': int(match[3])}
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stem', default='worker-matched-profile')
    args = parser.parse_args()
    raw = json.loads((ART / (args.stem + '-raw-20261030.json')).read_text())
    symbols = json.loads((ART / (args.stem + '-symbols-20261030.json')).read_text())
    symbols = {p['run']: p for p in symbols}
    result = {'method': 'exclusive user-IP samples, first sample +3s to +18s; 499 Hz',
              'buffer_scope': 'visible symbols outside PMD/ACL/NAT; inline allocation/recycling remains in its owner module',
              'phases': [], 'pooled': {}}
    totals = defaultdict(Counter)
    counts = Counter()
    for mode in raw['modes']:
        for phase in mode['phases']:
            profile = symbols[phase['run']]
            c = Counter()
            for row in profile['functions']:
                c[category(row)] += row['samples']
            totals[mode['mode']].update(c)
            counts[mode['mode']] += profile['samples_used']
            freqs = {t['frequency_khz'] for t in phase['worker_samples']['telemetry']}
            temps = [int(v) / 1000 for t in phase['worker_samples']['telemetry']
                     for v in t['temperatures'].values()]
            b, a = runtime(phase['before']['runtime']), runtime(phase['after']['runtime'])
            deltas = {}
            for node in set(b) & set(a):
                calls, vectors = (a[node][x] - b[node][x] for x in ('calls', 'vectors'))
                deltas[node] = {'calls': calls, 'vectors': vectors,
                                'vectors_per_call': vectors / calls if calls else None}
            tx_iface = 'nic0-dpdk.11' if mode['mode'] == 'vlan' else 'nic0-dpdk'
            tx = counter(phase['after']['interfaces'], tx_iface, 'tx packets') - counter(
                phase['before']['interfaces'], tx_iface, 'tx packets')
            after_rx, before_rx = phase['after_receiver'], phase['before_receiver']
            unique = sum(b['unique'] for b in after_rx['batches']) - sum(
                b['unique'] for b in before_rx['batches'])
            result['phases'].append({'run': phase['run'], 'mode': mode['mode'],
                'samples': profile['samples_used'], 'lost': profile['lost'],
                'percent': {k: n / profile['samples_used'] * 100 for k, n in c.items()},
                'frequency_khz_observed': sorted(freqs), 'temperature_range_c': [min(temps), max(temps)],
                'expected': phase['expected'], 'tx_packets': tx, 'receiver_unique': unique,
                'nat_packets': (phase['after_nat_packets'] or 0) - (phase['before_nat_packets'] or 0),
                'worker_node_deltas': deltas})
    for mode, c in totals.items():
        result['pooled'][mode] = {'samples': counts[mode],
            'percent': {k: n / counts[mode] * 100 for k, n in c.items()}}
    (ART / (args.stem + '-summary-20261030.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['pooled'], indent=2))
    for p in result['phases']:
        print(p['mode'], p['run'], 'temp', p['temperature_range_c'], 'TX', p['tx_packets'],
              'unique', p['receiver_unique'], 'NAT', p['nat_packets'])
        for node in ('dpdk-input', 'nic0-dpdk-tx', 'acl-plugin-in-ip4-fa',
                     'nat44-ei-out2in', 'nat44-ei-out2in-worker-handoff'):
            print(node, p['worker_node_deltas'].get(node))


if __name__ == '__main__':
    main()
