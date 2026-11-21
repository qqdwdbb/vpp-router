#!/usr/bin/env python3
"""Summarize exact test-run sequence delivery and ACL cache counters."""
from collections import Counter
import json
from pathlib import Path
import re

ART = Path(__file__).resolve().parents[2] / 'artifacts/vrouter'


def error_count(text, node, reason):
    match = re.search(r'^\s*(\d+)\s*' + re.escape(node) + r'\s+' + re.escape(reason) +
                      r'\s+(?:error|info)\s*$', text, re.M)
    return int(match[1]) if match else 0


def main():
    trial = json.loads((ART / 'acl-cache-nat-trial-20261030.json').read_text())
    result = {'phases': [], 'profiles': {}, 'trial_status': trial.get('restore', {}).get('status')}
    for run in trial['runs']:
        data = json.loads(Path(run['path']).read_text())
        for mode in data['modes']:
            for phase in mode['phases']:
                received = next(b for b in phase['after_receiver']['batches'] if b['run'] == phase['run'])
                nat = phase['after_nat_packets'] - phase['before_nat_packets']
                cache_hits = (error_count(phase['after']['errors'], 'acl-plugin-in-ip4-fa', 'frame permit cache hits') -
                              error_count(phase['before']['errors'], 'acl-plugin-in-ip4-fa', 'frame permit cache hits'))
                node_calls = []
                for side in ('before', 'after'):
                    # Only the worker's row; the main thread normally has no
                    # input ACL row, but restrict the match explicitly.
                    text = phase[side]['runtime'].split('vpp_wk_0', 1)[-1]
                    match = re.search(r'^acl-plugin-in-ip4-fa\s+active\s+(\d+)\s+(\d+)', text, re.M)
                    node_calls.append(int(match[1]) if match else 0)
                bins = phase['rx_status_samples']['bins']
                errors = {name: phase['after_receiver']['dpdk_stats'][name] -
                          phase['before_receiver']['dpdk_stats'][name]
                          for name in ('imissed', 'ierrors', 'rx_nombuf')}
                row = {'tag': run['tag'], 'run': phase['run'], 'flows': data['flows'],
                       'pps': phase['pps'], 'seconds': data['seconds'], 'expected': phase['expected'],
                       'nat_packets': nat, 'unique': received['unique'],
                       'lost': received['missing'], 'loss_percent': received['missing'] / phase['expected'] * 100,
                       'good_mpps': received['unique'] / data['seconds'] / 1e6,
                       'duplicates': received['duplicates'], 'reordered': received['reordered'],
                       'receiver_errors': errors, 'nat_receiver_equal': nat == received['unique'],
                       'cache_hits': cache_hits, 'cache_hit_percent': cache_hits / max(nat, 1) * 100,
                       'acl_calls': node_calls[1] - node_calls[0],
                       'isr_rdu_positive': sum(b['rdu_samples'] for b in bins),
                       'isr_samples': sum(b['samples'] for b in bins),
                       'frequencies_khz': sorted({b['worker_freq_khz'] for b in bins})}
                result['phases'].append(row)
                print(run['tag'], phase['pps'], 'good', round(row['good_mpps'], 6),
                      'loss%', round(row['loss_percent'], 4), 'cache%', round(row['cache_hit_percent'], 2),
                      'NAT=RX', row['nat_receiver_equal'], 'RXerrors', errors)
        profile = ART / ('acl-cache-nat-' + run['tag'] + '-symbols-20261030.json')
        if profile.exists():
            stats = json.loads(profile.read_text())[0]
            modules = Counter()
            for fn in stats['functions']:
                modules[fn['module']] += fn['percent']
            result['profiles'][run['tag']] = {'samples': stats['samples_used'],
                                             'lost': stats['lost'], 'modules_percent': dict(modules)}
    (ART / 'acl-cache-nat-summary-20261030.json').write_text(json.dumps(result, indent=2) + '\n')
    print('profiles:', json.dumps(result['profiles'], indent=2))


if __name__ == '__main__':
    main()
