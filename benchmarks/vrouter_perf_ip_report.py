#!/usr/bin/env python3
"""Resolve saved perf IP samples using the same, still-installed router ELF files."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--trim-start', type=float, default=1.0)
    parser.add_argument('--trim-end', type=float, default=-0.1)
    parser.add_argument('--router-socket', default='/tmp/vrouter-bench-router.sock')
    parser.add_argument('--elf-override', action='append', default=[], metavar='MAPPED_PATH=ELF_PATH')
    args = parser.parse_args()
    overrides = dict(x.split('=', 1) for x in args.elf_override)
    result = []
    for phase in json.loads(args.input.read_text())['phases']:
        profile = phase.get('worker_samples')
        if not profile:
            continue
        maps = []
        for line in profile['maps'].splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith('/') and 'x' in fields[1]:
                start, end = [int(n, 16) for n in fields[0].split('-')]
                maps.append((start, end, int(fields[2], 16), fields[5]))
        grouped, resolved = defaultdict(set), {}
        for ip, _ in profile['samples']:
            address = int(ip, 16)
            for start, end, offset, path in maps:
                if start <= address < end:
                    grouped[path].add(address - start + offset)
                    resolved[ip] = (path, address - start + offset)
                    break
        symbols = {}
        for path, offsets in grouped.items():
            offsets = sorted(offsets)
            for i in range(0, len(offsets), 128):
                chunk = offsets[i:i+128]
                command = shlex.join(['addr2line', '-f', '-C', '-e', overrides.get(path, path)] + [hex(n) for n in chunk])
                lines = subprocess.check_output(['ssh', '-S', args.router_socket,
                    '-o', 'BatchMode=yes', 'vpp-operator@10.61.20.1', command], text=True).splitlines()
                if len(lines) != len(chunk)*2:
                    raise RuntimeError('unexpected addr2line result')
                for index, offset in enumerate(chunk):
                    symbols[(path, offset)] = (lines[index*2], lines[index*2+1])
        # Trim one second at both ends to reduce startup and drain idle samples.
        first = profile['samples'][0][1]
        active_end = first + int((phase['duration_s'] - args.trim_end)*1e9)
        counted = Counter()
        lines_counted = Counter()
        total = 0
        for ip, timestamp in profile['samples']:
            if not first + int(args.trim_start * 1e9) <= timestamp <= active_end:
                continue
            total += 1
            key = resolved.get(ip)
            name, source = symbols.get(key, ('unresolved', '?'))
            module = Path(key[0]).name if key else '?'
            counted[(module, name)] += 1
            lines_counted[(module, name, source)] += 1
        result.append({'run': phase['run'], 'pps': phase['pps'], 'samples_used': total,
            'lost': profile['lost'],
            'window': f'first sample + {args.trim_start}s through first sample + requested traffic duration - {args.trim_end}s; approximate traffic alignment',
            'functions': [{'module': m, 'function': f, 'samples': n, 'percent': n/total*100}
                for (m, f), n in counted.most_common()],
            'lines': [{'module': m, 'function': f, 'source': s, 'samples': n, 'percent': n/total*100}
                for (m, f, s), n in lines_counted.most_common()]})
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    for item in result:
        print(item['pps'], 'samples', item['samples_used'], 'lost', item['lost'])
        for row in item['functions'][:15]:
            print(round(row['percent'], 2), row['module'], row['function'])


if __name__ == '__main__':
    main()
