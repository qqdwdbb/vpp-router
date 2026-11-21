"""Server-only isolated DNS route benchmark against real VPP."""
import argparse
import json
from pathlib import Path
import runpy
import statistics
import tempfile
import time


def report(name, values):
    ordered = sorted(values)
    print(name, 'n=', len(values), 'median_ms=', round(statistics.median(values), 3),
          'p95_ms=', round(ordered[max(0, int(len(values) * .95) - 1)], 3))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', default='/usr/local/lib/vpp-vrouter/scripts/dns-route-gate.py')
    parser.add_argument('--backend', default='/usr/local/lib/vpp-vrouter/scripts/nftset-route-sync.py')
    parser.add_argument('--samples', type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.samples <= 50:
        parser.error('samples must be between 1 and 50')
    gate = runpy.run_path(args.program)
    module = gate['load_sync'](args.backend)
    config = module.load_config('/etc/vpp/nftset-route-sync.json')
    table = 'vpp_route_bench'
    mapping = {'family': 'inet', 'table': table, 'set': 'targets',
               'interface': 'wg1', 'via': '10.62.30.1', 'fib_table': 0}
    config['mappings'] = [mapping]
    routes = [module.Route(0, f'198.51.100.{100+i}/32', '10.62.30.1', 'wg1')
              for i in range(args.samples)]
    backend = module.Backend(config)
    assert not backend.lookup(routes), 'reserved test prefixes already in use'
    try:
        with tempfile.TemporaryDirectory(prefix='vpp-route-bench-') as directory:
            root = Path(directory)
            config['state_file'] = str(root / 'state.json')
            (root / 'config.json').write_text(json.dumps(config))
            (root / 'rules.conf').write_text(f'nftset=/bench.invalid/4#inet#{table}#targets\n')
            controller = gate['Controller'](module, root / 'config.json',
                lambda: [root / 'rules.conf'], root / 'seen.json')
            with module.DeferredState([config['state_file'], root / 'seen.json']):
                backend.generation()
                backend.apply([])
                dns = []
                for route in routes:
                    controller.verified.clear()
                    before = time.perf_counter_ns()
                    controller.reconcile([('bench.invalid', route.prefix.split('/')[0], 60)],
                                         ('bench.invalid', 1, 1))
                    dns.append((time.perf_counter_ns() - before) / 1e6)
                report('DNS first-hit route barrier (no upstream RTT)', dns)
    finally:
        backend.apply([r.command('del') for r in routes])
        assert not backend.lookup(routes), 'test routes remain'
        print('test routes and temporary ledgers removed')


if __name__ == '__main__':
    main()
