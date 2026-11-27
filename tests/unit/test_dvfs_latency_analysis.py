"""Check monotonic trace correlation without counting an earlier boost as ours."""
import importlib.util
from pathlib import Path
import unittest

p = Path(__file__).resolve().parents[2] / 'benchmarks/analysis/vrouter_dvfs_latency.py'
spec = importlib.util.spec_from_file_location('dvfs_latency', p)
latency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(latency)


class LatencyAnalysisTests(unittest.TestCase):
    def test_trace_precision_cpu_filter_and_request_parse(self):
        events = latency.frequency_events('''
 worker [001] 1.123456789: cpu_frequency: state=408000 cpu_id=0
 worker [001] 1.123456790: cpu_frequency: state=2256000 cpu_id=4
 worker [001] 1.125000000: cpu_frequency: state=1800000 cpu_id=0
''', 0)
        self.assertEqual(events, [(1123456789, 408000), (1125000000, 1800000)])
        rows = latency.requests('header\n0 1124000000 20 30 50 100100 0\n')
        result = latency.correlate(rows, events, 1800000)[0]
        self.assertEqual(result['status'], 'after_write')
        self.assertEqual(result['frequency_us'], 1000)

    def test_already_high_natural_boost_unknown_and_timeout(self):
        def request(ns, write=100):
            return dict(id='0', trigger_ns=str(ns), wake_us='20',
                        write_begin_us=str(write), write_end_us='200',
                        hold_us='100100', error='0')
        events = [(1000000000, 408000), (1001000000, 1800000)]
        cases = [(request(1002000000), 'already_high'),
                 (request(1000900000, 200), 'before_write'),
                 (request(999900000), 'unknown_baseline'),
                 (request(800000000), 'not_observed')]
        for row, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(latency.correlate([row], events, 1800000)[0]['status'], expected)


if __name__ == '__main__':
    unittest.main()
