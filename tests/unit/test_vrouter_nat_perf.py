import importlib.util
import json
from pathlib import Path
import unittest

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "benchmarks/diagnostics/nat-perf.py"
spec = importlib.util.spec_from_file_location("nat_perf", SCRIPT_PATH)
nat_perf_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nat_perf_mod)

parse_iperf3_json = nat_perf_mod.parse_iperf3_json
parse_ping_output = nat_perf_mod.parse_ping_output
parse_vpp_runtime = nat_perf_mod.parse_vpp_runtime



class TestVROUTERNATPerfUnit(unittest.TestCase):

    def test_parse_iperf3_tcp_json(self):
        sample_iperf = {
            "end": {
                "sum_sent": {
                    "bits_per_second": 2350000000.0,
                    "seconds": 5.0
                },
                "sum_received": {
                    "bits_per_second": 2340000000.0,
                    "seconds": 5.0
                },
                "cpu_utilization_percent": {
                    "host_total": 45.2,
                    "remote_total": 38.1
                }
            }
        }
        res = parse_iperf3_json(json.dumps(sample_iperf))
        self.assertEqual(res["gbps_sent"], 2.35)
        self.assertEqual(res["gbps_recv"], 2.34)
        self.assertEqual(res["mbps_sent"], 2350.0)
        self.assertEqual(res["cpu_host_total"], 45.2)

    def test_parse_iperf3_udp_json(self):
        sample_udp = {
            "end": {
                "sum_sent": {
                    "bits_per_second": 1800000000.0
                },
                "sum_received": {
                    "bits_per_second": 1780000000.0
                },
                "sum": {
                    "lost_packets": 12,
                    "packets": 50000,
                    "lost_percent": 0.024,
                    "jitter_ms": 0.045
                }
            }
        }
        res = parse_iperf3_json(json.dumps(sample_udp))
        self.assertEqual(res["gbps_sent"], 1.8)
        self.assertEqual(res["lost_packets"], 12)
        self.assertEqual(res["total_packets"], 50000)
        self.assertEqual(res["loss_percent"], 0.02)
        self.assertEqual(res["jitter_ms"], 0.045)

    def test_parse_ping_output(self):
        sample_ping = """
--- 198.18.45.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4004ms
rtt min/avg/max/mdev = 0.125/0.180/0.245/0.042 ms
"""
        res = parse_ping_output(sample_ping)
        self.assertEqual(res["loss_percent"], 0.0)
        self.assertEqual(res["min_ms"], 0.125)
        self.assertEqual(res["avg_ms"], 0.180)
        self.assertEqual(res["max_ms"], 0.245)
        self.assertEqual(res["mdev_ms"], 0.042)

    def test_ping_partial_loss_keeps_rtt_and_fractional_loss(self):
        for loss in (20, 33.333):
            with self.subTest(loss=loss):
                output = f"5 packets transmitted, 4 received, {loss}% packet loss\n" \
                         "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.04 ms"
                result = parse_ping_output(output)
                self.assertEqual(result["loss_percent"], loss)
                self.assertEqual(result["avg_ms"], 0.2)
                self.assertNotIn("error", result)

    def test_ping_total_loss_and_missing_summary(self):
        for output in ("5 packets transmitted, 0 received, 100% packet loss", "ping failed"):
            with self.subTest(output=output):
                result = parse_ping_output(output)
                self.assertEqual(result["loss_percent"], 100)
                self.assertIn("error", result)
                self.assertNotIn("avg_ms", result)

    def test_runtime_sums_workers_and_weights_packet_cost(self):
        output = """
Thread 0 vpp_main
nat44-ei-in2out active 9 0 0 99.0
Thread 1 vpp_wk_0
nat44-ei-in2out active 10 100 0 2.0
nat44-ei-in2out-worker-handoff active 3 30 0 1.0
Thread 2 vpp_wk_1
nat44-ei-in2out active 20 300 0 4.0
nat44-ei-in2out-worker-handoff active 7 70 0 3.0
"""
        result = parse_vpp_runtime(output)
        self.assertEqual(result["nat44-ei-in2out"], {"calls": 39, "vectors": 400, "clocks": 3.5})
        self.assertEqual(result["nat44-ei-in2out-worker-handoff"],
                         {"calls": 10, "vectors": 100, "clocks": 2.4})

    def test_runtime_idle_and_malformed_rows(self):
        output = """
nat44-ei-out2in active bad 20 0 2.0
nat44-ei-out2in active 4 0 0 9.0
nat44-ei-out2in active 6 0 0 7.0
nat44-ei-in2out active 3
unrelated-node active 4 20 0 3.0
"""
        self.assertEqual(parse_vpp_runtime(output),
                         {"nat44-ei-out2in": {"calls": 10, "vectors": 0, "clocks": 0.0}})

    def test_parse_vpp_runtime(self):
        sample_runtime = """
Thread 1 vpp_wk_0 (lcore 5)
Time 12.5, average vectors/node 150.2
  Name                   State         Calls          Vectors        Suspends   Clocks/pkt
nat44-ei-in2out          active        15000          1500000               0         45.2
nat44-ei-out2in          active        14500          1450000               0         43.1
ip4-lookup               active        20000          2000000               0         22.0
"""
        res = parse_vpp_runtime(sample_runtime)
        self.assertIn("nat44-ei-in2out", res)
        self.assertIn("nat44-ei-out2in", res)
        self.assertEqual(res["nat44-ei-in2out"]["vectors"], 1500000)
        self.assertEqual(res["nat44-ei-in2out"]["clocks"], 45.2)


if __name__ == "__main__":
    unittest.main()
