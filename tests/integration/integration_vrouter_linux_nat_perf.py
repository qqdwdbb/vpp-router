#!/usr/bin/env python3
"""Linux Kernel Stack NAT Performance Benchmark for NanoPi VROUTER.

Measures native Linux iptables/nftables NAT (Netfilter / Conntrack) performance
under a single CPU core (Cortex-A76 Core 4 via RPS), directly mirroring the VPP
NAT44-EI single-core benchmark matrix for an exact 1:1 comparison.
"""
import argparse
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

BASE_DIR = Path(__file__).resolve().parents[2]
SCRIPT_PATH = BASE_DIR / "benchmarks/diagnostics/nat-perf.py"

spec = importlib.util.spec_from_file_location("nat_perf", SCRIPT_PATH)
nat_perf_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nat_perf_mod)

parse_iperf3_json = nat_perf_mod.parse_iperf3_json
parse_ping_output = nat_perf_mod.parse_ping_output


def run_cmd(*args, check=True, timeout=30):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(args)}): {p.stderr.strip()}")
    return p.stdout


def run_ns(ns, *args, check=True, timeout=30):
    return run_cmd("ip", "netns", "exec", ns, *args, check=check, timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description="Linux Kernel NAT Performance Benchmark")
    parser.add_argument("--duration", type=int, default=5, help="Test duration in seconds per scenario")
    parser.add_argument("--router-core", type=int, default=4, help="CPU core pinned for Linux router RPS softirq")
    parser.add_argument("--client-core", type=int, default=6, help="CPU core pinned for client iperf3")
    parser.add_argument("--server-core", type=int, default=7, help="CPU core pinned for server iperf3")
    args = parser.parse_args()

    pid = os.getpid()
    lan_ns = f"vrouter-lnat-lan-{pid}"
    rtr_ns = f"vrouter-lnat-rtr-{pid}"
    wan_ns = f"vrouter-lnat-wan-{pid}"
    namespaces = [lan_ns, rtr_ns, wan_ns]

    # RPS bitmask for router core (e.g. core 4 -> bit 4 = 16 = 0x10)
    rps_mask = f"{1 << args.router_core:x}"

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hardware": "NanoPi VROUTER (RK3588, 4x Cortex-A76 + 4x Cortex-A55)",
        "stack": "Linux Kernel Netfilter / Conntrack (MASQUERADE)",
        "router_core": args.router_core,
        "client_core": args.client_core,
        "server_core": args.server_core,
        "duration_per_test_sec": args.duration,
        "metrics": {}
    }

    print(f"=== Starting Linux Kernel NAT Performance Benchmark (PID {pid}, Router Core {args.router_core}) ===")

    with ExitStack() as stack:
        # 1. Create isolated namespaces
        for ns in namespaces:
            run_cmd("ip", "netns", "add", ns)
            stack.callback(subprocess.run, ["ip", "netns", "delete", ns], capture_output=True)
            run_cmd("ip", "-n", ns, "link", "set", "lo", "up")

        # 2. Setup VETH topology:
        # LAN: lan-c (in lan_ns, 10.61.20.100) <--> lan-r (in rtr_ns, 10.61.20.1)
        # WAN: wan-r (in rtr_ns, 198.18.45.2)   <--> wan-s (in wan_ns, 198.18.45.1)
        run_cmd("ip", "link", "add", "lan-c", "type", "veth", "peer", "name", "lan-r")
        run_cmd("ip", "link", "add", "wan-r", "type", "veth", "peer", "name", "wan-s")

        # Configure RPS on router interfaces before moving to router_ns
        run_cmd("bash", "-c", f"echo {rps_mask} > /sys/class/net/lan-r/queues/rx-0/rps_cpus")
        run_cmd("bash", "-c", f"echo {rps_mask} > /sys/class/net/wan-r/queues/rx-0/rps_cpus")

        run_cmd("ip", "link", "set", "lan-c", "netns", lan_ns)
        run_cmd("ip", "link", "set", "lan-r", "netns", rtr_ns)
        run_cmd("ip", "link", "set", "wan-r", "netns", rtr_ns)
        run_cmd("ip", "link", "set", "wan-s", "netns", wan_ns)

        # Configure LAN Client
        run_ns(lan_ns, "ip", "link", "set", "lan-c", "up")
        run_ns(lan_ns, "ip", "addr", "add", "10.61.20.100/24", "dev", "lan-c")
        run_ns(lan_ns, "ip", "route", "add", "default", "via", "10.61.20.1")

        # Configure WAN Server
        run_ns(wan_ns, "ip", "link", "set", "wan-s", "up")
        run_ns(wan_ns, "ip", "addr", "add", "198.18.45.1/24", "dev", "wan-s")

        # Configure Router
        run_ns(rtr_ns, "ip", "link", "set", "lan-r", "up")
        run_ns(rtr_ns, "ip", "addr", "add", "10.61.20.1/24", "dev", "lan-r")
        run_ns(rtr_ns, "ip", "link", "set", "wan-r", "up")
        run_ns(rtr_ns, "ip", "addr", "add", "198.18.45.2/24", "dev", "wan-r")
        run_ns(rtr_ns, "ip", "route", "add", "default", "via", "198.18.45.1")

        # Enable IPv4 Forwarding in Router
        run_ns(rtr_ns, "sysctl", "-w", "net.ipv4.ip_forward=1")

        # Configure Linux Kernel NAT (iptables MASQUERADE)
        run_ns(rtr_ns, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wan-r", "-j", "MASQUERADE")

        # 3. Start Servers in WAN namespace
        # 3a. iperf3 server on port 5201 (pinned to server-core)
        iperf_server = subprocess.Popen([
            "ip", "netns", "exec", wan_ns, "taskset", "-c", str(args.server_core),
            "iperf3", "-s", "-p", "5201"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(iperf_server.terminate)

        # 3b. Dedicated lightweight TCP server on port 5202 for CPS benchmark (pinned to server-core)
        cps_server = subprocess.Popen([
            "ip", "netns", "exec", wan_ns, "taskset", "-c", str(args.server_core),
            "python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('198.18.45.1', 5202))
s.listen(2048)
while True:
    try:
        c, _ = s.accept()
        c.close()
    except Exception:
        break
"""], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(cps_server.terminate)
        time.sleep(0.5)

        # Warmup ping to ensure dynamic ARP resolution is complete
        run_ns(lan_ns, "ping", "-c", "2", "-W", "1", "198.18.45.1", check=False)

        # --- Phase 1: Baseline Ping & Latency ---
        print("\n--- 1. Baseline Latency Measurement (ICMP) ---")
        ping_out = run_ns(lan_ns, "taskset", "-c", str(args.client_core), "ping", "-c", "5", "-W", "1", "198.18.45.1")
        ping_stats = parse_ping_output(ping_out)
        print(f"  RTT: min={ping_stats.get('min_ms')}ms, avg={ping_stats.get('avg_ms')}ms, max={ping_stats.get('max_ms')}ms")
        results["metrics"]["baseline_latency"] = ping_stats

        # --- Phase 2: TCP Single Stream Throughput ---
        print(f"\n--- 2. TCP Single-Stream Throughput ({args.duration}s) ---")
        t1_out = run_ns(lan_ns, "taskset", "-c", str(args.client_core),
                        "iperf3", "-c", "198.18.45.1", "-p", "5201", "-t", str(args.duration), "-J")
        t1_stats = parse_iperf3_json(t1_out)
        print(f"  Sender: {t1_stats.get('gbps_sent')} Gbps, Receiver: {t1_stats.get('gbps_recv')} Gbps")
        results["metrics"]["tcp_single_stream"] = t1_stats

        # --- Phase 3: TCP Multi-Stream Throughput (4 Parallel Flows) ---
        print(f"\n--- 3. TCP Multi-Stream (4 Parallel Streams, {args.duration}s) ---")
        t4_out = run_ns(lan_ns, "taskset", "-c", str(args.client_core),
                        "iperf3", "-c", "198.18.45.1", "-p", "5201", "-P", "4", "-t", str(args.duration), "-J")
        t4_stats = parse_iperf3_json(t4_out)
        print(f"  Sender: {t4_stats.get('gbps_sent')} Gbps, Receiver: {t4_stats.get('gbps_recv')} Gbps")
        results["metrics"]["tcp_multi_stream_4p"] = t4_stats

        # --- Phase 4: TCP Multi-Stream Throughput (8 Parallel Flows) ---
        print(f"\n--- 4. TCP Multi-Stream (8 Parallel Streams, {args.duration}s) ---")
        t8_out = run_ns(lan_ns, "taskset", "-c", str(args.client_core),
                        "iperf3", "-c", "198.18.45.1", "-p", "5201", "-P", "8", "-t", str(args.duration), "-J")
        t8_stats = parse_iperf3_json(t8_out)
        print(f"  Sender: {t8_stats.get('gbps_sent')} Gbps, Receiver: {t8_stats.get('gbps_recv')} Gbps")
        results["metrics"]["tcp_multi_stream_8p"] = t8_stats

        # --- Phase 5: TCP Reverse Throughput (Out2In) ---
        print(f"\n--- 5. TCP Reverse Path (out2in, {args.duration}s) ---")
        tr_out = run_ns(lan_ns, "taskset", "-c", str(args.client_core),
                        "iperf3", "-c", "198.18.45.1", "-p", "5201", "-R", "-t", str(args.duration), "-J")
        tr_stats = parse_iperf3_json(tr_out)
        print(f"  Receiver (LAN): {tr_stats.get('gbps_recv')} Gbps")
        results["metrics"]["tcp_reverse_out2in"] = tr_stats

        # --- Phase 6: UDP Throughput (1400B Standard MTU) ---
        print(f"\n--- 6. UDP Throughput (1400B Payload, {args.duration}s) ---")
        u14_out = run_ns(lan_ns, "taskset", "-c", str(args.client_core),
                         "iperf3", "-c", "198.18.45.1", "-p", "5201", "-u", "-b", "0", "-l", "1400", "-t", str(args.duration), "-J")
        u14_stats = parse_iperf3_json(u14_out)
        pps_1400 = int(u14_stats.get("total_packets", 0) / args.duration)
        u14_stats["packets_per_second"] = pps_1400
        print(f"  Throughput: {u14_stats.get('gbps_recv')} Gbps, Loss: {u14_stats.get('loss_percent')}%, PPS: {pps_1400}")
        results["metrics"]["udp_1400b"] = u14_stats

        # --- Phase 7a: UDP Packet Rate (512B Medium Packet) ---
        print(f"\n--- 7a. UDP Packet Rate (512B Payload, {args.duration}s) ---")
        u512_out = run_ns(lan_ns, "taskset", "-c", str(args.client_core),
                          "iperf3", "-c", "198.18.45.1", "-p", "5201", "-u", "-b", "0", "-l", "512", "-t", str(args.duration), "-J")
        u512_stats = parse_iperf3_json(u512_out)
        pps_512 = int(u512_stats.get("total_packets", 0) / args.duration)
        u512_stats["packets_per_second"] = pps_512
        print(f"  Throughput: {u512_stats.get('gbps_recv')} Gbps, Loss: {u512_stats.get('loss_percent')}%, PPS: {pps_512}")
        results["metrics"]["udp_512b"] = u512_stats

        # --- Phase 7b: UDP Packet Rate (64B Small Packet / PPS Stress) ---
        print(f"\n--- 7b. UDP Packet Rate (64B Small Packet, {args.duration}s) ---")
        u64_out = run_ns(lan_ns, "taskset", "-c", str(args.client_core),
                         "iperf3", "-c", "198.18.45.1", "-p", "5201", "-u", "-b", "0", "-l", "64", "-t", str(args.duration), "-J")
        u64_stats = parse_iperf3_json(u64_out)
        pps_64 = int(u64_stats.get("total_packets", 0) / args.duration)
        u64_stats["packets_per_second"] = pps_64
        print(f"  Throughput: {u64_stats.get('gbps_recv')} Gbps, Loss: {u64_stats.get('loss_percent')}%, PPS: {pps_64}")
        results["metrics"]["udp_64b"] = u64_stats

        # --- Phase 8: Connection Setup Rate (CPS) ---
        print("\n--- 8. Concurrent TCP Connection Setup Rate (CPS) ---")
        cps_test = run_ns(lan_ns, "taskset", "-c", str(args.client_core), "python3", "-c", """
import socket, time
target = ('198.18.45.1', 5202)
success = 0
start = time.time()
for _ in range(500):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(target)
        s.close()
        success += 1
    except Exception:
        pass
elapsed = time.time() - start
cps = round(success / elapsed, 1) if elapsed > 0 else 0
import json
print(json.dumps({'connections_attempted': 500, 'connections_success': success, 'elapsed_sec': round(elapsed, 3), 'cps': cps}))
""")
        cps_stats = json.loads(cps_test.strip())
        print(f"  CPS: {cps_stats.get('cps')} connections/sec ({cps_stats.get('connections_success')}/500 in {cps_stats.get('elapsed_sec')}s)")
        results["metrics"]["connection_setup_cps"] = cps_stats

        # --- Phase 9: Linux Kernel Conntrack Inspection ---
        print("\n--- 9. Linux Kernel Conntrack Telemetry ---")
        try:
            ct_out = run_ns(rtr_ns, "cat", "/proc/sys/net/netfilter/nf_conntrack_count")
            ct_count = int(ct_out.strip())
        except Exception:
            ct_count = 0
        print(f"  Linux Conntrack Active Entries in Router Namespace: {ct_count}")
        results["metrics"]["conntrack_entries"] = ct_count

        results["success"] = True
        print("\n=== All Linux Kernel NAT Benchmark Phases Completed Successfully! ===")

    return results


if __name__ == "__main__":
    benchmark_results = main()
    output_dir = Path("/opt/vpp-vrouter-migration/source/artifacts/vrouter")
    if not output_dir.exists():
        output_dir = Path("artifacts/vrouter")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_file = output_dir / "linux-nat-performance-20261017.json"
    with open(report_file, "w") as f:
        json.dump(benchmark_results, f, indent=2)
    print(f"Benchmark report written to {report_file}")
    sys.exit(0 if benchmark_results.get("success") else 1)
