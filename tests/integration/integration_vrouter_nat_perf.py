#!/usr/bin/env python3
"""Automated VPP NAT44-EI Performance Benchmark for NanoPi VROUTER.

Benchmarks:
1. Baseline Round-Trip Latency (ICMP ping)
2. TCP Single-Stream Throughput (in2out)
3. TCP Multi-Stream Throughput (4 & 8 parallel streams)
4. TCP Reverse Throughput (out2in)
5. UDP Throughput & PPS (1400B, 512B, 64B packets)
6. Dynamic Connection Setup Rate (CPS)
7. Loaded Latency & Jitter
8. VPP Node Graph Runtime Telemetry (clocks/packet, vectors/call)
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
parse_vpp_runtime = nat_perf_mod.parse_vpp_runtime


def run_cmd(*args, check=True, timeout=30):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(args)}): {p.stderr.strip()}")
    return p.stdout


def run_ns(ns, *args, check=True, timeout=30):
    return run_cmd("ip", "netns", "exec", ns, *args, check=check, timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description="VPP NAT44-EI Performance Benchmark")
    parser.add_argument("--workers", type=int, choices=[0, 1, 2], default=2, help="Number of VPP worker threads")
    parser.add_argument("--duration", type=int, default=5, help="Test duration in seconds per scenario")
    parser.add_argument("--vppctl", default="/opt/vpp-nic1-test/vpp/bin/vppctl")
    parser.add_argument("--vpp-bin", default="/opt/vpp-nic1-test/vpp/bin/vpp")
    args = parser.parse_args()

    pid = os.getpid()
    lan_ns = f"vrouter-perf-lan-{pid}"
    wan_ns = f"vrouter-perf-wan-{pid}"
    namespaces = [lan_ns, wan_ns]

    base = Path("/opt/vpp-vrouter-migration")
    vppctl = Path(args.vppctl)
    vpp_bin = Path(args.vpp_bin)

    env = dict(os.environ,
               PATH=f"/opt/vpp-nic1-test/vpp/bin:{os.environ['PATH']}",
               LD_LIBRARY_PATH="/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu",
               PYTHONPATH=str(base / "runtime/python"),
               VPP_API_DIR="/opt/vpp-nic1-test/vpp/share/vpp/api")

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hardware": "NanoPi VROUTER (RK3588, 4x Cortex-A76 + 4x Cortex-A55)",
        "vpp_workers": args.workers,
        "duration_per_test_sec": args.duration,
        "metrics": {}
    }

    print(f"=== Starting VPP NAT44-EI Performance Benchmark (PID {pid}, Workers {args.workers}) ===")

    with tempfile.TemporaryDirectory(prefix="vrouter-natperf-", dir="/run") as directory, ExitStack() as stack:
        root = Path(directory)
        root.chmod(0o755)

        # 1. Create isolated namespaces
        for ns in namespaces:
            run_cmd("ip", "netns", "add", ns)
            stack.callback(subprocess.run, ["ip", "netns", "delete", ns], capture_output=True)
            run_cmd("ip", "-n", ns, "link", "set", "lo", "up")

        # 2. Configure VPP
        sock_cli = root / "cli.sock"
        sock_api = root / "api.sock"
        sock_stats = root / "stats.sock"

        plugins = [
            "nat44_ei_plugin.so", "tap_plugin.so", "ping_plugin.so"
        ]

        if args.workers == 2:
            cpu_cfg = "cpu { main-core 4 corelist-workers 5,6 }"
        elif args.workers == 1:
            cpu_cfg = "cpu { main-core 4 corelist-workers 5 }"
        else:
            cpu_cfg = "cpu { main-core 4 }"

        (root / "startup.conf").write_text(f"""unix {{ nodaemon runtime-dir {root} cli-listen {sock_cli} }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {sock_api} }}
statseg {{ socket-name {sock_stats} }}
buffers {{ buffers-per-numa 16384 page-size 4k }}
plugins {{ path {base}/plugins
plugin default {{ disable }}
{chr(10).join('plugin ' + name + ' { enable }' for name in plugins)}
}}
{cpu_cfg}
""")

        def cli(cmd):
            out = run_cmd(str(vppctl), "-s", str(sock_cli), cmd)
            if any(w in out.lower() for w in ("error:", "unknown input", "invalid", "failed")):
                raise RuntimeError(f"VPP command failed: {cmd} -> {out}")
            return out

        vpp_proc = subprocess.Popen([str(vpp_bin), "-c", str(root / "startup.conf")],
                                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(vpp_proc.terminate)

        # Wait for VPP
        for _ in range(40):
            if sock_cli.exists():
                break
            time.sleep(0.1)
        assert sock_cli.exists(), "VPP CLI socket failed to appear"

        # Enable NAT44-EI plugin before configuring interfaces/addresses
        cli("nat44 ei plugin enable sessions 65536")

        # 3. Setup VPP Interfaces:
        # LAN: tap2001 (inside NAT44-EI, 10.61.20.1/24)
        cli(f"create tap id 2001 host-ns {lan_ns} host-if-name mgmt0 rx-ring-size 1024 tx-ring-size 1024 gso")
        cli("set interface ip address tap2001 10.61.20.1/24")
        cli("set interface state tap2001 up")

        # WAN: tap3952 (outside NAT44-EI, 198.18.45.2/24)
        cli(f"create tap id 3952 host-ns {wan_ns} host-if-name mgmt0 rx-ring-size 1024 tx-ring-size 1024 gso")
        cli("set interface ip address tap3952 198.18.45.2/24")
        cli("set interface state tap3952 up")

        # Routing & NAT44-EI Configuration
        cli("ip route add 0.0.0.0/0 via 198.18.45.1 tap3952")
        cli("nat44 ei add interface address tap3952")
        cli("set interface nat44 ei in tap2001 out tap3952")

        # Configure Linux namespaces
        run_ns(lan_ns, "ip", "link", "set", "mgmt0", "up")
        run_ns(lan_ns, "ip", "addr", "add", "10.61.20.100/24", "dev", "mgmt0")
        run_ns(lan_ns, "ip", "route", "add", "default", "via", "10.61.20.1", "dev", "mgmt0")

        run_ns(wan_ns, "ip", "link", "set", "mgmt0", "up")
        run_ns(wan_ns, "ip", "addr", "add", "198.18.45.1/24", "dev", "mgmt0")

        # 4. Start Servers in WAN namespace
        # 4a. iperf3 server on port 5201
        iperf_server = subprocess.Popen(["ip", "netns", "exec", wan_ns, "iperf3", "-s", "-p", "5201"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(iperf_server.terminate)

        # 4b. Dedicated lightweight TCP server on port 5202 for CPS benchmark
        cps_server = subprocess.Popen(["ip", "netns", "exec", wan_ns, "python3", "-c", """
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
        ping_out = run_ns(lan_ns, "ping", "-c", "5", "-W", "1", "198.18.45.1")
        ping_stats = parse_ping_output(ping_out)
        print(f"  RTT: min={ping_stats.get('min_ms')}ms, avg={ping_stats.get('avg_ms')}ms, max={ping_stats.get('max_ms')}ms")
        results["metrics"]["baseline_latency"] = ping_stats

        # --- Phase 2: TCP Single Stream Throughput ---
        print(f"\n--- 2. TCP Single-Stream Throughput ({args.duration}s) ---")
        t1_out = run_ns(lan_ns, "iperf3", "-c", "198.18.45.1", "-p", "5201", "-t", str(args.duration), "-J")
        t1_stats = parse_iperf3_json(t1_out)
        print(f"  Sender: {t1_stats.get('gbps_sent')} Gbps, Receiver: {t1_stats.get('gbps_recv')} Gbps")
        results["metrics"]["tcp_single_stream"] = t1_stats

        # --- Phase 3: TCP Multi-Stream Throughput (4 Parallel Flows) ---
        print(f"\n--- 3. TCP Multi-Stream (4 Parallel Streams, {args.duration}s) ---")
        t4_out = run_ns(lan_ns, "iperf3", "-c", "198.18.45.1", "-p", "5201", "-P", "4", "-t", str(args.duration), "-J")
        t4_stats = parse_iperf3_json(t4_out)
        print(f"  Sender: {t4_stats.get('gbps_sent')} Gbps, Receiver: {t4_stats.get('gbps_recv')} Gbps")
        results["metrics"]["tcp_multi_stream_4p"] = t4_stats

        # --- Phase 4: TCP Multi-Stream Throughput (8 Parallel Flows) ---
        print(f"\n--- 4. TCP Multi-Stream (8 Parallel Streams, {args.duration}s) ---")
        t8_out = run_ns(lan_ns, "iperf3", "-c", "198.18.45.1", "-p", "5201", "-P", "8", "-t", str(args.duration), "-J")
        t8_stats = parse_iperf3_json(t8_out)
        print(f"  Sender: {t8_stats.get('gbps_sent')} Gbps, Receiver: {t8_stats.get('gbps_recv')} Gbps")
        results["metrics"]["tcp_multi_stream_8p"] = t8_stats

        # --- Phase 5: TCP Reverse Throughput (Out2In) ---
        print(f"\n--- 5. TCP Reverse Path (out2in, {args.duration}s) ---")
        tr_out = run_ns(lan_ns, "iperf3", "-c", "198.18.45.1", "-p", "5201", "-R", "-t", str(args.duration), "-J")
        tr_stats = parse_iperf3_json(tr_out)
        print(f"  Receiver (LAN): {tr_stats.get('gbps_recv')} Gbps")
        results["metrics"]["tcp_reverse_out2in"] = tr_stats

        # --- Phase 6: UDP Throughput (1400B Standard MTU) ---
        print(f"\n--- 6. UDP Throughput (1400B Payload, {args.duration}s) ---")
        u14_out = run_ns(lan_ns, "iperf3", "-c", "198.18.45.1", "-p", "5201", "-u", "-b", "0", "-l", "1400", "-t", str(args.duration), "-J")
        u14_stats = parse_iperf3_json(u14_out)
        pps_1400 = int(u14_stats.get("total_packets", 0) / args.duration)
        u14_stats["packets_per_second"] = pps_1400
        print(f"  Throughput: {u14_stats.get('gbps_recv')} Gbps, Loss: {u14_stats.get('loss_percent')}%, PPS: {pps_1400}")
        results["metrics"]["udp_1400b"] = u14_stats

        # --- Phase 7a: UDP Packet Rate (512B Medium Packet) ---
        print(f"\n--- 7a. UDP Packet Rate (512B Payload, {args.duration}s) ---")
        u512_out = run_ns(lan_ns, "iperf3", "-c", "198.18.45.1", "-p", "5201", "-u", "-b", "0", "-l", "512", "-t", str(args.duration), "-J")
        u512_stats = parse_iperf3_json(u512_out)
        pps_512 = int(u512_stats.get("total_packets", 0) / args.duration)
        u512_stats["packets_per_second"] = pps_512
        print(f"  Throughput: {u512_stats.get('gbps_recv')} Gbps, Loss: {u512_stats.get('loss_percent')}%, PPS: {pps_512}")
        results["metrics"]["udp_512b"] = u512_stats

        # --- Phase 7b: UDP Packet Rate (64B Small Packet / PPS Stress) ---
        print(f"\n--- 7b. UDP Packet Rate (64B Small Packet, {args.duration}s) ---")
        u64_out = run_ns(lan_ns, "iperf3", "-c", "198.18.45.1", "-p", "5201", "-u", "-b", "0", "-l", "64", "-t", str(args.duration), "-J")
        u64_stats = parse_iperf3_json(u64_out)
        pps_64 = int(u64_stats.get("total_packets", 0) / args.duration)
        u64_stats["packets_per_second"] = pps_64
        print(f"  Throughput: {u64_stats.get('gbps_recv')} Gbps, Loss: {u64_stats.get('loss_percent')}%, PPS: {pps_64}")
        results["metrics"]["udp_64b"] = u64_stats

        # --- Phase 8: Connection Setup Rate (CPS) ---
        print("\n--- 8. Concurrent TCP Connection Setup Rate (CPS) ---")
        cps_test = run_ns(lan_ns, "python3", "-c", """
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

        # --- Phase 9: VPP Runtime Telemetry & Active Sessions ---
        print("\n--- 9. VPP NAT44-EI Runtime & Session Inspection ---")
        rx_placement = cli("show interface rx-placement")
        print("  Interface RX Placement:")
        for line in rx_placement.strip().splitlines():
            print(f"    {line}")
        results["metrics"]["rx_placement"] = rx_placement.strip()

        runtime_out = cli("show runtime")
        nat_runtime = parse_vpp_runtime(runtime_out)
        sessions_out = cli("show nat44 ei sessions")
        thread_sessions = [int(x) for x in re.findall(r"(\d+)\s+sessions", sessions_out)]
        total_sessions = sum(thread_sessions) if thread_sessions else 0
        if total_sessions == 0:
            m_sess = re.search(r"total sessions:\s*(\d+)", sessions_out, re.I)
            total_sessions = int(m_sess.group(1)) if m_sess else len(re.findall(r"dynamic translations", sessions_out))

        print(f"  NAT Active Sessions: {total_sessions}")
        for node, val in nat_runtime.items():
            print(f"  Node {node}: {val.get('vectors')} vectors, {val.get('clocks')} clocks/pkt")

        results["metrics"]["vpp_runtime"] = nat_runtime
        results["metrics"]["nat_sessions_recorded"] = total_sessions

        results["success"] = True
        print("\n=== All NAT Performance Benchmark Phases Completed Successfully! ===")

    return results


if __name__ == "__main__":
    benchmark_results = main()
    output_dir = Path("/opt/vpp-vrouter-migration/source/artifacts/vrouter")
    if not output_dir.exists():
        output_dir = Path("artifacts/vrouter")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_file = output_dir / "nat-performance-20261017.json"
    with open(report_file, "w") as f:
        json.dump(benchmark_results, f, indent=2)
    print(f"Benchmark report written to {report_file}")
    sys.exit(0 if benchmark_results.get("success") else 1)
