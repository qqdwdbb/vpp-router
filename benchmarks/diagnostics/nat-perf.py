#!/usr/bin/env python3
"""VPP NAT44-EI Performance Benchmark Tool for NanoPi VROUTER.

Measures:
1. TCP Throughput (Single-stream and multi-stream parallel flows)
2. Reverse TCP Throughput (out2in reverse path)
3. UDP Throughput and Packet Rate (PPS for MTU, 512B, and 64B small packets)
4. Connection Setup Rate (CPS - connections per second)
5. Forwarding Latency & Jitter (min/avg/max/mdev)
6. VPP Internal Node Graph Runtime Statistics (clocks/packet, vectors/call)
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def parse_iperf3_json(output):
    """Parse iperf3 JSON output to extract key throughput and loss metrics."""
    try:
        data = json.loads(output)
        end = data.get("end", {})
        sum_sent = end.get("sum_sent", {})
        sum_received = end.get("sum_received", {})
        
        # Bits per second to Gbits per second
        bps_sent = sum_sent.get("bits_per_second", 0)
        bps_recv = sum_received.get("bits_per_second", 0)

        # UDP specific metrics
        sum_udp = end.get("sum", {})
        if bps_recv == 0 and "bits_per_second" in sum_udp:
            bps_recv = sum_udp["bits_per_second"]
        if bps_sent == 0 and "bits_per_second" in sum_udp:
            bps_sent = sum_udp["bits_per_second"]

        gbps_sent = bps_sent / 1e9
        gbps_recv = bps_recv / 1e9

        lost_packets = sum_udp.get("lost_packets", 0)
        total_packets = sum_udp.get("packets", 0)
        loss_percent = sum_udp.get("lost_percent", 0.0)
        jitter_ms = sum_udp.get("jitter_ms", 0.0)

        # CPU utilization reported by iperf3
        cpu_util = end.get("cpu_utilization_percent", {})

        return {
            "gbps_sent": round(gbps_sent, 3),
            "gbps_recv": round(gbps_recv, 3),
            "mbps_sent": round(bps_sent / 1e6, 2),
            "mbps_recv": round(bps_recv / 1e6, 2),
            "lost_packets": lost_packets,
            "total_packets": total_packets,
            "loss_percent": round(loss_percent, 2),
            "jitter_ms": round(jitter_ms, 3),
            "cpu_host_total": cpu_util.get("host_total", 0),
            "cpu_remote_total": cpu_util.get("remote_total", 0)
        }
    except Exception as e:
        return {"error": str(e), "raw_snippet": output[:300]}


def parse_ping_output(output):
    """Parse ping output to extract min/avg/max/mdev RTT in milliseconds."""
    m_loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", output)
    loss = float(m_loss.group(1)) if m_loss else 100
    result = {"loss_percent": loss}
    m = re.search(r"rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms", output)
    if m:
        result.update({
            "min_ms": float(m.group(1)),
            "avg_ms": float(m.group(2)),
            "max_ms": float(m.group(3)),
            "mdev_ms": float(m.group(4))
        })
    else:
        result["error"] = "No RTT found"
    return result


def parse_vpp_runtime(runtime_output):
    """Sum node counters across threads; weight clocks/packet by vectors.

    Rows with no vectors add calls but no packet cost. If all rows are idle,
    report zero clocks/packet rather than treating clocks/call as packet cost.
    """
    nat_nodes = {}
    target_nodes = ["nat44-ei-in2out", "nat44-ei-out2in", "nat44-ei-in2out-worker-handoff",
                    "nat44-ei-out2in-worker-handoff", "ip4-lookup", "ip4-rewrite"]
    for line in runtime_output.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        name = parts[0]
        if not any(target in name for target in target_nodes):
            continue
        try:
            calls, vectors, clocks = int(parts[2]), int(parts[3]), float(parts[5])
        except ValueError:
            continue
        node = nat_nodes.setdefault(name, {"calls": 0, "vectors": 0, "clocks": 0.0})
        packet_cost = node["clocks"] * node["vectors"] + clocks * vectors
        node["calls"] += calls
        node["vectors"] += vectors
        node["clocks"] = packet_cost / node["vectors"] if node["vectors"] else 0.0
    return nat_nodes


def parse_args():
    parser = argparse.ArgumentParser(description="VPP NAT44-EI Performance Benchmark")
    parser.add_argument("--workers", type=int, choices=[0, 2], default=2, help="Number of VPP worker threads")
    parser.add_argument("--duration", type=int, default=5, help="Test duration in seconds per scenario")
    parser.add_argument("--parallel", type=int, default=4, help="Parallel streams for multi-stream test")
    parser.add_argument("--udp-bandwidth", default="0", help="Target bandwidth for UDP tests (0 for unlimited)")
    parser.add_argument("--output", help="Output JSON results file path")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print("VPP NAT Performance Benchmark Module")
