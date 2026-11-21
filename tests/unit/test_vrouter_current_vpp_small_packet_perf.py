#!/usr/bin/env python3
"""Physical 64B small-packet pressure test for the current production VPP path.

The legacy benchmark assumes Linux forwarding and iptables.  This test sends
合法 LAN-source packets from the physical peer and measures the current VPP
WAN sub-interface counters instead.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

CLIENT_IP = os.environ.get("CLIENT_IP")
ROUTER_IP = os.environ.get("ROUTER_IP")
CLIENT_USER = os.environ.get("CLIENT_USER")
ROUTER_USER = os.environ.get("ROUTER_USER")
GATEWAY_MAC = os.environ.get("GATEWAY_MAC")
CLIENT_INTERFACE = os.environ.get("CLIENT_INTERFACE", "eno1")
SOURCE_IP = os.environ.get("SOURCE_IP", CLIENT_IP)
DEST_IP = os.environ.get("DEST_IP", "1.1.1.1")
VPP_WAN_INTERFACE = os.environ.get("VPP_WAN_INTERFACE", "nic0-dpdk.100")

SSH = [
    "ssh", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
    "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
]


def ssh(host, user, command, askpass, timeout=120):
    env = dict(os.environ, SSH_ASKPASS_REQUIRE="force", SSH_ASKPASS=askpass, DISPLAY=":0")
    result = subprocess.run(
        SSH + [f"{user}@{host}", command], env=env, capture_output=True,
        text=True, timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(f"SSH command failed on {host}: {result.stderr.strip()}")
    return result.stdout


def sudo(command, password):
    return f"printf '%s\\n' {shlex.quote(password)} | sudo -S {command}"


def vpp_counters(askpass, password):
    out = ssh(
        ROUTER_IP, ROUTER_USER,
        sudo(f"vppctl show interface {shlex.quote(VPP_WAN_INTERFACE)}", password),
        askpass,
    )
    values = {}
    for key in ("tx packets", "tx bytes", "drops", "tx-error"):
        match = re.search(rf"^\s*{re.escape(key)}\s+(\d+)", out, re.MULTILINE)
        values[key.replace(" ", "_")] = int(match.group(1)) if match else 0
    return values


def parse_pktgen(output):
    results = []
    for match in re.finditer(
        r"Result: OK: (\d+)\([^)]*\) usec, (\d+) \(64byte.*?\n"
        r"\s+(\d+)pps", output, re.DOTALL,
    ):
        usec, packets, pps = map(int, match.groups())
        results.append({"duration_sec": usec / 1e6, "packets": packets, "pps": pps})
    if not results:
        raise RuntimeError(f"Cannot parse pktgen output: {output[-2000:]}")
    return {
        "packets": sum(item["packets"] for item in results),
        "duration_sec": max(item["duration_sec"] for item in results),
        "offered_pps": sum(item["pps"] for item in results),
        "queues": results,
    }


def send_stage(askpass, password, packets, threads, flows, clone_skb, burst, flowlen):
    per_thread = packets // threads
    base = '/usr/src/linux-headers-$(uname -r)/samples/pktgen/pktgen_sample05_flow_per_thread.sh'
    command = f"""
set -eu
tmp=$(mktemp /tmp/vrouter-pktgen.XXXXXX.sh)
trap 'rm -f "$tmp"' EXIT
cp {base} "$tmp"
cp "$(dirname {base})/functions.sh" "$(dirname "$tmp")/functions.sh"
cp "$(dirname {base})/parameters.sh" "$(dirname "$tmp")/parameters.sh"
chmod 700 "$tmp"
sed -i '/pg_set \\$dev "src_min/c\\    pg_set $dev "src_min {SOURCE_IP}"' "$tmp"
sed -i '/pg_set \\$dev "src_max/c\\    pg_set $dev "src_max {SOURCE_IP}"' "$tmp"
FLOWS={flows} FLOWLEN={flowlen} BURST={burst} CLONE_SKB={clone_skb} UDP_CSUM=1 COUNT={per_thread} \
  "$tmp" -i {shlex.quote(CLIENT_INTERFACE)} -s 64 -d {DEST_IP} -m {shlex.quote(GATEWAY_MAC)} -t {threads} -n {per_thread}
"""
    out = ssh(CLIENT_IP, CLIENT_USER, sudo("bash -c " + shlex.quote(command), password), askpass, timeout=180)
    return parse_pktgen(out)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--askpass", required=True)
    parser.add_argument("--client-pass", default=os.environ.get("CLIENT_PASS", ""))
    parser.add_argument("--router-pass", default=os.environ.get("ROUTER_PASS", ""))
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--clone-skb", type=int, default=100)
    parser.add_argument("--burst", type=int, default=64)
    parser.add_argument("--flowlen", type=int, default=10)
    parser.add_argument("--stages", default="100000,250000,500000,1000000")
    parser.add_argument("--output", type=Path, default=Path("artifacts/vrouter/current-vpp-small-packet.json"))
    args = parser.parse_args()
    required = ("CLIENT_IP", "ROUTER_IP", "CLIENT_USER", "ROUTER_USER", "GATEWAY_MAC")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        parser.error("set the required environment variables: " + ", ".join(missing))
    stages = [int(value) for value in args.stages.split(",") if int(value) > 0]
    results = []
    for packets in stages:
        before = vpp_counters(args.askpass, args.router_pass)
        started = time.monotonic()
        offered = send_stage(
            args.askpass, args.client_pass, packets, args.threads,
            max(1000, packets // 10), args.clone_skb, args.burst, args.flowlen,
        )
        elapsed = time.monotonic() - started
        after = vpp_counters(args.askpass, args.router_pass)
        forwarded = after["tx_packets"] - before["tx_packets"]
        result = {
            "requested_packets": packets,
            "offered": offered,
            "wall_seconds": round(elapsed, 3),
            "forwarded_packets_delta": forwarded,
            "forwarded_pps_wall": round(forwarded / elapsed) if elapsed else 0,
            "forwarded_pps_offered_window": round(
                forwarded / offered["duration_sec"]
            ) if offered["duration_sec"] else 0,
            "observed_loss_percent": round(
                max(0, offered["packets"] - forwarded) * 100 / offered["packets"], 3
            ),
            "vpp_before": before,
            "vpp_after": after,
        }
        results.append(result)
        print(json.dumps(result), flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "source": SOURCE_IP, "destination": DEST_IP, "packet_size": 64,
        "threads": args.threads, "results": results,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
