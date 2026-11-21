#!/usr/bin/env python3
"""Isolated VPP packet-generator forwarding benchmark on VROUTER.

PG interfaces and the private VPP process have no physical or production TAP
interfaces.  A 60-byte VPP L2 buffer represents a 64-byte Ethernet frame
including the on-wire FCS (preamble and IFG are additional).
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


VPP = Path("/opt/vpp-nic1-test/vpp/bin/vpp")
VPPCTL = Path("/opt/vpp-nic1-test/vpp/bin/vppctl")
PLUGINS = Path("/opt/vpp-vrouter-migration/plugins")


def run(*command, timeout=15):
    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, command))}: {result.stderr[-1000:]}")
    return result.stdout


def counter(output, name):
    match = re.search(rf"^[^\n]*?\b{re.escape(name)}\s+(\d+)\s*$", output, re.MULTILINE)
    return int(match.group(1)) if match else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("route", "nat"), default="route")
    parser.add_argument("--workers", type=int, choices=(0, 1), default=1)
    parser.add_argument("--rates", default="100000,250000,500000,1000000")
    parser.add_argument("--duration", type=float, default=3.0)
    parser.add_argument("--output", type=Path, default=Path("/tmp/vrouter-pg-perf.json"))
    args = parser.parse_args()
    rates = [int(rate) for rate in args.rates.split(",")]
    if not rates or any(rate < 1000 or rate > 5_000_000 for rate in rates):
        parser.error("rates must be 1,000..5,000,000 PPS")
    if not 1 <= args.duration <= 10:
        parser.error("duration must be 1..10 seconds")
    if not VPP.exists() or not VPPCTL.exists():
        raise RuntimeError("VPP binaries missing")
    production_pid = run("systemctl", "show", "-p", "MainPID", "--value", "vrouter-vpp").strip()
    if not production_pid.isdecimal() or production_pid == "0":
        raise RuntimeError("production VPP is not active")

    report = {"mode": args.mode, "workers": args.workers, "l2_bytes_without_fcs": 60,
              "ethernet_frame_bytes_with_fcs": 64, "results": []}
    with tempfile.TemporaryDirectory(prefix="vrouter-pg-perf-", dir="/run") as tmp, ExitStack() as stack:
        root = Path(tmp)
        conf = root / "startup.conf"
        worker = "cpu { main-core 4 corelist-workers 5 }" if args.workers else "cpu { main-core 4 }"
        nat_plugin = "plugin nat44_ei_plugin.so { enable }" if args.mode == "nat" else ""
        conf.write_text(f"""unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 16384 page-size 4k }}
plugins {{ path {PLUGINS}
plugin default {{ disable }}
{nat_plugin}
}}
{worker}
""")
        env = dict(os.environ, LD_LIBRARY_PATH="/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:"
                   "/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu")
        log = (root / "vpp.log").open("w")
        stack.callback(log.close)
        process = subprocess.Popen([str(VPP), "-c", str(conf)], env=env, stdout=log, stderr=log)
        stack.callback(process.wait, timeout=5)
        stack.callback(process.terminate)
        socket = root / "cli.sock"
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("isolated VPP exited: " + (root / "vpp.log").read_text()[-1000:])
            if socket.exists():
                break
            time.sleep(.5)
        if not socket.exists():
            raise RuntimeError("isolated VPP CLI timeout")

        def cli(command):
            output = run(str(VPPCTL), "-s", str(socket), command)
            if re.search(r"unknown input|error:|failed|invalid", output, re.I):
                raise RuntimeError(f"VPP CLI {command}: {output[-1000:]}")
            return output

        if args.mode == "nat":
            cli("nat44 ei plugin enable sessions 4096")
        cli("create packet-generator interface pg0")
        cli("create packet-generator interface pg1")
        cli("set interface state pg0 up")
        cli("set interface state pg1 up")
        cli("set interface mac address pg0 00:04:00:05:00:06")
        cli("set interface ip address pg0 10.240.0.1/24")
        cli("set interface ip address pg1 10.241.0.1/24")
        cli("set ip neighbor pg1 10.241.0.2 02:00:00:00:01:02")
        if args.mode == "nat":
            cli("nat44 ei add interface address pg1")
            cli("set interface nat44 ei in pg0 out pg1")
        cli("packet-generator new { name vrouter-perf limit 1 rate 1000 size 60-60 "
            "interface pg0 node ethernet-input "
            "data { IP4: 1.2.3 -> 4.5.6 UDP: 10.240.0.2 -> 10.241.0.2 "
            "UDP: 12345 -> 23456 incrementing 46 } }")
        cli("packet-generator enable-stream vrouter-perf")
        time.sleep(.2)
        warm = counter(cli("show interface pg1"), "tx packets")
        if warm < 1:
            raise RuntimeError("PG warmup packet did not reach pg1: "
                               + cli("show interface pg0") + cli("show interface pg1")
                               + cli("show hardware-interfaces pg0")
                               + cli("show packet-generator") + cli("show errors")
                               + cli("show trace"))
        for rate in rates:
            limit = int(rate * args.duration * 2)
            cli(f"packet-generator configure vrouter-perf limit {limit} rate {rate}")
            cli("clear interfaces")
            before_pg = cli("show interface pg0")
            before_out = cli("show interface pg1")
            cli("packet-generator enable-stream vrouter-perf")
            start = time.monotonic()
            time.sleep(args.duration)
            elapsed = time.monotonic() - start
            cli("packet-generator disable-stream vrouter-perf")
            time.sleep(.1)
            after_pg = cli("show interface pg0")
            after_out = cli("show interface pg1")
            injected = counter(after_pg, "rx packets") - counter(before_pg, "rx packets")
            forwarded = counter(after_out, "tx packets") - counter(before_out, "tx packets")
            if process.poll() is not None:
                raise RuntimeError("isolated VPP exited during test")
            result = {"target_pps": rate, "sample_duration_sec": round(elapsed, 3),
                      "injected_packets": injected, "forwarded_packets": forwarded,
                      "injected_pps": round(injected / elapsed),
                      "forwarded_pps": round(forwarded / elapsed),
                      "rx_tx_counter_gap_packets": injected - forwarded,
                      "rx_tx_counter_gap_percent": round(100 * (injected - forwarded) / injected, 3) if injected else None,
                      "generator_met_target": injected / elapsed >= rate * .95}
            report["results"].append(result)
            print(json.dumps(result), flush=True)
        report["production_vpp_pid_unchanged"] = (
            run("systemctl", "show", "-p", "MainPID", "--value", "vrouter-vpp").strip() == production_pid
        )
        if not report["production_vpp_pid_unchanged"]:
            raise RuntimeError("production VPP PID changed during test")
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
