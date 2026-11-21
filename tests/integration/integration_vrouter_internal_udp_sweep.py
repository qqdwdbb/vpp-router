#!/usr/bin/env python3
"""Bounded-rate 64-byte UDP sweep through an isolated VPP TAP topology."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import tempfile
import time

BASE = Path("/opt/vpp-vrouter-migration")
VPP = Path("/opt/vpp-nic1-test/vpp/bin/vpp")
VPPCTL = Path("/opt/vpp-nic1-test/vpp/bin/vppctl")


def run(*args, check=True, timeout=60):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(args)}: {p.stderr[-2000:]}")
    return p.stdout


def nsrun(ns, *args, **kwargs):
    return run("ip", "netns", "exec", ns, *args, **kwargs)


def parse_iperf(output, duration):
    data = json.loads(output)
    end = data["end"]
    udp = end.get("sum", {})
    sent = int(udp.get("packets", 0))
    lost = int(udp.get("lost_packets", 0))
    received = max(0, sent - lost)
    elapsed = float(udp.get("seconds", duration) or duration)
    payload_bps = float(udp.get("bits_per_second", 0))
    return {
        "offered_packets": sent,
        "received_packets": received,
        "lost_packets": lost,
        "offered_pps": round(sent / elapsed) if elapsed else 0,
        "received_pps": round(received / elapsed) if elapsed else 0,
        "loss_percent": round(float(udp.get("lost_percent", 0.0)), 3),
        "payload_gbps_sent": round(payload_bps / 1e9, 4),
        "elapsed_sec": round(elapsed, 3),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, choices=(0, 1, 2), default=1)
    parser.add_argument("--duration", type=int, default=5)
    parser.add_argument("--rates", default="100M,200M,300M,400M,500M,600M,800M")
    parser.add_argument("--loss-threshold", type=float, default=1.0)
    parser.add_argument("--no-nat", action="store_true", help="Measure pure routing without NAT44-EI")
    parser.add_argument("--output", type=Path, default=Path("/tmp/vrouter-internal-udp-sweep.json"))
    args = parser.parse_args()
    rates = [rate.strip() for rate in args.rates.split(",") if rate.strip()]
    pid = str(__import__("os").getpid())
    lan_ns, wan_ns = f"vrouter-sweep-lan-{pid}", f"vrouter-sweep-wan-{pid}"
    with tempfile.TemporaryDirectory(prefix="vrouter-sweep-", dir="/run") as tmp, ExitStack() as stack:
        root = Path(tmp)
        for ns in (lan_ns, wan_ns):
            run("ip", "netns", "add", ns)
            stack.callback(subprocess.run, ["ip", "netns", "delete", ns], capture_output=True)
            run("ip", "-n", ns, "link", "set", "lo", "up")
        worker_cfg = ""
        if args.workers == 1:
            worker_cfg = "cpu { main-core 4 corelist-workers 5 }"
        elif args.workers == 2:
            worker_cfg = "cpu { main-core 4 corelist-workers 5,6 }"
        conf = root / "startup.conf"
        conf.write_text(f"""unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 16384 page-size 4k }}
plugins {{ path {BASE}/plugins
plugin default {{ disable }}
plugin nat44_ei_plugin.so {{ enable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
}}
{worker_cfg}
""")
        env = dict(__import__("os").environ,
                   PATH=f"/opt/vpp-nic1-test/vpp/bin:{__import__('os').environ['PATH']}",
                   LD_LIBRARY_PATH="/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu",
                   VPP_API_DIR=str(BASE / "runtime/python"))
        vpp = subprocess.Popen([str(VPP), "-c", str(conf)], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(vpp.terminate)
        for _ in range(100):
            if (root / "cli.sock").exists():
                break
            time.sleep(.1)
        if not (root / "cli.sock").exists():
            raise RuntimeError("isolated VPP CLI did not start")

        def cli(command):
            return run(str(VPPCTL), "-s", str(root / "cli.sock"), command)

        if not args.no_nat:
            cli("nat44 ei plugin enable sessions 65536")
        cli(f"create tap id 2001 host-ns {lan_ns} host-if-name mgmt0 rx-ring-size 4096 tx-ring-size 4096")
        cli("set interface ip address tap2001 10.61.20.1/24")
        cli("set interface state tap2001 up")
        cli(f"create tap id 3952 host-ns {wan_ns} host-if-name mgmt0 rx-ring-size 4096 tx-ring-size 4096")
        cli("set interface ip address tap3952 198.18.45.2/24")
        cli("set interface state tap3952 up")
        cli("ip route add 0.0.0.0/0 via 198.18.45.1 tap3952")
        if not args.no_nat:
            cli("nat44 ei add interface address tap3952")
            cli("set interface nat44 ei in tap2001 out tap3952")
        nsrun(lan_ns, "ip", "link", "set", "mgmt0", "up")
        nsrun(lan_ns, "ip", "addr", "add", "10.61.20.100/24", "dev", "mgmt0")
        nsrun(lan_ns, "ip", "route", "add", "default", "via", "10.61.20.1", "dev", "mgmt0")
        nsrun(wan_ns, "ip", "link", "set", "mgmt0", "up")
        nsrun(wan_ns, "ip", "addr", "add", "198.18.45.1/24", "dev", "mgmt0")
        if args.no_nat:
            nsrun(wan_ns, "ip", "route", "add", "10.61.20.0/24", "via", "198.18.45.2", "dev", "mgmt0")
        server = subprocess.Popen(["ip", "netns", "exec", wan_ns, "iperf3", "-s", "-p", "5201"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(server.terminate)
        nsrun(lan_ns, "ping", "-c", "2", "-W", "1", "198.18.45.1", check=False)

        results = []
        for rate in rates:
            raw = nsrun(lan_ns, "iperf3", "-c", "198.18.45.1", "-p", "5201",
                        "-u", "-b", rate, "-l", "64", "-t", str(args.duration), "-J", timeout=args.duration + 20)
            metric = parse_iperf(raw, args.duration)
            metric.update({"target_rate": rate, "stable": metric["loss_percent"] <= args.loss_threshold})
            results.append(metric)
            print(json.dumps(metric), flush=True)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({
            "workers": args.workers, "nat": not args.no_nat, "payload_bytes": 64,
            "wire_bytes_estimate": 106, "duration_sec": args.duration,
            "loss_threshold_percent": args.loss_threshold, "results": results,
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()
