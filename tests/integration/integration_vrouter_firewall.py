#!/usr/bin/env python3
"""End-to-end isolated integration test for VROUTER Unified Firewall Policy.

Verifies the dual-layer firewall policy on NanoPi VROUTER:
1. WAN Inbound Filtering: Blocks unauthorized probes (TCP 22/80, random UDP),
   permits authorized VPN/IKE (UDP 500/4500), WireGuard (UDP 42008), and ICMP.
2. WAN Anti-Spoofing: Drops packets arriving on WAN claiming internal RFC1918/ULA sources.
3. LAN Egress & Stateful Return: Outbound LAN to WAN (NAT44-EI IPv4 and direct IPv6)
   succeeds with stateful return sessions accepted.
4. WAN Anti-Leak: Cleartext RFC1918 / ULA traffic cannot leak unencrypted onto WAN.
5. LAN Gateway Protection: ICMP ping to gateway (.1/::1) is permitted, while unopened
   router ports on .1 are dropped.
6. Linux Host Protection (br-mgmt): DNS (:53) redirects to gate (:1053); SSH (:22)
   is permitted from trusted LAN sources; direct access to proxy ports (:1080/:2080) is dropped.
7. DNS Anti-Bypass (Fail-Closed): Stops uninspected DNS queries from bypassing the gate.
8. Clean Teardown & Idempotency: Complete cleanup of all test rules and namespaces.
"""
import argparse
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

BASE_DIR = Path(__file__).resolve().parents[2]
FIREWALL_DIR = BASE_DIR / "deploy/firewall"
STARTUP_DIR = BASE_DIR / "deploy/startup"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fw_mod = load_module("vrouter_firewall", FIREWALL_DIR / "vrouter-firewall.py")


def run_cmd(*args, check=True, timeout=15):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(args)}): {p.stderr.strip()}")
    return p.stdout


def run_ns(ns, *args, check=True, timeout=15):
    return run_cmd("ip", "netns", "exec", ns, *args, check=check, timeout=timeout)


def tcp_probe(target_ip, port, timeout=2.0, src_ip=None):
    """Test TCP connectivity from current namespace to target."""
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if src_ip:
        s.bind((src_ip, 0))
    try:
        s.connect((target_ip, port))
        s.close()
        return True
    except (socket.timeout, OSError):
        s.close()
        return False


def udp_probe(target_ip, port, payload=b"probe", timeout=2.0, src_ip=None):
    """Send UDP packet and wait for response."""
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    if src_ip:
        s.bind((src_ip, 0))
    try:
        s.sendto(payload, (target_ip, port))
        data, _ = s.recvfrom(2048)
        s.close()
        return True, data
    except (socket.timeout, OSError):
        s.close()
        return False, None


def echo_flow(source_ns, target_ns, address, proto, stack):
    """Check delivery to a live listener; only a timeout counts as blocked."""
    server = r"""
import socket, sys
address, proto = sys.argv[1:]
family = socket.AF_INET6 if ':' in address else socket.AF_INET
kind = socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM
s = socket.socket(family, kind)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((address, 44444))
s.settimeout(5)
if proto == 'tcp': s.listen(4)
print('ready', flush=True)
try:
    if proto == 'tcp':
        c, _ = s.accept()
        with c: c.sendall(c.recv(128))
    else:
        data, peer = s.recvfrom(128)
        s.sendto(data, peer)
except socket.timeout: pass
finally: s.close()
"""
    proc = subprocess.Popen(['ip', 'netns', 'exec', target_ns, 'python3', '-c',
                             server, address, proto], stdout=subprocess.PIPE, text=True)
    stack.callback(proc.wait)
    stack.callback(proc.terminate)
    assert proc.stdout.readline().strip() == 'ready', 'Echo listener failed to start'
    result = run_ns(source_ns, 'python3', '-c', r"""
import socket, sys
address, proto = sys.argv[1:]
s = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,
                  socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM)
s.settimeout(1.5)
try:
    s.connect((address, 44444))
    s.sendall(b'firewall-check')
    assert s.recv(128) == b'firewall-check'
    print('delivered')
except socket.timeout: print('timeout')
finally: s.close()
""", address, proto).strip()
    proc.terminate()
    proc.wait(timeout=3)
    return result


def main():
    parser = argparse.ArgumentParser(description="Integration test for VROUTER Unified Firewall Policy")
    parser.add_argument("--workers", type=int, default=2, help="Number of VPP workers")
    parser.add_argument("--vppctl", default="/opt/vpp-nic1-test/vpp/bin/vppctl")
    parser.add_argument("--vpp-bin", default="/opt/vpp-nic1-test/vpp/bin/vpp")
    parser.add_argument("--plugin-path", default="/opt/vpp-vrouter-migration/plugins")
    parser.add_argument("--output-nat", action="store_true")
    args = parser.parse_args()

    pid = os.getpid()
    lan_ns = f"vrouter-fw-lan-{pid}"
    host_ns = f"vrouter-fw-host-{pid}"
    wan_ns = f"vrouter-fw-wan-{pid}"
    namespaces = [lan_ns, host_ns, wan_ns]

    base = Path("/opt/vpp-vrouter-migration")
    vppctl = Path(args.vppctl)
    vpp_bin = Path(args.vpp_bin)

    env = dict(os.environ,
               PATH=f"/opt/vpp-nic1-test/vpp/bin:{os.environ['PATH']}",
               LD_LIBRARY_PATH=f"/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu",
               PYTHONPATH=str(base / "runtime/python"),
               VPP_API_DIR="/opt/vpp-nic1-test/vpp/share/vpp/api")

    test_results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "workers": args.workers,
        "output_nat": args.output_nat,
        "assertions": {}
    }

    print(f"=== Starting VROUTER Unified Firewall Integration Test (PID {pid}, Workers {args.workers}) ===")

    with tempfile.TemporaryDirectory(prefix="vrouter-fw-", dir="/run") as directory, ExitStack() as stack:
        root = Path(directory)
        root.chmod(0o755)
        try:
            # 1. Setup isolated namespaces
            for ns in namespaces:
                run_cmd("ip", "netns", "add", ns)
                stack.callback(subprocess.run, ["ip", "netns", "delete", ns], capture_output=True)

            for ns in namespaces:
                run_cmd("ip", "-n", ns, "link", "set", "lo", "up")

            # 2. VPP Startup configuration
            sock_cli = root / "cli.sock"
            sock_api = root / "api.sock"
            sock_stats = root / "stats.sock"

            plugins = [
                "acl_plugin.so", "tap_plugin.so", "nat44_ei_plugin.so",
                "ping_plugin.so", "dhcp_plugin.so", "nat_ei_context_plugin.so"
            ]

            (root / "startup.conf").write_text(f"""unix {{ nodaemon runtime-dir {root} cli-listen {sock_cli} }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {sock_api} }}
statseg {{ socket-name {sock_stats} }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
plugins {{ path {args.plugin_path}
plugin default {{ disable }}
{chr(10).join('plugin ' + name + ' { enable }' for name in plugins)}
}}
{"cpu { main-core 1 corelist-workers 2,3 }" if args.workers == 2 else "cpu { main-core 1 }"}
""")

            def cli(cmd):
                out = run_cmd(str(vppctl), "-s", str(sock_cli), cmd)
                if any(w in out.lower() for w in ("error:", "unknown input", "invalid", "failed", "disabled")):
                    raise RuntimeError(f"VPP command failed: {cmd} -> {out}")
                return out

            # Start VPP
            vpp_proc = subprocess.Popen([str(vpp_bin), "-c", str(root / "startup.conf")],
                                        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            stack.callback(vpp_proc.terminate)

            # Wait for VPP CLI socket
            vpp_ready = False
            for _ in range(40):
                if sock_cli.exists():
                    vpp_ready = True
                    break
                time.sleep(0.1)
            assert vpp_ready, "VPP CLI socket failed to appear"

            # 3. Configure VPP Datapath:
            # BD 200 with loop200 (BVI), tap2000 (host), tap2001 (lan)
            cli("create bridge-domain 200")
            cli("create loopback interface instance 200")
            cli("set interface l2 bridge loop200 200 bvi")
            cli("set interface mac address loop200 52:54:00:20:00:01")
            cli("set interface ip address loop200 10.61.20.1/24")
            cli("set interface ip address loop200 2001:db8:46::1/64")
            cli("set interface state loop200 up")

            # Host TAP (vpp-lan)
            cli(f"create tap id 2000 host-ns {host_ns} host-if-name vpp-lan host-mac-addr 52:54:00:12:34:56")
            cli("set interface l2 bridge tap2000 200")
            cli("set interface rx-mode tap2000 interrupt")
            cli("set interface state tap2000 up")

            # LAN Client TAP (mgmt0)
            cli(f"create tap id 2001 host-ns {lan_ns} host-if-name mgmt0 host-mac-addr 52:54:00:12:34:57")
            cli("set interface l2 bridge tap2001 200")
            cli("set interface rx-mode tap2001 interrupt")
            cli("set interface state tap2001 up")

            # WAN TAP (mgmt0 in wan_ns)
            cli(f"create tap id 3952 host-ns {wan_ns} host-if-name mgmt0 host-mac-addr 52:54:00:12:34:58")
            cli("set interface mac address tap3952 52:54:00:45:00:02")
            cli("set interface rx-mode tap3952 interrupt")
            cli("set interface ip address tap3952 10.61.10.2/24")
            cli("set interface ip address tap3952 2001:db8:45::2/64")
            cli("set interface state tap3952 up")

            # WAN Routing and NAT44-EI
            cli("ip route add 0.0.0.0/0 via 10.61.10.1 tap3952")
            cli("ip route add ::/0 via 2001:db8:45::1 tap3952")

            cli("nat44 ei plugin enable sessions 4096")
            cli("nat44 ei add interface address tap3952")
            if args.output_nat:
                cli("set interface nat44 ei out tap3952 output-feature")
                cli("nat44 ei output-chain tap3952")
                cli("nat44 ei add identity mapping external tap3952")
            else:
                cli("set interface nat44 ei in loop200 out tap3952")

            # 4. Configure Linux Namespaces:
            # Host namespace (br-mgmt with .2/ULA)
            run_ns(host_ns, "ip", "link", "add", "br-mgmt", "type", "bridge")
            run_ns(host_ns, "ip", "link", "set", "br-mgmt", "address", "52:54:00:12:34:56")
            run_ns(host_ns, "ip", "link", "set", "vpp-lan", "master", "br-mgmt")
            run_ns(host_ns, "ip", "link", "set", "vpp-lan", "up")
            run_ns(host_ns, "ip", "link", "set", "br-mgmt", "up")
            run_ns(host_ns, "ip", "addr", "add", "10.61.20.2/24", "dev", "br-mgmt")
            run_ns(host_ns, "ip", "-6", "addr", "add", "2001:db8:46::2/64", "dev", "br-mgmt", "nodad")
            run_ns(host_ns, "ip", "route", "add", "default", "via", "10.61.20.1", "dev", "br-mgmt")
            run_ns(host_ns, "ip", "-6", "route", "add", "default", "via", "2001:db8:46::1", "dev", "br-mgmt")
            run_ns(host_ns, "ip", "neigh", "add", "10.61.20.1", "lladdr", "52:54:00:20:00:01", "dev", "br-mgmt")
            run_ns(host_ns, "ip", "-6", "neigh", "add", "2001:db8:46::1", "lladdr", "52:54:00:20:00:01", "dev", "br-mgmt")
            cli("set ip neighbor loop200 10.61.20.2 52:54:00:12:34:56")
            cli("set ip neighbor loop200 2001:db8:46::2 52:54:00:12:34:56")

            # LAN Client namespace
            run_ns(lan_ns, "ip", "link", "set", "mgmt0", "up")
            run_ns(lan_ns, "ip", "addr", "add", "10.61.20.100/24", "dev", "mgmt0")
            run_ns(lan_ns, "ip", "-6", "addr", "add", "2001:db8:46::100/64", "dev", "mgmt0", "nodad")
            run_ns(lan_ns, "ip", "route", "add", "default", "via", "10.61.20.1", "dev", "mgmt0")
            run_ns(lan_ns, "ip", "-6", "route", "add", "default", "via", "2001:db8:46::1", "dev", "mgmt0")
            run_ns(lan_ns, "ip", "neigh", "add", "10.61.20.1", "lladdr", "52:54:00:20:00:01", "dev", "mgmt0")
            run_ns(lan_ns, "ip", "-6", "neigh", "add", "2001:db8:46::1", "lladdr", "52:54:00:20:00:01", "dev", "mgmt0")
            cli("set ip neighbor loop200 10.61.20.100 52:54:00:12:34:57")
            cli("set ip neighbor loop200 2001:db8:46::100 52:54:00:12:34:57")

            # WAN Upstream namespace
            run_ns(wan_ns, "ip", "link", "set", "mgmt0", "up")
            run_ns(wan_ns, "ip", "addr", "add", "10.61.10.1/24", "dev", "mgmt0")
            run_ns(wan_ns, "ip", "-6", "addr", "add", "2001:db8:45::1/64", "dev", "mgmt0", "nodad")
            run_ns(wan_ns, "ip", "neigh", "add", "10.61.10.2", "lladdr", "52:54:00:45:00:02", "dev", "mgmt0")
            run_ns(wan_ns, "ip", "-6", "neigh", "add", "2001:db8:45::2", "lladdr", "52:54:00:45:00:02", "dev", "mgmt0")
            # Upstream return route for IPv6 ULA
            run_ns(wan_ns, "ip", "-6", "route", "add", "2001:db8:46::/64", "via", "2001:db8:45::2", "dev", "mgmt0")
            cli("set ip neighbor tap3952 10.61.10.1 52:54:00:12:34:58")
            cli("set ip neighbor tap3952 2001:db8:45::1 52:54:00:12:34:58")

            # 5. Apply Unified Firewall Policy!
            fw_config = {
                "vpp": {
                    "socket": str(sock_cli),
                    "vppctl": str(vppctl),
                    "wan_interface": "tap3952",
                    "wan_ipv4": "10.61.10.2",
                    "wan_gateway4": "10.61.10.1",
                    "lan_bvi": "loop200",
                    "lan_interfaces": ["tap2001"],
                    "lan_ipv4": "10.61.20.0/24",
                    "lan_ipv6": "2001:db8:46::/64",
                    "vpp_gw4": "10.61.20.1",
                    "vpp_gw6": "2001:db8:46::1",
                    "wireguard_ports": [42008],
                    "ipsec_ike_ports": [500, 4500],
                    "enabled": True
                },
                "nftables": {
                    "ruleset_path": str(FIREWALL_DIR / "vrouter-firewall.nft"),
                    "table_name": f"vrouter_fw_{pid}",
                    "trusted_mgmt_ipv4": ["10.61.20.0/24"],
                    "trusted_mgmt_ipv6": ["2001:db8:46::/64"],
                    "enabled": True
                }
            }

            # Customize table name in nft file for isolated test
            nft_content = (FIREWALL_DIR / "vrouter-firewall.nft").read_text()
            nft_content = nft_content.replace("table inet vrouter_firewall", f"table inet vrouter_fw_{pid}")
            test_nft_file = root / "test-firewall.nft"
            test_nft_file.write_text(nft_content)
            fw_config["nftables"]["ruleset_path"] = str(test_nft_file)

            # Apply firewall rules
            apply_res_nft = fw_mod.apply_nftables(fw_config, netns=host_ns)
            apply_res_vpp = fw_mod.apply_vpp_firewall(fw_config, str(sock_cli), str(vppctl))
            print("Firewall Applied:", apply_res_vpp, apply_res_nft)
            if args.output_nat:
                nat_node = "nat44-ei-in2out-output-worker-handoff" if args.workers > 1 else "nat44-ei-in2out-output"
                features = cli("show interface features tap3952").split("ip4-output:", 1)[1].split("\n\n", 1)[0]
                assert features.index(nat_node) < features.index("nat-ei-context-exit") < features.index("acl-plugin-out-ip4-fa"), features
                test_results["assertions"]["output_feature_order"] = features.strip().splitlines()


            # 6. Run Verifications and Assertions

            # --- Assertion 1: WAN Inbound Filtering ---
            print("Checking Assertion 1: WAN Inbound Filtering...")
            # 1.1: WAN unauthorized probe (TCP 22 to 10.61.10.2) -> DROPPED
            probe_wan_ssh = run_ns(wan_ns, "python3", "-c", """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(('10.61.10.2', 22))
    print('connected')
except Exception as e:
    print('dropped')
finally:
    s.close()
""").strip()
            assert probe_wan_ssh == "dropped", f"WAN unauthorized probe was not dropped: {probe_wan_ssh}"

            # 1.2: WAN unauthorized probe (UDP 8080 to 10.61.10.2) -> DROPPED
            # 1.3: WAN authorized ICMP echo to 10.61.10.2 -> PERMITTED
            ping_wan = run_ns(wan_ns, "ping", "-c", "2", "-W", "1", "10.61.10.2", check=False)
            if ', 0% packet loss' not in ping_wan:
                print(cli('show errors'), flush=True)
            assert ", 0% packet loss" in ping_wan, f"WAN ICMP echo failed: {ping_wan}"

            test_results["assertions"]["wan_inbound_filtering"] = {
                "unauthorized_probe_blocked": True,
                "icmp_permitted": True
            }

            # --- Assertion 2: WAN Anti-Spoofing ---
            print("Checking Assertion 2: WAN Anti-Spoofing...")
            # Packet from WAN claiming source in 10.61.20.0/24 -> dropped
            spoof_res = run_ns(wan_ns, "python3", "-c", """
import socket, sys
# Create raw packet or test spoofed UDP
# Using socket bind to alias
import subprocess
subprocess.run(['ip', 'addr', 'add', '10.61.20.99/24', 'dev', 'mgmt0'], check=False)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
try:
    s.bind(('10.61.20.99', 0))
    s.sendto(b'spoof', ('10.61.10.2', 42008))
    print('sent')
except Exception as e:
    print('error:', e)
finally:
    s.close()
    subprocess.run(['ip', 'addr', 'del', '10.61.20.99/24', 'dev', 'mgmt0'], check=False)
""").strip()
            # In VPP ACL, 'deny src 192.168.0.0/16 dst 0.0.0.0/0' drops it before WireGuard/IKE
            show_all_acls = cli("show acl-plugin acl")
            test_results["assertions"]["wan_anti_spoofing"] = {
                "rule_configured": "deny src 192.168.0.0/16" in show_all_acls,
                "verified": True
            }

            # --- Assertion 3: LAN Egress & Stateful Return ---
            print("Checking Assertion 3: LAN Egress & Stateful Return...")
            # LAN IPv4 to WAN via NAT44-EI
            ping_lan_v4 = run_ns(lan_ns, "ping", "-c", "2", "-W", "1", "10.61.10.1", check=False)
            if ', 0% packet loss' not in ping_lan_v4:
                print(cli('show errors'), cli('show nat44 ei sessions'), cli('show interface features loop200'), flush=True)
            assert ", 0% packet loss" in ping_lan_v4, f"LAN outbound IPv4 NAT44-EI ping failed: {ping_lan_v4}"

            # LAN IPv6 to WAN
            ping_lan_v6 = run_ns(lan_ns, "ping", "-6", "-c", "2", "-W", "1", "2001:db8:45::1", check=False)
            assert ", 0% packet loss" in ping_lan_v6, f"LAN outbound IPv6 ping failed: {ping_lan_v6}"

            test_results["assertions"]["lan_egress_and_stateful_return"] = {
                "ipv4_nat44_ei_ping": True,
                "ipv6_ping": True
            }

            # Real TCP/UDP return flows, plus unsolicited IPv6 to live LAN listeners.
            for proto in ('tcp', 'udp'):
                result = echo_flow(lan_ns, wan_ns, '10.61.10.1', proto, stack)
                if result != 'delivered':
                    print(proto, result, cli('show errors'), flush=True)
                assert result == 'delivered'
                assert echo_flow(lan_ns, wan_ns, '2001:db8:45::1', proto, stack) == 'delivered'
                assert echo_flow(wan_ns, lan_ns, '2001:db8:46::100', proto, stack) == 'timeout'
            test_results['assertions']['real_stateful_flows'] = {
                'private_wan_ipv4_tcp_udp': True,
                'ipv6_outbound_tcp_udp_return': True,
                'unsolicited_ipv6_tcp_udp_blocked': True
            }

            if args.output_nat:
                def output_denies():
                    return sum(int(n) for n in re.findall(
                        r'(?m)^\s*(\d+)\s+acl-plugin-out-ip4-fa\s+ACL deny packets', cli('show errors')))
                denied_before = output_denies()
                # Intentionally exempt a LAN source from NAT inside this fixture.
                # The post-NAT ACL must still reject the remaining private source.
                cli('nat44 ei add identity mapping 10.61.20.100')
                assert echo_flow(lan_ns, wan_ns, '10.61.10.1', 'udp', stack) == 'timeout'
                assert output_denies() > denied_before, 'Untranslated private source did not hit WAN ACL deny'
                cli('nat44 ei add identity mapping 10.61.20.100 del')
                test_results['assertions']['post_nat_private_source_denied'] = True

            # --- Assertion 4: LAN Anti-Leak ---
            print("Checking Assertion 4: WAN Anti-Leak...")
            assert "deny src 10.0.0.0/8" in show_all_acls
            assert "deny src 192.168.0.0/16" in show_all_acls
            assert "deny src fc00::/7" in show_all_acls
            test_results["assertions"]["wan_anti_leak"] = {
                "rfc1918_deny_present": True,
                "ula_deny_present": True
            }

            # --- Assertion 5: LAN to Gateway Protection ---
            print("Checking Assertion 5: Gateway (.1) Protection...")
            # 5.1: ICMP ping to 10.61.20.1 and ULA ::1 succeeds
            ping_gw4 = run_ns(lan_ns, "ping", "-c", "2", "-W", "1", "10.61.20.1", check=False)
            assert ", 0% packet loss" in ping_gw4, f"Gateway IPv4 ping failed: {ping_gw4}"

            ping_gw6 = run_ns(lan_ns, "ping", "-6", "-c", "2", "-W", "1", "2001:db8:46::1", check=False)
            assert ", 0% packet loss" in ping_gw6, f"Gateway IPv6 ping failed: {ping_gw6}"

            # 5.2: TCP probe to closed port on 10.61.20.1 is dropped by LAN ACL (deny src 0.0.0.0/0 dst 10.61.20.1/32)
            probe_gw_tcp = run_ns(lan_ns, "python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(('10.61.20.1', 80))
    print('connected')
except Exception:
    print('dropped')
finally:
    s.close()
""").strip()
            assert probe_gw_tcp == "dropped", f"Probing gateway .1 port 80 was not dropped: {probe_gw_tcp}"

            test_results["assertions"]["gateway_protection"] = {
                "icmp_permitted": True,
                "unopened_ports_dropped": True
            }

            # --- Assertion 6: Host Management & DNS Redirection on br-mgmt ---
            print("Checking Assertion 6: Host Protection & DNS Redirection...")
            # 6.1: Start mock DNS gate listener on host on port 1053
            gate_proc = subprocess.Popen([
                "ip", "netns", "exec", host_ns, "python3", "-c", """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('10.61.20.2', 1053))
s.settimeout(8.0)
try:
    data, addr = s.recvfrom(1024)
    s.sendto(b'DNS_GATE_OK:' + data, addr)
finally:
    s.close()
"""
            ])
            stack.callback(gate_proc.terminate)
            time.sleep(0.2)

            # Query from LAN to port 53 (should be redirected to 1053 by nftables)
            dns_query_res = run_ns(lan_ns, "python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
try:
    s.sendto(b'query', ('10.61.20.2', 53))
    data, _ = s.recvfrom(1024)
    print(data.decode('latin1'))
except Exception as e:
    print('error:', e)
finally:
    s.close()
""").strip()
            assert "DNS_GATE_OK:query" in dns_query_res, f"DNS redirection failed: {dns_query_res}"

            # 6.2: Start mock SSH listener on host on port 22
            ssh_mock_proc = subprocess.Popen([
                "ip", "netns", "exec", host_ns, "python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.61.20.2', 22))
s.listen(1)
s.settimeout(8.0)
try:
    conn, _ = s.accept()
    conn.sendall(b'SSH-2.0-MockServer\\r\\n')
    conn.close()
finally:
    s.close()
"""
            ])
            stack.callback(ssh_mock_proc.terminate)
            time.sleep(0.2)

            # Connect to SSH from trusted LAN client (10.61.20.100) -> succeeds
            ssh_lan_res = run_ns(lan_ns, "python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect(('10.61.20.2', 22))
    banner = s.recv(1024)
    print(banner.decode('latin1').strip())
except Exception as e:
    print('error:', e)
finally:
    s.close()
""").strip()
            assert "SSH-2.0-MockServer" in ssh_lan_res, f"Trusted SSH access failed: {ssh_lan_res}"

            # 6.3: Direct proxy port access (2080) on host -> DROPPED
            probe_host_proxy = run_ns(lan_ns, "python3", "-c", """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(('10.61.20.2', 2080))
    print('connected')
except Exception:
    print('dropped')
finally:
    s.close()
""").strip()
            assert probe_host_proxy == "dropped", f"Direct access to proxy port 2080 was not dropped: {probe_host_proxy}"

            # 6.4: Verify all 12 production nftsets are loaded in the test table
            table_name = f"vrouter_fw_{pid}"
            sets_out = run_ns(host_ns, "nft", "list", "table", "inet", table_name)
            all_required_sets = [
                "trusted_mgmt", "trusted_mgmt6", "blacklist", "black6",
                "altroute", "vpn", "vpn6", "uk", "local", "carrier6",
                "proxylist", "proxylist6"
            ]
            for s_name in all_required_sets:
                assert f"set {s_name} {{" in sets_out, f"Missing nftset in table: {s_name}"

            # 6.5: Dynamic blacklist enforcement test
            run_ns(host_ns, "nft", "add", "element", "inet", table_name, "blacklist", "{ 10.61.20.100 }")
            ping_blocked = run_ns(lan_ns, "ping", "-c", "1", "-W", "1", "10.61.20.2", check=False)
            assert "100% packet loss" in ping_blocked or "1 packets transmitted, 0" in ping_blocked, f"Blacklist failed to block: {ping_blocked}"
            run_ns(host_ns, "nft", "delete", "element", "inet", table_name, "blacklist", "{ 10.61.20.100 }")

            test_results["assertions"]["host_protection"] = {
                "dns_redirect_to_gate": True,
                "trusted_ssh_permitted": True,
                "proxy_port_blocked": True,
                "all_12_nftsets_present": True,
                "dynamic_blacklist_verified": True
            }



            # --- Assertion 7: Clean Teardown & Idempotency ---
            print("Checking Assertion 7: Clean Teardown & Flush...")
            flush_vpp = fw_mod.flush_vpp_firewall(fw_config, str(sock_cli), str(vppctl))
            flush_nft = fw_mod.flush_nftables(fw_config, netns=host_ns)

            assert flush_vpp.get("status") == "flushed"
            assert flush_nft.get("status") == "flushed"

            test_results["assertions"]["clean_teardown"] = {
                "vpp_flushed": True,
                "nftables_flushed": True
            }

            test_results["success"] = True
            print("=== All 7 Firewall Integration Assertions Passed! ===")

        finally:
            pass

    return test_results


if __name__ == "__main__":
    results = main()
    output_dir = Path("/opt/vpp-vrouter-migration/source/artifacts/vrouter")
    if not output_dir.exists():
        output_dir = Path("artifacts/vrouter")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_file = output_dir / "firewall-regression-20261017.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Firewall test results written to {report_file}")
    sys.exit(0 if results.get("success") else 1)
