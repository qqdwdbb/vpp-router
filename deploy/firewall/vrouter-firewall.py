#!/usr/bin/env python3
"""Unified Firewall Policy Manager for VROUTER VPP Gateway.

Orchestrates the dual-layer firewall policy:
1. VPP Datapath Security (VPP ACLs):
   - WAN Ingress: Drops unsolicited probes, blocks spoofed RFC1918/ULA sources,
     permits IKE (UDP 500/4500), WireGuard (UDP 42008), DHCPv6 (UDP 546),
     and ICMP/ICMPv6 essential control traffic.
   - WAN Egress: Prevents cleartext RFC1918 leaks to the public WAN.
   - LAN Ingress (bridge member ports): Enforces source address validation (BCP 38),
     protects the gateway (.1) from port scans, and permits legitimate forwarding.
2. Linux Host Control Plane Security (nftables):
   - Protects host services on br-mgmt (.2), loopback, and control TAPs.
   - Enforces DNS Gate redirection (port 53 -> 1053) and fail-closed anti-bypass.
   - Restricts SSH (port 22) strictly to trusted management subnets.
   - Blocks direct unauthorized access to internal transparent proxy ports.
"""
import argparse
import json
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys


DEFAULT_CONFIG = {
    "vpp": {
        "socket": "/run/vpp/cli.sock",
        "vppctl": "/usr/local/bin/vppctl",
        "wan_interface": "nic1",
        "wan_ipv4": "10.61.10.2",
        "wan_gateway4": "10.61.10.1",
        "lan_bvi": "loop200",
        "lan_interfaces": [],
        "lan_ipv4": "10.61.20.0/24",
        "lan_ipv6": "fd42:1111:2222:10::/64",
        "vpp_gw4": "10.61.20.1",
        "vpp_gw6": "fd42:1111:2222:10::1",
        "wireguard_ports": [42008, 42007, 42006],
        "ipsec_ike_ports": [500, 4500],
        "enabled": True
    },
    "nftables": {
        "ruleset_path": str(Path(__file__).parent / "vrouter-firewall.nft"),
        "table_name": "vrouter_firewall",
        "trusted_mgmt_ipv4": ["10.61.20.0/24"],
        "trusted_mgmt_ipv6": ["fd42:1111:2222:10::/64"],
        "enabled": True
    }
}


def run_cmd(*args, check=True, netns=None):
    cmd = list(args)
    if netns:
        cmd = ["ip", "netns", "exec", netns] + cmd
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {p.stderr.strip()}")
    return p.stdout


def vpp_cli(socket_path, command, vppctl="/usr/local/bin/vppctl"):
    out = run_cmd(vppctl, "-s", socket_path, command, check=True)
    if any(w in out.lower() for w in ("error:", "unknown input", "invalid")):
        raise RuntimeError(f"VPP command failed: {command} -> {out}")
    return out


def generate_vpp_acls(config):
    """Generate VPP ACL command strings according to security policy."""
    vpp_cfg = config.get("vpp", {})
    lan4 = vpp_cfg.get("lan_ipv4", "10.61.20.0/24")
    lan6 = vpp_cfg.get("lan_ipv6", "fd42:1111:2222:10::/64")
    lan6_prefixes = [lan6] if isinstance(lan6, str) else lan6
    lan6_prefixes = [str(ipaddress.IPv6Network(prefix)) for prefix in lan6_prefixes]
    gw4 = vpp_cfg.get("vpp_gw4", "10.61.20.1")
    gw6 = vpp_cfg.get("vpp_gw6", "fd42:1111:2222:10::1")
    wg_ports = vpp_cfg.get("wireguard_ports", [42008])
    ike_ports = vpp_cfg.get("ipsec_ike_ports", [500, 4500])
    blocked_lan_tcp_destinations = vpp_cfg.get("blocked_lan_tcp_destinations", [])
    if isinstance(blocked_lan_tcp_destinations, str):
        blocked_lan_tcp_destinations = [blocked_lan_tcp_destinations]
    blocked_lan_tcp_destinations = [
        str(ipaddress.IPv4Network(prefix, strict=False))
        for prefix in blocked_lan_tcp_destinations
    ]
    wan_host_tcp_sources = vpp_cfg.get('wan_host_tcp_sources', {})
    if not isinstance(wan_host_tcp_sources, dict):
        raise ValueError('wan_host_tcp_sources must be an object keyed by TCP port')

    def source_prefixes(port):
        values = wan_host_tcp_sources.get(str(port), [])
        if not isinstance(values, list) or not values:
            return []
        prefixes = []
        for value in values:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != 4:
                raise ValueError('wan_host_tcp_sources must contain IPv4 networks')
            prefixes.append(str(network))
        return prefixes

    # Use exact host exceptions, never exempt the whole private WAN subnet.
    wan4 = ipaddress.IPv4Address(vpp_cfg.get("wan_ipv4", "10.61.10.2"))
    gateway4 = ipaddress.IPv4Address(vpp_cfg.get("wan_gateway4", "10.61.10.1"))

    # 1. WAN Ingress ACL
    # - Anti-spoofing: Drop RFC1918 / ULA / Multicast entering from WAN
    # - Allow IKE (UDP 500, 4500)
    # - Allow WireGuard (UDP 42008)
    # - Allow DHCPv6 client responses (UDP sport 547 dport 546)
    # - Allow ICMP (proto 1) and ICMPv6 (proto 58) essential control traffic
    # - Drop all other unsolicited inbound
    wan_in_rules = []
    # Link-local control traffic must precede link-local anti-spoofing.
    wan_in_rules.append("permit src fe80::/10 dst ::/0 proto 58")
    wan_in_rules.append("permit src fe80::/10 dst ::/0 proto 17 sport 547 dport 546")
    wan_in_rules.append(f"permit src {gateway4}/32 dst {wan4}/32 proto 1")
    # Anti-spoofing drops
    wan_in_rules.append("deny src 10.0.0.0/8 dst 0.0.0.0/0")
    wan_in_rules.append("deny src 172.16.0.0/12 dst 0.0.0.0/0")
    wan_in_rules.append("deny src 192.168.0.0/16 dst 0.0.0.0/0")
    wan_in_rules.append("deny src 127.0.0.0/8 dst 0.0.0.0/0")
    wan_in_rules.append("deny src 224.0.0.0/4 dst 0.0.0.0/0")
    wan_in_rules.append("deny src fc00::/7 dst ::/0")
    wan_in_rules.append("deny src fe80::/10 dst ::/0")

    # Permitted incoming services
    for port in ike_ports:
        wan_in_rules.append(f"permit src 0.0.0.0/0 dst 0.0.0.0/0 proto 17 sport 0-65535 dport {port}")
        wan_in_rules.append(f"permit src ::/0 dst ::/0 proto 17 sport 0-65535 dport {port}")

    for port in wg_ports:
        wan_in_rules.append(f"permit src 0.0.0.0/0 dst 0.0.0.0/0 proto 17 sport 0-65535 dport {port}")
        wan_in_rules.append(f"permit src ::/0 dst ::/0 proto 17 sport 0-65535 dport {port}")

    for port in vpp_cfg.get('wan_host_tcp_ports', []):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('wan_host_tcp_ports must contain valid TCP ports')
        sources = source_prefixes(port)
        if sources:
            for source in sources:
                wan_in_rules.append(f"permit src {source} dst {wan4}/32 proto 6 dport {port}")
            # Keep the later host-service-path exception from reopening this
            # port for sources outside its explicit allow-list.
            wan_in_rules.append(f"deny src 0.0.0.0/0 dst {wan4}/32 proto 6 dport {port}")
        else:
            wan_in_rules.append(f"permit src 0.0.0.0/0 dst {wan4}/32 proto 6 dport {port}")

    host_path = vpp_cfg.get('host_service_path', False)
    if host_path:
        # Admission is enforced on the dedicated Linux service TAP. This does
        # not permit forwarding to arbitrary LAN destinations.
        for proto in (6, 17):
            wan_in_rules.append(f"permit src 0.0.0.0/0 dst {wan4}/32 proto {proto}")

    # DHCPv6 client responses from upstream
    wan_in_rules.append("permit src ::/0 dst ::/0 proto 17 sport 547 dport 546")

    # ICMPv4 (proto 1) and ICMPv6 (proto 58)
    wan_in_rules.append("permit src 0.0.0.0/0 dst 0.0.0.0/0 proto 1")
    wan_in_rules.append("permit src ::/0 dst ::/0 proto 58")

    # Return traffic is admitted by sessions created on WAN output.
    # Reflect on WAN input would also admit unsolicited new connections.

    # Drop all other unsolicited inbound on WAN
    wan_in_rules.append("deny src 0.0.0.0/0 dst 0.0.0.0/0")
    wan_in_rules.append("deny src ::/0 dst ::/0")

    # 2. WAN Egress ACL
    # Anti-leak: Prevent cleartext RFC1918 traffic from leaking out WAN
    wan_out_rules = [f"permit+reflect src {wan4}/32 dst 0.0.0.0/0"]
    wan_out_rules.append("deny src 10.0.0.0/8 dst 0.0.0.0/0")
    wan_out_rules.append("deny src 172.16.0.0/12 dst 0.0.0.0/0")
    wan_out_rules.append("deny src 192.168.0.0/16 dst 0.0.0.0/0")
    wan_out_rules.append("deny src fc00::/7 dst ::/0")
    wan_out_rules.append("permit+reflect src 0.0.0.0/0 dst 0.0.0.0/0")
    wan_out_rules.append("permit+reflect src ::/0 dst ::/0")

    # 3. LAN Ingress ACL (attached to actual bridge member ports)
    # Anti-spoofing: only allow packets with source matching LAN prefixes
    lan_in_rules = []
    # Allow DHCP requests before lease acquisition (0.0.0.0/32 sport 68 dport 67)
    lan_in_rules.append("permit src 0.0.0.0/32 dst 255.255.255.255/32 proto 17 sport 68 dport 67")
    lan_in_rules.append("permit src 0.0.0.0/32 dst 0.0.0.0/0 proto 17 sport 68 dport 67")
    lan_in_rules.append("permit src ::/128 dst ff02::1:2/128 proto 17 sport 546 dport 547")

    # Allow ICMP echo-request to gateway
    lan_in_rules.append(f"permit src {lan4} dst {gw4}/32 proto 1")
    for prefix in lan6_prefixes:
        lan_in_rules.append(f"permit src {prefix} dst {gw6}/128 proto 58")
    lan_in_rules.append(f"permit src fe80::/10 dst fe80::/10 proto 58")

    # Explicit LAN services may be punted to the Linux control plane.
    for port in vpp_cfg.get('lan_tcp_services', []):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('lan_tcp_services must contain valid TCP ports')
        lan_in_rules.append(f"permit src {lan4} dst {gw4}/32 proto 6 dport {port}")

    # Deny direct access to unused/closed ports on gateway (.1)
    if host_path:
        for proto in (6, 17):
            lan_in_rules.append(f"permit src {lan4} dst {gw4}/32 proto {proto}")

    # Block selected LAN TCP destinations before the stateful forwarding rule.
    # This keeps the policy in the VPP ACL datapath instead of relying on the
    # Linux path used for DNS-gate DNAT.
    for prefix in blocked_lan_tcp_destinations:
        lan_in_rules.append(f"permit src {lan4} dst {prefix} proto 6 dport 53")
        lan_in_rules.append(f"deny src {lan4} dst {prefix} proto 6")

    lan_in_rules.append(f"deny src 0.0.0.0/0 dst {gw4}/32")
    lan_in_rules.append(f"deny src ::/0 dst {gw6}/128")

    # Permit legitimate forwarding for valid LAN addresses (stateful)
    lan_in_rules.append(f"permit+reflect src {lan4} dst 0.0.0.0/0")
    for prefix in lan6_prefixes:
        lan_in_rules.append(f"permit+reflect src {prefix} dst ::/0")
    lan_in_rules.append("permit+reflect src fe80::/10 dst fe80::/10")

    # Deny all spoofed sources on LAN
    lan_in_rules.append("deny src 0.0.0.0/0 dst 0.0.0.0/0")
    lan_in_rules.append("deny src ::/0 dst ::/0")

    return {
        "wan_in": ", ".join(wan_in_rules),
        "wan_out": ", ".join(wan_out_rules),
        "lan_in": ", ".join(lan_in_rules)
    }


def apply_vpp_firewall(config, vpp_socket=None, vppctl=None):
    """Apply VPP ACLs to WAN and LAN interfaces."""
    vpp_cfg = config.get("vpp", {})
    if not vpp_cfg.get("enabled", True):
        return {"status": "skipped", "reason": "vpp disabled"}

    sock = vpp_socket or vpp_cfg.get("socket", "/run/vpp/cli.sock")
    ctl = vppctl or vpp_cfg.get("vppctl", "/usr/local/bin/vppctl")
    wan_if = vpp_cfg.get("wan_interface", "nic1")
    lan_bvi = vpp_cfg.get("lan_bvi", "loop200")

    lan_interfaces = vpp_cfg.get("lan_interfaces", [])
    if not isinstance(lan_interfaces, list) or not lan_interfaces or any(
            not isinstance(name, str) or not name or name == lan_bvi or name == wan_if
            for name in lan_interfaces):
        raise ValueError("lan_interfaces must list LAN ingress ports, excluding the BVI and WAN")

    acls = generate_vpp_acls(config)

    # Reuse tagged ACLs during delegated-prefix updates. Other owners stay intact.
    existing = vpp_cli(sock, "show acl-plugin acl", ctl)
    owned = {}
    current = None
    for line in existing.splitlines():
        match = re.search(r"acl-index (\d+)", line)
        if match:
            current = int(match[1])
        for tag in ('vrouter-wan-in', 'vrouter-wan-out', 'vrouter-lan-in'):
            if current is not None and tag in line:
                owned[tag] = current
    def set_acl(tag, rules):
        index = f"index {owned[tag]} " if tag in owned else ""
        return vpp_cli(sock, f"set acl-plugin acl {index}tag {tag} {rules}", ctl)

    # 1. Create / update ACLs
    wan_in_res = set_acl("vrouter-wan-in", acls["wan_in"])
    m_win = re.search(r"ACL index:(\d+)", wan_in_res)
    if not m_win:
        raise RuntimeError(f"Failed to create wan_in ACL: {wan_in_res}")
    wan_in_idx = int(m_win.group(1))

    wan_out_res = set_acl("vrouter-wan-out", acls["wan_out"])
    m_wout = re.search(r"ACL index:(\d+)", wan_out_res)
    if not m_wout:
        raise RuntimeError(f"Failed to create wan_out ACL: {wan_out_res}")
    wan_out_idx = int(m_wout.group(1))

    lan_in_res = set_acl("vrouter-lan-in", acls["lan_in"])
    m_lin = re.search(r"ACL index:(\d+)", lan_in_res)
    if not m_lin:
        raise RuntimeError(f"Failed to create lan_in ACL: {lan_in_res}")
    lan_in_idx = int(m_lin.group(1))

    # 2. Attach ACLs to interfaces
    # WAN: input acl wan_in, output acl wan_out
    vpp_cli(sock, f"set acl-plugin interface {wan_if} input acl {wan_in_idx}", ctl)
    vpp_cli(sock, f"set acl-plugin interface {wan_if} output acl {wan_out_idx}", ctl)

    # BVI injection also receives routed return traffic: filter physical/TAP
    # LAN ingress ports instead, before they enter the bridge domain.
    for interface in lan_interfaces:
        vpp_cli(sock, f"set acl-plugin interface {interface} input acl {lan_in_idx}", ctl)

    return {
        "status": "applied",
        "wan_in_acl": wan_in_idx,
        "wan_out_acl": wan_out_idx,
        "lan_in_acl": lan_in_idx,
        "wan_interface": wan_if,
        "lan_bvi": lan_bvi,
        "lan_interfaces": lan_interfaces
    }


def flush_vpp_firewall(config, vpp_socket=None, vppctl=None):
    """Detach and delete VPP ACLs."""
    vpp_cfg = config.get("vpp", {})
    sock = vpp_socket or vpp_cfg.get("socket", "/run/vpp/cli.sock")
    ctl = vppctl or vpp_cfg.get("vppctl", "/usr/local/bin/vppctl")
    wan_if = vpp_cfg.get("wan_interface", "nic1")
    lan_bvi = vpp_cfg.get("lan_bvi", "loop200")

    if not Path(sock).exists():
        return {"status": "skipped", "reason": "vpp socket not found"}

    try:
        # Show existing ACLs
        show_acls = vpp_cli(sock, "show acl-plugin acl", ctl)
        # Detach from interfaces
        vpp_cli(sock, f"set acl-plugin interface {wan_if} input acl 0 del", ctl)
        vpp_cli(sock, f"set acl-plugin interface {wan_if} output acl 0 del", ctl)
        for interface in vpp_cfg.get("lan_interfaces", []):
            vpp_cli(sock, f"set acl-plugin interface {interface} input acl 0 del", ctl)

        # Delete ACL indices
        for idx in re.findall(r"acl-index (\d+)", show_acls):
            try:
                vpp_cli(sock, f"delete acl-plugin acl index {idx}", ctl)
            except Exception:
                pass
    except Exception as e:
        return {"status": "error", "error": str(e)}

    return {"status": "flushed"}


def apply_nftables(config, netns=None):
    """Apply Linux host nftables firewall rules."""
    nft_cfg = config.get("nftables", {})
    if not nft_cfg.get("enabled", True):
        return {"status": "skipped", "reason": "nftables disabled"}

    ruleset_path = nft_cfg.get("ruleset_path")
    if not ruleset_path or not Path(ruleset_path).exists():
        ruleset_path = str(Path(__file__).parent / "vrouter-firewall.nft")

    if not Path(ruleset_path).exists():
        raise FileNotFoundError(f"nftables ruleset file not found: {ruleset_path}")

    # Read and render ruleset
    content = Path(ruleset_path).read_text()

    # Apply via nft -f
    cmd = ["nft", "-f", "-"]
    if netns:
        cmd = ["ip", "netns", "exec", netns] + cmd

    p = subprocess.run(cmd, input=content, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"nftables apply failed: {p.stderr.strip()}")

    # Update trusted sets if specified
    table_name = nft_cfg.get("table_name", "vrouter_firewall")
    mgmt4 = nft_cfg.get("trusted_mgmt_ipv4", [])
    if mgmt4:
        for ip in mgmt4:
            run_cmd("nft", "add", "element", "inet", table_name, "trusted_mgmt", f"{{ {ip} }}",
                    check=False, netns=netns)

    mgmt6 = nft_cfg.get("trusted_mgmt_ipv6", [])
    if mgmt6:
        for ip in mgmt6:
            run_cmd("nft", "add", "element", "inet", table_name, "trusted_mgmt6", f"{{ {ip} }}",
                    check=False, netns=netns)

    return {"status": "applied", "table": table_name, "ruleset": ruleset_path}


def flush_nftables(config, netns=None):
    """Delete the dedicated nftables firewall table."""
    nft_cfg = config.get("nftables", {})
    table_name = nft_cfg.get("table_name", "vrouter_firewall")
    try:
        run_cmd("nft", "delete", "table", "inet", table_name, check=False, netns=netns)
    except Exception as e:
        return {"status": "error", "error": str(e)}
    return {"status": "flushed", "table": table_name}


def parse_args():
    parser = argparse.ArgumentParser(description="VROUTER Unified Firewall Policy Manager")
    parser.add_argument("--config", help="Path to firewall JSON configuration")
    parser.add_argument("--apply", action="store_true", help="Apply unified firewall policy (VPP + nftables)")
    parser.add_argument("--flush", action="store_true", help="Flush and remove firewall rules")
    parser.add_argument("--check", action="store_true", help="Validate configuration and check syntax")
    parser.add_argument("--status", action="store_true", help="Show active firewall status and counters")
    parser.add_argument("--vpp-socket", help="Override VPP CLI socket path")
    parser.add_argument("--vppctl", help="Override vppctl executable path")
    parser.add_argument("--netns", help="Optional Linux network namespace for testing")
    parser.add_argument("--wan-interface", help="Override WAN interface name")
    parser.add_argument("--lan-bvi", help="Override LAN BVI interface name")
    return parser.parse_args()


import copy


def load_config(path):
    if not path or not Path(path).exists():
        return copy.deepcopy(DEFAULT_CONFIG)
    try:
        with open(path) as f:
            data = json.load(f)
        cfg = copy.deepcopy(DEFAULT_CONFIG)
        if "vpp" in data:
            cfg["vpp"].update(data["vpp"])
        if "nftables" in data:
            cfg["nftables"].update(data["nftables"])
        return cfg
    except Exception as e:
        raise ValueError(f"Failed to load config {path}: {e}")



def main():
    args = parse_args()
    config = load_config(args.config)

    if args.vpp_socket:
        config["vpp"]["socket"] = args.vpp_socket
    if args.vppctl:
        config["vpp"]["vppctl"] = args.vppctl
    if args.wan_interface:
        config["vpp"]["wan_interface"] = args.wan_interface
    if args.lan_bvi:
        config["vpp"]["lan_bvi"] = args.lan_bvi

    if args.check:
        acls = generate_vpp_acls(config)
        print("VPP ACL generation successful:")
        for name, rules in acls.items():
            print(f"  {name}: {rules[:120]}...")
        nft_path = config.get("nftables", {}).get("ruleset_path")
        if nft_path and Path(nft_path).exists():
            print(f"nftables ruleset found: {nft_path}")
        else:
            print("WARNING: nftables ruleset file not found")
        sys.exit(0)

    if args.flush:
        r_vpp = flush_vpp_firewall(config, args.vpp_socket, args.vppctl)
        r_nft = flush_nftables(config, args.netns)
        print(json.dumps({"action": "flush", "vpp": r_vpp, "nftables": r_nft}, indent=2))
        sys.exit(0)

    if args.status:
        status_info = {"vpp": {}, "nftables": {}}
        sock = config["vpp"]["socket"]
        ctl = config["vpp"]["vppctl"]
        if Path(sock).exists():
            try:
                status_info["vpp"]["acls"] = vpp_cli(sock, "show acl-plugin acl", ctl)
                status_info["vpp"]["interfaces"] = vpp_cli(sock, "show acl-plugin interface", ctl)
            except Exception as e:
                status_info["vpp"]["error"] = str(e)
        else:
            status_info["vpp"]["status"] = "socket_not_found"

        try:
            tbl = config["nftables"]["table_name"]
            status_info["nftables"]["ruleset"] = run_cmd("nft", "list", "table", "inet", tbl, netns=args.netns)
        except Exception as e:
            status_info["nftables"]["error"] = str(e)

        print(json.dumps(status_info, indent=2))
        sys.exit(0)

    if args.apply:
        results = {}
        # 1. Apply Linux host nftables
        try:
            results["nftables"] = apply_nftables(config, args.netns)
        except Exception as e:
            results["nftables"] = {"status": "error", "error": str(e)}

        # 2. Apply VPP ACLs
        try:
            results["vpp"] = apply_vpp_firewall(config, args.vpp_socket, args.vppctl)
        except Exception as e:
            results["vpp"] = {"status": "error", "error": str(e)}

        print(json.dumps({"action": "apply", "results": results}, indent=2))
        if any(r.get("status") == "error" for r in results.values()):
            sys.exit(1)
        sys.exit(0)

    print("Please specify an action: --apply, --flush, --check, or --status")


if __name__ == "__main__":
    main()
