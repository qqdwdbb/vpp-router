#!/usr/bin/env python3
"""Linux network preparation service for VROUTER VPP gateway.

Configures Linux host networking to pair with VPP:
- Attaches the shared LAN TAP (e.g. vpp-lan) to the management bridge (br-mgmt).
- Assigns 10.61.20.2/24 and ULA fd42:1111:2222:10::2/64 to br-mgmt.
- Establishes default routes to VPP (10.61.20.1 and ULA ::1).
- Sets static neighbor entries on host and VPP to prevent ARP/ND desync.
- Optionally loads DNS nftables sets.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def run_cmd(*args, check=True):
    p = subprocess.run(args, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(args)}): {p.stderr.strip()}")
    return p.stdout


def get_interface_mac(ifname, netns=None):
    cmd = ['ip']
    if netns:
        cmd += ['-n', netns]
    cmd += ['-j', 'link', 'show', ifname]
    try:
        out = run_cmd(*cmd, check=True)
        data = json.loads(out)
        if data and 'address' in data[0]:
            return data[0]['address']
    except Exception:
        pass
    return None


def get_vpp_mac(socket_path, ifname, vppctl_path='/usr/local/bin/vppctl'):
    try:
        out = run_cmd(vppctl_path, '-s', socket_path, f'show hardware-interfaces {ifname}', check=False)
        m = re.search(r'Ethernet address ([0-9a-f:]{17})', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def configure_network(config):
    bridge = config.get('bridge', 'br-mgmt')
    lan_tap = config.get('lan_tap', 'vpp-lan')
    lan_ip = config.get('lan_ip', '10.61.20.2/24')
    lan_ula = config.get('lan_ula', 'fd42:1111:2222:10::2/64')
    vpp_gw = config.get('vpp_gw', '10.61.20.1')
    vpp_ula_gw = config.get('vpp_ula_gw', 'fd42:1111:2222:10::1')
    vpp_socket = config.get('vpp_socket', '/run/vpp/cli.sock')
    vppctl = config.get('vppctl', '/usr/local/bin/vppctl')
    vpp_bvi = config.get('vpp_bvi', 'loop200')
    nftsets_path = config.get('nftsets_path', '/etc/vpp/dns-nftsets.nft')
    netns = config.get('netns')

    prefix = ['ip']
    if netns:
        prefix += ['-n', netns]

    # Fail before any mutation if VPP has not created the shared TAP.
    p_tap = subprocess.run(prefix + ['link', 'show', lan_tap], capture_output=True)
    if p_tap.returncode != 0:
        raise RuntimeError(f"Required LAN TAP is missing: {lan_tap}")

    # 1. Ensure bridge exists
    p = subprocess.run(prefix + ['link', 'show', bridge], capture_output=True)
    if p.returncode != 0:
        run_cmd(*(prefix + ['link', 'add', bridge, 'type', 'bridge']))

    tap_mac = get_interface_mac(lan_tap, netns)
    if tap_mac:
        run_cmd(*(prefix + ['link', 'set', bridge, 'address', tap_mac]), check=False)

    # 2. Attach TAP to bridge and bring UP
    run_cmd(*(prefix + ['link', 'set', lan_tap, 'master', bridge]))
    run_cmd(*(prefix + ['link', 'set', lan_tap, 'up']))

    run_cmd(*(prefix + ['link', 'set', bridge, 'up']))

    # 3. Configure IP addresses on bridge
    if lan_ip:
        run_cmd(*(prefix + ['addr', 'replace', lan_ip, 'dev', bridge]))
    if lan_ula:
        run_cmd(*(prefix + ['-6', 'addr', 'replace', lan_ula, 'dev', bridge, 'nodad']))

    # 4. Configure default routes
    if vpp_gw:
        run_cmd(*(prefix + ['route', 'replace', 'default', 'via', vpp_gw, 'dev', bridge]))
    if vpp_ula_gw:
        run_cmd(*(prefix + ['-6', 'route', 'replace', 'default', 'via', vpp_ula_gw, 'dev', bridge]))

    # 5. Static neighbor alignment
    if vpp_gw and Path(vpp_socket).exists():
        bvi_mac = get_vpp_mac(vpp_socket, vpp_bvi, vppctl)
        if bvi_mac:
            run_cmd(*(prefix + ['neigh', 'replace', vpp_gw, 'lladdr', bvi_mac, 'nud', 'permanent', 'dev', bridge]), check=False)
            if vpp_ula_gw:
                run_cmd(*(prefix + ['-6', 'neigh', 'replace', vpp_ula_gw, 'lladdr', bvi_mac, 'nud', 'permanent', 'dev', bridge]), check=False)

        # Also set Linux bridge MAC on VPP TAP/neighbor
        host_mac = get_interface_mac(bridge, netns)
        if host_mac and lan_ip:
            host_ip = lan_ip.split('/')[0]
            try:
                run_cmd(vppctl, '-s', vpp_socket, f'set ip neighbor {vpp_bvi} {host_ip} {host_mac}', check=False)
            except Exception:
                pass

    # 6. Load nftables sets if present
    if nftsets_path and Path(nftsets_path).exists():
        nft_cmd = ['nft', '-f', str(nftsets_path)]
        if netns:
            nft_cmd = ['ip', 'netns', 'exec', netns] + nft_cmd
        run_cmd(*nft_cmd, check=False)

    return True


def deconfigure_network(config):
    bridge = config.get('bridge', 'br-mgmt')
    lan_tap = config.get('lan_tap', 'vpp-lan')
    netns = config.get('netns')
    prefix = ['ip']
    if netns:
        prefix += ['-n', netns]

    # Remove TAP from bridge
    p_tap = subprocess.run(prefix + ['link', 'show', lan_tap], capture_output=True)
    if p_tap.returncode == 0:
        run_cmd(*(prefix + ['link', 'set', lan_tap, 'nomaster']), check=False)
    return True


def check_status(config):
    bridge = config.get('bridge', 'br-mgmt')
    lan_tap = config.get('lan_tap', 'vpp-lan')
    lan_ip = config.get('lan_ip', '10.61.20.2/24')
    netns = config.get('netns')
    prefix = ['ip']
    if netns:
        prefix += ['-n', netns]

    p_br = subprocess.run(prefix + ['link', 'show', bridge], capture_output=True, text=True)
    if p_br.returncode != 0 or 'UP' not in p_br.stdout:
        return False
    if lan_ip:
        p_addr = subprocess.run(prefix + ['addr', 'show', 'dev', bridge], capture_output=True, text=True)
        if lan_ip.split('/')[0] not in p_addr.stdout:
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description='VROUTER Linux Network Prep for VPP')
    parser.add_argument('--action', choices=['start', 'stop', 'status'], default='start')
    parser.add_argument('--config', default=None, help='Path to JSON configuration file')
    parser.add_argument('--bridge', default='br-mgmt', help='Linux bridge interface name')
    parser.add_argument('--lan-tap', default='vpp-lan', help='Linux LAN TAP interface name')
    parser.add_argument('--lan-ip', default='10.61.20.2/24', help='Linux LAN IPv4 address/mask')
    parser.add_argument('--lan-ula', default='fd42:1111:2222:10::2/64', help='Linux LAN ULA address/mask')
    parser.add_argument('--vpp-gw', default='10.61.20.1', help='VPP LAN IPv4 gateway')
    parser.add_argument('--vpp-ula-gw', default='fd42:1111:2222:10::1', help='VPP LAN ULA gateway')
    parser.add_argument('--vpp-socket', default='/run/vpp/cli.sock', help='VPP CLI socket')
    parser.add_argument('--vpp-bvi', default='loop200', help='VPP BVI interface name')
    parser.add_argument('--nftsets', default='/etc/vpp/dns-nftsets.nft', help='Path to dns-nftsets.nft')
    parser.add_argument('--netns', default=None, help='Optional network namespace for isolated testing')
    args = parser.parse_args()

    config = {
        'bridge': args.bridge,
        'lan_tap': args.lan_tap,
        'lan_ip': args.lan_ip,
        'lan_ula': args.lan_ula,
        'vpp_gw': args.vpp_gw,
        'vpp_ula_gw': args.vpp_ula_gw,
        'vpp_socket': args.vpp_socket,
        'vpp_bvi': args.vpp_bvi,
        'nftsets_path': args.nftsets,
        'netns': args.netns
    }

    if args.config:
        try:
            loaded = json.loads(Path(args.config).read_text())
            if not isinstance(loaded, dict):
                raise ValueError("configuration must be a JSON object")
            config.update(loaded)
        except (OSError, ValueError) as e:
            print(f"Failed to load network configuration: {type(e).__name__}", file=sys.stderr)
            sys.exit(1)

    if args.action == 'start':
        configure_network(config)
        print("Network preparation completed successfully.")
        sys.exit(0)
    elif args.action == 'stop':
        deconfigure_network(config)
        print("Network deconfiguration completed.")
        sys.exit(0)
    elif args.action == 'status':
        if check_status(config):
            print("Network preparation active and healthy.")
            sys.exit(0)
        else:
            print("Network preparation inactive or incomplete.", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
