#!/usr/bin/env python3
"""Private deployment hooks. Commands deliberately do not print CLI/key material."""
import argparse
import json
import ipaddress
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import time

VPPCTL = os.environ.get('VROUTER_VPPCTL', '/usr/local/bin/vppctl')


def config_path(root, name):
    """Trial bundles and installed deployments use explicit configuration roots."""
    return Path(os.environ.get('VROUTER_CONFIG_DIRECTORY', root/'config'))/name


EAP_ULA6 = 'fd42:1111:2222:60::/64'
WG8_ULA6 = 'fd42:1111:2222:70::/64'
PD_SYNC_STATE = Path('/run/vrouter-pd-sync/state.json')
IPSEC_TAP = 'tap4061'
# Cellular IPv6 ESP-in-UDP rarely delivers outer PTB; without a cap the
# pmtu-check skips and inner TCP blackholes. 1280 is the plugin minimum.


def host_routing_module():
    spec = importlib.util.spec_from_file_location('host_routing', Path(__file__).resolve().parents[1]/'host-services/host-routing.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tproxy_path_module():
    spec = importlib.util.spec_from_file_location('tproxy_path', Path(__file__).resolve().parents[1]/'tproxy-path.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*args, timeout=45, check=True):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        err = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Command failed ({' '.join(map(str, args))}): {err}")
    return result.stdout


def cli(line):
    result = run(VPPCTL, '-s', '/run/vpp/cli.sock', line, timeout=15)
    if line.startswith('nat44 ei pool receive ') and result.strip():
        raise RuntimeError('VPP rejected pool receive assignment')
    if not line.startswith('show ') and re.search(r'unknown|error|failed|invalid|unimplemented|not found|does not exist|cannot|must be|should be|not supported', result, re.I):
        raise RuntimeError('VPP rejected deployment command')
    return result


def cli_file(path, before=None):
    for line in path.read_text().splitlines():
        if before is not None:
            before(line.strip())
        if line.strip() and not line.lstrip().startswith('#'):
            cli(line)


def reserve_host_ports(root, p):
    spec = importlib.util.spec_from_file_location('host_path', Path(__file__).resolve().parents[1]/'host-services/host-path.py')
    host_path = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host_path)
    config = json.loads((config_path(root, 'host-services.json')).read_text())
    mappings = host_path.static_mappings(config, p['wan_identity_udp_ports']+[42001])
    commands = ['nat44 ei add static mapping local 10.64.20.14 42008 external 10.61.10.2 42001 udp']
    commands += host_path.mapping_commands(config, mappings)
    path = root/'host-fixed-mappings.vpp'
    path.write_text('\n'.join(commands)+'\n')
    path.chmod(0o600)
    # One CLI batch: do not spawn vppctl once for every TURN relay port.
    cli('exec '+str(path))
    record = dict(total=len(mappings), ordinary=[dict(protocol=proto, port=port)
                  for (proto, port), target in sorted(mappings.items()) if target == config['host']],
                  dedicated=sum(target == config['wan_backend'] for target in mappings.values()))
    (root/'host-fixed-mappings.json').write_text(json.dumps(record, indent=2)+'\n')


def ike_addresses(p):
    data = cli('show interface address')
    active, addresses = False, []
    for line in data.splitlines():
        if line and not line[0].isspace():
            active = line.split()[0] == p['wan']
        elif active:
            import ipaddress
            match = re.search(r'\b(?:[0-9a-fA-F]*:)[0-9a-fA-F:]+/\d+', line)
            if match:
                ip = ipaddress.ip_interface(match[0]).ip
                if ip.is_global:
                    addresses.append(str(ip))
    ns, dev = p['namespace'], p['wan']
    run('ip', '-n', ns, 'addr', 'replace', p['wan_address'].split('/')[0]+'/32', 'dev', dev)
    for value in addresses:
        run('ip', '-n', ns, '-6', 'addr', 'replace', value+'/128', 'dev', dev, 'nodad')


def lan_pd_prefixes():
    """LAN PD GUA must stay on table-0 FIB, same role as RFC1918 in the IPv4 ACL."""
    if not PD_SYNC_STATE.exists():
        return []
    try:
        prefix = json.loads(PD_SYNC_STATE.read_text()).get('pool_prefix')
        network = ipaddress.IPv6Network(prefix)
    except (OSError, TypeError, ValueError, json.JSONDecodeError, ipaddress.AddressValueError):
        return []
    if network.prefixlen != 64 or not network[0].is_global:
        return []
    return [str(network)]


def source_acl(tag, rules):
    existing = cli('show acl-plugin acl')
    current = re.search(
        rf'(?m)^acl-index\s+(\d+)\s+count\s+\d+\s+tag \{{{re.escape(tag)}\}}',
        existing,
    )
    command = f'set acl-plugin acl index {current[1]} {rules} tag {tag}' if current else \
        f'set acl-plugin acl tag {tag} {rules}'
    acl = cli(command)
    match = re.search(r'ACL index:\s*(\d+)', acl) or current
    if not match:
        raise RuntimeError('Source policy ACL missing')
    return match[1]


def lan_host6(p):
    return str(ipaddress.ip_interface(p.get('lan_ula_host', 'fd42:1111:2222:10::2/64')).ip)


def vps_gw6(p):
    return p.get('vps_gateway6', 'fd42:1111:2222:20::1')


def policy(p):
    # IPv4 decrypted IPsec / sg internet uses VPP SNAT on loop10. IPv6 EAP and
    # wg8 ULAs take the same loop10 path; the VPS routes both VPN prefixes through the BVI and
    # FULLCONENATs them out wg1 (mark 0x1), matching 10.61.50.0/24. Private,
    # ULA, and LAN-PD destinations stay on table-0 FIB. Public resolvers stay
    # on this source policy so EAP/sg reach 1.1.1.1 via br0, not the LAN gate.
    v4_rules = (
        'deny src 0.0.0.0/0 dst 10.0.0.0/8, '
        'deny src 0.0.0.0/0 dst 172.16.0.0/12, '
        'deny src 0.0.0.0/0 dst 192.168.0.0/16, '
        'permit src 10.62.20.0/24 dst 0.0.0.0/0, '
        'permit src 10.62.40.0/24 dst 0.0.0.0/0'
    )
    v6_denies = [
        'deny src ::/0 dst fc00::/7',
        'deny src ::/0 dst fe80::/10',
        'deny src ::/0 dst ff00::/8',
    ]
    v6_denies += [f'deny src ::/0 dst {prefix}' for prefix in lan_pd_prefixes()]
    v6_rules = ', '.join(v6_denies + [
        f'permit src {EAP_ULA6} dst ::/0',
        f'permit src {WG8_ULA6} dst ::/0',
    ])
    v4 = source_acl('vrouter-source-policy', v4_rules)
    v6 = source_acl('vrouter-source-policy6', v6_rules)
    # Adding a via to an existing ABF id appends a path and can mix address
    # families on one path-list. Only create the policy when it is absent.
    present = set(map(int, re.findall(r'policy:(\d+)', cli('show abf policy'))))
    if 620 not in present:
        cli(f'abf policy add id 620 acl {v4} via {p.get("vps_gateway", "10.61.50.1")} loop10')
    if 621 not in present:
        cli(f'abf policy add id 621 acl {v6} via {vps_gw6(p)} loop10')
    # wg8 attaches itself to these policies: see deploy/wireguard.
    cli(f'abf attach ip4 policy 620 {IPSEC_TAP}')
    cli(f'abf attach ip6 policy 621 {IPSEC_TAP}')


def setup_wg_proxy(root, clear_conntrack=True):
    # A missing transport must fail startup before wg1 can send any handshake.
    run('ip', 'link', 'set', 'vpp-wg-proxy', 'up')
    run('sysctl', '-w', 'net.ipv4.conf.vpp-wg-proxy.route_localnet=1')
    run('nft', '-f', config_path(root, 'wg-proxy.nft'))
    if clear_conntrack:
        # Exit 1 means there were no matching flows. Keep unrelated NAT state.
        run('conntrack', '-D', '-p', 'udp', '--orig-src', '10.63.50.1',
            '--orig-dst', '10.63.50.2', '--dport', '44441', check=False)


def lan_bridge_member(p):
    """Production LAN TAP into br-mgmt. Profile nic1 is the pre-cutover trial NIC."""
    return p.get('linux_lan_member') or 'vpp-lan'


def set_tap_offload(interface, enabled):
    """Keep TAP TX checksums software-complete while enabling GSO/GRO."""
    features = ('tx', 'off', 'gro', 'on', 'gso', 'on', 'tso', 'off') if enabled else \
        ('tx', 'off', 'gro', 'off', 'gso', 'off', 'tso', 'off')
    run('ethtool', '-K', interface, *features)


def configure_tap_offloads(p):
    # These are the Linux ends of VPP TAPs. TAP itself does not support TSO,
    # but checksum offload and generic segmentation/receive coalescing are safe
    # for the non-IPsec paths.
    interfaces = ['vpp-lan', 'vrouter-vps', 'vpp-wg-proxy', 'vpp-tproxy']
    if p.get('host_service_path'):
        interfaces.append('vpp-hostsvc')
    for interface in interfaces:
        set_tap_offload(interface, True)

    # tap4061 is the dedicated IPsec TAP. Its Linux peer is named after the
    # VPP WAN interface because strongSwan uses that name to discover IKE IPs.
    run('ip', 'netns', 'exec', p['namespace'], 'ethtool', '-K', p['wan'],
        'tx', 'off', 'gro', 'off', 'gso', 'off', 'tso', 'off')


def host(root, p):
    tproxy_path_module().host(run)
    baseline = json.loads((root/'baseline/linux-state.json').read_text())
    run('ip', 'link', 'set', 'br0', 'address', baseline['links']['br0']['mac'])
    run('ip', 'link', 'set', 'vrouter-vps', 'master', 'br0')
    run('ip', 'link', 'set', 'vrouter-vps', 'up')
    run('ip', 'link', 'set', 'dev', 'br0', 'mtu', '1342')
    # The shared bridge itself is made by the existing network prep utility.
    run('ip', 'link', 'add', 'br-mgmt', 'type', 'bridge', check=False)
    run('ip', 'link', 'set', 'br-mgmt', 'address', p['lan_host_mac'])
    lan_member = lan_bridge_member(p)
    run('ip', 'link', 'set', lan_member, 'master', 'br-mgmt')
    run('ip', 'link', 'set', lan_member, 'up')
    run('ip', 'link', 'set', 'br-mgmt', 'up')
    run('ip', 'addr', 'replace', p['lan_host'], 'dev', 'br-mgmt')
    run('ip', '-6', 'addr', 'replace', p['lan_ula_host'], 'dev', 'br-mgmt', 'nodad')
    run('sysctl', '-w', 'net.ipv6.conf.br-mgmt.accept_ra=0', 'net.ipv6.conf.br-mgmt.autoconf=0')
    configure_tap_offloads(p)
    if not p.get('host_service_path') and (config_path(root, 'socks-frontend.nft')).exists():
        run('nft', '-f', config_path(root, 'socks-frontend.nft'))
    if p.get('host_service_path'):
        # Dedicated ingress provides an unambiguous WAN security boundary.
        run('sysctl', '-w', 'net.ipv4.conf.vpp-hostsvc.rp_filter=0')
        run('python3', Path(__file__).resolve().parents[1]/'host-services/host-path.py',
            '--config', config_path(root, 'host-services.json'), '--apply')
        services = json.loads((config_path(root, 'host-services.json')).read_text())
        backend = str(ipaddress.IPv4Address(services['wan_backend']))
        run('ip', 'addr', 'replace', backend+'/30', 'dev', 'vpp-hostsvc')
        run('ip', 'link', 'set', 'vpp-hostsvc', 'up')
        host_routing_module().install(services, run, root/'host-routing.json')
    ns, dev = p['namespace'], p['wan']
    run('ip', '-n', ns, 'link', 'set', dev, 'up')
    run('ip', '-n', ns, 'route', 'replace', 'default', 'via', '10.63.10.1', 'dev', dev)
    run('ip', '-n', ns, '-6', 'route', 'replace', 'default', 'via', 'fd42:1111:2222:50::1', 'dev', dev)
    for family, gateway in (('-4', '10.63.10.1'), ('-6', 'fd42:1111:2222:50::1')):
        run('ip', '-n', ns, family, 'neigh', 'replace', gateway, 'lladdr', '02:76:70:70:61:01', 'nud', 'permanent', 'dev', dev)
    ike_addresses(p)
    run('ip','addr','replace','10.62.10.1/32','dev','lo')
    for prefix in ('10.62.10.0/24', '10.62.50.0/24', '10.62.20.0/24', '10.62.30.0/24', '10.62.40.0/24', '10.65.0.0/16', '10.61.70.0/24'):
        run('ip', 'route', 'replace', prefix, 'via', '10.61.20.1', 'dev', 'br-mgmt', 'onlink')
    for prefix in ('fd42:1111:2222:90::/64', WG8_ULA6, EAP_ULA6):
        run('ip', '-6', 'route', 'replace', prefix, 'via', 'fd42:1111:2222:10::1', 'dev', 'br-mgmt', 'onlink')
    for prefix in (EAP_ULA6, WG8_ULA6):
        run('ip', '-6', 'rule', 'del', 'from', prefix, 'lookup', 'vpn', check=False)
        run('ip', '-6', 'rule', 'add', 'from', prefix, 'lookup', 'vpn', 'pref', '3200')
    run('ip', 'route', 'replace', 'default', 'via', '10.61.20.1', 'dev', 'br-mgmt', 'onlink', 'table', 'altroute')


def topology(root, p):
    deadline = time.monotonic()+25
    while True:
        try:
            cli('show version')
            break
        except (RuntimeError, OSError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    reserved = False
    def before(line):
        nonlocal reserved
        if line == '# vrouter-host-static-reservations':
            reserve_host_ports(root, p)
            reserved = True
    cli_file(config_path(root, 'topology.vpp'), before=before)
    if p.get('host_service_path') and not reserved:
        raise RuntimeError('Host static reservation stage missing')
    # Trial bundles load the prepared host.nft. An installed restart must not
    # `nft -f /etc/nftables.conf`: that wipes live dnsmasq nftsets.
    if not os.environ.get('VROUTER_RUNTIME_DIRECTORY'):
        run('nft', '-f', config_path(root, 'host.nft'))
    # TAP route_localnet and DNAT must be configured before any tunnel can use the TAP, to
    # prevent premature handshake packets from establishing an un-DNAT'd conntrack entry.
    # vpp-wireguard creates the tunnels once this unit is active.
    setup_wg_proxy(root, clear_conntrack=True)
    cli_file(config_path(root, 'egress-vrf.vpp'))
    cli('nat66 plugin enable')
    cli(f'set interface nat66 out {p["wan"]}')
    # Restore static Nebula routes and inbound forwarding through the Linux host.
    state = json.loads((root/'baseline/linux-state.json').read_text())
    for route in state['routes4']:
        if route.get('dev') == 'nebula' and route.get('table', 'main') == 'main' and route.get('type', 'unicast') == 'unicast' and route.get('dst') not in (None, 'default'):
            cli(f'ip route add {ipaddress.ip_network(route["dst"], strict=False)} via 10.61.20.2 loop200')
    if not p.get('host_service_path'):
        cli('nat44 ei add static mapping local 10.64.20.14 42008 external 10.61.10.2 42001 udp')
    if p.get('host_service_path'):
        capabilities = cli('show nat44 ei host-fallback')
        if 'pool-receive-v1' not in capabilities:
            raise RuntimeError('Shared-WAN EI pool receive capability unavailable')
        cli_file(config_path(root, 'host-path.vpp'))
    # EI registers each pool receive on the last outside. Pin the VPS pool
    # onto loop10 after the WAN and loop10 outsides exist; a tunnel that becomes an
    # outside later pins it again in its own commands.
    cli('nat44 ei pool receive 10.61.50.3 loop10')
    for port in ([] if p.get('host_service_path') else p.get('wan_host_tcp_ports', [])):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('wan_host_tcp_ports must contain valid TCP ports')
        host4 = str(ipaddress.ip_interface(p['lan_host']).ip)
        wan4 = str(ipaddress.ip_interface(p['wan_address']).ip)
        cli(f'nat44 ei add static mapping local {host4} {port} external {wan4} {port} tcp')
    policy(p)
    cli('set punt udp 53')
    cli('set punt tcp all')
    # IPsec cleartext is reinjected on the dedicated IPsec TAP. Gateway-local services need
    # the same Linux frontend as WireGuard, independently of the IKE punt.
    cli(f'ip punt redirect rx {IPSEC_TAP} via 10.61.20.2 loop200')
    if 1080 in p.get('lan_tcp_services', []):
        cli('ip punt redirect rx loop200 via 10.61.20.2 loop200')


def sync_host_prefix(root):
    status = Path('/run/vrouter-pd-sync/state.json')
    if not status.exists():
        return
    prefix = json.loads(status.read_text()).get('pool_prefix')
    record = root/'host-prefix.json'
    old = json.loads(record.read_text()) if record.exists() else {}
    if old.get('prefix') == prefix and old.get('vpp_pid') == run('systemctl','show','vrouter-vpp.service','--property=MainPID','--value').strip():
        return
    pid = run('systemctl','show','vrouter-vpp.service','--property=MainPID','--value').strip()
    if old.get('address'):
        run('ip','-6','addr','del',old['address']+'/128','dev','lo',check=False)
    if prefix:
        network = ipaddress.IPv6Network(prefix)
        address = str(network.network_address+2)
        run('ip','-6','addr','replace',address+'/128','dev','lo','nodad')
        run('ip','-6','route','replace','default','via','fd42:1111:2222:10::1','dev','br-mgmt','src',address)
        cli(f'ip route add {address}/128 via fd42:1111:2222:10::2 loop200')
    else:
        address = None
        run('ip','-6','route','replace','default','via','fd42:1111:2222:10::1','dev','br-mgmt')
    if old.get('address') and old['address'] != address and old.get('vpp_pid') == pid:
        cli(f'ip route del {old["address"]}/128 via fd42:1111:2222:10::2 loop200')
    firewall_path = config_path(root, 'firewall.json')
    config = json.loads(firewall_path.read_text())
    config['vpp']['lan_ipv6'] = ['fd42:1111:2222:10::/64']+([prefix] if prefix else [])
    spec = importlib.util.spec_from_file_location('cutover_firewall',Path(__file__).resolve().parents[1]/'firewall/vrouter-firewall.py')
    firewall = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(firewall)
    firewall.apply_vpp_firewall(config)
    record.write_text(json.dumps({'prefix':prefix,'address':address,'vpp_pid':pid})+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('action', choices=('launch','namespace','namespace-stop','topology','host','ike-watch'))
    args = parser.parse_args()
    root = args.bundle.resolve()
    profile = config_path(root, 'profile.json') if 'VROUTER_CONFIG_DIRECTORY' in os.environ else root/'profile.json'
    p = json.loads(profile.read_text())
    if args.action == 'launch':
        installed = os.environ.get('VROUTER_RUNTIME_DIRECTORY')
        if installed:
            # Installed DPDK discovers the validated PMD in its own directory.
            binary = Path(installed)/'bin/vpp'
            os.execv(str(binary), ['vpp', '-c', str(config_path(root, 'startup.conf'))])
        os.execv(str(root/'bin/vpp'), ['vpp','-c',str(config_path(root, 'startup.conf'))])
    elif args.action == 'namespace':
        # A restart reuses only the namespace created by this deployment.
        if not Path('/run/netns', p['namespace']).exists():
            run('ip', 'netns', 'add', p['namespace'])
        run('ip', '-n', p['namespace'], 'link', 'set', 'lo', 'up')
    elif args.action == 'namespace-stop':
        run('ip', 'netns', 'delete', p['namespace'])
    elif args.action == 'topology':
        topology(root, p)
    elif args.action == 'host':
        host(root, p)
    else:
        while True:
            ike_addresses(p)
            sync_host_prefix(root)
            time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(f'Deployment hook failed: {type(error).__name__} ({error})')
