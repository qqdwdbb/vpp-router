#!/usr/bin/env python3
"""Render an immutable, root-private VROUTER deployment from the live Linux baseline."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
BASE = Path('/usr/local/src/vpp-vrouter/migration')
VPP = Path('/usr/local/src/vpp-vrouter/nic1-test/vpp')


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem.replace('-', '_'), path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(*args):
    p = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=60)
    if p.returncode:
        raise RuntimeError('Preparation command failed: ' + str(args[0]))
    return p.stdout


def write(root, name, value):
    path = root/name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+'\n' if isinstance(value, (dict, list)) else value)
    path.chmod(0o600)
    return path


def topology(p):
    parent, wan = p['parent'], p['wan']
    lines = [f'set interface mac address {parent} {p["wan_mac"]}',
             f'set interface promiscuous on {parent}', f'set interface state {parent} up',
             f'create sub-interface {parent} 100 dot1q 100 exact-match',
             f'set interface mtu packet 1500 {wan}',
             f'set interface ip address {wan} {p["wan_address"]}', f'set interface state {wan} up',
             f'ip route add 0.0.0.0/0 via {p["wan_gateway"]} {wan}']
    if p.get('wan_gateway_mac'):
        lines.append(f'set ip neighbor {wan} {p["wan_gateway"]} {p["wan_gateway_mac"]}')
    lan = (HERE.parent/'lan-services/lan.vpp.conf.example').read_text()
    lan = lan.replace('create tap id 2000 host-if-name vpp-lan', f'create tap id 2000 host-if-name vpp-lan host-mac-addr {p["lan_host_mac"]}')
    lines += lan.splitlines()
    lines += [f'set interface mac address loop200 {p["lan_gateway_mac"]}',
              f'set interface l2 bridge {parent} 200',
              'set interface mac address tap2000 02:76:70:70:20:01']
    lines += (HERE.parent/'vps-bridge/vps.vpp.conf.example').read_text().splitlines()
    lines += (HERE.parent/'ipv6/native-pd.vpp.conf.example').read_text().replace('WAN_INTERFACE', wan).splitlines()
    nat = {'sessions': 65536, 'users': 4096, 'user_sessions': 16384,
           'tcp_established': 1800, 'tcp_transitory': 120}
    nat.update(p.get('nat44_ei', {}))
    if any(type(nat.get(key)) is not int or nat[key] <= 0 for key in
           ('sessions', 'users', 'user_sessions', 'tcp_established', 'tcp_transitory')):
        raise ValueError('NAT capacity must be positive integer limits')
    fragment = (HERE.parent/'firewall/wan-output-nat.vpp.conf.example').read_text().replace('WAN_INTERFACE', wan)
    fragment = fragment.replace('nat44 ei plugin enable sessions 4096',
        f'nat44 ei plugin enable sessions {nat["sessions"]} users {nat["users"]} user-sessions {nat["user_sessions"]}')
    fragment += f'\nset nat44 ei timeout tcp-established {nat["tcp_established"]} tcp-transitory {nat["tcp_transitory"]}\n'
    # Address-only identity mapping sends all return traffic to its static owner,
    # overriding the dynamic outside-port worker partition in stock EI 26.06.
    ports = p.get('wan_identity_udp_ports')
    if not isinstance(ports, list) or not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError('Invalid WAN identity UDP ports')
    fragment = fragment.replace(f'nat44 ei add identity mapping external {wan}',
        '\n'.join(f'nat44 ei add identity mapping external {wan} udp {port}' for port in ports))
    lines += fragment.splitlines()
    if p.get('host_service_path'):
        services = json.loads((HERE.parent/'host-services/services.json').read_text())
        host_path = module(HERE.parent/'host-services/host-path.py')
        a = host_path.addresses(services)
        if a['wan_address'] != str(ipaddress.ip_interface(p['wan_address']).ip):
            raise ValueError('Host service WAN address mismatch')
        if a['host'] != str(ipaddress.ip_interface(p['lan_host']).ip) or a['gateway'] != str(ipaddress.ip_interface(p['lan_gateway']).ip):
            raise ValueError('Host service LAN address mismatch')
        position = lines.index(f'nat44 ei add interface address {wan}')
        lines[position] = f'nat44 ei add address {a["wan_address"]} tenant-vrf 0'
        # Reserve host ports before enabling the first outside NAT feature.
        position = lines.index(f'set interface nat44 ei out {wan} output-feature')
        lines.insert(position, '# vrouter-host-static-reservations')
    # loop10 exists in the VPS fragment; EI plugin enable is in the WAN fragment.
    lines += (HERE.parent/'vps-bridge/vpn-egress.vpp.conf.example').read_text().splitlines()
    lines += (HERE.parent/'wg-proxy/transport.vpp.conf').read_text().splitlines()
    lines += [f'create tap id 4061 host-ns {p["namespace"]} host-if-name {wan} host-mac-addr 02:76:70:70:61:02 host-ip4-addr 10.63.10.2/30 host-ip6-addr fd42:1111:2222:50::2/64',
              'set interface mac address tap4061 02:76:70:70:61:01',
              'set interface ip address tap4061 10.63.10.1/30',
              'set interface ip address tap4061 fd42:1111:2222:50::1/64',
              'set interface state tap4061 up', 'set interface rx-mode tap4061 interrupt',
              'ip6 nd tap4061 ra-suppress', 'ipsec cleartext ingress tap4061',
              'ipsec ike punt enable', 'set punt udp 500', 'set punt ip6 udp 500',
              f'ip punt redirect rx {wan} via 10.63.10.2 tap4061',
              f'ip6 punt redirect rx {wan} via fd42:1111:2222:50::2 tap4061',
              f'ip route add 10.62.50.0/24 via {p["wan_gateway"]} {wan}',
              f'ip route add 10.62.20.0/24 via {p["wan_gateway"]} {wan}']
    lines += module(HERE.parent/'tproxy-path.py').topology()
    return '\n'.join(line for line in lines if line.strip() and
                     (not line.lstrip().startswith('#') or line == '# vrouter-host-static-reservations'))+'\n'


def dnsmasq_fragment(text):
    """Keep dnsmasq rules that do not depend on the disabled nftset path."""
    return '\n'.join(line for line in text.splitlines()
                      if not line.strip().startswith('nftset=')) + '\n'


def ipsec_dns_config(text):
    """Publish resolvers that each VPN profile can reach through its selectors."""
    section = None
    lines = []
    for line in text.splitlines():
        if line.startswith('conn '):
            section = line[5:].strip()
        if line.lstrip().startswith('rightdns='):
            key, _ = line.split('=', 1)
            dns = ('1.1.1.1,2606:4700:4700::1111' if section == 'eap-mschapv2'
                   else '10.61.20.2,fd42:1111:2222:10::2')
            line = key + '=' + dns
        lines.append(line)
    return '\n'.join(lines) + '\n'


def stage_dnsmasq_fragments(source, root):
    """Copy dnsmasq fragments into the private bundle without nftset rules."""
    target = root/'config/dnsmasq.d'
    target.mkdir(parents=True, exist_ok=True)
    for fragment in sorted(source.iterdir()):
        if (not fragment.is_file() or fragment.is_symlink() or
                fragment.name.startswith('.') or
                fragment.name.endswith(('.dpkg-dist', '.dpkg-old', '.dpkg-new'))):
            continue
        write(target, fragment.name, dnsmasq_fragment(fragment.read_text()))
    return target


def dns_config(text, fragment_dir):
    result = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(('listen-address=', 'interface=', 'dhcp-range=', 'dhcp-option=', 'enable-ra', 'ra-param=', 'bind-interfaces', 'bind-dynamic')):
            continue
        if line.startswith('conf-dir=') or line.startswith('conf-file=/etc/dnsmasq.d/'):
            continue
        result.append(raw)
    result.append(f'conf-dir={fragment_dir},.dpkg-dist,.dpkg-old,.dpkg-new')
    result += ['interface=br-mgmt', 'bind-dynamic',
               'listen-address=127.0.0.1,::1,10.61.20.2,10.62.10.1,fd42:1111:2222:10::2',
               'dhcp-range=10.61.20.3,10.61.20.254,6h',
               'dhcp-option=option:router,10.61.20.1',
               'dhcp-option=option:dns-server,10.61.20.2',
               'enable-ra', 'dhcp-range=::,constructor:br-mgmt,ra-stateless,ra-names,6h',
               'ra-param=br-mgmt,10,0', 'dhcp-option=option6:dns-server,[fd42:1111:2222:10::2]']
    return '\n'.join(result)+'\n'


def remove_flowtable(text):
    match = re.search(r'\bflowtable\s+f\s*\{', text)
    if not match:
        return text
    depth, end = 1, match.end()
    while depth and end < len(text):
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if depth:
        raise ValueError('Unbalanced flowtable')
    return text[:match.start()]+text[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--host-service-path', action='store_true', help='Stage shared-WAN host reservations and the dedicated coturn path')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run on VROUTER as root')
    os.umask(0o077)
    root = args.directory.resolve()
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root)):
        raise ValueError('Bundle path must not contain shell/systemd special characters')
    p = json.loads((HERE/'profile.json').read_text())
    if args.host_service_path:
        p['host_service_path'] = True
        if Path('/proc/sys/net/ipv4/conf/all/rp_filter').read_text().strip() == '1':
            raise ValueError('Strict global reverse path filtering conflicts with dedicated host ingress')
    if 'wan_gateway_mac' not in p and p.get('wan_gateway'):
        out = run('ip', 'neigh', 'show', p['wan_gateway'])
        m = re.search(r'([0-9a-fA-F:]{17})', out)
        if m:
            p['wan_gateway_mac'] = m.group(1).lower()
    if root.exists():
        raise ValueError('Refusing to overwrite an existing bundle')
    # No host networking or service mutations in preparation.
    run('ip', 'route', 'get', p['management']['peer'])
    if Path('/sys/class/net/mgmt0/master').exists():
        raise ValueError('mgmt0 must be independent')
    if subprocess.run(['pgrep', '-x', 'vpp'], capture_output=True).returncode == 0:
        raise ValueError('Prepare from Linux, with VPP stopped')
    root.mkdir(mode=0o700, parents=True)
    audit = module(HERE/'linux-recovery-audit.py')
    baseline = root/'baseline'
    run('python3', HERE/'linux-recovery-audit.py', 'capture', '--directory', baseline)
    state = json.loads((baseline/'linux-state.json').read_text())
    if p.get('host_service_path'):
        module(HERE.parent/'host-services/host-routing.py').check_available(state['rules4'], state['routes4'])
    if state['links']['nic0']['master'] != 'lan' or state['drivers']['nic0'] != 'r8125':
        raise ValueError('Unexpected Linux topology')
    for name in ('br-mgmt', 'vpp-lan', 'vrouter-vps', 'vpp-wg-proxy', 'vpp-hostsvc', 'vpp-tproxy'):
        if Path('/sys/class/net', name).exists():
            raise ValueError('Reserved link already exists: ' + name)
    if p['namespace'] in run('ip', 'netns', 'list').split():
        raise ValueError('Reserved namespace already exists')
    leasefile = Path('/var/lib/misc/dnsmasq.leases')
    if leasefile.exists():
        import time
        for line in leasefile.read_text().splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[2] == '10.61.20.2' and (fields[0] == '0' or int(fields[0]) > time.time()):
                raise ValueError('10.61.20.2 is leased; resolve the host address conflict before preparation')
    for file in ('/etc/dnsmasq.conf', '/etc/network/interfaces'):
        shutil.copy2(file, baseline/Path(file).name)
    write(root, 'profile.json', p)
    (root/'config').mkdir()
    plugins = root/'plugins'
    shutil.copytree(BASE/'plugins', plugins)
    if p.get('host_service_path'):
        candidate = BASE/'shared-port-candidate/nat44_ei_plugin.so'
        if not candidate.exists() or b'pool-receive-v1' not in candidate.read_bytes():
            raise ValueError('Validated EI pool receive capability required')
        shutil.copy2(candidate, plugins/'nat44_ei_plugin.so')
    abf = BASE/'abf-build/lib/aarch64-linux-gnu/vpp_plugins/abf_plugin.so'
    shutil.copy2(abf, plugins/'abf_plugin.so')
    # A copied executable resolves the private crypto engine directory via $ORIGIN.
    (root/'bin').mkdir()
    shutil.copy2(VPP/'bin/vpp', root/'bin/vpp')
    shutil.copytree(BASE/'crypto_engines', root/'lib/aarch64-linux-gnu/vpp_crypto_engines')
    enabled = ['dpdk', 'tap', 'ping', 'nat44_ei', 'nat_ei_context', 'ipsec_ike_punt',
               'dhcp', 'acl', 'abf', 'dns_intercept', 'wireguard', 'wg_nat_order', 'mss_clamp',
               'nat66']
    startup = f'''unix {{ nodaemon runtime-dir /run/vpp cli-listen /run/vpp/cli.sock }}
api-segment {{ prefix vrouter-prod }}
socksvr {{ socket-name /run/vpp/api.sock }}
statseg {{ socket-name /run/vpp/stats.sock }}
cpu {{ main-core 4 corelist-workers 5-6 }}
memory {{ main-heap-size 1G }}
buffers {{ buffers-per-numa 8192 }}
plugins {{ path {plugins}
plugin default {{ disable }}
'''+''.join(f'plugin {name}_plugin.so {{ enable }}\n' for name in enabled)+f'''}}
dpdk {{ uio-driver uio_pci_generic
 dev {p['pci']} {{ name {p['parent']} num-rx-queues 4 num-tx-queues 2 rss {{ ipv4 ipv6 }} }}
 iova-mode pa huge-dir /dev/hugepages file-prefix vrouter-prod no-multi-seg
}}
'''
    write(root, 'config/startup.conf', startup)
    write(root, 'config/topology.vpp', topology(p))
    render = module(HERE.parent/'ipsec/real-client-lab.py')
    text, pools, identity, cert = render.render(Path('/etc/ipsec.conf').read_text())
    text = ipsec_dns_config(text)
    # Cert IPv6 comes from PD sync (GUA). Password EAP keeps a unique-local pool.
    prefix = module(HERE.parents[1]/'ipsec/ipsec-prefix-sync.py')
    text = prefix.rewrite_config(text, [])
    write(root, 'config/ipsec.conf', text)
    run('openssl', 'x509', '-in', '/etc/ipsec.d/certs/'+cert, '-checkend', '0', '-noout')
    shutil.copytree('/usr/lib/ipsec/plugins', root/'ipsec-plugins')
    shutil.copy2(BASE/'strongswan-build/vpp-sswan-5.9/libstrongswan-kernel-vpp.so', root/'ipsec-plugins/libstrongswan-kernel-vpp.so')
    conf = '''charon {
 load_modular = no
 load = random nonce x509 revocation constraints pubkey pkcs1 pkcs8 pem openssl gmp hmac kdf attr curl kernel-vpp! kernel-netlink socket-default stroke eap-identity eap-mschapv2 counters
 install_routes = no
 plugins {
  kernel-vpp { api_prefix = vrouter-prod
   read_timeout = 5000
   use_tunnel_mode_sa = yes
  }
  stroke { secrets_file = /etc/ipsec.secrets }
  openssl { load_legacy = yes }
 }
}
'''
    write(root, 'config/strongswan.conf', conf)
    for wg in p['wireguard']:
        source = wg['source']
        command = ['python3', HERE.parent/'render-wireguard.py', f'/etc/wireguard/{source}.conf',
                   '--instance', str(wg['instance']), '--source-address', '10.63.50.1' if source == 'wg1' else '10.61.10.2',
                   '--output', root/f'config/{source}.vpp']
        if source == 'wg1':
            command += ['--endpoint', '10.63.50.2:44441']
        if source == 'wg0':
            command += ['--nat66-policy', root/'config/wg0-nat66.json']
        run(*command)
    firewall = json.loads((HERE.parent/'firewall/firewall-config.json.example').read_text())
    firewall['vpp'].update(wan_interface=p['wan'], lan_interfaces=[p['parent']],
                           lan_tcp_services=p.get('lan_tcp_services', []),
                           wan_host_tcp_ports=p.get('wan_host_tcp_ports', []),
                           wan_host_tcp_sources=p.get('wan_host_tcp_sources', {}))
    if p.get('host_service_path'):
        services = json.loads((HERE.parent/'host-services/services.json').read_text())
        services['wan_interface'] = p['wan']
        firewall['vpp'].update(host_service_path=True)
        write(root, 'config/host-services.json', services)
        host_path = module(HERE.parent/'host-services/host-path.py')
        write(root, 'config/host-path.vpp', host_path.topology(services))
        write(root, 'config/host-path.nft', host_path.nft(services, [], owners={}))
        if state['services'].get('coturn.service') == 'active':
            write(root, 'config/turnserver.conf', host_path.coturn_config(Path('/etc/turnserver.conf').read_text(), services))
    # Preserve the real host policy/sets and Linux TUN forwarding; the example
    # global host drop policy is not suitable for this production topology.
    firewall['nftables']['enabled'] = False
    write(root, 'config/firewall.json', firewall)
    prep = dict(bridge='br-mgmt', lan_tap='vpp-lan', nftsets_path=None)
    write(root, 'config/vrouter-network.json', prep)
    pd = json.loads((HERE.parent/'ipv6/pd-sync.json').read_text())
    pd.update(wan_interface=p['wan'], ipsec_config=str(root/'config/ipsec.conf'),
              nat66_policy_file=str(root/'config/wg0-nat66.json'),
              ipsec_reload_command=['systemctl', 'reload', 'vrouter-strongswan.service'])
    write(root, 'config/vrouter-pd-sync.json', pd)
    routes = json.loads((HERE.parent/'dns-route-gate/nftset-route-sync.json').read_text())
    routes['vpp_service'] = 'vrouter-vpp.service'
    write(root, 'config/nftset-route-sync.json', routes)
    gate = json.loads((HERE.parent/'dns-route-gate/dns-route-gate.json').read_text())
    gate['route_config'] = str(root/'config/nftset-route-sync.json')
    gate['sync_program'] = str(HERE.parents[1]/'nftset-route-sync.py')
    write(root, 'config/dns-route-gate.json', gate)
    write(root, 'config/dns-route-gate.nft', (HERE.parent/'dns-route-gate/dns-route-gate.nft').read_text())
    dnsmasq_dir = stage_dnsmasq_fragments(Path('/etc/dnsmasq.d'), root)
    write(root, 'config/dnsmasq.conf', dns_config(Path('/etc/dnsmasq.conf').read_text(), dnsmasq_dir))
    run('dnsmasq', '--test', '--conf-file='+str(root/'config/dnsmasq.conf'))
    write(root, 'config/egress-vrf.vpp', (HERE.parent/'wg-proxy/egress-vrf.vpp.conf').read_text())
    write(root, 'config/vpn-egress.vpp', (HERE.parent/'vps-bridge/vpn-egress.vpp.conf.example').read_text())
    write(root, 'config/wg-proxy.nft', (HERE.parent/'wg-proxy/transport.nft').read_text())
    if not p.get('host_service_path') and 1080 in p.get('lan_tcp_services', []):
        write(root, 'config/socks-frontend.nft', (HERE/'socks-frontend.nft').read_text())
    # Existing host rules and nftsets remain the authoritative policy. Only rename
    # the LAN-facing interface; WAN SNAT must become host-side masquerade to VPP.
    rules = (baseline/'restore-firewall.nft').read_text()
    rules = re.sub(r'\blan\b', 'br-mgmt', rules)
    # VPP owns WAN NAT. Do not masquerade LAN/proxy replies on br-mgmt.
    wan_address = re.escape(str(ipaddress.ip_interface(p['wan_address']).ip))
    rules = '\n'.join(line for line in rules.splitlines()
                      if not re.search(rf'oifname "wan" .*snat (?:ip )?to {wan_address}\b', line))
    rules = module(HERE.parent/'firewall/persistent-rules.py').drop_vpp_owned_marks(rules)
    # The old Linux WAN flowtable cannot bind a DPDK-owned interface.
    rules = remove_flowtable(rules)
    rules = '\n'.join(l for l in rules.splitlines() if 'flow add @f' not in l)
    write(root, 'config/host.nft', rules+'\n')
    run('nft', '-c', '-f', root/'config/host.nft')
    units = root/'units'
    units.mkdir()
    for source in (HERE.parent/'startup').glob('vrouter-*.service'):
        unit = source.read_text().replace('/opt/vpp-vrouter-migration/source', str(SOURCE))
        unit = unit.replace('/opt/vpp-nic1-test/vpp', str(VPP))
        unit = unit.replace('/opt/vpp-nic1-test/dpdk', str(VPP.parent/'dpdk'))
        unit = unit.replace('/opt/vpp-vrouter-migration/ipsec-ip6-udp/lib', str(BASE/'ipsec-ip6-udp/lib'))
        unit = unit.replace('/etc/vpp/', str(root/'config')+'/')
        unit = unit.replace(str(root/'config/ipsec.d')+':/etc/ipsec.d ', '')
        unit = unit.replace(str(root/'config/ipsec-plugins'), str(root/'ipsec-plugins'))
        unit = unit.replace('/etc/strongswan-vpp.conf', str(root/'config/strongswan.conf'))
        unit = unit.replace('BindReadOnlyPaths=/run/vpp', 'BindReadOnlyPaths=/run/vpp /etc/ipsec.d /etc/ipsec.secrets')
        if source.name == 'vrouter-vpp.service':
            unit = unit.replace(f'ExecStart={VPP}/bin/vpp -c '+str(root/'config/startup.conf'),
                                f'ExecStart=/usr/bin/python3 {HERE}/runtime.py --bundle {root} launch')
            unit = unit.replace('ExecStartPost=', f'ExecStartPost=/usr/bin/python3 {HERE}/runtime.py --bundle {root} topology\nExecStartPost=', 1)
            unit = unit.replace('After=systemd-modules-load.service local-fs.target',
                                'Requires=vrouter-namespace.service\nAfter=systemd-modules-load.service local-fs.target vrouter-namespace.service')
            unit = unit.replace('DefaultDependencies=no\n', '')
        if source.name == 'vrouter-network-prep.service':
            unit = unit.replace('ExecStart=', f'ExecStart=/usr/bin/python3 {HERE}/runtime.py --bundle {root} host\nExecStart=', 1)
            unit += f'\n# Post-TAP host wiring is completed before consumers start.\n'
        write(units, source.name, unit)
    write(units, 'vrouter-namespace.service', f'''[Unit]
Description=VROUTER private IKE namespace
Before=vrouter-vpp.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {HERE}/runtime.py --bundle {root} namespace
ExecStop=/usr/bin/python3 {HERE}/runtime.py --bundle {root} namespace-stop
''')
    # DNS uses the staged full configuration; original unit/files remain untouched.
    write(units, 'vrouter-dnsmasq.service', f'''[Unit]
Requires=vrouter-network-prep.service
After=vrouter-network-prep.service
PartOf=vrouter-vpp.service
Before=vrouter-dns-route-gate.service
Conflicts=dnsmasq.service
[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file={root}/config/dnsmasq.conf --pid-file=/run/vrouter-dnsmasq.pid
Restart=on-failure
''')
    intercept_unit = (HERE.parent/'dns-intercept/vrouter-dns-intercept.service').read_text()
    intercept_unit = intercept_unit.replace('/usr/local/lib/vpp-vrouter/scripts', str(SOURCE/'scripts'))
    intercept_unit = intercept_unit.replace('EnvironmentFile=/etc/vpp/runtime.env\n', '')
    write(units, 'vrouter-dns-intercept.service', intercept_unit)
    unit = (units/'vrouter-dns-route-gate.service').read_text().replace('dnsmasq.service', 'vrouter-dnsmasq.service')
    unit = unit.replace('[Unit]\n', '[Unit]\nRequires=vrouter-dns-intercept.service\nAfter=vrouter-dns-intercept.service\n', 1)
    unit = unit.replace('Requires=vrouter-vpp.service', 'Requires=vrouter-dnsmasq.service vrouter-vpp.service')
    write(units, 'vrouter-dns-route-gate.service', unit)
    write(units, 'vrouter-ike-addresses.service', f'''[Unit]
Requires=vrouter-network-prep.service
After=vrouter-network-prep.service
PartOf=vrouter-vpp.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 {HERE}/runtime.py --bundle {root} ike-watch
Restart=on-failure
''')
    if p.get('host_service_path'):
        write(units, 'vrouter-host-services.service', f'''[Unit]
Requires=vrouter-network-prep.service
After=vrouter-network-prep.service
PartOf=vrouter-vpp.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 {HERE.parent}/host-services/host-path.py --config {root}/config/host-services.json --watch
Restart=on-failure
''')
        if (root/'config/turnserver.conf').exists():
            write(units, 'vrouter-coturn.service', f'''[Unit]
Requires=vrouter-network-prep.service vrouter-host-services.service
After=vrouter-network-prep.service vrouter-host-services.service
PartOf=vrouter-vpp.service
[Service]
Type=simple
User=turnserver
Group=turnserver
Slice=system.slice
RuntimeDirectory=vrouter-coturn
RuntimeDirectoryMode=0750
LoadCredential=turnserver.conf:{root}/config/turnserver.conf
ExecStartPre=+/usr/bin/python3 {HERE.parent}/host-services/host-path.py --config {root}/config/host-services.json --apply
ExecStart=/usr/bin/turnserver -c %d/turnserver.conf --pidfile=/run/vrouter-coturn/turnserver.pid
Restart=on-failure
''')
    inputs = ['/etc/dnsmasq.conf', '/etc/network/interfaces', '/etc/ipsec.conf']
    inputs += [f'/etc/wireguard/{w["source"]}.conf' for w in p['wireguard']]
    inputs += [str(f) for f in Path('/etc/dnsmasq.d').glob('*') if f.is_file()]
    inputs += [str(f) for f in SOURCE.glob('scripts/**/*') if f.is_file() and f.suffix in ('.py','.sh','.service','.json','.nft')]
    write(root, 'input-hashes.json', {f: hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in inputs})
    write(root, 'manifest.json', {str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest()
                                for f in sorted(root.rglob('*')) if f.is_file() and 'baseline' not in f.relative_to(root).parts})
    write(root, 'state.json', {'phase':'prepared', 'source':str(SOURCE), 'bundle':str(root)})
    print(json.dumps({'bundle':str(root), 'stage':'prepared', 'identity':identity, 'host_mutated':False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Configs and child stdout/stderr can contain keys; never echo them.
        raise SystemExit('Preparation failed: '+type(error).__name__)
