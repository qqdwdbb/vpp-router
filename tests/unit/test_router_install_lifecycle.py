"""Exercise installer lifecycle functions without touching host services or devices."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).parents[2] / 'deploy/install/vpp-router-install.sh'
SOURCE = SCRIPT.read_text()


def function(name):
    start = SOURCE.index(name + '() {')
    return SOURCE[start:SOURCE.index('\n}', start) + 2]


class RouterInstallLifecycleTests(unittest.TestCase):
    def test_build_refuses_silently_disabled_stack_traces(self):
        result = self.run_shell(['build_vpp'], '''
ARCH=x86_64; VPP_TAG=v26.06; VPP_LIBDIR_REL=lib/vpp-router; JOBS=1
mkdir -p "$SRC"
cmake(){ mkdir -p "$SRC/build-vpp"; printf 'LIBUNWIND_LIB:FILEPATH=LIBUNWIND_LIB-NOTFOUND\n' >"$SRC/build-vpp/CMakeCache.txt"; }
ninja(){ echo 'should not build without unwinding' >&2; return 97; }
build_vpp
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('libunwind', result.stderr)
        self.assertNotIn('should not build', result.stderr)

    def test_proxy_units_can_be_generated_without_rewriting_configuration(self):
        result = self.run_shell(['write_singbox_units'], '''
UNIT_DIR="$T/units"; SINGBOX_DIR="$CONF/sing-box"; SINGBOX_UNIT=vpp-router-sing-box
mkdir -p "$UNIT_DIR" "$SINGBOX_DIR" "$PREFIX/bin"
printf 'existing entry\n' >"$SINGBOX_DIR/entry.json"
printf 'private upstream\n' >"$SINGBOX_DIR/upstream.json"
cp "$SINGBOX_DIR/entry.json" "$T/entry.before"
cp "$SINGBOX_DIR/upstream.json" "$T/upstream.before"
touch "$PREFIX/bin/vpp-proxy"; chmod +x "$PREFIX/bin/vpp-proxy"
write_singbox_units
cmp "$SINGBOX_DIR/entry.json" "$T/entry.before"
cmp "$SINGBOX_DIR/upstream.json" "$T/upstream.before"
grep -F -- "--sing-box-dir $SINGBOX_DIR --unit $SINGBOX_UNIT.service" "$UNIT_DIR/vpp-proxy.service"
grep -F -- "sing-box run -C $SINGBOX_DIR" "$UNIT_DIR/$SINGBOX_UNIT.service"
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_shell(self, names, body):
        with tempfile.TemporaryDirectory() as directory:
            setup = '''
set -Eeuo pipefail
STATE="$T/state"; CONF="$T/conf"; PREFIX="$T/prefix"; SRC="$T/src"
MANIFEST="$STATE/installed-files"; OLD_PREFIX="$T/old"
LIBDIR="$PREFIX/lib/vpp-router"; DATADIR="$PREFIX/share/vpp-router"
IDS_FILE="$DATADIR/dpdk-pci-ids"; DEPS="$SRC/deps"; REPO="$T"
SERVICE=vpp-router; DNS_SERVICE=vpp-router-dnsmasq; HOST_TAP=vpp-host
STARTUP="$CONF/router.conf"; DISTRO_SERVICE=vpp.service; DISTRO_MASKED="$STATE/distro-vpp-masked"
SSH_CONNECTION=; SSH_CLIENT=; NEED_MLX=0
systemctl(){ return 1; }
info(){ :; }; note(){ :; }; warn(){ :; }
die(){ echo "$*" >&2; exit 1; }
'''
            return subprocess.run(
                ['bash', '-c', setup + '\n'.join(function(n) for n in names) + '\n' + body],
                env=dict(os.environ, T=directory, LC_ALL='C'), capture_output=True, text=True)

    def test_vpp_build_includes_gate_dns_hijack_plugins(self):
        for arch in ('x86_64', 'aarch64'):
            with self.subTest(arch=arch):
                result = self.run_shell(['build_vpp'], '''
VPP_TAG=v26.06; VPP_LIBDIR_REL=lib/vpp-router; JOBS=1
mkdir -p "$SRC/vpp/src/cmake"
: >"$SRC/vpp/src/cmake/cpu.cmake"
cmake(){ printf '%s\\n' "$@"; }
ninja(){ :; }
ARCH=''' + arch + '''
build_vpp
cat "$SRC/vpp-configure.log"
''')
                self.assertEqual(result.returncode, 0, result.stderr)
                plugins = next(line.split('=', 1)[1].split(',')
                               for line in result.stdout.splitlines()
                               if line.startswith('-DVPP_PLUGINS='))
                self.assertTrue({'acl', 'abf'}.issubset(plugins), plugins)

    def test_startup_enables_gate_dns_hijack_plugins(self):
        # Gate can be installed later, so its VPP dependencies must also be
        # available when it was not selected during the initial installation.
        for kind in ('dpdk', 'afp'):
            for gate in (0, 1):
                with self.subTest(kind=kind, gate=gate):
                    result = self.run_shell(['gen_startup'], '''
SEL=(0); N_KIND=(''' + kind + '''); N_PCI=(0000:01:00.0); V_NAME=(port0)
WORKERS=0; MEM_MB=4096; CPUS=1; IPSEC=0; UIO=vfio-pci
WANT_GATE=''' + str(gate) + '''
date(){ echo 2026-11-18T00:00:00Z; }
gen_startup
''')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('plugin default { disable }', result.stdout)
                    for plugin in ('acl', 'abf'):
                        self.assertIn(f'plugin {plugin}_plugin.so {{ enable }}', result.stdout)

    def test_optional_plugins_are_built_and_enabled(self):
        result = self.run_shell(['build_vpp', 'gen_startup'], '''
EXTRA_PLUGINS=nat66,nat_ei_context,wg_nat_order,dns_intercept
VPP_TAG=v26.06; VPP_LIBDIR_REL=lib/vpp-router; JOBS=1; ARCH=aarch64
mkdir -p "$SRC/vpp/src/cmake"
: >"$SRC/vpp/src/cmake/cpu.cmake"
cmake(){ printf '%s\\n' "$@"; }; ninja(){ :; }
build_vpp
cat "$SRC/vpp-configure.log"
SEL=(0); N_KIND=(dpdk); N_PCI=(0000:01:00.0); V_NAME=(port0)
WORKERS=0; MEM_MB=4096; CPUS=1; IPSEC=0; UIO=vfio-pci
gen_startup
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        plugins = next(line.split('=', 1)[1].split(',')
                       for line in result.stdout.splitlines()
                       if line.startswith('-DVPP_PLUGINS='))
        for plugin in ('nat66', 'nat_ei_context', 'wg_nat_order', 'dns_intercept'):
            self.assertIn(plugin, plugins)
            self.assertIn(f'plugin {plugin}_plugin.so {{ enable }}', result.stdout)

    def test_noncoherent_platform_disables_scatter_only_when_selected(self):
        for selected in (0, 1):
            result = self.run_shell(['gen_startup'], '''
SEL=(0); N_KIND=(dpdk); N_PCI=(0000:01:00.0); V_NAME=(wan0)
WORKERS=0; MEM_MB=4096; CPUS=1; IPSEC=0; UIO=uio_pci_generic
RTL_PLATFORM='''+str(selected)+'''
gen_startup
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual('  no-multi-seg' in result.stdout, bool(selected))

    def test_mlx4_disables_scatter_only_when_selected(self):
        for driver, expected in (('mlx4_core', True), ('mlx5_core', False)):
            result = self.run_shell(['gen_startup'], '''
SEL=(0); N_KIND=(mlx); N_IF=(-); N_PCIDRV=('''+driver+'''); N_PCI=(0000:01:00.0); V_NAME=(wan0)
WORKERS=0; MEM_MB=4096; CPUS=1; IPSEC=0; UIO=uio_pci_generic
RTL_PLATFORM=0
gen_startup
''')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual('  no-multi-seg' in result.stdout, expected)

    PORTS = 'PORT_VARS=(PANEL_PORT GATE_DNS_PORT SOCKS_PORT TPROXY_PORT FAKEDNS_PORT)\n' \
            'PANEL_PORT=9480 GATE_DNS_PORT=1053 SOCKS_PORT=1080 TPROXY_PORT=2082 FAKEDNS_PORT=5354\n'
    PORT_FUNCTIONS = ['port_label', 'valid_port', 'port_owner', 'load_ports', 'save_ports']

    def test_ports_come_from_the_environment_then_the_last_install(self):
        result = self.run_shell(self.PORT_FUNCTIONS, self.PORTS + '''
mkdir -p "$STATE"
printf 'PANEL_PORT=8443\\nSOCKS_PORT=01081\\nBOGUS=1\\nFAKEDNS_PORT=53\\n' >"$STATE/ports"
VPP_TPROXY_PORT=12082 load_ports
echo "$PANEL_PORT $GATE_DNS_PORT $SOCKS_PORT $TPROXY_PORT $FAKEDNS_PORT"
save_ports; cat "$STATE/ports"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines[0], '8443 1053 1081 12082 5354')
        self.assertEqual(lines[1:], ['PANEL_PORT=8443', 'GATE_DNS_PORT=1053', 'SOCKS_PORT=1081',
                                     'TPROXY_PORT=12082', 'FAKEDNS_PORT=5354'])

    def test_bad_or_shared_ports_stop_the_install(self):
        for env, message in (('VPP_PANEL_PORT=53', '不是可用的端口'), ('VPP_PANEL_PORT=70000', '不是可用的端口'),
                             ('VPP_SOCKS_PORT=2082', '都用了端口 2082')):
            with self.subTest(env=env):
                result = self.run_shell(self.PORT_FUNCTIONS, self.PORTS + f'''
die(){{ echo "$*" >&2; exit 3; }}
{env} load_ports
''')
                self.assertEqual(result.returncode, 3)
                self.assertIn(message, result.stderr)

    def test_multiport_trunk_uses_installer_names_and_bridges_both_lan_ports(self):
        result = self.run_shell(['wan_if', 'ipsec_wan_name', 'gen_router_vpp'], '''
SEL=(0 1); LAN=(1); N_KIND=(dpdk dpdk); V_NAME=(wan0 lan0)
WAN_NIC=0; SINGLE=0; WAN_TRUNK=1; WAN_VLAN=100; LAN_VLAN=1
LAN_CIDR=10.61.20.1/24; HOST_CIDR=10.61.20.2/24
WAN_MODE=static; WAN_CIDR=10.61.10.2/24; WAN_GW=10.61.10.1
IPSEC=0; HOST_TAP=vpp-host
stable_mac(){ echo 02:00:00:00:00:01; }
wan_if
ipsec_wan_name
gen_router_vpp
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith('wan0.100\nwan0.100\n'))
        for line in ('create sub-interface wan0 100 dot1q 100 exact-match',
                     'set interface l2 bridge wan0 1', 'set interface l2 bridge lan0 1',
                     'set interface l2 bridge tap0 1', 'set interface ip address wan0.100 10.61.10.2/24'):
            self.assertIn(line, result.stdout)

    def test_nat_mode_picks_the_plugin_and_its_commands(self):
        body = '''
SEL=(0); LAN=(); N_KIND=(afp); N_IF=(eth0); V_NAME=(host-eth0); N_PCI=(0000:01:00.0)
WAN_NIC=0; SINGLE=1; WAN_VLAN=100; LAN_VLAN=1
LAN_CIDR=10.61.30.1/24; HOST_CIDR=; WAN_MODE=dhcp; IPV6_PD=0
IPSEC=1; IPSEC_TAP_ID=2082; IPSEC_NS=vpp-ipsec
WORKERS=0; MEM_MB=4096; CPUS=1; UIO=vfio-pci
stable_mac(){ echo 02:00:00:00:00:01; }
date(){ echo 2026-11-24T00:00:00Z; }
NAT_MODE=@MODE@
gen_startup
gen_router_vpp
'''
        names = ['nat44', 'gen_ipsec_vpp', 'gen_startup', 'gen_router_vpp']
        ed = self.run_shell(names, body.replace('@MODE@', 'ed'))
        self.assertEqual(ed.returncode, 0, ed.stderr)
        self.assertIn('plugin nat_plugin.so { enable }', ed.stdout)
        self.assertNotIn('nat44_ei_plugin.so', ed.stdout)
        for line in ('nat44 plugin enable sessions 65536', 'set nat timeout tcp-established 1800 tcp-transitory 120',
                     'nat44 add interface address host-eth0.100', 'set interface nat44 out host-eth0.100 output-feature',
                     'nat44 add identity mapping external host-eth0.100 udp 4500'):
            self.assertIn(line + '\n', ed.stdout)
        self.assertNotIn('nat44 ei', ed.stdout)
        ei = self.run_shell(names, body.replace('@MODE@', 'ei'))
        self.assertEqual(ei.returncode, 0, ei.stderr)
        self.assertIn('plugin nat44_ei_plugin.so { enable }', ei.stdout)
        self.assertNotIn('nat_plugin.so', ei.stdout)
        for line in ('nat44 ei plugin enable sessions 65536 users 4096 user-sessions 16384',
                     'set nat44 ei timeout tcp-established 1800 tcp-transitory 120',
                     'set interface nat44 ei out host-eth0.100 output-feature',
                     'nat44 ei add identity mapping external host-eth0.100 udp 500'):
            self.assertIn(line + '\n', ei.stdout)

    def test_nat_mode_defaults_to_the_installed_plugin(self):
        body = '''
ask(){ printf -v "$1" '%s' "$3"; }
mkdir -p "$CONF"
@CONF@
ask_nat_mode
echo "mode=$NAT_MODE"
'''
        for conf, mode in (('', 'ei'),
                           ("printf 'plugins {\\n  plugin nat44_ei_plugin.so { enable }\\n}\\n' >\"$STARTUP\"", 'ei'),
                           ("printf 'plugins {\\n  plugin nat_plugin.so { enable }\\n}\\n' >\"$STARTUP\"", 'ed')):
            with self.subTest(mode=mode, conf=conf):
                result = self.run_shell(['ask_nat_mode'], body.replace('@CONF@', conf))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('mode=' + mode, result.stdout)

    def test_ipv6_pd_configuration_uses_selected_wan(self):
        body = '''
SEL=(0); LAN=(); N_KIND=(afp); N_IF=(eth0); V_NAME=(host-eth0)
WAN_NIC=0; SINGLE=1; WAN_VLAN=100; LAN_VLAN=1
LAN_CIDR=10.61.30.1/24; HOST_CIDR=; WAN_MODE=dhcp; IPSEC=0
stable_mac(){ echo 02:00:00:00:00:01; }
IPV6_PD=1; gen_router_vpp
'''
        result = self.run_shell(['gen_router_vpp'], body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dhcp6 pd client host-eth0.100 prefix group wan-pd', result.stdout)
        self.assertIn('set ip6 address loop0 prefix group wan-pd ::1/64', result.stdout)
        self.assertLess(result.stdout.index('enable ip6 interface loop0'), result.stdout.index('ip6 nd loop0 ra-interval 10 7'))
        self.assertIn('ip6 nd address autoconfig host-eth0.100 default-route', result.stdout)
        disabled = self.run_shell(['gen_router_vpp'], body.replace('IPV6_PD=1', 'IPV6_PD=0'))
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        self.assertNotIn('dhcp6 pd client', disabled.stdout)

    def test_wan_mac_is_pinned_before_dhcp6_and_kept_across_regeneration(self):
        body = '''
SEL=(0); LAN=(); N_KIND=(dpdk); V_NAME=(port0); N_MAC=(@MAC@)
WAN_NIC=0; SINGLE=1; WAN_VLAN=100; LAN_VLAN=1
LAN_CIDR=10.61.20.1/24; HOST_CIDR=; WAN_MODE=dhcp; IPSEC=0
stable_mac(){ echo 02:00:00:00:00:0$([ "$1" = wan ] && echo 9 || echo 1); }
IPV6_PD=1; gen_router_vpp
'''
        def run(mac, extra=''):
            result = self.run_shell(['wan_mac', 'gen_router_vpp'], extra + body.replace('@MAC@', mac))
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        out = run('AA:BB:CC:00:11:22')
        self.assertIn('set interface mac address port0 aa:bb:cc:00:11:22', out)
        self.assertLess(out.index('set interface mac address port0'), out.index('dhcp6 pd client port0.100'))
        # Unknown (already bound to DPDK) or multicast: a per-machine stable MAC.
        for mac in ('-', '01:00:5e:00:00:01', '00:00:00:00:00:00'):
            self.assertIn('set interface mac address port0 02:00:00:00:00:09', run(mac))
        # A value pinned by an earlier router.vpp wins.
        self.assertIn('set interface mac address port0 66:fd:34:28:ca:8e',
                      run('aa:bb:cc:00:11:22', 'WAN_MAC=66:fd:34:28:ca:8e\n'))
        afp = self.run_shell(['wan_mac', 'gen_router_vpp'], body.replace('N_KIND=(dpdk); V_NAME=(port0)', 'N_KIND=(afp); N_IF=(eth0); V_NAME=(host-eth0)').replace('@MAC@', '-'))
        self.assertNotIn('set interface mac address', afp.stdout)

    def test_pinned_wan_mac_reads_previous_router_vpp(self):
        result = self.run_shell(['pinned_wan_mac'], '''
V_NAME=(wan0); WAN_NIC=0
f=$(mktemp)
printf 'set interface mac address wan01 11:11:11:11:11:11\\nset interface mac address wan0 66:fd:34:28:ca:8e\\n' >"$f"
pinned_wan_mac "$f"; pinned_wan_mac /nonexistent; echo end
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '66:fd:34:28:ca:8e\nend\n')

    def test_lan_ula_is_set_and_advertised(self):
        body = '''
SEL=(0); LAN=(); N_KIND=(afp); N_IF=(eth0); V_NAME=(host-eth0)
WAN_NIC=0; SINGLE=1; WAN_VLAN=100; LAN_VLAN=1
LAN_CIDR=10.61.30.1/24; HOST_CIDR=; WAN_MODE=dhcp; IPSEC=0
stable_mac(){ echo 02:00:00:00:00:01; }
LAN_ULA=fd12:3456:789a::/64; IPV6_PD=0; gen_router_vpp
'''
        alone = self.run_shell(['gen_router_vpp'], body)
        self.assertEqual(alone.returncode, 0, alone.stderr)
        out = alone.stdout
        self.assertIn('set interface ip address loop0 fd12:3456:789a::1/64', out)
        # VPP does not advertise an address's prefix by itself.
        self.assertIn('ip6 nd loop0 prefix fd12:3456:789a::/64 infinite', out)
        self.assertLess(out.index('enable ip6 interface loop0'), out.index('set interface ip address loop0 fd12'))
        self.assertIn('ip6 nd loop0 ra-interval 10 7', out)
        self.assertNotIn('dhcp6 pd client', out)
        # With the delegation, loop0 is set up once.
        both = self.run_shell(['gen_router_vpp'], body.replace('IPV6_PD=0', 'IPV6_PD=1'))
        self.assertEqual(both.returncode, 0, both.stderr)
        self.assertEqual(both.stdout.count('enable ip6 interface loop0'), 1)
        self.assertEqual(both.stdout.count('ip6 nd loop0 ra-interval'), 1)
        self.assertIn('set ip6 address loop0 prefix group wan-pd ::1/64', both.stdout)
        self.assertIn('ip6 nd loop0 prefix fd12:3456:789a::/64 infinite', both.stdout)
        none = self.run_shell(['gen_router_vpp'], body.replace('LAN_ULA=fd12:3456:789a::/64', 'LAN_ULA='))
        self.assertNotIn('fd12', none.stdout)
        self.assertNotIn('ip6', none.stdout)

    def test_lan_ula_is_generated_once_and_kept(self):
        body = '''
ask_yn(){ return 0; }
mkdir -p "$CONF"
ask_lan_ula; echo "first $LAN_ULA"
printf 'set interface ip address loop0 10.61.30.1/24\nset interface ip address loop0 fdab:c65c:8cbc::1/64\n' >"$CONF/router.vpp"
ask_lan_ula; echo "kept $LAN_ULA"
ask_yn(){ return 1; }
ask_lan_ula; echo "declined [$LAN_ULA]"
'''
        result = self.run_shell(['ask_lan_ula'], body)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = dict(line.split(' ', 1) for line in result.stdout.splitlines())
        import ipaddress
        first = ipaddress.ip_network(lines['first'])
        self.assertEqual((first.prefixlen, str(first)[:2]), (64, 'fd'))
        self.assertTrue(first.subnet_of(ipaddress.ip_network('fd00::/8')))
        self.assertEqual(lines['kept'], 'fdab:c65c:8cbc::/64')
        self.assertEqual(lines['declined'], '[]')

    def test_lan_ula_installs_host_slaac_sysctls(self):
        result = self.run_shell(['gen_ipv6_sysctl'], '''
IPV6_PD=0; LAN_ULA=fd12:3456:789a::/64; gen_ipv6_sysctl
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('net.ipv6.conf.vpp-host.accept_ra = 2', result.stdout)

    def test_existing_gate_config_gets_the_lan_ipv6(self):
        body = '''
GATE_CONFIG="$T/egress-gate.json"; GATE_UNIT=vpp-egress-gate.service
note(){ echo "note $*"; }
systemctl(){ echo "systemctl $*"; }
printf '{"upstream": ["10.61.20.2", 53], "lan_prefixes": ["10.61.30.0/24"], "routes": []}' >"$GATE_CONFIG"
chmod 640 "$GATE_CONFIG"
LAN_ULA=fd12:3456:789a::/64; gate_lan_ipv6
cat "$GATE_CONFIG"; stat -c %a "$GATE_CONFIG"
echo ---
gate_lan_ipv6
'''
        result = self.run_shell(['gate_lan_ipv6'], body)
        self.assertEqual(result.returncode, 0, result.stderr)
        first, second = result.stdout.split('---\n')
        import json
        doc = json.loads(first[first.index('{'):first.rindex('}') + 1])
        self.assertEqual(doc['lan_prefixes'], ['10.61.30.0/24', 'fd12:3456:789a::/64'])
        self.assertEqual(doc['lan_interfaces'], ['loop0'])
        self.assertIn('systemctl try-restart vpp-egress-gate.service', first)
        self.assertIn('\n640\n', first)
        # Nothing more to add: nothing written, Gate left alone.
        self.assertEqual(second, '')

    def test_ipv6_pd_installs_host_slaac_sysctls(self):
        result = self.run_shell(['gen_ipv6_sysctl'], '''
IPV6_PD=1; gen_ipv6_sysctl
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('net.ipv6.conf.vpp-host.accept_ra = 2', result.stdout)
        self.assertIn('net.ipv6.conf.vpp-host.autoconf = 1', result.stdout)

        disabled = self.run_shell(['gen_ipv6_sysctl'], '''
IPV6_PD=0; gen_ipv6_sysctl
''')
        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        self.assertEqual(disabled.stdout, '')

        self.assertIn('sysctl -qw "net.ipv6.conf.$HOST_TAP.accept_ra=2"', SOURCE)
        self.assertIn('"net.ipv6.conf.$HOST_TAP.autoconf=1"', SOURCE)

    def test_fresh_install_creates_manifest_parent(self):
        result = self.run_shell(['check_prefix', 'manifest_has', 'panel_tools', 'install_vpp'], '''
PANEL_TOOLS=(vpp-monitor vpp-interfaces vpp-wireguard vpp-firewall vpp-system)
WANT_GATE=0; WANT_SINGBOX=0
gate_present(){ return 1; }
mkdir -p "$SRC/vpp/src/vpp-api/python/vpp_papi"
mkdir -p "$SRC/tools-bin"
for tool in "${PANEL_TOOLS[@]}"; do touch "$SRC/tools-bin/$tool"; done
python_dir(){ echo "$PREFIX/lib/python3/site-packages"; }
cmake(){
    mkdir -p "$DESTDIR$PREFIX/bin" "$DESTDIR$LIBDIR/vpp_plugins"
    touch "$DESTDIR$PREFIX/bin/vpp" "$DESTDIR$PREFIX/bin/vppctl" "$DESTDIR$LIBDIR/vpp_plugins/dpdk_plugin.so"
    chmod +x "$DESTDIR$PREFIX/bin/"*
}
write_ctl(){ :; }; prepare_reconfigure(){ :; }; remove_old_prefix(){ :; }
prune_private_dirs(){ :; }; tar(){ :; }; ldd(){ :; }; git(){ :; }
install_vpp
test -s "$MANIFEST"
for tool in "${PANEL_TOOLS[@]}"; do
    grep -qxF "$PREFIX/bin/$tool" "$MANIFEST"
done
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def check_ssh(self, device, server, old_interface='eth0', local_device=None):
        return self.run_shell(['check_management_path'], f'''
mkdir -p "$CONF"
printf '%s\\n' 'HOST_TAP=vpp-host' 'NICS=("lan - {old_interface} afp lan0")' >"$CONF/router.env"
SSH_CONNECTION='10.61.30.10 12345 {server} 22'
systemctl(){{ return 0; }}
ip(){{
    if [ "$1" = route ]; then echo '10.61.30.10 dev {device} src {server}';
    else echo '2: {local_device or device} inet {server}/24'; fi
}}
check_management_path
''')

    def test_ssh_over_tap_is_rejected_before_stop(self):
        result = self.check_ssh('vpp-host', '10.61.30.2')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('当前 SSH 经过 VPP', result.stderr)

    def test_ssh_over_old_physical_interface_is_rejected(self):
        self.assertNotEqual(self.check_ssh('eth0', '10.61.30.2').returncode, 0)

    def test_independent_management_interface_is_allowed(self):
        result = self.check_ssh('mgmt0', '10.0.0.2')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_tap_address_is_rejected_even_with_independent_return_route(self):
        result = self.check_ssh('mgmt0', '10.61.30.2', local_device='vpp-host')
        self.assertNotEqual(result.returncode, 0)

    def test_old_controller_restores_before_configuration_changes(self):
        result = self.run_shell(['prepare_reconfigure'], '''
mkdir -p "$CONF"
echo old-config >"$CONF/router.env"
check_management_path(){ echo guard; }
installed_ctl(){ echo old_ctl; }
old_ctl(){ test "$(cat "$CONF/router.env")" = old-config; echo "$1"; }
prepare_reconfigure
echo new-config >"$CONF/router.env"
echo rewritten
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['guard', 'restore', 'rewritten'])

    def test_restore_failure_prevents_reconfiguration(self):
        result = self.run_shell(['prepare_reconfigure'], '''
mkdir -p "$CONF"; touch "$CONF/router.env"
check_management_path(){ :; }; installed_ctl(){ echo old_ctl; }
old_ctl(){ return 1; }
prepare_reconfigure
echo rewritten
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('rewritten', result.stdout)

    def test_stop_failure_prevents_restore_and_reconfiguration(self):
        result = self.run_shell(['prepare_reconfigure'], '''
mkdir -p "$CONF"; touch "$CONF/router.env"
check_management_path(){ :; }; installed_ctl(){ echo old_ctl; }
systemctl(){ [ "$1" = is-active ]; }
old_ctl(){ echo restored; }
prepare_reconfigure
echo rewritten
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('restored', result.stdout)
        self.assertNotIn('rewritten', result.stdout)

    def test_dpdk_retries_missing_dependency_after_meson_failure(self):
        result = self.run_shell(['driver_path', 'configure_dpdk'], '''
mkdir -p "$SRC/dpdk/drivers/common/ionic"
touch "$SRC/dpdk/drivers/common/ionic/meson.build"
drivers=(net/ionic); opts=(--dummy); log="$T/meson.log"
meson(){
    case "$*" in
    *common/ionic*) echo configured ;;
    *) echo 'Message: Disabling ionic: missing internal dependency "common_ionic"'; return 1 ;;
    esac
}
configure_dpdk
printf '%s\\n' "${drivers[@]}"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('common/ionic', result.stdout)

    def test_dpdk_reports_unrelated_meson_failure(self):
        result = self.run_shell(['driver_path', 'configure_dpdk'], '''
drivers=(net/ionic); opts=(--dummy); log="$T/meson.log"
meson(){ echo 'compiler error'; return 1; }
configure_dpdk
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('compiler error', result.stdout)

    def test_old_generated_startup_is_moved_and_package_original_restored(self):
        result = self.run_shell(['migrate_startup'], '''
mkdir -p "$CONF" "$STATE"
echo '# 由 vpp-router-install.sh 生成' >"$CONF/startup.conf"
echo package >"$STATE/startup.conf.orig"
migrate_startup
cat "$CONF/startup.conf"; grep -c vpp-router-install.sh "$STATE/startup.conf.bak"
test ! -e "$STATE/startup.conf.orig"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['package', '1'])

    def test_package_startup_is_left_alone(self):
        result = self.run_shell(['migrate_startup'], '''
mkdir -p "$CONF" "$STATE"
echo package >"$CONF/startup.conf"
migrate_startup
cat "$CONF/startup.conf"; test ! -e "$STATE/startup.conf.bak"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'package\n')

    def test_write_config_never_writes_startup_conf(self):
        result = self.run_shell(['write_config'], '''
mkdir -p "$CONF"; echo '# vpp-router-install.sh old' >"$CONF/startup.conf"
gen_startup(){ echo '# vpp-router-install.sh startup'; }
gen_router_vpp(){ :; }; gen_env(){ :; }; pinned_wan_mac(){ :; }; save_ports(){ :; }
DNSMASQ=0; write_dnsmasq(){ :; }
write_config
cat "$CONF/startup.conf"; cat "$CONF/router.conf"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        # 旧单元仍指向 startup.conf，迁移留到 write_units 之后
        self.assertEqual(result.stdout.splitlines(), ['# vpp-router-install.sh old', '# vpp-router-install.sh startup'])

    def test_system_dnsmasq_state_is_recorded_once(self):
        result = self.run_shell(['disable_system_dnsmasq'], '''
SYSTEM_DNSMASQ="$STATE/system-dnsmasq"
systemctl(){ case $1 in is-enabled) echo "${EN:-enabled}" ;; is-active) echo active ;; *) echo "$*" >>"$T/calls" ;; esac; }
disable_system_dnsmasq
EN=masked disable_system_dnsmasq
cat "$SYSTEM_DNSMASQ" "$T/calls"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['enabled active'] + ['disable dnsmasq.service', 'mask dnsmasq.service'] * 2)

    def test_startup_migrates_only_after_units_point_to_router_conf(self):
        main = function('main')
        self.assertLess(main.index('\twrite_units\n'), main.index('\tmigrate_startup\n'))
        self.assertNotIn('migrate_startup', function('write_config'))

    def distro(self, state, active, answer, body='ask_distro_vpp; echo "mask=$MASK_DISTRO"'):
        return self.run_shell(['ask_distro_vpp'], f'''
systemctl(){{
    case $1 in
    is-enabled) echo {state} ;;
    is-active) return {0 if active else 1} ;;
    esac
}}
ask_yn(){{ return {0 if answer else 1}; }}
{body}
''')

    def test_distro_vpp_declined_while_enabled_stops_install(self):
        result = self.distro('enabled', False, False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('mask=', result.stdout)

    def test_distro_vpp_declined_while_disabled_continues(self):
        result = self.distro('disabled', False, False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'mask=0\n')

    def test_distro_vpp_absent_or_masked_is_not_asked(self):
        for state in ('', 'masked'):
            result = self.distro(state, False, False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'mask=0\n')

    def test_mask_records_first_state_and_uninstall_restores_it(self):
        result = self.run_shell(['mask_distro_vpp', 'unmask_distro_vpp'], '''
STATEFILE="$T/unit"; echo enabled >"$STATEFILE"
systemctl(){
    echo "$*" >>"$T/calls"
    case $1 in
    is-enabled) cat "$STATEFILE" ;;
    mask) echo masked >"$STATEFILE" ;;
    esac
}
MASK_DISTRO=1
mask_distro_vpp; mask_distro_vpp
cat "$DISTRO_MASKED"
unmask_distro_vpp
test ! -e "$DISTRO_MASKED"
grep -c '^mask' "$T/calls"; grep -x 'enable vpp.service' "$T/calls"; grep -c -- '--now vpp' "$T/calls"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['enabled', '2', 'enable vpp.service', '2'])

if __name__ == '__main__':
    unittest.main()
