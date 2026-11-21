"""Real private strongSwan joined to the staged startup service dependency chain."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from integration_vrouter_ipsec_lifecycle import Lifecycle, UnitProcess, properties

SOURCE = Path(__file__).resolve().parents[2]
STARTUP = SOURCE / 'deploy/startup'


class StartupChain(Lifecycle):
    def __init__(self, *args):
        super().__init__(*args)
        self.chain = {}
        self.unit_files = []
        self.host_ns = 'vrouter-chain-host-' + str(os.getpid())

    def prepare_rebuild(self, commands, names, outer6, mtu):
        self.names = names
        self.run('ip', 'netns', 'add', self.host_ns)
        self.run('ip', '-n', self.host_ns, 'link', 'set', 'lo', 'up')
        extra = [
            'create bridge-domain 200', 'create loopback interface instance 200',
            'set interface l2 bridge loop200 200 bvi',
            'set interface mac address loop200 52:54:00:20:00:01',
            'set interface ip address loop200 10.61.20.1/24',
            'set interface ip address loop200 fd42:1111:2222:10::1/64',
            'set interface state loop200 up',
            f'create tap id 3963 host-ns {self.host_ns} host-if-name vpp-lan host-mac-addr 52:54:00:20:00:02',
            'set interface l2 bridge tap3963 200',
            'set interface rx-mode tap3963 interrupt', 'set interface state tap3963 up',
            'nat44 ei plugin enable sessions 4096',
            'nat44 ei add interface address tap3960',
            'nat44 ei add identity mapping external tap3960',
            'set interface nat44 ei out tap3960 output-feature',
            'nat44 ei output-chain tap3960']
        for command in extra:
            self.cli(command)
        super().prepare_rebuild(commands + extra, names, outer6, mtu)

    def cli(self, command):
        result = subprocess.run(['/opt/vpp-nic1-test/vpp/bin/vppctl', '-s', str(self.root/'cli.sock'), command],
                                env=self.env, capture_output=True, text=True, timeout=10)
        if result.returncode or re.search(r'unknown input|error:|failed|invalid', result.stdout, re.I):
            raise RuntimeError('Private startup VPP command rejected')
        return result.stdout

    def write_unit(self, template, name, overrides):
        text = (STARTUP/template).read_text()
        replacements = {'vrouter-vpp.service': self.vpp_unit, 'vrouter-strongswan.service': self.server_unit,
                        **{f'vrouter-{key}.service': value for key, value in self.chain.items()}}
        for old, new in replacements.items():
            text = text.replace(old, new)
        text = text.replace('/opt/vpp-vrouter-migration/source', str(SOURCE))
        lines, section = [], None
        def finish():
            if section in overrides:
                lines.extend(f'{key}={value}' for key, value in overrides[section].items())
        for line in text.splitlines():
            if line.startswith('['):
                finish()
                section = line[1:-1]
            if '=' in line and not line.startswith('#') and line.split('=', 1)[0] in overrides.get(section, {}):
                continue
            lines.append(line)
        finish()
        path = Path('/run/systemd/system')/name
        path.write_text('\n'.join(lines)+'\n')
        self.unit_files.append(path)
        self.units.append(name)

    def start(self, args, server=False):
        if not server:
            return super().start(args)
        root = self.root
        self.chain = {key: f'vrouter-chain-{os.getpid()}-{key}.service'
                      for key in ('network-prep', 'firewall', 'dns-route-gate', 'pd-sync')}
        def config(name, data):
            path = root/name
            path.write_text(json.dumps(data))
            return path
        prep = config('prep.json', {'bridge':'br-mgmt', 'lan_tap':'vpp-lan',
            'vpp_socket':str(root/'cli.sock'), 'netns':self.host_ns, 'nftsets_path':None})
        fw = config('firewall.json', {'vpp':{'socket':str(root/'cli.sock'),
            'wan_interface':'tap3960', 'wan_ipv4':'198.18.60.1', 'wan_gateway4':'198.18.60.2',
            'lan_interfaces':['tap3962'], 'lan_ipv4':'10.254.62.0/24',
            'lan_ipv6':'2001:db8:62::/64', 'vpp_gw4':'10.254.62.1', 'vpp_gw6':'2001:db8:62::1'},
            'nftables':{'ruleset_path':str(SOURCE/'deploy/firewall/vrouter-firewall.nft')}})
        (root/'sets.nft').write_text('table inet chain_routes {\n set altroute {\n type ipv4_addr;\n flags interval;\n }\n}\n')
        routes = config('routes.json', {'mappings':[{'family':'inet','table':'chain_routes','set':'altroute',
            'interface':'loop200','via':'10.61.20.2','fib_table':0}],
            'state_file':str(root/'gate-state.json'), 'state_socket':str(root/'gate.sock'),
            'vpp_socket':str(root/'cli.sock'),'api_socket':str(root/'api.sock'), 'vpp_service':self.vpp_unit})
        (root/'rules').mkdir()
        (root/'seen.json').write_text('[]')
        gate = config('gate.json', {'sync_program':str(SOURCE/'tools/nftset-route-sync.py'),
            'route_config':str(routes),'rules_directory':str(root/'rules'),'lease_file':str(root/'seen.json'),
            'upstream':['127.0.0.1',5353], 'listen':[['10.61.20.2',1053]]})
        # Run the real PD poller without rewriting this test's fixed dual-stack lease.
        # Pool rollover/withdrawal is covered by the separate real IPsec PD scenario.
        self.pd_state = Path(f'/run/vrouter-chain-pd-{os.getpid()}/state.json')
        pd = config('pd.json', {'vpp_socket':str(root/'cli.sock'), 'state_file':str(self.pd_state),
            'lan_interface':'loop200','wan_interface':'tap3960','prefix_group':'wan-pd',
            'withdraw_seconds':5,'interval_seconds':1,'ra_max_interval_seconds':2})
        helper = STARTUP/'vrouter-network-prep.py'
        self.write_unit('vrouter-network-prep.service', self.chain['network-prep'], {'Service':{
            'ExecStart':f'/usr/bin/python3 {helper} --action start --config {prep}',
            'ExecStop':f'/usr/bin/python3 {helper} --action stop --config {prep}'}})
        helper = SOURCE/'deploy/firewall/vrouter-firewall.py'
        self.write_unit('vrouter-firewall.service', self.chain['firewall'], {'Service':{
            'ExecStart':f'/usr/bin/python3 {helper} --apply --config {fw} --netns {self.host_ns}',
            'ExecStop':f'/usr/bin/python3 {helper} --flush --config {fw} --netns {self.host_ns}'}})
        self.write_unit('vrouter-strongswan.service', self.server_unit, {'Service':{
            'NetworkNamespacePath':f'/run/netns/{self.names["server"]}',
            'RuntimeDirectory':f'vrouter-chain-ike-{os.getpid()}',
            'BindReadOnlyPaths':f'{root}:/run/vpp',
            'BindPaths':f'{root}/server/run:/run {root}/server/ipsec.d:/etc/ipsec.d {root}/server/plugins:/usr/lib/ipsec/plugins',
            'Environment':f'STRONGSWAN_CONF={root}/server/strongswan.conf LD_LIBRARY_PATH={self.env["LD_LIBRARY_PATH"]} PATH={self.env["PATH"]}',
            'ExecStart':f'/usr/lib/ipsec/starter --daemon charon --nofork --conf {root}/server/ipsec.conf',
            'ExecStartPost':f'/usr/bin/python3 {STARTUP}/vrouter-strongswan-ready.py --pid $MAINPID --socket /run/vpp/cli.sock --conn lab --timeout 25'}})
        self.write_unit('vrouter-dns-route-gate.service', self.chain['dns-route-gate'], {'Service':{
            'NetworkNamespacePath':f'/run/netns/{self.host_ns}',
            'ExecStartPre':f'/usr/sbin/nft -f {root}/sets.nft',
            'ExecStart':f'/usr/bin/python3 {SOURCE}/scripts/dns-route-gate.py --config {gate}',
            'RuntimeDirectory':f'vrouter-chain-gate-{os.getpid()}',
            'StateDirectory':f'vrouter-chain-gate-{os.getpid()}'} })
        self.write_unit('vrouter-pd-sync.service', self.chain['pd-sync'], {'Service':{
            'ExecStart':f'/usr/bin/python3 {SOURCE}/scripts/vrouter/ipv6/pd-sync.py --config {pd}',
            'RuntimeDirectory':f'vrouter-chain-pd-{os.getpid()}'}})
        self.run('systemctl','daemon-reload')
        # VPP's real readiness/rebuild hook runs before any dependent is launched.
        self.run('systemctl','restart',self.vpp_unit,timeout=60)
        self.run('systemctl','start',self.chain['pd-sync'],self.chain['dns-route-gate'],timeout=60)
        self.wait(lambda: all(properties(u).get('ActiveState') == 'active'
                             for u in [self.vpp_unit,self.server_unit,*self.chain.values()]),
                  'Full private startup chain did not become active',40)
        self.assert_order()
        self.check_services()
        return UnitProcess(self.server_unit)

    def assert_order(self):
        def stamp(unit, field):
            value = int(properties(unit).get(field, '0'))
            assert value > 0, 'Missing systemd lifecycle timestamp'
            return value
        ready = 'ActiveEnterTimestampMonotonic'
        started = 'ExecMainStartTimestampMonotonic'
        assert stamp(self.vpp_unit, ready) <= stamp(self.chain['network-prep'], started)
        assert stamp(self.chain['network-prep'], ready) <= stamp(self.chain['firewall'], started)
        for consumer in (self.server_unit, self.chain['dns-route-gate']):
            assert stamp(self.chain['firewall'], ready) <= stamp(consumer, started)
        assert stamp(self.server_unit, ready) <= stamp(self.chain['pd-sync'], started)

    def check_services(self):
        self.run('ip','netns','exec',self.host_ns,'ping','-c','2','-W','2','10.61.20.1')
        # Warm both sides of LAN ARP/ND before measuring encrypted packet loss.
        for family, gateway in (('-4','10.254.62.1'),('-6','2001:db8:62::1')):
            self.run('ip','netns','exec',self.names['lan'],'ping',family,'-c','2','-W','2',gateway)
        self.run('ip','netns','exec',self.host_ns,'nft','add','element','inet','chain_routes','altroute',
                 '{','198.51.100.88','}')
        self.wait(lambda:'198.51.100.88/32' in self.cli('show ip fib table 0 198.51.100.88/32'),
                  'DNS gate did not reconcile into current VPP',25)
        self.wait(lambda:self.pd_state.exists() and
                  json.loads(self.pd_state.read_text()).get('vpp_generation') ==
                  (self.root/'cli.sock').stat().st_ino, 'PD poller did not follow VPP generation',25)

    def verify(self, daemons, cli, status, exchange):
        features = cli('show interface features tap3960').split('ip4-output:', 1)[1].split('\n\n', 1)[0]
        nat = 'nat44-ei-in2out-output-worker-handoff' if 'worker-handoff' in features else 'nat44-ei-in2out-output'
        assert features.index('ipsec4-output-feature') < features.index(nat) < features.index('nat-ei-context-exit') < features.index('acl-plugin-out-ip4-fa'), features
        features6 = cli('show interface features tap3960').split('ip6-output:', 1)[1].split('\n\n', 1)[0]
        assert features6.index('ipsec6-output-feature') < features6.index('acl-plugin-out-ip6-fa'), features6
        old = {u:properties(u).get('MainPID') for u in [self.vpp_unit,self.server_unit,
               self.chain['dns-route-gate'], self.chain['pd-sync']]}
        self.run('systemctl','restart',self.vpp_unit,timeout=60)
        self.wait(lambda:all(properties(u).get('ActiveState') == 'active' and
                            properties(u).get('MainPID') not in ('0', old[u]) for u in old),
                  'Full chain did not restart with VPP',40)
        self.assert_order()
        # The gate nft set survives, so do not insert the same element again.
        self.wait(lambda:'198.51.100.88/32' in cli('show ip fib table 0 198.51.100.88/32'),
                  'DNS gate did not restore route after restart',25)
        self.wait(lambda:json.loads(self.pd_state.read_text()).get('vpp_generation') ==
                  (self.root/'cli.sock').stat().st_ino, 'PD generation stale after restart',25)
        for family, gateway in (('-4','10.254.62.1'),('-6','2001:db8:62::1')):
            self.run('ip','netns','exec',self.names['lan'],'ping',family,'-c','2','-W','2',gateway)
        self.runtime_after_rebuild = cli('show runtime')
        self.run('nsenter','-t',str(daemons['client'].pid),'-m','-n','/usr/lib/ipsec/stroke','down','lab')
        self.run('nsenter','-t',str(daemons['client'].pid),'-m','-n','/usr/lib/ipsec/stroke','up','lab')
        self.wait(lambda:'INSTALLED, TUNNEL' in status(), 'EAP reconnect failed after chain restart',35)
        exchange()
        return {'real_strongswan_template_start':True,'private_runtime_and_network':True,
                'firewall_precedes_ike_and_dns':True,'network_prep_connectivity':True,
                'dns_gate_fib_restore':True,'pd_poller_generation_restore':True,
                'vpp_restart_full_chain':True,'eap_reconnect_dual_stack_tcp':True,
                'output_feature_order':features.strip().splitlines(),
                'ipv6_output_feature_order':features6.strip().splitlines()}

    def stop_dependency(self):
        super().stop_dependency()
        self.wait(lambda:all(properties(u).get('ActiveState') not in ('active','activating','deactivating')
                            for u in self.chain.values()), 'Startup dependents did not stop',25)
        return True

    def close(self):
        super().close()
        for path in self.unit_files:
            path.unlink(missing_ok=True)
        self.run('systemctl','daemon-reload')
        subprocess.run(['systemctl','reset-failed',*self.chain.values(),self.server_unit],capture_output=True)
        subprocess.run(['ip','netns','delete',self.host_ns],capture_output=True)
        shutil.rmtree(f'/var/lib/vrouter-chain-gate-{os.getpid()}', ignore_errors=True)
