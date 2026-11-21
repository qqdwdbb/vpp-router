#!/usr/bin/env python3
"""Joint PD publisher / DNS gate recovery on the private LAN fixture."""
import json
import re
import sys
from pathlib import Path
import time


class Recovery:
    def __init__(self, root, names, unit, run, nsrun, cli, spawn, wait, commands, lease, query):
        self.root, self.names, self.unit = root, names, unit
        self.run, self.nsrun, self.cli, self.spawn, self.wait = run, nsrun, cli, spawn, wait
        self.commands, self.lease, self.query = commands, lease, query
        self.dropin = None

    def verify(self, runtime, gate, dnsmasq):
        client, dns, wan = self.names
        root = self.root
        linux = []
        def ip(name, *args):
            linux.append(['ip', '-n', name, *args])
        old_indices = {}
        for name in self.names:
            link = json.loads(self.nsrun(name, 'ip', '-j', 'link', 'show', 'mgmt0'))[0]
            old_indices[name] = link['ifindex']
            ip(name, 'link', 'set', 'mgmt0', 'down')
            ip(name, 'link', 'set', 'mgmt0', 'address', link['address'])
            ip(name, 'link', 'set', 'mgmt0', 'up')
        ip(client, 'address', 'replace', self.lease['address']+'/24', 'dev', 'mgmt0')
        ip(client, 'route', 'replace', 'default', 'via', self.lease['gateway'])
        linux.append(['ip','netns','exec',client,'sysctl','-qw',
                      'net.ipv6.conf.mgmt0.accept_ra=2','net.ipv6.conf.mgmt0.autoconf=1'])
        ip(dns, 'address', 'del', '198.18.44.2/24', 'dev', 'mgmt0')
        ip(dns, 'link', 'set', 'mgmt0', 'master', 'br-mgmt')
        ip(wan, '-6', 'address', 'replace', '2001:db8:45::2/64', 'dev', 'mgmt0', 'nodad')
        link_macs = {name: json.loads(self.nsrun(name, 'ip', '-j', 'link', 'show', 'mgmt0'))[0]['address']
                     for name in self.names}
        macs = {name:re.search(r'Ethernet address ([0-9a-f:]{17})',
                    self.cli('show hardware-interfaces '+name))[1]
                for name in ('loop3950','tap3950','tap3951','tap3952')}
        commands = []
        for command in self.commands:
            if command.startswith('create tap id '):
                ident = int(command.split()[3])
                peer_mac = link_macs[self.names[ident - 3950]]
                commands.append(command + ' host-mac-addr ' + peer_mac)
                name = 'tap' + str(ident)
                commands.append('set interface mac address ' + name + ' ' + macs[name])
                if ident == 3952:
                    commands.append('set ip neighbor tap3952 198.18.45.2 ' + peer_mac)
            else:
                commands.append(command)
                if command.startswith('create loopback interface '):
                    commands.append('set interface mac address loop3950 ' + macs['loop3950'])
        (root/'rebuild.json').write_text(json.dumps({'vpp_commands':commands,
                                                   'linux_commands':linux,'outer6':False}))
        directory = Path('/run/systemd/system')/(self.unit+'.service.d')
        directory.mkdir(mode=0o700)
        self.dropin = directory
        release = root/'rebuild-release'
        (directory/'rebuild.conf').write_text('[Service]\nExecStartPre=/usr/bin/python3 '+
            str(Path(__file__).resolve())+' --wait-release '+str(release)+
            '\nExecStartPost=/usr/bin/python3 '
            '/opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipsec_lifecycle.py --rebuild '+str(root)+'\n')
        self.run('systemctl','daemon-reload')
        old_pid = self.run('systemctl','show',self.unit,'--property=MainPID','--value').strip()
        old_socket = (root/'cli.sock').stat().st_ino
        publisher = runtime['publisher']
        pool = root/'ipsec.conf'
        pool_text, pool_stamp = pool.read_text(), pool.stat().st_mtime_ns
        for process in (runtime['pd_server'],runtime['ra_capture']):
            process.terminate();process.wait(timeout=5)
        self.run('systemctl','restart','--no-block',self.unit)
        self.wait(lambda: not Path('/proc',old_pid).exists() and
                  self.run('systemctl','show',self.unit,'--property=ActiveState','--value').strip() == 'activating',
                  'VPP did not enter the controlled restart outage')
        # Query the surviving gate directly, without the destroyed LAN TAP.
        direct = self.query.replace('(host,53)', '(host,1053)')
        for mode in ('udp','tcp'):
            self.nsrun(dns,'python3','-c',direct,'outage.altroute.test',mode,'fail','198.18.44.2')
        time.sleep(.5)
        assert publisher.poll() is None and gate.poll() is None and dnsmasq.poll() is None
        assert pool.read_text() == pool_text and pool.stat().st_mtime_ns == pool_stamp, 'API outage withdrew PD pool'
        release.write_text('continue\n')
        self.wait(lambda:self.run('systemctl','show',self.unit,'--property=ActiveState','--value').strip() == 'active',
                  'VPP restart did not finish rebuilding',seconds=30)
        self.wait(lambda:(root/'rebuild-ready').exists(),'LAN rebuild did not finish')
        assert self.run('systemctl','show',self.unit,'--property=MainPID','--value').strip() != old_pid
        assert (root/'cli.sock').stat().st_ino != old_socket, 'VPP generation did not change'
        for name in self.names:
            link = json.loads(self.nsrun(name,'ip','-j','link','show','mgmt0'))[0]
            assert link['ifindex'] != old_indices[name], 'Fixture TAP was not recreated'
        self.wait(lambda:any(a['scope']=='link' and 'tentative' not in a
                  for link in json.loads(self.nsrun(wan,'ip','-j','-6','addr','show','dev','mgmt0'))
                  for a in link['addr_info']), 'Rebuilt upstream link-local DAD incomplete')
        # These are test facilities bound to the old interface indices, not the
        # publisher/gate whose recovery is under test.
        script = '/opt/vpp-vrouter-migration/source/tests/integration_vrouter_ipv6_pd.py'
        for name in ('pd-ready','ra-capture-ready'):
            (root/name).unlink(missing_ok=True)
        self.spawn(client,'python3',script,'--capture',str(root))
        self.spawn(wan,'python3',script,'--serve',str(root))
        self.wait(lambda:(root/'pd-ready').exists() and (root/'ra-capture-ready').exists(),
                  'Rebound PD/RA test facilities did not start')
        self.wait(runtime['wan_address'],'Rebuilt VPP did not acquire WAN SLAAC',seconds=20)
        self.nsrun(wan,'ip','-6','route','replace','2001:db8:4400::/56','via',runtime['wan_address']())
        first = runtime['first']
        self.wait(lambda:runtime['pool_ready'](first) and
                  json.loads((root/'pd-state.json').read_text()).get('vpp_generation') == (root/'cli.sock').stat().st_ino,
                  'Publisher did not recover VPN pool in the new generation',seconds=25)
        self.wait(lambda:runtime['address_for'](first),'Client SLAAC did not recover',seconds=20)
        self.wait(lambda:'wg1' in self.cli('show ip fib table 0 198.51.100.77/32'),
                  'Gate did not restore IPv4 route')
        self.wait(lambda:'loop3950' in self.cli('show ip6 fib table 0 2001:db8:2080::77/128'),
                  'Gate did not restore IPv6 route')
        for mode in ('udp','tcp'):
            self.nsrun(client,'python3','-c',self.query,'a.altroute.test',mode,'ok')
            self.nsrun(client,'python3','-c',self.query,mode+'.six.test',mode,'ok',
                       'fd42:1111:2222:10::2','28')
        import subprocess
        def wan_ready(family, target):
            args = ['ip','netns','exec',client,'ping','-n']
            if family == 6:
                args += ['-6','-I',runtime['address_for'](first)]
            result = subprocess.run(args+['-c','1','-W','1',target],
                                    capture_output=True,text=True,timeout=3)
            (root/('recovery-wan'+str(family)+'-ping.log')).write_text(result.stdout+result.stderr)
            return result.returncode == 0
        for family,target in ((6,'2001:db8:45::2'),(4,'198.18.45.2')):
            self.wait(lambda:wan_ready(family,target),
                      'WAN did not converge after rebuild: IPv'+str(family),seconds=12)
        self.nsrun(client,'ping','-6','-n','-I',runtime['address_for'](first),'-c','2','-W','2','2001:db8:45::2')
        self.nsrun(client,'ping','-n','-c','2','-W','2','198.18.45.2')
        lease = json.loads(self.nsrun(client,'python3','/opt/vpp-vrouter-migration/source/tests/vrouter_dhcp_client.py'))
        assert lease['address']==self.lease['address'] and lease['renewal']
        assert publisher.poll() is None and gate.poll() is None and dnsmasq.poll() is None
        return {'vpp_rebuilt':True,'all_taps_recreated':True,'publisher_gate_dnsmasq_survived':True,
                'api_outage_preserved_pool':True,'dns_during_outage_failed_closed':True,
                'native_pd_reacquired':True,'vpn_pool_recovered':True,'client_slaac_recovered':True,
                'ipv4_ipv6_gate_routes_recovered':True,'udp_tcp_dns_both_families':True,
                'dhcp_renewal_after_rebuild':True,'ipv4_ipv6_wan_after_rebuild':True,
                'pd_upstream_and_ra_capture_rebound':True}

    def close(self):
        if self.dropin:
            (self.dropin/'rebuild.conf').unlink()
            self.dropin.rmdir()
            self.run('systemctl','daemon-reload')


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '--wait-release':
        raise SystemExit('Use integration_vrouter_lan_services.py --ipv6 --recovery')
    deadline = time.monotonic()+20
    while not Path(sys.argv[2]).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('Private restart outage was not released')
        time.sleep(.05)
