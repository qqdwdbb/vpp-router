#!/usr/bin/env python3
"""Real DHCPv6-PD renewal coupled to strongSwan EAP pool reconnects."""
import ipaddress as ip
import json
from pathlib import Path
import re
import tempfile

BASE = Path('/opt/vpp-vrouter-migration')


class PDScenario:
    def __init__(self, root, names, run, wait, cli, start):
        self.root, self.names = root, names
        self.run, self.wait, self.cli, self.start = run, wait, cli, start
        self.runtime = tempfile.TemporaryDirectory(prefix='vrouter-ipsec-pd-', dir='/run')
        self.config_path = root/'pd-sync.json'
        self.pool = root/'server/ipsec.conf'
        self.prefixes = ['2001:db8:61::/64', '2001:db8:71::/64', '2001:db8:81::/64']
        self.state = Path(self.runtime.name)/'state.json'
        self.config = {'vpp_socket':str(root/'cli.sock'), 'lan_interface':'tap3962',
                       'wan_interface':'tap3960', 'prefix_group':'wan-pd',
                       'interval_seconds':.25, 'ra_max_interval_seconds':4, 'withdraw_seconds':5,
                       'state_file':str(self.state), 'ipsec_config':str(self.pool),
                       'dhcp_lease_file':str(root/'no-leases'), 'ipsec_pool_routes':True}
        run('ip','-n',names['client'],'-6','addr','add','2001:db8:45::2/64','dev','mgmt0','nodad')
        cli('ip6 nd tap3960 ra-suppress')
        cli('ip6 nd tap3962 ra-interval 4 3 ra-lifetime 30')
        (root/'pd-prefix').write_text(self.prefixes[0])
        start(['ip','netns','exec',names['client'],'python3',
               str(BASE/'source/tests/integration_vrouter_ipv6_pd.py'),'--serve',str(root)], 'pd-server.log')
        wait(lambda:(root/'pd-ready').exists(), 'PD server did not start')
        wait(lambda: any(a['scope']=='link' and 'tentative' not in a
                         for i in json.loads(run('ip','-n',names['client'],'-j','-6','address','show','dev','mgmt0'))
                         for a in i['addr_info']), 'PD server link-local DAD incomplete')
        cli('dhcp6 pd client tap3960 prefix group wan-pd')
        cli('set ip6 address tap3962 prefix group wan-pd ::1/64')
        cli('ip6 nd address autoconfig tap3960 default-route')
        self.publisher = self.start_publisher()
        self.wait_pool(self.prefixes[0])

    def start_publisher(self):
        self.config_path.write_text(json.dumps(self.config))
        return self.start(['python3',str(BASE/'source/scripts/vrouter/ipv6/pd-sync.py'),
                           '--config',str(self.config_path)], 'pd-publisher.log')

    def attach_reload(self, process):
        self.publisher.terminate()
        self.publisher.wait(timeout=5)
        self.config['ipsec_reload_command'] = ['kill','-HUP',str(process.pid)]
        self.publisher = self.start_publisher()

    def wait_pool(self, prefix):
        def ready():
            if not self.state.exists():
                return False
            data = json.loads(self.state.read_text())
            return data.get('pool_prefix') == prefix and (prefix is None or data.get('ipsec_routes'))
        self.wait(ready, 'PD pool publication did not converge', 25)
        text = self.pool.read_text()
        assert text.count('rightsourceip=10.254.61.100-10.254.61.200')==2
        assert 'rightauth=eap-mschapv2' in text
        conn, assigned = None, {}
        for line in text.splitlines():
            if line.startswith('conn '):
                conn = line.split()[1]
            if 'rightsourceip=' in line and conn:
                assigned[conn] = line
        assert '%default' in assigned and 'eap-mschapv2' in assigned
        if prefix:
            net = ip.ip_network(prefix)
            expected = f'{net.network_address+0x100}-{net.network_address+0x200}'
            assert expected in assigned['%default']
            assert expected not in assigned['eap-mschapv2']
        else:
            assert '2001:db8:' not in assigned['%default']
        eap_v6 = [item.strip() for item in assigned['eap-mschapv2'].split('=', 1)[1].split(',') if ':' in item]
        assert eap_v6 and ip.IPv6Address(eap_v6[0].split('/')[0].split('-')[0]) in ip.IPv6Network('fc00::/7')

    def verify(self, daemons, client_status):
        def stroke(role, *args):
            return self.run('nsenter','-t',str(daemons[role].pid),'-m','-n','/usr/lib/ipsec/stroke',*args)
        def sources():
            data=json.loads(self.run('ip','-n',self.names['client'],'-j','address','show'))
            addresses=[ip.ip_address(a['local']) for i in data for a in i['addr_info']]
            v4=[str(a) for a in addresses if a.version==4 and a in ip.ip_network('10.254.61.0/24')]
            v6=[str(a) for a in addresses if a.version==6 and any(a in ip.ip_network(n) for n in self.prefixes)]
            assert len(v4)==1 and len(v6)<=1
            return v4[0], v6[0] if v6 else None
        def ping(source, destination):
            # Neighbour resolution is excluded from the functional burst.
            import subprocess
            subprocess.run(['ip','netns','exec',self.names['client'],'ping','-I',source,'-c','1','-W','1',destination],capture_output=True,timeout=3)
            out=self.run('ip','netns','exec',self.names['client'],'ping','-I',source,'-n','-c','3','-i','.1','-W','2',destination)
            assert '3 packets transmitted, 3 received' in out
        # Persistent dual-family echo servers for each reconnect phase.
        echo='''import socket,threading
from pathlib import Path
import sys
def serve(family,host,port):
 s=socket.socket(family,socket.SOCK_STREAM)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((host,port));s.listen(8);Path(sys.argv[1]+str(port)).touch()
 while True:
  c,a=s.accept()
  with c:
   while True:
    d=c.recv(16384)
    if not d:break
    c.sendall(d)
threading.Thread(target=serve,args=(socket.AF_INET,'10.254.62.2',49873),daemon=True).start()
serve(socket.AF_INET6,'2001:db8:62::2',49872)
'''
        self.start(['ip','netns','exec',self.names['lan'],'python3','-u','-c',echo,str(self.root/'pd-echo-')], 'pd-echo.log')
        self.wait(lambda:all((self.root/('pd-echo-'+str(p))).exists() for p in (49872,49873)), 'PD echo server failed')
        exchange='''import socket,os,threading,sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(10);s.bind((sys.argv[1],0));s.connect((sys.argv[2],int(sys.argv[3])))
data=os.urandom(65536)
def send():s.sendall(data);s.shutdown(socket.SHUT_WR)
t=threading.Thread(target=send);t.start();out=b''
while True:
 d=s.recv(16384)
 if not d:break
 out+=d
t.join();assert out==data;s.close()
'''
        def check_traffic(expected):
            v4,v6=sources()
            assert (v6 is not None)==(expected is not None)
            ping(v4,'10.254.62.2')
            pairs=[(v4,'10.254.62.2',49873)]
            if expected:
                net=ip.ip_network(expected)
                assert net.network_address+0x100 <= ip.ip_address(v6) <= net.network_address+0x200
                ping(v6,'2001:db8:62::2')
                pairs.append((v6,'2001:db8:62::2',49872))
                fib=self.cli('show ip6 fib '+str(net.network_address+0x100)+'/120')
                assert 'tap3960' in fib, 'Pool return route did not reach WAN SPD'
            for source,destination,port in pairs:
                self.run('ip','netns','exec',self.names['client'],'python3','-c',exchange,source,destination,str(port))
            assert not self.run('ip','netns','exec',self.names['server'],'ip','xfrm','state').strip()
            return {'pool_prefix':expected,'source4':v4,'source6':v6,'tcp_64k':True,'server_linux_xfrm_empty':True}
        def reconnect(expected):
            stroke('client','down','lab')
            self.wait(lambda:not re.findall(r'(?m)^\[', self.cli('show ipsec sa')), 'Old SAs not removed')
            self.wait(lambda:'INSTALLED, TUNNEL' not in client_status(), 'Client did not disconnect')
            stroke('client','up','lab')
            self.wait(lambda:'INSTALLED, TUNNEL' in client_status(), 'Reconnect did not install CHILD_SA',35)
            return check_traffic(expected)
        marker=(self.root/'server/run/charon.pid').read_text().strip()
        original_ike=re.findall(r'lab\[(\d+)\]: ESTABLISHED',client_status())
        stamp=self.pool.stat().st_mtime_ns
        events=self.root/'pd-events.jsonl'
        count=events.read_text().count('"kind": 5')
        self.wait(lambda:events.read_text().count('"kind": 5')>=count+2, 'Repeated PD renewals missing',15)
        assert self.pool.stat().st_mtime_ns==stamp, 'Same-prefix renewal rewrote pool'
        phases=[check_traffic(self.prefixes[0])]
        for prefix in (self.prefixes[1],None,self.prefixes[2]):
            reloads=(self.root/'server-charon.log').read_text().count("added configuration 'lab'")
            (self.root/'pd-prefix').write_text(prefix or 'none')
            self.wait_pool(prefix)
            self.wait(lambda:(self.root/'server-charon.log').read_text().count("added configuration 'lab'")>reloads,
                      'starter did not reload the changed pool')
            if prefix:
                # Confirm starter applied the new connection/pool, not just the file.
                needle=str(ip.ip_network(prefix).network_address+0x100)
                self.wait(lambda:needle in stroke('server','statusall'), 'strongSwan did not reload new pool')
            assert (self.root/'server/run/charon.pid').read_text().strip()==marker, 'charon restarted on pool update'
            assert re.findall(r'lab\[(\d+)\]: ESTABLISHED',client_status())==original_ike, 'Existing IKE was terminated'
            ping(sources()[0],'10.254.62.2')
            phases.append(reconnect(prefix))
            original_ike=re.findall(r'lab\[(\d+)\]: ESTABLISHED',client_status())
        return {'real_dhcpv6_pd':True,'same_prefix_pool_mtime_unchanged':True,
                'pool_reload_without_charon_restart':True,'existing_ipv4_survives_pool_update':True,
                'renumber_withdraw_recover_reconnect':True,'phases':phases}

    def close(self):
        self.runtime.cleanup()
