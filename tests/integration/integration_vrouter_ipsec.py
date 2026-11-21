#!/usr/bin/env python3
"""Isolated strongSwan control plane / VPP ESP datapath validation on VROUTER.

Uses disposable PSKs or certificate/EAP credentials, private mount + network namespaces and private plugins.
Never loads production connections/secrets or changes production daemons.
"""
import argparse
import json
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time

BASE = Path('/opt/vpp-vrouter-migration')
VPP = Path('/opt/vpp-nic1-test/vpp')


def run(*args, timeout=15):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError('Command failed: ' + args[0])
    return p.stdout


def wait(check, message, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if check():
            return
        time.sleep(.1)
    raise RuntimeError(message)


def launcher(root, role):
    # Enter network namespace before /run (including /run/netns) is hidden.
    run('mount', '--bind', str(root/role/'plugins'), '/usr/lib/ipsec/plugins')
    run('mount', '--bind', str(root/role/'run'), '/run')
    run('mount', '--bind', str(root/role/'ipsec.d'), '/etc/ipsec.d')
    os.environ['STRONGSWAN_CONF'] = str(root/role/'strongswan.conf')
    os.execv('/usr/lib/ipsec/starter', ['starter', '--nofork', '--conf', str(root/role/'ipsec.conf')])


def main(workers, nat=False, eap=False, bad_password=False, pd=False, outer6=False, native_esp=False, wan_mtu=1500, pmtu=False, diagnose=False, outer_injection=False, vnet_library_dir=None, lifecycle=False, startup_chain=False, plugin_path=None, nat66_inbound_order=False):
    assert not nat66_inbound_order or (outer6 and eap), 'NAT66 input ordering requires outer IPv6 EAP'
    if startup_chain:
        assert eap and not nat, 'Startup chain requires EAP without the separate input-NAT scenario'
        lifecycle = True
    assert not lifecycle or (eap and not any((bad_password, pd, pmtu, diagnose, outer_injection))), 'Lifecycle requires a separate successful EAP scenario'
    assert not outer_injection or (outer6 and eap and not pmtu and not diagnose and not pd and not bad_password), 'Outer injection requires separate outer6 EAP scenario'
    pmtu = pmtu or diagnose
    assert not pmtu or (outer6 and eap and not pd and not bad_password), 'PMTU requires outer6 EAP'
    assert wan_mtu == 1500 or outer6, 'Custom MTU requires outer6'
    assert not native_esp or outer6, 'Native ESP mode currently requires outer IPv6'
    assert not (pd and outer6), 'PD and outer IPv6 are separate validation scenarios'
    assert not pd or (eap and not bad_password), 'PD test requires successful EAP mode'
    assert not bad_password or eap, 'Wrong-password test requires EAP'
    os.umask(0o077)
    names = {role: 'vrouter-ipsec-' + role for role in ('server', 'client', 'lan')}
    if outer6:
        names['wire']='vrouter-ipsec-wire'
    assert all(name not in run('ip', 'netns', 'list') for name in names.values())
    children, created, logs = [], [], []
    pd_scenario = None
    lifecycle_scenario = None
    library_dir = Path(vnet_library_dir) if vnet_library_dir else BASE/'ipv6-pd/lib'
    assert (library_dir/'libvnet.so').is_file(), 'Selected libvnet unavailable'
    env = dict(os.environ, PATH=str(VPP/'bin')+':'+os.environ['PATH'], LD_LIBRARY_PATH=str(library_dir) + ':' +
               '/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:' + str(VPP/'lib/aarch64-linux-gnu'))
    with tempfile.TemporaryDirectory(prefix='ipsec-lab-', dir=BASE/'strongswan-build') as directory:
        root = Path(directory)
        try:
            for name in names.values():
                run('ip', 'netns', 'add', name)
                created.append(name)
                run('ip', '-n', name, 'link', 'set', 'lo', 'up')
            (root/'bin').mkdir()
            shutil.copy2(VPP/'bin/vpp', root/'bin/vpp')
            shutil.copytree(BASE/'crypto_engines', root/'lib/aarch64-linux-gnu/vpp_crypto_engines')
            (root/'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {root} cli-listen {root}/cli.sock }}
api-segment {{ prefix {root.name} }}
socksvr {{ socket-name {root}/api.sock }}
statseg {{ socket-name {root}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
{'cpu { main-core 4 corelist-workers 5-6 }' if workers else ''}
plugins {{ path {plugin_path or BASE/"plugins"}
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
plugin ipsec_ike_punt_plugin.so {{ enable }}
{'plugin nat44_ei_plugin.so { enable }' if nat or startup_chain else ''}
{'plugin nat_ei_context_plugin.so { enable }' if nat or startup_chain else ''}
{'plugin dhcp_plugin.so { enable }' if pd or startup_chain else ''}
{'plugin acl_plugin.so { enable }' if startup_chain else ''}
{'plugin mss_clamp_plugin.so { enable }' if pmtu else ''}
{'plugin nat66_plugin.so { enable }' if nat66_inbound_order else ''}
}}
''')
            def start(args, log, **kwargs):
                handle = (root/log).open('w')
                logs.append(handle)
                p = subprocess.Popen(args, stdout=handle, stderr=handle, env=env,
                                     start_new_session=True, **kwargs)
                children.append(p)
                return p
            if lifecycle:
                if startup_chain:
                    from integration_vrouter_ipsec_startup import StartupChain as Lifecycle
                else:
                    from integration_vrouter_ipsec_lifecycle import Lifecycle
                lifecycle_scenario = Lifecycle(root, env, run, wait)
            vpp_args = [str(root/'bin/vpp'), '-c', str(root/'startup.conf')]
            vpp_process = lifecycle_scenario.start(vpp_args) if lifecycle else start(vpp_args, 'vpp.log')
            wait(lambda: (root/'cli.sock').exists(), 'VPP startup failed')
            assert str(library_dir.resolve())+'/' in Path(f'/proc/{vpp_process.pid}/maps').read_text(), 'Selected libvnet not loaded'
            def cli(command):
                return subprocess.run([str(VPP/'bin/vppctl'), '-s', str(root/'cli.sock'), command],
                                      env=env, capture_output=True, text=True, timeout=15, check=True).stdout
            topology_commands = []
            def command(text):
                output = cli(text)
                if re.search(r'unknown input|error:|failed|invalid', output, re.I):
                    raise RuntimeError('VPP configuration rejected: ' + text)
                topology_commands.append(text)
                return output
            for ident, role, host, local, hostif in (
                (3960, 'client', '198.18.60.2/24', '198.18.60.1/24', 'mgmt0'),
                (3961, 'server', '172.31.246.2/30', '172.31.246.1/30', 'tap3960'),
                (3962, 'lan', '10.254.62.2/24', '10.254.62.1/24', 'mgmt0')):
                target = names['wire'] if outer6 and role=='client' else names[role]
                address = '' if outer6 and role=='client' else ' host-ip4-addr '+host
                command(f'create tap id {ident} host-ns {target} host-if-name {hostif}{address}'+
                        (f' host-mtu-size {wan_mtu if role=="client" else 1500}' if outer6 else ''))
                if lifecycle:
                    command(f'set interface mac address tap{ident} 02:76:00:00:{ident >> 8:02x}:{ident & 255:02x}')
                command(f'set interface ip address tap{ident} {local}')
                if outer6:
                    command(f'set interface mtu packet {wan_mtu if role=="client" else 1500} tap{ident}')
                command(f'set interface state tap{ident} up')
                command(f'set interface rx-mode tap{ident} interrupt')
            if outer6:
                # Capture on an independent L2 bridge, before Linux XFRM can
                # re-inject decrypted packets into client packet sockets.
                run('ip','-n',names['wire'],'link','add','br-wire','type','bridge')
                run('ip','-n',names['wire'],'link','add','to-client','type','veth',
                    'peer','name','mgmt0','netns',names['client'])
                for device in ('mgmt0','to-client'):
                    run('ip','-n',names['wire'],'link','set',device,'master','br-wire')
                    run('ip','-n',names['wire'],'link','set',device,'up')
                run('ip','-n',names['wire'],'link','set','br-wire','up')
                run('ip','-n',names['client'],'link','set','mgmt0','up')
                run('ip','-n',names['client'],'address','add','198.18.60.2/24','dev','mgmt0')
            if outer6:
                for role, devices in (('wire', ('mgmt0','to-client','br-wire')), ('client', ('mgmt0',))):
                    for device in devices:
                        run('ip','-n',names[role],'link','set',device,'mtu',str(wan_mtu))
            command('set interface ip address tap3960 2001:db8:60::1/64')
            command('set interface ip address tap3962 2001:db8:62::1/64')
            run('ip', '-n', names['client'], '-6', 'addr', 'add', '2001:db8:60::2/64', 'dev', 'mgmt0', 'nodad')
            if not eap:
                run('ip', '-n', names['client'], '-6', 'addr', 'add', '2001:db8:61::1/128', 'dev', 'lo', 'nodad')
            run('ip', '-n', names['client'], '-6', 'route', 'add', '2001:db8:62::/64', 'via', '2001:db8:60::1')
            run('ip', '-n', names['lan'], '-6', 'addr', 'add', '2001:db8:62::2/64', 'dev', 'mgmt0', 'nodad')
            run('ip', '-n', names['lan'], '-6', 'route', 'add', 'default', 'via', '2001:db8:62::1')
            if not pd:
                command('ip route add 2001:db8:61::/64 via 2001:db8:60::2 tap3960')
            run('ip', '-n', names['server'], 'addr', 'add', '198.18.60.1/32', 'dev', 'tap3960')
            run('ip', '-n', names['server'], 'route', 'add', 'default', 'via', '172.31.246.1')
            if outer6:
                command('set interface ip address tap3961 fd76:7070:3961::1/64')
                run('ip','-n',names['server'],'-6','addr','add','fd76:7070:3961::2/64','dev','tap3960','nodad')
                run('ip','-n',names['server'],'-6','addr','add','2001:db8:60::1/128','dev','tap3960','nodad')
                run('ip','-n',names['server'],'-6','route','add','default','via','fd76:7070:3961::1')
                command('ip6 nd tap3961 ra-suppress')
            if not eap:
                run('ip', '-n', names['client'], 'addr', 'add', '10.254.61.1/32', 'dev', 'lo')
            run('ip', '-n', names['client'], 'route', 'add', '10.254.62.0/24', 'via', '198.18.60.1')
            run('ip', '-n', names['lan'], 'route', 'add', 'default', 'via', '10.254.62.1')
            command('ip route add 10.254.61.0/24 via 198.18.60.2 tap3960')
            command('ipsec ike punt enable')
            command('set punt udp 500')
            command('ip punt redirect rx tap3960 via 172.31.246.2 tap3961')
            if outer6:
                command('set punt ip6 udp 500')
                command('ip6 punt redirect rx tap3960 via fd76:7070:3961::2 tap3961')
            # IPv6 cleartext also needs an enabled IPv6 FIB on control ingress
            # when IKE itself uses only IPv4.
            if not outer6:
                command('enable ip6 interface tap3961')
            command('ipsec cleartext ingress tap3961')
            if nat66_inbound_order:
                command('nat66 plugin enable')
                command('set interface nat66 out tap3960')
            if nat:
                command('nat44 ei plugin enable sessions 4096')
                command('nat44 ei add address 10.254.62.1')
                command('set interface nat44 ei in tap3961 out tap3962')
            segment = '/' + root.name + '-vpe-api'
            assert (Path('/dev/shm')/segment[1:]).exists(), 'Unexpected VPP API SHM name'
            key = secrets.token_hex(32)
            if eap:
                pki = root/'pki'
                pki.mkdir()
                run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                    '-subj','/CN=VROUTER isolated test CA','-addext','basicConstraints=critical,CA:TRUE',
                    '-keyout',str(pki/'ca.key'),'-out',str(pki/'ca.pem'))
                run('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=lab-server',
                    '-keyout',str(pki/'server.key'),'-out',str(pki/'server.csr'))
                (pki/'extensions').write_text('subjectAltName=DNS:lab-server\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2\n')
                run('openssl','x509','-req','-in',str(pki/'server.csr'),'-CA',str(pki/'ca.pem'),
                    '-CAkey',str(pki/'ca.key'),'-CAcreateserial','-days','1',
                    '-extfile',str(pki/'extensions'),'-out',str(pki/'server.pem'))
            outer_capture = None
            if outer6:
                outer_capture = start(['ip','netns','exec',names['wire'],'python3',
                                       str(BASE/'source/tests/integration_vrouter_ipsec_outer.py'),str(root),str(wan_mtu), 'to-client' if lifecycle else 'mgmt0'], 'outer-capture.log')
                wait(lambda:(root/'outer-capture-ready').exists(), 'Outer IPv6 capture did not start')
            if lifecycle_scenario:
                lifecycle_scenario.prepare_rebuild(topology_commands, names, outer6, wan_mtu)
            daemons = {}
            for role in ('server', 'client'):
                private = root/role
                (private/'run').mkdir(parents=True)
                for subdir in ('cacerts','certs','private'):
                    (private/'ipsec.d'/subdir).mkdir(parents=True)
                if eap:
                    shutil.copy2(root/'pki/ca.pem',private/'ipsec.d/cacerts/ca.pem')
                    if role == 'server':
                        shutil.copy2(root/'pki/server.pem',private/'ipsec.d/certs/server.pem')
                        shutil.copy2(root/'pki/server.key',private/'ipsec.d/private/server.key')
                shutil.copytree('/usr/lib/ipsec/plugins', private/'plugins')
                if role == 'server':
                    shutil.copy2(BASE/'strongswan-build/vpp-sswan-5.9/libstrongswan-kernel-vpp.so',
                                 private/'plugins/libstrongswan-kernel-vpp.so')
                if eap:
                    password = secrets.token_hex(32) if bad_password and role == 'client' else key
                    (private/'secrets').write_text(f'lab-user : EAP "{password}"\n' +
                                                  (': RSA server.key\n' if role == 'server' else ''))
                else:
                    (private/'secrets').write_text(f'@lab-server @lab-client : PSK "{key}"\n')
                (private/'strongswan.conf').write_text(f'''charon {{
load_modular = no
load = random nonce x509 pubkey pkcs1 pkcs8 pem openssl hmac kdf {'kernel-vpp!' if role == 'server' else ''} kernel-netlink socket-default stroke {'eap-identity eap-mschapv2' if eap else ''}
install_routes = no
install_virtual_ip_on = lo
filelog {{
lab {{ path = {root}/{role}-charon.log
default = 2
flush_line = yes
}}
}}
plugins {{
kernel-vpp {{ api_prefix = {root.name}
read_timeout = 5000
use_tunnel_mode_sa = yes
}}
stroke {{ secrets_file = {private}/secrets }}
}}
}}
''')
                left, right = ('198.18.60.1', '198.18.60.2') if role == 'server' else ('198.18.60.2', '198.18.60.1')
                if outer6:
                    left,right = ('2001:db8:60::1','2001:db8:60::2') if role=='server' else ('2001:db8:60::2','2001:db8:60::1')
                leftid, rightid = ('server', 'client') if role == 'server' else ('client', 'server')
                leftnet, rightnet = ('10.254.62.0/24', '10.254.61.0/24') if role == 'server' else ('10.254.61.0/24', '10.254.62.0/24')
                (private/'ipsec.conf').write_text(f'''config setup
    uniqueids=no
conn lab
    keyexchange=ikev2
    authby=psk
    left={left}
    leftid=@lab-{leftid}
    leftsubnet={leftnet},2001:db8:{'62' if role == 'server' else '61'}::/64
    right={right}
    rightid=@lab-{rightid}
    rightsubnet={rightnet},2001:db8:{'61' if role == 'server' else '62'}::/64
    ike=aes128-sha256-modp2048!
    esp=aes128gcm16!
    forceencaps={'no' if native_esp else 'yes'}
    mobike=no
    auto={'add' if role == 'server' else 'start'}
''')
                if eap:
                    auth = ('leftauth=pubkey\n    leftcert=server.pem\n    rightauth=eap-mschapv2\n    rightid=%any\n    eap_identity=%identity\n    rightsourceip=10.254.61.100-10.254.61.200,2001:db8:61::100-2001:db8:61::200' if role == 'server' else
                            'leftauth=eap-mschapv2\n    leftid=lab-user\n    eap_identity=lab-user\n    leftsourceip=%config4,%config6\n    rightauth=pubkey\n    rightid=@lab-server')
                    selectors = ('leftsubnet=10.254.62.0/24,2001:db8:62::/64' if role == 'server' else
                                 'rightsubnet=10.254.62.0/24,2001:db8:62::/64')
                    (private/'ipsec.conf').write_text(f'''config setup
    uniqueids=no
conn lab
    keyexchange=ikev2
    left={left}
    right={right}
    {'leftid=@lab-server' if role == 'server' else ''}
    {auth}
    {selectors}
    ike=aes128-sha256-modp2048!
    esp=aes128gcm16!
    forceencaps={'no' if native_esp else 'yes'}
    mobike=no
    auto={'add' if role == 'server' else 'start'}
''')
                if pd and role == 'server':
                    # Match the two production pool directives (default + profile).
                    target = private/'ipsec.conf'
                    target.write_text(target.read_text().replace('conn lab',
                        'conn %default\n    rightsourceip=10.254.61.100-10.254.61.200\nconn lab',1))
                    from integration_vrouter_ipsec_pd import PDScenario
                    pd_scenario = PDScenario(root,names,run,wait,command,start)
                launch_args = ['ip','netns','exec',names[role], 'unshare','--mount','--propagation','private',
                               'python3',str(Path(__file__).resolve()),'--launch',str(root),role]
                daemons[role] = lifecycle_scenario.start(launch_args, server=True) if lifecycle and role == 'server' else start(launch_args, role+'.log')
                wait(lambda: (private/'run/charon.pid').exists() or daemons[role].poll() is not None,
                     role + ' charon did not start')
                if daemons[role].poll() is not None:
                    raise RuntimeError(role + ' starter exited')
                if role == 'server':
                    wait(lambda: 'strongswan' in cli('show api clients'), 'strongSwan did not connect VPP API')
            if pd_scenario:
                pd_scenario.attach_reload(daemons['server'])
            def status():
                return run('nsenter','-t',str(daemons['client'].pid),'-m','-n','/usr/lib/ipsec/stroke','statusall')
            if bad_password:
                wait(lambda: re.search(r'EAP.*(failed|failure)', (root/'server-charon.log').read_text(), re.I),
                     'Wrong EAP password was not explicitly rejected', 25)
                assert 'INSTALLED, TUNNEL' not in status()
                assert not re.findall(r'(?m)^\[', cli('show ipsec sa')), 'Wrong credentials installed VPP SAs'
                assert not run('ip','netns','exec',names['server'],'ip','xfrm','state').strip()
                result = {'workers':workers, 'wrong_eap_password_rejected':True,
                          'vpp_sa_count':0, 'server_linux_xfrm_empty':True}
                (BASE/'logs'/f'ipsec-workers{workers}-eap-rejected.json').write_text(json.dumps(result,indent=2)+'\n')
                print(json.dumps(result))
                return
            wait(lambda: 'INSTALLED, TUNNEL' in status(), 'IKE CHILD_SA installation failed', 35)
            source4, source6 = '10.254.61.1', '2001:db8:61::1'
            if eap:
                addresses = json.loads(run('ip','-n',names['client'],'-j','address','show'))
                assigned = [ipaddress.ip_address(a['local']) for iface in addresses for a in iface['addr_info']]
                v4 = [a for a in assigned if a.version==4 and a in ipaddress.ip_network('10.254.61.0/24')]
                v6 = [a for a in assigned if a.version==6 and a in ipaddress.ip_network('2001:db8:61::/64')]
                assert len(v4)==len(v6)==1, 'Dual-stack virtual IPs missing'
                assert ipaddress.ip_address('10.254.61.100') <= v4[0] <= ipaddress.ip_address('10.254.61.200')
                assert ipaddress.ip_address('2001:db8:61::100') <= v6[0] <= ipaddress.ip_address('2001:db8:61::200')
                source4, source6 = str(v4[0]), str(v6[0])
                assert re.search(r'EAP method EAP_MSCHAPV2 succeeded', (root/'server-charon.log').read_text())
                assert re.search(r"authentication of 'lab-server' with RSA.*successful", (root/'client-charon.log').read_text())
            server_status = run('nsenter','-t',str(daemons['server'].pid),'-m','-n','/usr/lib/ipsec/stroke','statusall')
            assert 'kernel-vpp' in server_status and 'INSTALLED, TUNNEL' in server_status
            if nat66_inbound_order:
                features = cli('show interface features tap3960').split('ip6-unicast:', 1)[1].split('\n\n', 1)[0]
                assert features.index('ipsec6-input-feature') < features.index('nat66-out2in'), features
            assert not run('ip','netns','exec',names['server'],'ip','xfrm','state').strip(), 'Server used Linux XFRM'
            # SA output includes keys: capture internally and never log it.
            sa = cli('show ipsec sa')
            assert len(re.findall(r'(?m)^\[', sa)) >= 2, 'VPP SA pair missing'
            if outer6:
                headers=re.findall(r'(?m)^\[.*$',sa)
                assert all('tunnel-v6' in line for line in headers), 'VPP did not install IPv6 outer SAs'
                assert all(('udp-encap' in line)==(not native_esp) for line in headers), 'Unexpected ESP encapsulation'
            before = cli('show runtime')
            if startup_chain:
                command('trace add tap-input 64')
            subprocess.run(['ip','netns','exec',names['client'],'ping','-I',source4,
                            '-n','-c','1','-W','2','10.254.62.2'], capture_output=True, timeout=4)
            output = run('ip','netns','exec',names['client'],'ping','-I',source4,'-n','-c','5','-i','.1','-W','2','10.254.62.2')
            (root/'ping.log').write_text(output)
            (root/'errors.log').write_text(cli('show errors'))
            (root/'runtime.log').write_text(cli('show runtime'))
            assert re.search(r'5 packets transmitted, 5 received', output), 'Encrypted forwarded ping failed'
            for source, target in [(source6, '2001:db8:62::2')]:
                subprocess.run(['ip','netns','exec',names['client'],'ping','-I',source,'-c','1','-W','2',target],
                               capture_output=True, timeout=4)
                out = run('ip','netns','exec',names['client'],'ping','-I',source,'-n','-c','5','-i','.1','-W','2',target)
                assert '5 packets transmitted, 5 received' in out, 'IPv6 inner traffic failed'
            if outer_injection:
                from integration_vrouter_ipsec_inject import verify
                injected=verify(root,names,source6,wan_mtu,native_esp,run,wait,start,cli)
                run('nsenter','-t',str(daemons['client'].pid),'-m','-n','/usr/lib/ipsec/stroke','down','lab')
                wait(lambda:not re.findall(r'(?m)^\[',cli('show ipsec sa')),'SAs remained after outer injection')
                os.kill(outer_capture.pid,signal.SIGUSR1)
                wait(lambda:(root/'outer-capture.json').exists(),'Outer injection capture missing')
                counters=json.loads((root/'outer-capture.json').read_text())
                assert all(c['plaintext_leak']==c['ipv4_ipsec']==c['oversize_l3']==0 for c in counters.values()), 'Wire isolation/MTU assertion failed'
                result={'workers':workers,'natt':not native_esp,'wan_mtu':wan_mtu,'outer_injection':injected,
                        'outer_packets':counters,'sa_removed_after_disconnect':True,'server_linux_xfrm_empty':True}
                path=BASE/'logs'/f'ipsec-outer-injection-w{workers}-mtu{wan_mtu}-{"native" if native_esp else "natt"}.json'
                path.write_text(json.dumps(result,indent=2)+'\n')
                print(json.dumps({'workers':workers,'mtu':wan_mtu,'native':native_esp,'passed':injected['passed']}))
                return
            syn_capture = None
            if pmtu:
                syn_capture=start(['ip','netns','exec',names['lan'],'python3',
                    str(BASE/'source/tests/integration_vrouter_ipsec_pmtu.py'),str(root)],'tcp-syn.log')
                wait(lambda:(root/'tcp-syn-ready').exists(),'TCP SYN capture missing')
            echo = '''import socket,threading,sys,struct,json
from pathlib import Path
def serve(family,host,port):
 s=socket.socket(family,socket.SOCK_STREAM)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((host,port));s.listen(1)
 Path(sys.argv[1]+str(port)).touch()
 for attempt in range(int(sys.argv[2])):
  c,a=s.accept()
  Path(sys.argv[1]+str(port)+"-source").write_text(a[0])
  with c:
   while True:
    d=c.recv(16384)
    if not d:break
    c.sendall(d)
   info=c.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)
   Path(sys.argv[1]+str(port)+'-tcp').write_text(json.dumps({'effective_mss':c.getsockopt(socket.IPPROTO_TCP,socket.TCP_MAXSEG),'total_retrans':struct.unpack_from('I',info,100)[0]}))
 s.close()
a=threading.Thread(target=serve,args=(socket.AF_INET,'10.254.62.2',49870));a.start()
serve(socket.AF_INET6,'2001:db8:62::2',49871);a.join()
'''
            start(['ip','netns','exec',names['lan'],'python3','-u','-c',echo,str(root/'echo-ready-'),str(6 if lifecycle else 1)], 'echo.log')
            wait(lambda: all((root/('echo-ready-'+str(p))).exists() for p in (49870,49871)), 'Echo listener failed')
            client = '''import socket,sys,os,threading,struct,json
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(10);s.bind((sys.argv[1],0));s.connect((sys.argv[2],int(sys.argv[3])))
data=os.urandom(int(sys.argv[4]))
def send():s.sendall(data);s.shutdown(socket.SHUT_WR)
t=threading.Thread(target=send);t.start();received=b''
while True:
 d=s.recv(16384)
 if not d:break
 received+=d
t.join();assert received==data,'TCP content mismatch'
info=s.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,104)
print(json.dumps({'bytes':len(data),'effective_mss':s.getsockopt(socket.IPPROTO_TCP,socket.TCP_MAXSEG),'total_retrans':struct.unpack_from('I',info,100)[0]}));s.close()
'''
            tcp_metrics = {}
            for source,target,port in [(source4,'10.254.62.2',49870),(source6,'2001:db8:62::2',49871)]:
                if startup_chain:
                    cli('clear trace')
                    cli('trace add tap-input 32')
                probe=subprocess.run(['ip','netns','exec',names['client'],'python3','-c',client,source,target,str(port),str(262144 if pmtu else 65536)],
                                     capture_output=True,text=True,timeout=20)
                (root/f'tcp-{port}.log').write_text(probe.stdout+probe.stderr)
                if probe.returncode:
                    if outer_capture:
                        os.kill(outer_capture.pid,signal.SIGUSR1)
                        wait(lambda:(root/'outer-capture.json').exists(),'Missing failure capture')
                        (root/'outer-counters.log').write_text((root/'outer-capture.json').read_text())
                    (root/'tcp-errors.log').write_text(cli('show errors'))
                    (root/'tcp-interfaces.log').write_text(cli('show hardware-interfaces')+
                        run('ip','-n',names['client'],'-d','link','show')+
                        cli('show interface'))
                    raise RuntimeError('TCP content validation failed on port '+str(port))
                wait(lambda:(root/f'echo-ready-{port}-tcp').exists(),'TCP server metrics missing')
                tcp_metrics[str(port)]={'client':json.loads(probe.stdout),'server':json.loads((root/f'echo-ready-{port}-tcp').read_text())}
            if syn_capture:
                os.kill(syn_capture.pid,signal.SIGUSR1)
                wait(lambda:(root/'tcp-syn.json').exists(),'TCP SYN snapshot missing')
                tcp_metrics['syn_packets']=json.loads((root/'tcp-syn.json').read_text())
                assert all(any(p['family']==family and p['syn_ack']==ack and p['mss'] for p in tcp_metrics['syn_packets'])
                           for family in (4,6) for ack in (False,True)), 'TCP SYN MSS evidence missing'
            assert (root/'echo-ready-49870-source').read_text() == ('10.254.62.1' if nat else source4)
            assert (root/'echo-ready-49871-source').read_text() == source6
            pmtu_result = None
            if pmtu:
                from integration_vrouter_ipsec_pmtu import verify
                pmtu_result = verify(root, names, source4, source6, wan_mtu, native_esp, run, cli, outer_capture, wait, start, echo, client, diagnose=diagnose)
            if diagnose:
                after = cli('show runtime')
                def vectors(text, node):
                    return sum(int(n) for n in re.findall(r'(?m)^'+re.escape(node)+r'\s+\S+\s+\d+\s+(\d+)', text))
                delta = {n: vectors(after,n)-vectors(before,n) for n in ('esp4-encrypt','esp6-encrypt','esp6-decrypt' if outer6 else 'esp4-decrypt','ipsec-cleartext-input') + (('ipsec-cleartext6-input',) if startup_chain else ())}
                result = {'workers': workers, 'authentication': 'certificate-eap-mschapv2' if eap else 'psk',
                          'dynamic_dual_stack_pool': eap, 'source4': source4, 'source6': source6,
                          'strongswan_kernel_vpp': True, 'vpp_sa_pair': True,
                          'server_linux_xfrm_empty': True, 'outer_family':6 if outer6 else 4,
                          'natt':not native_esp, 'wan_mtu':wan_mtu if outer6 else None, 'pmtu':pmtu_result,
                          'capture_location':'isolated_l2_bridge' if outer6 else None,
                          'nat44_ei': nat, 'tcp_source_addresses_verified': True,
                          'diagnose': True, 'child_sa_rekey': False, 'reconnect_verified': False,
                          'forwarded_ping': True, 'ipv6_inner_ping': True,
                          'tcp_64k_both_families': True, 'tcp_metrics':tcp_metrics,
                          'node_packet_deltas': delta}
                path = BASE/'logs'/f'ipsec-workers{workers}{"-eap" if eap else ""}{"-ei" if nat else ""}{"-outer6" if outer6 else ""}{"-native" if native_esp else ""}-pmtu-{wan_mtu}-diagnose.json'
                path.write_text(json.dumps(result, indent=2)+'\n')
                print(json.dumps({k:v for k,v in result.items() if not k.startswith(('runtime_', 'vpp_crypto_'))}))
                return
            # Rekey must replace SAs without moving the data path into Linux.
            old_status = status()
            old_spis = set(re.findall(r'\bspi \d+ \(0x([0-9a-f]+)\)', cli('show ipsec sa')))
            child_id = re.search(r'lab\{(\d+)\}:.*INSTALLED, TUNNEL', old_status)[1]
            run('nsenter','-t',str(daemons['client'].pid),'-m','-n','/usr/lib/ipsec/stroke','rekey','lab{'+child_id+'}')
            wait(lambda: 'INSTALLED, TUNNEL' in status() and
                 re.findall(r'lab\{(\d+)\}:.*INSTALLED, TUNNEL', status()) !=
                 re.findall(r'lab\{(\d+)\}:.*INSTALLED, TUNNEL', old_status), 'CHILD_SA rekey failed', 20)
            def changed_spis():
                current = set(re.findall(r'\bspi \d+ \(0x([0-9a-f]+)\)', cli('show ipsec sa')))
                return len(current-old_spis) >= 2
            wait(changed_spis, 'New ESP SPIs were not installed in VPP')
            out = run('ip','netns','exec',names['client'],'ping','-I',source4,'-n','-c','5','-i','.1','-W','2','10.254.62.2')
            assert '5 packets transmitted, 5 received' in out, 'Traffic failed after rekey'
            assert not run('ip','netns','exec',names['server'],'ip','xfrm','state').strip()
            lifecycle_result = None
            if lifecycle_scenario:
                def lifecycle_exchange():
                    for source, target, port in ((source4,'10.254.62.2',49870),(source6,'2001:db8:62::2',49871)):
                        run('ip','netns','exec',names['client'],'python3','-c',client,source,target,str(port),'65536',timeout=20)
                    assert not run('ip','netns','exec',names['server'],'ip','xfrm','state').strip()
                    assert len(re.findall(r'(?m)^\[',cli('show ipsec sa'))) == 2
                lifecycle_result = lifecycle_scenario.verify(daemons,cli,status,lifecycle_exchange)
                before = lifecycle_scenario.runtime_after_rebuild
            pd_result = pd_scenario.verify(daemons,status) if pd_scenario else None
            reconnect_verified = False
            outer_packets = None
            if outer6:
                # Re-establish IKE and dynamic addresses after a full disconnect.
                run('nsenter','-t',str(daemons['client'].pid),'-m','-n','/usr/lib/ipsec/stroke','down','lab')
                wait(lambda:not re.findall(r'(?m)^\[',cli('show ipsec sa')), 'SAs remained before reconnect')
                run('nsenter','-t',str(daemons['client'].pid),'-m','-n','/usr/lib/ipsec/stroke','up','lab')
                wait(lambda:'INSTALLED, TUNNEL' in status(), 'IPv6 outer reconnect failed',35)
                for source,destination in ((source4,'10.254.62.2'),(source6,'2001:db8:62::2')):
                    out=run('ip','netns','exec',names['client'],'ping','-I',source,'-n','-c','3','-i','.1','-W','2',destination)
                    assert '3 packets transmitted, 3 received' in out
                assert not run('ip','netns','exec',names['server'],'ip','xfrm','state').strip()
                reconnect_verified = True
                os.kill(outer_capture.pid,signal.SIGUSR1)
                wait(lambda:(root/'outer-capture.json').exists(), 'Outer packet snapshot missing')
                outer_packets=json.loads((root/'outer-capture.json').read_text())
                (root/'outer-counters.log').write_text(json.dumps(outer_packets))
                for counters in outer_packets.values():
                    assert counters['ike_udp500']>0, 'IPv6 IKE not observed on wire'
                    assert counters['esp_native' if native_esp else 'esp_udp4500']>0, 'IPv6 ESP not observed on wire'
                    assert counters['esp_udp4500' if native_esp else 'esp_native']==0, 'Unexpected ESP transport on wire'
                    assert counters['ipv4_ipsec']==counters['plaintext_leak']==0, 'IPv4 fallback or cleartext leak observed'
                    assert counters['oversize_l3']==0 and counters['max_l3_bytes']<=wan_mtu, 'Outer packets exceeded WAN MTU'
                    if not native_esp:
                        assert counters['ike_udp4500']>0, 'IPv6 NAT-T IKE marker not observed'
            after = cli('show runtime')
            def vectors(text, node):
                return sum(int(n) for n in re.findall(r'(?m)^'+re.escape(node)+r'\s+\S+\s+\d+\s+(\d+)', text))
            delta = {n: vectors(after,n)-vectors(before,n) for n in ('esp4-encrypt','esp6-encrypt','esp6-decrypt' if outer6 else 'esp4-decrypt','ipsec-cleartext-input') + (('ipsec-cleartext6-input',) if startup_chain else ())}
            assert all(n>0 for n in delta.values()), 'VPP ESP/cleartext counters did not increase'
            run('nsenter','-t',str(daemons['client'].pid),'-m','-n','/usr/lib/ipsec/stroke','down','lab')
            wait(lambda: not re.findall(r'(?m)^\[', cli('show ipsec sa')), 'VPP SAs leaked after disconnect')
            # Functional proof only: physical throughput is a separate test.
            result = {'workers': workers, 'authentication': 'certificate-eap-mschapv2' if eap else 'psk',
                      'dynamic_dual_stack_pool': eap, 'source4': source4, 'source6': source6,
                      'strongswan_kernel_vpp': True, 'vpp_sa_pair': True,
                      'server_linux_xfrm_empty': True, 'outer_family':6 if outer6 else 4,
                      'natt':not native_esp, 'wan_mtu':wan_mtu if outer6 else None, 'pmtu':pmtu_result,
                      'capture_location':'isolated_l2_bridge' if outer6 else None, 'outer_packets':outer_packets, 'reconnect_verified':reconnect_verified, 'nat44_ei': nat or startup_chain,
                      'nat44_ei_mode': 'output-feature' if startup_chain else 'input' if nat else None, 'tcp_source_addresses_verified': True,
                      'child_sa_rekey': True, 'sa_removed_after_disconnect': True,
                      'forwarded_ping': True, 'ipv6_inner_ping': True,
                      'tcp_64k_both_families': True, 'tcp_metrics':tcp_metrics, 'pd_lifecycle': pd_result, 'control_lifecycle': lifecycle_result, 'node_packet_deltas': delta,
                      'vpp_crypto_engines': cli('show crypto engines').strip(),
                      'vpp_crypto_handlers': cli('show crypto handlers').strip(),
                      'runtime_before': before, 'runtime_after': after}
            if lifecycle_scenario:
                lifecycle_result['vpp_stop_stops_control'] = lifecycle_scenario.stop_dependency()
            path = BASE/'logs'/f'ipsec-workers{workers}{"-eap" if eap else ""}{"-ei" if nat else ""}{"-pd" if pd else ""}{"-startup-chain" if startup_chain else "-lifecycle" if lifecycle else ""}{"-outer6" if outer6 else ""}{"-native" if native_esp else ""}{f"-pmtu-{wan_mtu}" if pmtu else ""}.json'
            path.write_text(json.dumps(result, indent=2)+'\n')
            print(json.dumps({k:v for k,v in result.items() if not k.startswith(('runtime_', 'vpp_crypto_'))}))
        except Exception:
            if startup_chain and (root/'cli.sock').exists():
                try:
                    print(cli('show errors'), file=sys.stderr)
                    stats = run('ip','netns','exec',names['client'],'nstat','-az')
                    print(run('ip','netns','exec',names['client'],'cat','/proc/net/xfrm_stat'), file=sys.stderr)
                    if outer_capture:
                        os.kill(outer_capture.pid, signal.SIGUSR1)
                        wait(lambda:(root/'outer-capture.json').exists(), 'Diagnostic snapshot missing')
                        print('WIRE COUNTERS', (root/'outer-capture.json').read_text(), file=sys.stderr)
                    print('CLIENT ERRORS', '\n'.join(line for line in stats.splitlines() if any(k in line for k in ('CsumErrors','XfrmIn','XfrmOut'))), file=sys.stderr)
                    trace = cli('show trace')
                    for packet in trace.split('Packet '):
                        if 'action: 0' in packet:
                            print('TRACE ACL DENY', '\n'.join(line for line in packet.splitlines() if re.match(r'^\d\d:\d\d:', line) or 'acl-plugin:' in line or 'lc_index ' in line), file=sys.stderr)
                    for packet in trace.split('Packet '):
                        if 'esp4-encrypt' in packet:
                            print('TRACE ENCRYPT PATH', '\n'.join(line for line in packet.splitlines() if re.match(r'^\d\d:\d\d:', line)), file=sys.stderr)
                            break
                except Exception:
                    pass
            # Private logs can contain negotiated SA details: preserve root-only,
            # do not print them in the assistant transcript.
            dest = BASE/'logs'/f'ipsec-failure-workers{workers}'
            dest.mkdir(exist_ok=True)
            for path in root.glob('*.log'):
                shutil.copy2(path, dest/path.name)
            print('Private diagnostic logs: ' + str(dest), file=sys.stderr)
            raise
        finally:
            if lifecycle_scenario:
                lifecycle_scenario.close()
            for p in reversed(children):
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGTERM)
                    try:
                        p.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGKILL)
                        p.wait(timeout=5)
            if pd_scenario:
                pd_scenario.close()
            for handle in logs:
                handle.close()
            for name in reversed(created):
                subprocess.run(['ip','netns','delete',name], capture_output=True, timeout=10)


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--launch':
        launcher(Path(sys.argv[2]), sys.argv[3])
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('--workers',type=int,choices=(0,2),default=0)
        parser.add_argument('--nat',action='store_true')
        parser.add_argument('--eap',action='store_true')
        parser.add_argument('--bad-password',action='store_true')
        parser.add_argument('--pd',action='store_true')
        parser.add_argument('--outer6',action='store_true')
        parser.add_argument('--native-esp',action='store_true')
        parser.add_argument('--wan-mtu',type=int,choices=(1280,1500),default=1500)
        parser.add_argument('--pmtu',action='store_true')
        parser.add_argument('--diagnose',action='store_true')
        parser.add_argument('--outer-injection',action='store_true')
        parser.add_argument('--vnet-library-dir',type=Path)
        parser.add_argument('--lifecycle',action='store_true')
        parser.add_argument('--startup-chain',action='store_true')
        parser.add_argument('--plugin-path',type=Path)
        parser.add_argument('--nat66-inbound-order',action='store_true')
        args = parser.parse_args()
        main(args.workers, args.nat, args.eap, args.bad_password, args.pd, args.outer6, args.native_esp, args.wan_mtu, args.pmtu, args.diagnose, args.outer_injection, args.vnet_library_dir, args.lifecycle, args.startup_chain, args.plugin_path, args.nat66_inbound_order)
