#!/usr/bin/env python3
"""Bounded VROUTER real-client lab. Explicitly replaces only the Linux IKE service.

Run through the documented transient systemd unit. Credentials are mounted
read-only in a private mount namespace, never copied into the lab or project.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

BASE=Path('/opt/vpp-vrouter-migration')
VPP=Path('/opt/vpp-nic1-test/vpp')
ROOT=BASE/'private-ipsec-real-client'
NS='vrouter-ike-server'
TAP='vrouter-ike-wan'
TABLE='vrouter_ike_live'
TAG='vrouter-ike-live'
WAN4='198.18.236.2'
HOST4='198.18.236.1'
WAN6='fd76:7070:4060::2'
HOST6='fd76:7070:4060::1'
KEYS=set('keyexchange type left leftid leftcert leftauth leftsendcert leftsubnet right rightid rightauth rightauth2 rightca rightsourceip rightdns ike esp rekey reauth ikelifetime lifetime keylife rekeymargin rekeyfuzz keyingtries dpdaction dpddelay dpdtimeout closeaction fragmentation eap_identity auto forceencaps mobike'.split())


def run(*args,timeout=15):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError('Command failed: '+args[0])
    return p.stdout


def save(path,data):
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(data,indent=2)+'\n');temp.chmod(0o600);temp.replace(path)


def render(text):
    sections={};current=None
    for raw in text.splitlines():
        line=raw.split('#',1)[0].strip()
        if not line:continue
        if line.startswith('config '):current=None;continue
        if line.startswith('conn '):
            current=line[5:].strip()
            if not re.fullmatch(r'[%\w-]+',current) or current in sections:raise ValueError('Invalid connection section')
            sections[current]={};continue
        if current is None:
            if '=' in line and line.split('=',1)[0].strip()=='uniqueids':continue
            raise ValueError('Unsupported configuration directive')
        if '=' not in line:raise ValueError('Unsupported connection directive')
        key,value=map(str.strip,line.split('=',1))
        if key not in KEYS:raise ValueError('Unsupported connection option: '+key)
        if key in sections[current]:raise ValueError('Repeated option requires explicit handling: '+key)
        sections[current][key]=value
    if not {'%default','cert','eap-mschapv2'}<=sections.keys():raise ValueError('Expected production default/cert/EAP profiles')
    defaults=sections['%default']
    if defaults.get('keyexchange')!='ikev2' or defaults.get('leftauth')!='pubkey':raise ValueError('Expected IKEv2 certificate server')
    pools=[]
    for name,values in sections.items():
        if 'rightsourceip' in values:
            for item in values['rightsourceip'].split(','):
                item=item.strip()
                if '-' in item:
                    first,last=map(ipaddress.ip_address,item.split('-',1))
                    pools.extend(str(n) for n in ipaddress.summarize_address_range(first,last))
                else:pools.append(str(ipaddress.ip_network(item,strict=False)))
    defaults.update(left='%any',forceencaps='yes',mobike='no',auto='add')
    lines=['config setup','    uniqueids=no']
    for name,values in sections.items():
        lines.append('conn '+name)
        for key,value in values.items():
            if key=='auto':value='add'
            if key=='mobike':value='no'
            if key=='forceencaps':value='yes'
            lines.append('    '+key+'='+value)
    return '\n'.join(lines)+'\n',sorted(set(pools)),defaults['leftid'],defaults['leftcert']


def env():
    return dict(os.environ,LD_LIBRARY_PATH=os.environ.get('VROUTER_IPSEC_VNET_LIBRARY_DIR',str(BASE/'ipv6-pd/lib'))+':/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:'+str(VPP/'lib/aarch64-linux-gnu'))


def cli(command):
    out=subprocess.run([str(VPP/'bin/vppctl'),'-s',str(ROOT/'cli.sock'),command],capture_output=True,text=True,env=env(),timeout=10,check=True).stdout
    if re.search(r'unknown input|error:|failed|invalid',out,re.I):raise RuntimeError('VPP configuration rejected')
    return out


def prepare():
    text,pools,identity,cert=render(Path('/etc/ipsec.conf').read_text())
    if ROOT.exists():raise RuntimeError('Existing lab directory must be recovered first')
    if NS in run('ip','netns','list') or subprocess.run(['ip','link','show',TAP],capture_output=True).returncode==0:raise RuntimeError('Existing lab resources')
    if subprocess.run(['pgrep','-x','vpp'],capture_output=True).returncode==0:raise RuntimeError('Another VPP is running')
    if not Path('/etc/ipsec.d/certs',cert).is_file() or not Path('/etc/ipsec.secrets').is_file():raise RuntimeError('Production credential references unavailable')
    run('openssl','x509','-in',str(Path('/etc/ipsec.d/certs',cert)),'-checkend','0','-noout')
    addresses=json.loads(run('ip','-j','address','show','dev','wan'))[0]['addr_info']
    endpoints={4:[],6:[]}
    for a in addresses:
        if a['scope']=='global':endpoints[4 if a['family']=='inet' else 6].append(a['local'])
    if not endpoints[4] or not endpoints[6]:raise RuntimeError('Expected dual-stack WAN')
    for network in pools:
        af='-4' if ':' not in network else '-6'
        if json.loads(run('ip',af,'-j','route','show','exact',network)):raise RuntimeError('Existing pool route must be reviewed')
    if subprocess.run(['nft','list','table','inet',TABLE],capture_output=True).returncode==0:raise RuntimeError('Existing lab nft table')
    ROOT.mkdir(mode=0o700)
    state={'namespace':NS,'tap':TAP,'nft_table':TABLE,'pools':pools,'routes_added':[],
           'wan_endpoints':endpoints,'server_identity':identity,'production_was_active':False,'production_stopped':False,
           'network_owned':False,'stage':'prepared','credential_mode':'read-only original files; no key copies'}
    save(ROOT/'state.json',state)
    (ROOT/'ipsec.conf').write_text(text);(ROOT/'ipsec.conf').chmod(0o600)
    (ROOT/'plugins').mkdir();shutil.copytree('/usr/lib/ipsec/plugins',ROOT/'plugins',dirs_exist_ok=True)
    shutil.copy2(BASE/'strongswan-build/vpp-sswan-5.9/libstrongswan-kernel-vpp.so',ROOT/'plugins/libstrongswan-kernel-vpp.so')
    (ROOT/'run').mkdir();(ROOT/'bin').mkdir()
    run('gcc','-O2','-Wall','-Wextra','-Werror',str(Path(__file__).with_name('clear-ike-conntrack.c')),
        '-o',str(ROOT/'bin/clear-ike-conntrack'),'-lnetfilter_conntrack')
    run(str(ROOT/'bin/clear-ike-conntrack'),'--check',*[a for values in endpoints.values() for a in values])
    shutil.copy2(VPP/'bin/vpp',ROOT/'bin/vpp')
    shutil.copytree(BASE/'crypto_engines',ROOT/'lib/aarch64-linux-gnu/vpp_crypto_engines')
    (ROOT/'startup.conf').write_text(f'''unix {{ nodaemon runtime-dir {ROOT} cli-listen {ROOT}/cli.sock }}
api-segment {{ prefix vrouter-live }}
socksvr {{ socket-name {ROOT}/api.sock }}
statseg {{ socket-name {ROOT}/stats.sock }}
buffers {{ buffers-per-numa 8192 page-size 4k }}
cpu {{ main-core 4 corelist-workers 5-6 }}
plugins {{ path {BASE}/plugins
plugin default {{ disable }}
plugin tap_plugin.so {{ enable }}
plugin ping_plugin.so {{ enable }}
plugin ipsec_ike_punt_plugin.so {{ enable }}
plugin nat44_ei_plugin.so {{ enable }}
plugin nat_ei_context_plugin.so {{ enable }}
}}
''')
    (ROOT/'strongswan.conf').write_text(f'''charon {{
load_modular = no
load = random nonce x509 revocation constraints pubkey pkcs1 pkcs8 pem openssl gmp hmac kdf attr curl kernel-vpp! kernel-netlink socket-default stroke eap-identity eap-mschapv2 counters
install_routes = no
filelog {{ lab {{ path = {ROOT}/charon.log
default = 1
flush_line = yes
}} }}
plugins {{
kernel-vpp {{ api_prefix = vrouter-live
read_timeout = 5000
use_tunnel_mode_sa = yes
}}
stroke {{ secrets_file = /etc/ipsec.secrets }}
openssl {{ load_legacy = yes }}
}}
}}
''')
    print(json.dumps({'stage':'prepared','identity':identity,'credential_copy':False,'production_changed':False}))


def launch():
    run('mount','--bind',str(ROOT/'plugins'),'/usr/lib/ipsec/plugins')
    run('mount','--bind',str(ROOT/'run'),'/run')
    for path in ('/etc/ipsec.d','/etc/ipsec.secrets'):
        run('mount','--bind',path,path);run('mount','-o','remount,bind,ro',path)
    os.environ['STRONGSWAN_CONF']=str(ROOT/'strongswan.conf')
    os.execv('/usr/lib/ipsec/starter',['starter','--nofork','--conf',str(ROOT/'ipsec.conf')])


def nft_script(state):
    lines=[f'table inet {TABLE} {{', 'chain prerouting { type nat hook prerouting priority -110; policy accept;']
    for family,addresses in state['wan_endpoints'].items():
        proto='ip' if int(family)==4 else 'ip6';target=WAN4 if int(family)==4 else WAN6
        for address in addresses:
            lines.append(f'iifname "wan" {proto} daddr {address} udp dport {{500,4500}} counter dnat {proto} to {target}')
    lines+=['}', 'chain postrouting { type nat hook postrouting priority 90; policy accept;',
            f'iifname "{TAP}" ip saddr {WAN4} oifname "wan" counter masquerade']
    for pool in [WAN6+'/128']+state['pools']:
        network=ipaddress.ip_network(pool)
        if network.version==6 and network.network_address in ipaddress.ip_network('fc00::/7'):
            lines.append(f'iifname "{TAP}" ip6 saddr {pool} oifname "wan" counter masquerade')
    lines+=['}','}']
    # Existing blacklist and policy rules run first. Add only lab-specific accepts.
    for family,target in (('ip',WAN4),('ip6',WAN6)):
        lines.append(f'add rule inet filter forward iifname "wan" oifname "{TAP}" {family} daddr {target} udp dport {{500,4500}} counter accept comment "{TAG}:ike"')
    for pool in [WAN4+'/32']+[p for p in state['pools'] if ':' not in p]:
        lines.append(f'add rule inet filter forward iifname "{TAP}" ip saddr {pool} counter accept comment "{TAG}:data4"')
    for pool in [WAN6+'/128']+[p for p in state['pools'] if ':' in p]:
        lines.append(f'add rule inet filter forward iifname "{TAP}" ip6 saddr {pool} counter accept comment "{TAG}:data6"')
    return '\n'.join(lines)+'\n'


def recover():
    if not (ROOT/'state.json').exists():return
    state=json.loads((ROOT/'state.json').read_text())
    errors=[]
    # Run every cleanup step, even if an earlier command failed. Production
    # service recovery must not depend on successful conntrack cleanup.
    rules=subprocess.run(['nft','-j','list','chain','inet','filter','forward'],capture_output=True,text=True)
    if rules.returncode==0:
        for item in json.loads(rules.stdout)['nftables']:
            r=item.get('rule',{})
            if r.get('comment','').startswith(TAG+':'):
                p=subprocess.run(['nft','delete','rule','inet','filter','forward','handle',str(r['handle'])],capture_output=True)
                if p.returncode:errors.append('forward rule cleanup')
    subprocess.run(['nft','delete','table','inet',TABLE],capture_output=True)
    for network in reversed(state['routes_added']):
        af='-6' if ':' in network else '-4';gateway=WAN6 if ':' in network else WAN4
        subprocess.run(['ip',af,'route','del',network,'via',gateway,'dev',TAP],capture_output=True)
    if state['network_owned']:
        subprocess.run(['ip','link','delete',TAP],capture_output=True)
        subprocess.run(['ip','netns','delete',NS],capture_output=True)
    if state['production_stopped']:
        p=subprocess.run([str(ROOT/'bin/clear-ike-conntrack'),*[a for values in state['wan_endpoints'].values() for a in values]],capture_output=True)
        if p.returncode:errors.append('IKE conntrack cleanup')
    if state['production_stopped'] and state['production_was_active']:
        p=subprocess.run(['systemctl','start','strongswan-starter'],capture_output=True)
        if p.returncode:errors.append('production service recovery')
    active=subprocess.run(['systemctl','is-active','--quiet','strongswan-starter']).returncode==0
    state.update(stage='restored' if not errors else 'recovery-warning',production_stopped=bool(state['production_was_active'] and not active),recovery_errors=errors)
    save(ROOT/'state.json',state)
    print(json.dumps({'stage':state['stage'],'production_active':active,'recovery_errors':errors}))


def serve(seconds):
    state=json.loads((ROOT/'state.json').read_text())
    if state['stage']!='prepared':raise RuntimeError('Lab is not freshly prepared')
    children=[];handles=[]
    def start(args,name):
        handle=(ROOT/name).open('w');handles.append(handle)
        p=subprocess.Popen(args,stdout=handle,stderr=handle,env=env(),start_new_session=True);children.append(p);return p
    def wait(check,message,seconds=15):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if check():return
            if any(p.poll() is not None for p in children):raise RuntimeError('Private lab process exited')
            time.sleep(.1)
        raise RuntimeError(message)
    try:
        state['network_owned']=True;save(ROOT/'state.json',state)
        run('ip','netns','add',NS);run('ip','-n',NS,'link','set','lo','up')
        vpp_process=start([str(ROOT/'bin/vpp'),'-c',str(ROOT/'startup.conf')],'vpp.log')
        wait(lambda:(ROOT/'cli.sock').exists(),'VPP did not start')
        selected=os.environ.get('VROUTER_IPSEC_VNET_LIBRARY_DIR')
        if selected and str(Path(selected).resolve())+'/' not in Path(f'/proc/{vpp_process.pid}/maps').read_text():
            raise RuntimeError('Selected libvnet not loaded')
        cli(f'create tap id 4060 host-if-name {TAP} host-ip4-addr {HOST4}/30 host-ip6-addr {HOST6}/64 host-mtu-size 1500')
        cli(f'create tap id 4061 host-ns {NS} host-if-name tap4060 host-ip4-addr 10.63.10.2/30 host-ip6-addr fd42:1111:2222:50::2/64 host-mtu-size 1500')
        for name,addresses in (('tap4060',[WAN4+'/30',WAN6+'/64']),('tap4061',['10.63.10.1/30','fd42:1111:2222:50::1/64'])):
            for address in addresses:cli(f'set interface ip address {name} {address}')
            cli(f'set interface mtu packet 1500 {name}');cli(f'set interface state {name} up');cli(f'set interface rx-mode {name} interrupt');cli(f'ip6 nd {name} ra-suppress')
        cli(f'ip route add 0.0.0.0/0 via {HOST4} tap4060');cli(f'ip route add ::/0 via {HOST6} tap4060')
        for af,addr in (('-4',WAN4+'/32'),('-6',WAN6+'/128')):run('ip','-n',NS,af,'addr','add',addr,'dev','tap4060')
        run('ip','-n',NS,'route','add','default','via','10.63.10.1')
        run('ip','-n',NS,'-6','route','add','default','via','fd42:1111:2222:50::1')
        # IKE binds the WAN /128 alias; pin this private point-to-point peer so
        # neighbor discovery cannot resolve the control gateway on the WAN path.
        peer=re.search(r'Ethernet address ([0-9a-f:]{17})',cli('show hardware-interfaces tap4061'))
        if not peer:raise RuntimeError('Control TAP MAC unavailable')
        run('ip','-n',NS,'-6','neigh','replace','fd42:1111:2222:50::1','lladdr',peer[1],'nud','permanent','dev','tap4060')
        cli('ipsec ike punt enable');cli('set punt udp 500');cli('set punt ip6 udp 500')
        cli('ip punt redirect rx tap4060 via 10.63.10.2 tap4061');cli('ip6 punt redirect rx tap4060 via fd42:1111:2222:50::2 tap4061')
        # Keep client sources visible to the existing Linux policy routing.
        cli('ipsec cleartext ingress tap4061')
        server=start(['ip','netns','exec',NS,'unshare','--mount','--propagation','private','python3',str(Path(__file__).resolve()),'--launch'],'starter.log')
        wait(lambda:(ROOT/'run/charon.pid').exists(),'Private charon did not start')
        wait(lambda:'strongswan' in cli('show api clients'),'Private charon did not attach to VPP')
        def profiles_ready():
            status=run('nsenter','-t',str(server.pid),'-m','-n','/usr/lib/ipsec/stroke','statusall')
            return 'kernel-vpp' in status and all(re.search(r'(?m)^\s*'+name+r':',status) for name in ('cert','eap-mschapv2'))
        wait(profiles_ready,'Private authentication profiles were not loaded')
        # All private setup succeeds before interrupting production IKE.
        state['production_was_active']=subprocess.run(['systemctl','is-active','--quiet','strongswan-starter']).returncode==0
        state['production_stopped']=True;save(ROOT/'state.json',state)
        run('systemctl','stop','strongswan-starter')
        for network in state['pools']:
            af='-6' if ':' in network else '-4';gateway=WAN6 if ':' in network else WAN4
            run('ip',af,'route','add',network,'via',gateway,'dev',TAP)
            state['routes_added'].append(network);save(ROOT/'state.json',state)
        rules=nft_script(state);(ROOT/'live.nft').write_text(rules)
        p=subprocess.run(['nft','-f',str(ROOT/'live.nft')],capture_output=True,text=True)
        if p.returncode:raise RuntimeError('Temporary ingress rules rejected')
        run(str(ROOT/'bin/clear-ike-conntrack'),*[a for values in state['wan_endpoints'].values() for a in values])
        state.update(stage='ready',ready_at=int(time.time()),deadline=int(time.time()+seconds));save(ROOT/'state.json',state)
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if any(p.poll() is not None for p in children):raise RuntimeError('Private lab process exited')
            # Header lines only; SA details/keys are never written or displayed.
            sa_count=len(re.findall(r'(?m)^\[',cli('show ipsec sa')))
            status=run('nsenter','-t',str(server.pid),'-m','-n','/usr/lib/ipsec/stroke','statusall')
            xfrm=run('ip','netns','exec',NS,'ip','xfrm','state')
            if xfrm.strip():raise RuntimeError('Isolated server installed Linux XFRM')
            save(ROOT/'status.json',{'stage':'ready','server_identity':state['server_identity'],'vpp_sa_count':sa_count,
                'ike_established':bool(re.search(r'\bESTABLISHED\b',status)),'child_installed':bool(re.search(r'INSTALLED, TUNNEL',status)),
                'server_linux_xfrm_empty':True,'updated_at':int(time.time()),'deadline':state['deadline']})
            time.sleep(3)
    finally:
        for p in reversed(children):
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGTERM)
                try:p.wait(timeout=8)
                except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
        for handle in handles:handle.close()
        recover()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    for name in ('prepare','serve','recover','launch'):mode.add_argument('--'+name,action='store_true')
    parser.add_argument('--seconds',type=int,default=1800)
    parser.add_argument('--vnet-library-dir',type=Path)
    args=parser.parse_args();os.umask(0o077)
    if args.vnet_library_dir:
        selected=args.vnet_library_dir.resolve()
        if not (selected/'libvnet.so').is_file():raise ValueError('Selected libvnet unavailable')
        os.environ['VROUTER_IPSEC_VNET_LIBRARY_DIR']=str(selected)
    if not 60<=args.seconds<=3600:raise ValueError('Lab duration must be 60..3600 seconds')
    if args.prepare:prepare()
    elif args.launch:launch()
    elif args.recover:recover()
    else:
        signal.signal(signal.SIGTERM,lambda *unused:(_ for _ in ()).throw(KeyboardInterrupt()))
        serve(args.seconds)


if __name__=='__main__':
    try:main()
    except (RuntimeError,ValueError) as exc:
        print('Real-client lab failed: '+str(exc),file=sys.stderr);raise SystemExit(1)
