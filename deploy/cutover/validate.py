#!/usr/bin/env python3
"""Load the rendered VPP topology in isolated namespaces using throwaway WG keys."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from importlib.util import module_from_spec, spec_from_file_location
HERE = Path(__file__).resolve().parent


def load_module(path):
    spec = spec_from_file_location(path.stem.replace('-','_'),path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*args, input=None):
    p = subprocess.run(list(map(str,args)),input=input,capture_output=True,text=True,timeout=60)
    if p.returncode:
        raise RuntimeError('Validation subprocess failed: '+str(args[0]))
    return p.stdout


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:
        parser.error('run on VROUTER as root')
    os.umask(0o077)
    root=args.bundle.resolve()
    transition=load_module(HERE/'transition.py')
    transition.verify_manifest(root)
    if transition.load(root)['phase']!='prepared':
        raise ValueError('Validate only an unused prepared bundle')
    ns='vrouter-config-check-'+str(os.getpid())
    ike=ns+'-ike'
    temp=root/'validation-runtime'
    if temp.exists():
        shutil.rmtree(temp)
    temp.mkdir(mode=0o700)
    p=json.loads((root/'profile.json').read_text())
    process=None
    ike_unit='vrouter-config-ike-'+str(os.getpid())+'.service'
    ike_unit_path=Path('/run/systemd/system')/ike_unit
    turn_unit='vrouter-config-turn-'+str(os.getpid())+'.service'
    turn_unit_path=Path('/run/systemd/system')/turn_unit
    stage='namespace'
    try:
        for name in (ns,ike):
            run('ip','netns','add',name)
            run('ip','-n',name,'link','set','lo','up')
        startup=(root/'config/startup.conf').read_text()
        startup=startup[:startup.index('\ndpdk {')]+'\n'
        startup=startup.replace('plugin dpdk_plugin.so { enable }','plugin dpdk_plugin.so { disable }')
        startup=startup.replace('/run/vpp',str(temp)).replace('vrouter-prod',ns)
        # No hugepage or physical device interaction in configuration validation.
        startup=startup.replace('buffers-per-numa 8192','buffers-per-numa 8192 page-size 4k')
        (temp/'startup.conf').write_text(startup)
        env=dict(os.environ,LD_LIBRARY_PATH='/opt/vpp-vrouter-migration/ipsec-ip6-udp/lib:/opt/vpp-nic1-test/dpdk/lib/aarch64-linux-gnu:/opt/vpp-nic1-test/vpp/lib/aarch64-linux-gnu')
        log=open(temp/'vpp.log','w')
        process=subprocess.Popen(['ip','netns','exec',ns,str(root/'bin/vpp'),'-c',str(temp/'startup.conf')],
                                 stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,env=env)
        stage='VPP startup'
        def raw_cli(line):
            result=subprocess.run(['/opt/vpp-nic1-test/vpp/bin/vppctl','-s',str(temp/'cli.sock'),line],
                                  capture_output=True,text=True,timeout=15,env=env)
            if result.returncode or (not line.startswith('show ') and re.search(r'unknown|error|failed|invalid|unimplemented|not found|does not exist|cannot|must be|should be|not supported',result.stdout,re.I)):
                # Never include a command: a WG key may be present.
                raise RuntimeError('Isolated VPP command rejected: '+' '.join(line.split()[:4]))
            return result.stdout
        for _ in range(250):
            if process.poll() is not None:
                raise RuntimeError('Isolated VPP exited')
            try:
                raw_cli('show version')
                break
            except (RuntimeError,OSError):
                time.sleep(0.1)
        else:
            raise RuntimeError('Isolated VPP startup timed out')
        raw_cli('create tap id 3500 host-if-name check-parent')
        private=run('wg','genkey').strip()
        public=run('wg','pubkey',input=private+'\n').strip()
        runtime=load_module(HERE/'runtime.py')
        def cli(line):
            if line.startswith('set interface promiscuous '):
                return ''  # A virtual parent cannot exercise DPDK promiscuity.
            if line.startswith('exec ') and Path(line[5:]).name == 'host-fixed-mappings.vpp':
                return raw_cli(line)  # Public address/port rules need no key/interface rewriting.
            line=line.replace(p['parent'],'tap3500').replace('host-ns '+p['namespace'],'host-ns '+ike)
            line=re.sub(r'(private-key|public-key|preshared-key) \S+',lambda m:m[1]+' '+(public if m[1]=='public-key' else private),line)
            return raw_cli(line)
        runtime.cli=cli
        stage='rendered topology, NAT, WireGuard, ABF'
        runtime.topology(root,p)
        stage='WAN and LAN ACL'
        fw=load_module(HERE.parent/'firewall/vrouter-firewall.py')
        config=json.loads((root/'config/firewall.json').read_text())
        config['vpp']['socket']=str(temp/'cli.sock')
        config['vpp']['wan_interface']='tap3500.100'
        config['vpp']['lan_interfaces']=['tap3500']
        fw.vpp_cli=lambda sock,line,ctl=None:raw_cli(line)
        fw.apply_vpp_firewall(config)
        count = raw_cli('show acl-plugin acl').count('acl-index')
        config['vpp']['lan_ipv6'] = ['fd42:1111:2222:10::/64', '2001:db8:1234::/64']
        fw.apply_vpp_firewall(config)
        if raw_cli('show acl-plugin acl').count('acl-index') != count:
            raise RuntimeError('Prefix refresh leaked ACL objects')
        stage='real strongSwan private startup'
        # Use the rendered production profiles and original read-only credential
        # paths, but only in the disconnected test namespace / private /run.
        unit=(root/'units/vrouter-strongswan.service').read_text()
        lines=[]
        for line in unit.splitlines():
            if line.startswith(('Requires=','After=','PartOf=','Before=','WantedBy=')):
                continue
            line=line.replace('/run/netns/'+p['namespace'],'/run/netns/'+ike)
            line=line.replace('RuntimeDirectory=vrouter-strongswan','RuntimeDirectory=vrouter-config-ike-'+str(os.getpid()))
            line=line.replace('/run/vrouter-strongswan:', '/run/vrouter-config-ike-'+str(os.getpid())+':')
            line=line.replace('BindReadOnlyPaths=/run/vpp',f'BindReadOnlyPaths={temp}:/run/vpp')
            line=line.replace(str(root/'config/strongswan.conf'),str(temp/'strongswan.conf'))
            lines.append(line)
        (temp/'strongswan.conf').write_text((root/'config/strongswan.conf').read_text().replace('vrouter-prod',ns))
        ike_unit_path.write_text('\n'.join(lines)+'\n')
        run('ip','-n',ike,'addr','replace','10.61.10.2/32','dev','tap3500.100')
        run('systemctl','daemon-reload')
        run('systemctl','start',ike_unit)
        if run('systemctl','is-active',ike_unit).strip()!='active':
            raise RuntimeError('Private real strongSwan was not ready')
        run('systemctl','stop',ike_unit)
        if p.get('host_service_path'):
            stage='host-service policy syntax'
            run('nft', '-c', '-f', root/'config/host-path.nft')
            if (root/'units/vrouter-coturn.service').exists():
                stage='private coturn startup'
                run('ip', '-n', ns, 'addr', 'replace', p['lan_host'], 'dev', 'vpp-lan')
                run('ip', '-n', ns, 'link', 'set', 'vpp-lan', 'up')
                unit = (root/'units/vrouter-coturn.service').read_text()
                unit = '\n'.join(line for line in unit.splitlines()
                                 if not line.startswith(('Requires=', 'After=', 'PartOf=', 'Before=', 'WantedBy=')))
                unit = unit.replace('vrouter-coturn', 'vrouter-config-turn-'+str(os.getpid()))
                turn_unit_path.write_text(unit+'\nNetworkNamespacePath=/run/netns/'+ns+'\n')
                run('systemctl', 'daemon-reload')
                run('systemctl', 'start', turn_unit)
                time.sleep(1)
                if run('systemctl', 'is-active', turn_unit).strip() != 'active':
                    raise RuntimeError('Private coturn startup failed')
                listeners = run('ip', 'netns', 'exec', ns, 'ss', '-H', '-lnut')
                if str(ipaddress.ip_interface(p['lan_host']).ip)+':42004' not in listeners:
                    raise RuntimeError('Private coturn host listener unavailable')
                services = json.loads((root/'config/host-services.json').read_text())
                for service in services['services']:
                    if service.get('owner_unit') == 'vrouter-coturn.service':
                        service['owner_unit'] = turn_unit
                host_path = load_module(HERE.parent/'host-services/host-path.py')
                guarded = temp/'coturn-admission.nft'
                guarded.write_text(host_path.nft(services, []))
                if 'socket cgroupv2' not in guarded.read_text():
                    raise RuntimeError('Coturn socket cgroup unavailable')
                run('nsenter', '--net=/run/netns/'+ns, '--', 'nft', '-c', '-f', guarded)
                run('systemctl', 'stop', turn_unit)
        stage='systemd and daemon configuration'
        run('systemd-analyze','verify',*[str(f) for f in (root/'units').glob('*.service')])
        run('dnsmasq','--test','--conf-file='+str(root/'config/dnsmasq.conf'))
        # The snapshot already contains a flowtable bound to real Linux names;
        # check while those names still exist, without applying either ruleset.
        run('nft','-c','-f',root/'config/host.nft')
        report={'passed':True,'manifest_sha256':hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest(),
                'coverage':['isolated rendered VPP topology','NAT/WG/ABF CLI','WAN/LAN ACL attachment','real strongSwan rendered-profile readiness','systemd verify','dnsmasq syntax','nft dry-check'],
                'not_verified':['physical cutover','real WG peers','public client connectivity','boot recovery']}
        if p.get('host_service_path'):
            report['coverage'].append('host-service nft syntax')
            if (root/'units/vrouter-coturn.service').exists():
                report['coverage'].append('isolated coturn startup and IPv4 host listener')
            report['not_verified'] += ['client NAT pool ownership and upstream reachability',
                                      'dual-interface host-service policy routing and active egress SNAT',
                                      'public TURN relay', 'IPv6 host-service forwarding', 'UPnP VPP backend']
        (root/'validation.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report))
    except Exception as error:
        (root/'validation.json').write_text(json.dumps({'passed':False,'stage':stage,'error_type':type(error).__name__})+'\n')
        raise SystemExit('Isolated validation failed at '+stage+' ('+type(error).__name__+' '+str(error)+'); private logs remain on device')
    finally:
        if turn_unit_path.exists():
            subprocess.run(['systemctl', 'stop', turn_unit], capture_output=True)
            turn_unit_path.unlink()
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
            subprocess.run(['systemctl', 'reset-failed', turn_unit], capture_output=True)
        if ike_unit_path.exists():
            subprocess.run(['systemctl','stop',ike_unit],capture_output=True)
            ike_unit_path.unlink()
            subprocess.run(['systemctl','daemon-reload'],capture_output=True)
            subprocess.run(['systemctl','reset-failed',ike_unit],capture_output=True)
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill();process.wait()
            log.close()
        for name in (ike,ns):
            subprocess.run(['ip','netns','delete',name],capture_output=True)
        # These logs contain only ephemeral keys; retain root-private on failure.
        if (root/'validation.json').exists() and json.loads((root/'validation.json').read_text()).get('passed'):
            shutil.rmtree(temp)


if __name__=='__main__':
    main()
