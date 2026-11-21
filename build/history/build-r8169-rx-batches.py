#!/usr/bin/env python3
"""Stage descriptor-read and rearm variants plus a separately built 64-RX-call plugin."""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT=Path('/usr/local/src/vpp-vrouter')
BASE=ROOT/'maintenance/rx-alloc-bulk'
DEPLOYED=Path('/usr/local/lib/aarch64-linux-gnu/dpdk/pmds-26.1/librte_net_r8169.so.26.1')
PLUGIN=Path('/usr/local/lib/vpp-vrouter/plugins/dpdk_plugin.so')
READ_BLOCK='''		if (rtl_nc_dma) {
			uintptr_t line = (uintptr_t)rxd &
					 ~(uintptr_t)(rtl_nc_line - 1);
			if (line != *synced_line) {
				rtl_nc_sync(rxd, hw->RxDescLength, 1);
				*synced_line = line;
			}
		}'''
READ_BATCH='''		if (rtl_nc_dma && tail >= synced_until) {
			uintptr_t line = (uintptr_t)rxd &
					 ~(uintptr_t)(rtl_nc_line - 1);
			if (line != *synced_line) {
				uint16_t end = tail + 8 - *scanned;

				if (end > rxq->nb_rx_desc)
					end = rxq->nb_rx_desc;
				if ((unsigned int)(end - tail) > limit - count)
					end = tail + limit - count;
				/* No OWN stores occur in this bounded forward window.
				 * Complete all line invalidations before reading status. */
				rtl_nc_sync(rxd, (end - tail) * hw->RxDescLength, 1);
				synced_until = end;
				*synced_line = (uintptr_t)rtl_get_rxdesc(hw,
					rxq->hw_ring, end - 1) &
					~(uintptr_t)(rtl_nc_line - 1);
			} else {
				/* The caller already synchronized the first line. */
				synced_until = tail + 1;
			}
		}'''


def transform(source, lines):
    if lines not in (2,4,8):
        raise ValueError('Unsupported rearm batch')
    assert source.count(READ_BLOCK)==1
    start=source.index('rtl_rx_scan_ready(')
    index=source.index('\tunsigned int count = 0;',start)
    source=source[:index]+source[index:].replace('\tunsigned int count = 0;',
        '\tunsigned int count = 0;\n\tuint16_t synced_until = tail;',1)
    source=source.replace(READ_BLOCK,READ_BATCH)
    assert source.count('if (*count >= 4 * per_line')==1
    source=source.replace('if (*count >= 4 * per_line','if (*count >= RTL_NC_REARM_LINES * per_line')
    source=source.replace('static unsigned int rtl_nc_line;',
        f'static unsigned int rtl_nc_line;\n#define RTL_NC_REARM_LINES {lines}')
    source=source.replace('/* Collect at most four complete lines;',
                          '/* Collect at most RTL_NC_REARM_LINES complete lines;')
    return source


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relocate(text):
    return text.replace('/opt/vpp-nic1-test',str(ROOT/'nic1-test')).replace(
        '/opt/vpp-vrouter-migration',str(ROOT/'migration'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--plugin-only',action='store_true')
    args=parser.parse_args()
    assert sha(DEPLOYED)==sha(BASE/DEPLOYED.name)=='f89a9e9d5210046d5b8a5dc7960e2b0ec3bd0f6bc99cf1cf787d4ffcd8da97a8'
    args.output.mkdir(parents=True,exist_ok=args.plugin_only)
    spec=importlib.util.spec_from_file_location('existing_build',args.assets/'build-r8169-rx-dma.py')
    existing=importlib.util.module_from_spec(spec);spec.loader.exec_module(existing)
    baseline=(BASE/'source/r8169_rxtx.c').read_text()
    manifest=(json.loads((args.output/'manifest.json').read_text()) if args.plugin_only else
              dict(baseline_pmd=sha(DEPLOYED),baseline_plugin=sha(PLUGIN),variants={}))
    for name,lines in ([] if args.plugin_only else [('read',4),('rearm2',2),('rearm8',8)]):
        output=args.output/name;output.mkdir()
        source=output/'source';shutil.copytree(BASE/'source',source)
        changed=transform(baseline,lines);(source/'r8169_rxtx.c').write_text(changed)
        (output/'change.patch').write_text(''.join(difflib.unified_diff(baseline.splitlines(True),changed.splitlines(True),fromfile='a/r8169_rxtx.c',tofile='b/r8169_rxtx.c')))
        for ring in (8,12,16):
            subprocess.run(['python3',str(args.assets/'integration_r8169_rx_dma.py'),'--source',str(source/'r8169_rxtx.c'),'--ring-size',str(ring),'--sanitize'],check=True)
        for test,target in [('tx_dma','rxtx'),('tx_reclaim','rxtx'),('tally_dma','hw')]:
            subprocess.run(['python3',str(args.assets/f'integration_r8169_{test}.py'),'--source',str(source/f'r8169_{target}.c')],check=True)
        objects={}
        template=existing.command(ROOT/'migration/baseline/rxtx-build-commands.txt')
        for stem in ['r8169_rxtx','r8169_hw','r8169_ethdev']:
            obj=output/(stem+'.o');cmd=template.copy()
            for flag in ['-o','-MF','-MQ']:
                cmd[cmd.index(flag)+1]=str(obj)+('.d' if flag=='-MF' else '')
            cmd[-1]=str(source/(stem+'.c'))
            subprocess.run(cmd,cwd=ROOT/'nic1-test/dpdk-build',check=True);objects[stem]=obj
        link=existing.command(ROOT/'migration/baseline/r8169-link-command.txt')
        library=output/DEPLOYED.name;link[link.index('-o')+1]=str(library)
        for i,value in enumerate(link):
            for stem,obj in objects.items():
                if value.endswith('/net_r8169_'+stem+'.c.o'):link[i]=str(obj)
        subprocess.run(link,cwd=ROOT/'nic1-test/dpdk-build',check=True)
        subprocess.run(['patchelf','--set-rpath','$ORIGIN/../..',str(library)],check=True)
        manifest['variants'][name]=dict(pmd=str(library),pmd_sha=sha(library),source_sha=sha(source/'r8169_rxtx.c'),read_batch=True,rearm_lines=lines)
    # Build node.c in isolation. Other plugin objects must match deployed code.
    build=ROOT/'nic1-test/vpp-build'
    commands=subprocess.check_output(['ninja','-C',str(build),'-t','commands'],text=True).splitlines()
    compile_cmd=next(c for c in commands if ' -c ' in c and c.endswith('/plugins/dpdk/device/node.c'))
    link_text=next(c for c in commands if ' -o lib/aarch64-linux-gnu/vpp_plugins/dpdk_plugin.so ' in c)
    original_node=ROOT/'nic1-test/src/vpp-stable-2606/src/plugins/dpdk/device/node.c'
    token='clib_min (DPDK_RX_BURST_SZ - n_rx_packets, 32)'
    assert original_node.read_text().count(token)==1
    plugin_dir=args.output/'call64';plugin_dir.mkdir(exist_ok=args.plugin_only)
    for cap in (32,64):
        node=plugin_dir/f'node{cap}.c';node.write_text(original_node.read_text().replace(token,token.replace('32)',f'{cap})')))
        cmd=shlex.split(relocate(compile_cmd));obj=plugin_dir/f'node{cap}.o'
        cmd.extend(['-fmacro-prefix-map='+str(ROOT/'nic1-test')+'=/opt/vpp-nic1-test',
                    '-fmacro-prefix-map='+str(node)+'=/opt/vpp-nic1-test/src/vpp-stable-2606/src/plugins/dpdk/device/node.c'])
        for flag in ['-o','-MF','-MT']:cmd[cmd.index(flag)+1]=str(obj)+('.d' if flag=='-MF' else '')
        source_at=cmd.index('-c')+1;cmd[source_at]=str(node)
        subprocess.run(cmd,cwd=build,check=True)
        link=shlex.split(relocate(link_text.split(' && ')[1]));target=plugin_dir/f'dpdk_plugin_{cap}.so'
        # Keep original link-time string-table layout; runtime path is fixed below.
        old_link=shlex.split(link_text.split(' && ')[1])
        for i,value in enumerate(link):
            if value.startswith('-Wl,-rpath,'):link[i]=old_link[i]
        link[link.index('-o')+1]=str(target)
        at=next(i for i,c in enumerate(link) if c.endswith('/device/node.c.o'));link[at]=str(obj)
        subprocess.run(link,cwd=build,check=True)
        subprocess.run(['patchelf','--set-rpath','$ORIGIN/../lib/aarch64-linux-gnu:/usr/local/lib/aarch64-linux-gnu',str(target)],check=True)
    manifest['plugin64']=dict(path=str(plugin_dir/'dpdk_plugin_64.so'),sha=sha(plugin_dir/'dpdk_plugin_64.so'),control32=str(plugin_dir/'dpdk_plugin_32.so'))
    for tag,path in [('installed',PLUGIN),('control32',plugin_dir/'dpdk_plugin_32.so')]:
        subprocess.run(['objcopy','--dump-section','.text='+str(plugin_dir/(tag+'.text')),
                        str(path),str(plugin_dir/(tag+'-inspect.so'))],check=True)
    assert sha(plugin_dir/'installed.text')==sha(plugin_dir/'control32.text'), '32-packet control differs from installed machine code'
    manifest['plugin64']['control32_text_sha']=sha(plugin_dir/'control32.text')
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest))


if __name__=='__main__':main()
