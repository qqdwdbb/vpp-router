W=/tmp/vrouter-src-audit/nat; rm -rf $W; mkdir -p $W/scripts; echo @@B@@ | base64 -d | tar -xz -C $W/scripts 2>/dev/null
exec taskset -c 0-3 nice -n 15 unshare -m bash <<'IN'
set -eu
W=/tmp/vrouter-src-audit/nat; S=/usr/local/src/vpp-vrouter; UP=/tmp/vrouter-src-audit/vpp/src/plugins/nat/nat44-ei
mount --make-rprivate /
mount -t tmpfs -o size=1G tmpfs /opt
mkdir -p /opt/vpp-vrouter-migration/source/nat44-ei-handoff/src/plugins/nat /opt/vpp-nic1-test
cp -a $S/migration/baseline /opt/vpp-vrouter-migration/
mount --bind $S/nic1-test /opt/vpp-nic1-test; mount -o remount,ro,bind /opt/vpp-nic1-test
B=/opt/vpp-vrouter-migration; H=$B/source/nat44-ei-handoff/src/plugins/nat/nat44-ei; cp -a $UP $H
N=$B/nat-resource-fix-20261019; mkdir -p $N; cp $UP/*.c $UP/*.h $N/
cd $N; for p in handoff-reassembly-order output-acl-order static-port-byte-order host-fallback-worker-order; do if patch -p5 --dry-run -s nat44_ei.c < $W/scripts/nat44-ei-$p.patch >/dev/null 2>&1; then patch -p5 -s nat44_ei.c < $W/scripts/nat44-ei-$p.patch; echo "patch $p ok"; else echo "patch $p FAIL"; fi; done; rm -f *.orig *.rej
patch -p5 -s nat44_ei_in2out.c < $W/scripts/nat44-ei-port-allocation-rollback.patch && echo rollback ok
grep -c 'host-fallback-v1 pool-receive-v1' nat44_ei.c || true
echo "vs retained handoff tree: nat44_ei.c $(diff nat44_ei.c $S/migration/source/nat44-ei-handoff/src/plugins/nat/nat44-ei/nat44_ei.c | grep -c '^[<>]' || true) in2out $(diff nat44_ei_in2out.c $S/migration/source/nat44-ei-handoff/src/plugins/nat/nat44-ei/nat44_ei_in2out.c | grep -c '^[<>]' || true)"
python3 - <<'P'
import shlex,subprocess
from pathlib import Path
base=Path('/opt/vpp-vrouter-migration');N=base/'nat-resource-fix-20261019';build=Path('/opt/vpp-nic1-test/vpp-build')
for n in ['nat44_ei','nat44_ei_in2out']:
    c=shlex.split((base/'baseline/nat44-ei-compile-command.txt').read_text());o=str(N/(n+'.c.o'))
    for fl in('-o','-MF','-MT','-MQ'):
        if fl in c: c[c.index(fl)+1]=o+('.d' if fl=='-MF' else '')
    c[c.index('-c')+1]=str(N/(n+'.c'))
    subprocess.run(c,cwd=build,check=True)
print('resource-fix objects built')
P
cd $W/scripts; python3 build-nat44-ei-expiry.py 2>&1 | tail -3 | cut -c1-200
python3 build-nat44-ei-single-worker.py --context-source $W/scripts/nat_ei_context.c 2>&1 | tail -3 | cut -c1-200
python3 build-nat44-ei-thread-control.py 2>&1 | tail -3 | cut -c1-200
O=$B/nat44-ei-thread-control/nat44_ei_plugin.so; P=/usr/local/lib/vpp-vrouter/plugins/nat44_ei_plugin.so; ls -la $O $P | cut -c24-120
for x in $O $P; do for sec in .text .rodata .data; do objcopy -O binary -j $sec $x /tmp/t.bin; echo "$sec $(sha256sum /tmp/t.bin | cut -c1-16) $(stat -c %s /tmp/t.bin)"; done; done; rm -f /tmp/t.bin
nm -S $O | awk 'NF==4{print $4,$2,$3}' | sort > /tmp/a.sym; nm -S $P | awk 'NF==4{print $4,$2,$3}' | sort > /tmp/b.sym; echo "symbols a=$(wc -l </tmp/a.sym) b=$(wc -l </tmp/b.sym) diff=$(diff /tmp/a.sym /tmp/b.sym | grep -c '^[<>]' || true)"; diff /tmp/a.sym /tmp/b.sym | head -14 | cut -c1-90 || true; rm -f /tmp/a.sym /tmp/b.sym
mkdir -p /tmp/vrouter-src-audit/out; cp $O /tmp/vrouter-src-audit/out/nat44_ei_plugin.rebuilt.so; cp -a $B/nat44-ei-thread-control/*.c /tmp/vrouter-src-audit/out/ 2>/dev/null || true
IN
