#!/bin/sh
# Phase 1: bind ONLY nic1 (0000:02:00.0). Never touch nic0.
# Usage: sudo /opt/vpp-nic1-test/phase1-nic1-test.sh
set -eu

BDF=0000:02:00.0
ETH2_BDF=0000:01:00.0
MAC=02:00:00:00:10:07
TEST_IP=10.61.20.250/24
PING_DST=10.61.20.1
HP=/opt/vpp-nic1-test/hugepages
DPDK=/opt/vpp-nic1-test/dpdk
VPP=/opt/vpp-nic1-test/vpp
UIO=/opt/vpp-nic1-test/src/uio/uio_pci_generic.ko
RESTORE=/opt/vpp-nic1-test/restore-nic1.sh
LOGDIR=/opt/vpp-nic1-test/logs
STARTUP=/opt/vpp-nic1-test/startup-phase1.conf
SOCK=/run/vpp-nic1-test/cli.sock

if [ "$(id -u)" -ne 0 ]; then
	echo "need root" >&2
	exit 1
fi

nic0_drv=$(basename "$(readlink /sys/bus/pci/devices/$ETH2_BDF/driver)" 2>/dev/null || echo none)
echo "nic0 driver=$nic0_drv"
if [ "$nic0_drv" != r8125 ]; then
	echo "ABORT: nic0 is not r8125" >&2
	exit 1
fi

mkdir -p "$HP" "$LOGDIR" /run/vpp-nic1-test

cleanup() {
	set +e
	echo "--- cleanup ---"
	if [ -S "$SOCK" ]; then
		"$VPP/bin/vppctl" -s "$SOCK" quit 2>/dev/null
		sleep 1
	fi
	pkill -9 -f 'dpdk-testpmd.*0000:02:00.0' 2>/dev/null
	pkill -9 -f '/opt/vpp-nic1-test/vpp/bin/vpp' 2>/dev/null
	sleep 1
	sh "$RESTORE"
	echo 0 > /proc/sys/vm/nr_hugepages 2>/dev/null
	umount "$HP" 2>/dev/null
	rmmod uio_pci_generic 2>/dev/null
	echo "nic1=$(basename "$(readlink /sys/bus/pci/devices/$BDF/driver)" 2>/dev/null || echo none)"
	echo "nic0=$(basename "$(readlink /sys/bus/pci/devices/$ETH2_BDF/driver)" 2>/dev/null || echo none)"
	ip -br link show nic1 nic0 wan lan 2>/dev/null || true
}
trap cleanup EXIT INT TERM

modprobe uio 2>/dev/null || true
insmod "$UIO" 2>/dev/null || true
echo 64 > /proc/sys/vm/nr_hugepages
mount -t hugetlbfs nodev "$HP" 2>/dev/null || true

if [ -e /sys/bus/pci/devices/$BDF/driver ]; then
	printf '%s' "$BDF" > /sys/bus/pci/devices/$BDF/driver/unbind
fi
printf 'uio_pci_generic' > /sys/bus/pci/devices/$BDF/driver_override
printf '%s' "$BDF" > /sys/bus/pci/drivers_probe
printf '\n' > /sys/bus/pci/devices/$BDF/driver_override
echo "nic1 now $(basename "$(readlink /sys/bus/pci/devices/$BDF/driver)")"
echo "nic0 still $(basename "$(readlink /sys/bus/pci/devices/$ETH2_BDF/driver)")"
if [ "$(basename "$(readlink /sys/bus/pci/devices/$ETH2_BDF/driver)")" != r8125 ]; then
	echo "ABORT: nic0 driver changed" >&2
	exit 1
fi

export LD_LIBRARY_PATH="$DPDK/lib/aarch64-linux-gnu:${VPP}/lib/aarch64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

echo "===== testpmd ====="
{
	sleep 5
	printf '%s\n' \
		"show port info 0" \
		"mac_addr set 0 $MAC" \
		"set promisc 0 on" \
		"show port info 0" \
		"set fwd rxonly" \
		"start"
	sleep 10
	printf '%s\n' \
		"stop" \
		"show port stats all" \
		"set fwd txonly" \
		"start"
	sleep 5
	printf '%s\n' \
		"stop" \
		"show port stats all" \
		"show port 0 rss-hash" \
		"quit"
} | timeout --kill-after=5s 55s "$DPDK/bin/dpdk-testpmd" \
	-l 4,5 -n 1 -a "$BDF" \
	--huge-dir "$HP" --socket-mem 128 --file-prefix nic1-p1 \
	--log-level=pmd.net.r8169,8 \
	-- \
	-i --rxq=4 --txq=2 --nb-cores=1 --rss-ip --total-num-mbufs=8192 \
	> "$LOGDIR/phase1-testpmd.log" 2>&1 || true
echo "testpmd_exit=$?"
grep -E "MAC address|Link status|RX-packets|RX-bytes|Rx-pps|RSS|rss-|queue|Bad arguments|error|Error|Max possible" "$LOGDIR/phase1-testpmd.log" | head -80
echo "(full log $LOGDIR/phase1-testpmd.log)"

# VPP after testpmd released the device (same UIO bind remains).
cat > "$STARTUP" << EOF
unix {
  nodaemon
  runtime-dir /run/vpp-nic1-test
  cli-listen $SOCK
  log $LOGDIR/vpp-phase1.log
  pidfile /run/vpp-nic1-test/vpp.pid
  exec /tmp/phase1-vpp.cmds
}
api-segment { prefix nic1-test }
socksvr { socket-name /run/vpp-nic1-test/api.sock }
cpu { main-core 4 corelist-workers 5 }
memory { main-heap-size 128M }
buffers { buffers-per-numa 4096 }
plugins {
  path $VPP/lib/aarch64-linux-gnu/vpp_plugins
  plugin default { disable }
  plugin dpdk_plugin.so { enable }
}
dpdk {
  uio-driver uio_pci_generic
  dev $BDF {
    name nic1-dpdk
    num-rx-queues 4
    num-tx-queues 2
    rss { ipv4 ipv6 }
  }
  iova-mode pa
  huge-dir $HP
  file-prefix nic1-vpp
  no-multi-seg
}
EOF

cat > /tmp/phase1-vpp.cmds << EOF
set interface mac address nic1-dpdk $MAC
set interface state nic1-dpdk up
set interface ip address nic1-dpdk $TEST_IP
create sub-interfaces nic1-dpdk 100
create sub-interfaces nic1-dpdk 10
set interface state nic1-dpdk.100 up
set interface state nic1-dpdk.10 up
show hardware-interfaces nic1-dpdk
show interface
show interface addr
set interface rx-mode nic1-dpdk interrupt
show interface rx-placement
EOF

echo "===== vpp ====="
timeout --kill-after=5s 60s "$VPP/bin/vpp" -c "$STARTUP" \
	> "$LOGDIR/vpp-phase1-stdout.log" 2>&1 &
vpp_pid=$!
i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 40 ]; do
	sleep 0.5
	i=$((i + 1))
done
sleep 3
if [ -S "$SOCK" ]; then
	"$VPP/bin/vppctl" -s "$SOCK" show hardware-interfaces nic1-dpdk > "$LOGDIR/vpp-phase1-hw.txt" 2>&1 || true
	# Isolated VPP has only dpdk_plugin; ping CLI is not built in.
	# If nic1 is on the same L2 as lan, this reaches VPP via nic0/switch.
	ping -c 5 -W 1 "$PING_DST" >/dev/null 2>&1 || true
	ping -c 5 -W 1 10.61.20.250 > "$LOGDIR/vpp-phase1-linux-ping.txt" 2>&1 || true
	"$VPP/bin/vppctl" -s "$SOCK" show interface > "$LOGDIR/vpp-phase1-int.txt" 2>&1 || true
	"$VPP/bin/vppctl" -s "$SOCK" show errors > "$LOGDIR/vpp-phase1-errors.txt" 2>&1 || true
	"$VPP/bin/vppctl" -s "$SOCK" show interface rx-placement > "$LOGDIR/vpp-phase1-rxpl.txt" 2>&1 || true
	cat "$LOGDIR/vpp-phase1-hw.txt"
	echo "--- linux ping 10.61.20.250 ---"
	cat "$LOGDIR/vpp-phase1-linux-ping.txt"
	echo "--- int ---"
	cat "$LOGDIR/vpp-phase1-int.txt"
	echo "--- rx-placement ---"
	cat "$LOGDIR/vpp-phase1-rxpl.txt"
	echo "--- errors ---"
	cat "$LOGDIR/vpp-phase1-errors.txt"
	"$VPP/bin/vppctl" -s "$SOCK" quit 2>/dev/null || true
fi
wait "$vpp_pid" 2>/dev/null || true
echo "vpp_exit=$?"
echo "===== logs in $LOGDIR ====="
