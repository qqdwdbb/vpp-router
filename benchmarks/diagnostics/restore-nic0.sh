#!/bin/sh
# Restore nic0 (PCI 0000:01:00.0) to r8125 and rebuild wan/vps/lan.
# Does not touch nic1 / 0000:02:00.0.
# Restores the base link/VLAN topology only; see cutover/README.md for full recovery.
#
# Usage:
#   restore-nic0.sh           # restore if unbound or on UIO
#   restore-nic0.sh --check   # print state, change nothing
#   restore-nic0.sh --force   # rebuild even if already on r8125
set -eu

BDF=0000:01:00.0
WAN_MAC=02:00:00:00:10:01
WAN_ADDR=10.61.10.2/24
WAN_GW=10.61.10.1
ETH1_BDF=0000:02:00.0

FORCE=0
CHECK=0
for arg in "$@"; do
	case "$arg" in
	--force) FORCE=1 ;;
	--check) CHECK=1 ;;
	-h|--help)
		sed -n '2,9p' "$0"
		exit 0
		;;
	*)
		echo "unknown arg: $arg" >&2
		exit 2
		;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "need root" >&2
	exit 1
fi

drv_of() {
	if [ -L "/sys/bus/pci/devices/$1/driver" ]; then
		basename "$(readlink "/sys/bus/pci/devices/$1/driver")"
	else
		echo none
	fi
}

netdev_of() {
	ls "/sys/bus/pci/devices/$1/net" 2>/dev/null || true
}

wait_netdev() {
	n=0
	while [ ! -e "/sys/class/net/$1" ] && [ "$n" -lt 50 ]; do
		sleep 0.1
		n=$((n + 1))
	done
	[ -e "/sys/class/net/$1" ]
}

show_state() {
	for iface in nic0 wan vps lan br0; do
		ip -br link show dev "$iface" 2>/dev/null || true
	done
	for iface in wan lan br0; do
		ip -br addr show dev "$iface" 2>/dev/null || true
	done
}

nic0_drv=$(drv_of "$BDF")
nic1_drv=$(drv_of "$ETH1_BDF")
echo "nic0 $BDF driver=$nic0_drv net=$(netdev_of "$BDF")"
echo "nic1 $ETH1_BDF driver=$nic1_drv (must stay r8125; this script does not touch it)"

if [ "$nic1_drv" != r8125 ]; then
	echo "ABORT: nic1 is not on r8125; refusing to continue" >&2
	exit 1
fi

already=0
if [ "$nic0_drv" = r8125 ] && [ -e /sys/class/net/nic0 ] && [ -e /sys/class/net/wan ] && [ -e /sys/class/net/vps ]; then
	already=1
fi

if [ "$CHECK" -eq 1 ]; then
	show_state
	if [ "$already" -eq 1 ]; then
		echo "check: nic0 already looks restored (r8125 + wan + vps)"
	else
		echo "check: nic0 needs restore"
	fi
	exit 0
fi

if [ "$already" -eq 1 ] && [ "$FORCE" -eq 0 ]; then
	echo "nic0 already on r8125 with wan/vps; pass --force to rebuild"
	exit 0
fi

# Stop VPP explicitly before invoking recovery. Never unbind an active owner.
command -v pgrep >/dev/null || { echo "missing pgrep" >&2; exit 1; }
if pgrep -x vpp >/dev/null 2>&1; then
	echo "ABORT: stop VPP and confirm it has exited before restoring nic0" >&2
	exit 1
fi
if [ "$(drv_of "$BDF")" = uio_pci_generic ]; then
	command -v fuser >/dev/null || { echo "missing fuser" >&2; exit 1; }
	found=0
	for uio in /sys/bus/pci/devices/$BDF/uio/uio*; do
		[ -d "$uio" ] || continue
		found=1
		dev=/dev/$(basename "$uio")
		[ -c "$dev" ] || { echo "ABORT: missing $dev" >&2; exit 1; }
		result=0
		fuser "$dev" >/dev/null 2>&1 || result=$?
		if [ "$result" -ne 1 ]; then
			echo "ABORT: $dev is in use or ownership check failed" >&2
			exit 1
		fi
	done
	[ "$found" -eq 1 ] || { echo "ABORT: no UIO device found" >&2; exit 1; }
fi

if [ "$(drv_of "$BDF")" = uio_pci_generic ]; then
	printf '%s' "$BDF" > /sys/bus/pci/drivers/uio_pci_generic/unbind
fi

if [ "$(drv_of "$BDF")" != r8125 ]; then
	printf 'r8125' > /sys/bus/pci/devices/$BDF/driver_override
	printf '%s' "$BDF" > /sys/bus/pci/drivers_probe
	printf '\n' > /sys/bus/pci/devices/$BDF/driver_override
fi

if ! wait_netdev nic0; then
	echo "nic0 netdev missing after r8125 bind" >&2
	exit 1
fi

ip link set nic0 up
ip link set nic0 master lan 2>/dev/null || true

if ! ip link show wan >/dev/null 2>&1; then
	ip link add link nic0 name wan type vlan id 100
fi
ip link set wan address "$WAN_MAC"
ip link set wan up
if ! ip -4 addr show dev wan | grep -q "inet ${WAN_ADDR%/*}/"; then
	ip addr add "$WAN_ADDR" dev wan 2>/dev/null || true
fi
ip route replace default via "$WAN_GW" dev wan

if ! ip link show vps >/dev/null 2>&1; then
	ip link add link nic0 name vps type vlan id 10
fi
ip link set vps up
ip link set vps master br0 2>/dev/null || true

if ip link show lan >/dev/null 2>&1; then
	ip link set lan up
fi
if ip link show br0 >/dev/null 2>&1; then
	ip link set br0 up
fi

if command -v dhcpcd >/dev/null && pgrep -x dhcpcd >/dev/null; then
	dhcpcd --rebind wan >/dev/null 2>&1 || dhcpcd -n wan >/dev/null 2>&1 || true
fi

echo "nic0 driver=$(drv_of "$BDF") net=$(netdev_of "$BDF")"
echo "nic1 driver=$(drv_of "$ETH1_BDF") (untouched)"
show_state
