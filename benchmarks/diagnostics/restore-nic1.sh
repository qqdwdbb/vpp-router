#!/bin/sh
# Restore nic1 (PCI 0000:02:00.0) to r8125 and the lan bridge.
# Does not touch nic0 / 0000:01:00.0.
set -eu

BDF=0000:02:00.0
MAC=02:00:00:00:10:07

if [ "$(id -u)" -ne 0 ]; then
	echo "need root" >&2
	exit 1
fi

drv() {
	basename "$(readlink "/sys/bus/pci/devices/$BDF/driver" 2>/dev/null)" 2>/dev/null || echo none
}

current=$(drv)
if [ "$current" = uio_pci_generic ]; then
	printf '%s' "$BDF" > /sys/bus/pci/drivers/uio_pci_generic/unbind
fi

if [ "$(drv)" != r8125 ]; then
	printf 'r8125' > /sys/bus/pci/devices/$BDF/driver_override
	printf '%s' "$BDF" > /sys/bus/pci/drivers_probe
	printf '\n' > /sys/bus/pci/devices/$BDF/driver_override
fi

i=0
while [ ! -e /sys/class/net/nic1 ] && [ "$i" -lt 50 ]; do
	sleep 0.1
	i=$((i + 1))
done
if [ ! -e /sys/class/net/nic1 ]; then
	echo "nic1 netdev missing after r8125 bind" >&2
	exit 1
fi

ip link set nic1 down
ip link set nic1 address "$MAC"
ip link set nic1 master lan 2>/dev/null || true
ip link set nic1 up
echo "nic1 driver=$(drv) master=$(cat /sys/class/net/nic1/master/uevent 2>/dev/null | sed -n 's/^INTERFACE=//p')"
