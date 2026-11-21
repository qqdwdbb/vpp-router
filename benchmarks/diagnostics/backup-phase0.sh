#!/bin/sh
# Snapshot VROUTER Linux network stack onto the router. Secrets stay on-box.
# Does not bind or unbind any NIC.
set -eu

DEST_ROOT=/root/vpp-vrouter-backup
STAMP=$(date +%Y%m%d-%H%M%S)
DEST="$DEST_ROOT/phase0-$STAMP"

if [ "$(id -u)" -ne 0 ]; then
	echo "need root" >&2
	exit 1
fi

mkdir -p "$DEST/etc" "$DEST/live" "$DEST/etc/network"
chmod 700 "$DEST_ROOT" "$DEST"

copy_path() {
	src=$1
	if [ -e "$src" ]; then
		mkdir -p "$DEST$(dirname "$src")"
		cp -a "$src" "$DEST$src"
	fi
}

copy_path /etc/network/interfaces
copy_path /etc/network/interfaces.d
copy_path /etc/dhcpcd.conf
copy_path /etc/dnsmasq.conf
copy_path /etc/dnsmasq.d
copy_path /etc/nftables.conf
copy_path /etc/sysctl.conf
copy_path /etc/sysctl.d
copy_path /etc/iproute2/rt_tables
copy_path /etc/wireguard
copy_path /etc/ipsec.conf
copy_path /etc/ipsec.secrets
copy_path /etc/ipsec.d
copy_path /etc/nebula
copy_path /usr/local/bin/br0
copy_path /etc/hostname
copy_path /etc/resolv.conf
copy_path /etc/hosts
copy_path /etc/nftables.d
copy_path /etc/miniupnpd
copy_path /etc/default/miniupnpd
copy_path /proc/cmdline

{
	uname -a
	echo "--- cpu ---"
	lscpu 2>/dev/null | head -20 || true
	echo "--- pci ---"
	for d in 0000:02:00.0 0000:01:00.0; do
		echo "$d driver=$(basename "$(readlink /sys/bus/pci/devices/$d/driver 2>/dev/null)" 2>/dev/null)"
		echo "  net=$(ls /sys/bus/pci/devices/$d/net 2>/dev/null)"
	done
} > "$DEST/live/host.txt"

ip -br link > "$DEST/live/ip-link.txt"
ip -br addr > "$DEST/live/ip-addr.txt"
ip addr > "$DEST/live/ip-addr-full.txt"
ip route show table all > "$DEST/live/ip-route.txt"
ip -6 route show table all > "$DEST/live/ip6-route.txt"
ip rule > "$DEST/live/ip-rule.txt"
ip -6 rule > "$DEST/live/ip6-rule.txt"
ip neigh > "$DEST/live/ip-neigh.txt" 2>/dev/null || true
bridge link > "$DEST/live/bridge-link.txt" 2>/dev/null || ip -d link > "$DEST/live/ip-link-detail.txt"
cat /proc/net/vlan/config > "$DEST/live/vlan.txt" 2>/dev/null || true
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter > "$DEST/live/sysctl-fwd.txt" 2>/dev/null || true
nft list ruleset > "$DEST/live/nft.ruleset" 2>/dev/null || true
wg show all dump > "$DEST/live/wg.dump" 2>/dev/null || true
ipsec statusall > "$DEST/live/ipsec-status.txt" 2>/dev/null || true
lsmod > "$DEST/live/lsmod.txt"
systemctl list-units --type=service --state=running --no-pager > "$DEST/live/services-running.txt"
systemctl list-unit-files --no-pager > "$DEST/live/unit-files.txt"
crontab -l > "$DEST/live/root.crontab" 2>/dev/null || true
dmesg -T | tail -200 > "$DEST/live/dmesg-tail.txt" 2>/dev/null || true

{
	echo "phase0 backup $STAMP"
	echo "host $(hostname) $(uname -r)"
	echo "secrets included: /etc/wireguard /etc/ipsec.secrets /etc/ipsec.d/private /etc/nebula/*.key"
	echo "keep this directory root-only on the router; do not copy into git"
} > "$DEST/MANIFEST.txt"

( cd "$DEST" && find . -type f | sort | xargs sha256sum ) > "$DEST/SHA256SUMS"

echo "$DEST"
du -sh "$DEST"
echo "files=$(find "$DEST" -type f | wc -l)"
