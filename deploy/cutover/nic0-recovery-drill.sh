#!/bin/sh
# Bounded driver/VLAN recovery drill, only from the existing Linux baseline.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODE=drill
if [ "${1:-}" = --restore ]; then MODE=restore; shift; fi
BASE=${1:?baseline directory required}
[ "$(id -u)" -eq 0 ]
restore() {
    "$HERE/../restore-nic0.sh" --force
    python3 - "$BASE/linux-state.json" <<'PY'
import json, subprocess, sys
s = json.load(open(sys.argv[1]))
for name in ('nic0', 'vps', 'lan', 'br0'):
    link = s['links'][name]
    subprocess.run(['ip', 'link', 'set', 'dev', name, 'address', link['mac'],
                    'mtu', str(link['mtu'])], check=True)
PY
    # Recreated WAN loses its nft ingress flowtable device binding.
    nft -c -f "$BASE/restore-firewall.nft"
    nft -f "$BASE/restore-firewall.nft"
    dhcpcd --rebind wan
}
if [ "$MODE" = restore ]; then restore; exit; fi
[ "${SSH_CONNECTION:-}" != "" ] || { echo 'Run with verified SSH_CONNECTION'; exit 1; }
set -- $SSH_CONNECTION
[ "$1" = 10.61.60.2 ] && [ "$3" = 10.61.60.1 ]
ip route get 10.61.60.2 | grep -q 'dev mgmt0 src 10.61.60.1'
[ ! -e /sys/class/net/mgmt0/master ]
! pgrep -x vpp >/dev/null
[ "$(basename "$(readlink /sys/bus/pci/devices/0000:01:00.0/driver)")" = r8125 ]
python3 "$HERE/linux-recovery-audit.py" check --directory "$BASE"
trap restore EXIT
printf '%s' 0000:01:00.0 > /sys/bus/pci/drivers/r8125/unbind
[ ! -e /sys/class/net/nic0 ]
echo 'nic0 driver unbound; independent mgmt0 retained'
sleep 2
restore
trap - EXIT
n=0
until python3 "$HERE/linux-recovery-audit.py" check --directory "$BASE"; do
    n=$((n+1)); [ "$n" -lt 18 ] || exit 1
    sleep 5
done
echo 'Driver/VLAN recovery and Linux baseline check passed'
