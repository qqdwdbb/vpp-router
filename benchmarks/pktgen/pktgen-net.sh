#!/usr/bin/env bash
# Temporarily configure a packet generator host. Runtime state only: nothing is
# written outside /run, and a reboot discards every change.
#
#   pktgen-net.sh [--conf FILE] up [--ttl MINUTES]   apply the configuration
#   pktgen-net.sh [--conf FILE] down                 restore the state saved by "up"
#   pktgen-net.sh [--conf FILE] status               show the current state
#
# Configuration: --conf, $PKTGEN_NET_CONF, or pktgen-net.conf next to this script.
set -euo pipefail

SELF=$(readlink -f "$0" 2>/dev/null || echo "$0")
CONF=${PKTGEN_NET_CONF:-$(dirname "$SELF")/pktgen-net.conf}
STATE=${PKTGEN_NET_STATE:-/run/pktgen-net}
TIMER=pktgen-net-restore

INTERFACES=()
DEFAULT_VIA=""
DEFAULT_DEV=""
PAUSE_OFF=()
GOVERNOR=""
CLEAR_HUGEPAGES=0
TTL_MINUTES=120
SSH_PORT=22

die() { echo "pktgen-net: $*" >&2; exit 1; }
log() { echo "pktgen-net: $*"; }

load_config() {
    [ -r "$CONF" ] || die "cannot read configuration $CONF"
    # shellcheck disable=SC1090
    . "$CONF"
    [ "${#INTERFACES[@]}" -gt 0 ] || die "INTERFACES is empty in $CONF"
}

require_root() { [ "$(id -u)" = 0 ] || die "run as root"; }

# Every interface with an established SSH session; independent of the caller's
# environment because sudo normally drops SSH_CONNECTION.
ssh_interfaces() {
    local local_addr addr
    {
        if [ -n "${SSH_CONNECTION:-}" ]; then
            ip route get "${SSH_CONNECTION%% *}" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p'
        fi
        ss -Htn state established 2>/dev/null | awk '{print $3}' | while read -r local_addr; do
            [ "${local_addr##*:}" = "$SSH_PORT" ] || continue
            addr=${local_addr%:*}
            addr=${addr#[}
            addr=${addr%]}
            addr=${addr#::ffff:}
            ip -o addr show to "$addr" 2>/dev/null | awk '{print $2}'
        done
    } | sort -u
}

carries_ssh() { echo "$1" | grep -qxF "$2"; }

nm_available() { command -v nmcli >/dev/null 2>&1 && nmcli -t -f RUNNING general 2>/dev/null | grep -q running; }

nm_managed() {
    nm_available || return 1
    nmcli -t -f DEVICE,STATE device 2>/dev/null | grep -F "$1:" | grep -qv ':unmanaged'
}

pause_value() { ethtool -a "$1" 2>/dev/null | awk -v k="$2:" '$1==k{print $2; exit}'; }

save_state() {
    local entry name
    mkdir -p "$STATE"
    chmod 700 "$STATE"
    ip -4 route show default > "$STATE/default-routes"
    for entry in "${INTERFACES[@]}"; do
        name=${entry%% *}
        ip link show "$name" >/dev/null 2>&1 || die "no such interface: $name"
        ip -4 -o addr show dev "$name" scope global | awk '{print $4}' > "$STATE/$name.addr"
        if nm_managed "$name"; then echo yes; else echo no; fi > "$STATE/$name.managed"
    done
    if [ "${#PAUSE_OFF[@]}" -gt 0 ]; then
        for name in "${PAUSE_OFF[@]}"; do
            echo "$(pause_value "$name" Autonegotiate) $(pause_value "$name" RX) $(pause_value "$name" TX)" > "$STATE/$name.pause"
        done
    fi
    if [ -n "$GOVERNOR" ]; then
        for name in /sys/devices/system/cpu/cpufreq/policy*; do
            [ -e "$name/scaling_governor" ] && echo "$name $(cat "$name/scaling_governor")"
        done > "$STATE/governors"
    fi
}

clear_hugepages() {
    if pgrep -x '_t-rex-64' >/dev/null 2>&1 || pgrep -f 'dpdk' >/dev/null 2>&1; then
        log "DPDK process running, hugepage files left alone"
        return 0
    fi
    rm -f /dev/hugepages/rtemap_* 2>/dev/null || true
}

cmd_up() {
    local ttl=$TTL_MINUTES entry name addrs addr sshif
    while [ $# -gt 0 ]; do
        case "$1" in
            --ttl) [ $# -ge 2 ] || die "--ttl needs minutes"; ttl=$2; shift 2 ;;
            *) die "unknown option: $1" ;;
        esac
    done
    case "$ttl" in ''|*[!0-9]*) die "--ttl must be whole minutes" ;; esac
    [ ! -e "$STATE/active" ] || die "already active; run down first"
    save_state
    : > "$STATE/active"
    sshif=$(ssh_interfaces)
    if [ "$ttl" -gt 0 ] && command -v systemd-run >/dev/null 2>&1; then
        systemctl stop "$TIMER.timer" >/dev/null 2>&1 || true
        systemctl reset-failed "$TIMER.service" >/dev/null 2>&1 || true
        systemd-run --quiet --unit="$TIMER" --on-active="${ttl}min" \
            --setenv=PKTGEN_NET_CONF="$CONF" --setenv=PKTGEN_NET_STATE="$STATE" \
            /bin/bash "$SELF" down
    fi
    for entry in "${INTERFACES[@]}"; do
        name=${entry%% *}
        addrs=${entry#* }
        if carries_ssh "$sshif" "$name"; then
            log "$name carries an SSH session: adding addresses only"
            : > "$STATE/$name.protected"
        else
            if [ "$(cat "$STATE/$name.managed")" = yes ]; then
                nmcli device set "$name" managed no
            fi
            ip -4 addr flush dev "$name" scope global
        fi
        ip link set "$name" up
        for addr in ${addrs//,/ }; do
            ip addr replace "$addr" dev "$name"
        done
    done
    if [ -n "$DEFAULT_VIA" ]; then
        ip route replace default via "$DEFAULT_VIA" dev "$DEFAULT_DEV"
    fi
    if [ "${#PAUSE_OFF[@]}" -gt 0 ]; then
        for name in "${PAUSE_OFF[@]}"; do
            ethtool -A "$name" autoneg off rx off tx off 2>/dev/null || log "$name: pause unchanged"
        done
    fi
    if [ -n "$GOVERNOR" ]; then
        for name in /sys/devices/system/cpu/cpufreq/policy*; do
            [ -e "$name/scaling_governor" ] && echo "$GOVERNOR" > "$name/scaling_governor"
        done
    fi
    if [ "$CLEAR_HUGEPAGES" = 1 ]; then clear_hugepages; fi
    log "up; restores automatically in $ttl min (0 = never)"
}

cmd_down() {
    local entry name addr sshif protected auto rx tx path value
    [ -e "$STATE/active" ] || { log "not active"; return 0; }
    sshif=$(ssh_interfaces)
    systemctl stop "$TIMER.timer" >/dev/null 2>&1 || true
    for entry in "${INTERFACES[@]}"; do
        name=${entry%% *}
        [ -e "$STATE/$name.addr" ] || continue
        if [ -e "$STATE/$name.protected" ] || carries_ssh "$sshif" "$name"; then
            protected=1
            for addr in $(echo "${entry#* }" | tr ',' ' '); do
                grep -qxF "$addr" "$STATE/$name.addr" || ip addr del "$addr" dev "$name" 2>/dev/null || true
            done
        else
            protected=0
            ip -4 addr flush dev "$name" scope global
        fi
        while read -r addr; do
            [ -n "$addr" ] && ip addr replace "$addr" dev "$name"
        done < "$STATE/$name.addr"
        if [ "$(cat "$STATE/$name.managed")" = yes ] && [ "$protected" = 0 ]; then
            nmcli device set "$name" managed yes
        fi
    done
    if [ -n "$DEFAULT_VIA" ] && ! grep -q "via $DEFAULT_VIA dev $DEFAULT_DEV" "$STATE/default-routes"; then
        ip route del default via "$DEFAULT_VIA" dev "$DEFAULT_DEV" 2>/dev/null || true
    fi
    while read -r value; do
        # shellcheck disable=SC2086
        [ -n "$value" ] && { ip route replace $value 2>/dev/null || log "route not restored: $value"; }
    done < "$STATE/default-routes"
    for path in "$STATE"/*.pause; do
        [ -e "$path" ] || continue
        name=$(basename "$path" .pause)
        read -r auto rx tx < "$path"
        [ -n "$tx" ] && { ethtool -A "$name" autoneg "$auto" rx "$rx" tx "$tx" 2>/dev/null || log "$name: pause not restored"; }
    done
    if [ -e "$STATE/governors" ]; then
        while read -r path value; do
            echo "$value" > "$path/scaling_governor"
        done < "$STATE/governors"
    fi
    rm -rf "$STATE"
    log "down; previous state restored"
}

cmd_status() {
    local entry name
    if [ -e "$STATE/active" ]; then echo "active"; else echo "inactive"; fi
    for entry in "${INTERFACES[@]}"; do
        name=${entry%% *}
        ip -br -4 addr show dev "$name" 2>/dev/null || echo "$name missing"
    done
    ip -4 route show default
    systemctl list-timers --no-legend --no-pager "$TIMER.timer" 2>/dev/null || true
}

main() {
    if [ "${1:-}" = --conf ]; then
        [ $# -ge 2 ] || die "--conf needs a file"
        CONF=$(readlink -f "$2" 2>/dev/null || echo "$2")
        shift 2
    fi
    local action=${1:-}
    [ $# -gt 0 ] && shift
    case "$action" in
        up) load_config; require_root; cmd_up "$@" ;;
        down) load_config; require_root; cmd_down ;;
        status) load_config; cmd_status ;;
        *) sed -n '2,8p' "$SELF" | sed 's/^# \{0,1\}//'; [ -n "$action" ] && exit 2; exit 0 ;;
    esac
}

main "$@"
