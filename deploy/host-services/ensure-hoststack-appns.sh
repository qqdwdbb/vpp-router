#!/bin/bash
# Recreate VPP default app ns on the configured LAN if its sw_if_index was deleted.
# Starting nginx-hoststack against a DELETED ns busy-loops the LDP worker
# (epoll_wait EBADFD) and never binds 10.61.20.1:80.
set -euo pipefail
VPPCTL=(/usr/local/bin/vppctl -s /run/vpp/cli.sock)
LAN_INTERFACE=${LAN_INTERFACE:-loop0}
[[ $LAN_INTERFACE =~ ^[a-zA-Z0-9_.-]+$ ]]
"${VPPCTL[@]}" session enable
ns=$("${VPPCTL[@]}" show app ns || true)
if echo "$ns" | grep -q DELETED; then
  "${VPPCTL[@]}" app ns del id default || true
  "${VPPCTL[@]}" app ns add id default secret 0 if "$LAN_INTERFACE"
fi
test -S /run/vpp/app_ns_sockets/default
