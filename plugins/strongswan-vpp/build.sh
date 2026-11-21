#!/bin/sh
# Build only the IPsec backend, using configured strongSwan 6.0.4 headers.
set -eu
: "${STRONGSWAN_SOURCE:?Set STRONGSWAN_SOURCE to configured strongSwan 6.0.4 source}"
: "${VPP_SSWAN_SOURCE:?Set VPP_SSWAN_SOURCE to pristine stable/2606 extras/strongswan/vpp_sswan}"
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$VPP_SSWAN_SOURCE"
patch -p1 < "$project_dir/strongswan-6-vpp-26.patch"
patch -p1 < "$project_dir/strongswan-ipv6-outer-policy.patch"
python3 - <<'PY'
import json,re
from pathlib import Path
messages={}
for path in Path('/usr/share/vpp/api').rglob('*.api.json'):
    for message in json.loads(path.read_text()).get('messages',[]):
        if isinstance(message[-1],dict) and 'crc' in message[-1]:
            messages[message[0]]=message[-1]['crc'].removeprefix('0x')
for name in ['kernel_vpp_ipsec.c','kernel_vpp_shared.c']:
    path=Path(name)
    def replace(match):
        return '"'+match[1]+'_'+messages[match[1]]+'"'
    path.write_text(re.sub(r'"([a-z0-9_]+)_[0-9a-f]{8}"',replace,path.read_text()))
PY
for unit in ipsec shared plugin; do
    gcc -O2 -g -Wall -Wextra -fPIC -include "$STRONGSWAN_SOURCE/config.h" \
        -I"$STRONGSWAN_SOURCE/src/libstrongswan" -I"$STRONGSWAN_SOURCE/src/libcharon" \
        -c "kernel_vpp_$unit.c"
done
gcc -shared -o libstrongswan-kernel-vpp.so kernel_vpp_ipsec.o kernel_vpp_shared.o kernel_vpp_plugin.o \
    -lvppinfra -lvlibmemoryclient -lvlibapi -lsvm -lvppapiclient
printf '%s\n' "Built $VPP_SSWAN_SOURCE/libstrongswan-kernel-vpp.so; install only while strongSwan is stopped."
