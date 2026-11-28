#!/usr/bin/env python3
"""Bounded NAT test: 5 s warmup -> measured burst -> tail, without a pause.

Only the measured burst has a packet-group ID. Warmup and tail share its
five-tuples but do not enter the reported TX/RX counters. Requires an existing
NAT/VLAN fixture and static neighbor for the test destination.
"""
import argparse
import json
import sys
import time
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trex', type=Path, required=True)
    for name in ('src-mac', 'lan-mac', 'wan-mac', 'src-first', 'src-last', 'destination'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--rates', default='3000000,5000000,7000000,9000000')
    p.add_argument('--repeats', type=int, default=3)
    p.add_argument('--warmup', type=int, default=5)
    p.add_argument('--seconds', type=int, default=20)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    rates = [int(r) for r in a.rates.split(',')]
    if (not rates or any(not 10000 <= r <= 10000000 for r in rates)
            or not 1 <= a.repeats <= 5 or not 2 <= a.warmup <= 30
            or not 5 <= a.seconds <= 60):
        p.error('rate, warmup, duration or repeat outside bounded limits')
    sys.path.insert(0, str(a.trex / 'automation/trex_control_plane/interactive'))
    from trex.stl.api import (STLClient, Ether, Dot1Q, IP, UDP, STLVM,
                              STLPktBuilder, STLStream, STLTXCont,
                              STLTXSingleBurst, STLFlowStats)
    pkt = (Ether(src=a.src_mac, dst=a.lan_mac) / Dot1Q(vlan=2) /
           IP(src=a.src_first, dst=a.destination) /
           UDP(sport=20000, dport=7000, chksum=0) / (b'T' * 14))
    assert len(bytes(pkt)) == 60
    vm = STLVM()
    vm.var(name='src', min_value=a.src_first, max_value=a.src_last, size=4, op='inc')
    vm.write(fv_name='src', pkt_offset='IP.src')
    vm.var(name='sport', min_value=20000, max_value=21023, size=2, op='random')
    vm.write(fv_name='sport', pkt_offset='UDP.sport')
    vm.fix_chksum()
    learn = Ether(src=a.src_mac, dst=a.wan_mac) / Dot1Q(vlan=100, type=0x88b5) / (b'L'*42)
    c = STLClient()
    c.connect()
    try:
        for rate in rates:
            for repeat in range(1, a.repeats+1):
                c.reset(ports=[0])
                def builder():
                    return STLPktBuilder(pkt=pkt, vm=vm)
                c.add_streams([
                    STLStream(name='warmup', next='measure', isg=500000,
                              packet=builder(), mode=STLTXSingleBurst(
                                  pps=rate, total_pkts=rate*a.warmup)),
                    STLStream(name='measure', next='tail', self_start=False,
                              packet=builder(), mode=STLTXSingleBurst(
                                  pps=rate, total_pkts=rate*a.seconds),
                              flow_stats=STLFlowStats(pg_id=17)),
                    STLStream(name='tail', self_start=False, packet=builder(),
                              mode=STLTXSingleBurst(pps=rate, total_pkts=rate)),
                    STLStream(packet=STLPktBuilder(pkt=learn), mode=STLTXCont(pps=20)),
                ], ports=[0])
                c.clear_stats(ports=[0])
                c.start(ports=[0], duration=a.warmup+a.seconds+2)
                c.wait_on_traffic(ports=[0], timeout=a.warmup+a.seconds+20)
                time.sleep(2)
                stats = c.get_stats(ports=[0])
                flow = stats['flow_stats'][17]
                tx, rx = flow['tx_pkts']['total'], flow['rx_pkts']['total']
                row = dict(rate=rate, repeat=repeat, warmup_seconds=a.warmup,
                           measured_seconds=a.seconds, frame_bytes=64,
                           tx=tx, rx=rx, loss_percent=100*(tx-rx)/tx if tx else None,
                           rx_mpps=rx/a.seconds/1e6, port=stats[0], flow=flow,
                           generator_met_target=abs(tx-rate*a.seconds) <= 4)
                with a.output.open('a') as f:
                    f.write(json.dumps(row)+'\n')
                print(json.dumps({k:v for k,v in row.items() if k not in ('port','flow')}), flush=True)
    finally:
        try:
            c.stop(ports=[0])
        finally:
            c.disconnect()


if __name__ == '__main__':
    main()
