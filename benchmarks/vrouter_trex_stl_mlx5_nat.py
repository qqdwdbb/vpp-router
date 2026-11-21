#!/usr/bin/env python3
"""Bounded STL burst from TRex net_mlx5 through VROUTER NAT44-EI to local eno1.

Sends 64-byte UDP frames: 203.0.113.10 -> 10.61.10.2:45997, Ethernet dest
the VROUTER WAN MAC. A public source address is required so vrouter-wan-in does not
drop RFC1918 bogons. The static mapping on the router must already exist.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


SRC_MAC = '02:00:00:00:10:03'
DST_MAC = '02:00:00:00:10:01'
SRC_IP = '203.0.113.10'
DST_IP = '10.61.10.2'
DST_PORT = 45997


def nic_stats(dev):
    link = json.loads(subprocess.check_output(
        ['ip', '-s', '-j', 'link', 'show', dev], text=True))
    try:
        driver = subprocess.check_output(['ethtool', '-S', dev], text=True)
    except subprocess.CalledProcessError:
        driver = ''
    return {'link': link, 'ethtool': driver}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trex', type=Path, required=True)
    parser.add_argument('--pps', type=int, required=True)
    parser.add_argument('--seconds', type=int, default=8)
    parser.add_argument('--rx-dev', default='eno1')
    parser.add_argument('--vary-sport', action='store_true')
    args = parser.parse_args()
    if not 1000 <= args.pps <= 8000000 or not 1 <= args.seconds <= 30:
        parser.error('rate or duration outside bounded benchmark limits')
    sys.path.insert(0, str(args.trex/'automation/trex_control_plane/interactive'))
    from trex.stl.api import (STLClient, Ether, IP, UDP, STLPktBuilder,
                              STLStream, STLTXCont, STLVM)

    packet = (Ether(src=SRC_MAC, dst=DST_MAC) /
              IP(src=SRC_IP, dst=DST_IP, ttl=64) /
              UDP(sport=50000, dport=DST_PORT, chksum=0) /
              (b'T' * 18))
    assert len(bytes(packet)) == 60
    vm = STLVM()
    vm.var(name='sport', min_value=1024, max_value=65535, size=2, op='inc')
    vm.write(fv_name='sport', pkt_offset='UDP.sport')
    builder_kwargs = dict(pkt=packet)
    if args.vary_sport:
        builder_kwargs['vm'] = vm
    try:
        builder = STLPktBuilder(enable_offload=False, **builder_kwargs)
    except TypeError:
        builder = STLPktBuilder(**builder_kwargs)

    client = STLClient()
    try:
        client.connect()
        client.reset(ports=[0])
        client.add_streams(
            STLStream(packet=builder, mode=STLTXCont(pps=args.pps)),
            ports=[0])
        client.clear_stats(ports=[0])
        result = dict(
            target_pps=args.pps, duration=args.seconds, frame_bytes=64,
            src_mac=SRC_MAC, dst_mac=DST_MAC, src_ip=SRC_IP, dst_ip=DST_IP,
            dst_port=DST_PORT, rx_dev=args.rx_dev,
            before_rx=nic_stats(args.rx_dev),
            version=client.get_server_version(),
            port_info=client.get_port_info(ports=[0]))
        start = time.monotonic()
        result['start'] = time.time()
        client.start(ports=[0])
        samples = []
        for _ in range(args.seconds):
            time.sleep(1)
            samples.append(client.get_stats(ports=[0]))
        client.stop(ports=[0])
        client.wait_on_traffic(ports=[0], timeout=10)
        result.update(
            elapsed=time.monotonic()-start, end=time.time(),
            stats=client.get_stats(ports=[0]), samples=samples,
            after_rx=nic_stats(args.rx_dev))
        path = Path('/var/tmp')/f'vrouter-trex-mlx5-{args.pps}-{int(result["start"])}.json'
        path.write_text(json.dumps(result, indent=2)+'\n')
        port0 = result['stats'].get('0') or result['stats'].get(0) or {}
        print('TREX_RESULT'+json.dumps({
            'target_pps': args.pps,
            'elapsed': result['elapsed'],
            'tx_packets': port0.get('opackets'),
            'tx_bytes': port0.get('obytes'),
            'tx_pps': port0.get('tx_pps'),
            'tx_errors': result['stats'].get('global', {}).get('queue_full', 0),
            'path': str(path),
        }), flush=True)
    finally:
        if client.is_connected():
            try:
                client.stop(ports=[0])
            finally:
                client.disconnect()


if __name__ == '__main__':
    main()
