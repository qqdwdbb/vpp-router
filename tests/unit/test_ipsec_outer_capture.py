#!/usr/bin/env python3
"""Synthetic wire frames cover length and extension/fragment accounting."""
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from integration_vrouter_ipsec_outer import capture


def frame(protocol, payload, padding=b''):
    header=struct.pack('!IHBB16s16s',6<<28,len(payload),protocol,64,
        socket.inet_pton(socket.AF_INET6,'2001:db8:60::2'),
        socket.inet_pton(socket.AF_INET6,'2001:db8:60::1'))
    return b'\0'*12+b'\x86\xdd'+header+payload+padding


class CaptureTests(unittest.TestCase):
    def counters(self, frames, mtu=1500):
        callbacks={}
        sock=MagicMock()
        sock.__enter__.return_value=sock
        sock.recv.side_effect=[*frames,StopIteration()]
        with tempfile.TemporaryDirectory() as directory:
            with patch('integration_vrouter_ipsec_outer.socket.AF_PACKET',17,create=True), \
                 patch('integration_vrouter_ipsec_outer.socket.socket',return_value=sock), \
                 patch('integration_vrouter_ipsec_outer.signal.signal',side_effect=lambda sig,handler:callbacks.update(handler=handler)):
                with self.assertRaises(StopIteration):
                    capture(Path(directory),mtu)
                callbacks['handler']()
            return json.loads((Path(directory)/'outer-capture.json').read_text())['client_to_server']

    def test_padding_is_excluded_and_mtu_is_configurable(self):
        c=self.counters([frame(50,b'\1'*1240,b'\0'*32)],1280)
        self.assertEqual(c['max_l3_bytes'],1280)
        self.assertEqual(c['oversize_l3'],0)
        self.assertEqual(c['lengths'],{'1280':1})

    def test_extension_chain_and_first_nonfirst_fragments(self):
        first=struct.pack('!BBHI',50,0,1,42)+b'\1'*8
        following=struct.pack('!BBHI',50,0,8,42)+b'\1'*8
        hop=bytes([44,0])+b'\0'*6
        c=self.counters([frame(0,hop+first),frame(44,following)])
        self.assertEqual(c['esp_native'],1)
        self.assertEqual(c['outer_fragments'],2)
        self.assertEqual(c['first_fragments'],1)
        self.assertEqual(c['nonfirst_fragments'],1)
        self.assertEqual(c['extension_headers'],3)

    def test_natt_first_fragment_and_non_esp_marker(self):
        udp=struct.pack('!HHHH',4500,4500,24,0)
        fragment=struct.pack('!BBHI',17,0,1,42)
        c=self.counters([frame(44,fragment+udp+b'\x01'*16),frame(17,udp+b'\0'*16)])
        self.assertEqual(c['esp_udp4500'],1)
        self.assertEqual(c['ike_udp4500'],1)

    def test_ptb_records_advertised_mtu(self):
        c=self.counters([frame(58,struct.pack('!BBHI',2,0,0,1280))])
        self.assertEqual(c['icmp_errors'],{'6:2:0':1})
        self.assertEqual(c['ptb_mtu'],{'1280':1})

    def test_truncated_extension_does_not_invent_esp(self):
        c=self.counters([frame(60,bytes([50,8])+b'\0'*6)])
        self.assertEqual(c['esp_native'],0)


if __name__=='__main__':
    unittest.main()
