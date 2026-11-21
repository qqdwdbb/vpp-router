#!/usr/bin/env python3
"""Parsers and frame decoding for IPsec PTB/MSS drop-node diagnostics."""
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from integration_vrouter_ipsec_diagnose import (
    capture_path, classify_ptb, decode_frame, error_delta, feature_order,
    first_tcp_drop, parse_errors, parse_runtime, parse_trace)


def ethernet(payload, proto):
    return b'\0' * 12 + proto + payload


def ipv4_tcp(src, dst, sport, dport, syn_ack=False, mss=1460, checksum=0xabcd):
    options = b'\x02\x04' + struct.pack('!H', mss)
    offset = 6 << 4
    flags = 0x12 if syn_ack else 0x02
    tcp = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, offset, flags, 65535, checksum, 0) + options
    total = 20 + len(tcp)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, 0, 64, 6, 0x1111,
                     socket.inet_aton(src), socket.inet_aton(dst)) + tcp
    return ethernet(ip, b'\x08\x00')


def ipv4_dest_unreach(src, dst, mtu, quoted_src, quoted_dst, quoted_sport, quoted_dport, proto=17):
    quoted_l4 = struct.pack('!HHHH', quoted_sport, quoted_dport, 8, 0)
    quoted = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 1, 0, 64, proto, 0,
                         socket.inet_aton(quoted_src), socket.inet_aton(quoted_dst)) + quoted_l4
    icmp = struct.pack('!BBHHH', 3, 4, 0, 0, mtu) + quoted
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0,
                     socket.inet_aton(src), socket.inet_aton(dst)) + icmp
    return ethernet(ip, b'\x08\x00')


def ipv6_ptb(src, dst, mtu, quoted_src, quoted_dst, next_header=50):
    quoted = struct.pack('!IHBB16s16s', 6 << 28, 0, next_header, 64,
                         socket.inet_pton(socket.AF_INET6, quoted_src),
                         socket.inet_pton(socket.AF_INET6, quoted_dst))
    icmp = struct.pack('!BBHI', 2, 0, 0, mtu) + quoted
    header = struct.pack('!IHBB16s16s', 6 << 28, len(icmp), 58, 64,
                         socket.inet_pton(socket.AF_INET6, src),
                         socket.inet_pton(socket.AF_INET6, dst))
    return ethernet(header + icmp, b'\x86\xdd')


class DiagnoseParserTests(unittest.TestCase):
    def test_parse_trace_node_path(self):
        packets = parse_trace('''Packet 1

00:00:00:000001: tap-input
  TAP rx
00:00:00:000002: ip6-input
00:00:00:000003: ip6-icmp-input
  unknown type
00:00:00:000004: ip6-punt
00:00:00:000005: ip6-punt-redirect
Packet 2

00:00:00:000006: tap-input
  TCP SYN
00:00:00:000007: tcp-mss-clamping-ip4-out
  max mss: 1158 clamped: 1
''')
        self.assertEqual(packets[0]['nodes'],
                         ['tap-input', 'ip6-input', 'ip6-icmp-input', 'ip6-punt', 'ip6-punt-redirect'])
        self.assertTrue(any('unknown type' in hint for hint in packets[0]['hints']))
        self.assertEqual(packets[1]['nodes'], ['tap-input', 'tcp-mss-clamping-ip4-out'])

    def test_error_and_runtime_deltas(self):
        before = '   Count                  Node                              Reason               Severity \n         1             ip6-icmp-input                    unknown type               error  \n'
        after = '   Count                  Node                              Reason               Severity \n         4             ip6-icmp-input                    unknown type               error  \n         1      tcp-mss-clamping-ip4-out               packets clamped             info   \n'
        delta = error_delta(before, after)
        self.assertEqual({(row['node'], row['count']) for row in delta},
                         {('ip6-icmp-input', 3), ('tcp-mss-clamping-ip4-out', 1)})
        runtime = parse_runtime('ip6-punt                        active              2               2               0\n'
                                'tcp-mss-clamping-ip4-in         active              0               0               0\n')
        self.assertEqual(runtime['ip6-punt'], 2)

    def test_feature_order_and_mss_before_nat(self):
        text = '''Available features:\n\narc: ip4-unicast\n  [ 0]: ip4-sv-reass\n  [ 1]: tcp-mss-clamping-ip4-in\n  [ 2]: nat44-ei-out2in\n\narc: ip4-output\n  [ 0]: ipsec4-output-feature\n  [ 1]: nat44-ei-in2out-output\n  [ 2]: tcp-mss-clamping-ip4-out\n'''
        unicast = feature_order(text, 'ip4-unicast')
        output = feature_order(text, 'ip4-output')
        self.assertEqual(unicast, ['ip4-sv-reass', 'tcp-mss-clamping-ip4-in', 'nat44-ei-out2in'])
        self.assertLess(unicast.index('tcp-mss-clamping-ip4-in'), unicast.index('nat44-ei-out2in'))
        self.assertEqual(output[-1], 'tcp-mss-clamping-ip4-out')

    def test_decode_syn_and_outer_ptb(self):
        syn = decode_frame(ipv4_tcp('10.254.62.1', '10.254.62.2', 40000, 49876, mss=1158, checksum=0x2222))
        ack = decode_frame(ipv4_tcp('10.254.62.2', '10.254.62.1', 49876, 40000, syn_ack=True, mss=1460, checksum=0x3333))
        ptb = decode_frame(ipv6_ptb('2001:db8:60::fe', '2001:db8:60::1', 1280,
                                    '2001:db8:60::1', '2001:db8:60::2'))
        self.assertEqual((syn['kind'], syn['mss'], syn['syn_ack'], syn['tcp_checksum']),
                         ('tcp', 1158, False, 0x2222))
        self.assertEqual((ack['mss'], ack['syn_ack']), (1460, True))
        self.assertEqual((ptb['kind'], ptb['icmp_type'], ptb['advertised_mtu'], ptb['quoted_next_header']),
                         ('icmp', 2, 1280, 50))
        self.assertEqual(ptb['quoted_dst'], '2001:db8:60::2')
        v4 = decode_frame(ipv4_dest_unreach('10.254.62.1', '10.254.62.2', 1198,
                                           '10.254.62.2', '10.254.62.1', 49880, 4500))
        self.assertEqual((v4['kind'], v4['icmp_type'], v4['icmp_code'], v4['advertised_mtu']),
                         ('icmp', 3, 4, 1198))
        self.assertEqual((v4['quoted_src'], v4['quoted_dst'], v4['quoted_sport'], v4['quoted_dport'],
                          v4['quoted_protocol']),
                         ('10.254.62.2', '10.254.62.1', 49880, 4500, 17))

    def test_classify_ptb_punt_without_inner_feedback(self):
        packets = [{'nodes': ['tap-input', 'ip6-icmp-input', 'ip6-punt', 'ip6-punt-redirect'], 'hints': ['unknown type']}]
        errors = [{'node': 'ip6-icmp-input', 'reason': 'unknown type', 'count': 1, 'severity': 'error'}]
        control = [{'kind': 'icmp', 'icmp_type': 2, 'advertised_mtu': 1280, 'dst': '2001:db8:60::1'}]
        result = classify_ptb(packets, errors, control, [])
        self.assertEqual(result['fate'], 'punt-to-control-tap')
        self.assertFalse(result['associated_with_sa'])
        self.assertFalse(result['inner_feedback_on_lan'])

    def test_classify_ptb_inner_icmp_from_encrypt(self):
        packets = [{'nodes': ['tap-input', 'ip6-lookup', 'ipsec6-output-feature',
                              'ipsec6-pmtu-check', 'ip6-icmp-error'], 'hints': []}]
        lan = [{'kind': 'icmp', 'icmp_type': 2, 'advertised_mtu': 1206, 'dst': '2001:db8:62::2'}]
        result = classify_ptb(packets, [], [], lan)
        self.assertEqual(result['fate'], 'inner-icmp')
        self.assertTrue(result['associated_with_sa'])
        self.assertTrue(result['inner_feedback_on_lan'])

    def test_first_drop_is_payload_when_synack_unclamped(self):
        drop = first_tcp_drop([{'bytes': 1, 'ok': True}, {'bytes': 1200, 'ok': False, 'error': 'timed out'}],
                              {'connected': True, 'effective_mss': 1460}, clamp_in=0, clamp_out=1)
        self.assertEqual(drop['stage'], 'payload')
        self.assertEqual(drop['bytes'], 1200)
        self.assertTrue(drop['syn_clamped'])
        self.assertFalse(drop['synack_clamped'])

    def test_capture_path_writes_snapshot(self):
        frames = [ipv4_tcp('10.254.62.1', '10.254.62.2', 40000, 49876, mss=1158),
                  ipv6_ptb('2001:db8:60::fe', '2001:db8:60::1', 1280, '2001:db8:60::1', '2001:db8:60::2')]
        callbacks = {}
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [*frames, StopIteration()]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('integration_vrouter_ipsec_diagnose.socket.AF_PACKET', 17, create=True), \
                 patch('integration_vrouter_ipsec_diagnose.socket.socket', return_value=sock), \
                 patch('integration_vrouter_ipsec_diagnose.signal.signal',
                       side_effect=lambda sig, handler: callbacks.update(handler=handler)):
                with self.assertRaises(StopIteration):
                    capture_path(root, 'mgmt0', 'lan-path')
                callbacks['handler']()
            records = json.loads((root / 'lan-path.json').read_text())
        self.assertEqual([row['kind'] for row in records], ['tcp', 'icmp'])
        self.assertEqual(records[0]['mss'], 1158)
        self.assertEqual(records[1]['advertised_mtu'], 1280)


if __name__ == '__main__':
    unittest.main()
