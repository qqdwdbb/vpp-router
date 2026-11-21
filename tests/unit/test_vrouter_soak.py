"""Verify the UDP integrity detector using real loopback traffic."""
import importlib.util
import hashlib
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest

spec = importlib.util.spec_from_file_location('nic1_soak',
    Path(__file__).resolve().parents[2] / 'benchmarks/diagnostics/nic1_soak.py')
soak = importlib.util.module_from_spec(spec)
spec.loader.exec_module(soak)
sys.modules['nic1_soak'] = soak
capture_spec = importlib.util.spec_from_file_location('udp_capture',
    Path(__file__).resolve().parents[2] / 'benchmarks/diagnostics/udp-capture.py')
capture = importlib.util.module_from_spec(capture_spec)
capture_spec.loader.exec_module(capture)


class IntegrityTests(unittest.TestCase):
    def exercise(self, corrupt=False, drop_first=False, targets='127.0.0.1'):
        stop = threading.Event()
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 46090))
        server.settimeout(.1)

        def echo():
            first = True
            while not stop.is_set():
                try:
                    packet, address = server.recvfrom(65535)
                    if drop_first and first:
                        first = False
                        continue
                    if corrupt:
                        packet = packet[:-1] + bytes([packet[-1] ^ 1])
                    server.sendto(packet, address)
                except socket.timeout:
                    pass

        thread = threading.Thread(target=echo)
        thread.start()
        result = {}
        try:
            soak.datagram_integrity(['127.0.0.1'] * 4, 1, targets, result)
        finally:
            stop.set()
            thread.join(timeout=2)
            server.close()
        return result

    def test_exact_echo(self):
        result = self.exercise(targets=['127.0.0.1'] * 4)
        self.assertTrue(result['passed'], result)
        self.assertTrue(all(flow['sent'] == flow['received'] for flow in result['flows']))

    def test_corrupt_echo_is_rejected(self):
        result = self.exercise(True)
        self.assertFalse(result['passed'])
        self.assertTrue(all(flow['corrupt'] > 0 for flow in result['flows']))

    def test_single_loss_is_rejected_and_identified(self):
        result = self.exercise(drop_first=True)
        self.assertFalse(result['passed'])
        self.assertEqual(sum(flow['lost'] for flow in result['flows']), 1)
        losses = [loss for flow in result['flows'] for loss in flow['loss_examples']]
        self.assertEqual(len(losses), 1)
        self.assertEqual(losses[0]['sequence'], 1)
        self.assertGreaterEqual(losses[0]['timeout_ms'], 2000)

    def test_capture_distinguishes_checksum_and_payload_damage(self):
        header = struct.pack('!8sQQ', b'VRSDMA01', 1, 2)
        payload = header + hashlib.shake_256(header).digest(41)
        addresses = socket.inet_aton('192.0.2.134') + socket.inet_aton('10.252.12.2')
        length = len(payload) + 8
        udp = struct.pack('!HHHH', 46090, 46100, length, 0) + payload
        value = soak.checksum(addresses + struct.pack('!BBH', 0, 17, length) + udp)
        udp = udp[:6] + struct.pack('!H', value or 65535) + udp[8:]
        ip = struct.pack('!BBHHHBBH', 0x45, 0, length + 20, 0, 0, 64, 17, 0) + addresses
        ip = ip[:10] + struct.pack('!H', soak.checksum(ip)) + ip[12:]
        frame = bytes(12) + b'\x08\x00' + ip + udp
        result = capture.inspect(frame, '192.0.2.134')
        self.assertTrue(result['udp_checksum_valid'])
        self.assertTrue(result['payload_valid'])
        damaged = frame[:40] + bytes([frame[40] ^ 1]) + frame[41:]
        result = capture.inspect(damaged, '192.0.2.134')
        self.assertFalse(result['udp_checksum_valid'])
        self.assertTrue(result['payload_valid'])
        damaged = frame[:-1] + bytes([frame[-1] ^ 1])
        result = capture.inspect(damaged, '192.0.2.134')
        self.assertFalse(result['udp_checksum_valid'])
        self.assertFalse(result['payload_valid'])


if __name__ == '__main__':
    unittest.main()
