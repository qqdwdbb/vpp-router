"""Exercise the production C translator with real IPv6 wire packets."""
import ctypes
import ipaddress
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def address(value):
    return ipaddress.IPv6Address(value).packed


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def check(packet):
    payload = packet[40:40 + struct.unpack('!H', packet[4:6])[0]]
    return checksum(packet[8:40] + struct.pack('!I3xB', len(payload), packet[6]) + payload)


def packet(src='fd00::2', dst='2001:db8::9', proto=17, sport=12345,
           dport=443, echo=128, payload=None):
    if payload is None:
        if proto == 17:
            payload = struct.pack('!4H', sport, dport, 13, 0) + b'hello'
        elif proto == 6:
            payload = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 80, 2, 65535, 0, 0)
        else:
            payload = struct.pack('!BBHHH', echo, 0, 0, sport, 1) + b'hello'
    data = bytearray(struct.pack('!IHBB', 6 << 28, len(payload), proto, 64)
                     + address(src) + address(dst) + payload)
    offset = {6: 56, 17: 46, 58: 42}[proto]
    data[offset:offset + 2] = b'\0\0'
    struct.pack_into('!H', data, offset, check(data) or 65535)
    return data


class NAPT66Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        library = Path(cls.temp.name) / 'napt66.so'
        subprocess.run([shutil.which('cc') or 'cc', '-shared', '-fPIC', '-std=c11',
                        '-Wall', '-Wextra', '-Werror', '-O2',
                        str(ROOT / 'plugins/napt66/napt66_core.c'), '-o', str(library)], check=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.n66_translate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_size_t, ctypes.c_int, ctypes.c_double]
        cls.lib.n66_expire.argtypes = [ctypes.c_void_p, ctypes.c_double, ctypes.c_uint]

    def setUp(self):
        # Prefix and external address are the first fields; ample aligned storage
        # keeps this test independent of platform-specific session padding.
        self.state = ctypes.create_string_buffer(2 * 1024 * 1024)
        ctypes.memmove(self.state, address('2001:db8::1') + address('fd00::'), 32)
        ctypes.c_uint.from_buffer(self.state, 32).value = 64

    def translate(self, data, inbound=False, now=1):
        buf = (ctypes.c_ubyte * len(data)).from_buffer(data)
        return self.lib.n66_translate(self.state, buf, len(data), inbound, now)

    def test_clients_same_port_and_roundtrip(self):
        for proto in (6, 17, 58):
            ports = []
            for client in ('fd00::2', 'fd00::3'):
                original = packet(src=client, proto=proto)
                data = original.copy()
                self.assertEqual(self.translate(data), 1)
                self.assertEqual(data[8:24], address('2001:db8::1'))
                self.assertEqual(check(data), 0)
                offset = 44 if proto == 58 else 40
                port = struct.unpack_from('!H', data, offset)[0]
                ports.append(port)
                repeat = original.copy()
                self.assertEqual(self.translate(repeat), 1)
                self.assertEqual(data, repeat)
                reply = packet(src='2001:db8::9', dst='2001:db8::1',
                               proto=proto, sport=port if proto == 58 else 443,
                               dport=port, echo=129)
                self.assertEqual(self.translate(reply, True), 1)
                self.assertEqual(reply[24:40], address(client))
                self.assertEqual(struct.unpack_from('!H', reply, 44 if proto == 58 else 42)[0], 12345)
                self.assertEqual(check(reply), 0)
            self.assertNotEqual(*ports)

    def test_remote_filter_and_timeout(self):
        data = packet()
        self.translate(data)
        port = struct.unpack_from('!H', data, 40)[0]
        for source, sport, now in [('2001:db8::8', 443, 2),
                                    ('2001:db8::9', 444, 2),
                                    ('2001:db8::9', 443, 302)]:
            reply = packet(src=source, dst='2001:db8::1', sport=sport, dport=port)
            before = reply.copy()
            self.assertEqual(self.translate(reply, True, now), -1)
            self.assertEqual(reply, before)

    def test_icmp_errors_and_truncated_tcp_quote(self):
        for proto in (6, 17, 58):
            for truncate in (False, True):
                data = packet(proto=proto)
                self.translate(data)
                quote = data[:48] if truncate else data
                error = packet(src='2001:db8::abcd', dst='2001:db8::1', proto=58,
                               payload=struct.pack('!BBHI', 2, 0, 0, 1280) + quote)
                self.assertEqual(self.translate(error, True), 1)
                self.assertEqual(error[24:40], address('fd00::2'))
                self.assertEqual(error[56:72], address('fd00::2'))
                self.assertEqual(check(error), 0)
                if not truncate:
                    self.assertEqual(check(error[48:]), 0)

    def test_bypass_and_reject(self):
        for data, inbound in [(packet(dst='fd00::9'), False),
                              (packet(src='fd01::2'), False),
                              (packet(src='2001:db8::9', dst='2001:db8::2'), True),
                              (packet(src='2001:db8::9', dst='2001:db8::1', proto=58), True)]:
            before = data.copy()
            self.assertEqual(self.translate(data, inbound), 0)
            self.assertEqual(data, before)
        for size in range(53):
            data = packet()[:size]
            self.assertEqual(self.translate(data), -1)
        for protocol in (0, 43, 44, 60):
            data = packet()
            data[6] = protocol
            self.assertEqual(self.translate(data), -1)

    def test_exhaustion_and_reclaim(self):
        for i in range(16384):
            data = packet(sport=i)
            self.assertEqual(self.translate(data), 1)
        self.assertEqual(self.translate(packet(sport=20000)), -1)
        self.lib.n66_expire(self.state, 302, 16384)
        self.assertEqual(self.translate(packet(sport=20000), now=303), 1)

    def test_malformed_udp_and_unmatched_inbound(self):
        for field, value in ((4, 7), (4, 65535), (44, 7), (44, 12), (46, 0)):
            data = packet()
            struct.pack_into('!H', data, field, value)
            before = data.copy()
            self.assertEqual(self.translate(data), -1)
            self.assertEqual(data, before)
        reply = packet(src='2001:db8::9', dst='2001:db8::1', dport=49152)
        self.assertEqual(self.translate(reply, True), -1)

    def test_shared_pool_across_inside_prefixes(self):
        # The VPP node selects the receiving interface's source prefix under
        # the session lock; all interfaces retain the same session table.
        for proto in (6, 17, 58):
            ports = []
            for prefix, client in [('fd00::', 'fd00::2'), ('fd42:1111:2222:90::', 'fd42:1111:2222:90::2')]:
                ctypes.memmove(ctypes.addressof(self.state) + 16, address(prefix), 16)
                data = packet(src=client, proto=proto)
                self.assertEqual(self.translate(data), 1)
                self.assertEqual(check(data), 0)
                ports.append(struct.unpack_from('!H', data, 44 if proto == 58 else 40)[0])
                # The same address received on the other inside is not selected.
                wrong = packet(src='fd42:1111:2222:90::2' if prefix == 'fd00::' else 'fd00::2', proto=proto)
                original = wrong.copy()
                self.assertEqual(self.translate(wrong), 0)
                self.assertEqual(wrong, original)
            self.assertNotEqual(*ports)
            for port, client in zip(ports, ['fd00::2', 'fd42:1111:2222:90::2']):
                reply = packet(src='2001:db8::9', dst='2001:db8::1', proto=proto,
                               sport=port if proto == 58 else 443, dport=port, echo=129)
                self.assertEqual(self.translate(reply, True), 1)
                self.assertEqual(reply[24:40], address(client))
                self.assertEqual(check(reply), 0)

    def test_parser_sanitizers(self):
        repo = Path(__file__).resolve().parents[2]
        binary = Path(self.temp.name) / 'parser-sanitizers'
        subprocess.run([shutil.which('cc') or 'cc', '-std=c11', '-g',
                        '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        str(repo / 'plugins/napt66/napt66_core.c'),
                        str(repo / 'tests/unit/test_napt66_core.c'), '-o', str(binary)],
                       check=True, capture_output=True)
        subprocess.run([str(binary)], check=True, capture_output=True, timeout=30)


if __name__ == '__main__':
    unittest.main()
