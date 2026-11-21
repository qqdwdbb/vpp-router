"""Compile and exercise the actual C quote parser, without VPP dependencies."""
import ctypes
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from integration_vrouter_ipsec_inject import quote_cases


class QuoteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root=Path(cls.temp.name)
        header=Path(__file__).resolve().parents[2]/'plugins/ipsec-ike-punt/ipsec_ptb_quote.h'
        source=root/'quote.c'
        source.write_text('#include "'+str(header)+'"\nint parse(const unsigned char *p, size_t n, uint32_t *s) { return ipsec_ptb_quote_spi(p,n,s); }\n')
        subprocess.run([shutil.which('cc') or 'cc','-Wall','-Wextra','-Werror','-shared','-fPIC',str(source),'-o',str(root/'quote.so')],check=True,capture_output=True)
        cls.lib=ctypes.CDLL(str(root/'quote.so'))
        cls.lib.parse.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_uint32)]
        cls.lib.parse.restype=ctypes.c_int

    def test_live_quote_shapes_and_negative_controls(self):
        for native in (True,False):
            for name,packet,expected in quote_cases(0x12345678,native):
                with self.subTest(native=native,name=name):
                    spi=ctypes.c_uint32(0)
                    accepted=self.lib.parse(packet,len(packet),ctypes.byref(spi))
                    self.assertEqual(bool(accepted),expected)
                    if accepted:self.assertEqual(spi.value,0x12345678)

    def test_truncation_at_every_header_byte(self):
        for native in (True,False):
            for name,packet,expected in quote_cases(0x12345678,native):
                if not expected:continue
                for size in range(len(packet)-4):
                    spi=ctypes.c_uint32(0)
                    self.assertEqual(self.lib.parse(packet[:size],size,ctypes.byref(spi)),0,(native,name,size))

    def test_wrong_version_unknown_protocol_and_bounded_chain(self):
        valid=quote_cases(0x12345678,True)[0][1]
        cases=[]
        wrong=bytearray(valid);wrong[0]=0x40;cases.append(bytes(wrong))
        unknown=bytearray(valid);unknown[6]=59;cases.append(bytes(unknown))
        long=bytearray(valid[:40]);long[6]=60
        body=(bytes([60,0])+b'\0'*6)*17+valid[40:]
        long[4:6]=len(body).to_bytes(2,'big');cases.append(bytes(long)+body)
        for packet in cases:
            spi=ctypes.c_uint32(0)
            self.assertEqual(self.lib.parse(packet,len(packet),ctypes.byref(spi)),0)
