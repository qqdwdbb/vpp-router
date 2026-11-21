import struct
import unittest

from integration_vrouter_ipsec_inject import rewrite
from test_ipsec_outer_capture import frame


class RewriteTests(unittest.TestCase):
    def test_extensions_preserve_ciphertext(self):
        encrypted=bytes(range(256))*5
        original=frame(50,encrypted)
        for mode,extra in [('hop',8),('dest',8),('hop-dest',16),('atomic',8)]:
            with self.subTest(mode=mode):
                packet,=rewrite(original,mode,1500,42)
                self.assertEqual(packet[54+extra:],encrypted)
                self.assertEqual(struct.unpack_from('!H',packet,18)[0],len(encrypted)+extra)

    def test_fragment_boundaries_reassemble_exactly(self):
        for mtu in (1280,1500):
            encrypted=bytes((i%251 for i in range(mtu-40)))
            original=frame(50,encrypted)
            for mode in ('frag-boundary','frag-reverse','frag-first8'):
                with self.subTest(mtu=mtu,mode=mode):
                    packets=rewrite(original,mode,mtu,42)
                    self.assertTrue(all(len(p)-14<=mtu for p in packets))
                    parts=sorted((struct.unpack_from('!H',p,56)[0]&0xfff8,p[62:]) for p in packets)
                    self.assertEqual(parts[0][0],0)
                    self.assertEqual(parts[1][0],len(parts[0][1]))
                    self.assertEqual(b''.join(p for offset,p in parts),encrypted)

    def test_invalid_fragment_probes_are_actually_invalid(self):
        original=frame(50,b'x'*1460)
        first,last=rewrite(original,'frag-overlap',1500,42)
        self.assertLess(struct.unpack_from('!H',last,56)[0]&0xfff8,len(first)-62)
        first,last=rewrite(original,'frag-short-first',1500,42)
        self.assertNotEqual((len(first)-62)%8,0)
        last,=rewrite(original,'frag-orphan',1500,42)
        self.assertGreater(struct.unpack_from('!H',last,56)[0]&0xfff8,0)
