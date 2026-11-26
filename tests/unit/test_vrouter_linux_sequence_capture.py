"""Exercise actual Linux receiver parsing without sockets or a live network."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class ReceiverTests(unittest.TestCase):
    def test_sequences_and_truncated_frames(self):
        source = Path(__file__).resolve().parents[2] / 'benchmarks' / 'vrouter_linux_sequence_capture.c'
        harness = r'''
#define main capture_program_main
#include "SOURCE"
#undef main
#include <assert.h>
static void put32(unsigned char *p, uint32_t value) {
    value=htonl(value); memcpy(p,&value,4);
}
int main(void) {
    unsigned char frame[60]={0}; frame[14]=0x45; frame[23]=17;
    memcpy(frame+42,"VRS2",4); put32(frame+46,7); put32(frame+54,3);
    put32(frame+50,0); packet(frame,60,1);
    put32(frame+50,2); packet(frame,60,2);
    put32(frame+50,1); packet(frame,60,3); packet(frame,60,4);
    assert(used==1 && batches[0].unique==3 && batches[0].duplicate==1);
    assert(batches[0].reordered==1 && batches[0].first==1 && batches[0].last==3);
    unsigned char *short_frame=malloc(1); assert(short_frame);
    short_frame[0]=0;
    packet(short_frame,1,5); free(short_frame);
    put32(frame+50,3); packet(frame,60,6);
    put32(frame+54,0); packet(frame,60,7);
    put32(frame+54,30000001); packet(frame,60,8);
    put32(frame+54,4); put32(frame+50,0); packet(frame,60,9);
    assert(invalid==5 && batches[0].unique==3);
    put32(frame+46,8); put32(frame+54,30000000); put32(frame+50,29999999);
    packet(frame,60,10);
    assert(used==2 && batches[1].unique==1 && batches[1].highest==29999999);
    for (unsigned i=0; i<used; i++) free(batches[i].seen);
    return 0;
}
'''.replace('SOURCE', str(source))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'test.c').write_text(harness)
            subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',
                '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                str(root/'test.c'),'-o',str(root/'test')],check=True)
            subprocess.run([str(root/'test')],check=True)


if __name__=='__main__':
    unittest.main()
