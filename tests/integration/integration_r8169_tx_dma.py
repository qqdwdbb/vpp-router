#!/usr/bin/env python3
"""Compile real TX functions with deferred clean operations and a no-close NIC.

Use --baseline for the deployed RX-batched PMD. The model allows descriptor
eviction before payload clean completion, but consumes only at the SW-tail
doorbell. It checks ordering, not real ARM cache or NIC implementation details.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

from integration_r8169_tally_dma import function


PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define RTE_ARCH_ARM64 1
#define RTE_ASSERT(x) assert(x)
#define RTE_SET_USED(x) ((void)(x))
#define RTL_R8(hw, reg) 1
#define ChipCmd 0
#define CmdTxEnb 1
#define PMD_TX_LOG(...) ((void)0)
#define CFG_METHOD_48 48
#define CFG_METHOD_53 53
#define RTL_TX_OFFLOAD_MASK UINT64_MAX
#define FirstFrag UINT32_C(0x20000000)
#define LastFrag UINT32_C(0x10000000)
#define DescOwn UINT32_C(0x80000000)
#define RingEnd UINT32_C(0x40000000)
#define RTE_MIN(a,b) ((a)<(b)?(a):(b))
#define rte_cpu_to_le_64(x) (x)
#define rte_cpu_to_le_32(x) (x)
#define rte_pktmbuf_mtod(m, type) ((type)((char *)(m)->buf_addr + (m)->data_off))
#define RTL_DEV_PRIVATE(d) ((struct rtl_adapter *)(d)->data->dev_private)
#define N 16
#define BUFS 64
#define ROOM 2048
typedef uint32_t u32;
struct rtl_tx_desc { uint32_t opts1, opts2; uint64_t addr; };
_Static_assert(sizeof(struct rtl_tx_desc)==16, "TX descriptor stride");
struct rtl_hw { unsigned EnableTxNoClose, mcfg; };
struct rte_mbuf {
    void *buf_addr; uint16_t data_off, nb_segs, data_len;
    uint32_t pkt_len; uint64_t ol_flags; struct rte_mbuf *next;
};
struct rtl_tx_entry { struct rte_mbuf *mbuf; };
struct rtl_tx_queue {
    struct rtl_hw *hw; struct rtl_tx_desc *hw_ring; struct rtl_tx_entry *sw_ring;
    uint32_t tx_tail; uint16_t nb_tx_desc, tx_head, tx_free, port_id;
};
struct rtl_sw_stats { uint64_t tx_bytes, tx_packets; };
struct rtl_adapter { struct rtl_sw_stats sw_stats; };
struct rte_eth_dev_data { void *dev_private; };
struct rte_eth_dev { struct rte_eth_dev_data *data; };
static struct rtl_adapter adapter;
static struct rte_eth_dev_data dev_data = {&adapter};
static struct rte_eth_dev rte_eth_devices[] = {{&dev_data}};
static int rtl_nc_dma=1;
static unsigned rtl_nc_line=64;
static _Alignas(128) struct rtl_tx_desc cpu[N], device[N];
static _Alignas(128) unsigned char data[BUFS][ROOM], dma_data[BUFS][ROOM];
static struct rte_mbuf mbufs[BUFS], *packets[BUFS];
static struct rtl_tx_entry sw[N];
static struct rtl_hw hw = {.EnableTxNoClose=1, .mcfg=50};
static struct rtl_tx_queue queue = {.hw=&hw, .hw_ring=cpu, .sw_ring=sw, .nb_tx_desc=N};
static uint32_t published;
static unsigned fences, write_barriers, desc_lines, data_lines, doorbells, consumed, reclaimed;
static unsigned clean_calls, free_calls, tso_calls, csum_calls, ptp_calls;
static unsigned external_ready_at, external_completions;
static int evict_early;
static uint64_t now;
struct op { uintptr_t address; unsigned char bytes[128]; };
static struct op pending[2048];
static unsigned pending_count;
static void cache_op(uintptr_t address, int invalidate) {
    assert(!invalidate && pending_count<2048 && rtl_nc_line<=128);
    pending[pending_count].address=address;
    memcpy(pending[pending_count++].bytes, (void *)address, rtl_nc_line);
    if (address>=(uintptr_t)cpu && address<(uintptr_t)(cpu+N)) desc_lines++;
    else {
        assert(address>=(uintptr_t)data && address<(uintptr_t)(data+BUFS));
        data_lines++;
        /* A dirty descriptor line may evict before data maintenance completes.
         * In no-close mode no unpublished descriptor may be consumed yet. */
        if (evict_early) memcpy(device,cpu,sizeof(cpu));
    }
}
static void complete(void) {
    fences++;
    /* Adversarial completion order: descriptors can reach memory first. */
    for (unsigned pass=0; pass<2; pass++) {
        for (unsigned i=0; i<pending_count; i++) {
            uintptr_t a=pending[i].address;
            int desc=a>=(uintptr_t)cpu && a<(uintptr_t)(cpu+N);
            if ((pass==0)!=desc) continue;
            unsigned char *destination;
            if (desc) destination=(unsigned char *)device+(a-(uintptr_t)cpu);
            else destination=(unsigned char *)dma_data+(a-(uintptr_t)data);
            memcpy(destination,pending[i].bytes,rtl_nc_line);
        }
    }
    pending_count=0;
}
static void rte_wmb(void) { write_barriers++; }
static uint64_t rte_mbuf_data_iova(struct rte_mbuf *m) {
    return (uintptr_t)m->buf_addr+m->data_off;
}
static void rte_pktmbuf_free_seg(struct rte_mbuf *m) { (void)m; free_calls++; }
static uint32_t rtl_tx_vlan_tag(struct rte_mbuf *m, uint64_t flags) {
    (void)m; return flags ? 0x1234 : 0;
}
static int rtl_tso_setup(struct rte_mbuf *m, uint64_t flags, uint32_t *opts) {
    if (!(flags & 1)) return 0;
    tso_calls++;
    opts[0] |= 0x10000;
    *rte_pktmbuf_mtod(m,unsigned char *)=0x77;
    return 1;
}
static void rtl_setup_csum_offload(struct rte_mbuf *m, uint64_t flags, uint32_t *opts) {
    (void)m; (void)flags; opts[1] |= 0x20000; csum_calls++;
}
static void rtl8125_ptp_patch(struct rte_mbuf *m) {
    *rte_pktmbuf_mtod(m,unsigned char *)=0x88; ptp_calls++;
}
static uint64_t rte_get_timer_cycles(void) { return now; }
static uint64_t rte_get_timer_hz(void) { return 1000000; }
static void rte_delay_us_block(unsigned us) { now+=us; }
static void rtl_tx_clean(struct rtl_hw *h, struct rtl_tx_queue *q) {
    (void)h; clean_calls++;
    q->tx_free+=reclaimed; reclaimed=0;
    if (external_ready_at && now>=external_ready_at) {
        q->tx_free+=external_completions;
        external_ready_at=external_completions=0;
    }
}
static void rtl_doorbell(struct rtl_hw *h, struct rtl_tx_queue *q) {
    (void)h; assert(!pending_count);
    if (!rtl_nc_dma) {
        memcpy(device,cpu,sizeof(cpu)); memcpy(dma_data,data,sizeof(data));
    }
    uint32_t count=q->tx_tail-published;
    assert(count<N);
    for (unsigned n=0; n<count; n++) {
        unsigned i=(published+n)%N;
        struct rtl_tx_desc *d=&device[i];
        struct rte_mbuf *m=sw[i].mbuf;
        assert(m && (d->opts1 & DescOwn));
        assert(d->addr==rte_mbuf_data_iova(m));
        assert((d->opts1 & 0xffff)==m->data_len && d->opts2==cpu[i].opts2);
        unsigned offset=d->addr-(uintptr_t)data;
        assert(offset<sizeof(data) && m->data_len<=ROOM-offset%ROOM);
        assert(!memcmp((unsigned char *)dma_data+offset,(void *)(uintptr_t)d->addr,m->data_len));
        assert(!!(d->opts1 & RingEnd)==(i==N-1));
    }
    consumed+=count; reclaimed+=count; published=q->tx_tail; doorbells++;
}
'''


SUFFIX = r'''
static void reset(uint32_t first) {
    rtl_nc_dma=1; rtl_nc_line=64; hw.EnableTxNoClose=1;
    memset(cpu,0,sizeof(cpu)); memset(device,0,sizeof(device)); memset(sw,0,sizeof(sw));
    memset(&adapter,0,sizeof(adapter));
    memset(data,0x3c,sizeof(data)); memset(dma_data,0xee,sizeof(dma_data));
    for (unsigned i=0; i<BUFS; i++) {
        mbufs[i]=(struct rte_mbuf){.buf_addr=data[i],.data_off=128,.data_len=60,.pkt_len=60,.nb_segs=1};
        packets[i]=&mbufs[i];
    }
    queue.tx_tail=published=first; queue.tx_head=first%N; queue.tx_free=N-1;
    fences=write_barriers=desc_lines=data_lines=doorbells=consumed=reclaimed=pending_count=0;
    clean_calls=free_calls=tso_calls=csum_calls=ptp_calls=0;
    external_ready_at=external_completions=0;
    evict_early=0; now=0;
}
int main(void) {
    reset(0);
    assert(rtl_xmit_pkts(&queue,packets,8)==8 && consumed==8 && doorbells==1);
    printf("8-packet burst: %u completion barriers, %u descriptor line cleans, %u data line cleans\n",
           fences,desc_lines,data_lines);
#ifdef BASELINE
    assert(fences==16 && write_barriers==9 && desc_lines==8 && data_lines==8);
#else
    assert(fences==1 && write_barriers==1 && desc_lines==2 && data_lines==8);
#endif
    assert(csum_calls==8 && ptp_calls==8);
    assert(adapter.sw_stats.tx_packets==8 && adapter.sw_stats.tx_bytes==480);
    /* Every partial cache line and wrap, with/without early descriptor eviction. */
    for (unsigned line=32; line<=128; line*=2) {
        for (unsigned first=0; first<N; first++) {
            for (int evict=0; evict<2; evict++) {
                reset(first); rtl_nc_line=line; evict_early=evict;
                assert(rtl_xmit_pkts(&queue,packets,8)==8 && consumed==8);
                assert(queue.tx_tail==first+8 && queue.tx_free==N-1);
                assert(!pending_count);
            }
        }
    }
    /* Repeated calls sharing a descriptor line, then repeated ring wraps. */
    reset(0);
    for (unsigned n=0; n<40; n++) {
        assert(rtl_xmit_pkts(&queue,packets,n%8+1)==n%8+1);
        assert(published==queue.tx_tail && !pending_count);
    }
    assert(free_calls>0);
    /* Multi-segment packet across wrap; all fragment and offload fields survive. */
    reset(N-1);
    mbufs[0].nb_segs=3; mbufs[0].pkt_len=360; mbufs[0].ol_flags=1;
    mbufs[0].data_off=130; mbufs[0].data_len=120; mbufs[0].next=&mbufs[1];
    mbufs[1].data_len=140; mbufs[1].next=&mbufs[2]; mbufs[2].data_len=100;
    assert(rtl_xmit_pkts(&queue,packets,1)==1 && consumed==3);
    assert((device[N-1].opts1 & (FirstFrag|LastFrag|RingEnd))==(FirstFrag|RingEnd));
    assert(!(device[0].opts1 & (FirstFrag|LastFrag|RingEnd)));
    assert((device[1].opts1 & (FirstFrag|LastFrag|RingEnd))==LastFrag);
    assert((device[N-1].opts1 & 0x10000) && device[N-1].opts2==0x1234);
    assert(tso_calls==1 && ptp_calls==0);
    /* MTU packet, unaligned data, and a 32-bit monotonic tail rollover. */
    reset(UINT32_MAX-3);
    mbufs[0].data_off=133; mbufs[0].data_len=1500; mbufs[0].pkt_len=1500;
    assert(rtl_xmit_pkts(&queue,packets,8)==8 && consumed==8 && queue.tx_tail==4);
    /* Partial burst on invalid input or descriptor timeout must still publish. */
    reset(0); mbufs[1].nb_segs=0;
    assert(rtl_xmit_pkts(&queue,packets,8)==1 && consumed==1 && !pending_count);
    reset(0); queue.tx_free=2;
    assert(rtl_xmit_pkts(&queue,packets,8)==2 && consumed==2 && now==2000);
    reset(0); queue.tx_free=0;
    assert(rtl_xmit_pkts(&queue,packets,8)==0 && now==2000 && !fences && !doorbells);
    reset(0); queue.tx_free=0; external_ready_at=25; external_completions=2;
    assert(rtl_xmit_pkts(&queue,packets,2)==2 && now==25 && consumed==2);
    reset(0);
    assert(rtl_xmit_pkts(&queue,packets,0)==0 && !fences && !doorbells);
    mbufs[0].pkt_len=0;
    assert(rtl_xmit_pkts(&queue,packets,1)==0 && !fences && !doorbells);
    /* Existing coherent and close-mode behavior is retained. */
    reset(0); rtl_nc_dma=0;
    assert(rtl_xmit_pkts(&queue,packets,8)==8 && !fences && !desc_lines && !data_lines);
    reset(0); hw.EnableTxNoClose=0;
    assert(rtl_xmit_pkts(&queue,packets,8)==8 && fences==16 && desc_lines==8);
    puts("PASS: publication ordering, early eviction, partial lines, wrap/rollover, repeated calls, multi-segment, offloads, timeout and coherent/close paths");
    return 0;
}
'''


def program(source):
    names = ['rtl_nc_sync_range', 'rtl_nc_sync_complete', 'rtl_nc_sync', 'rtl_xmit_pkt']
    if 'rtl_nc_tx_sync(' in source:
        names.append('rtl_nc_tx_sync')
    names.append('rtl_xmit_pkts')
    code = '\n'.join(function(source, name) for name in names)
    for op, invalidate in [('civac', 1), ('cvac', 0)]:
        code = code.replace('__asm__ volatile("dc ' + op + ', %0" :: "r" (start) : "memory");',
                            f'cache_op(start, {invalidate});')
    code = code.replace('__asm__ volatile("dsb sy" ::: "memory");', 'complete();')
    assert '__asm__' not in code, 'Uninstrumented assembly in test'
    return PREFIX + code + SUFFIX


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='r8169-tx-dma-') as directory:
        root = Path(directory)
        source = root / 'test.c'
        source.write_text(program(args.source.read_text()))
        flags = ['-DBASELINE'] if args.baseline else []
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', *flags,
                        str(source), '-o', str(root / 'test')], check=True)
        subprocess.run([str(root / 'test')], check=True)


if __name__ == '__main__':
    main()
