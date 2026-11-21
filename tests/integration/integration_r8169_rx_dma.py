#!/usr/bin/env python3
"""Compile the real RX loop and sync helpers against deferred DMA/cache mocks.

Use --baseline for the source before RX DMA batching. RX-batched and grouped
sources are recognized automatically; all versions run the same correctness cases.
The mocks check ordering; they cannot establish ARM cache or NIC correctness.
"""
import argparse
import re
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
#define RTE_PKTMBUF_HEADROOM 128
#define RTE_ETHER_CRC_LEN 4
#define RTE_SET_USED(x) ((void)(x))
#define RTL_R8(hw, reg) 1
#define ChipCmd 0
#define CmdRxEnb 1
#define PMD_RX_LOG(...) ((void)0)
#define unlikely(x) (x)
#define rte_rmb() ((void)0)
#define rte_wmb() ((void)0)
#define rte_prefetch0(x) ((void)(x))
#define rte_prefetch1(x) ((void)(x))
#define rte_cpu_to_le_64(x) (x)
#define rte_bswap16(x) __builtin_bswap16(x)
#define rte_pktmbuf_mtod(m, type) ((type)((char *)(m)->buf_addr + (m)->data_off))
#define RTL_DEV_PRIVATE(dev) ((struct rtl_adapter *)(dev)->data->dev_private)
#define DescOwn UINT32_C(0x80000000)
#define RingEnd UINT32_C(0x40000000)
#define RxVlanTag UINT32_C(0x10000)
#define BAD UINT32_C(0x20000)
#ifndef N
#define N 8
#endif
#define BUFS (N > 16 ? 8*N : 128)
#define ROOM 384
typedef uint32_t u32;
struct rtl_rx_desc { uint32_t reserved[4]; uint64_t addr; uint32_t opts2, opts1; };
_Static_assert(sizeof(struct rtl_rx_desc) == 32, "type-3 RX stride");
struct rtl_hw { unsigned RxDescLength, rx_buf_sz; };
struct rte_mbuf {
    void *buf_addr; uint16_t data_off, nb_segs, data_len, port, vlan_tci;
    uint32_t pkt_len, hash; uint64_t ol_flags; struct rte_mbuf *next;
};
struct rtl_rx_entry { struct rte_mbuf *mbuf; };
struct rtl_rx_queue {
    void *mb_pool; struct rtl_rx_desc *hw_ring; struct rtl_rx_entry *sw_ring;
    struct rtl_hw *hw;
    uint16_t rx_tail, nb_rx_desc, port_id, queue_id, nb_rx_hold, rx_free_thresh;
};
struct rtl_sw_stats { uint64_t rx_errors, rx_bytes, rx_packets; };
struct rtl_adapter { struct rtl_sw_stats sw_stats; };
struct rte_eth_dev_data { void *dev_private; unsigned rx_mbuf_alloc_failed; };
struct rte_eth_dev { struct rte_eth_dev_data *data; };
static struct rtl_adapter adapter;
static struct rte_eth_dev_data dev_data = {.dev_private=&adapter};
static struct rte_eth_dev rte_eth_devices[] = {{&dev_data}};
static int rtl_nc_dma = 1;
static unsigned rtl_nc_line = 64;
static _Alignas(128) struct rtl_rx_desc cpu[N], device[N];
static _Alignas(128) unsigned char data[BUFS][ROOM], dma_data[BUFS][ROOM];
static struct rte_mbuf mbufs[BUFS], *output[N];
static struct rtl_rx_entry sw[N];
static struct rtl_hw hw = {32, 256};
static struct rtl_rx_queue queue = {.hw=&hw, .hw_ring=cpu, .sw_ring=sw,
                                   .nb_rx_desc=N, .rx_free_thresh=0};
static unsigned allocated, allocation_limit, fences, desc_reads, desc_writes;
static unsigned single_calls, bulk_calls, bulk_failures, freed, force_bulk_fail;
static unsigned prepared[BUFS], payload_lines, map_calls, rdu_calls;
static int complete_late, stop_early;
struct op { uintptr_t address; int invalidate; };
static struct op pending[1024];
static unsigned pending_count;
static unsigned reverse_ops;

static void cache_op(uintptr_t address, int invalidate) {
    assert(pending_count < 1024);
    pending[pending_count++] = (struct op){address, invalidate};
}
static void complete(void) {
    fences++;
    for (unsigned n=0; n<pending_count; n++) {
        unsigned op = reverse_ops ? pending_count - 1 - n : n;
        uintptr_t a = pending[op].address;
        if (a >= (uintptr_t)cpu && a < (uintptr_t)(cpu+N)) {
            unsigned i = (a - (uintptr_t)cpu) / sizeof(*cpu);
            if (pending[op].invalidate) {
                memcpy(&cpu[i], &device[i], rtl_nc_line);
                desc_reads++;
            } else {
                for (unsigned j=i; j<i+rtl_nc_line/sizeof(*cpu); j++) {
                    assert(!(device[j].opts1 & DescOwn));
                    assert(cpu[j].opts1 & DescOwn);
                }
                memcpy(&device[i], &cpu[i], rtl_nc_line);
                desc_writes++;
            }
        } else {
            assert(a >= (uintptr_t)data && a < (uintptr_t)(data+BUFS));
            unsigned offset = a - (uintptr_t)data;
            unsigned b = offset / ROOM, line = offset % ROOM;
            assert(pending[op].invalidate && line >= RTE_PKTMBUF_HEADROOM);
            memcpy(&data[b][line], &dma_data[b][line], rtl_nc_line);
            prepared[b] |= 1u << ((line-RTE_PKTMBUF_HEADROOM)/rtl_nc_line);
            payload_lines++;
        }
    }
    pending_count = 0;
}
static struct rtl_rx_desc *rtl_get_rxdesc(struct rtl_hw *h, struct rtl_rx_desc *ring, unsigned i) {
    assert(h->RxDescLength == sizeof(*ring) && i<N); return &ring[i];
}
static uint64_t rte_mbuf_data_iova_default(struct rte_mbuf *m) {
    return (uintptr_t)m->buf_addr + RTE_PKTMBUF_HEADROOM;
}
static struct rte_mbuf *rte_mbuf_raw_alloc(void *pool) {
    (void)pool;
    single_calls++;
    if (allocated >= allocation_limit) return NULL;
    return &mbufs[allocated++];
}
#ifdef BULK_RX
static int rte_mbuf_raw_alloc_bulk(void *pool, struct rte_mbuf **objects, unsigned count) {
    (void)pool; bulk_calls++;
    if (force_bulk_fail || count > allocation_limit-allocated) { bulk_failures++; return -1; }
    for (unsigned i=0; i<count; i++) objects[i]=&mbufs[allocated++];
    return 0;
}
static void rte_mbuf_raw_free_bulk(void *pool, struct rte_mbuf **objects, unsigned count) {
    (void)pool;
    for (unsigned i=0; i<count; i++) assert(objects[i]==&mbufs[allocated-count+i]);
    allocated-=count; freed+=count;
}
#endif
static unsigned rtl_rx_desc_opts1(struct rtl_hw *h, struct rtl_rx_desc *d) {
    (void)h; return d->opts1;
}
static unsigned rtl_rx_desc_opts2(struct rtl_hw *h, struct rtl_rx_desc *d) {
    (void)h; return d->opts2;
}
static int rtl_check_rx_desc_error(struct rtl_hw *h, unsigned opts) {
    (void)h; return opts & BAD;
}
static uint64_t rtl_rx_desc_error_to_pkt_flags(struct rtl_rx_queue *q, unsigned a, unsigned b) {
    (void)q; (void)a; return b;
}
static void rtl_rx_set_rss_hash(struct rtl_hw *h, struct rtl_rx_desc *d, struct rte_mbuf *m) {
    (void)h; m->hash = d->reserved[2];
    if (stop_early) { cpu[1].opts1 |= DescOwn; stop_early=0; }
    if (complete_late) {
        device[1].opts1 = 64;
        complete_late = 0;
    }
}
static void rtl_mark_to_asic(struct rtl_hw *h, struct rtl_rx_desc *d) {
    unsigned i = d-cpu;
    assert(!(device[i].opts1 & DescOwn));
    if (rtl_nc_dma) {
        unsigned b = ((uintptr_t)d->addr - (uintptr_t)data - RTE_PKTMBUF_HEADROOM)/ROOM;
        assert(b<BUFS && prepared[b] == ((1u << (h->rx_buf_sz/rtl_nc_line))-1));
    }
    d->opts1 = (d->opts1 & RingEnd) | DescOwn | h->rx_buf_sz;
    d->opts2 = 0;
    map_calls++;
}
static void rtl_map_to_asic(struct rtl_hw *h, struct rtl_rx_desc *d, uint64_t address) {
    d->addr = address; rtl_mark_to_asic(h, d);
}
static void rtl_clear_rdu(struct rtl_hw *h, unsigned q) {
    (void)h; (void)q; assert(!pending_count); rdu_calls++;
}
'''


SUFFIX = r'''
static void reset(void) {
    rtl_nc_dma=1; rtl_nc_line=64;
    memset(&adapter, 0, sizeof(adapter)); dev_data.rx_mbuf_alloc_failed=0;
    memset(cpu, 0, sizeof(cpu)); memset(device, 0, sizeof(device));
    memset(prepared, 0, sizeof(prepared)); memset(data, 0xee, sizeof(data));
    memset(dma_data, 0x5a, sizeof(dma_data));
    for (unsigned i=0; i<BUFS; i++) {
        mbufs[i]=(struct rte_mbuf){.buf_addr=data[i],.nb_segs=1,.next=NULL};
    }
    for (unsigned i=0; i<N; i++) {
        sw[i].mbuf=&mbufs[i];
        device[i].opts1=DescOwn | (i==N-1 ? RingEnd : 0);
        device[i].addr=rte_mbuf_data_iova_default(sw[i].mbuf);
        device[i].reserved[2]=100+i;
    }
    queue.rx_tail=queue.nb_rx_hold=0;
    allocated=N; allocation_limit=BUFS;
    fences=desc_reads=desc_writes=payload_lines=map_calls=rdu_calls=pending_count=0;
    complete_late=stop_early=0;
    single_calls=bulk_calls=bulk_failures=freed=force_bulk_fail=0;
}
static void ready(unsigned i) { device[i].opts1=(device[i].opts1 & RingEnd) | 64; }
static void fresh(unsigned n) {
    assert(!pending_count);
    for (unsigned i=0; i<n; i++) {
        assert(output[i]->pkt_len==60 && output[i]->data_len==60);
        assert(output[i]->nb_segs==1 && output[i]->next==NULL && output[i]->port==queue.port_id);
        assert(*(unsigned char *)rte_pktmbuf_mtod(output[i], void *)==0x5a);
    }
}
int main(void) {
    reset();
    for (unsigned i=0; i<N; i++) ready(i);
    assert(rtl_recv_pkts(&queue,output,N)==N); fresh(N);
    assert(adapter.sw_stats.rx_packets==N && adapter.sw_stats.rx_bytes==60*N);
    assert(queue.rx_tail==0 && map_calls==N && desc_writes==N/2);
    assert(device[N-1].opts1 & RingEnd);
    printf("%u-packet burst: %u completion barriers, %u descriptor line reads, %u data line operations\n",
           N, fences, desc_reads, payload_lines);
#if defined(GROUPED)
    #ifdef READ_BATCH
    unsigned reads=2*((N+7)/8);
#else
    unsigned reads=N/2;
#endif
    assert(fences==reads+2*((N+2*REARM_LINES-1)/(2*REARM_LINES))+1 && desc_reads==N/2 && payload_lines==5*N);
#elif !defined(BASELINE)
    assert(fences==3*N/2+1 && desc_reads==N/2 && payload_lines==5*N);
#else
    assert(fences==7*N/2 && desc_reads==N && payload_lines==5*N);
#endif
#ifdef BULK_RX
    assert(bulk_calls==(N+7)/8 && !single_calls && !bulk_failures && !freed);
    printf("%u-packet burst: %u bulk allocations, %u scalar allocations\n", N, bulk_calls, single_calls);
    reset();
    for (unsigned i=0; i<N; i++) ready(i);
    force_bulk_fail=1;
    assert(rtl_recv_pkts(&queue,output,N)==N); fresh(N);
    assert(bulk_calls==1 && bulk_failures==1 && single_calls==N);
    assert(!dev_data.rx_mbuf_alloc_failed && !freed);
    /* A failed bulk must preserve scalar partial progress, including errors. */
    for (unsigned available=0; available<8; available++) {
        reset();
        for (unsigned i=0; i<N; i++) ready(i);
        allocation_limit=N+available;
        assert(rtl_recv_pkts(&queue,output,N)==available); fresh(available);
        assert(allocated==N+available && bulk_calls==1 && bulk_failures==1);
        assert(single_calls==available+1 && dev_data.rx_mbuf_alloc_failed==1);
        assert(queue.rx_tail==available && !freed);
        assert(adapter.sw_stats.rx_packets==available && adapter.sw_stats.rx_bytes==60*available);
        allocation_limit=BUFS;
        assert(rtl_recv_pkts(&queue,output,1)==1); fresh(1);
    }
    reset();
    for (unsigned i=0; i<N; i++) ready(i);
    device[1].opts1 |= BAD; device[3].opts1 |= BAD;
    allocation_limit=N+3;
    assert(rtl_recv_pkts(&queue,output,N)==3); fresh(3);
    assert(adapter.sw_stats.rx_errors==2 && queue.rx_tail==5 && allocated==N+3);
    assert(bulk_failures==1 && dev_data.rx_mbuf_alloc_failed==1);
    reset(); ready(0);
    assert(rtl_recv_pkts(&queue,output,N)==1); fresh(1);
    assert(single_calls==1 && !bulk_calls && allocated==N+1);
    /* Fault-inject an unexpected OWN to exercise defensive unused-refill cleanup. */
    reset();
    for (unsigned i=0; i<N; i++) ready(i);
    stop_early=1;
    assert(rtl_recv_pkts(&queue,output,N)==1); fresh(1);
    assert(freed==7 && allocated==N+1 && queue.rx_tail==1);
    reset(); rtl_nc_dma=0;
    for (unsigned i=0; i<N; i++) ready(i);
    memcpy(cpu,device,sizeof(cpu)); memcpy(data,dma_data,sizeof(data));
    assert(rtl_recv_pkts(&queue,output,N)==N); fresh(N);
    assert(!fences && map_calls==N && bulk_calls==(N+7)/8);
#endif
    /* Low-rate partial lines: no writeback while a neighbour is NIC-owned. */
    reset(); ready(0);
    assert(rtl_recv_pkts(&queue,output,1)==1); fresh(1);
    assert(!map_calls && !desc_writes && device[1].opts1 & DescOwn);
    ready(1);
    assert(rtl_recv_pkts(&queue,output,1)==1); fresh(1);
    assert(map_calls==2 && desc_writes==1 && queue.rx_tail==2);
    /* Allocation failure after one packet must drain pending data operations. */
    reset(); ready(0); ready(1); allocation_limit=N+1;
    assert(rtl_recv_pkts(&queue,output,8)==1); fresh(1);
    assert(queue.rx_tail==1 && !map_calls && dev_data.rx_mbuf_alloc_failed==1);
    allocation_limit=BUFS;
    assert(rtl_recv_pkts(&queue,output,1)==1); fresh(1);
    assert(queue.rx_tail==2 && map_calls==2);
    /* Error descriptors reuse their buffer, including an error-only line. */
    reset(); ready(0); ready(1); ready(2); ready(3);
    device[0].opts1 |= BAD; device[1].opts1 |= BAD; device[2].opts1 |= BAD;
    assert(rtl_recv_pkts(&queue,output,1)==1); fresh(1);
    assert(adapter.sw_stats.rx_errors==3 && allocated==N+1 && map_calls==4);
    /* A stale OWN snapshot may delay a neighbour until the next poll. */
    reset(); ready(0); complete_late=1;
    unsigned got=rtl_recv_pkts(&queue,output,2); fresh(got);
    if (got==1) { assert(rtl_recv_pkts(&queue,output,1)==1); fresh(1); }
    else assert(got==2);
    assert(queue.rx_tail==2 && adapter.sw_stats.rx_packets==2);
    /* Ring wrap with metadata read before rearm and RingEnd preserved. */
    reset(); queue.rx_tail=N-2;
    ready(N-2); ready(N-1); ready(0); ready(1);
    device[N-2].opts2=RxVlanTag | 0x1234;
    assert(rtl_recv_pkts(&queue,output,4)==4); fresh(4);
    assert(output[0]->vlan_tci==0x3412 && output[0]->hash==100+N-2);
    assert(queue.rx_tail==2 && device[N-1].opts1 & RingEnd);
    /* Repeated ownership transfers around the ring, using fresh mbufs. */
    reset();
    for (unsigned lap=0; lap<5; lap++) {
        for (unsigned i=0; i<N; i++) ready(i);
        assert(rtl_recv_pkts(&queue,output,N)==N); fresh(N);
        assert(queue.rx_tail==0 && device[N-1].opts1 & RingEnd);
    }
    /* CTR-derived line sizes: one, two or four type-3 descriptors per line. */
    for (unsigned line=32; line<=128; line*=2) {
        reset(); rtl_nc_line=line;
        for (unsigned i=0; i<N; i++) ready(i);
        assert(rtl_recv_pkts(&queue,output,N)==N); fresh(N);
        assert(desc_writes==N/(line/sizeof(*cpu)) && map_calls==N);
        reset(); rtl_nc_line=line; ready(0);
        device[0].opts1=hw.rx_buf_sz;
        assert(rtl_recv_pkts(&queue,output,1)==1 && !pending_count);
        assert(output[0]->pkt_len==252);
        unsigned char *p=rte_pktmbuf_mtod(output[0], unsigned char *);
        assert(p[0]==0x5a && p[251]==0x5a);
    }
    /* Empty polling must refresh on each call, including after zero allocation. */
    reset();
    assert(rtl_recv_pkts(&queue,output,8)==0);
    ready(0); allocation_limit=N;
    assert(rtl_recv_pkts(&queue,output,8)==0 && queue.rx_tail==0);
    allocation_limit=BUFS;
    assert(rtl_recv_pkts(&queue,output,1)==1); fresh(1);
    reset();
    assert(rtl_recv_pkts(&queue,output,0)==0 && !fences && !desc_reads);
    /* Empty and zero-budget paths still service deferred RDU accounting. */
    reset(); queue.nb_rx_hold=1;
    assert(rtl_recv_pkts(&queue,output,8)==0 && rdu_calls==1 && !queue.nb_rx_hold);
    reset(); queue.nb_rx_hold=1;
    assert(rtl_recv_pkts(&queue,output,0)==0 && rdu_calls==1 && !queue.nb_rx_hold);
    /* Completed lines must be published on every exit, including no packets. */
    reset();
    for (unsigned i=0; i<4; i++) { ready(i); device[i].opts1 |= BAD; }
    assert(rtl_recv_pkts(&queue,output,N)==0 && !pending_count);
    assert(map_calls==4 && desc_writes==2 && queue.rx_tail==4);
    reset();
    for (unsigned i=0; i<N; i++) { ready(i); device[i].opts1 |= BAD; }
    assert(rtl_recv_pkts(&queue,output,N)==0 && !pending_count);
    assert(map_calls==N && queue.rx_tail==0 && adapter.sw_stats.rx_errors==N);
    reset();
    for (unsigned i=0; i<N; i++) ready(i);
    allocation_limit=N+3;
    assert(rtl_recv_pkts(&queue,output,N)==3); fresh(3);
    assert(map_calls==2 && queue.rx_tail==3);
    allocation_limit=BUFS;
    assert(rtl_recv_pkts(&queue,output,1)==1); fresh(1);
    assert(map_calls==4 && queue.rx_tail==4);
    /* Every start/burst length, partial lines across calls, ring wrap, and
     * cache operations completing in reverse order at each barrier. */
    for (unsigned reverse=0; reverse<2; reverse++) {
        reverse_ops=reverse;
        for (unsigned line=32; line<=128; line*=2) {
            for (unsigned start=0; start<N; start++) {
                for (unsigned burst=1; burst<=N; burst++) {
                    reset(); rtl_nc_line=line;
                    for (unsigned i=0; i<N; i++) ready(i);
                    if (start) {
                        assert(rtl_recv_pkts(&queue,output,start)==start); fresh(start);
                    }
                    unsigned maps_before=map_calls, writes_before=desc_writes;
                    unsigned total=0;
                    while (total<N) {
                        if (total && queue.rx_tail==0)
                            for (unsigned i=0; i<start; i++) ready(i);
                        unsigned limit=burst < N-total ? burst : N-total;
                        if (limit > (unsigned)(N-queue.rx_tail)) limit=N-queue.rx_tail;
                        unsigned got=rtl_recv_pkts(&queue,output,limit);
                        assert(got==limit); fresh(got); total+=got;
                    }
                    assert(queue.rx_tail==start && map_calls==maps_before+N);
                    assert(desc_writes==writes_before+N/(line/sizeof(*cpu)));
                    for (unsigned i=0; i<N; i++) {
                        unsigned partial_first=start/(line/sizeof(*cpu))*(line/sizeof(*cpu));
                        if (i<partial_first || i>=start) assert(device[i].opts1 & DescOwn);
                        else assert(!(device[i].opts1 & DescOwn));
                    }
                }
            }
        }
    }
    reverse_ops=0;
    /* Coherent mode retains direct rearm and issues no cache maintenance. */
    reset(); rtl_nc_dma=0; ready(0); memcpy(cpu,device,sizeof(cpu));
    assert(rtl_recv_pkts(&queue,output,1)==1);
    assert(!fences && !pending_count && map_calls==1 && cpu[0].opts1 & DescOwn);
    puts("PASS: data visibility, rearm ordering, partial lines, allocation failure, errors, stale OWN, wrap, metadata, empty/coherent paths");
    return 0;
}
'''


def instrument(source):
    names = ['rtl_nc_sync'] if 'rtl_nc_sync_range(' not in source else [
        'rtl_nc_sync_range', 'rtl_nc_sync_complete', 'rtl_nc_sync']
    names += ['rtl_nc_rearm']
    if 'rtl_nc_rearm_consumed(' in source:
        names.append('rtl_nc_rearm_consumed')
    if 'rtl_rx_scan_ready(' in source:
        names.append('rtl_rx_scan_ready')
    if 'rtl_recv_pkts_ready(' in source:
        names.append('rtl_recv_pkts_ready')
    code = '\n'.join(function(source, name) for name in names + ['rtl_recv_pkts'])
    for op, invalidate in [('civac', 1), ('cvac', 0)]:
        code = code.replace('__asm__ volatile("dc ' + op + ', %0" :: "r" (start) : "memory");',
                            f'cache_op(start, {invalidate});')
    code = code.replace('__asm__ volatile("dsb sy" ::: "memory");', 'complete();')
    assert '__asm__' not in code, 'Uninstrumented assembly in test'
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--ring-size', type=int, choices=[8, 12, 16, 32, 64], default=8)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='r8169-rx-dma-') as directory:
        root = Path(directory)
        source = root / 'test.c'
        driver = args.source.read_text()
        source.write_text(PREFIX + instrument(driver) + SUFFIX)
        match=re.search(r'#define RTL_NC_REARM_LINES (2|4|8)\b',driver)
        lines=int(match[1]) if match else 4
        flags = [f'-DN={args.ring_size}',f'-DREARM_LINES={lines}',f'-DRTL_NC_REARM_LINES={lines}']
        if 'uint16_t synced_until = tail;' in driver:
            flags.append('-DREAD_BATCH')
        if args.baseline:
            flags.append('-DBASELINE')
        if 'rtl_nc_rearm_consumed(' in driver:
            flags.append('-DGROUPED')
        if 'rtl_rx_scan_ready(' in driver:
            flags.append('-DBULK_RX')
        if args.sanitize:
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', *flags,
                        str(source), '-o', str(root / 'test')], check=True)
        subprocess.run([str(root / 'test')], check=True)


if __name__ == '__main__':
    main()
