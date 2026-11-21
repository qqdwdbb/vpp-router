#!/usr/bin/env python3
"""Compile the real PMD transmit function against deterministic completion mocks.

Run with --source /path/to/r8169_rxtx.c. --expect-bug verifies the old function
reproduces a zero return despite available hardware completions. No NIC needed.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile


def transmit_function(source):
    start = source.index('uint16_t\nrtl_xmit_pkts(')
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define RTE_ASSERT(x) assert(x)
#define RTL_R8(hw, reg) 1
#define ChipCmd 0
#define CmdTxEnb 1
#define PMD_TX_LOG(...) ((void)0)
#define rte_wmb() ((void)0)
struct rtl_hw { int unused; };
struct rte_mbuf { uint16_t nb_segs; uint32_t pkt_len; struct rte_mbuf *next; };
struct rtl_tx_queue { struct rtl_hw *hw; uint16_t tx_free, tx_tail, tx_head;
                      unsigned pending, published, completed, clean_calls, ready_at, delayed, period; };
static uint64_t now;
static inline uint64_t rte_get_timer_cycles(void) { return now; }
static inline uint64_t rte_get_timer_hz(void) { return 1000000; }
static inline void rte_delay_us_block(unsigned us) { now += us; }
static void rtl_tx_clean(struct rtl_hw *hw, struct rtl_tx_queue *q) {
    (void)hw;
    q->clean_calls++;
    if (q->ready_at && now >= q->ready_at) {
        q->completed += q->delayed;
        if (q->period)
            q->ready_at += q->period;
        else {
            q->delayed = 0;
            q->ready_at = 0;
        }
    }
    q->tx_free += q->completed;
    q->completed = 0;
}
static void rtl_xmit_pkt(struct rtl_hw *hw, struct rtl_tx_queue *q, struct rte_mbuf *m) {
    (void)hw;
    assert(q->tx_free >= m->nb_segs);
    q->tx_free -= m->nb_segs;
    q->pending += m->nb_segs;
}
static void rtl_doorbell(struct rtl_hw *hw, struct rtl_tx_queue *q) {
    (void)hw;
    q->published += q->pending;
    q->pending = 0;
}
/* DMA publication is verified separately by integration_r8169_tx_dma.py. */
static inline void rtl_nc_tx_sync(struct rtl_tx_queue *q, uint32_t first) {
    (void)q; (void)first;
}
'''

SUFFIX = r'''
int main(void) {
    struct rtl_hw hw = {0};
    struct rte_mbuf m = {.nb_segs=1, .pkt_len=64};
    struct rte_mbuf *packets[4] = {&m, &m, &m, &m};
    struct rtl_tx_queue stale = {.hw=&hw, .tx_free=0, .completed=4};
    unsigned sent = rtl_xmit_pkts(&stale, packets, 4);
#ifdef EXPECT_BUG
    assert(sent == 0 && stale.tx_free == 4 && stale.published == 0);
    puts("Reproduced: old PMD returns zero despite reclaiming 4 completions");
#else
    assert(sent == 4 && stale.published == 4);
    struct rtl_tx_queue mid = {.hw=&hw, .tx_free=1, .completed=3};
    assert(rtl_xmit_pkts(&mid, packets, 4) == 4 && mid.published == 4);
    struct rtl_tx_queue full = {.hw=&hw, .tx_free=0};
    assert(rtl_xmit_pkts(&full, packets, 4) == 0 && full.published == 0);
    assert(full.clean_calls <= 403 && now == 2000); /* whole-burst budget */
    now = 0;
    struct rtl_tx_queue slow = {.hw=&hw, .tx_free=0, .ready_at=25, .delayed=4};
    assert(rtl_xmit_pkts(&slow, packets, 4) == 4 && slow.published == 4);
    assert(now == 25);
    now = 0;
    struct rtl_tx_queue bounded = {.hw=&hw, .tx_free=0, .ready_at=1000, .delayed=1, .period=1000};
    assert(rtl_xmit_pkts(&bounded, packets, 4) == 2 && bounded.published == 2);
    assert(now == 2000); /* progress does not restart the burst's deadline */
    struct rtl_tx_queue partial = {.hw=&hw, .tx_free=2};
    assert(rtl_xmit_pkts(&partial, packets, 4) == 2 && partial.published == 2);
    struct rtl_tx_queue empty = {.hw=&hw, .tx_free=4};
    assert(rtl_xmit_pkts(&empty, packets, 0) == 0 && empty.published == 0);
    struct rte_mbuf invalid = {.nb_segs=0, .pkt_len=0};
    struct rte_mbuf *bad[1] = {&invalid};
    assert(rtl_xmit_pkts(&empty, bad, 1) == 0 && empty.published == 0);
    puts("PASS: stale free count, mid-burst reclaim, bounded full-ring wait, delayed completion, partial burst, empty and invalid packets");
#endif
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--expect-bug', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='r8169-tx-reclaim-') as directory:
        root = Path(directory)
        program = root/'test.c'
        program.write_text(PREFIX + transmit_function(args.source.read_text()) + SUFFIX)
        command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror']
        if args.expect_bug:
            command.append('-DEXPECT_BUG')
        subprocess.run(command + [str(program), '-o', str(root/'test')], check=True)
        subprocess.run([str(root/'test')], check=True)


if __name__ == '__main__':
    main()
