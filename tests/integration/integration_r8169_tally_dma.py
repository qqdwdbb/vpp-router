#!/usr/bin/env python3
"""Compile the actual tally reader with separate CPU-cache and device snapshots."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def function(text, name):
    start = text.index(name + '(')
    start = text.rfind('\n', 0, start - 1) + 1
    opening = text.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define RTE_DIM(a) (sizeof(a) / sizeof((a)[0]))
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t u16;
struct rtl_counters {
    uint64_t tx_packets, rx_packets, tx_errors;
    uint32_t rx_errors;
    uint16_t rx_missed;
};
struct rtl_hw { struct rtl_counters *tally_vaddr; uint64_t tally_paddr; int rtl8125; };
static int rtl_is_8125(struct rtl_hw *hw) { return hw->rtl8125; }
struct rtl_adapter { struct rtl_hw hw; };
struct rte_eth_dev { struct rtl_adapter *adapter; };
struct rte_eth_xstat { uint64_t id, value; };
struct rte_eth_xstat_name { char name[64]; };
#define RTL_DEV_PRIVATE(dev) ((dev)->adapter)
struct rte_eth_stats { uint64_t imissed, ierrors, oerrors, ipackets, opackets; };
#define CounterAddrHigh 1
#define CounterAddrLow 2
#define CounterDump 8
#define DMA_BIT_MASK(n) ((UINT64_C(1) << (n)) - 1)
#define rte_le_to_cpu_16(n) ((uint16_t)(n))
#define rte_le_to_cpu_32(n) ((uint32_t)(n))
#define rte_le_to_cpu_64(n) ((uint64_t)(n))
static struct rtl_counters device;
static unsigned sync_calls, writes, waits;
static int stuck;
static void rtl_sync_tally_dma(struct rtl_hw *hw) {
    sync_calls++;
    if (!(sync_calls & 1)) *hw->tally_vaddr = device;
}
static void mock_write(struct rtl_hw *hw, int reg, uint32_t value) {
    (void)hw;
    writes++;
    if (reg == CounterAddrLow && (value & CounterDump)) {
        device.rx_packets += 1000;
        device.tx_packets += 900;
    }
}
static uint32_t mock_read(struct rtl_hw *hw, int reg) {
    (void)hw; (void)reg;
    return stuck ? CounterDump : 0;
}
#define RTL_W32(hw, reg, value) mock_write(hw, reg, value)
#define RTL_R32(hw, reg) mock_read(hw, reg)
static void rte_delay_us(unsigned us) { assert(us == 10); waits++; }
'''

SUFFIX = r'''
int main(void) {
    struct rtl_counters cached = {.rx_packets=1, .tx_packets=2};
    struct rtl_hw hw = {.tally_vaddr=&cached, .tally_paddr=0x1000};
    struct rte_eth_stats stats = {0};
    device = (struct rtl_counters){.rx_errors=0x12345678, .rx_missed=65000,
                                  .tx_errors=UINT64_C(0x123456789)};
#ifdef EXPECT_BUG
    rtl_get_tally_stats(&hw, &stats);
    assert(device.rx_packets == 1000 && stats.ipackets == 1);
    assert(sync_calls == 0);
    puts("Reproduced: completed DMA snapshot is hidden behind stale CPU cache");
#else
    assert(rtl_get_tally_stats(&hw, &stats) == 0);
    assert(sync_calls == 2 && stats.ipackets == 1000 && stats.opackets == 900);
    assert(stats.imissed == 65000 && stats.ierrors == 0x12345678);
    assert(stats.oerrors == UINT64_C(0x123456789));
    _Static_assert(sizeof(struct rtl_counters) == 192, "complete RTL8125 DMA tally size");
    _Static_assert(offsetof(struct rtl_counters, rx_mac_missed) == 176, "RTL8125 missed offset");
    device.rx_mac_missed = 100000;
    hw.rtl8125 = 1;
    assert(rtl_get_tally_stats(&hw, &stats) == 0);
    assert(sync_calls == 4 && stats.ipackets == 2000 && stats.opackets == 1800);
    assert(stats.imissed == 65000); /* retain the vendor/mainline standard statistic */
    struct rte_eth_stats previous = stats;
    stuck = 1;
    assert(rtl_get_tally_stats(&hw, &stats) == -ETIMEDOUT);
    assert(waits == 21 && sync_calls == 5);
    assert(!memcmp(&previous, &stats, sizeof(stats)));
    unsigned old_writes = writes;
    hw.tally_vaddr = NULL;
    assert(rtl_get_tally_stats(&hw, &stats) == -ENODEV);
    assert(writes == old_writes && sync_calls == 5);
    struct rtl_adapter adapter = {.hw={.tally_vaddr=&cached, .tally_paddr=0x1000, .rtl8125=1}};
    struct rte_eth_dev dev = {.adapter=&adapter};
    struct rte_eth_xstat_name names[16];
    struct rte_eth_xstat values[16] = {0};
    int count = rtl_xstats_get_names(&dev, NULL, 0);
    assert(count == 15 && rtl_xstats_get(&dev, NULL, 0) == count);
    assert(rtl_xstats_get_names(&dev, names, 16) == count);
    assert(rtl_xstats_get(&dev, values, 0) == count);
    sync_calls = 0; stuck = 0; device.rdu = 123; device.rx_octets = UINT64_C(0x1234567890);
    assert(rtl_xstats_get(&dev, values, 16) == count);
    for (int i = 0; i < count; i++) {
        assert(values[i].id == (uint64_t)i);
        if (!strcmp(names[i].name, "rx_mac_missed")) assert(values[i].value == 100000);
        if (!strcmp(names[i].name, "rdu")) assert(values[i].value == 123);
        if (!strcmp(names[i].name, "rx_octets")) assert(values[i].value == UINT64_C(0x1234567890));
    }
    stuck = 1;
    assert(rtl_xstats_get(&dev, values, 16) == -ETIMEDOUT);
    adapter.hw.rtl8125 = 0;
    assert(rtl_xstats_get_names(&dev, NULL, 0) == 0);
    assert(rtl_xstats_get(&dev, values, 16) == 0);
    puts("PASS: fresh DMA snapshot, repeated updates, field widths, timeout and absent buffer");
#endif
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--expect-bug', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='r8169-tally-test-') as directory:
        root = Path(directory)
        source = root / 'test.c'
        compat = (args.source.parent / 'r8169_compat.h').read_text()
        first = compat.index('struct rtl_counters {')
        counters = compat[first:compat.index('};', first) + 2]
        first = PREFIX.index('struct rtl_counters {')
        prefix = PREFIX[:first] + counters + PREFIX[PREFIX.index('};', first) + 2:]
        extra = ''
        if not args.expect_bug:
            ethdev = (args.source.parent / 'r8169_ethdev.c').read_text()
            first = ethdev.index('/* RTL8125 diagnostics are distinct')
            extra = ethdev[first:ethdev.index('/* Return 0 means', first)]
        source.write_text(prefix + function(args.source.read_text(), 'rtl_get_tally_stats') + extra + SUFFIX)
        command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror']
        if args.expect_bug:
            # The old function never calls the synchronization mock.
            command += ['-DEXPECT_BUG', '-Wno-unused-function']
        subprocess.run(command + [str(source), '-o', str(root / 'test')], check=True)
        subprocess.run([str(root / 'test')], check=True)


if __name__ == '__main__':
    main()
