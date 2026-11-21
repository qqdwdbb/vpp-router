/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef N1_STATS_H
#define N1_STATS_H
#include <stdint.h>
#include <stdbool.h>

#define N1_BATCH_BINS 7u
#define N1_STATS_POLL_MASK 255u
#define N1_STATS_HZ_DIVISOR 100u /* target10ms; actual maximum gap is exported */
#define N1_MMC_EXTRA 11u
static const char *const n1_batch_labels[N1_BATCH_BINS] = {
    "0", "1", "2_4", "5_8", "9_16", "17_32", "33_64",
};
struct n1_batch_stats {
    uint64_t nonzero[6], maximum, budget_hits;
};
struct n1_hw_stats {
    bool mmc, initialized;
    uint32_t previous[3 + N1_MMC_EXTRA], missed_last;
    uint64_t pause_tx, pause_rx, fifo_frames;
    uint64_t desc_missed, dma_fifo_frames, desc_overflow_reads, fifo_overflow_reads;
    uint64_t unavailable_samples, overflow_samples, samples, rebases;
    uint64_t last_sample_cycles, max_interval_us;
    uint64_t mac[N1_MMC_EXTRA];
};

/* Count only nonempty bursts on the hot path; bucket zero is derived. */
static inline void n1_batch_record(struct n1_batch_stats *s, unsigned count,
                                    unsigned budget)
{
    if (!count)
        return;
    unsigned bin = count == 1 ? 0 : count <= 4 ? 1 : count <= 8 ? 2 :
                   count <= 16 ? 3 : count <= 32 ? 4 : 5;
    s->nonzero[bin]++;
    if (count > s->maximum) s->maximum = count;
    if (budget && count == budget) s->budget_hits++;
}
static inline uint64_t n1_batch_value(const struct n1_batch_stats *s,
                                       uint64_t calls, unsigned bin)
{
    if (bin) return s->nonzero[bin - 1];
    uint64_t nonzero = 0;
    for (unsigned i = 0; i < 6; i++) nonzero += s->nonzero[i];
    return calls - nonzero;
}
static inline uint32_t n1_counter_delta(uint32_t *previous, uint32_t current)
{
    uint32_t delta = current - *previous;
    *previous = current;
    return delta;
}
/* CSR8 clears on read. Overflow flags make the totals lower bounds: do not
 * invent the number of lost wraps or interpret a flag as a packet count. */
static inline void n1_missed_account(struct n1_hw_stats *s, uint32_t value)
{
    s->missed_last = value;
    s->desc_missed += value & (1u << 16) ? 0xffffu : value & 0xffffu;
    s->dma_fifo_frames += value & (1u << 28) ? 0x7ffu : (value >> 17) & 0x7ffu;
    s->desc_overflow_reads += !!(value & (1u << 16));
    s->fifo_overflow_reads += !!(value & (1u << 28));
}
#endif
