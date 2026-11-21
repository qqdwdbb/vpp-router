/* SPDX-License-Identifier: BSD-3-Clause
 * Experimental DWMAC1000 normal-descriptor PMD, one RX/TX queue.
 * Register/descriptor layout: Linux v6.1.129 stmmac documentation/code.
 * Packet DMA directly accesses pinned mbuf data; the coherent arena holds rings.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_io.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_version.h>
#include <rte_interrupts.h>
#include <ethdev_vdev.h>
#include "n1_dma.h"
#include "n1_checksum.h"
#include "n1_stats.h"

#define OWN (1u << 31)
#define END (1u << 25)
#define ERROR (1u << 15)
#define MAC_SLOTS 16u
struct descriptor { uint32_t status, control, addr, next; };
struct n1_mapping;
struct n1 {
    int fd, intr_fd;
    uint8_t *regs, *arena;
    struct n1_info info;
    struct rte_mempool *pool;
    struct descriptor *rx, *tx;
    uint16_t port, rx_head, tx_head, tx_tail, outstanding;
    bool started, loopback, failed, flow_configured;
    struct rte_mbuf *rx_mbuf[N1_RING], *tx_mbuf[N1_RING];
    struct n1_mapping *maps;
    struct n1_mapping *last_map;
    uint64_t mapped_pages, sync_calls, split_descriptors;
    uint64_t cache_cpu, cache_device;
    uint32_t pause;
    uint64_t rx_offloads, tx_offloads;
    uint64_t tx_ring_full, tx_bad_layout, tx_bad_checksum, tx_sync_failure;
    uint64_t tx_calls, tx_requested, tx_accepted, tx_zero, tx_completed;
    uint64_t rx_calls, rx_ready;
    uint64_t rx_requested, reclaim_calls;
    struct n1_batch_stats rx_batch, tx_batch, reclaim_batch;
    struct n1_hw_stats hw;
    struct rte_eth_stats stats;
};
#include "n1_direct.h"
_Static_assert((N1_RING & (N1_RING - 1)) == 0, "N1_RING must be a power of two");

static uint32_t rd(struct n1 *p, uint32_t off)
{
    return rte_read32(p->regs + off);
}
static void wr(struct n1 *p, uint32_t off, uint32_t value)
{
    rte_write32(value, p->regs + off);
}
static const uint16_t mmc_offsets[] = {
    0x170, 0x1d0, 0x1d4, /* pauseTX, pauseRX, RX FIFO */
    0x180, 0x184, 0x194, 0x198, 0x1c8, 0x1dc, /* RX frames/bytes/CRC/align/length/watchdog */
    0x118, 0x148, 0x1a8, 0x1a4, 0x1a0, /* TX frames/underflow, RX over/under-size/jabber */
};
_Static_assert(RTE_DIM(mmc_offsets) == 3 + N1_MMC_EXTRA, "MMC counter layout");
static void hw_stats_init(struct n1 *p)
{
    struct n1_hw_stats *s = &p->hw;
    s->mmc = !!(rd(p, 0x1058) & (1u << 11));
    if (s->mmc) {
        /* Free running, rollover enabled, no reset-on-read or freeze. Only
         * the PMD owns these registers. Mask MMC IRQs in this polling driver. */
        wr(p, 0x100, 0);
        wr(p, 0x10c, UINT32_MAX);
        wr(p, 0x110, UINT32_MAX);
        wr(p, 0x200, UINT32_MAX);
        for (unsigned i = 0; i < RTE_DIM(mmc_offsets); i++)
            s->previous[i] = rd(p, mmc_offsets[i]);
    }
    (void)rd(p, 0x1020); /* discard pre-start CSR8 counts */
    wr(p, 0x1014, 0x90); /* discard pre-start RBU/overflow indications */
    s->initialized = true;
    s->rebases++;
    s->last_sample_cycles = rte_get_timer_cycles();
}
static void hw_stats_update(struct n1 *p)
{
    struct n1_hw_stats *s = &p->hw;
    if (!p->started || !s->initialized)
        return;
    uint64_t now = rte_get_timer_cycles(), hz = rte_get_timer_hz();
    uint64_t ticks = now - s->last_sample_cycles;
    uint64_t us = hz ? (ticks / hz) * 1000000 + (ticks % hz) * 1000000 / hz : 0;
    if (us > s->max_interval_us) s->max_interval_us = us;
    s->last_sample_cycles = now;
    s->samples++;
    n1_missed_account(s, rd(p, 0x1020));
    uint32_t indications = rd(p, 0x1014) & 0x90;
    s->unavailable_samples += !!(indications & 0x80);
    s->overflow_samples += !!(indications & 0x10);
    if (indications)
        wr(p, 0x1014, indications); /* W1C only these two bits, never FBI etc. */
    if (s->mmc) {
        s->pause_tx += n1_counter_delta(&s->previous[0], rd(p, 0x170));
        s->pause_rx += n1_counter_delta(&s->previous[1], rd(p, 0x1d0));
        s->fifo_frames += n1_counter_delta(&s->previous[2], rd(p, 0x1d4));
        for (unsigned i = 0; i < N1_MMC_EXTRA; i++)
            s->mac[i] += n1_counter_delta(&s->previous[i + 3], rd(p, mmc_offsets[i + 3]));
    }
    /* CSR8 reasons are disjoint; MMC FIFO is a cross-check, never add it a
     * second time. Overflow-read counters identify lower-bound intervals. */
    p->stats.imissed = s->desc_missed + s->dma_fifo_frames;
}
static uint32_t status(struct descriptor *d)
{
    return rte_le_to_cpu_32(__atomic_load_n(&d->status, __ATOMIC_RELAXED));
}
static inline void handoff(struct descriptor *d)
{
    __atomic_store_n(&d->status, rte_cpu_to_le_32(OWN), __ATOMIC_RELAXED);
}
static void intr_setup(struct rte_eth_dev *dev)
{
    struct n1 *p = dev->data->dev_private;
    struct rte_intr_handle *intr;
    int fd;
    if (p->intr_fd >= 0 || !dev->data->dev_conf.intr_conf.rxq)
        return;
    fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0)
        return;
    intr = rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_SHARED);
    if (!intr) {
        close(fd);
        return;
    }
    if (rte_intr_type_set(intr, RTE_INTR_HANDLE_EXT) ||
        rte_intr_vec_list_alloc(intr, "n1_rxq_intr", 1) ||
        rte_intr_vec_list_index_set(intr, 0, RTE_INTR_VEC_RXTX_OFFSET) ||
        rte_intr_efds_index_set(intr, 0, fd) ||
        rte_intr_nb_efd_set(intr, 1) || ioctl(p->fd, N1_IRQ_SETUP, &fd)) {
        fprintf(stderr, "n1_dwmac: RX interrupt setup failed: %s\n", strerror(errno));
        rte_intr_vec_list_free(intr);
        rte_intr_instance_free(intr);
        close(fd);
        return;
    }
    p->intr_fd = fd;
    dev->intr_handle = intr;
}

static int rx_intr_enable(struct rte_eth_dev *dev, uint16_t id)
{
    struct n1 *p = dev->data->dev_private;
    uint64_t one = 1;
    if (id || p->intr_fd < 0 || !p->started)
        return -ENOTSUP;
    if (ioctl(p->fd, N1_IRQ_ENABLE))
        return -errno;
    /* Recheck the ring after arming: a packet already completed before the
     * status clear cannot generate a new edge. */
    rte_io_rmb();
    if (!(status(&p->rx[p->rx_head]) & OWN) &&
        write(p->intr_fd, &one, sizeof(one)) < 0 && errno != EAGAIN)
        return -errno;
    return 0;
}

static int rx_intr_disable(struct rte_eth_dev *dev, uint16_t id)
{
    struct n1 *p = dev->data->dev_private;
    if (id || p->intr_fd < 0)
        return -ENOTSUP;
    return ioctl(p->fd, N1_IRQ_DISABLE) ? -errno : 0;
}
static int configure(struct rte_eth_dev *dev)
{
    if (dev->data->nb_rx_queues != 1 || dev->data->nb_tx_queues != 1 ||
        (dev->data->dev_conf.rxmode.offloads & ~N1_RX_CSUM) ||
        (dev->data->dev_conf.txmode.offloads & ~N1_TX_CSUM) ||
        dev->data->dev_conf.lpbk_mode > 1)
        return -ENOTSUP;
    struct n1 *p = dev->data->dev_private;
    p->rx_offloads = dev->data->dev_conf.rxmode.offloads;
    p->tx_offloads = dev->data->dev_conf.txmode.offloads;
    intr_setup(dev);
    return 0;
}
static int dev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *info)
{
    struct n1 *p = dev->data->dev_private;
    uint32_t features = rd(p, 0x1058);
    if (features & (1u << 18)) /* Type-2 RX COE; Type-1 appends extra bytes. */
        info->rx_offload_capa = N1_RX_CSUM;
    if (features & (1u << 16))
        info->tx_offload_capa = N1_TX_CSUM;
    info->max_rx_queues = info->max_tx_queues = 1;
    info->min_rx_bufsize = 1536;
    /* DPDK's frame limit includes FCS; the software limit is 1522 without it.
     * VPP reserves VLAN overhead separately when deriving the port MTU. */
    info->max_rx_pktlen = 1522 + RTE_ETHER_CRC_LEN;
    info->max_mtu = 1522 - RTE_ETHER_HDR_LEN;
    info->min_mtu = 68;
    info->max_mac_addrs = MAC_SLOTS;
    info->rx_desc_lim = (struct rte_eth_desc_lim){
        .nb_max = N1_RING, .nb_min = N1_RING, .nb_align = N1_RING,
        .nb_seg_max = 1, .nb_mtu_seg_max = 1,
    };
    info->tx_desc_lim = info->rx_desc_lim;
    info->speed_capa = RTE_ETH_LINK_SPEED_1G;
    return 0;
}
static int rx_setup(struct rte_eth_dev *dev, uint16_t id, uint16_t count,
                    unsigned socket, const struct rte_eth_rxconf *conf,
                    struct rte_mempool *pool)
{
    struct n1 *p = dev->data->dev_private;
    (void)socket; (void)conf;
    if (id || count != N1_RING || rte_pktmbuf_data_room_size(pool) < 1664)
        return -EINVAL;
    p->pool = pool;
    dev->data->rx_queues[0] = p;
    return 0;
}
static int tx_setup(struct rte_eth_dev *dev, uint16_t id, uint16_t count,
                    unsigned socket, const struct rte_eth_txconf *conf)
{
    (void)socket; (void)conf;
    if (id || count != N1_RING)
        return -EINVAL;
    dev->data->tx_queues[0] = dev->data->dev_private;
    return 0;
}
static void flow_control(struct n1 *p, uint32_t pause)
{
    if (p->flow_configured && p->pause == pause)
        return;
    uint32_t control = rd(p, 0x1018) & ~0x00c01f00u;
    uint32_t mac = 0;
    if (pause & N1_PAUSE_RX)
        mac |= 1u << 2;
    if (pause & N1_PAUSE_TX) {
        mac |= 1u << 1;
        /* N1 4 KiB FIFO: assert XOFF at full-2K and release at full-3K. */
        control |= (1u << 8) | (1u << 9) | (1u << 12);
    }
    if (mac)
        mac |= 0xffffu << 16;
    wr(p, 0x18, mac);
    wr(p, 0x1018, control);
    p->pause = pause;
    p->flow_configured = true;
}
static int link_update(struct rte_eth_dev *dev, int wait)
{
    struct n1 *p = dev->data->dev_private;
    struct n1_link l = {0};
    struct rte_eth_link link = {0};
    uint32_t control;
    (void)wait;
    if (ioctl(p->fd, N1_LINK, &l))
        return -errno;
    /* Half duplex and non-gigabit PHY clock changes are not implemented. */
    if (l.up && (l.speed != 1000 || !l.full_duplex))
        return -ENOTSUP;
    if (p->started && l.up) {
        control = rd(p, 0);
        control &= ~((1u << 15) | (1u << 14));
        wr(p, 0, control | (1u << 11));
    }
    if (p->started)
        flow_control(p, l.up ? l.pause : 0);
    link.link_status = l.up ? RTE_ETH_LINK_UP : RTE_ETH_LINK_DOWN;
    link.link_speed = l.speed;
    link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
    link.link_autoneg = RTE_ETH_LINK_AUTONEG;
    return rte_eth_linkstatus_set(dev, &link);
}
static int start(struct rte_eth_dev *dev)
{
    struct n1 *p = dev->data->dev_private;
    uint32_t i, control;
    int err;
    if (!p->pool)
        return -EINVAL;
    if (ioctl(p->fd, N1_STOP))
        return -errno;
    memset(p->arena, 0, N1_ARENA);
    p->rx_head = p->tx_head = p->tx_tail = p->outstanding = 0;
    p->failed = false;
    p->flow_configured = false;
    p->loopback = dev->data->dev_conf.lpbk_mode == 1;
    /* Claiming the helper restarts PHY autonegotiation. Both the physical
     * test and MAC loopback require a stabilized gigabit RGMII clock. */
    {
        struct n1_link physical = {0};
        unsigned tries;
        for (tries = 0; tries < 50; tries++) {
            if (ioctl(p->fd, N1_LINK, &physical))
                return -errno;
            if (physical.up)
                break;
            rte_delay_us_sleep(100000);
        }
        if (!physical.up)
            return -ENETDOWN;
        if (physical.speed != 1000 || !physical.full_duplex)
            return -ENOTSUP;
    }
    for (i = 0; i < N1_RING; i++) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(p->pool);
        if (!m || rx_prepare(p, i, m)) {
            if (m) rte_pktmbuf_free(m);
            release_mbufs(p);
            forget_maps(p);
            return -ENOMEM;
        }
        n1_cache_inval(rte_pktmbuf_mtod(m, void *), N1_RX_CAPACITY);
        p->rx_mbuf[i] = m;
    }
    n1_cache_barrier();
    p->cache_device += N1_RING;
    p->sync_calls++;
    p->last_map = NULL;
    rte_io_wmb();
    for (i = 0; i < N1_RING; i++) {
        handoff(&p->rx[i]);
    }
    wr(p, 0x101c, 0); /* RX interrupts are armed by the application. */
    /* N1 DT: snps,txpbl=8, snps,rxpbl=8, snps,aal; Linux enables PBLx8
     * unless snps,no-pbl-x8 is present. Restore that board DMA setup after
     * reset: separate RX/TX bursts, 8*8 beats, address-aligned bursts. */
    wr(p, 0x1000, (8u << 8) | (8u << 17) | (1u << 23) |
                   (1u << 24) | (1u << 25));
    wr(p, 0x100c, p->info.dma_base + N1_RX_DESC);
    wr(p, 0x1010, p->info.dma_base + N1_TX_DESC);
    wr(p, 0x44, (uint32_t)dev->data->mac_addrs[0].addr_bytes[0] |
               ((uint32_t)dev->data->mac_addrs[0].addr_bytes[1] << 8) |
               ((uint32_t)dev->data->mac_addrs[0].addr_bytes[2] << 16) |
               ((uint32_t)dev->data->mac_addrs[0].addr_bytes[3] << 24));
    wr(p, 0x40, (uint32_t)dev->data->mac_addrs[0].addr_bytes[4] |
               ((uint32_t)dev->data->mac_addrs[0].addr_bytes[5] << 8));
    wr(p, 0x4, 1); /* promiscuous; retain VLAN headers for VPP subinterfaces */
    wr(p, 0x1c, 0); /* no VLAN filtering/stripping */
    wr(p, 0x3c, 0x207); /* mask GMAC link/PMT/LPI interrupts */
    hw_stats_init(p);
    control = (1u << 27) | (1u << 22) | (1u << 16) | (1u << 11) | 0x0c;
    if (p->loopback)
        control |= 1u << 12;
    if (p->rx_offloads)
        control |= 1u << 10; /* GMAC_CONTROL_IPC */
    wr(p, 0, control); /* keep FCS in RX DMA length */
    wr(p, 0x1014, 0x1ffff);
    rte_io_wmb();
    /* Deliver checksum errors as BAD. Like dwmac1000_dma_operation_mode_tx,
     * enable OSF with TX store-and-forward so DMA can prepare the next frame
     * while the MAC transmits. Keep store-and-forward for checksum insertion. */
    wr(p, 0x1018, (1u << 26) | (1u << 25) | (1u << 21) | 0x2006);
    p->started = true;
    dev->data->rx_queue_state[0] = RTE_ETH_QUEUE_STATE_STARTED;
    dev->data->tx_queue_state[0] = RTE_ETH_QUEUE_STATE_STARTED;
    err = link_update(dev, 0);
    if (err < -1) {
        if (!ioctl(p->fd, N1_STOP)) { release_mbufs(p); forget_maps(p); }
        p->started = false;
        return err;
    }
    return 0;
}
static int stop(struct rte_eth_dev *dev)
{
    struct n1 *p = dev->data->dev_private;
    hw_stats_update(p);
    if (ioctl(p->fd, N1_STOP))
        return -errno;
    release_mbufs(p);
    if (forget_maps(p))
        return -EIO;
    p->started = false;
    dev->data->rx_queue_state[0] = RTE_ETH_QUEUE_STATE_STOPPED;
    dev->data->tx_queue_state[0] = RTE_ETH_QUEUE_STATE_STOPPED;
    return 0;
}
static int mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
    (void)dev;
    return mtu >= 68 && mtu <= 1522 - RTE_ETHER_HDR_LEN ? 0 : -EINVAL;
}
static int mac_set(struct rte_eth_dev *dev, struct rte_ether_addr *mac)
{
    struct n1 *p = dev->data->dev_private;
    const uint8_t *a = mac->addr_bytes;
    if (!rte_is_valid_assigned_ether_addr(mac))
        return -EINVAL;
    wr(p, 0x44, (uint32_t)a[0] | ((uint32_t)a[1] << 8) |
               ((uint32_t)a[2] << 16) | ((uint32_t)a[3] << 24));
    wr(p, 0x40, (uint32_t)a[4] | ((uint32_t)a[5] << 8));
    return 0;
}
static int mac_add(struct rte_eth_dev *dev, struct rte_ether_addr *mac,
                    uint32_t index, uint32_t pool)
{
    (void)dev; (void)pool;
    /* The port is always promiscuous. VPP performs destination filtering;
     * ethdev retains the logical secondary-address list in mac_addrs. */
    return index < MAC_SLOTS && rte_is_valid_assigned_ether_addr(mac) ? 0 : -EINVAL;
}
static void mac_remove(struct rte_eth_dev *dev, uint32_t index)
{
    (void)dev; (void)index;
}
static uint16_t rx_burst(void *queue, struct rte_mbuf **bufs, uint16_t limit)
{
    struct n1 *p = queue;
    struct rte_mbuf *replacement[64] = {0};
    uint32_t states[64];
    uint16_t count = 0, scanned = 0;
    if (unlikely(!p->started || p->failed))
        return 0;
    p->rx_calls++;
    p->rx_requested += limit;
    /* Drain narrow hardware counters even when nobody reads the CLI. Timer
     * checks are amortized across polls; no per-packet MMIO is introduced. */
    if (unlikely(!(p->rx_calls & N1_STATS_POLL_MASK)) && p->hw.initialized &&
        rte_get_timer_cycles() - p->hw.last_sample_cycles >=
            rte_get_timer_hz() / N1_STATS_HZ_DIVISOR)
        hw_stats_update(p);
    while (scanned < RTE_MIN(limit, 64)) {
        unsigned index = (p->rx_head + scanned) & N1_MASK;
        uint32_t s = status(&p->rx[index]);
        if (s & OWN)
            break;
        states[scanned++] = s;
    }
    if (!scanned)
        return 0;
    rte_io_rmb();
    if (unlikely(rte_pktmbuf_alloc_bulk(p->pool, replacement, scanned))) {
        unsigned got = 0;
        while (got < scanned) {
            replacement[got] = rte_pktmbuf_alloc(p->pool);
            if (!replacement[got])
                break;
            got++;
        }
        p->stats.rx_nombuf++;
        if (!got)
            return 0;
        scanned = got;
    }
    for (unsigned i = 0; i < scanned; i++) {
        unsigned index = (p->rx_head + i) & N1_MASK;
        unsigned dma_len = (states[i] >> 16) & 0x3fff;
        if (dma_len < 18 || dma_len > N1_RX_CAPACITY)
            dma_len = N1_RX_CAPACITY;
        n1_cache_inval(rte_pktmbuf_mtod(p->rx_mbuf[index], void *), dma_len);
        if (unlikely(rx_prepare(p, index, replacement[i])))
            goto failed;
        n1_cache_inval(rte_pktmbuf_mtod(replacement[i], void *), N1_RX_CAPACITY);
    }
    n1_cache_barrier();
    p->rx_ready += scanned;
    p->cache_cpu += scanned;
    p->cache_device += scanned;
    p->sync_calls++;
    rte_io_wmb();
    for (unsigned i = 0; i < scanned; i++) {
        unsigned index = (p->rx_head + i) & N1_MASK;
        handoff(&p->rx[index]);
    }
    wr(p, 0x1008, 1);
    for (unsigned i = 0; i < scanned; i++) {
        unsigned index = p->rx_head;
        struct rte_mbuf *m = p->rx_mbuf[index];
        uint32_t s = states[i], length = (s >> 16) & 0x3fff;
        p->rx_mbuf[index] = replacement[i];
        p->rx_head = (index + 1) & N1_MASK;
        if (unlikely(n1_rx_fatal(s) || (s & 0x300) != 0x300 || length < 18 || length > 1526)) {
            p->stats.ierrors++;
            rte_pktmbuf_free(m);
        } else {
            length -= 4;
            m->data_len = length; m->pkt_len = length; m->port = p->port;
            m->ol_flags = n1_rx_checksum(s, rte_pktmbuf_mtod(m, void *), length, p->rx_offloads);
            bufs[count++] = m;
            p->stats.ipackets++; p->stats.ibytes += length;
        }
    }
    n1_batch_record(&p->rx_batch, count, RTE_MIN(limit, 64));
    return count;
failed:
    p->failed = true;
    for (unsigned i = 0; i < scanned; i++)
        if (replacement[i]) rte_pktmbuf_free(replacement[i]);
    return count;
}
static void tx_clean(struct n1 *p)
{
    p->reclaim_calls++;
    unsigned ready = 0;
    uint32_t states[64];
    struct rte_mbuf *to_free[64];
    unsigned max_clean = RTE_MIN(p->outstanding, 64u);
    while (ready < max_clean) {
        unsigned index = (p->tx_tail + ready) & N1_MASK;
        uint32_t s = status(&p->tx[index]);
        if (s & OWN)
            break;
        states[ready++] = s;
    }
    if (!ready)
        return;
    n1_batch_record(&p->reclaim_batch, ready, max_clean);
    rte_io_rmb();
    p->tx_completed += ready;
    for (unsigned i = 0; i < ready; i++) {
        struct rte_mbuf *m = p->tx_mbuf[p->tx_tail];
        if (unlikely(states[i] & ERROR))
            p->stats.oerrors++;
        else {
            p->stats.opackets++;
            p->stats.obytes += m->pkt_len;
        }
        to_free[i] = m;
        p->tx_mbuf[p->tx_tail] = NULL;
        p->tx_tail = (p->tx_tail + 1) & N1_MASK;
    }
    p->outstanding -= ready;
    rte_pktmbuf_free_bulk(to_free, ready);
}
static uint16_t tx_burst(void *queue, struct rte_mbuf **bufs, uint16_t limit)
{
    struct n1 *p = queue;
    uint16_t count = 0;
    if (unlikely(!p->started || p->failed))
        return 0;
    p->tx_calls++; p->tx_requested += limit;
    if (p->outstanding >= 64 || p->outstanding + limit >= N1_RING - 1)
        tx_clean(p);
    if (unlikely(p->failed)) { p->tx_sync_failure++; p->tx_zero++; return 0; }
    while (count < RTE_MIN(limit, 64) && p->outstanding + count < N1_RING - 1) {
        struct rte_mbuf *m = bufs[count];
        uint16_t index = (p->tx_head + count) & N1_MASK;
        void *data = rte_pktmbuf_mtod(m, void *);
        uint32_t length = rte_pktmbuf_pkt_len(m);
        int checksum;
        if (unlikely(length < 14 || length > 1522 || m->nb_segs != 1 ||
                     m->data_len != length || rte_mbuf_refcnt_read(m) != 1 ||
                     m->pool != p->pool ||
                     (m->ol_flags & (RTE_MBUF_F_EXTERNAL | RTE_MBUF_F_INDIRECT)))) {
            p->tx_bad_layout++;
            break;
        }
        checksum = n1_tx_checksum(data, length, m->ol_flags, p->tx_offloads,
                                  m->l2_len, m->l3_len);
        if (unlikely(checksum < 0)) {
            p->tx_bad_checksum++;
            break;
        }
        if (unlikely(descriptor_data(p, &p->tx[index], data, length, (3u << 29) |
                                     ((uint32_t)checksum << 27) | (index == N1_RING - 1 ? END : 0)))) {
            p->tx_sync_failure++;
            break;
        }
        n1_cache_clean(data, length);
        p->tx_mbuf[index] = m;
        count++;
    }
    if (unlikely(count < RTE_MIN(limit, 64) && p->outstanding + count == N1_RING - 1))
        p->tx_ring_full++;
    if (count) {
        n1_cache_barrier();
        p->cache_device += count;
        p->sync_calls++;
        rte_io_wmb();
        for (unsigned i = 0; i < count; i++) handoff(&p->tx[(p->tx_head + i) & N1_MASK]);
        p->tx_accepted += count;
        p->outstanding += count; p->tx_head = (p->tx_head + count) & N1_MASK;
        wr(p, 0x1004, 1);
    } else {
        p->tx_zero++;
    }
    n1_batch_record(&p->tx_batch, count, RTE_MIN(limit, 64));
    return count;
}
#if RTE_VERSION >= RTE_VERSION_NUM(26, 3, 0, 0)
static int stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *out,
                     struct eth_queue_stats *queues)
#else
static int stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *out)
#endif
{
    struct n1 *p = dev->data->dev_private;
    tx_clean(p);
    hw_stats_update(p);
    *out = p->stats;
#if RTE_VERSION >= RTE_VERSION_NUM(26, 3, 0, 0)
    if (queues) {
        memset(queues, 0, sizeof(*queues));
        queues->q_ipackets[0] = p->stats.ipackets;
        queues->q_opackets[0] = p->stats.opackets;
        queues->q_ibytes[0] = p->stats.ibytes;
        queues->q_obytes[0] = p->stats.obytes;
        queues->q_errors[0] = p->stats.ierrors;
    }
#endif
    if (getenv("N1_DWMAC_DIAG")) {
        fprintf(stderr, "DIRECT pages=%llu sync=%llu cache_cpu=%llu cache_dev=%llu split=%llu outstanding=%u failed=%u\n",
                (unsigned long long)p->mapped_pages, (unsigned long long)p->sync_calls,
                (unsigned long long)p->cache_cpu, (unsigned long long)p->cache_device,
                (unsigned long long)p->split_descriptors, p->outstanding, p->failed);
        const uint32_t offsets[] = {0, 4, 0x20, 0x1000, 0x100c, 0x1010,
                                    0x1014, 0x1018, 0x101c, 0x1048,
                                    0x104c, 0x1050, 0x1054, 0x1058};
        for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++)
            fprintf(stderr, "REG %04x=%08x\n", offsets[i], rd(p, offsets[i]));
        for (unsigned i = 0; i < 4; i++)
            fprintf(stderr, "DESC %u RX=%08x/%08x/%08x TX=%08x/%08x/%08x\n", i,
                    status(&p->rx[i]), rte_le_to_cpu_32(p->rx[i].control),
                    rte_le_to_cpu_32(p->rx[i].addr), status(&p->tx[i]),
                    rte_le_to_cpu_32(p->tx[i].control), rte_le_to_cpu_32(p->tx[i].addr));
    }
    return 0;
}
static int close_dev(struct rte_eth_dev *dev)
{
    struct n1 *p = dev->data->dev_private;
    if (p->fd < 0)
        return 0;
    if (p->started && stop(dev))
        return -EIO;
    if (p->regs && p->regs != MAP_FAILED)
        munmap(p->regs, N1_REG_SIZE);
    if (p->arena && p->arena != MAP_FAILED)
        munmap(p->arena, N1_ARENA);
    close(p->fd); /* helper resets DMA and restores Linux on last reference */
    if (p->intr_fd >= 0) {
        rte_intr_nb_efd_set(dev->intr_handle, 0);
        rte_intr_vec_list_free(dev->intr_handle);
        rte_intr_instance_free(dev->intr_handle);
        dev->intr_handle = NULL;
        close(p->intr_fd);
        p->intr_fd = -1;
    }
    rte_free(p->maps); p->maps = NULL;
    p->last_map = NULL;
    p->fd = -1;
    return 0;
}
static int promisc(struct rte_eth_dev *dev) { (void)dev; return 0; }
static const char *const direct_names[] = {
    "rx_direct_dma_packets", "tx_direct_dma_packets", "dma_pinned_pages",
    "dma_sync_batches", "dma_cache_cpu", "dma_cache_device",
    "dma_cross_page_descriptors", "tx_pending_mbufs",
    "dma_failed", "tx_ring_full", "tx_bad_layout", "tx_bad_checksum",
    "tx_sync_failure", "tx_burst_calls", "tx_requested", "tx_accepted",
    "tx_zero_bursts", "tx_completed", "rx_burst_calls", "rx_ready",
    "dma_bus_mode", "dma_operation_mode", "dma_status",
    "negotiated_pause", "mac_flow_control",
    "rx_desc_missed_frames", "rx_fifo_overflow_frames",
    "rx_desc_counter_overflow_reads", "rx_dma_fifo_counter_overflow_reads",
    "rx_desc_unavailable_samples", "rx_fifo_overflow_samples",
    "rx_mmc_fifo_overflow_frames", "tx_pause_frames", "rx_pause_frames",
    "hw_mmc_supported", "hw_stats_samples", "hw_stats_rebases",
    "hw_stats_max_interval_us", "dma_missed_last", "mmc_control",
    "rx_burst_requested", "rx_burst_max", "rx_burst_budget_hits",
    "tx_burst_max", "tx_burst_budget_hits", "tx_reclaim_calls",
    "tx_reclaim_max", "tx_reclaim_budget_hits", "rx_refill_alloc_failures",
    "dma_axi_bus_mode", "mac_config", "mac_debug", "mac_address0_high", "dma_hw_feature",
    "mmc_rx_frames", "mmc_rx_bytes", "mmc_rx_crc_errors", "mmc_rx_align_errors",
    "mmc_rx_length_errors", "mmc_rx_watchdog_errors", "mmc_tx_frames",
    "mmc_tx_underflow_errors", "mmc_rx_oversize_frames", "mmc_rx_undersize_frames",
    "mmc_rx_jabber_errors", "mac_frame_filter",
};
static const char *const batch_prefixes[] = {"rx_burst", "tx_burst", "tx_reclaim"};
#define N1_XSTATS_COUNT (RTE_DIM(direct_names) + RTE_DIM(batch_prefixes) * N1_BATCH_BINS)
static int direct_names_get(struct rte_eth_dev *dev, struct rte_eth_xstat_name *out,
                             unsigned size)
{
    (void)dev;
    if (out && size >= N1_XSTATS_COUNT) {
        for (unsigned i = 0; i < RTE_DIM(direct_names); i++)
            snprintf(out[i].name, sizeof(out[i].name), "%s", direct_names[i]);
        for (unsigned g = 0; g < RTE_DIM(batch_prefixes); g++)
            for (unsigned b = 0; b < N1_BATCH_BINS; b++) {
                unsigned i = RTE_DIM(direct_names) + g * N1_BATCH_BINS + b;
                snprintf(out[i].name, sizeof(out[i].name), "%s_%s",
                         batch_prefixes[g], n1_batch_labels[b]);
            }
    }
    return N1_XSTATS_COUNT;
}
static int direct_stats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *out,
                             unsigned size)
{
    struct n1 *p = dev->data->dev_private;
    if (!out || size < N1_XSTATS_COUNT)
        return N1_XSTATS_COUNT;
    hw_stats_update(p);
    uint64_t values[] = {p->stats.ipackets, p->stats.opackets, p->mapped_pages,
                         p->sync_calls, p->cache_cpu, p->cache_device,
                         p->split_descriptors, p->outstanding, p->failed,
                         p->tx_ring_full, p->tx_bad_layout, p->tx_bad_checksum,
                         p->tx_sync_failure, p->tx_calls, p->tx_requested,
                         p->tx_accepted, p->tx_zero, p->tx_completed,
                         p->rx_calls, p->rx_ready,
                         rd(p, 0x1000), rd(p, 0x1018), rd(p, 0x1014),
                         p->pause, rd(p, 0x18),
                         p->hw.desc_missed, p->hw.dma_fifo_frames,
                         p->hw.desc_overflow_reads, p->hw.fifo_overflow_reads,
                         p->hw.unavailable_samples, p->hw.overflow_samples,
                         p->hw.fifo_frames, p->hw.pause_tx, p->hw.pause_rx,
                         p->hw.mmc, p->hw.samples, p->hw.rebases,
                         p->hw.max_interval_us, p->hw.missed_last,
                         p->hw.mmc ? rd(p, 0x100) : 0,
                         p->rx_requested, p->rx_batch.maximum, p->rx_batch.budget_hits,
                         p->tx_batch.maximum, p->tx_batch.budget_hits, p->reclaim_calls,
                         p->reclaim_batch.maximum, p->reclaim_batch.budget_hits,
                         p->stats.rx_nombuf, rd(p, 0x1028), rd(p, 0), rd(p, 0x24),
                         rd(p, 0x40), rd(p, 0x1058),
                         p->hw.mac[0], p->hw.mac[1], p->hw.mac[2], p->hw.mac[3],
                         p->hw.mac[4], p->hw.mac[5], p->hw.mac[6], p->hw.mac[7],
                         p->hw.mac[8], p->hw.mac[9], p->hw.mac[10], rd(p, 4)};
    _Static_assert(RTE_DIM(values) == RTE_DIM(direct_names), "xstat name/value mismatch");
    for (unsigned i = 0; i < RTE_DIM(values); i++)
        out[i] = (struct rte_eth_xstat){ .id = i, .value = values[i] };
    const struct n1_batch_stats *batches[] = {&p->rx_batch, &p->tx_batch, &p->reclaim_batch};
    uint64_t calls[] = {p->rx_calls, p->tx_calls, p->reclaim_calls};
    for (unsigned g = 0; g < RTE_DIM(batches); g++)
        for (unsigned b = 0; b < N1_BATCH_BINS; b++) {
            unsigned i = RTE_DIM(values) + g * N1_BATCH_BINS + b;
            out[i] = (struct rte_eth_xstat){ .id = i,
                         .value = n1_batch_value(batches[g], calls[g], b) };
        }
    return N1_XSTATS_COUNT;
}
static const struct eth_dev_ops ops = {
    .dev_configure = configure, .dev_infos_get = dev_info,
    .rx_queue_setup = rx_setup, .tx_queue_setup = tx_setup,
    .dev_start = start, .dev_stop = stop, .dev_close = close_dev,
    .link_update = link_update, .stats_get = stats_get,
    .rx_queue_intr_enable = rx_intr_enable, .rx_queue_intr_disable = rx_intr_disable,
    .xstats_get = direct_stats_get, .xstats_get_names = direct_names_get,
    .promiscuous_enable = promisc,
    .allmulticast_enable = promisc, .mtu_set = mtu_set, .mac_addr_set = mac_set,
    .mac_addr_add = mac_add, .mac_addr_remove = mac_remove,
};
static int probe(struct rte_vdev_device *vdev)
{
    struct rte_eth_dev *dev;
    struct n1 *p;
    int err = -ENOMEM;
    if (rte_eal_process_type() != RTE_PROC_PRIMARY ||
        rte_vdev_device_args(vdev)[0])
        return -ENOTSUP;
    dev = rte_eth_vdev_allocate(vdev, sizeof(*p));
    if (!dev)
        return -ENOMEM;
    p = dev->data->dev_private;
    p->intr_fd = -1;
    p->fd = open("/dev/n1-dwmac", O_RDWR | O_CLOEXEC);
    if (p->fd < 0) {
        err = -errno;
        goto fail;
    }
    if (ioctl(p->fd, N1_INFO, &p->info) || p->info.abi != N1_ABI ||
        p->info.arena_size != N1_ARENA || p->info.ring_size != N1_RING ||
        p->info.page_size != (unsigned)sysconf(_SC_PAGESIZE) ||
        !p->info.cache_align || (p->info.cache_align & (p->info.cache_align - 1)) ||
        p->info.cache_align > 256 ||
        p->info.dma_base + N1_ARENA - 1 > UINT32_MAX) {
        err = -EINVAL;
        goto fail;
    }
    p->regs = mmap(NULL, N1_REG_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, p->fd, 0);
    p->arena = mmap(NULL, N1_ARENA, PROT_READ | PROT_WRITE, MAP_SHARED,
                    p->fd, sysconf(_SC_PAGESIZE));
    if (p->regs == MAP_FAILED || p->arena == MAP_FAILED)
        goto fail;
    if ((rd(p, 0x20) & 0xff) != 0x37) {
        err = -ENODEV;
        goto fail;
    }
    dev->data->mac_addrs = rte_zmalloc(NULL, MAC_SLOTS * sizeof(struct rte_ether_addr), 0);
    if (!dev->data->mac_addrs)
        goto fail;
    p->maps = rte_zmalloc(NULL, N1_PAGE_HASH * sizeof(*p->maps), 0);
    if (!p->maps)
        goto fail;
    memcpy(dev->data->mac_addrs, p->info.mac, 6);
    p->rx = (void *)(p->arena + N1_RX_DESC);
    p->tx = (void *)(p->arena + N1_TX_DESC);
    p->port = dev->data->port_id;
    dev->dev_ops = &ops;
    dev->rx_pkt_burst = rx_burst;
    dev->tx_pkt_burst = tx_burst;
    dev->data->mtu = 1500;
    rte_eth_dev_probing_finish(dev);
    return 0;
fail:
    close_dev(dev);
    rte_eth_dev_release_port(dev);
    return err;
}
static int remove_dev(struct rte_vdev_device *vdev)
{
    struct rte_eth_dev *dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
    int err;
    if (!dev)
        return 0;
    err = close_dev(dev);
    return err ? err : rte_eth_dev_release_port(dev);
}
static struct rte_vdev_driver driver = { .probe = probe, .remove = remove_dev };
RTE_PMD_REGISTER_VDEV(net_n1_dwmac, driver);
