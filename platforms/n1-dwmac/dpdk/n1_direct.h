/* SPDX-License-Identifier: BSD-3-Clause
 * Persistent user-page DMA mappings. No mbuf IOVA or virtual address is used
 * as a hardware address. Only the helper's validated DMA addresses are used.
 * Packet-path cache maintenance executes directly in EL0 via ARM64 CMO
 * (dc cvac / dc civac) with full-system dsb sy, bypassing ioctls entirely.
 */
#define N1_PAGE_HASH (N1_MAX_PAGES * 2)
#define N1_RX_CAPACITY 1536u
#define N1_CACHELINE 64u
struct n1_mapping { uintptr_t address; uint64_t dma; uint32_t id; };

static inline void n1_cache_clean(const void *address, size_t length)
{
#if defined(RTE_ARCH_ARM64)
    if (!length) return;
    uintptr_t start = (uintptr_t)address & ~(uintptr_t)(N1_CACHELINE - 1);
    uintptr_t end = (uintptr_t)address + length;
    for (; start < end; start += N1_CACHELINE)
        __asm__ volatile("dc cvac, %0" :: "r"(start));
    __asm__ volatile("" ::: "memory");
#else
    (void)address; (void)length;
#endif
}

static inline void n1_cache_inval(const void *address, size_t length)
{
#if defined(RTE_ARCH_ARM64)
    if (!length) return;
    uintptr_t start = (uintptr_t)address & ~(uintptr_t)(N1_CACHELINE - 1);
    uintptr_t end = (uintptr_t)address + length;
    for (; start < end; start += N1_CACHELINE)
        __asm__ volatile("dc civac, %0" :: "r"(start));
    __asm__ volatile("" ::: "memory");
#else
    (void)address; (void)length;
#endif
}

static inline void n1_cache_barrier(void)
{
#if defined(RTE_ARCH_ARM64)
    __asm__ volatile("dsb sy" ::: "memory");
#endif
}

static struct n1_mapping *dma_page(struct n1 *p, uintptr_t address)
{
    uintptr_t base = address & ~(uintptr_t)(p->info.page_size - 1);
    if (p->last_map && p->last_map->address == base)
        return p->last_map;
    unsigned bucket = ((base >> 12) ^ (base >> 23)) & (N1_PAGE_HASH - 1);
    for (unsigned i = 0; i < N1_PAGE_HASH; i++) {
        struct n1_mapping *entry = &p->maps[(bucket + i) & (N1_PAGE_HASH - 1)];
        if (entry->address == base) {
            p->last_map = entry;
            return entry;
        }
        if (!entry->address) {
            struct n1_page request = { .address = base };
            if (ioctl(p->fd, N1_MAP_PAGE, &request)) {
                p->failed = true;
                fprintf(stderr, "n1_dwmac: DMA page registration failed: %s\n", strerror(errno));
                return NULL;
            }
            entry->address = base; entry->dma = request.dma; entry->id = request.id;
            p->mapped_pages++;
            p->last_map = entry;
            return entry;
        }
    }
    return NULL;
}

static int descriptor_data(struct n1 *p, struct descriptor *d, void *data,
                            unsigned length, unsigned flags)
{
    uintptr_t address = (uintptr_t)data;
    struct n1_mapping *first = dma_page(p, address), *second = NULL;
    unsigned offset = address & (p->info.page_size - 1);
    unsigned size = RTE_MIN(length, p->info.page_size - offset);
    if (unlikely(!first || size > 2047 || length - size > 2047))
        return -EINVAL;
    if (unlikely(length > size)) {
        second = dma_page(p, address + size);
        if (!second)
            return -EINVAL;
    }
    d->addr = rte_cpu_to_le_32(first->dma + offset);
    d->next = rte_cpu_to_le_32(second ? second->dma : 0);
    d->control = rte_cpu_to_le_32(size | ((length - size) << 11) | flags);
    p->split_descriptors += second != NULL;
    return 0;
}

static int rx_prepare(struct n1 *p, unsigned index, struct rte_mbuf *m)
{
    uintptr_t data = (uintptr_t)m->buf_addr + RTE_PKTMBUF_HEADROOM;
    unsigned align = p->info.cache_align;
    data = (data + align - 1) & ~(uintptr_t)(align - 1);
    if (unlikely(data - (uintptr_t)m->buf_addr + N1_RX_CAPACITY > m->buf_len))
        return -EINVAL;
    m->data_off = data - (uintptr_t)m->buf_addr;
    return descriptor_data(p, &p->rx[index], (void *)data, N1_RX_CAPACITY,
                           (p->intr_fd < 0 ? (1u << 31) : 0) |
                           (index == N1_RING - 1 ? END : 0));
}

static void release_mbufs(struct n1 *p)
{
    /* The caller has completed DMA reset before touching these references. */
    for (unsigned i = 0; i < N1_RING; i++) {
        if (p->rx_mbuf[i])
            n1_cache_inval(rte_pktmbuf_mtod(p->rx_mbuf[i], void *), N1_RX_CAPACITY);
        if (p->tx_mbuf[i])
            n1_cache_inval(rte_pktmbuf_mtod(p->tx_mbuf[i], void *), p->tx_mbuf[i]->pkt_len);
    }
    n1_cache_barrier();
    for (unsigned i = 0; i < N1_RING; i++) {
        if (p->rx_mbuf[i]) rte_pktmbuf_free(p->rx_mbuf[i]);
        if (p->tx_mbuf[i]) rte_pktmbuf_free(p->tx_mbuf[i]);
        p->rx_mbuf[i] = p->tx_mbuf[i] = NULL;
    }
    p->outstanding = 0;
}

static int forget_maps(struct n1 *p)
{
    if (ioctl(p->fd, N1_UNMAP_ALL)) {
        p->failed = true;
        return -errno;
    }
    memset(p->maps, 0, N1_PAGE_HASH * sizeof(*p->maps));
    p->mapped_pages = 0;
    p->last_map = NULL;
    return 0;
}
