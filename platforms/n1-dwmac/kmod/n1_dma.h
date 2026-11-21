/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef N1_DMA_H
#define N1_DMA_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define N1_ABI 3
#define N1_RING 256u
#define N1_MASK (N1_RING - 1u)
#define N1_RX_DESC 0u
#define N1_TX_DESC 4096u
#define N1_SCRATCH 8192u
#define N1_ARENA 12288u /* descriptors plus idle-test scratch; no packet slots */
#define N1_MAX_PAGES 8192u
#define N1_SYNC_BATCH 256u
#define N1_REG_SIZE 8192u
struct n1_info {
    __u32 abi, arena_size, regs_size, ring_size;
    __u64 dma_base;
    __u8 mac[6];
    __u8 pad[2];
    __u32 page_size, cache_align;
};
struct n1_page { __u64 address, dma; __u32 id, pad; };
struct n1_range { __u32 id, offset, length, pad; };
struct n1_sync {
    __u32 count, for_cpu;
    struct n1_range ranges[N1_SYNC_BATCH];
};
#define N1_PAUSE_RX 1u
#define N1_PAUSE_TX 2u
/* ABI2 reserved word now reports negotiated pause; ioctl size is unchanged. */
struct n1_link { __u32 up, speed, full_duplex, pause; };
#define N1_INFO _IOR('N', 0, struct n1_info)
#define N1_LINK _IOR('N', 1, struct n1_link)
#define N1_STOP _IO('N', 2)
#define N1_MAP_PAGE _IOWR('N', 3, struct n1_page)
#define N1_SYNC _IOW('N', 4, struct n1_sync)
#define N1_UNMAP_ALL _IO('N', 5)
#define N1_IRQ_SETUP _IOW('N', 6, int)
#define N1_IRQ_ENABLE _IO('N', 7)
#define N1_IRQ_DISABLE _IO('N', 8)
#endif
