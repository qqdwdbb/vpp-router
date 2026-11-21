/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef N1_CHECKSUM_H
#define N1_CHECKSUM_H

#define N1_RX_CSUM (RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | \
                    RTE_ETH_RX_OFFLOAD_TCP_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
#define N1_TX_CSUM (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | \
                    RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM)

struct n1_packet {
    unsigned ip, l3, l4, end, proto;
    bool fragment;
};

static inline unsigned n1_be16(const uint8_t *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

/* Classify only formats whose checksum coverage the normal descriptor exposes.
 * IPv6 extension headers stay UNKNOWN until explicitly supported and tested. */
static inline struct n1_packet n1_packet(const uint8_t *b, unsigned length)
{
    struct n1_packet p = {0};
    unsigned type, l3 = 14;
    if (length < 14)
        return p;
    type = n1_be16(b + 12);
    if (type == 0x8100) {
        if (length < 18)
            return p;
        type = n1_be16(b + 16);
        l3 = 18;
    }
    if (type == 0x0800 && length >= l3 + 20 && (b[l3] >> 4) == 4) {
        unsigned ihl = (b[l3] & 15) * 4;
        unsigned total = n1_be16(b + l3 + 2);
        if (ihl < 20 || total < ihl || total > length - l3)
            return p;
        p.ip = 4; p.l4 = l3 + ihl; p.end = l3 + total;
        p.proto = b[l3 + 9];
        p.fragment = (n1_be16(b + l3 + 6) & 0x3fff) != 0;
    } else if (type == 0x86dd && length >= l3 + 40 && (b[l3] >> 4) == 6) {
        unsigned payload = n1_be16(b + l3 + 4);
        if (!payload || payload > length - l3 - 40)
            return p;
        p.ip = 6; p.l4 = l3 + 40; p.end = p.l4 + payload;
        p.proto = b[l3 + 6];
    }
    p.l3 = l3;
    return p;
}

static inline uint64_t n1_rx_checksum(uint32_t status, const uint8_t *b,
                               unsigned length, uint64_t offloads)
{
    struct n1_packet p = n1_packet(b, length);
    uint64_t flags = 0;
    /* Type-2 COE: bit5=IP frame, bit7=header error, bit0=payload error.
     * Other combinations encode bypass/unsupported, not a GOOD result. */
    if (!p.ip || !(status & (1u << 5)))
        return 0;
    if (p.ip == 4 && (offloads & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM))
        flags |= status & (1u << 7) ? RTE_MBUF_F_RX_IP_CKSUM_BAD :
                                       RTE_MBUF_F_RX_IP_CKSUM_GOOD;
    if ((status & (1u << 7)) || p.fragment)
        return flags;
    if (p.proto == 17 && (offloads & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)) {
        if (p.end - p.l4 < 8 || n1_be16(b + p.l4 + 4) != p.end - p.l4)
            return flags;
        if (!n1_be16(b + p.l4 + 6)) {
            /* UDP/IPv4 may omit its checksum; UDP/IPv6 may not. */
            return flags | (p.ip == 6 ? RTE_MBUF_F_RX_L4_CKSUM_BAD : 0);
        }
    } else if (p.proto == 6 && (offloads & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)) {
        if (p.end - p.l4 < 20 || (b[p.l4 + 12] >> 4) < 5 ||
            (unsigned)(b[p.l4 + 12] >> 4) * 4 > p.end - p.l4)
            return flags;
    } else {
        return flags;
    }
    return flags | (status & 1 ? RTE_MBUF_F_RX_L4_CKSUM_BAD :
                                  RTE_MBUF_F_RX_L4_CKSUM_GOOD);
}

static inline bool n1_rx_fatal(uint32_t status)
{
    const uint32_t fatal = (1u << 1) | (1u << 3) | (1u << 4) | (1u << 6) |
                          (1u << 11) | (1u << 12) | (1u << 14);
    return (status & fatal) ||
           ((status & (1u << 15)) && !(status & ((1u << 7) | 1)));
}

static inline uint32_t n1_checksum_sum(const uint8_t *b, unsigned length)
{
    uint32_t sum = 0;
    while (length >= 2) {
        sum += n1_be16(b);
        b += 2; length -= 2;
    }
    return sum + (length ? (unsigned)b[0] << 8 : 0);
}

/* Full COE generates the pseudo-header itself. Clear DPDK's partial seed in
 * the writable packet before handing its data to DMA. */
static inline int n1_tx_checksum(uint8_t *b, unsigned length, uint64_t flags,
                          uint64_t offloads, unsigned l2_len, unsigned l3_len)
{
    uint64_t work = flags & RTE_MBUF_F_TX_OFFLOAD_MASK &
                    ~(RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IPV6);
    uint64_t l4 = work & RTE_MBUF_F_TX_L4_MASK;
    struct n1_packet p;
    const uint8_t *ip6_dst = NULL;
    bool software = false;
    if (!work)
        return 0;
    if (work & ~(RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_L4_MASK))
        return -ENOTSUP;
    p = n1_packet(b, length);
    if (!p.ip || (p.fragment && l4) || l2_len != p.l3 ||
        !!(flags & RTE_MBUF_F_TX_IPV4) != (p.ip == 4) ||
        !!(flags & RTE_MBUF_F_TX_IPV6) != (p.ip == 6))
        return -EINVAL;
    /* Type-2 COE bypasses IPv6 extension headers. Complete these requests in
     * software so advertising ordinary TCP/UDP COE does not break that traffic. */
    if (p.ip == 6) {
        ip6_dst = b + p.l3 + 24;
        for (unsigned depth = 0; p.proto != 6 && p.proto != 17; depth++) {
            unsigned size;
            const uint8_t *ext = b + p.l4;
            if (depth == 8 || p.end - p.l4 < 8)
                return -ENOTSUP;
            if (p.proto == 0 || p.proto == 43 || p.proto == 60)
                size = ((unsigned)ext[1] + 1) * 8;
            else if (p.proto == 44) {
                if (n1_be16(ext + 2) & 0xfff9)
                    return -ENOTSUP; /* only atomic fragments contain full L4 */
                size = 8;
            } else if (p.proto == 51)
                size = ((unsigned)ext[1] + 2) * 4;
            else
                return -ENOTSUP;
            if (size > p.end - p.l4)
                return -EINVAL;
            if (p.proto == 43 && ext[3]) {
                if ((ext[2] == 0 && size >= 24 && (size - 8) % 16 == 0) ||
                    (ext[2] == 2 && size == 24))
                    ip6_dst = ext + size - 16;
                else if (ext[2] == 4 && size >= 24 &&
                         8 + ((unsigned)ext[4] + 1) * 16 <= size)
                    ip6_dst = ext + 8;
                else
                    return -ENOTSUP;
            }
            p.proto = ext[0]; p.l4 += size; software = true;
        }
    }
    if (l3_len != p.l4 - p.l3)
        return -EINVAL;
    if ((work & RTE_MBUF_F_TX_IP_CKSUM) &&
        (p.ip != 4 || !(offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)))
        return -ENOTSUP;
    if (l4 == RTE_MBUF_F_TX_UDP_CKSUM) {
        if (p.proto != 17 || !(offloads & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) ||
            p.end - p.l4 < 8 || n1_be16(b + p.l4 + 4) != p.end - p.l4)
            return -ENOTSUP;
    } else if (l4 == RTE_MBUF_F_TX_TCP_CKSUM) {
        if (p.proto != 6 || !(offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) ||
            p.end - p.l4 < 20 || (b[p.l4 + 12] >> 4) < 5 ||
            (unsigned)(b[p.l4 + 12] >> 4) * 4 > p.end - p.l4)
            return -ENOTSUP;
    } else if (l4) {
        return -ENOTSUP;
    }
    if (p.ip == 4)
        b[p.l3 + 10] = b[p.l3 + 11] = 0;
    if (l4 == RTE_MBUF_F_TX_UDP_CKSUM)
        b[p.l4 + 6] = b[p.l4 + 7] = 0;
    if (l4 == RTE_MBUF_F_TX_TCP_CKSUM)
        b[p.l4 + 16] = b[p.l4 + 17] = 0;
    if (software && l4) {
        unsigned length = p.end - p.l4;
        uint32_t sum = n1_checksum_sum(b + p.l3 + 8, 16) +
                       n1_checksum_sum(ip6_dst, 16) + length + p.proto +
                       n1_checksum_sum(b + p.l4, length);
        while (sum >> 16)
            sum = (sum & 65535) + (sum >> 16);
        unsigned value = (~sum) & 65535;
        if (!value && p.proto == 17)
            value = 65535;
        unsigned offset = p.l4 + (p.proto == 17 ? 6 : 16);
        b[offset] = value >> 8; b[offset + 1] = value;
        return 0;
    }
    return l4 ? 3 : 1;
}
#endif
