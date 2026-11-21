/* Parse only bytes actually present in an ICMPv6 quote. A quote may be
 * shorter than its IPv6 payload length, but Ethernet padding is not payload.
 * Non-first fragments cannot identify ESP; their data may resemble a SPI. */
#ifndef included_ipsec_ptb_quote_h
#define included_ipsec_ptb_quote_h

#include <stddef.h>
#include <stdint.h>

static inline int
ipsec_ptb_quote_spi (const uint8_t *ip, size_t available, uint32_t *spi)
{
  size_t end, offset = 40;
  unsigned protocol;
  if (available < 40 || (ip[0] >> 4) != 6)
    return 0;
  end = 40 + ((size_t) ip[4] << 8) + ip[5];
  if (end > available)
    end = available;
  protocol = ip[6];
  for (unsigned depth = 0; depth < 16; depth++)
    {
      size_t length;
      if (protocol == 50 || protocol == 17)
        {
          if (protocol == 17)
            {
              if (end - offset < 12 ||
                  !((ip[offset] == 0x11 && ip[offset + 1] == 0x94) ||
                    (ip[offset + 2] == 0x11 && ip[offset + 3] == 0x94)))
                return 0;
              offset += 8;
            }
          if (end - offset < 4)
            return 0;
          *spi = ((uint32_t) ip[offset] << 24) |
                 ((uint32_t) ip[offset + 1] << 16) |
                 ((uint32_t) ip[offset + 2] << 8) | ip[offset + 3];
          return *spi != 0;
        }
      if (protocol != 0 && protocol != 43 && protocol != 44 &&
          protocol != 51 && protocol != 60)
        return 0;
      if (end - offset < 8)
        return 0;
      if (protocol == 44)
        {
          if ((ip[offset + 2] << 8 | ip[offset + 3]) & 0xfff8)
            return 0;
          length = 8;
        }
      else if (protocol == 51)
        length = ((size_t) ip[offset + 1] + 2) * 4;
      else
        length = ((size_t) ip[offset + 1] + 1) * 8;
      if (length > end - offset)
        return 0;
      protocol = ip[offset];
      offset += length;
    }
  return 0;
}
#endif
