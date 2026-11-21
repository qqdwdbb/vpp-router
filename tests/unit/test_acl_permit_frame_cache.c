/* Exercise the actual cache helper, including every key bit and interface IDs. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef union { uint64_t words[6]; unsigned char bytes[48]; } fa_5tuple_t;
#define static_always_inline static inline __attribute__((always_inline))
#include "../patches/history/acl-permit-frame-cache.h"

int main(void)
{
  fa_5tuple_t key = { .words = { 1, 2, 3, 4, 5, 6 } };
  acl_permit_frame_cache_t cache = { .valid = 0 };
  u32 pos = 0, acl = 0, rule = 0;
#define HIT(k, i, c) acl_permit_frame_cache_lookup (&cache, k, i, c, &pos, &acl, &rule)
  assert (!HIT (&key, 7, 9));
  acl_permit_frame_cache_store (&cache, &key, 7, 9, 11, 13, 17);
  assert (HIT (&key, 7, 9));
  assert (pos == 11 && acl == 13 && rule == 17);
  assert (!HIT (&key, 65543, 9)); /* Same low 16 bits is not the same interface. */
  assert (!HIT (&key, 7, 10));
  for (unsigned bit = 0; bit < sizeof (key) * 8; ++bit)
    {
      fa_5tuple_t changed = key;
      changed.bytes[bit / 8] ^= (unsigned char) (1U << (bit % 8));
      assert (!HIT (&changed, 7, 9));
    }
  acl_permit_frame_cache_t next_frame = { .valid = 0 };
  assert (!acl_permit_frame_cache_lookup (&next_frame, &key, 7, 9, &pos, &acl, &rule));
  fa_5tuple_t new_key = { .words = { 8, 7, 6, 5, 4, 3 } };
  acl_permit_frame_cache_store (&cache, &new_key, 12, 14, 19, 23, 29);
  assert (!HIT (&key, 7, 9));
  assert (HIT (&new_key, 12, 14));
  assert (pos == 19 && acl == 23 && rule == 29);
  puts ("PASS: full 384-bit key, interface/context isolation, metadata, replacement, frame reset");
  return 0;
}
