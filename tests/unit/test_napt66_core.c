/* Exercise production packet parsing with ASan/UBSan, including malformed input. */
#include "../../plugins/napt66/napt66.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
  n66_state *s = calloc(1, sizeof(*s));
  assert(s);
  s->external[0] = 0x20; s->external[1] = 1; s->external[15] = 1;
  s->prefix[0] = 0xfd; s->prefix_len = 64;
  uint32_t rng = 1;
  for (unsigned i = 0; i < 100000; i++) {
    size_t len = i % 257;
    uint8_t *p = malloc(len ? len : 1);
    assert(p);
    for (size_t j = 0; j < len; j++) {
      rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
      p[j] = rng;
    }
    if (len >= 40) {
      p[0] = 0x60;
      if (i & 1) memcpy(p + 24, s->external, 16);
      else { memcpy(p + 8, s->prefix, 16); p[24] = 0x20; }
      if (i & 2) { p[4] = 0; p[5] = len - 40; }
      if (i & 4) p[6] = (uint8_t[]){6, 17, 58, 44}[(i >> 3) & 3];
    }
    int result = n66_translate(s, p, len, i & 1, i / 100.0);
    assert(result >= -1 && result <= 1);
    free(p);
  }
  n66_expire(s, 100000, N66_SLOTS);
  for (unsigned i = 0; i < N66_SLOTS; i++) assert(!s->sessions[i].used);
  free(s);
  return 0;
}
