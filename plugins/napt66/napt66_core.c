/* SPDX-License-Identifier: Apache-2.0 */
#include "napt66.h"
#include <string.h>

static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static void put16(uint8_t *p, uint16_t x) { p[0] = x >> 8; p[1] = x; }

/* RFC 1624 update, with wire-order words and no alignment assumptions. */
static void replace(uint8_t *sum, uint8_t *field, const uint8_t *value, unsigned n)
{
  uint32_t c = (uint16_t)~get16(sum);
  for (unsigned i = 0; i < n; i += 2)
    c += (uint16_t)~get16(field + i) + get16(value + i);
  while (c >> 16) c = (c & 65535) + (c >> 16);
  put16(sum, (uint16_t)~c ? (uint16_t)~c : 65535);
  memcpy(field, value, n);
}

static unsigned hash(const uint8_t *a, const uint8_t *r, uint16_t p,
                     uint16_t q, uint8_t proto)
{
  uint32_t h = 2166136261u;
  for (unsigned i = 0; i < 16; i++) { h = (h ^ a[i]) * 16777619u; h = (h ^ r[i]) * 16777619u; }
  h = (h ^ p) * 16777619u; h = (h ^ q) * 16777619u;
  return (h ^ proto) & (N66_BUCKETS - 1);
}
static void remove_slot(n66_state *s, unsigned i)
{
  n66_session *v = s->sessions + i;
  uint32_t *link = s->buckets + hash(v->local, v->remote, v->local_port,
                                    v->remote_port, v->protocol);
  while (*link && *link != i + 1) link = &s->sessions[*link - 1].next;
  if (*link) *link = v->next;
  memset(v, 0, sizeof(*v));
}
void n66_expire(n66_state *s, double now, unsigned budget)
{
  while (budget--) {
    unsigned i = s->sweep++ % N66_SLOTS;
    if (s->sessions[i].used && s->sessions[i].expires <= now) remove_slot(s, i);
  }
}
static int prefix_match(n66_state *s, const uint8_t *a)
{
  unsigned n = s->prefix_len / 8, bits = s->prefix_len % 8;
  return !memcmp(a, s->prefix, n) &&
    (!bits || !((a[n] ^ s->prefix[n]) & (255 << (8 - bits))));
}

static int layout(uint8_t *p, size_t len, int quote, unsigned *off,
                  unsigned *check, uint8_t *proto)
{
  if (len < 40 || p[0] >> 4 != 6 || !get16(p + 4)) return -1;
  *proto = p[6];
  unsigned need;
  if (*proto == 6) { *off = 40; *check = 56; need = quote ? 48 : 60; }
  else if (*proto == 17) { *off = 40; *check = 46; need = 48; }
  else if (*proto == 58 && len >= 48 && (p[40] == 128 || p[40] == 129))
    { *off = 44; *check = 42; need = 48; }
  else return -1;
  if (len < need || (!quote && ((size_t)get16(p + 4) + 40 > len ||
      get16(p + 4) < need - 40))) return -1;
  if (!quote && *proto == 6 && ((p[52] >> 4) < 5 ||
      (unsigned)(p[52] >> 4) * 4 > get16(p + 4))) return -1;
  if (!quote && *proto == 17 && (get16(p + 44) < 8 ||
      get16(p + 44) != get16(p + 4) || !get16(p + 46))) return -1;
  return 0;
}

int n66_translate(n66_state *s, uint8_t *p, size_t len, int in, double now)
{
  unsigned off, check;
  uint8_t proto;
  if (len < 40 || p[0] >> 4 != 6) return -1;
  if (in) {
    if (memcmp(p + 24, s->external, 16)) return 0;
    /* Router-local echo requests and ND/MLD are not NAPT sessions. */
    if (p[6] == 58 && len >= 48 && p[40] >= 128 && p[40] != 129) return 0;
  } else if (!prefix_match(s, p + 8) || (p[24] & 0xe0) != 0x20) return 0;
  n66_expire(s, now, 32);
  if (in && p[6] == 58 && len >= 48 && p[40] < 128) {
    if (p[40] < 1 || p[40] > 4 || get16(p + 4) < 56 ||
        (size_t)get16(p + 4) + 40 > len) return -1;
    uint8_t *q = p + 48;
    size_t qlen = get16(p + 4) - 8;
    if (layout(q, qlen, 1, &off, &check, &proto) ||
        memcmp(q + 8, s->external, 16)) return -1;
    unsigned port = get16(q + off);
    if (port < N66_FIRST) return 0;
    n66_session *v = s->sessions + port - N66_FIRST;
    uint16_t remote = proto == 58 ? 0 : get16(q + off + 2);
    if (!v->used || v->expires <= now || v->protocol != proto ||
        v->remote_port != remote || memcmp(v->remote, q + 24, 16)) return -1;
    uint8_t translated[2]; put16(translated, v->local_port);
    if (qlen >= check + 2) {
      uint8_t old[2]; memcpy(old, q + check, 2);
      replace(q + check, q + 8, v->local, 16);
      replace(q + check, q + off, translated, 2);
      uint8_t updated[2]; memcpy(updated, q + check, 2);
      memcpy(q + check, old, 2);
      replace(p + 42, q + check, updated, 2);
    }
    memcpy(q + 8, s->external, 16); put16(q + off, port);
    replace(p + 42, q + 8, v->local, 16);
    replace(p + 42, q + off, translated, 2);
    replace(p + 42, p + 24, v->local, 16);
    return 1;
  }

  if (layout(p, len, 0, &off, &check, &proto)) return -1;
  if (proto == 58 && p[40] != (in ? 129 : 128)) return -1;
  uint16_t port = get16(p + off + (in && proto != 58 ? 2 : 0));
  uint16_t remote = proto == 58 ? 0 : get16(p + off + (in ? 0 : 2));
  const uint8_t *addr = p + (in ? 8 : 24);
  n66_session *v = 0; unsigned slot = 0;
  if (in) {
    if (port < N66_FIRST) return 0; /* router-local ports remain available */
    slot = port - N66_FIRST; v = s->sessions + slot;
    if (!v->used) return -1;
    if (v->expires <= now) { remove_slot(s, slot); return -1; }
    if (v->protocol != proto || v->remote_port != remote || memcmp(v->remote, addr, 16)) return -1;
  } else {
    unsigned h = hash(p + 8, addr, port, remote, proto);
    for (uint32_t i = s->buckets[h]; i; i = s->sessions[i - 1].next) {
      n66_session *candidate = s->sessions + i - 1;
      if (candidate->local_port == port && candidate->remote_port == remote &&
          candidate->protocol == proto && !memcmp(candidate->local, p + 8, 16) &&
          !memcmp(candidate->remote, addr, 16)) {
        slot = i - 1;
        if (candidate->expires <= now) remove_slot(s, slot);
        else v = candidate;
        break;
      }
    }
    if (!v) {
      for (unsigned i = 0; i < N66_SLOTS; i++) {
        slot = s->cursor++ % N66_SLOTS; v = s->sessions + slot;
        if (v->used && v->expires <= now) remove_slot(s, slot);
        if (!v->used) break;
        v = 0;
      }
      if (!v) return -1;
      memcpy(v->local, p + 8, 16); memcpy(v->remote, addr, 16);
      v->local_port = port; v->remote_port = remote; v->protocol = proto; v->used = 1;
      v->next = s->buckets[h]; s->buckets[h] = slot + 1;
    }
  }
  v->expires = now + (proto == 6 ? 7440 : proto == 17 ? 300 : 60);
  uint8_t translated[2]; put16(translated, in ? v->local_port : slot + N66_FIRST);
  replace(p + check, p + (in ? 24 : 8), in ? v->local : s->external, 16);
  replace(p + check, p + off + (in && proto != 58 ? 2 : 0), translated, 2);
  return 1;
}
