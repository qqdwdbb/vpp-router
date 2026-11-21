/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_napt66_h
#define included_napt66_h
#include <stdint.h>
#include <stddef.h>

#define N66_FIRST 49152
#define N66_SLOTS (65536 - N66_FIRST)
#define N66_BUCKETS 4096
typedef struct {
  uint8_t local[16], remote[16], protocol, used;
  uint16_t local_port, remote_port;
  uint32_t next;
  double expires;
} n66_session;
typedef struct {
  uint8_t external[16], prefix[16];
  unsigned prefix_len, cursor, sweep;
  uint32_t buckets[N66_BUCKETS]; /* slot + 1; zero terminates */
  n66_session sessions[N66_SLOTS];
} n66_state;

/* Caller serializes access. Packet must be contiguous, starting at IPv6.
 * Returns 1 translated, 0 bypass, -1 unsupported/invalid/no session/full. */
int n66_translate(n66_state *, uint8_t *, size_t, int inbound, double now);
void n66_expire(n66_state *, double now, unsigned budget);
#endif
