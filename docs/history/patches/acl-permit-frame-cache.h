/* SPDX-License-Identifier: Apache-2.0
 * One ordinary-permit decision, owned by a single node invocation.
 * Include after fa_node.h. Never persists across frames or creates a session.
 */
#ifndef included_acl_permit_frame_cache_h
#define included_acl_permit_frame_cache_h

typedef struct
{
  fa_5tuple_t tuple;
  u32 sw_if_index;
  u32 lc_index;
  u32 acl_pos;
  u32 acl_index;
  u32 rule_index;
  u8 valid;
} acl_permit_frame_cache_t;

static_always_inline int
acl_permit_frame_cache_lookup (const acl_permit_frame_cache_t *cache,
                               const fa_5tuple_t *tuple, u32 sw_if_index,
                               u32 lc_index, u32 *acl_pos, u32 *acl_index,
                               u32 *rule_index)
{
  if (!cache->valid || cache->sw_if_index != sw_if_index ||
      cache->lc_index != lc_index ||
      memcmp (&cache->tuple, tuple, sizeof (*tuple)))
    return 0;
  *acl_pos = cache->acl_pos;
  *acl_index = cache->acl_index;
  *rule_index = cache->rule_index;
  return 1;
}

static_always_inline void
acl_permit_frame_cache_store (acl_permit_frame_cache_t *cache,
                              const fa_5tuple_t *tuple, u32 sw_if_index,
                              u32 lc_index, u32 acl_pos, u32 acl_index,
                              u32 rule_index)
{
  cache->tuple = *tuple;
  cache->sw_if_index = sw_if_index;
  cache->lc_index = lc_index;
  cache->acl_pos = acl_pos;
  cache->acl_index = acl_index;
  cache->rule_index = rule_index;
  cache->valid = 1;
}

#endif
