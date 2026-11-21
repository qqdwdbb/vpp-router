/* SPDX-License-Identifier: Apache-2.0 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/format.h>
#include <vnet/feature/feature.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/lock.h>
#include <vpp/app/version.h>
#include "napt66.h"

static n66_state state;
static clib_spinlock_t session_lock;
#define N66_INSIDE_MAX 16
typedef struct {
  u32 sw_if_index, len;
  ip6_address_t prefix;
} n66_inside_t;
static n66_inside_t insides[N66_INSIDE_MAX];
static u32 n_insides, outside = ~0;

/* WireGuard managers delete and recreate interfaces. Forget deleted bindings
 * before their indices can be reused for unrelated interfaces. */
static clib_error_t *
napt66_interface_deleted(vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  (void)vnm;
  if (is_add) return 0;
  vlib_main_t *vm = vlib_get_main();
  vlib_worker_thread_barrier_sync(vm);
  if (sw_if_index == outside) {
    for (u32 i = 0; i < n_insides; i++)
      vnet_feature_enable_disable("ip6-unicast", "napt66", insides[i].sw_if_index, 0, 0, 0);
    n_insides = 0; outside = ~0;
    memset(&state, 0, sizeof(state));
  } else {
    for (u32 i = 0; i < n_insides; i++) {
      if (insides[i].sw_if_index != sw_if_index) continue;
      memmove(insides + i, insides + i + 1, (n_insides - i - 1) * sizeof(*insides));
      n_insides--;
      memset(&state.sessions, 0, sizeof(state.sessions));
      memset(&state.buckets, 0, sizeof(state.buckets));
      if (!n_insides && outside != ~0) {
        vnet_feature_enable_disable("ip6-unicast", "napt66", outside, 0, 0, 0);
        outside = ~0;
      }
      break;
    }
  }
  vlib_worker_thread_barrier_release(vm);
  return 0;
}
VNET_SW_INTERFACE_ADD_DEL_FUNCTION(napt66_interface_deleted);

static uword
napt66_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args(frame);
  double now = vlib_time_now(vm);
  for (u32 i = 0; i < frame->n_vectors; i++) {
    vlib_buffer_t *b = vlib_get_buffer(vm, from[i]);
    u32 next;
    vnet_feature_next(&next, b);
    int inbound = vnet_buffer(b)->sw_if_index[VLIB_RX] == outside;
    int result = -1;
    /* Chained packets require a separate parser/reassembly implementation. */
    if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)) {
      clib_spinlock_lock(&session_lock);
      /* Prefix selection is protected by the same lock as the shared table.
       * Disjoint source prefixes make the local address a unique return key. */
      for (u32 j = 0; j < n_insides; j++) {
        if (!inbound && insides[j].sw_if_index != vnet_buffer(b)->sw_if_index[VLIB_RX])
          continue;
        memcpy(state.prefix, insides[j].prefix.as_u8, 16);
        state.prefix_len = insides[j].len;
        result = n66_translate(&state, vlib_buffer_get_current(b),
                               b->current_length, inbound, now);
        break;
      }
      clib_spinlock_unlock(&session_lock);
    }
    if (result < 0) {
      next = 0;
      b->error = node->errors[0];
    } else if (result > 0) {
      /* Translation invalidates receive checksum metadata. */
      b->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
                    VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
      vlib_node_increment_counter(vm, node->node_index, 1, 1);
    }
    vlib_set_next_frame_buffer(vm, node, next, from[i]);
  }
  return frame->n_vectors;
}
static char *errors[] = { "invalid, unsupported, expired or exhausted",
                          "translated packets" };
VLIB_REGISTER_NODE(napt66_node) = {
  .function = napt66_node_fn,
  .name = "napt66",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(errors),
  .error_strings = errors,
  .n_next_nodes = 1,
  .next_nodes = { [0] = "error-drop" },
};
VNET_FEATURE_INIT(napt66_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "napt66",
  .runs_before = VNET_FEATURES("ip6-lookup"),
};

static clib_error_t *
napt66_config(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  (void)cmd;
  vnet_main_t *vnm = vnet_get_main();
  u32 out = ~0, count = 0;
  n66_inside_t requested[N66_INSIDE_MAX] = {};
  ip6_address_t external = {};
  int have_external = 0, disable = 0;
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    u32 in;
    if (unformat(input, "inside %U", unformat_vnet_sw_interface, vnm, &in)) {
      if (count == N66_INSIDE_MAX)
        return clib_error_return(0, "at most %u inside interfaces", N66_INSIDE_MAX);
      requested[count++].sw_if_index = in;
    }
    else if (unformat(input, "outside %U", unformat_vnet_sw_interface, vnm, &out)) {}
    else if (count && unformat(input, "prefix %U/%u", unformat_ip6_address,
                              &requested[count-1].prefix, &requested[count-1].len)) {}
    else if (unformat(input, "external %U", unformat_ip6_address, &external)) have_external = 1;
    else if (unformat(input, "disable")) disable = 1;
    else return clib_error_return(0, "unknown input: %U", format_unformat_error, input);
  }
  if (!disable && (!count || out == ~0 || !have_external ||
                   (external.as_u8[0] & 0xe0) != 0x20))
    return clib_error_return(0, "require inside prefixes, outside and global external address");
  for (u32 i = 0; !disable && i < count; i++) {
    n66_inside_t *a = requested + i;
    if (a->sw_if_index == out || a->len < 7 || a->len > 128 ||
        (a->prefix.as_u8[0] & 0xfe) != 0xfc)
      return clib_error_return(0, "require distinct inside/outside and ULA prefix /7..128");
    for (u32 j = 0; j < i; j++) {
      n66_inside_t *b = requested + j;
      u32 bits = clib_min(a->len, b->len), bytes = bits / 8;
      if (a->sw_if_index == b->sw_if_index ||
          (!memcmp(a->prefix.as_u8, b->prefix.as_u8, bytes) &&
           (!(bits % 8) || !((a->prefix.as_u8[bytes] ^ b->prefix.as_u8[bytes]) &
                             (255 << (8 - bits % 8))))))
        return clib_error_return(0, "inside interfaces must be unique with disjoint prefixes");
    }
  }
  vlib_worker_thread_barrier_sync(vm);
  for (u32 i = 0; i < n_insides; i++)
    vnet_feature_enable_disable("ip6-unicast", "napt66", insides[i].sw_if_index, 0, 0, 0);
  if (outside != ~0) {
    vnet_feature_enable_disable("ip6-unicast", "napt66", outside, 0, 0, 0);
  }
  memset(&state, 0, sizeof(state));
  n_insides = 0; outside = ~0;
  if (!disable) {
    memcpy(state.external, external.as_u8, 16);
    memcpy(insides, requested, count * sizeof(*requested));
    n_insides = count; outside = out;
    for (u32 i = 0; i < count; i++)
      vnet_feature_enable_disable("ip6-unicast", "napt66", insides[i].sw_if_index, 1, 0, 0);
    vnet_feature_enable_disable("ip6-unicast", "napt66", outside, 1, 0, 0);
  }
  vlib_worker_thread_barrier_release(vm);
  return 0;
}
VLIB_CLI_COMMAND(napt66_command, static) = {
  .path = "napt66",
  .short_help = "napt66 inside <if> prefix <ULA>/<len> [inside <if> prefix <ULA>/<len> ...] outside <if> external <IPv6> | disable",
  .function = napt66_config,
};
static clib_error_t *
napt66_show(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  (void)input; (void)cmd;
  unsigned count = 0;
  clib_spinlock_lock(&session_lock);
  n66_expire(&state, vlib_time_now(vm), N66_SLOTS);
  for (unsigned i = 0; i < N66_SLOTS; i++) count += state.sessions[i].used;
  clib_spinlock_unlock(&session_lock);
  vlib_cli_output(vm, "NAPT66 %s, sessions %u/%u, reserved ports %u-65535",
                  n_insides == 0 ? "disabled" : "enabled", count, N66_SLOTS, N66_FIRST);
  for (u32 i = 0; i < n_insides; i++)
    vlib_cli_output(vm, "  inside %U prefix %U/%u", format_vnet_sw_if_index_name,
                    vnet_get_main(), insides[i].sw_if_index, format_ip6_address,
                    &insides[i].prefix, insides[i].len);
  return 0;
}
VLIB_CLI_COMMAND(napt66_show_command, static) = {
  .path = "show napt66", .short_help = "show napt66", .function = napt66_show,
};
static clib_error_t *napt66_init(vlib_main_t *vm)
{
  (void)vm;
  clib_spinlock_init(&session_lock);
  return 0;
}
VLIB_INIT_FUNCTION(napt66_init);
VLIB_PLUGIN_REGISTER() = {
  .version = VPP_BUILD_VER, .description = "Stateful single-address IPv6 NAPT",
};
