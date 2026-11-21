/* Isolate EI inside keys by egress while keeping the routing table unchanged. */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vlib/threads.h>
#include <vlib/buffer_node.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

static u32 *contexts;
static int wired;
static u8 context_output_arc = (u8) ~0;

static clib_error_t *
wire_output_chain (vlib_main_t *vm)
{
  if (wired) return 0;
  context_output_arc = vnet_get_feature_arc_index ("ip4-output");
  if (context_output_arc == (u8) ~0)
    return clib_error_return (0, "ip4-output feature arc is unavailable");
  vlib_node_t *destination = vlib_get_node_by_name (vm, (u8 *) "interface-output");
  char *names[] = { "nat44-ei-in2out-output", "nat44-ei-in2out-output-slowpath",
                    "nat44-ei-in2out-hairpinning-finish-interface-output" };
  for (u32 i = 0; i < ARRAY_LEN (names); i++)
    {
      vlib_node_t *source = vlib_get_node_by_name (vm, (u8 *) names[i]);
      if (!source || !destination) return clib_error_return (0, "EI output graph is unavailable");
      uword slot = vlib_node_get_next (vm, source->index, destination->index);
      if (slot == ~0) return clib_error_return (0, "Unexpected EI output graph");
      vlib_node_add_named_next_with_slot (vm, source->index, "nat-ei-context-exit", slot);
    }
  wired = 1;
  return 0;
}

/* Position of this node's own entry in the egress config string. The string is
 * [next-to-feature-0, cfg-0..., next-to-feature-1, cfg-1..., ...], and the arc
 * start consumes the first next. Returns ~0 when the position is not unique.
 * Workers only read the config under the barrier's protection. */
static u32
context_exit_cursor (u32 tx, u32 node_index)
{
  vnet_feature_config_main_t *fcm = vnet_feature_get_config_main (context_output_arc);
  if (tx >= vec_len (fcm->config_index_by_sw_if_index)) return ~0;
  u32 start = fcm->config_index_by_sw_if_index[tx];
  vnet_config_main_t *cm = &fcm->config_main;
  if (start >= vec_len (cm->config_pool_index_by_user_index)) return ~0;
  vnet_config_t *c = pool_elt_at_index (cm->config_pool, cm->config_pool_index_by_user_index[start]);
  u32 cursor = start + 1, expected = ~0;
  vnet_config_feature_t *f;
  vec_foreach (f, c->features)
    {
      if (f->node_index == node_index)
        {
          /* Enabling both the output chain and a context on one interface adds
           * this node twice. Either position is legitimate, so leave it to the
           * range check. */
          if (expected != ~0) return ~0;
          expected = cursor;
        }
      cursor += 1 + vec_len (f->feature_config);
    }
  return expected;
}

/* Return handoff. The patched EI handoff nodes record the thread that
 * received each packet in vnet_buffer2 (b)->unused[4] as thread index + 1
 * (0 means unknown). EI keeps the user's state on one thread, but nothing after
 * the translation needs it. With return handoff enabled, the owner thread sends
 * translated packets back to their RX thread:
 * - in2out (output feature): context-exit runs again there and resumes the
 *   output arc (ACL, MSS, WireGuard) and the TX;
 * - out2in: EI's ip4-lookup edge is redirected to nat-ei-out2in-return, which
 *   runs again there and continues to ip4-lookup, L2 and TX.
 * A flow always takes the same RX -> owner -> RX path, so its order is kept. */
#define CONTEXT_RX_THREAD(b) (vnet_buffer2 (b)->unused[4])
/* Frame-queue elements left free for other producers before falling back to
 * finishing the packet on the owner thread instead of dropping it. */
#define CONTEXT_RETURN_RESERVE 4

static int return_enabled, return_out2in_enabled, out2in_wired;
static u32 return_fq_index = ~0, return_out2in_fq_index = ~0;

static clib_error_t *
wire_out2in_return (vlib_main_t *vm)
{
  if (out2in_wired) return 0;
  vlib_node_t *source = vlib_get_node_by_name (vm, (u8 *) "nat44-ei-out2in");
  vlib_node_t *destination = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  if (!source || !destination) return clib_error_return (0, "EI out2in graph is unavailable");
  uword slot = vlib_node_get_next (vm, source->index, destination->index);
  if (slot == ~0) return clib_error_return (0, "Unexpected EI out2in graph");
  vlib_node_add_named_next_with_slot (vm, source->index, "nat-ei-out2in-return", slot);
  out2in_wired = 1;
  return 0;
}

static int
context_return_has_room (u32 fq_index, u32 thread)
{
  vlib_frame_queue_main_t *fqm = vec_elt_at_index (vlib_thread_main.frame_queue_mains,
                                                   fq_index);
  vlib_frame_queue_t *fq = vec_elt (fqm->vlib_frame_queues, thread);
  u64 head = __atomic_load_n (&fq->head, __ATOMIC_ACQUIRE);
  u64 tail = __atomic_load_n (&fq->tail, __ATOMIC_RELAXED);
  return tail + 1 + CONTEXT_RETURN_RESERVE < head + fq->nelts;
}

static u32
context_return_enqueue (vlib_main_t *vm, vlib_node_runtime_t *node, u32 fq_index,
                        u32 *buffers, u16 *threads, u32 count)
{
  return vlib_buffer_enqueue_to_thread (vm, node, fq_index, buffers, threads,
                                        count, 1 /* drop on congestion */);
}

typedef enum
{
  CONTEXT_ERROR_INVALID_NEXT,
  CONTEXT_ERROR_CURSOR_MISMATCH,
  CONTEXT_ERROR_RETURNED,
  CONTEXT_ERROR_RETURN_DROP,
  CONTEXT_N_ERROR,
} context_error_t;

static char *context_error_strings[] = {
  "invalid-next-index",
  "cursor-mismatch",
  "returned-to-rx-thread",
  "return-congestion-drop",
};

typedef struct
{
  f64 next_warning;
} context_runtime_t;

static context_runtime_t context_runtime;

/* Reserve a real drop edge: never pass an invalid slot to the enqueue helpers.
 * Validate the u32 feature result before narrowing it to the batch's u16. */
static_always_inline u32
context_checked_next (vlib_main_t *vm, vlib_node_runtime_t *node,
                      vlib_buffer_t *b, u32 next, u32 config_index)
{
  if (PREDICT_TRUE (next < node->n_next_nodes)) return next;

  b->error = node->errors[CONTEXT_ERROR_INVALID_NEXT];
  context_runtime_t *rt = (void *) node->runtime_data;
  f64 now = vlib_time_now (vm);
  if (now >= rt->next_warning)
    {
      rt->next_warning = now + 5.0;
      clib_warning ("%v thread %u: invalid-next-index %u (n_next_nodes %u), "
                    "rx %u tx %u config %u; dropping",
                    vlib_get_node (vm, node->node_index)->name, vm->thread_index,
                    next, node->n_next_nodes,
                    vnet_buffer (b)->sw_if_index[VLIB_RX],
                    vnet_buffer (b)->sw_if_index[VLIB_TX], config_index);
    }
  return 0; /* Both context nodes register slot 0 as error-drop. */
}

/* A misplaced cursor can still produce an in-range next that belongs to another
 * node's edge table, so the range check alone cannot catch it. */
static_always_inline void
context_cursor_drop (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
                     u32 cursor, u32 expected)
{
  b->error = node->errors[CONTEXT_ERROR_CURSOR_MISMATCH];
  context_runtime_t *rt = (void *) node->runtime_data;
  f64 now = vlib_time_now (vm);
  if (now >= rt->next_warning)
    {
      rt->next_warning = now + 5.0;
      clib_warning ("%v thread %u: feature cursor %u, expected %u, rx %u tx %u; dropping",
                    vlib_get_node (vm, node->node_index)->name, vm->thread_index,
                    cursor, expected, vnet_buffer (b)->sw_if_index[VLIB_RX],
                    vnet_buffer (b)->sw_if_index[VLIB_TX]);
    }
}

/* RX thread to hand this buffer back to, or ~0 to finish it here. room[] caches
 * one queue check per RX thread and frame: 0 unknown, 1 room, 2 full. */
static_always_inline u32
context_return_target (vlib_buffer_t *b, u32 thread, u32 n_threads, u32 fq_index, u8 *room)
{
  u32 origin = CONTEXT_RX_THREAD (b);
  if (!origin || origin - 1 == thread || origin > n_threads || origin > 256) return ~0;
  u8 *r = &room[origin - 1];
  if (!*r) *r = context_return_has_room (fq_index, origin - 1) ? 1 : 2;
  return *r == 1 ? origin - 1 : ~0;
}

static_always_inline void
context_return_flush (vlib_main_t *vm, vlib_node_runtime_t *node, u32 fq_index,
                      u32 *back, u16 *back_threads, u32 n_back, u32 returned, u32 dropped)
{
  if (!n_back) return;
  u32 n_enq = context_return_enqueue (vm, node, fq_index, back, back_threads, n_back);
  vlib_node_increment_counter (vm, node->node_index, returned, n_enq);
  if (n_enq < n_back)
    vlib_node_increment_counter (vm, node->node_index, dropped, n_back - n_enq);
}

static uword
context_enter (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 tx = vnet_buffer (b)->sw_if_index[VLIB_TX], next;
      vnet_buffer2 (b)->unused[0] = vnet_buffer (b)->sw_if_index[VLIB_RX];
      vnet_buffer (b)->sw_if_index[VLIB_RX] = contexts[tx];
      u32 config_index = b->current_config_index;
      vnet_feature_next (&next, b);
      next = context_checked_next (vm, node, b, next, config_index);
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}

static uword
context_exit (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 local[VLIB_FRAME_SIZE], back[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE], back_threads[VLIB_FRAME_SIZE];
  u32 n_local = 0, n_back = 0;
  /* EI selects the handoff feature whenever a worker is configured.
   * That feature already consumes the pending EI -> exit cursor entry. */
  int handoff = vlib_num_workers () > 0;
  int returning = handoff && return_enabled;
  u32 thread = vm->thread_index, n_threads = vlib_num_workers () + 1;
  /* Per-frame room decision for each RX thread: 0 unknown, 1 room, 2 full. */
  u8 room[256] = {};
  u32 cached_tx = ~0, expected = ~0;
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = bufs[i];
      u32 target = returning ? context_return_target (b, thread, n_threads, return_fq_index, room) : ~0;
      if (target != ~0)
        {
          /* Leave the buffer untouched: the RX thread runs this node again. */
          back[n_back] = from[i];
          back_threads[n_back++] = target;
          continue;
        }
      CONTEXT_RX_THREAD (b) = 0;
      u32 next, discarded, tx = vnet_buffer (b)->sw_if_index[VLIB_TX];
      local[n_local] = from[i];
      if (tx < vec_len (contexts) && contexts[tx] != ~0)
        vnet_buffer (b)->sw_if_index[VLIB_RX] = vnet_buffer2 (b)->unused[0];
      /* Without handoff, EI jumps here without advancing the cursor. */
      if (!handoff) vnet_feature_next (&discarded, b);
      u32 config_index = b->current_config_index;
      if (tx != cached_tx)
        {
          cached_tx = tx;
          expected = context_exit_cursor (tx, node->node_index);
        }
      if (PREDICT_FALSE (expected != ~0 && config_index != expected))
        {
          context_cursor_drop (vm, node, b, config_index, expected);
          nexts[n_local++] = 0;
          continue;
        }
      vnet_feature_next (&next, b);
      nexts[n_local++] = context_checked_next (vm, node, b, next, config_index);
    }
  if (n_local) vlib_buffer_enqueue_to_next (vm, node, local, nexts, n_local);
  context_return_flush (vm, node, return_fq_index, back, back_threads, n_back,
                        CONTEXT_ERROR_RETURNED, CONTEXT_ERROR_RETURN_DROP);
  return frame->n_vectors;
}

/* Replaces EI out2in's ip4-lookup edge. Next 0 is ip4-lookup. */
static uword
out2in_return (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 local[VLIB_FRAME_SIZE], back[VLIB_FRAME_SIZE];
  u16 back_threads[VLIB_FRAME_SIZE];
  u32 n_local = 0, n_back = 0;
  int returning = vlib_num_workers () > 0 && return_out2in_enabled;
  u32 thread = vm->thread_index, n_threads = vlib_num_workers () + 1;
  u8 room[256] = {};
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 target = returning ?
        context_return_target (b, thread, n_threads, return_out2in_fq_index, room) : ~0;
      if (target != ~0)
        {
          back[n_back] = from[i];
          back_threads[n_back++] = target;
          continue;
        }
      CONTEXT_RX_THREAD (b) = 0;
      local[n_local++] = from[i];
    }
  if (n_local) vlib_buffer_enqueue_to_single_next (vm, node, local, 0, n_local);
  context_return_flush (vm, node, return_out2in_fq_index, back, back_threads, n_back,
                        CONTEXT_ERROR_RETURNED, CONTEXT_ERROR_RETURN_DROP);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ei_context_enter_node) = {
  .function = context_enter, .name = "nat-ei-context-enter",
  .vector_size = sizeof (u32), .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CONTEXT_N_ERROR, .error_strings = context_error_strings,
  .n_next_nodes = 1, .next_nodes = { [0] = "error-drop" },
  .runtime_data_bytes = sizeof (context_runtime_t), .runtime_data = &context_runtime,
};
VLIB_REGISTER_NODE (ei_context_exit_node) = {
  .function = context_exit, .name = "nat-ei-context-exit",
  .vector_size = sizeof (u32), .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CONTEXT_N_ERROR, .error_strings = context_error_strings,
  .n_next_nodes = 1, .next_nodes = { [0] = "error-drop" },
  .runtime_data_bytes = sizeof (context_runtime_t), .runtime_data = &context_runtime,
};
VLIB_REGISTER_NODE (ei_out2in_return_node) = {
  .function = out2in_return, .name = "nat-ei-out2in-return",
  .vector_size = sizeof (u32), .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CONTEXT_N_ERROR, .error_strings = context_error_strings,
  .n_next_nodes = 1, .next_nodes = { [0] = "ip4-lookup" },
};
VNET_FEATURE_INIT (ei_context_enter_feature, static) = {
  .arc_name = "ip4-output", .node_name = "nat-ei-context-enter",
  .runs_after = VNET_FEATURES ("ipsec4-output-feature"),
  .runs_before = VNET_FEATURES ("nat44-ei-in2out-output", "nat44-ei-in2out-output-worker-handoff"),
};
VNET_FEATURE_INIT (ei_context_exit_feature, static) = {
  .arc_name = "ip4-output", .node_name = "nat-ei-context-exit",
  .runs_after = VNET_FEATURES ("nat44-ei-in2out-output", "nat44-ei-in2out-output-worker-handoff"),
  .runs_before = VNET_FEATURES ("acl-plugin-out-ip4-fa", "tcp-mss-clamping-ip4-out", "wg4-output-tun", "interface-output"),
};

static clib_error_t *
context_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 output, context;
  int enable = 1;
  if (!unformat (input, "%U %U", unformat_vnet_sw_interface, vnet_get_main (), &output,
                 unformat_vnet_sw_interface, vnet_get_main (), &context))
    return clib_error_return (0, "Expected output and context interfaces");
  if (unformat (input, "del")) enable = 0;
  clib_error_t *error = wire_output_chain (vm);
  if (error) return error;
  vec_validate_init_empty (contexts, output, ~0);
  contexts[output] = context;
  int rv = vnet_feature_enable_disable ("ip4-output", "nat-ei-context-enter", output, enable, 0, 0);
  if (!rv) rv = vnet_feature_enable_disable ("ip4-output", "nat-ei-context-exit", output, enable, 0, 0);
  if (rv) return clib_error_return (0, "Unable to configure EI context (%d)", rv);
  if (!enable) contexts[output] = ~0;
  return 0;
}
VLIB_CLI_COMMAND (ei_context_command, static) = {
  .path = "nat44 ei context",
  .short_help = "nat44 ei context <output-interface> <context-interface> [del]",
  .function = context_command,
};

static clib_error_t *
output_chain_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 output;
  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnet_get_main (), &output))
    return clib_error_return (0, "Expected EI output interface");
  clib_error_t *error = wire_output_chain (vm);
  if (error) return error;
  int rv = vnet_feature_enable_disable ("ip4-output", "nat-ei-context-exit", output, 1, 0, 0);
  return rv ? clib_error_return (0, "Unable to configure EI output chain (%d)", rv) : 0;
}
VLIB_CLI_COMMAND (ei_output_chain_command, static) = {
  .path = "nat44 ei output-chain",
  .short_help = "nat44 ei output-chain <interface>",
  .function = output_chain_command,
};
static clib_error_t *
return_handoff_command (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  int enable, in2out = 1, out2in = 1;
  if (unformat (input, "enable")) enable = 1;
  else if (unformat (input, "disable")) enable = 0;
  else return clib_error_return (0, "Expected enable or disable");
  if (unformat (input, "in2out")) out2in = 0;
  else if (unformat (input, "out2in")) in2out = 0;
  if (enable && !vlib_num_workers ())
    return clib_error_return (0, "Return handoff needs worker threads");
  if (enable && vlib_num_workers () + 1 > 256)
    return clib_error_return (0, "Return handoff supports at most 256 threads");
  if (enable && out2in)
    {
      clib_error_t *error = wire_out2in_return (vm);
      if (error) return error;
      if (return_out2in_fq_index == ~0)
        return_out2in_fq_index = vlib_frame_queue_main_init (ei_out2in_return_node.index, 0);
    }
  if (enable && in2out && return_fq_index == ~0)
    return_fq_index = vlib_frame_queue_main_init (ei_context_exit_node.index, 0);
  if (in2out) return_enabled = enable;
  if (out2in) return_out2in_enabled = enable;
  return 0;
}
VLIB_CLI_COMMAND (return_handoff_cli, static) = {
  .path = "nat44 ei return-handoff",
  .short_help = "nat44 ei return-handoff enable|disable [in2out|out2in]",
  .function = return_handoff_command,
};

static clib_error_t *
return_handoff_show (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vlib_cli_output (vm, "NAT44 EI return handoff: in2out %s, out2in %s",
                   return_enabled ? "enabled" : "disabled",
                   return_out2in_enabled ? "enabled" : "disabled");
  return 0;
}
VLIB_CLI_COMMAND (return_handoff_show_cli, static) = {
  .path = "show nat44 ei return-handoff",
  .short_help = "show nat44 ei return-handoff",
  .function = return_handoff_show,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Separate NAT44 EI inside VRFs by output interface",
};
