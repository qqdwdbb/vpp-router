/* Small VPP boundary shim; the generated include contains the real node code. */
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uintptr_t uword;
typedef double f64;
#define VLIB_FRAME_SIZE 256
#define VLIB_RX 0
#define VLIB_TX 1
#define VLIB_NODE_TYPE_INTERNAL 0
#define PREDICT_TRUE(x) (x)
#define PREDICT_FALSE(x) (x)
#define static_always_inline static inline
#define ARRAY_LEN(x) (sizeof (x) / sizeof ((x)[0]))
#define vec_len(x) (sizeof (context_values) / sizeof (context_values[0]))

typedef struct
{
  u32 sw_if_index[2], unused[5];
} opaque_t;
typedef struct
{
  opaque_t opaque;
  u32 error, current_config_index, feature_next[2], consumed;
} vlib_buffer_t;
typedef struct { const char *name; } vlib_node_t;
typedef struct
{
  u32 thread_index;
  f64 now;
  vlib_node_t node;
  vlib_buffer_t buffers[VLIB_FRAME_SIZE];
} vlib_main_t;
typedef struct
{
  u32 n_next_nodes, node_index, errors[2];
  _Alignas(f64) unsigned char runtime_data[64];
} vlib_node_runtime_t;
typedef struct { u32 n_vectors, from[VLIB_FRAME_SIZE]; } vlib_frame_t;
typedef uword (*node_fn_t) (vlib_main_t *, vlib_node_runtime_t *, vlib_frame_t *);
typedef struct
{
  node_fn_t function;
  const char *name;
  u32 vector_size, type, n_errors, n_next_nodes, runtime_data_bytes;
  char **error_strings;
  const char *next_nodes[1];
  void *runtime_data;
} node_registration_t;
#define VLIB_REGISTER_NODE(name) static node_registration_t name

static u32 workers, warnings, dropped, queued[VLIB_FRAME_SIZE];
static u32 logged_next, logged_config, expected_cursor = ~0u, mismatches;
static u32 context_exit_cursor (u32 tx, u32 node_index)
{ (void) tx; (void) node_index; return expected_cursor; }
static u32 context_values[] = { ~0u, ~0u, 101 };
static u32 *contexts = context_values;

static u32 vlib_num_workers (void) { return workers; }

/* Return handoff boundary: per-thread room and the frames handed back. */
static int return_enabled, return_out2in_enabled;
static u32 return_fq_index = 7, return_out2in_fq_index = 9, last_fq = ~0u;
static int room_full[8], room_checks[8];
static u32 returned[VLIB_FRAME_SIZE], returned_thread[VLIB_FRAME_SIZE];
static u32 n_returned, return_accept = ~0u, counters[4];
#define CONTEXT_RX_THREAD(b) (vnet_buffer2 (b)->unused[4])
static int context_return_has_room (u32 fq_index, u32 thread)
{ assert (thread < 8); last_fq = fq_index; room_checks[thread]++; return !room_full[thread]; }
static u32 context_return_enqueue (vlib_main_t *vm, vlib_node_runtime_t *node, u32 fq_index,
                                   u32 *buffers, u16 *threads, u32 count)
{
  (void) vm; (void) node;
  assert (fq_index == last_fq);
  u32 n = count < return_accept ? count : return_accept;
  for (u32 i = 0; i < count; i++)
    {
      returned[n_returned] = buffers[i];
      returned_thread[n_returned++] = threads[i];
    }
  return n;
}
static void vlib_node_increment_counter (vlib_main_t *vm, u32 node, u32 counter, u32 n)
{ (void) vm; (void) node; assert (counter < 4); counters[counter] += n; }
static f64 vlib_time_now (vlib_main_t *vm) { return vm->now; }
static vlib_node_t *vlib_get_node (vlib_main_t *vm, u32 index)
{ (void) index; return &vm->node; }
static vlib_buffer_t *vlib_get_buffer (vlib_main_t *vm, u32 index)
{ assert (index < VLIB_FRAME_SIZE); return &vm->buffers[index]; }
static u32 *vlib_frame_vector_args (vlib_frame_t *frame) { return frame->from; }
#define vnet_buffer(b) (&(b)->opaque)
#define vnet_buffer2(b) (&(b)->opaque)
static void vnet_feature_next (u32 *next, vlib_buffer_t *b)
{
  assert (b->consumed < 2);
  *next = b->feature_next[b->consumed++];
  b->current_config_index++;
}
static void vlib_get_buffers (vlib_main_t *vm, u32 *from,
                             vlib_buffer_t **buffers, u32 count)
{
  for (u32 i = 0; i < count; i++) buffers[i] = vlib_get_buffer (vm, from[i]);
}
static void vlib_set_next_frame_buffer (vlib_main_t *vm,
                                       vlib_node_runtime_t *node,
                                       u32 next, u32 buffer)
{
  /* This is the boundary the original crashing code reached without a guard. */
  assert (next < node->n_next_nodes);
  queued[buffer] = next;
  if (!next && vm->buffers[buffer].error == node->errors[0]) dropped++;
  if (!next && vm->buffers[buffer].error == node->errors[1]) mismatches++;
}
static void vlib_buffer_enqueue_to_single_next (vlib_main_t *vm,
                                                vlib_node_runtime_t *node, u32 *from,
                                                u16 next, u32 count)
{
  for (u32 i = 0; i < count; i++)
    vlib_set_next_frame_buffer (vm, node, next, from[i]);
}
static void vlib_buffer_enqueue_to_next (vlib_main_t *vm,
                                         vlib_node_runtime_t *node, u32 *from,
                                         u16 *nexts, u32 count)
{
  for (u32 i = 0; i < count; i++)
    vlib_set_next_frame_buffer (vm, node, nexts[i], from[i]);
}
static void clib_warning (const char *format, ...)
{
  va_list args;
  va_start (args, format);
  (void) va_arg (args, const char *); /* node name (%v) */
  (void) va_arg (args, u32); /* thread */
  logged_next = va_arg (args, u32);
  (void) va_arg (args, u32); /* next count */
  (void) va_arg (args, u32); /* RX */
  (void) va_arg (args, u32); /* TX */
  logged_config = va_arg (args, u32);
  va_end (args);
  warnings++;
}

#include "nat_ei_context_nodes.inc"

static void init (vlib_main_t *vm, vlib_node_runtime_t *node,
                  vlib_frame_t *frame, node_registration_t *reg, u32 count)
{
  memset (vm, 0, sizeof (*vm));
  memset (node, 0, sizeof (*node));
  memset (frame, 0, sizeof (*frame));
  assert (reg->n_next_nodes == 1);
  assert (!strcmp (reg->next_nodes[0], reg->function == out2in_return ? "ip4-lookup" : "error-drop"));
  assert (reg->n_errors == 4);
  assert (!strcmp (reg->error_strings[2], "returned-to-rx-thread"));
  assert (!strcmp (reg->error_strings[3], "return-congestion-drop"));
  assert (!strcmp (reg->error_strings[1], "cursor-mismatch"));
  assert (!strcmp (reg->error_strings[0], "invalid-next-index"));
  assert (reg->runtime_data_bytes <= sizeof (node->runtime_data));
  if (reg->runtime_data_bytes)
    memcpy (node->runtime_data, reg->runtime_data, reg->runtime_data_bytes);
  /* Slot 0 is error-drop, then the four real exit edges. */
  node->n_next_nodes = 5;
  node->errors[0] = 77;
  node->errors[1] = 78;
  vm->node.name = reg->name;
  frame->n_vectors = count;
  for (u32 i = 0; i < count; i++)
    {
      frame->from[i] = i;
      vm->buffers[i].opaque.sw_if_index[VLIB_RX] = 12;
      vm->buffers[i].opaque.sw_if_index[VLIB_TX] = 2;
      vm->buffers[i].opaque.unused[0] = 12;
      vm->buffers[i].current_config_index = 100;
    }
  dropped = warnings = mismatches = 0;
  expected_cursor = ~0u;
  return_enabled = return_out2in_enabled = 0;
  last_fq = ~0u;
  n_returned = 0;
  return_accept = ~0u;
  memset (room_full, 0, sizeof (room_full));
  memset (room_checks, 0, sizeof (room_checks));
  memset (counters, 0, sizeof (counters));
  memset (queued, 0xff, sizeof (queued));
}

int main (int argc, char **argv)
{
  assert (argc == 2);
  vlib_main_t vm;
  vlib_node_runtime_t node;
  vlib_frame_t frame;
  workers = 1;
  if (!strcmp (argv[1], "full-frame"))
    {
      init (&vm, &node, &frame, &ei_context_exit_node, VLIB_FRAME_SIZE);
      for (u32 i = 0; i < VLIB_FRAME_SIZE; i++) vm.buffers[i].feature_next[0] = 5;
      assert (context_exit (&vm, &node, &frame) == VLIB_FRAME_SIZE);
      assert (dropped == VLIB_FRAME_SIZE && warnings == 1);
      for (u32 i = 0; i < VLIB_FRAME_SIZE; i++) assert (queued[i] == 0);
      assert (logged_next == 5 && logged_config == 100);
    }
  else if (!strcmp (argv[1], "mixed"))
    {
      u32 nexts[] = { 1, 5, 2, 65536, 3, UINT32_MAX };
      init (&vm, &node, &frame, &ei_context_exit_node, 6);
      for (u32 i = 0; i < 6; i++) vm.buffers[i].feature_next[0] = nexts[i];
      context_exit (&vm, &node, &frame);
      assert (dropped == 3 && warnings == 1);
      for (u32 i = 0; i < 6; i++)
        {
          assert (queued[i] == (i % 2 ? 0 : nexts[i]));
          assert (vm.buffers[i].error == (i % 2 ? 77 : 0));
        }
    }
  else if (!strcmp (argv[1], "no-truncation"))
    {
      init (&vm, &node, &frame, &ei_context_exit_node, 1);
      vm.buffers[0].feature_next[0] = 65537; /* Would truncate to valid slot 1. */
      context_exit (&vm, &node, &frame);
      assert (queued[0] == 0 && dropped == 1 && logged_next == 65537);
    }
  else if (!strcmp (argv[1], "cursor-and-context"))
    {
      for (workers = 0; workers <= 2; workers++)
        {
          init (&vm, &node, &frame, &ei_context_exit_node, 1);
          vm.buffers[0].feature_next[0] = workers ? 2 : 99999;
          vm.buffers[0].feature_next[1] = 2;
          vm.buffers[0].opaque.sw_if_index[VLIB_RX] = 101;
          context_exit (&vm, &node, &frame);
          assert (queued[0] == 2 && !dropped && !warnings);
          assert (vm.buffers[0].consumed == (workers ? 1 : 2));
          assert (vm.buffers[0].opaque.sw_if_index[VLIB_RX] == 12);
        }
    }
  else if (!strcmp (argv[1], "cursor-mismatch-valid-next"))
    {
      /* The original crash value is a valid slot once slot 0 is reserved. */
      init (&vm, &node, &frame, &ei_context_exit_node, VLIB_FRAME_SIZE);
      expected_cursor = 101;
      for (u32 i = 0; i < VLIB_FRAME_SIZE; i++) vm.buffers[i].feature_next[0] = 4;
      assert (context_exit (&vm, &node, &frame) == VLIB_FRAME_SIZE);
      assert (mismatches == VLIB_FRAME_SIZE && !dropped && warnings == 1);
      for (u32 i = 0; i < VLIB_FRAME_SIZE; i++)
        {
          assert (queued[i] == 0 && vm.buffers[i].consumed == 0);
          assert (vm.buffers[i].error == 78);
        }
    }
  else if (!strcmp (argv[1], "cursor-match"))
    {
      for (workers = 0; workers <= 2; workers++)
        {
          init (&vm, &node, &frame, &ei_context_exit_node, 1);
          expected_cursor = workers ? 100 : 101;
          vm.buffers[0].feature_next[0] = workers ? 4 : 99999;
          vm.buffers[0].feature_next[1] = 4;
          context_exit (&vm, &node, &frame);
          assert (queued[0] == 4 && !mismatches && !dropped && !warnings);
        }
    }
  else if (!strcmp (argv[1], "enter"))
    {
      init (&vm, &node, &frame, &ei_context_enter_node, 2);
      vm.buffers[0].feature_next[0] = 1;
      vm.buffers[1].feature_next[0] = UINT32_MAX;
      context_enter (&vm, &node, &frame);
      assert (queued[0] == 1 && queued[1] == 0 && dropped == 1);
      assert (vm.buffers[0].opaque.sw_if_index[VLIB_RX] == 101);
      assert (vm.buffers[0].opaque.unused[0] == 12);
      assert (logged_next == UINT32_MAX && warnings == 1);
    }
  else if (!strcmp (argv[1], "no-worker-invalid"))
    {
      workers = 0;
      init (&vm, &node, &frame, &ei_context_exit_node, 1);
      vm.buffers[0].feature_next[0] = 1;
      vm.buffers[0].feature_next[1] = 5;
      context_exit (&vm, &node, &frame);
      assert (dropped == 1 && warnings == 1 && queued[0] == 0);
      assert (logged_config == 101 && vm.buffers[0].consumed == 2);
    }
  else if (!strcmp (argv[1], "unmanaged-exit"))
    {
      init (&vm, &node, &frame, &ei_context_exit_node, 2);
      vm.buffers[0].opaque.sw_if_index[VLIB_TX] = 0; /* No context. */
      vm.buffers[1].opaque.sw_if_index[VLIB_TX] = 999; /* Outside context vector. */
      vm.buffers[0].feature_next[0] = vm.buffers[1].feature_next[0] = 3;
      context_exit (&vm, &node, &frame);
      assert (!dropped && !warnings && queued[0] == 3 && queued[1] == 3);
      assert (vm.buffers[0].opaque.sw_if_index[VLIB_RX] == 12);
      assert (vm.buffers[1].opaque.sw_if_index[VLIB_RX] == 12);
    }
  else if (!strcmp (argv[1], "rate-limit"))
    {
      init (&vm, &node, &frame, &ei_context_exit_node, 1);
      for (u32 i = 0; i < 3; i++)
        {
          vm.now = i == 2 ? 5.0 : i;
          vm.buffers[0].consumed = 0;
          vm.buffers[0].feature_next[0] = 5;
          context_exit (&vm, &node, &frame);
          assert (warnings == (i == 2 ? 2 : 1));
        }
      assert (dropped == 3); /* Rate limiting must not suppress drop accounting. */
      vlib_node_runtime_t other = node;
      memcpy (other.runtime_data, &context_runtime, sizeof (context_runtime));
      vm.now = 1.0;
      vm.thread_index = 2;
      vm.buffers[0].consumed = 0;
      context_exit (&vm, &other, &frame);
      assert (warnings == 3 && dropped == 4);
    }
  else if (!strcmp (argv[1], "return-to-rx"))
    {
      /* Owner thread 1: packets from RX threads 2 and 3 go back untouched,
       * its own and unmarked packets finish here, one room check per thread. */
      workers = 3;
      init (&vm, &node, &frame, &ei_context_exit_node, 6);
      vm.thread_index = 1;
      return_enabled = 1;
      u32 marks[] = { 3, 2, 3, 0, 4, 2 };
      for (u32 i = 0; i < 6; i++)
        {
          vm.buffers[i].opaque.unused[4] = marks[i];
          vm.buffers[i].feature_next[0] = 3;
          vm.buffers[i].opaque.sw_if_index[VLIB_RX] = 101;
        }
      context_exit (&vm, &node, &frame);
      assert (n_returned == 3 && counters[2] == 3 && !counters[3] && last_fq == 7);
      assert (returned[0] == 0 && returned_thread[0] == 2);
      assert (returned[1] == 2 && returned_thread[1] == 2);
      assert (returned[2] == 4 && returned_thread[2] == 3);
      assert (room_checks[2] == 1 && room_checks[3] == 1);
      for (u32 i = 0; i < 6; i++)
        {
          int back = i == 0 || i == 2 || i == 4;
          assert (vm.buffers[i].consumed == (back ? 0 : 1));
          assert (vm.buffers[i].opaque.sw_if_index[VLIB_RX] == (back ? 101 : 12));
          assert (vm.buffers[i].opaque.unused[4] == (back ? marks[i] : 0));
          assert (queued[i] == (back ? UINT32_MAX : 3));
        }
      /* The RX thread runs the node again and finishes the packet. */
      init (&vm, &node, &frame, &ei_context_exit_node, 1);
      vm.thread_index = 2;
      return_enabled = 1;
      vm.buffers[0].opaque.unused[4] = 3;
      vm.buffers[0].feature_next[0] = 4;
      vm.buffers[0].opaque.sw_if_index[VLIB_RX] = 101;
      context_exit (&vm, &node, &frame);
      assert (!n_returned && queued[0] == 4 && vm.buffers[0].consumed == 1);
      assert (vm.buffers[0].opaque.unused[4] == 0);
      assert (vm.buffers[0].opaque.sw_if_index[VLIB_RX] == 12);
    }
  else if (!strcmp (argv[1], "return-full-or-off"))
    {
      workers = 3;
      /* A full RX-thread queue: finish on the owner instead of dropping. */
      init (&vm, &node, &frame, &ei_context_exit_node, 3);
      vm.thread_index = 1;
      return_enabled = 1;
      room_full[2] = 1;
      vm.buffers[0].opaque.unused[4] = 3;
      vm.buffers[1].opaque.unused[4] = 3;
      vm.buffers[2].opaque.unused[4] = 4;
      for (u32 i = 0; i < 3; i++) vm.buffers[i].feature_next[0] = 2;
      context_exit (&vm, &node, &frame);
      assert (n_returned == 1 && returned[0] == 2 && room_checks[2] == 1);
      assert (queued[0] == 2 && queued[1] == 2 && queued[2] == UINT32_MAX);
      /* Out-of-range marks, disabled mode and no workers never return. */
      u32 setups[][2] = { { 1, 9 }, { 0, 3 } };
      for (u32 c = 0; c < 2; c++)
        {
          init (&vm, &node, &frame, &ei_context_exit_node, 1);
          vm.thread_index = 1;
          return_enabled = setups[c][0];
          vm.buffers[0].opaque.unused[4] = setups[c][1];
          vm.buffers[0].feature_next[0] = 2;
          context_exit (&vm, &node, &frame);
          assert (!n_returned && queued[0] == 2);
        }
      workers = 0;
      init (&vm, &node, &frame, &ei_context_exit_node, 1);
      return_enabled = 1;
      vm.buffers[0].opaque.unused[4] = 2;
      vm.buffers[0].feature_next[0] = 99999;
      vm.buffers[0].feature_next[1] = 2;
      context_exit (&vm, &node, &frame);
      assert (!n_returned && queued[0] == 2);
      /* Congestion drops at enqueue are counted, not finished twice. */
      workers = 3;
      init (&vm, &node, &frame, &ei_context_exit_node, 2);
      vm.thread_index = 1;
      return_enabled = 1;
      return_accept = 1;
      vm.buffers[0].opaque.unused[4] = vm.buffers[1].opaque.unused[4] = 3;
      context_exit (&vm, &node, &frame);
      assert (counters[2] == 1 && counters[3] == 1);
      assert (queued[0] == UINT32_MAX && queued[1] == UINT32_MAX);
    }
  else if (!strcmp (argv[1], "out2in-return"))
    {
      /* Owner thread 1 sends out2in packets from RX threads 2 and 3 back on the
       * out2in queue; its own, unmarked and out-of-range ones go to ip4-lookup. */
      assert (!strcmp (ei_out2in_return_node.next_nodes[0], "ip4-lookup"));
      workers = 3;
      init (&vm, &node, &frame, &ei_out2in_return_node, 6);
      vm.thread_index = 1;
      return_out2in_enabled = 1;
      return_enabled = 0; /* Directions are independent. */
      u32 marks[] = { 3, 2, 0, 4, 9, 3 };
      for (u32 i = 0; i < 6; i++) vm.buffers[i].opaque.unused[4] = marks[i];
      out2in_return (&vm, &node, &frame);
      assert (n_returned == 3 && last_fq == 9 && counters[2] == 3);
      assert (returned[0] == 0 && returned_thread[0] == 2);
      assert (returned[1] == 3 && returned_thread[1] == 3);
      assert (returned[2] == 5 && returned_thread[2] == 2);
      assert (room_checks[2] == 1 && room_checks[3] == 1);
      for (u32 i = 0; i < 6; i++)
        {
          int back = i == 0 || i == 3 || i == 5;
          assert (queued[i] == (back ? UINT32_MAX : 0));
          assert (vm.buffers[i].opaque.unused[4] == (back ? marks[i] : 0));
        }
      /* On the RX thread it continues to ip4-lookup. */
      init (&vm, &node, &frame, &ei_out2in_return_node, 1);
      vm.thread_index = 2;
      return_out2in_enabled = 1;
      vm.buffers[0].opaque.unused[4] = 3;
      out2in_return (&vm, &node, &frame);
      assert (!n_returned && queued[0] == 0 && vm.buffers[0].opaque.unused[4] == 0);
      /* Disabled, a full queue, or no workers: forward locally. */
      init (&vm, &node, &frame, &ei_out2in_return_node, 1);
      vm.thread_index = 1;
      return_enabled = 1;
      vm.buffers[0].opaque.unused[4] = 3;
      out2in_return (&vm, &node, &frame);
      assert (!n_returned && queued[0] == 0);
      init (&vm, &node, &frame, &ei_out2in_return_node, 1);
      vm.thread_index = 1;
      return_out2in_enabled = 1;
      room_full[2] = 1;
      vm.buffers[0].opaque.unused[4] = 3;
      out2in_return (&vm, &node, &frame);
      assert (!n_returned && queued[0] == 0);
      workers = 0;
      init (&vm, &node, &frame, &ei_out2in_return_node, 1);
      return_out2in_enabled = 1;
      vm.buffers[0].opaque.unused[4] = 2;
      out2in_return (&vm, &node, &frame);
      assert (!n_returned && queued[0] == 0);
    }
  else assert (0 && "unknown test case");
  puts ("PASS");
  return 0;
}
