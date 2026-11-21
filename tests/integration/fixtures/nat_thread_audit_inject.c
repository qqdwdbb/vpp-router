/* Isolated-test helper: enqueue a raw IPv4 packet on the CLI/main thread. */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

static clib_error_t *
inject (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 *bytes = 0;
  u32 bi;
  if (!unformat (input, "%U", unformat_hex_string, &bytes) ||
      vec_len (bytes) < 20 || vec_len (bytes) > 1500)
    {
      vec_free (bytes);
      return clib_error_return (0, "Expected 20..1500 IPv4 bytes in hex");
    }
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      vec_free (bytes);
      return clib_error_return (0, "Buffer allocation failed");
    }
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  clib_memcpy_fast (vlib_buffer_get_current (b), bytes, vec_len (bytes));
  b->current_length = vec_len (bytes);
  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID | VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0; /* IPv4 FIB index */
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  vlib_frame_t *frame = vlib_get_frame_to_node (vm, node->index);
  ((u32 *) vlib_frame_vector_args (frame))[0] = bi;
  frame->n_vectors = 1;
  vlib_put_frame_to_node (vm, node->index, frame);
  vlib_cli_output (vm, "injected thread %u", vm->thread_index);
  vec_free (bytes);
  return 0;
}

VLIB_CLI_COMMAND (audit_inject, static) = {
  .path = "test nat-thread inject",
  .short_help = "test nat-thread inject <IPv4 hex>",
  .function = inject,
};
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Isolated NAT thread ownership test helper",
};
