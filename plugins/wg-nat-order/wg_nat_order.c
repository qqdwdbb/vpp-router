/* VPP 26.06: order IPv4 output NAT before WireGuard consumes the feature arc. */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

/* This anchor is never enabled. Its constraints order the existing features. */
static uword
wg_nat_order_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      u32 next;
      vlib_buffer_t *buffer = vlib_get_buffer (vm, from[i]);
      vnet_feature_next (&next, buffer);
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (wg_nat_order_node) = {
  .function = wg_nat_order_node_fn,
  .name = "wg-nat-order-anchor",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VNET_FEATURE_INIT (wg_nat_order_anchor, static) = {
  .arc_name = "ip4-output",
  .node_name = "wg-nat-order-anchor",
  .runs_after = VNET_FEATURES ("nat44-ei-in2out-output", "nat-ei-context-exit",
				"nat-pre-in2out-output", "nat44-in2out-output-worker-handoff",
				"nat44-ed-in2out-output", "tcp-mss-clamping-ip4-out"),
  .runs_before = VNET_FEATURES ("wg4-output-tun"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Order NAT44 output before WireGuard IPv4 encryption",
};
