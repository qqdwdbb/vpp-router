/* Steer client DNS (TCP/UDP to one destination port) into a separate FIB table.
 *
 * ABF ran a full ACL match on every IPv4/IPv6 packet of the attached
 * interface just to find port 53. This feature reads only the L4 protocol
 * and destination port; everything else continues down the arc untouched.
 * A packet to the port is then checked against source, exempt-source and
 * exempt-destination prefixes and, if selected, looked up in the configured
 * table (like svs). Routes in that table decide where DNS goes, so neighbour
 * resolution and path changes stay with the FIB. Like an ABF match, a steered
 * packet leaves the arc, so later features (another ABF policy) cannot
 * override it.
 *
 * Non-first fragments and IPv6 packets whose first next header is not TCP or
 * UDP carry no readable port and are never steered. */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/format.h>
#include <vnet/udp/udp_packet.h>
#include <vpp/app/version.h>

typedef struct
{
  ip46_address_t net, mask;
  u8 len;
} dnsi_prefix_t;

typedef struct
{
  u32 fib_index, table_id;
  u16 port; /* network order */
  dnsi_prefix_t *src, *exempt_src, *exempt_dst;
} dnsi_cfg_t;

/* Indexed by [is_ip6][sw_if_index]; null when the feature is off there. */
static dnsi_cfg_t **dnsi_cfg_by_sw[2];
static fib_source_t dnsi_fib_src;

#define foreach_dnsi_error _ (STEERED, "steered to intercept table")

typedef enum
{
#define _(sym, str) DNSI_ERROR_##sym,
  foreach_dnsi_error
#undef _
    DNSI_N_ERROR,
} dnsi_error_t;

static char *dnsi_error_strings[] = {
#define _(sym, str) str,
  foreach_dnsi_error
#undef _
};

typedef enum
{
  DNSI_NEXT_LOOKUP,
  DNSI_N_NEXT,
} dnsi_next_t;

typedef struct
{
  u32 fib_index; /* ~0 when not steered */
} dnsi_trace_t;

static u8 *
format_dnsi_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dnsi_trace_t *t = va_arg (*args, dnsi_trace_t *);
  if (t->fib_index == ~0)
    return format (s, "not steered");
  return format (s, "steered fib_index %u", t->fib_index);
}

static_always_inline int
dnsi_in4 (const dnsi_prefix_t *v, const ip4_address_t *a)
{
  const dnsi_prefix_t *p;
  vec_foreach (p, v)
    if ((a->as_u32 & p->mask.ip4.as_u32) == p->net.ip4.as_u32)
      return 1;
  return 0;
}

static_always_inline int
dnsi_in6 (const dnsi_prefix_t *v, const ip6_address_t *a)
{
  const dnsi_prefix_t *p;
  vec_foreach (p, v)
    if ((a->as_u64[0] & p->mask.ip6.as_u64[0]) == p->net.ip6.as_u64[0] &&
	(a->as_u64[1] & p->mask.ip6.as_u64[1]) == p->net.ip6.as_u64[1])
      return 1;
  return 0;
}

/* Same order as the ACL it replaces: exemptions first, then sources. */
static_always_inline int
dnsi_select (vlib_buffer_t *b, const dnsi_cfg_t *c, int is_ip6)
{
  if (is_ip6)
    {
      ip6_header_t *ip = vlib_buffer_get_current (b);
      udp_header_t *l4 = ip6_next_header (ip);
      if (ip->protocol != IP_PROTOCOL_UDP && ip->protocol != IP_PROTOCOL_TCP)
	return 0;
      if (b->current_length < sizeof (*ip) + 4 || l4->dst_port != c->port)
	return 0;
      return !dnsi_in6 (c->exempt_dst, &ip->dst_address) &&
	     !dnsi_in6 (c->exempt_src, &ip->src_address) &&
	     dnsi_in6 (c->src, &ip->src_address);
    }
  ip4_header_t *ip = vlib_buffer_get_current (b);
  if (ip->protocol != IP_PROTOCOL_UDP && ip->protocol != IP_PROTOCOL_TCP)
    return 0;
  if (ip4_get_fragment_offset (ip))
    return 0;
  udp_header_t *l4 = ip4_next_header (ip);
  if (b->current_length < ip4_header_bytes (ip) + 4 || l4->dst_port != c->port)
    return 0;
  return !dnsi_in4 (c->exempt_dst, &ip->dst_address) &&
	 !dnsi_in4 (c->exempt_src, &ip->src_address) &&
	 dnsi_in4 (c->src, &ip->src_address);
}

static_always_inline uword
dnsi_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
	     int is_ip6)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors, steered = 0;
  dnsi_cfg_t **cfgs = dnsi_cfg_by_sw[is_ip6];

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left > 0)
    {
      u32 sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      dnsi_cfg_t *c = sw_if_index < vec_len (cfgs) ? cfgs[sw_if_index] : 0;
      u32 fib_index = ~0;

      if (c && dnsi_select (b[0], c, is_ip6))
	{
	  fib_index = c->fib_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = fib_index;
	  next[0] = DNSI_NEXT_LOOKUP;
	  steered++;
	}
      else
	vnet_feature_next_u16 (next, b[0]);
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  dnsi_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->fib_index = fib_index;
	}
      b++;
      next++;
      n_left--;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index, DNSI_ERROR_STEERED,
			       steered);
  return frame->n_vectors;
}

static uword
dnsi_ip4 (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return dnsi_inline (vm, node, frame, 0);
}

static uword
dnsi_ip6 (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return dnsi_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (dnsi_ip4_node) = {
  .function = dnsi_ip4,
  .name = "dns-intercept-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_dnsi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = DNSI_N_ERROR,
  .error_strings = dnsi_error_strings,
  .n_next_nodes = DNSI_N_NEXT,
  .next_nodes = { [DNSI_NEXT_LOOKUP] = "ip4-lookup" },
};

VLIB_REGISTER_NODE (dnsi_ip6_node) = {
  .function = dnsi_ip6,
  .name = "dns-intercept-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_dnsi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = DNSI_N_ERROR,
  .error_strings = dnsi_error_strings,
  .n_next_nodes = DNSI_N_NEXT,
  .next_nodes = { [DNSI_NEXT_LOOKUP] = "ip6-lookup" },
};

/* The position ABF had: after input ACLs and reassembly, before ABF. */
VNET_FEATURE_INIT (dnsi_ip4_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "dns-intercept-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-full-reassembly-feature",
			       "ip4-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("abf-input-ip4"),
};

VNET_FEATURE_INIT (dnsi_ip6_feat, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "dns-intercept-ip6",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa",
			       "ip6-full-reassembly-feature",
			       "ip6-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("abf-input-ip6"),
};

static void
dnsi_cfg_free (dnsi_cfg_t *c, int is_ip6)
{
  if (!c)
    return;
  fib_table_unlock (c->fib_index, is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4,
		    dnsi_fib_src);
  vec_free (c->src);
  vec_free (c->exempt_src);
  vec_free (c->exempt_dst);
  clib_mem_free (c);
}

/* Replace (c != 0) or remove (c == 0) the configuration. Runs under the
 * worker barrier, so the old one can be freed at once. */
static void
dnsi_set (u32 sw_if_index, int is_ip6, dnsi_cfg_t *c)
{
  dnsi_cfg_t *old;
  vec_validate (dnsi_cfg_by_sw[is_ip6], sw_if_index);
  old = dnsi_cfg_by_sw[is_ip6][sw_if_index];
  dnsi_cfg_by_sw[is_ip6][sw_if_index] = c;
  if (!old != !c)
    vnet_feature_enable_disable (is_ip6 ? "ip6-unicast" : "ip4-unicast",
				 is_ip6 ? "dns-intercept-ip6" : "dns-intercept-ip4",
				 sw_if_index, c != 0, 0, 0);
  dnsi_cfg_free (old, is_ip6);
}

static uword
dnsi_unformat_prefix (unformat_input_t *input, va_list *args)
{
  dnsi_prefix_t *p = va_arg (*args, dnsi_prefix_t *);
  int is_ip6 = va_arg (*args, int);
  u32 len;

  clib_memset (p, 0, sizeof (*p));
  if (!is_ip6 && unformat (input, "%U/%u", unformat_ip4_address, &p->net.ip4, &len) &&
      len <= 32)
    {
      ip4_preflen_to_mask (len, &p->mask.ip4);
      p->net.ip4.as_u32 &= p->mask.ip4.as_u32;
    }
  else if (is_ip6 && unformat (input, "%U/%u", unformat_ip6_address, &p->net.ip6, &len) &&
	   len <= 128)
    {
      ip6_preflen_to_mask (len, &p->mask.ip6);
      p->net.ip6.as_u64[0] &= p->mask.ip6.as_u64[0];
      p->net.ip6.as_u64[1] &= p->mask.ip6.as_u64[1];
    }
  else
    return 0;
  p->len = len;
  return 1;
}

static clib_error_t *
dnsi_cli (vlib_main_t *vm, unformat_input_t *main_input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line, *line = &_line;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0, table_id = ~0, port = 53;
  int is_ip6 = -1, disable = 0;
  dnsi_prefix_t p, *src = 0, *exempt_src = 0, *exempt_dst = 0;
  clib_error_t *error = 0;

  if (!unformat_user (main_input, unformat_line_input, line))
    return clib_error_return (0, "expected arguments");
  while (unformat_check_input (line) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line, "ip4"))
	is_ip6 = 0;
      else if (unformat (line, "ip6"))
	is_ip6 = 1;
      else if (unformat (line, "disable"))
	disable = 1;
      else if (unformat (line, "table %u", &table_id))
	;
      else if (unformat (line, "port %u", &port))
	;
      else if (is_ip6 >= 0 &&
	       unformat (line, "exempt-src %U", dnsi_unformat_prefix, &p, is_ip6))
	vec_add1 (exempt_src, p);
      else if (is_ip6 >= 0 &&
	       unformat (line, "exempt-dst %U", dnsi_unformat_prefix, &p, is_ip6))
	vec_add1 (exempt_dst, p);
      else if (is_ip6 >= 0 && unformat (line, "src %U", dnsi_unformat_prefix, &p, is_ip6))
	vec_add1 (src, p);
      else if (sw_if_index == ~0 &&
	       unformat (line, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U' (give ip4 or ip6 before prefixes)",
				     format_unformat_error, line);
	  goto done;
	}
    }
  if (sw_if_index == ~0 || is_ip6 < 0)
    {
      error = clib_error_return (0, "expected <interface> ip4|ip6");
      goto done;
    }
  if (disable)
    {
      dnsi_set (sw_if_index, is_ip6, 0);
      goto done;
    }
  if (table_id == ~0 || !vec_len (src) || port == 0 || port > 0xffff)
    {
      error = clib_error_return (0, "expected table <id>, at least one src and a port 1-65535");
      goto done;
    }

  dnsi_cfg_t *c = clib_mem_alloc (sizeof (*c));
  clib_memset (c, 0, sizeof (*c));
  c->table_id = table_id;
  c->fib_index = fib_table_find_or_create_and_lock (
    is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4, table_id, dnsi_fib_src);
  c->port = clib_host_to_net_u16 (port);
  c->src = src;
  c->exempt_src = exempt_src;
  c->exempt_dst = exempt_dst;
  src = exempt_src = exempt_dst = 0;
  dnsi_set (sw_if_index, is_ip6, c);

done:
  vec_free (src);
  vec_free (exempt_src);
  vec_free (exempt_dst);
  unformat_free (line);
  return error;
}

VLIB_CLI_COMMAND (dnsi_command, static) = {
  .path = "dns intercept",
  .short_help = "dns intercept <interface> ip4|ip6 {disable | table <id> [port <n>] "
		"src <prefix>... [exempt-src <prefix>]... [exempt-dst <prefix>]...}",
  .function = dnsi_cli,
};

static u8 *
format_dnsi_prefixes (u8 *s, va_list *args)
{
  dnsi_prefix_t *v = va_arg (*args, dnsi_prefix_t *), *p;
  vec_foreach (p, v)
    s = format (s, " %U/%u", format_ip46_address, &p->net, IP46_TYPE_ANY, p->len);
  return s;
}

static clib_error_t *
dnsi_show (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  for (int is_ip6 = 0; is_ip6 < 2; is_ip6++)
    for (u32 i = 0; i < vec_len (dnsi_cfg_by_sw[is_ip6]); i++)
      {
	dnsi_cfg_t *c = dnsi_cfg_by_sw[is_ip6][i];
	if (!c)
	  continue;
	vlib_cli_output (vm, "%U %s table %u port %u", format_vnet_sw_if_index_name,
			 vnet_get_main (), i, is_ip6 ? "ip6" : "ip4", c->table_id,
			 clib_net_to_host_u16 (c->port));
	vlib_cli_output (vm, "  src%U", format_dnsi_prefixes, c->src);
	vlib_cli_output (vm, "  exempt-src%U", format_dnsi_prefixes, c->exempt_src);
	vlib_cli_output (vm, "  exempt-dst%U", format_dnsi_prefixes, c->exempt_dst);
      }
  return 0;
}

VLIB_CLI_COMMAND (dnsi_show_command, static) = {
  .path = "show dns intercept",
  .short_help = "show dns intercept",
  .function = dnsi_show,
};

static clib_error_t *
dnsi_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  if (!is_add)
    for (int is_ip6 = 0; is_ip6 < 2; is_ip6++)
      if (sw_if_index < vec_len (dnsi_cfg_by_sw[is_ip6]) &&
	  dnsi_cfg_by_sw[is_ip6][sw_if_index])
	dnsi_set (sw_if_index, is_ip6, 0);
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (dnsi_sw_interface_add_del);

static clib_error_t *
dnsi_init (vlib_main_t *vm)
{
  dnsi_fib_src = fib_source_allocate ("dns-intercept", FIB_SOURCE_PRIORITY_LOW,
				      FIB_SOURCE_BH_SIMPLE);
  return 0;
}

VLIB_INIT_FUNCTION (dnsi_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Steer client DNS by destination port into a FIB table",
};
