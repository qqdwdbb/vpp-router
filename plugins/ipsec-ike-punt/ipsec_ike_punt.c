/* Forward IKE's UDP/4500 Non-ESP markers to the existing IP punt redirect.
 * ESP packets and invalid ESP SPIs remain with VPP's IPsec processing.
 * Outer ICMPv6 PTB is consumed here and turned into inner ICMP before encrypt. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vlib/vlib.h>
#include <vlib/punt.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/icmp4.h>
#include <vnet/ip/icmp6.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <vnet/ipsec/ipsec_funcs.h>
#include <vnet/ipsec/ipsec_punt.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/lock.h>
#include <vppinfra/bihash_8_8.h>
#include <vpp/app/version.h>
#include <nat/nat44-ei/nat44_ei.h>
#include "ipsec_ptb_quote.h"

static void pmtu_save_dst_enable (void);

static clib_error_t *
ike_punt_enable (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  static int enabled;
  if (enabled)
    return 0;
  vlib_punt_hdl_t client = vlib_punt_client_register ("strongswan-ike-punt");
  if (vlib_punt_register (client, ipsec_punt_reason[IPSEC_PUNT_IP4_SPI_UDP_0], "ip4-punt") ||
      vlib_punt_register (client, ipsec_punt_reason[IPSEC_PUNT_IP6_SPI_UDP_0], "ip6-punt"))
    return clib_error_return (0, "Unable to register IKE Non-ESP marker punt");
  ipsec_register_udp_port (4500, 1);
  ipsec_register_udp_port (4500, 0);
  pmtu_save_dst_enable ();
  enabled = 1;
  return 0;
}

VLIB_CLI_COMMAND (ike_punt_command, static) = {
  .path = "ipsec ike punt enable",
  .short_help = "ipsec ike punt enable",
  .function = ike_punt_enable,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "StrongSwan IKE Non-ESP marker punt and IPsec PMTU",
};

/* A policy SA otherwise reinjects its cleartext on the WAN RX interface.
 * Give authenticated cleartext a distinct ingress before NAT classifies it. */
static u32 cleartext_rx = ~0;
static uword
ipsec_cleartext_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u8 version = (*(u8 *) vlib_buffer_get_current (b)) >> 4;
      vnet_buffer (b)->sw_if_index[VLIB_RX] = cleartext_rx;
      b->flags &= ~VNET_BUFFER_F_IS_NATED;
      clib_memset (&vnet_buffer2 (b)->nat, 0, sizeof (vnet_buffer2 (b)->nat));
      vlib_set_next_frame_buffer (vm, node, version == 6 ? 1 : 0, from[i]);
    }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (ipsec_cleartext_node) = {
  .function = ipsec_cleartext_input,
  .name = "ipsec-cleartext-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 2,
  .next_nodes = { [0] = "ip4-input-no-checksum", [1] = "ip6-input" },
};
/* VPP deduplicates next slots by destination node. Two decrypt next slots
 * therefore need distinct destinations even though their processing is shared. */
VLIB_REGISTER_NODE (ipsec_cleartext6_node) = {
  .function = ipsec_cleartext_input,
  .name = "ipsec-cleartext6-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 2,
  .next_nodes = { [0] = "ip4-input-no-checksum", [1] = "ip6-input" },
};
static clib_error_t *
ipsec_cleartext_enable (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnet_get_main (), &cleartext_rx))
    return clib_error_return (0, "Expected cleartext ingress interface");
  char *names[] = { "esp4-decrypt", "esp6-decrypt", "esp4-decrypt-post", "esp6-decrypt-post" };
  char *destinations[] = { "ip4-input-no-checksum", "ip6-input" };
  for (u32 i = 0; i < ARRAY_LEN (names); i++)
    {
      vlib_node_t *source = vlib_get_node_by_name (vm, (u8 *) names[i]);
      if (!source) continue;
      for (u32 j = 0; j < ARRAY_LEN (destinations); j++)
        {
          vlib_node_t *dest = vlib_get_node_by_name (vm, (u8 *) destinations[j]);
          uword slot = vlib_node_get_next (vm, source->index, dest->index);
          if (slot != ~0)
            vlib_node_add_named_next_with_slot (vm, source->index,
              j == 0 ? "ipsec-cleartext-input" : "ipsec-cleartext6-input", slot);
        }
    }
  return 0;
}
VLIB_CLI_COMMAND (cleartext_command, static) = {
  .path = "ipsec cleartext ingress",
  .short_help = "ipsec cleartext ingress <interface>",
  .function = ipsec_cleartext_enable,
};

/* Protect VPN return traffic before output NAT can translate it again.
 * NAT44-EI or NAT44-ED, whichever plugin VPP loads. */
VNET_FEATURE_INIT (ipsec_output_order, static) = {
  .arc_name = "ip4-output",
  .node_name = "ipsec-cleartext-input",
  .runs_after = VNET_FEATURES ("ipsec4-output-feature"),
  .runs_before = VNET_FEATURES ("nat-ei-context-enter", "nat44-ei-in2out-output",
				"nat-pre-in2out-output", "nat44-in2out-output-worker-handoff",
				"nat44-ed-in2out-output", "acl-plugin-out-ip4-fa"),
};

/* Let SPD protection consume private IPv6 cleartext before WAN anti-leak ACLs. */
VNET_FEATURE_INIT (ipsec6_output_order, static) = {
  .arc_name = "ip6-output",
  .node_name = "ipsec-cleartext-input",
  .runs_after = VNET_FEATURES ("ipsec6-output-feature"),
  .runs_before = VNET_FEATURES ("acl-plugin-out-ip6-fa"),
};

/* EI and ED out2in jump to ip4-lookup and skip the rest of ip4-unicast,
 * including mss-clamp-in. Clamp SYN-ACK before NAT consumes the arc. This
 * feature is an ordering constraint; it is not enabled as a packet node on LAN. */
VNET_FEATURE_INIT (ipsec_input_order, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ipsec-cleartext-input",
  .runs_after = VNET_FEATURES ("ipsec4-input-feature", "tcp-mss-clamping-ip4-in"),
  .runs_before = VNET_FEATURES ("nat44-ei-out2in", "nat44-ei-out2in-worker-handoff",
				"nat-pre-out2in", "nat44-out2in-worker-handoff",
				"nat44-ed-out2in"),
};

/* NAT66 can leave the ip6-unicast arc before a policy-based UDP/4500 ESP
 * packet reaches IPsec. Keep the inbound SPD ahead of that jump. */
VNET_FEATURE_INIT (ipsec6_input_order, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ipsec-cleartext-input",
  .runs_after = VNET_FEATURES ("ipsec6-input-feature"),
  .runs_before = VNET_FEATURES ("nat66-out2in"),
};

#define IPSEC_PMTU_SAVED_DST 0x50544d31u

static uword
ipsec_pmtu_save_dst (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      ip4_header_t *ip = vlib_buffer_get_current (b);
      u32 next;
      if ((ip->protocol == IP_PROTOCOL_UDP || ip->protocol == IP_PROTOCOL_TCP) &&
	  b->current_length >= sizeof (*ip) + sizeof (udp_header_t))
	{
	  udp_header_t *l4 = ip4_next_header (ip);
	  vnet_buffer2 (b)->unused[1] = ip->dst_address.as_u32;
	  vnet_buffer2 (b)->unused[2] = l4->dst_port;
	  vnet_buffer2 (b)->unused[3] = IPSEC_PMTU_SAVED_DST;
	}
      vnet_feature_next (&next, b);
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipsec_pmtu_save_dst_node) = {
  .function = ipsec_pmtu_save_dst,
  .name = "ipsec-pmtu-save-dst",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VNET_FEATURE_INIT (ipsec_pmtu_save_dst_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ipsec-pmtu-save-dst",
  .runs_after = VNET_FEATURES ("tcp-mss-clamping-ip4-in", "ipsec4-input-feature"),
  .runs_before = VNET_FEATURES ("nat44-ei-out2in", "nat44-ei-out2in-worker-handoff",
				"nat44-ei-classify", "nat44-ei-handoff-classify",
				"nat-pre-out2in", "nat44-out2in-worker-handoff",
				"nat44-ed-out2in", "nat44-ed-classify", "nat44-handoff-classify"),
};

/* Only NAT out2in (EI or ED) rewrites the destination that ICMP must quote, so
 * save it only on interfaces where one of these features runs. Follow them as
 * NAT interfaces come and go instead of costing every packet on every
 * interface. A name the loaded plugins do not have is never enabled. */
static const char *const pmtu_out2in_features[] = {
  "nat44-ei-out2in", "nat44-ei-out2in-worker-handoff",
  "nat44-ei-classify", "nat44-ei-handoff-classify",
  "nat-pre-out2in", "nat44-out2in-worker-handoff",
  "nat44-ed-out2in", "nat44-ed-classify", "nat44-handoff-classify",
};
static u8 pmtu_save_dst_on;

static void
pmtu_save_dst_sync (u32 sw_if_index)
{
  int want = 0;
  for (u32 i = 0; i < ARRAY_LEN (pmtu_out2in_features); i++)
    if (vnet_feature_is_enabled ("ip4-unicast", pmtu_out2in_features[i],
				 sw_if_index) == 1)
      want = 1;
  if (want != (vnet_feature_is_enabled ("ip4-unicast", "ipsec-pmtu-save-dst",
					sw_if_index) == 1))
    vnet_feature_enable_disable ("ip4-unicast", "ipsec-pmtu-save-dst",
				 sw_if_index, want, 0, 0);
}

static void
pmtu_save_dst_update (u32 sw_if_index, u8 arc_index, u8 is_enable, void *data)
{
  /* Enabling save-dst itself calls back here; the sync is then a no-op. */
  if (pmtu_save_dst_on && arc_index == vnet_get_feature_arc_index ("ip4-unicast"))
    pmtu_save_dst_sync (sw_if_index);
}

static void
pmtu_save_dst_enable (void)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;
  pmtu_save_dst_on = 1;
  pool_foreach (sw, vnm->interface_main.sw_interfaces)
    pmtu_save_dst_sync (sw->sw_if_index);
}

/* Outer ICMPv6 PTB quotes ESP, so GCM cannot recover the inner 5-tuple.
 * Store the advertised outer MTU by outbound SPI; the next protect that
 * would exceed it emits inner ICMP and drops. Inner ICMP stays in VPP
 * lookup/NAT; it is not punted to the IKE TAP. */
static uword *pmtu_by_spi;
static clib_spinlock_t pmtu_lock;

static void
pmtu_store (u32 spi, u32 mtu)
{
  uword *p;
  clib_spinlock_lock (&pmtu_lock);
  p = hash_get (pmtu_by_spi, spi);
  if (p)
    p[0] = clib_min (p[0], mtu);
  else
    hash_set (pmtu_by_spi, spi, mtu);
  clib_spinlock_unlock (&pmtu_lock);
}

static u32
pmtu_lookup (u32 spi)
{
  uword *p;
  u32 mtu = 0;
  clib_spinlock_lock (&pmtu_lock);
  p = hash_get (pmtu_by_spi, spi);
  if (p)
    mtu = p[0];
  clib_spinlock_unlock (&pmtu_lock);
  return mtu;
}

static int
outbound_esp_spi (u32 spi)
{
  ipsec_sa_t *sa;
  pool_foreach (sa, ipsec_main.sa_pool)
    {
      if (!ipsec_sa_is_set_IS_INBOUND (sa) && sa->protocol == IPSEC_PROTOCOL_ESP &&
          sa->spi == spi)
        return 1;
    }
  return 0;
}

static int
quoted_esp_spi (vlib_buffer_t *b, u32 *spi, u32 *mtu)
{
  ip6_header_t *ip;
  icmp46_header_t *icmp;
  u8 *quoted;
  u32 used;

  if (b->current_length < sizeof (*ip) + 8 + sizeof (*ip))
    return 0;
  ip = vlib_buffer_get_current (b);
  icmp = ip6_next_header (ip);
  if (icmp->type != ICMP6_packet_too_big)
    return 0;
  *mtu = clib_net_to_host_u32 (*(u32 *) (icmp + 1));
  quoted = (u8 *) (icmp + 1) + 4;
  used = quoted - (u8 *) ip;
  return ipsec_ptb_quote_spi (quoted, b->current_length - used, spi);
}

#define foreach_ipsec_ptb_error                                               \
  _ (LEARNED, "outer PTB bound to outbound SPI")                              \
  _ (NO_SA, "outer PTB ESP SPI not in SAD")                                   \
  _ (PUNT, "outer PTB is not ESP")

typedef enum
{
#define _(sym, str) IPSEC_PTB_ERROR_##sym,
  foreach_ipsec_ptb_error
#undef _
    IPSEC_PTB_N_ERROR,
} ipsec_ptb_error_t;

static char *ipsec_ptb_error_strings[] = {
#define _(sym, str) str,
  foreach_ipsec_ptb_error
#undef _
};

static uword
ipsec_ptb_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 spi, mtu, next = 1, error = IPSEC_PTB_ERROR_PUNT;
      if (quoted_esp_spi (b, &spi, &mtu) && mtu)
        {
          if (outbound_esp_spi (spi))
            {
              pmtu_store (spi, mtu);
              next = 0;
              error = IPSEC_PTB_ERROR_LEARNED;
            }
          else
            {
              next = 0;
              error = IPSEC_PTB_ERROR_NO_SA;
            }
        }
      b->error = node->errors[error];
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipsec_ptb_node) = {
  .function = ipsec_ptb_input,
  .name = "ipsec-ptb-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = IPSEC_PTB_N_ERROR,
  .error_strings = ipsec_ptb_error_strings,
  .n_next_nodes = 2,
  .next_nodes = { [0] = "error-drop", [1] = "ip6-punt" },
};

static u32
esp_outer_length (const ipsec_sa_outb_rt_t *ort, u32 inner)
{
  u32 align = ort->cached.esp_block_align ? ort->cached.esp_block_align : 4;
  u32 payload = (inner + 2 + align - 1) / align * align;
  return ort->cached.tunnel_fixed_hdr_bytes + payload + ort->cached.integ_icv_size;
}

static u32
inner_mtu_for_outer (const ipsec_sa_outb_rt_t *ort, u32 outer_mtu)
{
  u32 align = ort->cached.esp_block_align ? ort->cached.esp_block_align : 4;
  u32 fixed = ort->cached.tunnel_fixed_hdr_bytes + ort->cached.integ_icv_size;
  u32 payload;
  if (outer_mtu <= fixed + align)
    return 0;
  payload = ((outer_mtu - fixed) / align) * align;
  return payload > 2 ? payload - 2 : 0;
}

static u64 pmtu_nat4_hit, pmtu_nat4_miss, pmtu_nat4_nomain;

struct ipsec_so_find
{
  const char *sub;
  Elf64_Addr base;
  char path[256];
};

static int
ipsec_so_phdr (struct dl_phdr_info *info, size_t size, void *data)
{
  struct ipsec_so_find *f = data;
  (void) size;
  if (info->dlpi_name && strstr (info->dlpi_name, f->sub))
    {
      f->base = info->dlpi_addr;
      snprintf (f->path, sizeof f->path, "%s", info->dlpi_name);
      return 1;
    }
  return 0;
}

/* nat44_ei_main is hidden in the NAT plugin .dynsym. Read .symtab. */
static void *
ipsec_hidden_symbol (const char *so_sub, const char *name)
{
  struct ipsec_so_find f = { .sub = so_sub };
  Elf64_Ehdr eh;
  Elf64_Shdr *sh = 0;
  Elf64_Sym *sym = 0;
  u8 *strtab = 0;
  FILE *fp;
  size_t i, nsym = 0;
  void *addr = 0;

  dl_iterate_phdr (ipsec_so_phdr, &f);
  if (!f.path[0] || !(fp = fopen (f.path, "rb")))
    return 0;
  if (fread (&eh, 1, sizeof eh, fp) != sizeof eh ||
      memcmp (eh.e_ident, ELFMAG, SELFMAG))
    goto out;
  sh = malloc (eh.e_shnum * sizeof *sh);
  if (!sh || fseek (fp, eh.e_shoff, SEEK_SET) ||
      fread (sh, sizeof *sh, eh.e_shnum, fp) != eh.e_shnum)
    goto out;
  for (i = 0; i < eh.e_shnum; i++)
    {
      Elf64_Shdr *strsh;
      if (sh[i].sh_type != SHT_SYMTAB)
	continue;
      nsym = sh[i].sh_size / sizeof (Elf64_Sym);
      sym = malloc (sh[i].sh_size);
      strsh = &sh[sh[i].sh_link];
      strtab = malloc (strsh->sh_size);
      if (!sym || !strtab || fseek (fp, sh[i].sh_offset, SEEK_SET) ||
	  fread (sym, 1, sh[i].sh_size, fp) != sh[i].sh_size ||
	  fseek (fp, strsh->sh_offset, SEEK_SET) ||
	  fread (strtab, 1, strsh->sh_size, fp) != strsh->sh_size)
	goto out;
      break;
    }
  if (!sym || !strtab)
    goto out;
  for (i = 0; i < nsym; i++)
    {
      if (strcmp ((const char *) strtab + sym[i].st_name, name))
	continue;
      addr = (void *) (uword) (f.base + sym[i].st_value);
      break;
    }
out:
  free (sh);
  free (sym);
  free (strtab);
  fclose (fp);
  return addr;
}

void *vlib_get_plugin_symbol (const char *plugin_name, const char *symbol_name);

static nat44_ei_main_t *
ipsec_nat44_ei_main (void)
{
  static nat44_ei_main_t *nm;
  static int resolved;
  if (resolved)
    return nm;
  nm = dlsym (RTLD_DEFAULT, "nat44_ei_main");
  if (!nm)
    nm = vlib_get_plugin_symbol ("nat44_ei_plugin.so", "nat44_ei_main");
  if (!nm)
    nm = ipsec_hidden_symbol ("nat44_ei_plugin.so", "nat44_ei_main");
  resolved = 1;
  return nm;
}

static u64
ipsec_nat_key (ip4_address_t addr, u16 port, u32 fib_index, u8 proto)
{
  return (u64) addr.as_u32 << 32 | (u64) port << 16 | (u64) fib_index << 3 |
	 (proto & 7);
}

/* After out2in the quoted dest is the VPN inside address. Linux updates
 * PMTU on the quoted dest, so restore the outside 5-tuple: the one
 * ipsec-pmtu-save-dst saved before out2in (EI or ED), else the EI in2out
 * session's. Without nat44_ei (NAT44-ED) only the saved one is there.
 * Resolved at ICMP time because this plugin loads before nat44_ei. */
static int
ipsec_reverse_nat44_quoted (vlib_buffer_t *b)
{
  ip4_header_t *ip;
  udp_header_t *l4;
  nat44_ei_main_t *nm;
  nat44_ei_main_per_thread_data_t *tnm;
  nat44_ei_session_t *s;
  clib_bihash_kv_8_8_t kv, value;
  u32 fib, thread, session;
  u16 old_port, new_port;
  u32 old_addr, new_addr;
  u8 proto;

  ip = vlib_buffer_get_current (b);
  if (ip->protocol != IP_PROTOCOL_UDP && ip->protocol != IP_PROTOCOL_TCP)
    return 0;
  if (b->current_length < sizeof (*ip) + sizeof (*l4))
    return 0;
  l4 = ip4_next_header (ip);
  if (vnet_buffer2 (b)->unused[3] == IPSEC_PMTU_SAVED_DST)
    {
      old_addr = ip->dst_address.as_u32;
      new_addr = vnet_buffer2 (b)->unused[1];
      old_port = l4->dst_port;
      new_port = (u16) vnet_buffer2 (b)->unused[2];
      if (old_addr != new_addr || old_port != new_port)
	{
	  ip->dst_address.as_u32 = new_addr;
	  l4->dst_port = new_port;
	  ip->checksum = ip_csum_fold (ip_csum_update (
	    ip->checksum, old_addr, new_addr, ip4_header_t, dst_address));
	  if (ip->protocol == IP_PROTOCOL_TCP || l4->checksum)
	    {
	      ip_csum_t sum = l4->checksum;
	      sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t,
				    dst_address);
	      sum = ip_csum_update (sum, old_port, new_port, ip4_header_t,
				    length);
	      l4->checksum = ip_csum_fold (sum);
	      if (ip->protocol == IP_PROTOCOL_UDP && l4->checksum == 0)
		l4->checksum = 0xffff;
	    }
	}
      return 1;
    }
  nm = ipsec_nat44_ei_main ();
  if (!nm)
    {
      pmtu_nat4_nomain++;
      return 0;
    }
  l4 = ip4_next_header (ip);
  proto = ip->protocol == IP_PROTOCOL_TCP ? NAT_PROTOCOL_TCP : NAT_PROTOCOL_UDP;
  for (fib = 0; fib < 8; fib++)
    {
      kv.key = ipsec_nat_key (ip->dst_address, l4->dst_port, fib, proto);
      kv.value = ~0ULL;
      if (clib_bihash_search_inline_2_8_8 (&nm->in2out, &kv, &value))
	continue;
      thread = value.value >> 32;
      session = value.value & (u32) ~0;
      if (thread >= vec_len (nm->per_thread_data))
	continue;
      tnm = nm->per_thread_data + thread;
      if (pool_is_free_index (tnm->sessions, session))
	continue;
      s = pool_elt_at_index (tnm->sessions, session);
      if (s->in2out.addr.as_u32 != ip->dst_address.as_u32 ||
	  s->in2out.port != l4->dst_port)
	continue;
      old_addr = ip->dst_address.as_u32;
      new_addr = s->out2in.addr.as_u32;
      old_port = l4->dst_port;
      new_port = s->out2in.port;
      if (old_addr == new_addr && old_port == new_port)
	return 1;
      ip->dst_address.as_u32 = new_addr;
      l4->dst_port = new_port;
      ip->checksum = ip_csum_fold (ip_csum_update (
	ip->checksum, old_addr, new_addr, ip4_header_t, dst_address));
      if (ip->protocol == IP_PROTOCOL_TCP || l4->checksum)
	{
	  ip_csum_t sum = l4->checksum;
	  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t,
				dst_address);
	  sum = ip_csum_update (sum, old_port, new_port, ip4_header_t, length);
	  l4->checksum = ip_csum_fold (sum);
	  if (ip->protocol == IP_PROTOCOL_UDP && l4->checksum == 0)
	    l4->checksum = 0xffff;
	}
      return 1;
    }
  return 0;
}

#define foreach_ipsec_pmtu_error                                              \
  _ (ALLOW, "encrypt allowed")                                                \
  _ (ICMP4, "inner ICMPv4 fragmentation-needed")                              \
  _ (ICMP6, "inner ICMPv6 packet-too-big")

typedef enum
{
#define _(sym, str) IPSEC_PMTU_ERROR_##sym,
  foreach_ipsec_pmtu_error
#undef _
    IPSEC_PMTU_N_ERROR,
} ipsec_pmtu_error_t;

static char *ipsec_pmtu_error_strings[] = {
#define _(sym, str) str,
  foreach_ipsec_pmtu_error
#undef _
};

static uword
ipsec_pmtu_check (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
                  int is_ip6)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 sa_index = vnet_buffer (b)->ipsec.sad_index;
      ipsec_sa_t *sa = ipsec_sa_get (sa_index);
      ipsec_sa_outb_rt_t *ort = ipsec_sa_get_outb_rt_by_index (sa_index);
      u32 outer_mtu = pmtu_lookup (sa->spi);
      u32 inner, next = 0, error = IPSEC_PMTU_ERROR_ALLOW;
      if (is_ip6)
        {
          ip6_header_t *ip = vlib_buffer_get_current (b);
          inner = sizeof (*ip) + clib_net_to_host_u16 (ip->payload_length);
        }
      else
        {
          ip4_header_t *ip = vlib_buffer_get_current (b);
          inner = clib_net_to_host_u16 (ip->length);
        }
      if (outer_mtu && ort && esp_outer_length (ort, inner) > outer_mtu)
        {
          u32 inner_mtu = inner_mtu_for_outer (ort, outer_mtu);
          vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
          vnet_buffer (b)->ip.save_rewrite_length = 0;
          if (is_ip6)
            {
              icmp6_error_set_vnet_buffer (b, ICMP6_packet_too_big, 0, inner_mtu);
              error = IPSEC_PMTU_ERROR_ICMP6;
            }
          else
            {
              if (ipsec_reverse_nat44_quoted (b))
                pmtu_nat4_hit++;
              else
                pmtu_nat4_miss++;
              icmp4_error_set_vnet_buffer (
                b, ICMP4_destination_unreachable,
                ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
                inner_mtu);
              error = IPSEC_PMTU_ERROR_ICMP4;
            }
          next = 1;
        }
      b->error = node->errors[error];
      vlib_set_next_frame_buffer (vm, node, next, from[i]);
    }
  return frame->n_vectors;
}

static uword
ipsec4_pmtu_check (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ipsec_pmtu_check (vm, node, frame, 0);
}

static uword
ipsec6_pmtu_check (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ipsec_pmtu_check (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (ipsec4_pmtu_node) = {
  .function = ipsec4_pmtu_check,
  .name = "ipsec4-pmtu-check",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = IPSEC_PMTU_N_ERROR,
  .error_strings = ipsec_pmtu_error_strings,
  .n_next_nodes = 2,
  .next_nodes = { [0] = "esp4-encrypt", [1] = "ip4-icmp-error" },
};

VLIB_REGISTER_NODE (ipsec6_pmtu_node) = {
  .function = ipsec6_pmtu_check,
  .name = "ipsec6-pmtu-check",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = IPSEC_PMTU_N_ERROR,
  .error_strings = ipsec_pmtu_error_strings,
  .n_next_nodes = 2,
  .next_nodes = { [0] = "esp6-encrypt", [1] = "ip6-icmp-error" },
};

static void
hijack_next (vlib_main_t *vm, char *source_name, char *dest_name, char *via)
{
  vlib_node_t *source = vlib_get_node_by_name (vm, (u8 *) source_name);
  vlib_node_t *dest = vlib_get_node_by_name (vm, (u8 *) dest_name);
  uword slot;
  if (!source || !dest)
    return;
  slot = vlib_node_get_next (vm, source->index, dest->index);
  if (slot != ~0)
    vlib_node_add_named_next_with_slot (vm, source->index, via, slot);
}

static clib_error_t *
ipsec_pmtu_init (vlib_main_t *vm)
{
  pmtu_by_spi = hash_create (0, sizeof (uword));
  clib_spinlock_init (&pmtu_lock);
  icmp6_register_type (vm, ICMP6_packet_too_big, ipsec_ptb_node.index);
  vnet_feature_register (pmtu_save_dst_update, 0);
  hijack_next (vm, "ipsec4-output-feature", "esp4-encrypt", "ipsec4-pmtu-check");
  hijack_next (vm, "ipsec6-output-feature", "esp6-encrypt", "ipsec6-pmtu-check");
  return 0;
}

VLIB_INIT_FUNCTION (ipsec_pmtu_init) = {
  .runs_after = VLIB_INITS ("icmp6_init", "ipsec_init"),
};

static clib_error_t *
show_ipsec_pmtu (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  uword spi, mtu;
  clib_spinlock_lock (&pmtu_lock);
  hash_foreach (spi, mtu, pmtu_by_spi, ({
                  vlib_cli_output (vm, "spi 0x%x outer-mtu %u", (u32) spi, (u32) mtu);
                }));
  clib_spinlock_unlock (&pmtu_lock);
  vlib_cli_output (vm, "quoted-v4 reverse-NAT hit %llu miss %llu no-main %llu",
		   (unsigned long long) pmtu_nat4_hit,
		   (unsigned long long) pmtu_nat4_miss,
		   (unsigned long long) pmtu_nat4_nomain);
  return 0;
}

VLIB_CLI_COMMAND (show_ipsec_pmtu_command, static) = {
  .path = "show ipsec pmtu",
  .short_help = "show ipsec pmtu",
  .function = show_ipsec_pmtu,
};
