/* SPDX-License-Identifier: Apache-2.0
 *
 * VPP 26.06 compatibility (vpp-router): the DHCPv6 runtime snapshot types
 * the detail CLI and API print come from FD.io master commit 0a143dac6
 * ("dhcp: export DHCPv6 runtime state for PPPoE observability"), which
 * VPP 26.06 does not have.  The layouts below are copied from that commit.
 * VPP 26.06's dhcp_plugin.so exports none of the *_get_runtime getters, so
 * vlib_get_plugin_symbol () returns 0 and the DHCPv6 lines read
 * "<unavailable>"; nothing here is ever filled in by the dhcp plugin.
 */
#ifndef included_pppoeclient_dhcp6_runtime_compat_h
#define included_pppoeclient_dhcp6_runtime_compat_h

#include <vnet/ip/ip6_packet.h>

#define DHCP6_MAX_LEARNED_DNS_SERVERS 2

typedef struct
{
  u8 enabled;
  u8 rebinding;
  u32 server_index;
  u32 T1;
  u32 T2;
  u32 address_count;
  u32 t1_remaining;
  u32 t2_remaining;
  u8 first_address_present;
  ip6_address_t first_address;
  u32 first_address_preferred_lt;
  u32 first_address_valid_lt;
  u8 dns_server_count;
  ip6_address_t dns_servers[DHCP6_MAX_LEARNED_DNS_SERVERS];
} dhcp6_ia_na_client_runtime_t;

typedef struct
{
  u8 enabled;
  u8 rebinding;
  u32 server_index;
  u32 T1;
  u32 T2;
  u32 prefix_count;
  u32 t1_remaining;
  u32 t2_remaining;
  char prefix_group[65];
} dhcp6_pd_client_runtime_t;

typedef struct
{
  u8 present;
  ip6_address_t prefix;
  u8 prefix_length;
  u32 preferred_lt;
  u32 valid_lt;
  u32 valid_remaining;
} dhcp6_pd_active_prefix_runtime_t;

typedef struct
{
  u8 present;
  u32 consumer_count;
  u32 sw_if_index;
  ip6_address_t address;
  u8 prefix_length;
} dhcp6_pd_consumer_runtime_t;

#endif /* included_pppoeclient_dhcp6_runtime_compat_h */
