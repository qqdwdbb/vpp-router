/* Delete only UDP/500,4500 entries whose original destination is a supplied
 * local WAN address. No tuples, payloads, or credentials are printed. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static struct nfct_handle *deleter;
static int address_count, deleted, matched, dry_run;
static char **addresses;
static int
entry(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
  (void)type; (void)data;
  if (!nfct_attr_is_set(ct, ATTR_L4PROTO) || nfct_get_attr_u8(ct, ATTR_L4PROTO)!=IPPROTO_UDP ||
      !nfct_attr_is_set(ct, ATTR_PORT_DST)) return NFCT_CB_CONTINUE;
  unsigned port=ntohs(nfct_get_attr_u16(ct,ATTR_PORT_DST));
  if (port!=500 && port!=4500) return NFCT_CB_CONTINUE;
  unsigned family=nfct_get_attr_u8(ct,ATTR_L3PROTO);
  enum nf_conntrack_attr attr=family==AF_INET?ATTR_IPV4_DST:ATTR_IPV6_DST;
  if ((family!=AF_INET && family!=AF_INET6) || !nfct_attr_is_set(ct,attr)) return NFCT_CB_CONTINUE;
  const void *dst=nfct_get_attr(ct,attr);
  for (int i=0;i<address_count;i++) {
    unsigned char expected[16];
    if (inet_pton(family,addresses[i],expected)!=1 || memcmp(dst,expected,family==AF_INET?4:16)) continue;
    matched++;
    if (!dry_run && nfct_query(deleter,NFCT_Q_DESTROY,ct)==0) deleted++;
    break;
  }
  return NFCT_CB_CONTINUE;
}
int main(int argc,char **argv)
{
  if (argc<2) return 2;
  dry_run=!strcmp(argv[1],"--check");
  address_count=argc-1-dry_run; addresses=argv+1+dry_run;
  if (!address_count) return 2;
  struct nfct_handle *reader=nfct_open(CONNTRACK,0);
  deleter=nfct_open(CONNTRACK,0);
  if (!reader || !deleter) return 3;
  nfct_callback_register(reader,NFCT_T_ALL,entry,NULL);
  unsigned char family=AF_UNSPEC;
  int result=nfct_query(reader,NFCT_Q_DUMP,&family);
  nfct_close(reader); nfct_close(deleter);
  if (result<0) return 4;
  printf("{\"matched\":%d,\"deleted\":%d,\"dry_run\":%s}\n",matched,deleted,dry_run?"true":"false");
  return 0;
}
