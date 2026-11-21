#!/usr/bin/env python3
"""Compare actual baseline/candidate TX cleanup, including non-power-of-two rings."""
import argparse
from pathlib import Path
import subprocess,tempfile
from integration_r8169_tally_dma import function
p=argparse.ArgumentParser();p.add_argument('--baseline',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);a=p.parse_args()
old=function(a.baseline.read_text(),'rtl8125_tx_clean').replace('rtl8125_tx_clean(', 'clean_old(')
new=function(a.candidate.read_text(),'rtl8125_tx_clean').replace('rtl8125_tx_clean(', 'clean_new(')
prefix=r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define DescOwn 0x80000000U
#define RTE_MIN(a,b) ((a)<(b)?(a):(b))
#define rte_atomic_load_explicit(p,o) (*(p))
#define rte_memory_order_relaxed 0
struct rte_mbuf { unsigned id; };
struct rtl_tx_entry { struct rte_mbuf *mbuf; };
struct rtl_tx_desc { uint32_t opts1; };
struct rtl_hw { uint8_t EnableTxNoClose; uint32_t MaxTxDescPtrMask; };
struct rtl_tx_queue { struct rtl_tx_entry *sw_ring; struct rtl_tx_desc *hw_ring; uint16_t nb_tx_desc,tx_head,tx_free;uint32_t tx_tail,NextHwDesCloPtr,BeginHwDesCloPtr,closed; };
static uint32_t rtl_get_hw_clo_ptr(struct rtl_tx_queue *q) { return q->closed; }
static uint32_t rtl_fast_mod_mask(uint32_t v,uint32_t m) { return v&m; }
static uint32_t rtl_get_opts1(struct rtl_tx_desc *d) { return d->opts1; }
static unsigned frees[1024];
static void rte_pktmbuf_free_seg(struct rte_mbuf *m) { assert(++frees[m->id]==1); }
'''
suffix=r'''
int main(void) {
 unsigned rings[]={8,12,16,1024};
 struct rte_mbuf mb[1024];for(unsigned i=0;i<1024;i++)mb[i].id=i;
 for(unsigned ri=0;ri<4;ri++)for(unsigned mode=0;mode<2;mode++) {
  unsigned n=rings[ri];
  for(unsigned head=0;head<n;head++)for(unsigned k=0;k<n;k+=(n>16?31:1)) {
   struct rtl_tx_entry sa[1024],sb[1024];struct rtl_tx_desc da[1024],db[1024];
   for(unsigned i=0;i<n;i++){sa[i].mbuf=sb[i].mbuf=i%3?&mb[i]:NULL;da[i].opts1=DescOwn;}
   for(unsigned i=0;i<k;i++)da[(head+i)%n].opts1=0;
   memcpy(db,da,sizeof da);
   struct rtl_hw hw={mode,0xffff};
   struct rtl_tx_queue x={sa,da,n,head,0,head+k,0,0,k},y=x;y.sw_ring=sb;y.hw_ring=db;
   memset(frees,0,sizeof frees);clean_old(&hw,&x);unsigned expected[1024];memcpy(expected,frees,sizeof frees);
   memset(frees,0,sizeof frees);clean_new(&hw,&y);
   assert(x.tx_head==(head+k)%n && x.tx_free==k);
   assert(x.tx_head==y.tx_head && x.tx_free==y.tx_free && x.BeginHwDesCloPtr==y.BeginHwDesCloPtr);
   assert(!memcmp(expected,frees,sizeof frees));
   for(unsigned i=0;i<n;i++)assert(sa[i].mbuf==sb[i].mbuf);
  }
 }
 puts("PASS: real TX cleanup equivalence, 8/12/16/1024 rings, wrap, OWN stop, no-close, null mbufs");
}
'''
with tempfile.TemporaryDirectory() as d:
 s=Path(d)/'test.c';e=Path(d)/'test';s.write_text(prefix+old+new+suffix)
 subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(s),'-o',str(e)],check=True);subprocess.run([str(e)],check=True)
