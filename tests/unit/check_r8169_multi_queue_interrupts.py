"""Compile the actual PMD interrupt routines with mocked MMIO/eventfds.

Usage: python3 tests/unit/check_r8169_multi_queue_interrupts.py /path/to/patched/r8169_ethdev.c
This checks queue routing and lifecycle; it does not emulate PCI IRQ delivery.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

s = Path(sys.argv[1]).read_text()
a=s.index('/* RX causes'); b=s.index('\nstatic int\n',s.index('rtl_rx_queue_intr_disable(struct rte_eth_dev *dev, uint16_t queue_id)\n{',a))
functions=s[a:b]
a=s.index('static void\nrtl_dev_interrupt_handler(void *param)\n{'); b=s.index('\n}',a)+2
handler=s[a:b]
stub=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
typedef uint32_t u32;
struct rtl_hw { unsigned regs[4096]; };
struct rtl_adapter { struct rtl_hw hw; int intr_lock; unsigned rxq_intr_count; bool rxq_intr_armed[4]; int rxq_intr_efd[4]; };
struct rte_intr_handle { int fds[4], vec[4], count; };
struct rte_eth_dev { struct rtl_adapter *p; struct rte_intr_handle *intr_handle; struct {struct {struct {int rxq;} intr_conf;} dev_conf; unsigned nb_rx_queues;} *data; };
#define RTL_DEV_PRIVATE(d) ((d)->p)
#define container_of(p,t,m) ((t *)(p))
#define RxOK 1
#define RxDescUnavail 16
#define LinkChg 32
#define BIT_0 1
#define BIT_1 2
#define IMR0_8125 0x38
#define ISR0_8125 0x3c
#define IMR1_8125 0x800
#define ISR1_8125 0x802
#define IntrMask 0x38
#define IntrStatus 0x3c
#define RTL_W32(h,r,v) ((h)->regs[r]=(v))
#define RTL_W16 RTL_W32
#define RTL_R32(h,r) ((h)->regs[r])
#define RTL_R16 RTL_R32
#define PMD_INIT_FUNC_TRACE()
#define PMD_INIT_LOG(...)
#define PMD_DRV_LOG(...)
#define RTE_INTR_VEC_RXTX_OFFSET 1
#define EFD_NONBLOCK 1
#define EFD_CLOEXEC 2
static int next_fd, closed, signals[32], fail_at=-1;
static int eventfd(int n,int f) { (void)n;(void)f; if(next_fd==fail_at) return -1;return next_fd++; }
static int close(int fd){assert(fd>=0);closed++;return 0;}
static int write(int fd,const void *p,unsigned n){(void)p;signals[fd]++;return n;}
static bool rtl_is_8125(struct rtl_hw *h){(void)h;return true;}
static void rte_spinlock_lock(int *p){(void)p;}
static void rte_spinlock_unlock(int *p){(void)p;}
static int rte_intr_vec_list_alloc(struct rte_intr_handle *h,const char *n,int c){(void)h;(void)n;(void)c;return 0;}
static void rte_intr_vec_list_free(struct rte_intr_handle *h){(void)h;}
static int rte_intr_vec_list_index_set(struct rte_intr_handle *h,int q,int v){h->vec[q]=v;return 0;}
static int rte_intr_efds_index_set(struct rte_intr_handle *h,int q,int v){h->fds[q]=v;return 0;}
static int rte_intr_nb_efd_set(struct rte_intr_handle *h,int n){h->count=n;return 0;}
static void rtl_disable_intr(struct rtl_hw *h){h->regs[IMR0_8125]=0;h->regs[ISR0_8125]=0;}
static void rtl_dev_link_update(struct rte_eth_dev *d,int n){(void)d;(void)n;}
static void rte_intr_ack(struct rte_intr_handle *h){(void)h;}
'''
test=r'''
int main(void) {
 struct rtl_adapter a={0}; struct rte_intr_handle h={0};
 struct rte_eth_dev d={.p=&a,.intr_handle=&h}; typeof(*d.data) data={0};d.data=&data;
 data.dev_conf.intr_conf.rxq=1;data.nb_rx_queues=4;
 rtl_rxq_intr_setup(&d);assert(a.rxq_intr_count==4 && h.count==4);
 for(int q=0;q<4;q++){assert(h.vec[q]==q+1);assert(h.fds[q]==q);}
 assert(rtl_rx_queue_intr_enable(&d,1)==0);assert(a.hw.regs[IMR1_8125]==3);
 assert(rtl_rx_queue_intr_enable(&d,2)==0);assert(a.hw.regs[IMR1_8125+4]==3);
 assert(rtl_rx_queue_intr_enable(&d,4)==-ENOTSUP);
 rtl_dev_interrupt_handler(&d);
 assert(signals[1]==1 && signals[2]==1 && signals[0]==0 && signals[3]==0);
 assert(a.hw.regs[IMR1_8125]==0 && a.hw.regs[IMR1_8125+4]==0);
 rtl_dev_interrupt_handler(&d);assert(signals[1]==1);
 assert(rtl_rx_queue_intr_enable(&d,3)==0);
 assert(rtl_rx_queue_intr_disable(&d,3)==0);
 rtl_dev_interrupt_handler(&d);assert(signals[3]==0);
 rtl_rxq_intr_teardown(&d);assert(closed==4 && h.count==0);
 next_fd=0;closed=0;fail_at=2;
 rtl_rxq_intr_setup(&d);assert(a.rxq_intr_count==0 && h.count==0 && closed==2);
 rtl_rxq_intr_teardown(&d);assert(closed==2);
 fail_at=-1;
 for(unsigned count=1;count<=2;count++) {
  next_fd=0;closed=0;memset(signals,0,sizeof(signals));
  data.nb_rx_queues=count;rtl_rxq_intr_setup(&d);
  assert(a.rxq_intr_count==count && h.count==(int)count);
  for(unsigned q=0;q<count;q++) assert(rtl_rx_queue_intr_enable(&d,q)==0);
  rtl_dev_interrupt_handler(&d);
  for(unsigned q=0;q<count;q++) assert(signals[q]==1);
  rtl_rxq_intr_teardown(&d);assert(closed==(int)count);
 }
 return 0;
}
'''
with tempfile.TemporaryDirectory() as directory:
    source = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    source.write_text(stub + functions + handler + test)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('queue setup, wakeup, masking, teardown and partial failure: passed')
