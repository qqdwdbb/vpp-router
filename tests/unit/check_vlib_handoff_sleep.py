"""Check file-poll sleep decisions using the actual VPP function prefix.

Usage: python3 tests/unit/check_vlib_handoff_sleep.py /path/to/src/vlib/file.c
Only epoll/callback dispatch is stubbed; pending-work and idle decisions come
from the supplied source. The old implementation fails the pending-frame case.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
start = source.index('vlib_file_poll (vlib_main_t *vm)')
end = source.index('\nskip_loops:', start)
prefix = source[start:end]
stubs = r'''
#include <assert.h>
#include <stdint.h>
#include <time.h>
typedef unsigned u32;
struct epoll_event { int unused; };
typedef struct { int pending_frames; int input_node_counts_by_state[2];
                 void *node_interrupts[2]; } vlib_node_main_t;
typedef struct { vlib_node_main_t node_main; unsigned thread_index;
                 int api_queue_nonempty, thread_sleeps, file_poll_skip_loops;
                 int vectors; double time_last_barrier_release; } vlib_main_t;
typedef struct { unsigned poll_sleep_usec; } unix_main_t;
unix_main_t unix_main;
static int barrier;
static struct { int *wait_at_barrier; } worker = { &barrier };
#define vlib_worker_threads (&worker)
#define PREDICT_FALSE(x) (x)
#define vec_len(x) (x)
#define VLIB_NODE_STATE_POLLING 1
#define VLIB_N_NODE_TYPE 2
#define TW_SLOTS_PER_RING 1024
#define VLIB_TW_TICKS_PER_SECOND 1000
#define clib_min(a,b) ((a)<(b)?(a):(b))
static vlib_main_t main_vm;
static int timeout_observed;
static int inject_work_at_sleep;
/* Deterministically publish work between the first busy check and the
 * consumer's sleep announcement. Only this test replaces the atomic store. */
#define __atomic_store_n(p,v,order) do { *(p) = (v); \
  if (inject_work_at_sleep && (v) == 1) vm->check_frame_queues = 1; } while (0)
static int vlib_last_vectors_per_main_loop(vlib_main_t *vm) { return vm->vectors; }
static vlib_main_t *vlib_get_first_main(void) { return &main_vm; }
static double vlib_time_now(vlib_main_t *vm) { (void)vm; return 100; }
static int clib_interrupt_is_any_pending(void *p) { return p != 0; }
static u32 vlib_tw_timer_first_expires_in_ticks(vlib_main_t *vm) {
  (void)vm; return TW_SLOTS_PER_RING;
}
'''
# check_frame_queues is deliberately a separate published flag, as in VPP.
stubs = stubs.replace('int vectors;', 'unsigned char check_frame_queues; int vectors;')
body = 'static void\n' + prefix + r'''
skip_loops:
  vm->file_poll_skip_loops = 1024;
epoll:
  timeout_observed = timeout_ms;
  vm->thread_sleeps = 0;
}
int main(void) {
  vlib_main_t vm = { .thread_index = 1 };
  vlib_file_poll(&vm);
  assert(timeout_observed == 10); /* idle workers must still sleep */
  vm.node_main.pending_frames = 1;
  vlib_file_poll(&vm);
  assert(timeout_observed == 0); /* dequeued frame, zero previous-loop vectors */
  vm.node_main.pending_frames = 0;
  vm.check_frame_queues = 1;
  vlib_file_poll(&vm);
  assert(timeout_observed == 0); /* producer published work since dequeue */
  vm.check_frame_queues = 0;
  vm.vectors = 2;
  vlib_file_poll(&vm);
  assert(timeout_observed == 0);
  vm.vectors = 0;
  vm.check_frame_queues = 0;
  inject_work_at_sleep = 1;
  vlib_file_poll(&vm);
  assert(timeout_observed == 0); /* publish during the sleep transition */
  return 0;
}
'''
with tempfile.TemporaryDirectory() as directory:
    c = Path(directory) / 'check.c'
    binary = Path(directory) / 'check'
    c.write_text(stubs + body)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-variable', str(c), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('pending handoff frames stay awake; idle workers still sleep: passed')
