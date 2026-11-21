/* SPDX-License-Identifier: Apache-2.0
 * Included by nat44_ei.c. Run expiry on the session's owning worker.
 */

typedef struct
{
  u32 cursor;
} nat44_ei_cleaner_runtime_t;

static char *nat44_ei_cleaner_errors[] = {
  "session slots scanned",
  "expired sessions reclaimed",
};

static uword
nat44_ei_cleaner_worker (vlib_main_t *vm, vlib_node_runtime_t *rt,
                       vlib_frame_t *frame)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  u32 ti = vm->thread_index;
  nat44_ei_cleaner_runtime_t *cr = (void *) rt->runtime_data;
  u32 scanned = 0, expired = 0;

  if (!nm->enabled || ti >= vec_len (nm->per_thread_data))
    return 0;

  nat44_ei_main_per_thread_data_t *tnm = &nm->per_thread_data[ti];
  u32 length = vec_len (tnm->sessions);
  u32 budget = clib_min (length, 4096);
  f64 now = vlib_time_now (vm);

  while (scanned < budget)
    {
      if (cr->cursor >= length)
        cr->cursor = 0;
      u32 index = cr->cursor++;
      scanned++;
      if (pool_is_free_index (tnm->sessions, index))
        continue;

      nat44_ei_session_t *s = pool_elt_at_index (tnm->sessions, index);
      f64 timeout = nat_session_get_timeout (&nm->timeouts, s->nat_proto,
                                            s->state);
      if (now < s->last_heard + timeout)
        continue;

      /* Also releases both lookup keys, ports, user lists and HA state.
       * Static mapping configuration is separate from its session state.
       */
      nat44_ei_free_session_data_v2 (nm, s, ti, 0);
      nat44_ei_delete_session (nm, s, ti);
      expired++;
    }

  vlib_node_increment_counter (vm, rt->node_index, 0, scanned);
  vlib_node_increment_counter (vm, rt->node_index, 1, expired);
  return 0;
}

VLIB_REGISTER_NODE (nat44_ei_cleaner_worker_node) = {
  .function = nat44_ei_cleaner_worker,
  .name = "nat44-ei-expire-worker",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .runtime_data_bytes = sizeof (nat44_ei_cleaner_runtime_t),
  .n_errors = ARRAY_LEN (nat44_ei_cleaner_errors),
  .error_strings = nat44_ei_cleaner_errors,
};

static uword
nat44_ei_cleaner_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
                        vlib_frame_t *frame)
{
  uword *event_data = 0;
  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);
      if (!nat44_ei_main.enabled)
        continue;
      for (u32 ti = 0; ti < vlib_get_n_threads (); ti++)
        vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
                                        nat44_ei_cleaner_worker_node.index);
    }
  return 0;
}

VLIB_REGISTER_NODE (nat44_ei_cleaner_process_node) = {
  .function = nat44_ei_cleaner_process,
  .name = "nat44-ei-expire-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};
