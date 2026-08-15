/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Carlos Aguado.
 *
 * DPAA2 IPsec full-ESP protocol offload: observability.
 *
 * `show dpaa2 ipsec` is the summary: which devices can offload, how workers
 * map to queue-pairs, and plugin-wide packet totals (offloaded vs fallback vs
 * dropped). `show dpaa2 ipsec verbose` adds a per-SA line -- offload vs
 * fallback with the reason, the pinned worker, and packets/bytes. The per-SA
 * reason is the point: it proves an unsupported config was left on the software
 * path on purpose (full window, correct semantics), never silently downgraded.
 *
 * The per-SA packets/bytes come from the same core counter the built-in ESP
 * nodes feed; the offload nodes now feed it too (see node.c), so an
 * offloaded SA is counted like any other -- in `show ipsec sa` as well as here.
 */

#include <vlib/vlib.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_funcs.h>

#include "ipsec.h"

static char *dpaa2_ipsec_fallback_reason_strings[] = {
#define _(f, s) s,
  foreach_dpaa2_ipsec_fallback_reason
#undef _
};

/* The cached decision for an offloaded SA is authoritative; for any SA without
 * an offload session (gate-rejected SAs never reach the provider, so they have
 * no cache entry) recompute the reason from the gate -- read-only. */
static void
dpaa2_ipsec_sa_decision (u32 sa_index, ipsec_sa_t *sa, int *offloaded,
			 u8 *reason)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;

  if (sa_index < vec_len (dm->sa_route) &&
      dm->sa_route[sa_index].decision == DPAA2_IPSEC_ROUTE_OFFLOAD)
    {
      *offloaded = 1;
      *reason = DPAA2_IPSEC_FALLBACK_NONE;
      return;
    }

  dpaa2_ipsec_fallback_reason_t r;
  *offloaded = dpaa2_ipsec_offload_gate (sa, &r);
  *reason = *offloaded ? DPAA2_IPSEC_FALLBACK_NONE : (u8) r;
}

static clib_error_t *
dpaa2_ipsec_show_offload (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  ipsec_main_t *im = &ipsec_main;
  dpaa2_ipsec_dev_t *dev;
  dpaa2_ipsec_stats_t st;
  int verbose = 0;
  u32 sai;

  if (unformat (input, "verbose") || unformat (input, "detail"))
    verbose = 1;

  vlib_cli_output (vm, "SEC protocol offload: %s",
		   dm->have_security_dev ? "SECURITY-capable device present"
					 : "no SECURITY-capable device");
  vlib_cli_output (vm, "  offload: %s",
		   dm->offload_disabled ? "disabled by configuration"
					: "enabled (capability-only)");

  dpaa2_ipsec_get_stats (&st);
  vlib_cli_output (vm, "  traffic: %llu received, %llu offloaded, %llu handed "
		       "off, %llu fallback (+%llu no-op), %llu enqueue-drop",
		   st.rx, st.offloaded, st.handoff, st.fallback, st.cop_fallback,
		   st.enq_drop);
  vlib_cli_output (vm, "  completions: %llu dequeued, %llu auth-fail, %llu "
		       "other-fail, %llu straggler",
		   st.dequeued, st.auth_fail, st.status_fail, st.straggler);
  vlib_cli_output (vm, "  pmd qp: %llu enqueued, %llu enqueue-err, %llu "
		       "dequeued, %llu dequeue-err",
		   st.pmd_enq, st.pmd_enq_err, st.pmd_deq, st.pmd_deq_err);
  vlib_cli_output (vm, "  teardowns: %llu deferred, %llu drained "
		       "(deferred = freed with ops still in flight)",
		   dm->sessions_deferred, dm->sessions_drained);

  if (!dm->scanned)
    {
      vlib_cli_output (vm, "  device scan pending (no SA added yet)");
      return 0;
    }

  vlib_cli_output (vm, "  devices:");
  vec_foreach (dev, dm->devs)
    {
      if (dev->security && dev->base_qp != DPAA2_IPSEC_INVALID_U16 &&
	  dev->n_offload_qp)
	vlib_cli_output (vm, "    dev %u (%s): %u qp, SECURITY, offload qp %u..%u",
			 dev->dev_id, dev->name, dev->max_qp, dev->base_qp,
			 dev->base_qp + dev->n_offload_qp - 1);
      else
	vlib_cli_output (vm, "    dev %u (%s): %u qp, %s", dev->dev_id,
			 dev->name, dev->max_qp,
			 dev->security ? "SECURITY, no queue-pairs for offload"
				       : "no SECURITY");
    }

  vlib_cli_output (vm, "  worker placement:");
  for (u32 t = 0; t < vec_len (dm->workers); t++)
    {
      dpaa2_ipsec_worker_t *w = vec_elt_at_index (dm->workers, t);
      if (w->dev_id == DPAA2_IPSEC_INVALID_U16)
	vlib_cli_output (vm, "    thread %u -> no queue-pair (SAs fall back)", t);
      else
	vlib_cli_output (vm, "    thread %u -> dev %u qp %u, %u in flight", t,
			 w->dev_id, w->qp_id, w->inflight);
    }

  /* The per-SA list is the detailed view only; the summary stops here. */
  if (!verbose)
    return 0;

  vlib_cli_output (vm, "  SAs:");
  pool_foreach_index (sai, im->sa_pool)
    {
      ipsec_sa_t *sa = ipsec_sa_get (sai);
      int is_in = ipsec_sa_is_set_IS_INBOUND (sa);
      int offloaded;
      u8 reason;
      vlib_counter_t c;

      dpaa2_ipsec_sa_decision (sai, sa, &offloaded, &reason);
      vlib_get_combined_counter (&ipsec_sa_counters, sai, &c);

      if (offloaded)
	{
	  clib_thread_index_t ti =
	    is_in ? ipsec_sa_get_inb_rt_by_index (sai)->thread_index
		  : ipsec_sa_get_outb_rt_by_index (sai)->thread_index;
	  if (ti == (clib_thread_index_t) ~0)
	    vlib_cli_output (
	      vm,
	      "    sa %u spi 0x%08x %s: offload (worker unassigned), %llu pkts "
	      "%llu bytes",
	      sai, sa->spi, is_in ? "in " : "out", c.packets, c.bytes);
	  else
	    vlib_cli_output (
	      vm, "    sa %u spi 0x%08x %s: offload (thread %u), %llu pkts %llu bytes",
	      sai, sa->spi, is_in ? "in " : "out", ti, c.packets, c.bytes);
	}
      else
	vlib_cli_output (
	  vm, "    sa %u spi 0x%08x %s: fallback (%s), %llu pkts %llu bytes", sai,
	  sa->spi, is_in ? "in " : "out",
	  dpaa2_ipsec_fallback_reason_strings[reason], c.packets, c.bytes);
    }

  return 0;
}

/* Vendor operator surface lives under the vendor token: `show ipsec ...` is
 * core namespace, not a plugin's to claim. */
VLIB_CLI_COMMAND (dpaa2_ipsec_show_offload_cmd, static) = {
  .path = "show dpaa2 ipsec",
  .short_help = "show dpaa2 ipsec [verbose]",
  .function = dpaa2_ipsec_show_offload,
};
