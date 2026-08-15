/*
 * gate_decision.h - pure SA routing predicate (offload vs fallback)
 *
 * Freestanding: no VPP or DPDK includes, so the routing decision is unit-testable
 * on the host with plain cc (see test_gate.c). The plugin's
 * dpaa2_ipsec_offload_gate() reduces an ipsec_sa_t + device state to the plain
 * inputs below and calls dpaa2_ipsec_gate_decide(); the CLI reason table is built
 * from the same X-macro, so enum and strings cannot drift.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __included_dpaa2_ipsec_gate_decision_h__
#define __included_dpaa2_ipsec_gate_decision_h__

/* Why an SA is on the fallback path -- surfaced by "show dpaa2 ipsec" to prove
 * unsupported configs fall back rather than run with weaker security. NONE means
 * the SA is offloaded. SESSION_CREATE_FAILED is set dynamically by session create,
 * not by the static gate below. */
#define foreach_dpaa2_ipsec_fallback_reason                                   \
  _ (NONE, "offloaded")                                                       \
  _ (DISABLED, "SEC ESP offload disabled by configuration")                   \
  _ (NO_SECURITY_DEV, "no SECURITY-capable cryptodev for this SA")            \
  _ (UNSUPPORTED_CONFIG, "SA config not accepted by rte_security")            \
  _ (WINDOW_TOO_LARGE, "anti-replay window exceeds device maximum")           \
  _ (SESSION_CREATE_FAILED, "rte_security session create failed")

typedef enum
{
#define _(f, s) DPAA2_IPSEC_FALLBACK_##f,
  foreach_dpaa2_ipsec_fallback_reason
#undef _
    DPAA2_IPSEC_FALLBACK_N_REASON,
} dpaa2_ipsec_fallback_reason_t;

/* Device anti-replay window tops out here; larger requested windows run on
 * fallback with the full window rather than being silently truncated. */
#define DPAA2_IPSEC_MAX_REPLAY_WINDOW 1024

/*
 * Pure routing predicate. Returns 1 = offload, 0 = fallback (with *reason set).
 * Takes NO packet size or rate input by construction: routing cannot be steered
 * by traffic -- the security invariant this predicate encodes. If a size
 * argument is ever added here, the T1 tripwire in the unit test must still hold.
 */
static inline int
dpaa2_ipsec_gate_decide (int offload_disabled, int have_security_dev, int is_esp,
			 int is_tunnel, int alg_offloadable,
			 unsigned replay_window,
			 dpaa2_ipsec_fallback_reason_t *reason)
{
  *reason = DPAA2_IPSEC_FALLBACK_NONE;

  if (offload_disabled)
    {
      *reason = DPAA2_IPSEC_FALLBACK_DISABLED;
      return 0;
    }
  if (!have_security_dev)
    {
      *reason = DPAA2_IPSEC_FALLBACK_NO_SECURITY_DEV;
      return 0;
    }
  /* ESP tunnel only. */
  if (!is_esp || !is_tunnel)
    {
      *reason = DPAA2_IPSEC_FALLBACK_UNSUPPORTED_CONFIG;
      return 0;
    }
  /* Algorithm must map to a session we can build. */
  if (!alg_offloadable)
    {
      *reason = DPAA2_IPSEC_FALLBACK_UNSUPPORTED_CONFIG;
      return 0;
    }
  if (replay_window > DPAA2_IPSEC_MAX_REPLAY_WINDOW)
    {
      *reason = DPAA2_IPSEC_FALLBACK_WINDOW_TOO_LARGE;
      return 0;
    }

  return 1;
}

#endif /* __included_dpaa2_ipsec_gate_decision_h__ */
