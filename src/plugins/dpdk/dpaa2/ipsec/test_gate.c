/*
 * test_gate.c - host unit test for the pure SA routing predicate.
 *
 * Board-free: the decision core has no VPP/DPDK deps, so this compiles and runs
 * with plain cc. Covers: T1 (no size input -- routing cannot be steered by
 * traffic), T2 (disable overrides capability), T4 (reason-string table
 * parity), plus the window boundary and device-present gates.
 *
 *   cc -Wall -Werror test_gate.c && ./a.out
 *
 * Also wired as add_vpp_test(test_dpaa2_ipsec_gate) so the VPP build runs it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdio.h>
#include "gate_decision.h"

/* Mirror of the CLI reason table, built from the same X-macro. If the enum and
 * this table ever drift, the T4 count assert below fails. */
static const char *reason_strings[] = {
#define _(f, s) [DPAA2_IPSEC_FALLBACK_##f] = s,
  foreach_dpaa2_ipsec_fallback_reason
#undef _
};

/* Convenience: an offloadable GCM-tunnel-like config (esp+tunnel+alg, small win). */
#define OFFLOADABLE 0 /* disabled */, 1 /* have_dev */, 1 /* esp */, 1 /* tunnel */, \
		    1 /* alg */, 64 /* window */
/* A transport SA (unsupported: not IS_TUNNEL). */
#define TRANSPORT   0, 1, 1 /* esp */, 0 /* not tunnel */, 1, 64

static int
decide (int dis, int dev, int esp, int tun, int alg, unsigned win,
	dpaa2_ipsec_fallback_reason_t *r)
{
  return dpaa2_ipsec_gate_decide (dis, dev, esp, tun, alg, win, r);
}

/* T4 - reason-string table parity: one string per enum value, none empty. */
static void
test_reason_table_parity (void)
{
  assert (sizeof (reason_strings) / sizeof (reason_strings[0]) ==
	  DPAA2_IPSEC_FALLBACK_N_REASON);
  for (int i = 0; i < DPAA2_IPSEC_FALLBACK_N_REASON; i++)
    {
      assert (reason_strings[i] != 0);
      assert (reason_strings[i][0] != '\0');
    }
  printf ("  T4 reason-table parity: %d reasons, all named\n",
	  DPAA2_IPSEC_FALLBACK_N_REASON);
}

/* T2 - the disable lever overrides capability, and is reversible in-process. */
static void
test_disable_overrides_capability (void)
{
  dpaa2_ipsec_fallback_reason_t r;

  /* disabled=1: both an offloadable and an unsupported SA report DISABLED. */
  assert (decide (1, 1, 1, 1, 1, 64, &r) == 0 && r == DPAA2_IPSEC_FALLBACK_DISABLED);
  assert (decide (1, 1, 1, 0, 1, 64, &r) == 0 && r == DPAA2_IPSEC_FALLBACK_DISABLED);

  /* disabled=0: capability decides again -- offloadable offloads, transport not. */
  assert (decide (OFFLOADABLE, &r) == 1 && r == DPAA2_IPSEC_FALLBACK_NONE);
  assert (decide (TRANSPORT, &r) == 0 &&
	  r == DPAA2_IPSEC_FALLBACK_UNSUPPORTED_CONFIG);
  printf ("  T2 disable overrides capability, reversible: ok\n");
}

/* T1 - routing takes no size/rate input: the same config yields the same verdict
 * regardless of any notional per-packet value. The predicate has no size param,
 * so this is a tripwire against a future size argument changing the verdict. */
static void
test_no_size_input (void)
{
  dpaa2_ipsec_fallback_reason_t r0, r;
  int v0 = decide (OFFLOADABLE, &r0);
  for (unsigned notional_size = 0; notional_size <= 9000; notional_size += 37)
    {
      int v = decide (OFFLOADABLE, &r);
      assert (v == v0 && r == r0); /* size cannot move routing */
    }
  printf ("  T1 no size input (verdict stable across sizes): ok\n");
}

/* Classification + window boundary + device-present gates. */
static void
test_classification (void)
{
  dpaa2_ipsec_fallback_reason_t r;

  /* No SECURITY device: even an offloadable SA falls back with NO_SECURITY_DEV. */
  assert (decide (0, 0, 1, 1, 1, 64, &r) == 0 &&
	  r == DPAA2_IPSEC_FALLBACK_NO_SECURITY_DEV);

  /* Unsupported algorithm -> UNSUPPORTED_CONFIG. */
  assert (decide (0, 1, 1, 1, 0 /* alg */, 64, &r) == 0 &&
	  r == DPAA2_IPSEC_FALLBACK_UNSUPPORTED_CONFIG);

  /* Anti-replay window boundary: max is offloaded, max+1 falls back. */
  assert (decide (0, 1, 1, 1, 1, DPAA2_IPSEC_MAX_REPLAY_WINDOW, &r) == 1 &&
	  r == DPAA2_IPSEC_FALLBACK_NONE);
  assert (decide (0, 1, 1, 1, 1, DPAA2_IPSEC_MAX_REPLAY_WINDOW + 1, &r) == 0 &&
	  r == DPAA2_IPSEC_FALLBACK_WINDOW_TOO_LARGE);
  printf ("  classification + window boundary + device gate: ok\n");
}

int
main (void)
{
  printf ("test_dpaa2_ipsec_gate:\n");
  test_reason_table_parity ();
  test_disable_overrides_capability ();
  test_no_size_input ();
  test_classification ();
  printf ("PASS\n");
  return 0;
}
