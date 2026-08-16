/*
 * test_dev_name_match.c - host unit test for the bus-qualified device key/match.
 *
 * Board-free: dev_name_match.h has no VPP/DPDK deps, so this compiles and runs
 * with plain cc. Covers: exact match, cross-bus and cross-leaf non-match,
 * malformed keys (missing ':' and bus-prefix-only), a lookup miss, the overflow
 * guard on a too-small buffer, and a build/match round-trip.
 *
 *   cc -Wall -Werror test_dev_name_match.c && ./a.out
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "dev_name_match.h"

/* Exact match: the key builds as "<bus>:<name>" and matches its own (bus,name). */
static void
test_exact_match (void)
{
  char buf[32];

  assert (dpdk_dev_name_key ("fslmc", "dpni.7", buf, sizeof buf) == true);
  assert (strcmp (buf, "fslmc:dpni.7") == 0);
  assert (dpdk_dev_name_match ("fslmc:dpni.7", "fslmc", "dpni.7") == true);
  printf ("  exact match builds and matches: ok\n");
}

/* Cross-bus and cross-leaf: same key must not match a different bus or leaf. */
static void
test_cross_bus_non_match (void)
{
  /* same leaf, different bus */
  assert (dpdk_dev_name_match ("fslmc:dpni.7", "pci", "dpni.7") == false);
  /* same bus, different leaf */
  assert (dpdk_dev_name_match ("fslmc:dpni.7", "fslmc", "dpni.9") == false);
  printf ("  cross-bus / cross-leaf non-match: ok\n");
}

/* Malformed keys: no ':' separator, and a bare bus prefix with no leaf. */
static void
test_malformed_key (void)
{
  assert (dpdk_dev_name_match ("fslmcdpni.7", "fslmc", "dpni.7") == false);
  assert (dpdk_dev_name_match ("fslmc", "fslmc", "dpni.7") == false);
  printf ("  malformed key (no ':' / bus-only) rejected: ok\n");
}

/* Lookup miss: a valid key for a different leaf models a not-found lookup. */
static void
test_lookup_miss (void)
{
  assert (dpdk_dev_name_match ("fslmc:dpni.7", "fslmc", "dpni.3") == false);
  printf ("  lookup miss (different leaf): ok\n");
}

/* Overflow guard: key does not fit -> false and out left empty. */
static void
test_overflow_guard (void)
{
  char small[8]; /* "fslmc:dpni.7" needs 13 bytes */

  assert (dpdk_dev_name_key ("fslmc", "dpni.7", small, sizeof small) == false);
  assert (small[0] == '\0');
  printf ("  overflow guard leaves out empty: ok\n");
}

/* Round-trip: a built key matches its own (bus,name) and rejects a different name. */
static void
test_round_trip (void)
{
  char buf[32];

  assert (dpdk_dev_name_key ("fslmc", "dpni.7", buf, sizeof buf) == true);
  assert (dpdk_dev_name_match (buf, "fslmc", "dpni.7") == true);
  assert (dpdk_dev_name_match (buf, "fslmc", "dpni.9") == false);
  printf ("  round-trip build then match: ok\n");
}

int
main (void)
{
  printf ("test_dev_name_match:\n");
  test_exact_match ();
  test_cross_bus_non_match ();
  test_malformed_key ();
  test_lookup_miss ();
  test_overflow_guard ();
  test_round_trip ();
  printf ("all tests passed\n");
  return 0;
}
