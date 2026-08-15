/*
 * test_dpaa2_config.c - device-free tripwire for the `dpaa2 {}` startup block.
 *
 * The `dpaa2 {}` handler must be an EARLY config function: rte_eal_init runs in
 * the dpdk plugin's normal-pass dpdk_config, where the fslmc bus reads the
 * container via getenv("DPRC"). Only an early handler sets DPRC before that
 * getenv; downgraded to a normal config function, the `dprc` binding silently
 * reverts to env-only and nothing at runtime complains. That regression is
 * invisible without hardware, so this asserts it from the source itself -- no
 * VPP/DPDK link, plain cc, runs at build time via add_vpp_test.
 *
 * Ceiling: this is a source tripwire, not a runtime exercise. It proves the
 * registration is early and the offload token still maps; the actual container
 * binding is proven on-board (change task 3.1).
 *
 *   cc -Wall -Werror -DDPAA2_CONFIG_SRC=... test_dpaa2_config.c && ./a.out
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DPAA2_CONFIG_SRC
#error "DPAA2_CONFIG_SRC must point at dpaa2_config.c (set in CMakeLists.txt)"
#endif

/* Slurp the whole source file so the checks below are plain substring scans. */
static char *
slurp (const char *path)
{
  FILE *f = fopen (path, "rb");
  assert (f && "cannot open dpaa2_config.c");
  fseek (f, 0, SEEK_END);
  long n = ftell (f);
  fseek (f, 0, SEEK_SET);
  char *buf = malloc (n + 1);
  assert (buf);
  assert (fread (buf, 1, n, f) == (size_t) n);
  buf[n] = 0;
  fclose (f);
  return buf;
}

int
main (void)
{
  char *src = slurp (DPAA2_CONFIG_SRC);

  printf ("test_dpaa2_config:\n");

  /* Registered EARLY under the top-level `dpaa2` name. */
  assert (strstr (src, "VLIB_EARLY_CONFIG_FUNCTION (dpaa2_config, \"dpaa2\")"));
  printf ("  dpaa2 block registered as EARLY config: ok\n");

  /* Not downgraded to a normal (normal-pass) config function -- that would run
   * after rte_eal_init and lose the binding. The early macro is VLIB_EARLY_...,
   * so this substring matches only a genuine downgrade. */
  assert (!strstr (src, "VLIB_CONFIG_FUNCTION (dpaa2_config"));
  printf ("  not downgraded to a normal config function: ok\n");

  /* The offload kill switch maps `no-esp-offload` -> offload_disabled. */
  assert (strstr (src, "\"no-esp-offload\""));
  assert (strstr (src, "offload_disabled = 1"));
  printf ("  no-esp-offload sets offload_disabled: ok\n");

  free (src);
  printf ("PASS\n");
  return 0;
}
