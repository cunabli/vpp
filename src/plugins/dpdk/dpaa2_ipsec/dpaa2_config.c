/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Carlos Aguado.
 *
 * The `dpaa2 {}` startup.conf block: DPAA2-wide configuration, consolidated in
 * one place. Today it carries the container binding (`dprc`) and the SEC ESP
 * offload lever (`ipsec { no-esp-offload }`); future DPAA2-wide knobs attach
 * here rather than arriving as scattered top-level stanzas.
 *
 * This is deliberately DPDK-header-free -- it only touches vlib's config/parse
 * machinery and the plugin's own `dpaa2_ipsec_main`. It compiles into the dpdk
 * plugin (dpdk_plugin.so) alongside the fslmc bus and rte_eal_init, so setting
 * DPRC here feeds the same binary that consumes it; there is no cross-plugin
 * reach. When the dpaa2 code is eventually split into its own plugin, this file
 * moves with it and takes a dependency on the (patched) dpdk plugin.
 */

#include <stdlib.h> /* setenv, for the `dprc` container binding */
#include <vlib/vlib.h>

#include "dpaa2_ipsec.h" /* dpaa2_ipsec_main.offload_disabled */

/* Parse the nested `ipsec { … }` sub-block of the top-level `dpaa2 {}` block. */
static clib_error_t *
dpaa2_ipsec_sub_config (unformat_input_t *input)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* Global lever: turn SEC ESP offload off entirely (all SAs then use the
       * async fallback). Absent, offload is enabled (capability-only). */
      if (unformat (input, "no-esp-offload"))
	dm->offload_disabled = 1;
      else
	return clib_error_return (0, "unknown ipsec input `%U'",
				  format_unformat_error, input);
    }

  return 0;
}

/* Top-level `dpaa2 {}` startup block.
 *
 *   dpaa2 {
 *     dprc dprc.N              # bind the container in-file (replaces env DPRC=)
 *     ipsec { no-esp-offload } # SEC ESP offload off; every SA uses async fallback
 *   }
 *
 * This is an EARLY config function on purpose. rte_eal_init runs in the dpdk
 * plugin's normal-pass dpdk_config, where the fslmc bus reads the container via
 * getenv("DPRC"). Setting DPRC from an early handler is the only ordering that
 * lands before that getenv. If this is ever downgraded to a normal config
 * function the binding silently reverts to env-only -- test_dpaa2_config asserts
 * the EARLY registration to catch that.
 */
static clib_error_t *
dpaa2_config (vlib_main_t *vm, unformat_input_t *input)
{
  clib_error_t *error = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat_input_t sub_input;
      u8 *name = 0;

      /* Bind the container in-file. overwrite=1 makes an explicit `dprc` win
       * over any inherited DPRC env var; without a `dprc` line the env var
       * remains the fallback the fslmc bus reads. */
      if (unformat (input, "dprc %s", &name))
	{
	  setenv ("DPRC", (char *) name, 1);
	  vec_free (name);
	}
      else if (unformat (input, "ipsec %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  error = dpaa2_ipsec_sub_config (&sub_input);
	  unformat_free (&sub_input);
	  if (error)
	    return error;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (dpaa2_config, "dpaa2");
