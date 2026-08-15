/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 *
 * Unit test for the per-buffer-pool allocation backend ops
 * (vlib_buffer_pool_set_backend_ops).  Change: dpaa2-hw-buffer-pool.
 *
 * The test backend is a transparent pass-through to the pool's own main
 * store (bp->buffers / n_avail) with a per-alloc cap, so it is safe to
 * register on the live default pool for a short, single-threaded, no-traffic
 * window: buffers are never lost, only routed through the hook.  The cap lets
 * us drive the partial-allocation path deterministically.
 */

#include <vlib/vlib.h>

#define BB_TEST(_cond, _comment, _args...)                                    \
  {                                                                           \
    if (!(_cond))                                                             \
      {                                                                       \
	fformat (stderr, "FAIL:%d: " _comment "\n", __LINE__, ##_args);        \
	res = -1;                                                              \
	goto done;                                                            \
      }                                                                       \
    fformat (stderr, "PASS:%d: " _comment "\n", __LINE__, ##_args);          \
  }

static u32 bb_cap;	   /* max buffers the backend hands out per alloc call */
static u64 bb_alloc_total; /* buffers served by the backend alloc hook */
static u64 bb_free_total;  /* buffers taken by the backend free hook */

static u32
bb_backend_alloc (vlib_main_t *vm, vlib_buffer_pool_t *bp, u32 *buffers,
		  u32 n_buffers)
{
  u32 want = clib_min (n_buffers, bb_cap);
  u32 got;

  clib_spinlock_lock (&bp->lock);
  got = clib_min (want, bp->n_avail);
  bp->n_avail -= got;
  vlib_buffer_copy_indices (buffers, bp->buffers + bp->n_avail, got);
  clib_spinlock_unlock (&bp->lock);

  bb_alloc_total += got;
  return got;
}

static void
bb_backend_free (vlib_main_t *vm, vlib_buffer_pool_t *bp, u32 *buffers,
		 u32 n_buffers)
{
  clib_spinlock_lock (&bp->lock);
  vlib_buffer_copy_indices (bp->buffers + bp->n_avail, buffers, n_buffers);
  bp->n_avail += n_buffers;
  clib_spinlock_unlock (&bp->lock);

  bb_free_total += n_buffers;
}

/* count op returning a sentinel, to prove availability dispatch */
#define BB_COUNT_SENTINEL 0xC0FFEE
static u32
bb_backend_count (vlib_main_t *vm, vlib_buffer_pool_t *bp)
{
  return BB_COUNT_SENTINEL;
}

/* observational callback, only used to prove the slot is independent */
static u32
bb_dummy_obs (vlib_main_t *vm, u8 buffer_pool_index, u32 *buffers,
	      u32 n_buffers)
{
  return n_buffers;
}

/* total live buffers in a pool: main store + every thread cache */
static u64
bb_pool_count (vlib_buffer_pool_t *bp)
{
  vlib_buffer_pool_thread_t *bpt;
  u64 n = bp->n_avail;
  vec_foreach (bpt, bp->threads)
    n += bpt->n_cached;
  return n;
}

static clib_error_t *
buffer_backend_test (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  vlib_buffer_pool_t *bp;
  u8 pool_index = vlib_buffer_pool_get_default_for_numa (vm, vm->numa_node);
  u32 *bi = 0;
  u64 count_before;
  u32 n_alloc, i;
  int res = 0;
  int registered = 0;

  bp = vlib_get_buffer_pool (vm, pool_index);

  /* Refuse to run against a pool that already has a backend (e.g. the DPAA2
     DPBP pool).  This test *installs its own* backend and deregisters it on
     the way out, which would clobber the real one and leave the pool with no
     backend and n_avail == 0 -- i.e. permanently unable to allocate for the
     rest of this VPP run.  The stock-path semantics it checks are also not
     observable here: bb_pool_count() reads bp->n_avail, which a
     backend-owned pool deliberately keeps at 0. */
  if (bp->backend_ops.alloc || bp->backend_ops.free)
    {
      vlib_cli_output (vm,
		       "buffer-backend unit test skipped: pool %u is already "
		       "backend-owned (hardware pool); this test needs a "
		       "stock vlib pool",
		       pool_index);
      return 0;
    }

  count_before = bb_pool_count (bp);
  BB_TEST (count_before >= 2048, "pool has enough buffers (%llu)",
	   count_before);

  vlib_buffer_pool_backend_ops_t ops = { .alloc = bb_backend_alloc,
					 .free = bb_backend_free,
					 .count = bb_backend_count };

  /* --- coexistence: backend + observational slot register independently --- */
  BB_TEST (vlib_buffer_pool_set_backend_ops (vm, pool_index, ops) == 0,
	   "backend ops register");
  registered = 1;

  /* --- count op: availability dispatches to the backend, not n_avail --- */
  BB_TEST (vlib_buffer_pool_available (vm, bp) == BB_COUNT_SENTINEL,
	   "count op dispatched (sentinel 0x%x)", BB_COUNT_SENTINEL);
  BB_TEST (vlib_buffer_set_alloc_free_callback (vm, bb_dummy_obs,
						bb_dummy_obs) == 0,
	   "observational callback coexists with backend");
  vlib_buffer_set_alloc_free_callback (vm, 0, 0);

  /* --- partial alloc: cap below the request; expect the cap, not 0 --- */
  bb_cap = 300;
  bb_alloc_total = bb_free_total = 0;
  vec_validate (bi, 1023); /* 1024 slots, > per-thread cache (512) */
  n_alloc = vlib_buffer_alloc_from_pool (vm, bi, 1024, pool_index);
  BB_TEST (n_alloc == 300, "partial alloc honored (got %u, want cap 300)",
	   n_alloc);
  BB_TEST (bb_alloc_total == 300, "backend alloc hook was used (%llu)",
	   bb_alloc_total);
  for (i = 0; i < n_alloc; i++)
    BB_TEST (bi[i] != 0 && vlib_get_buffer (vm, bi[i]) != 0,
	     "buffer %u valid", i);

  /* free them back; freeing 1024-worth would overflow the 512 cache, but 300
     may fit the cache, so this leg only checks conservation, not the hook */
  vlib_buffer_free (vm, bi, n_alloc);

  /* --- free hook: allocate a big batch, free it, overflow hits backend --- */
  bb_cap = 2048;
  bb_alloc_total = bb_free_total = 0;
  n_alloc = vlib_buffer_alloc_from_pool (vm, bi, 1024, pool_index);
  BB_TEST (n_alloc == 1024, "full alloc under high cap (got %u)", n_alloc);
  vlib_buffer_free (vm, bi, n_alloc);
  BB_TEST (bb_free_total > 0, "backend free hook was used (%llu)",
	   bb_free_total);

  /* --- conservation: no buffers leaked through the hooks --- */
  /* deregister first so cached buffers settle against the real pool */
  vlib_buffer_pool_set_backend_ops (vm, pool_index,
				    (vlib_buffer_pool_backend_ops_t){ 0 });
  registered = 0;
  BB_TEST (bb_pool_count (bp) == count_before,
	   "buffers conserved (before %llu, after %llu)", count_before,
	   bb_pool_count (bp));
  BB_TEST (vlib_buffer_pool_available (vm, bp) == bp->n_avail,
	   "availability reverts to n_avail after deregistration");

done:
  if (registered)
    vlib_buffer_pool_set_backend_ops (vm, pool_index,
				      (vlib_buffer_pool_backend_ops_t){ 0 });
  vec_free (bi);
  if (res)
    return clib_error_return (0, "buffer-backend unit test failed");
  vlib_cli_output (vm, "buffer-backend unit test passed");
  return 0;
}

VLIB_CLI_COMMAND (buffer_backend_test_command, static) = {
  .path = "test buffer-backend",
  .short_help = "internal vlib buffer-pool backend-ops unit test",
  .function = buffer_backend_test,
};
