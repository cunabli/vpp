/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#include <unistd.h>
#include <errno.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_ethdev.h>
#include <rte_cryptodev.h>
#include <rte_vfio.h>
#include <rte_version.h>

#include <vlib/vlib.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>

STATIC_ASSERT (VLIB_BUFFER_PRE_DATA_SIZE == RTE_PKTMBUF_HEADROOM,
	       "VLIB_BUFFER_PRE_DATA_SIZE must be equal to RTE_PKTMBUF_HEADROOM");

extern struct rte_mbuf *dpdk_mbuf_template_by_pool_index;
#ifndef CLIB_MARCH_VARIANT
struct rte_mempool **dpdk_mempool_by_buffer_pool_index = 0;
struct rte_mempool **dpdk_no_cache_mempool_by_buffer_pool_index = 0;
struct rte_mbuf *dpdk_mbuf_template_by_pool_index = 0;
/* 1 for pools backed by a hardware mempool (e.g. DPAA2/QBMan DPBP) */
u8 *dpdk_buffer_pool_is_hw = 0;

/* Return the platform/user hardware mempool ops name (e.g. "dpaa2") if one is
   registered, else 0.  The DPAA2 fslmc bus calls
   rte_mbuf_set_platform_mempool_ops("dpaa2") when a DPBP object exists, which
   makes best_mempool_ops() differ from the compiled-in default.  That
   difference is our signal to build a hardware-backed pool.
   Note this keys on best != default, so an explicit --mbuf-pool-ops-name
   also selects this path -- which is the operator asking for it. */
static const char *
dpdk_hw_pool_ops_name (void)
{
  const char *best = rte_mbuf_best_mempool_ops ();
  if (best && strcmp (best, RTE_MBUF_DEFAULT_MEMPOOL_OPS) != 0)
    return best;
  return 0;
}

struct dpdk_rewrite_args
{
  vlib_main_t *vm;
  vlib_buffer_pool_t *bp;
};

/* rte_mempool_obj_iter callback: rebuild bp->buffers[] in the mempool's object
   order.  Address-derived, so it is correct regardless of the order in which
   rte_mempool_populate_iova enumerated objects. */
static void
dpdk_rewrite_vlib_bufs (struct rte_mempool *mp, void *opaque, void *obj,
			unsigned i)
{
  struct dpdk_rewrite_args *args = opaque;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf ((struct rte_mbuf *) obj);
  args->bp->buffers[i] = vlib_get_buffer_index (args->vm, b);
}

/* Hardware-backed pool init: the buffers live in a QBMan/DPBP mempool with
   platform ops, so net/dpaa2 RX queue setup can resolve a bpid.  The stock
   "vpp"/"vpp-no-cache" pair is skipped — QBMan owns the pool. */
static clib_error_t *
dpdk_hw_buffer_pool_init (vlib_main_t *vm, vlib_buffer_pool_t *bp,
			  const char *mp_ops_name)
{
  uword buffer_mem_start = vm->buffer_main->buffer_mem_start;
  struct rte_mempool *mp;
  struct rte_pktmbuf_pool_private priv;
  enum rte_iova_mode iova_mode = rte_eal_iova_mode ();
  vlib_physmem_map_t *pm;
  struct dpdk_rewrite_args args;
  size_t page_sz;
  u8 *name = 0;
  u32 i;
  int do_vfio_map = 1;

  u32 elt_size =
    sizeof (struct rte_mbuf) + sizeof (vlib_buffer_t) + bp->data_size;

  /* This path hands DPDK-laid-out mempool objects to vlib by index, so the two
     must agree on object placement: vlib indexes CLIB_CACHE_LINE_BYTES
     multiples, DPDK aligns objects to RTE_CACHE_LINE_SIZE.  It cannot be a
     STATIC_ASSERT -- the software path lays buffers out at VPP's own alignment
     and is unaffected, so a mismatched build is only invalid once a
     hardware-backed pool is actually requested. */
  if (CLIB_CACHE_LINE_BYTES != RTE_CACHE_LINE_SIZE)
    return clib_error_return (
      0,
      "HW buffer pool %u: VPP cache line is %u bytes but DPDK's is %u; "
      "mempool objects would not land on the vlib buffer index grid.  "
      "Rebuild VPP with -DVPP_CACHE_LINE_SIZE=%u",
      bp->index, (u32) CLIB_CACHE_LINE_BYTES, (u32) RTE_CACHE_LINE_SIZE,
      (u32) RTE_CACHE_LINE_SIZE);

  vec_validate_aligned (dpdk_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (dpdk_no_cache_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (dpdk_buffer_pool_is_hw, bp->index,
			CLIB_CACHE_LINE_BYTES);

  name = format (name, "vpp pool %u%c", bp->index, 0);
  /* 512-deep per-lcore cache: saves a QBMan acquire/release round-trip per
     buffer; holds back at most lcores * 512 buffers from the hardware. */
  mp = rte_mempool_create_empty ((char *) name, bp->n_buffers, elt_size, 512,
				 sizeof (priv), bp->numa_node, 0);
  vec_free (name);
  if (!mp)
    return clib_error_return (0, "failed to create HW mempool for pool %u",
			      bp->index);

  dpdk_mempool_by_buffer_pool_index[bp->index] = mp;
  dpdk_no_cache_mempool_by_buffer_pool_index[bp->index] = 0;

  /* Deliberately NOT setting mp->pool_id here.  It is a union with pool_data
     (rte_mempool.h), and on this path the pool's ops belong to the platform
     driver, which owns pool_data: net/dpaa2 stores its bp_info there during
     .alloc and dereferences it on every TX.  Writing pool_id would be
     clobbered by .alloc during populate below, and in the reverse order it
     corrupts the driver's pointer.  Nothing reads pool_id for a HW pool
     anyway -- every reader lives in the "vpp" / "vpp-no-cache" ops, which
     only the software path registers.  Use
     dpdk_mempool_by_buffer_pool_index[] for mp lookup instead. */

  /* platform ops (e.g. "dpaa2") — resolves a bpid net/dpaa2 RX requires */
  rte_mempool_set_ops_byname (mp, mp_ops_name, NULL);

  clib_memset (&priv, 0, sizeof (priv));
  priv.mbuf_data_room_size =
    VLIB_BUFFER_PRE_DATA_SIZE + vlib_buffer_get_default_data_size (vm);
  priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  rte_pktmbuf_pool_init (mp, &priv);

  /* populate from vlib physmem pages + VFIO DMA map (seeds QBMan) */
  pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
  page_sz = 1ULL << pm->log2_page_size;
  for (i = 0; i < pm->n_pages; i++)
    {
      char *va = ((char *) pm->base) + i * page_sz;
      uword pa = (iova_mode == RTE_IOVA_VA) ? pointer_to_uword (va) :
						    pm->page_table[i];
      int ret = rte_mempool_populate_iova (mp, va, pa, page_sz, 0, 0);
      if (ret < 0)
	{
	  rte_mempool_free (mp);
	  dpdk_mempool_by_buffer_pool_index[bp->index] = 0;
	  return clib_error_return (
	    0, "failed to populate HW mempool pool %u page %u: %d", bp->index,
	    i, ret);
	}
      if (do_vfio_map &&
	  rte_vfio_container_dma_map (RTE_VFIO_DEFAULT_CONTAINER_FD,
				      pointer_to_uword (va), pa, page_sz))
	do_vfio_map = 0;
    }

  /* rebuild bp->buffers[] in object order, then run object initializers */
  args.vm = vm;
  args.bp = bp;
  rte_mempool_obj_iter (mp, dpdk_rewrite_vlib_bufs, &args);
  rte_mempool_obj_iter (mp, rte_pktmbuf_init, 0);

  /* mbuf header template from the first object */
  vec_validate_aligned (dpdk_mbuf_template_by_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  clib_memcpy (vec_elt_at_index (dpdk_mbuf_template_by_pool_index, bp->index),
	       rte_mbuf_from_vlib_buffer (vlib_buffer_ptr_from_index (
		 buffer_mem_start, *bp->buffers, 0)),
	       sizeof (struct rte_mbuf));

  /* stamp vlib templates and verify index round-trip for every object.  A
     release-build check, not an ASSERT: a layout disagreement between vlib's
     buffer-index granularity and DPDK's object alignment corrupts memory
     arbitrarily far from its cause once the pool is live, so a mismatched
     build must be refused at init, in every build type. */
  for (i = 0; i < mp->populated_size; i++)
    {
      vlib_buffer_t *b =
	vlib_buffer_ptr_from_index (buffer_mem_start, bp->buffers[i], 0);
      b->template = bp->buffer_template;
      if (PREDICT_FALSE (vlib_get_buffer (vm, vlib_get_buffer_index (vm, b)) !=
			 b))
	{
	  rte_mempool_free (mp);
	  dpdk_mempool_by_buffer_pool_index[bp->index] = 0;
	  return clib_error_return (
	    0,
	    "HW buffer pool %u: object %u does not round-trip through the "
	    "vlib buffer index grid; vlib and DPDK disagree on object "
	    "placement.  Rebuild VPP with -DVPP_CACHE_LINE_SIZE=%u to match "
	    "DPDK's RTE_CACHE_LINE_SIZE",
	    bp->index, i, (u32) RTE_CACHE_LINE_SIZE);
	}
    }

  /* Buffers now live in the hardware pool; vlib's main pool must not also hand
     them out.  The backend ops (registered post-create) own allocation. */
  bp->n_avail = 0;
  dpdk_buffer_pool_is_hw[bp->index] = 1;

  /* Pool sizing is bounded by the seeded physmem, not by any MC per-pool cap,
     so report requested vs populated. */
  vlib_log_notice (vm->buffer_main->log_default,
		   "HW buffer pool %u (%s): requested %u, populated %u buffers",
		   bp->index, mp_ops_name, bp->n_buffers, mp->populated_size);

  return 0;
}

/* vlib backend alloc op: acquire buffers from the hardware mempool (QBMan).
   Honors partial results — returns however many it could supply. */
static u32
dpdk_hw_pool_alloc (vlib_main_t *vm, vlib_buffer_pool_t *bp, u32 *buffers,
		    u32 n_buffers)
{
  struct rte_mempool *mp = dpdk_mempool_by_buffer_pool_index[bp->index];
  struct rte_mbuf *mb[256];
  u32 n_done = 0;

  while (n_done < n_buffers)
    {
      u32 n = clib_min (n_buffers - n_done, ARRAY_LEN (mb));
      u32 avail = rte_mempool_avail_count (mp);
      if (n > avail)
	n = avail;
      /* On a concurrent-drain race get_bulk fails and we stop here; the
	 caller falls back to its normal path for the remainder. */
      if (n == 0 || rte_mempool_get_bulk (mp, (void **) mb, n))
	break;
      vlib_get_buffer_indices_with_offset (vm, (void **) mb, buffers + n_done,
					   n, sizeof (struct rte_mbuf));
      n_done += n;
    }
  return n_done;
}

/* vlib backend free op: release buffers back to the hardware mempool (QBMan). */
static void
dpdk_hw_pool_free (vlib_main_t *vm, vlib_buffer_pool_t *bp, u32 *buffers,
		   u32 n_buffers)
{
  struct rte_mempool *mp = dpdk_mempool_by_buffer_pool_index[bp->index];
  struct rte_mbuf *mb[256];
  u32 n_done = 0;

  while (n_done < n_buffers)
    {
      u32 n = clib_min (n_buffers - n_done, ARRAY_LEN (mb));
      vlib_get_buffers_with_offset (vm, buffers + n_done, (void **) mb, n,
				    -(i32) sizeof (struct rte_mbuf));
      rte_mempool_put_bulk (mp, (void **) mb, n);
      n_done += n;
    }
}

clib_error_t *
dpdk_buffer_pool_init (vlib_main_t * vm, vlib_buffer_pool_t * bp)
{
  /* Hardware-backed pools are strictly opt-in: the ops heuristic is consulted
     only when the operator set `dpdk { hw-buffer-pools }`.  Without the knob
     this is the unmodified stock path on every platform, including ones whose
     DPDK registers platform mempool ops (fslmc, cnxk, octeontx, dpaa, or an
     explicit --mbuf-pool-ops-name). */
  if (dpdk_config_main.hw_buffer_pools)
    {
      const char *hw_ops = dpdk_hw_pool_ops_name ();
      if (!hw_ops)
	return clib_error_return (
	  0, "dpdk { hw-buffer-pools } is set but no platform/hardware "
	     "mempool ops are registered on this system");
      return dpdk_hw_buffer_pool_init (vm, bp, hw_ops);
    }

  uword buffer_mem_start = vm->buffer_main->buffer_mem_start;
  struct rte_mempool *mp, *nmp;
  struct rte_pktmbuf_pool_private priv;
  enum rte_iova_mode iova_mode;
  u32 i;
  u8 *name = 0;

  u32 elt_size =
    sizeof (struct rte_mbuf) + sizeof (vlib_buffer_t) + bp->data_size;

  /* create empty mempools */
  vec_validate_aligned (dpdk_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (dpdk_no_cache_mempool_by_buffer_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);

  /* normal mempool */
  name = format (name, "vpp pool %u%c", bp->index, 0);
  mp = rte_mempool_create_empty ((char *) name, bp->n_buffers,
				 elt_size, 512, sizeof (priv),
				 bp->numa_node, 0);
  if (!mp)
    {
      vec_free (name);
      return clib_error_return (0,
				"failed to create normal mempool for numa node %u",
				bp->index);
    }
  vec_reset_length (name);

  /* non-cached mempool */
  name = format (name, "vpp pool %u (no cache)%c", bp->index, 0);
  nmp = rte_mempool_create_empty ((char *) name, bp->n_buffers,
				  elt_size, 0, sizeof (priv),
				  bp->numa_node, 0);
  if (!nmp)
    {
      rte_mempool_free (mp);
      vec_free (name);
      return clib_error_return (0,
				"failed to create non-cache mempool for numa nude %u",
				bp->index);
    }
  vec_free (name);

  dpdk_mempool_by_buffer_pool_index[bp->index] = mp;
  dpdk_no_cache_mempool_by_buffer_pool_index[bp->index] = nmp;

  mp->pool_id = nmp->pool_id = bp->index;

  rte_mempool_set_ops_byname (mp, "vpp", NULL);
  rte_mempool_set_ops_byname (nmp, "vpp-no-cache", NULL);

  /* Call the mempool priv initializer */
  memset (&priv, 0, sizeof (priv));
  priv.mbuf_data_room_size = VLIB_BUFFER_PRE_DATA_SIZE +
    vlib_buffer_get_default_data_size (vm);
  priv.mbuf_priv_size = VLIB_BUFFER_HDR_SIZE;
  rte_pktmbuf_pool_init (mp, &priv);
  rte_pktmbuf_pool_init (nmp, &priv);

  iova_mode = rte_eal_iova_mode ();

  /* populate mempool object buffer header */
  for (i = 0; i < bp->n_buffers; i++)
    {
      struct rte_mempool_objhdr *hdr;
      vlib_buffer_t *b = vlib_get_buffer (vm, bp->buffers[i]);
      struct rte_mbuf *mb = rte_mbuf_from_vlib_buffer (b);
      hdr = (struct rte_mempool_objhdr *) RTE_PTR_SUB (mb, sizeof (*hdr));
      hdr->mp = mp;
      hdr->iova = (iova_mode == RTE_IOVA_VA) ?
	pointer_to_uword (mb) : vlib_physmem_get_pa (vm, mb);
      STAILQ_INSERT_TAIL (&mp->elt_list, hdr, next);
      STAILQ_INSERT_TAIL (&nmp->elt_list, hdr, next);
      mp->populated_size++;
      nmp->populated_size++;
    }
  mp->flags &= ~RTE_MEMPOOL_F_NON_IO;

  /* call the object initializers */
  rte_mempool_obj_iter (mp, rte_pktmbuf_init, 0);

  /* create mbuf header tempate from the first buffer in the pool */
  vec_validate_aligned (dpdk_mbuf_template_by_pool_index, bp->index,
			CLIB_CACHE_LINE_BYTES);
  clib_memcpy (vec_elt_at_index (dpdk_mbuf_template_by_pool_index, bp->index),
	       rte_mbuf_from_vlib_buffer (vlib_buffer_ptr_from_index
					  (buffer_mem_start, *bp->buffers,
					   0)), sizeof (struct rte_mbuf));

  for (i = 0; i < bp->n_buffers; i++)
    {
      vlib_buffer_t *b;
      b = vlib_buffer_ptr_from_index (buffer_mem_start, bp->buffers[i], 0);
      b->template = bp->buffer_template;
    }

  /* map DMA pages if at least one physical device exists */
  if (rte_eth_dev_count_avail () || rte_cryptodev_count ())
    {
      uword i;
      size_t page_sz;
      vlib_physmem_map_t *pm;
      int do_vfio_map = 1;

      pm = vlib_physmem_get_map (vm, bp->physmem_map_index);
      page_sz = 1ULL << pm->log2_page_size;

      for (i = 0; i < pm->n_pages; i++)
	{
	  char *va = ((char *) pm->base) + i * page_sz;
	  uword pa = (iova_mode == RTE_IOVA_VA) ?
	    pointer_to_uword (va) : pm->page_table[i];

	  if (do_vfio_map && rte_vfio_container_dma_map (RTE_VFIO_DEFAULT_CONTAINER_FD,
							 pointer_to_uword (va), pa, page_sz))
	    do_vfio_map = 0;

	  struct rte_mempool_memhdr *memhdr;
	  memhdr = clib_mem_alloc (sizeof (*memhdr));
	  memhdr->mp = mp;
	  memhdr->addr = va;
	  memhdr->iova = pa;
	  memhdr->len = page_sz;
	  memhdr->free_cb = 0;
	  memhdr->opaque = 0;

	  STAILQ_INSERT_TAIL (&mp->mem_list, memhdr, next);
	  mp->nb_mem_chunks++;
	}
    }

  return 0;
}

static int
dpdk_ops_vpp_alloc (struct rte_mempool *mp)
{
  clib_warning ("");
  return 0;
}

static void
dpdk_ops_vpp_free (struct rte_mempool *mp)
{
  clib_warning ("");
}

#endif

static_always_inline void
dpdk_ops_vpp_enqueue_one (vlib_buffer_template_t *bt, void *obj)
{
  /* Only non-replicated packets (b->ref_count == 1) expected */

  struct rte_mbuf *mb = obj;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
  ASSERT (b->ref_count == 1);
  ASSERT (b->buffer_pool_index == bt->buffer_pool_index);
  b->template = *bt;
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_enqueue) (struct rte_mempool * mp,
					  void *const *obj_table, unsigned n)
{
  const int batch_size = 32;
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_template_t bt;
  u8 buffer_pool_index = mp->pool_id;
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  u32 bufs[batch_size];
  u32 n_left = n;
  void *const *obj = obj_table;

  bt = bp->buffer_template;

  while (n_left >= 4)
    {
      dpdk_ops_vpp_enqueue_one (&bt, obj[0]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[1]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[2]);
      dpdk_ops_vpp_enqueue_one (&bt, obj[3]);
      obj += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      dpdk_ops_vpp_enqueue_one (&bt, obj[0]);
      obj += 1;
      n_left -= 1;
    }

  while (n >= batch_size)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) obj_table, bufs,
					   batch_size,
					   sizeof (struct rte_mbuf));
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, batch_size);
      n -= batch_size;
      obj_table += batch_size;
    }

  if (n)
    {
      vlib_get_buffer_indices_with_offset (vm, (void **) obj_table, bufs,
					   n, sizeof (struct rte_mbuf));
      vlib_buffer_pool_put (vm, buffer_pool_index, bufs, n);
    }

  return 0;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_enqueue);

static_always_inline void
dpdk_ops_vpp_enqueue_no_cache_one (vlib_main_t *vm, struct rte_mempool *old,
				   struct rte_mempool *new, void *obj,
				   vlib_buffer_template_t *bt)
{
  struct rte_mbuf *mb = obj;
  vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);

  if (clib_atomic_sub_fetch (&b->ref_count, 1) == 0)
    {
      u32 bi = vlib_get_buffer_index (vm, b);
      b->template = *bt;
      vlib_buffer_pool_put (vm, bt->buffer_pool_index, &bi, 1);
      return;
    }
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_enqueue_no_cache) (struct rte_mempool * cmp,
						   void *const *obj_table,
						   unsigned n)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_template_t bt;
  struct rte_mempool *mp;
  mp = dpdk_mempool_by_buffer_pool_index[cmp->pool_id];
  u8 buffer_pool_index = cmp->pool_id;
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, buffer_pool_index);
  bt = bp->buffer_template;

  while (n >= 4)
    {
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[0], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[1], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[2], &bt);
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[3], &bt);
      obj_table += 4;
      n -= 4;
    }

  while (n)
    {
      dpdk_ops_vpp_enqueue_no_cache_one (vm, cmp, mp, obj_table[0], &bt);
      obj_table += 1;
      n -= 1;
    }

  return 0;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_enqueue_no_cache);

static_always_inline void
dpdk_mbuf_init_from_template (struct rte_mbuf **mba, struct rte_mbuf *mt,
			      int count)
{
  /* Assumptions about rte_mbuf layout */
  STATIC_ASSERT_OFFSET_OF (struct rte_mbuf, buf_addr, 0);
  STATIC_ASSERT_OFFSET_OF (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF_ELT (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF_ELT (struct rte_mbuf, buf_iova, 8);
  STATIC_ASSERT_SIZEOF (struct rte_mbuf, 128);

  while (count--)
    {
      struct rte_mbuf *mb = mba[0];
      int i;
      /* bytes 0 .. 15 hold buf_addr and buf_iova which we need to preserve */
      /* copy bytes 16 .. 31 */
      *((u8x16 *) mb + 1) = *((u8x16 *) mt + 1);

      /* copy bytes 32 .. 127 */
#ifdef CLIB_HAVE_VEC256
      for (i = 1; i < 4; i++)
	*((u8x32 *) mb + i) = *((u8x32 *) mt + i);
#else
      for (i = 2; i < 8; i++)
	*((u8x16 *) mb + i) = *((u8x16 *) mt + i);
#endif
      mba++;
    }
}

int
CLIB_MULTIARCH_FN (dpdk_ops_vpp_dequeue) (struct rte_mempool * mp,
					  void **obj_table, unsigned n)
{
  /*
   * The cache path is bounded by RTE_MEMPOOL_CACHE_MAX_SIZE (512) so at
   * most cache->size + remaining = 1024 entries.  However the ops dequeue
   * function can also be called directly (e.g. by ena_populate_rx_queue to
   * pre-fill an RX ring), in which case n equals the ring size and can be
   * much larger. Process in chunks to keep the on-stack bufs[] array small.
   */
  const unsigned chunk_size = RTE_MEMPOOL_CACHE_MAX_SIZE * 2;
  vlib_main_t *vm = vlib_get_main ();
  u8 buffer_pool_index = mp->pool_id;
  struct rte_mbuf t = dpdk_mbuf_template_by_pool_index[buffer_pool_index];
  unsigned done = 0;

  while (done < n)
    {
      u32 bufs[chunk_size];
      unsigned batch = clib_min (n - done, chunk_size);
      u32 n_alloc;

      n_alloc = vlib_buffer_alloc_from_pool (vm, bufs, batch, buffer_pool_index);
      if (n_alloc != batch)
	{
	  if (n_alloc)
	    vlib_buffer_pool_put (vm, buffer_pool_index, bufs, n_alloc);
	  /* free already-issued mbufs */
	  if (done)
	    rte_mempool_ops_enqueue_bulk (mp, obj_table, done);
	  return -ENOENT;
	}

      vlib_get_buffers_with_offset (vm, bufs, obj_table + done, batch,
				    -(i32) sizeof (struct rte_mbuf));
      dpdk_mbuf_init_from_template ((struct rte_mbuf **) (obj_table + done), &t, batch);
      done += batch;
    }

  return 0;
}

CLIB_MARCH_FN_REGISTRATION (dpdk_ops_vpp_dequeue);

#ifndef CLIB_MARCH_VARIANT

static int
dpdk_ops_vpp_dequeue_no_cache (struct rte_mempool *mp, void **obj_table,
			       unsigned n)
{
  clib_error ("bug");
  return 0;
}

static unsigned
dpdk_ops_vpp_get_count (const struct rte_mempool *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  if (mp)
    {
      vlib_buffer_pool_t *pool = vlib_get_buffer_pool (vm, mp->pool_id);
      if (pool)
	{
	  return pool->n_avail;
	}
    }
  return 0;
}

static unsigned
dpdk_ops_vpp_get_count_no_cache (const struct rte_mempool *mp)
{
  struct rte_mempool *cmp;
  cmp = dpdk_no_cache_mempool_by_buffer_pool_index[mp->pool_id];
  return dpdk_ops_vpp_get_count (cmp);
}

/* vlib backend count op: true availability straight from the hardware mempool,
   so `show buffers` and the stats gauges report populated-minus-in-flight
   rather than the zero a backend-owned pool keeps in n_avail. */
static u32
dpdk_hw_pool_count (vlib_main_t *vm, vlib_buffer_pool_t *bp)
{
  return rte_mempool_avail_count (dpdk_mempool_by_buffer_pool_index[bp->index]);
}

/* Attach the vlib alloc/free backend ops to every hardware-backed pool.
   Called post-pool-create from the dpdk init path. */
clib_error_t *
dpdk_buffer_register_hw_backend (vlib_main_t *vm)
{
  vlib_buffer_pool_t *bp;
  vlib_buffer_pool_backend_ops_t ops = {
    .alloc = dpdk_hw_pool_alloc,
    .free = dpdk_hw_pool_free,
    .count = dpdk_hw_pool_count,
  };

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    if (bp->index < vec_len (dpdk_buffer_pool_is_hw) &&
	dpdk_buffer_pool_is_hw[bp->index])
      if (vlib_buffer_pool_set_backend_ops (vm, bp->index, ops))
	return clib_error_return (
	  0, "failed to register HW backend ops for pool %u", bp->index);
  return 0;
}

/* Detach the backend ops (teardown / interface delete-re-add). */
void
dpdk_buffer_deregister_hw_backend (vlib_main_t *vm)
{
  vlib_buffer_pool_t *bp;
  vlib_buffer_pool_backend_ops_t none = { 0 };

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    if (bp->index < vec_len (dpdk_buffer_pool_is_hw) &&
	dpdk_buffer_pool_is_hw[bp->index])
      vlib_buffer_pool_set_backend_ops (vm, bp->index, none);
}

clib_error_t *
dpdk_buffer_pools_create (vlib_main_t * vm)
{
  clib_error_t *err;
  vlib_buffer_pool_t *bp;

  struct rte_mempool_ops ops = { };

  strncpy (ops.name, "vpp", 4);
  ops.alloc = dpdk_ops_vpp_alloc;
  ops.free = dpdk_ops_vpp_free;
  ops.get_count = dpdk_ops_vpp_get_count;
  ops.enqueue = CLIB_MARCH_FN_POINTER (dpdk_ops_vpp_enqueue);
  ops.dequeue = CLIB_MARCH_FN_POINTER (dpdk_ops_vpp_dequeue);
  rte_mempool_register_ops (&ops);

  strncpy (ops.name, "vpp-no-cache", 13);
  ops.get_count = dpdk_ops_vpp_get_count_no_cache;
  ops.enqueue = CLIB_MARCH_FN_POINTER (dpdk_ops_vpp_enqueue_no_cache);
  ops.dequeue = dpdk_ops_vpp_dequeue_no_cache;
  rte_mempool_register_ops (&ops);

  vec_foreach (bp, vm->buffer_main->buffer_pools)
    if (bp->start && (err = dpdk_buffer_pool_init (vm, bp)))
      return err;
  return 0;
}

VLIB_BUFFER_SET_EXT_HDR_SIZE (sizeof (struct rte_mempool_objhdr) +
			      sizeof (struct rte_mbuf));

#endif

/** @endcond */
