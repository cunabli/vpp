/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Carlos Aguado.
 *
 * DPAA2 IPsec full-ESP protocol offload: encrypt/decrypt steering nodes.
 *
 * These are the demux nodes that own the ESP tunnel next-node indices
 * (im->esp{4,6}_{encrypt,decrypt}_tun_node_index; installed by the steering
 * step). One node runs for every tunnel SA of its family/direction. Per packet
 * it reads the SA index, consults the cached per-SA routing decision, and:
 *
 *   - offload: attaches the SA's rte_security session to a crypto op, points it
 *     at the packet's mbuf, and enqueues it to this worker's SEC queue-pair.
 *     SEC then performs the entire ESP transform (encap/decap, crypto, IV, seq,
 *     anti-replay). The buffer leaves the graph here; the poll node re-injects
 *     it when SEC completes.
 *
 *   - fallback: forwards the buffer unchanged to the original built-in ESP node
 *     (the async cryptodev path), so SAs the device cannot honour still work.
 *
 * For lookaside PROTOCOL the op needs nothing but the session and the source
 * mbuf -- no per-op IV/AAD/digest wiring, since SEC owns the whole transform.
 * That also means no custom op private is needed: the completion carries the
 * mbuf (recoverable to the vlib buffer), and the buffer still holds the SA
 * index, so the poll node reconstructs everything it needs.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipsec/ipsec_funcs.h>

#include "dpaa2_ipsec.h"

#include <dpdk/device/dpdk.h>
#include <dpdk/buffer.h>
#undef always_inline
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_security.h>
#include <rte_mbuf.h>
#include <rte_config.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

/* The demux (producer) arms this poll node (consumer) after each enqueue. */
extern vlib_node_registration_t dpaa2_ipsec_poll_node;

/* Crypto ops per worker pool. One op per in-flight offloaded packet, so this
 * caps a worker's SEC-inflight depth; sized above a full vector plus headroom
 * for the split-phase (enqueued-but-not-dequeued) window. */
#define DPAA2_IPSEC_N_COPS 2048

#define foreach_dpaa2_ipsec_next                                              \
  _ (FALLBACK, "fallback") /* set per node to the built-in ESP node */        \
  _ (HANDOFF, "handoff")   /* set per node to the built-in ESP handoff node */ \
  _ (DROP, "error-drop")

typedef enum
{
#define _(n, s) DPAA2_IPSEC_NEXT_##n,
  foreach_dpaa2_ipsec_next
#undef _
    DPAA2_IPSEC_N_NEXT,
} dpaa2_ipsec_next_t;

#define foreach_dpaa2_ipsec_error                                             \
  _ (RX, "packets received")                                                  \
  _ (OFFLOAD, "packets offloaded to SEC")                                     \
  _ (HANDOFF, "packets handed off to the SA's worker")                        \
  _ (FALLBACK, "packets sent to software fallback")                           \
  _ (COP_ALLOC, "crypto-op alloc failed (fell back)")                         \
  _ (ENQ_FAIL, "SEC enqueue failed, queue full (dropped)")

typedef enum
{
#define _(n, s) DPAA2_IPSEC_ERROR_##n,
  foreach_dpaa2_ipsec_error
#undef _
    DPAA2_IPSEC_N_ERROR,
} dpaa2_ipsec_error_t;

static char *dpaa2_ipsec_error_strings[] = {
#define _(n, s) s,
  foreach_dpaa2_ipsec_error
#undef _
};

typedef struct
{
  u32 sa_index;
  u8 offloaded;
} dpaa2_ipsec_trace_t;

static u8 *
format_dpaa2_ipsec_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dpaa2_ipsec_trace_t *t = va_arg (*args, dpaa2_ipsec_trace_t *);

  s = format (s, "sa %u -> %s", t->sa_index,
	      t->offloaded ? "SEC offload" : "fallback");
  return s;
}

/* Lazily create this worker's crypto-op pool on the SECURITY device's socket. */
static struct rte_mempool *
ensure_cop_pool (dpaa2_ipsec_worker_t *w, u32 thread_index)
{
  char name[RTE_MEMPOOL_NAMESIZE];

  if (w->cop_pool)
    return w->cop_pool;

  snprintf (name, sizeof (name), "dpaa2_ipsec_cop_%u", thread_index);
  /* priv_size 0: lookaside-protocol needs no per-op scratch. */
  w->cop_pool = rte_crypto_op_pool_create (
    name, RTE_CRYPTO_OP_TYPE_SYMMETRIC, DPAA2_IPSEC_N_COPS, 256, 0,
    rte_cryptodev_socket_id (w->dev_id));
  return w->cop_pool;
}

/* Sync the vlib buffer's geometry into its rte_mbuf so SEC sees the packet the
 * node sees. Mirrors the dpdk plugin's own dpdk_validate_rte_mbuf (which is
 * file-static and cannot be linked), including the chained-buffer walk so
 * jumbo/multi-seg ESP packets are handed to SEC whole.
 * ponytail: drops the ref_count>1 pool-swap the TX path does for cloned
 * buffers -- crypto never enqueues clones; add it only if that changes. */
static_always_inline void
dpaa2_ipsec_mbuf_sync (vlib_main_t *vm, vlib_buffer_t *b)
{
  struct rte_mbuf *mb, *first_mb, *last_mb;
  last_mb = first_mb = mb = rte_mbuf_from_vlib_buffer (b);

  if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_EXT_HDR_VALID) == 0))
    rte_pktmbuf_reset (mb);

  first_mb->nb_segs = 1;
  mb->data_len = b->current_length;
  mb->pkt_len = vlib_buffer_length_in_chain (vm, b);
  mb->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;

  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      b = vlib_get_buffer (vm, b->next_buffer);
      mb = rte_mbuf_from_vlib_buffer (b);
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_EXT_HDR_VALID) == 0))
	rte_pktmbuf_reset (mb);
      last_mb->next = mb;
      last_mb = mb;
      mb->data_len = b->current_length;
      mb->pkt_len = b->current_length;
      mb->data_off = VLIB_BUFFER_PRE_DATA_SIZE + b->current_data;
      first_mb->nb_segs++;
    }
}

static_always_inline uword
dpaa2_ipsec_offload_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			    vlib_frame_t *frame, int is_decrypt)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  u32 thread_index = vm->thread_index;
  dpaa2_ipsec_worker_t *w = (thread_index < vec_len (dm->workers))
			      ? vec_elt_at_index (dm->workers, thread_index)
			      : 0;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  /* Buffers that stay in the graph (fallback or drop) collected with their
   * next; offloaded+enqueued buffers leave the graph and are not listed. */
  u32 to_graph[VLIB_FRAME_SIZE], *tg = to_graph;
  u16 nexts[VLIB_FRAME_SIZE], *nx = nexts;
  struct rte_crypto_op *ops[VLIB_FRAME_SIZE];
  u32 op_bi[VLIB_FRAME_SIZE];
  u32 n_off = 0, n_fb = 0, n_cop_fail = 0, n_ho = 0;

  int have_qp = w && w->dev_id != DPAA2_IPSEC_INVALID_U16;
  struct rte_mempool *cop_pool =
    have_qp ? ensure_cop_pool (w, thread_index) : 0;

  while (n_left > 0)
    {
      u32 bi = from[0];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      u32 sa_index;
      void *sess = 0;

      from += 1;
      n_left -= 1;

      if (is_decrypt)
	sa_index = vnet_buffer (b)->ipsec.sad_index;
      else
	{
	  /* Encrypt tunnel: resolve the SA through the adjacency, as the
	   * built-in esp*-encrypt-tun node does. */
	  sa_index = ipsec_tun_protect_get_sa_out (
	    vnet_buffer (b)->ip.adj_index[VLIB_TX]);
	  vnet_buffer (b)->ipsec.sad_index = sa_index;
	}

      /* Routing is a cached per-SA property (see the header), not per-worker.
       * Sessions are directional: encrypt uses egress, decrypt uses ingress. */
      if (sa_index < vec_len (dm->sa_route) &&
	  dm->sa_route[sa_index].decision == DPAA2_IPSEC_ROUTE_OFFLOAD)
	sess = is_decrypt ? dm->sa_session[sa_index].ingress
			  : dm->sa_session[sa_index].egress;

      if (sess)
	{
	  /* One SA is pinned to one worker's queue-pair for its lifetime (D3):
	   * SEC keeps the SA's sequence/replay state, so every packet must reach
	   * that worker before enqueue. The first packet claims one via
	   * cmp-and-swap, constrained to the qp-owning workers (so the pinned
	   * worker can actually enqueue), mirroring the built-in ESP handoff we
	   * displaced. */
	  clib_thread_index_t sa_ti;
	  if (is_decrypt)
	    {
	      ipsec_sa_inb_rt_t *rt = ipsec_sa_get_inb_rt_by_index (sa_index);
	      if (PREDICT_FALSE (rt->thread_index == (clib_thread_index_t) ~0))
		clib_atomic_cmp_and_swap (&rt->thread_index, ~0,
					  dpaa2_ipsec_assign_offload_thread (thread_index));
	      sa_ti = rt->thread_index;
	    }
	  else
	    {
	      ipsec_sa_outb_rt_t *rt = ipsec_sa_get_outb_rt_by_index (sa_index);
	      if (PREDICT_FALSE (rt->thread_index == (clib_thread_index_t) ~0))
		clib_atomic_cmp_and_swap (&rt->thread_index, ~0,
					  dpaa2_ipsec_assign_offload_thread (thread_index));
	      sa_ti = rt->thread_index;
	    }

	  if (PREDICT_FALSE (thread_index != sa_ti))
	    {
	      /* Not the SA's worker: hand off. The ESP handoff frame queue is
	       * bound to the tunnel node index we own, so the packet re-enters
	       * this demux on the pinned worker (wired by the steering step). */
	      vnet_buffer (b)->ipsec.thread_index = sa_ti;
	      tg[0] = bi;
	      nx[0] = DPAA2_IPSEC_NEXT_HANDOFF;
	      tg += 1;
	      nx += 1;
	      n_ho += 1;
	      goto trace;
	    }

	  if (PREDICT_FALSE (cop_pool == 0))
	    {
	      /* Pinned here but this worker holds no SEC queue-pair: keep the
	       * whole SA on software rather than fracture it. */
	      tg[0] = bi;
	      nx[0] = DPAA2_IPSEC_NEXT_FALLBACK;
	      tg += 1;
	      nx += 1;
	      n_fb += 1;
	      goto trace;
	    }

	  struct rte_crypto_op *op =
	    rte_crypto_op_alloc (cop_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	  if (PREDICT_FALSE (op == 0))
	    {
	      /* Transient pool exhaustion: fall back this packet, don't drop it. */
	      tg[0] = bi;
	      nx[0] = DPAA2_IPSEC_NEXT_FALLBACK;
	      tg += 1;
	      nx += 1;
	      n_cop_fail += 1;
	      goto trace;
	    }
	  rte_security_attach_session (op, sess);
	  op->sym->m_src = rte_mbuf_from_vlib_buffer (b);
	  /* Encap only: an explicit destination routes dpaa2_sec through the
	   * compound-FD path; the single-buffer path puts SEC in allocate mode,
	   * which rejects our VPP-pool buffer on the growing encap (QI frc
	   * 0x..45). Decap shrinks and stays on the single path. */
	  if (!is_decrypt)
	    op->sym->m_dst = op->sym->m_src;
	  else
	    {
	      /* SEC decap consumes the packet from the OUTER IP header (it strips
	       * sizeof(ip)); the tun-decrypt path already advanced current_data to
	       * the ESP header, so rewind to the recorded L3 offset. Else SEC reads
	       * ESP bytes as the outer IP and the descriptor faults (DECO 0x10). */
	      i16 l3 = vnet_buffer (b)->l3_hdr_offset;
	      if (b->current_data > l3)
		vlib_buffer_advance (b, (word) (l3 - b->current_data));
	    }
	  dpaa2_ipsec_mbuf_sync (vm, b);
	  ops[n_off] = op;
	  op_bi[n_off] = bi;
	  n_off += 1;
	}
      else
	{
	  tg[0] = bi;
	  nx[0] = DPAA2_IPSEC_NEXT_FALLBACK;
	  tg += 1;
	  nx += 1;
	  n_fb += 1;
	}

    trace:
      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  dpaa2_ipsec_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->sa_index = sa_index;
	  t->offloaded = (sess != 0);
	}
    }

  /* One burst enqueue to this worker's SEC queue-pair. */
  u32 n_enq = 0;
  if (n_off)
    {
      n_enq =
	rte_cryptodev_enqueue_burst (w->dev_id, w->qp_id, ops, (u16) n_off);
      w->inflight += n_enq;

      if (n_enq)
	/* Wake this worker's poll node to drain what we just queued (D2'
	 * self-gating: the producer arms the interrupt INPUT consumer). */
	vlib_node_set_interrupt_pending (vm, dpaa2_ipsec_poll_node.index);

      if (PREDICT_FALSE (n_enq < n_off))
	{
	  /* SEC queue-pair full: drop the un-enqueued packets (bounded, no worker
	   * block, no corruption) and free their ops back to the pool. */
	  for (u32 i = n_enq; i < n_off; i++)
	    {
	      tg[0] = op_bi[i];
	      nx[0] = DPAA2_IPSEC_NEXT_DROP;
	      tg += 1;
	      nx += 1;
	    }
	  rte_mempool_put_bulk (cop_pool, (void **) &ops[n_enq], n_off - n_enq);
	}
    }

  u32 n_to_graph = tg - to_graph;
  if (n_to_graph)
    vlib_buffer_enqueue_to_next (vm, node, to_graph, nexts, n_to_graph);

  vlib_node_increment_counter (vm, node->node_index, DPAA2_IPSEC_ERROR_RX,
			       frame->n_vectors);
  if (n_enq)
    vlib_node_increment_counter (vm, node->node_index,
				 DPAA2_IPSEC_ERROR_OFFLOAD, n_enq);
  if (n_ho)
    vlib_node_increment_counter (vm, node->node_index,
				 DPAA2_IPSEC_ERROR_HANDOFF, n_ho);
  if (n_fb)
    vlib_node_increment_counter (vm, node->node_index,
				 DPAA2_IPSEC_ERROR_FALLBACK, n_fb);
  if (n_cop_fail)
    vlib_node_increment_counter (vm, node->node_index,
				 DPAA2_IPSEC_ERROR_COP_ALLOC, n_cop_fail);
  if (n_off - n_enq)
    vlib_node_increment_counter (vm, node->node_index,
				 DPAA2_IPSEC_ERROR_ENQ_FAIL, n_off - n_enq);

  return frame->n_vectors;
}

VLIB_NODE_FN (dpaa2_esp4_encrypt_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return dpaa2_ipsec_offload_inline (vm, node, frame, 0 /* encrypt */);
}

VLIB_NODE_FN (dpaa2_esp6_encrypt_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return dpaa2_ipsec_offload_inline (vm, node, frame, 0 /* encrypt */);
}

VLIB_NODE_FN (dpaa2_esp4_decrypt_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return dpaa2_ipsec_offload_inline (vm, node, frame, 1 /* decrypt */);
}

VLIB_NODE_FN (dpaa2_esp6_decrypt_tun_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return dpaa2_ipsec_offload_inline (vm, node, frame, 1 /* decrypt */);
}

VLIB_REGISTER_NODE (dpaa2_esp4_encrypt_tun_node) = {
  .name = "dpaa2-esp4-encrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_dpaa2_ipsec_trace,
  .n_errors = DPAA2_IPSEC_N_ERROR,
  .error_strings = dpaa2_ipsec_error_strings,
  .n_next_nodes = DPAA2_IPSEC_N_NEXT,
  .next_nodes = {
    [DPAA2_IPSEC_NEXT_FALLBACK] = "esp4-encrypt-tun",
    [DPAA2_IPSEC_NEXT_HANDOFF] = "esp4-encrypt-tun-handoff",
    [DPAA2_IPSEC_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (dpaa2_esp6_encrypt_tun_node) = {
  .name = "dpaa2-esp6-encrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_dpaa2_ipsec_trace,
  .n_errors = DPAA2_IPSEC_N_ERROR,
  .error_strings = dpaa2_ipsec_error_strings,
  .n_next_nodes = DPAA2_IPSEC_N_NEXT,
  .next_nodes = {
    [DPAA2_IPSEC_NEXT_FALLBACK] = "esp6-encrypt-tun",
    [DPAA2_IPSEC_NEXT_HANDOFF] = "esp6-encrypt-tun-handoff",
    [DPAA2_IPSEC_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (dpaa2_esp4_decrypt_tun_node) = {
  .name = "dpaa2-esp4-decrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_dpaa2_ipsec_trace,
  .n_errors = DPAA2_IPSEC_N_ERROR,
  .error_strings = dpaa2_ipsec_error_strings,
  .n_next_nodes = DPAA2_IPSEC_N_NEXT,
  .next_nodes = {
    [DPAA2_IPSEC_NEXT_FALLBACK] = "esp4-decrypt-tun",
    [DPAA2_IPSEC_NEXT_HANDOFF] = "esp4-decrypt-tun-handoff",
    [DPAA2_IPSEC_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (dpaa2_esp6_decrypt_tun_node) = {
  .name = "dpaa2-esp6-decrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_dpaa2_ipsec_trace,
  .n_errors = DPAA2_IPSEC_N_ERROR,
  .error_strings = dpaa2_ipsec_error_strings,
  .n_next_nodes = DPAA2_IPSEC_N_NEXT,
  .next_nodes = {
    [DPAA2_IPSEC_NEXT_FALLBACK] = "esp6-decrypt-tun",
    [DPAA2_IPSEC_NEXT_HANDOFF] = "esp6-decrypt-tun-handoff",
    [DPAA2_IPSEC_NEXT_DROP] = "error-drop",
  },
};

/*
 * Poll node: the split-phase back half. SEC processes enqueued ops
 * asynchronously and DMAs each completed packet back; this per-worker node
 * dequeues those completions and re-injects the packets into the graph.
 *
 * It self-gates like the in-tree async engine's `crypto-deq`: an INTERRUPT
 * INPUT node, quiescent until the demux (producer) arms it on enqueue, and
 * re-arming itself while SEC still holds ops (tracked by w->inflight -- no
 * per-SA refcount). Re-entry mirrors the built-in nodes: a decap'd inner
 * packet routes by its IP version, an encap'd outer packet rides the tunnel's
 * midchain adjacency out.
 */

#define foreach_dpaa2_ipsec_poll_next                                         \
  _ (IP4_INPUT, "ip4-input-no-checksum")                                      \
  _ (IP6_INPUT, "ip6-input")                                                  \
  _ (MIDCHAIN_TX, "adj-midchain-tx")                                          \
  _ (DROP, "error-drop")

typedef enum
{
#define _(n, s) DPAA2_IPSEC_POLL_NEXT_##n,
  foreach_dpaa2_ipsec_poll_next
#undef _
    DPAA2_IPSEC_POLL_N_NEXT,
} dpaa2_ipsec_poll_next_t;

#define foreach_dpaa2_ipsec_poll_error                                        \
  _ (DEQ, "completions dequeued from SEC")                                    \
  _ (AUTH_FAIL, "SEC authentication failed (dropped)")                        \
  _ (STATUS_FAIL, "SEC operation failed (dropped)")

typedef enum
{
#define _(n, s) DPAA2_IPSEC_POLL_ERROR_##n,
  foreach_dpaa2_ipsec_poll_error
#undef _
    DPAA2_IPSEC_POLL_N_ERROR,
} dpaa2_ipsec_poll_error_t;

static char *dpaa2_ipsec_poll_error_strings[] = {
#define _(n, s) s,
  foreach_dpaa2_ipsec_poll_error
#undef _
};

/* Fold the transform SEC applied back into the vlib buffer. SEC moved the
 * packet start (decap strips the outer+ESP, encap prepends them) and set the
 * new length in the mbuf; recover both, using the same computation the dpdk
 * plugin's own RX path uses to derive a vlib buffer from an mbuf
 * (device/node.c) -- and the exact inverse of the enqueue-side sync, since the
 * CMake gate pins RTE_PKTMBUF_HEADROOM == VLIB_BUFFER_PRE_DATA_SIZE.
 * ponytail: single-seg -- rebuilds only the first segment's geometry. SEC
 * returns the ESP packet in one segment for MTU-sized traffic; add a chain
 * walk (next-buffer links + total_length) only if jumbo offload is enabled. */
static_always_inline void
dpaa2_ipsec_buffer_resync (vlib_buffer_t *b, struct rte_mbuf *mb)
{
  b->current_data = mb->data_off - RTE_PKTMBUF_HEADROOM;
  b->current_length = mb->data_len;
}

static_always_inline uword
dpaa2_ipsec_poll_inline (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  u32 thread_index = vm->thread_index;
  dpaa2_ipsec_worker_t *w = (thread_index < vec_len (dm->workers))
			      ? vec_elt_at_index (dm->workers, thread_index)
			      : 0;

  if (w == 0 || w->dev_id == DPAA2_IPSEC_INVALID_U16 || w->inflight == 0)
    return 0;

  struct rte_crypto_op *ops[VLIB_FRAME_SIZE];
  u16 burst = w->inflight < VLIB_FRAME_SIZE ? w->inflight : VLIB_FRAME_SIZE;
  u16 n_deq = rte_cryptodev_dequeue_burst (w->dev_id, w->qp_id, ops, burst);

  if (n_deq == 0)
    {
      /* SEC still holds ops -- stay scheduled until they drain. */
      vlib_node_set_interrupt_pending (vm, node->node_index);
      return 0;
    }

  u32 bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  u32 n_auth_fail = 0, n_status_fail = 0;

  for (u16 i = 0; i < n_deq; i++)
    {
      struct rte_crypto_op *op = ops[i];
      struct rte_mbuf *mb = op->sym->m_src;
      vlib_buffer_t *b = vlib_buffer_from_rte_mbuf (mb);
      u16 next;

      /* D6' SW lever: prefetch a later completion's head while we work the
       * current one, hiding the post-DMA cold miss the HW stash did not cover.
       * ponytail: fixed stride 4; the stride and the stash/prefetch split are
       * tuning knobs measured on-silicon in task 4.1, not constants. */
      if (i + 4 < n_deq)
	CLIB_PREFETCH (rte_pktmbuf_mtod (ops[i + 4]->sym->m_src, void *),
		       CLIB_CACHE_LINE_BYTES, LOAD);

      dpaa2_ipsec_buffer_resync (b, mb);

      if (PREDICT_FALSE (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS))
	{
	  next = DPAA2_IPSEC_POLL_NEXT_DROP;
	  if (op->status == RTE_CRYPTO_OP_STATUS_AUTH_FAILED)
	    n_auth_fail += 1;
	  else
	    n_status_fail += 1;
	}
      else
	{
	  /* Direction is carried per-op via the attached session, not the SA's
	   * IS_INBOUND flag: a tunnel-protect SA is used both ways under one
	   * sa_index and one flag. The op keeps the session we attached (the PMD
	   * preserves op->sym->session), so a decap completion is the one holding
	   * this SA's ingress session. sad_index addresses a stable (never-unmapped)
	   * pool slot even if the SA was deleted in-flight, so the compare is safe. */
	  u32 sad = vnet_buffer (b)->ipsec.sad_index;
	  int is_dec = sad < vec_len (dm->sa_session) &&
		       op->sym->session == dm->sa_session[sad].ingress;
	  if (is_dec)
	    {
	      /* Tunnel decap: SEC handed us the inner packet; route by its IP
	       * version, as the built-in decrypt-tun node does. */
	      u8 *ih = vlib_buffer_get_current (b);
	      next = ((ih[0] >> 4) == 6) ? DPAA2_IPSEC_POLL_NEXT_IP6_INPUT
					 : DPAA2_IPSEC_POLL_NEXT_IP4_INPUT;
	    }
	  else
	    /* Tunnel encap: SEC produced the outer ESP packet; the tunnel
	     * midchain adjacency (still in adj_index[VLIB_TX]) sends it out. */
	    next = DPAA2_IPSEC_POLL_NEXT_MIDCHAIN_TX;

	  /* Feed the core per-SA counter (the one the built-in ESP nodes feed)
	   * so an offloaded SA shows packets/bytes in `show ipsec sa` too. On
	   * completion, successful transforms only, with the on-wire length.
	   * ponytail: per-packet increment; batch same-SA runs only if the perf
	   * pass (4.1) shows it matters. */
	  vlib_increment_combined_counter (&ipsec_sa_counters, thread_index,
					   vnet_buffer (b)->ipsec.sad_index, 1,
					   vlib_buffer_length_in_chain (vm, b));
	}

      bufs[i] = vlib_get_buffer_index (vm, b);
      nexts[i] = next;

      if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  dpaa2_ipsec_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->sa_index = vnet_buffer (b)->ipsec.sad_index;
	  t->offloaded = 1;
	}
    }

  w->inflight -= n_deq;
  rte_mempool_put_bulk (w->cop_pool, (void **) ops, n_deq);

  vlib_buffer_enqueue_to_next (vm, node, bufs, nexts, n_deq);

  vlib_node_increment_counter (vm, node->node_index,
			       DPAA2_IPSEC_POLL_ERROR_DEQ, n_deq);
  if (n_auth_fail)
    vlib_node_increment_counter (vm, node->node_index,
				 DPAA2_IPSEC_POLL_ERROR_AUTH_FAIL, n_auth_fail);
  if (n_status_fail)
    vlib_node_increment_counter (vm, node->node_index,
				 DPAA2_IPSEC_POLL_ERROR_STATUS_FAIL,
				 n_status_fail);

  /* More may still be in SEC -- stay scheduled until inflight hits zero. */
  if (w->inflight)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  return n_deq;
}

VLIB_NODE_FN (dpaa2_ipsec_poll_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return dpaa2_ipsec_poll_inline (vm, node);
}

VLIB_REGISTER_NODE (dpaa2_ipsec_poll_node) = {
  .name = "dpaa2-ipsec-poll",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .format_trace = format_dpaa2_ipsec_trace,
  .n_errors = DPAA2_IPSEC_POLL_N_ERROR,
  .error_strings = dpaa2_ipsec_poll_error_strings,
  .n_next_nodes = DPAA2_IPSEC_POLL_N_NEXT,
  .next_nodes = {
    [DPAA2_IPSEC_POLL_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [DPAA2_IPSEC_POLL_NEXT_IP6_INPUT] = "ip6-input",
    [DPAA2_IPSEC_POLL_NEXT_MIDCHAIN_TX] = "adj-midchain-tx",
    [DPAA2_IPSEC_POLL_NEXT_DROP] = "error-drop",
  },
};

/* Sum one node error counter across all workers, net of the last `clear` --
 * the same read the `show errors` command does. */
static u64
dpaa2_ipsec_sum_error (vlib_main_t *vm, u32 node_index, u32 err)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  u32 idx = n->error_heap_index + err;
  u64 total = 0;

  foreach_vlib_main ()
    {
      vlib_error_main_t *em = &this_vlib_main->error_main;
      u64 c = em->counters[idx];
      if (idx < vec_len (em->counters_last_clear))
	c -= em->counters_last_clear[idx];
      total += c;
    }
  return total;
}

void
dpaa2_ipsec_get_stats (dpaa2_ipsec_stats_t *s)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 demux[4] = {
    dpaa2_esp4_encrypt_tun_node.index,
    dpaa2_esp6_encrypt_tun_node.index,
    dpaa2_esp4_decrypt_tun_node.index,
    dpaa2_esp6_decrypt_tun_node.index,
  };
  u32 poll = dpaa2_ipsec_poll_node.index;

  clib_memset (s, 0, sizeof (*s));

  /* The four demux nodes share one error enum; sum each counter over all of
   * them so the totals are direction/family agnostic. */
  for (int i = 0; i < 4; i++)
    {
      s->rx += dpaa2_ipsec_sum_error (vm, demux[i], DPAA2_IPSEC_ERROR_RX);
      s->offloaded +=
	dpaa2_ipsec_sum_error (vm, demux[i], DPAA2_IPSEC_ERROR_OFFLOAD);
      s->handoff +=
	dpaa2_ipsec_sum_error (vm, demux[i], DPAA2_IPSEC_ERROR_HANDOFF);
      s->fallback +=
	dpaa2_ipsec_sum_error (vm, demux[i], DPAA2_IPSEC_ERROR_FALLBACK);
      s->cop_fallback +=
	dpaa2_ipsec_sum_error (vm, demux[i], DPAA2_IPSEC_ERROR_COP_ALLOC);
      s->enq_drop +=
	dpaa2_ipsec_sum_error (vm, demux[i], DPAA2_IPSEC_ERROR_ENQ_FAIL);
    }

  s->dequeued = dpaa2_ipsec_sum_error (vm, poll, DPAA2_IPSEC_POLL_ERROR_DEQ);
  s->auth_fail =
    dpaa2_ipsec_sum_error (vm, poll, DPAA2_IPSEC_POLL_ERROR_AUTH_FAIL);
  s->status_fail =
    dpaa2_ipsec_sum_error (vm, poll, DPAA2_IPSEC_POLL_ERROR_STATUS_FAIL);
}
