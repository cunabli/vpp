/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Carlos Aguado.
 *
 * DPAA2 IPsec full-ESP protocol offload: data model.
 *
 * The SEC block (dpseci / dpaa2_sec PMD) can own the entire ESP transform via
 * rte_security lookaside-protocol -- encap/decap, encryption, IV and sequence
 * bookkeeping, anti-replay -- not just the crypto primitive. This plugin steers
 * eligible tunnel SAs to SEC and leaves every other SA on the upstream async
 * cryptodev engine, which stays enabled as the fallback path. The two coexist
 * on one dpseci by partitioning its queue-pairs (see base_qp).
 *
 * The offload/fallback choice is a per-SA property, decided once and fixed for
 * the SA's lifetime. It is never made per-packet: SEC owns the SA's sequence
 * number and anti-replay window, so routing individual packets of one SA to
 * different engines (e.g. by size) would split that state and open a replay
 * hole. Offload is therefore a capability decision plus a global on/off lever
 * (offload_disabled), not a per-packet size gate.
 */
#ifndef __DPAA2_IPSEC_H__
#define __DPAA2_IPSEC_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ipsec/ipsec_sa.h>

#define DPAA2_IPSEC_INVALID_U16 ((u16) ~0)

/* Per-SA routing decision, cached by sa_index. UNDECIDED means not yet
 * resolved; the decision is taken lazily (on session create / first packet). */
typedef enum
{
  DPAA2_IPSEC_ROUTE_UNDECIDED = 0,
  DPAA2_IPSEC_ROUTE_OFFLOAD,
  DPAA2_IPSEC_ROUTE_FALLBACK,
} dpaa2_ipsec_route_decision_t;

/* The fallback-reason enum and the pure routing predicate live in a freestanding
 * header (no VPP/DPDK deps) so the routing decision is host-unit-testable. */
#include "dpaa2_ipsec_gate_decision.h"

/* Per-SA routing cache entry (vec indexed by sa_index). */
typedef struct
{
  u8 decision; /* dpaa2_ipsec_route_decision_t */
  u8 reason;   /* dpaa2_ipsec_fallback_reason_t */
} dpaa2_ipsec_sa_route_t;

/* Per-SA rte_security sessions, one per direction (opaque rte_security_session*).
 * The demux picks egress on the encrypt path, ingress on the decrypt path. */
typedef struct
{
  void *egress;
  void *ingress;
  /* Ops enqueued to SEC for each direction's session, not yet completed. The
   * session's flow context is DMA memory the hardware reads mid-op, so the
   * session must not be destroyed while its count is nonzero. Single-writer per
   * counter: a direction's enqueue (demux) and completion (poll) both run on
   * that direction's pinned worker. On delete this snapshot becomes the deferred
   * entry's remaining count (see dpaa2_ipsec_pending_destroy_t). */
  u32 egress_inflight;
  u32 ingress_inflight;
} dpaa2_ipsec_sa_sess_t;

/* A session whose SA was deleted while SEC still held ops for it: it is destroyed
 * only when its own ops drain (remaining hits zero), NOT when the SA's cache slot
 * empties. Keyed by the session pointer (op->sym->session, which the PMD preserves
 * on completion), so a straggler is matched here even after its cache slot has been
 * reused by a new SA -- which is what makes reuse-before-drain safe: the new SA's
 * in-flight counters are never touched by an old op, and the old session is freed
 * exactly when the last op referencing it completes (no leak, no use-after-free).
 * Held on the owning worker's list (the direction's pinned thread), so the poll node
 * retires it lock-free; the main thread only appends under the worker barrier. */
typedef struct
{
  void *session;   /* rte_security_session* awaiting its ops to drain */
  u32 remaining;   /* ops still in SEC for this session */
  u8 is_ingress;   /* direction, for routing its straggler completions */
} dpaa2_ipsec_pending_destroy_t;

/* Per-device capability record, one per rte_cryptodev. Offload availability is
 * a per-device property (does it advertise the SECURITY feature), not a global
 * switch, so a mix of SECURITY-capable and plain crypto devices routes SAs
 * correctly. base_qp splits the device's queue-pairs between the two engines:
 * rte_cryptodev_configure is a device-global reset, so only the async cryptodev
 * engine configures/starts the device and claims [0 .. base_qp-1]; offload
 * attaches to the already-set-up pairs [base_qp .. base_qp+n_offload_qp-1],
 * preserving the lock-free one-worker-to-one-queue-pair invariant. */
typedef struct
{
  u16 dev_id;
  u8 driver_id;
  u8 numa;
  u16 max_qp;	/* queue-pairs the dpseci was created with */
  u8 security;	/* advertises rte_security protocol offload */
  u64 feature_flags;
  const char *name;
  u16 base_qp;	    /* first queue-pair offload may claim (see above) */
  u16 n_offload_qp; /* queue-pairs left for offload past base_qp */
} dpaa2_ipsec_dev_t;

/* Per-worker SEC placement, indexed by vlib thread index. One SA is pinned to
 * one worker's queue-pair for its lifetime: SEC holds the SA's sequence and
 * anti-replay state, so splitting the SA across queue-pairs would corrupt the
 * replay window and reorder within the SA. dev_id == INVALID means this worker
 * has no SEC queue-pair. cop_pool and inflight are per-worker so both the
 * enqueue (demux) and dequeue (poll) sides run lock-free: the SPSC pairing of
 * one worker to one queue-pair. */
typedef struct
{
  u16 dev_id;
  u16 qp_id;
  void *cop_pool; /* crypto-op mempool (opaque rte_mempool*), lazily created */
  u16 inflight;	  /* ops enqueued to this qp, not yet dequeued back */
  /* Sessions of deleted SAs whose ops are still draining on this worker's qp. The
   * poll node retires each as its stragglers complete; the main thread appends here
   * under the worker barrier. */
  dpaa2_ipsec_pending_destroy_t *pending_destroy;
} dpaa2_ipsec_worker_t;

typedef struct
{
  dpaa2_ipsec_dev_t *devs;	 /* per-device capability records */
  dpaa2_ipsec_worker_t *workers; /* per-thread SEC placement, by thread */
  /* Thread indices of the workers that own a SEC queue-pair; an offloaded SA
   * must pin to one of these, keeping thread-assignment in the qp-owning set. */
  u16 *qp_workers;
  u32 qp_rr; /* round-robin cursor over qp_workers, for non-qp-local SAs */
  dpaa2_ipsec_sa_route_t *sa_route; /* per-SA routing cache, by sa_index */
  /* Per-SA rte_security sessions, one per direction (SEC sessions are
   * directional; a tunnel-protect SA can be sa-out on one tunnel and sa-in on
   * another), indexed by sa_index. Both NULL when the SA is not offloaded. */
  dpaa2_ipsec_sa_sess_t *sa_session;

  void *session_pool; /* rte_security session mempool, created on first use */
  /* Device sessions are created on; INVALID until the scan finds a
   * SECURITY-capable device. Single-device for now. */
  u16 sec_dev_id;

  /* When set, SEC ESP offload is disabled and every SA uses the async fallback;
   * default 0 (offload enabled, capability-only). Global on/off lever -- there
   * is deliberately no per-packet size gate (see the file header). */
  u8 offload_disabled;
  u8 have_security_dev; /* scan found a SECURITY-capable device */
  u8 scanned;		/* one-time lazy device scan + placement done */

  /* Deferred-teardown observability (task 3.5): a session freed while SEC still
   * held ops for it is deferred, then destroyed by the poll node once its
   * in-flight drains. Counted so the delete-under-traffic path is visible in
   * `show ipsec offload` -- deferred should equal drained once traffic quiesces. */
  u64 sessions_deferred; /* teardowns deferred because ops were in flight */
  u64 sessions_drained;  /* deferred teardowns the poll node later completed */

  vlib_log_class_t log_class;
} dpaa2_ipsec_main_t;

extern dpaa2_ipsec_main_t dpaa2_ipsec_main;

/* Enumerate rte_cryptodevs into per-device capability records; sets
 * have_security_dev. Safe to call when no crypto device exists (no-op). */
void dpaa2_ipsec_scan_devs (void);

/* Assign each vlib worker a SEC queue-pair on a SECURITY-capable device and
 * compute each device's base_qp offset past the async engine's claim. */
void dpaa2_ipsec_place_workers (void);

/* Pick the worker thread an offloaded SA should be pinned to. Prefers the
 * caller's own thread when it owns a queue-pair (the SA then runs entirely
 * local, no handoff); otherwise round-robins across the qp-owning workers so an
 * SA first seen on a non-qp worker still lands on hardware. Returns the caller's
 * thread unchanged when no worker owns a queue-pair (the SA falls back). */
u16 dpaa2_ipsec_assign_offload_thread (u32 thread_index);

/* Single source of truth for the per-SA offload decision. Returns nonzero if
 * the SA can be offloaded; on a zero return, *reason says why it falls back.
 * Consulted by the provider's check_support and by the show command. */
int dpaa2_ipsec_offload_gate (ipsec_sa_t *sa,
			      dpaa2_ipsec_fallback_reason_t *reason);

/* Register as an ESP offload provider and create the session mempool. Called
 * from init once a SECURITY-capable device is present. */
void dpaa2_ipsec_session_init (void);

/* Plugin-wide packet totals, summed across workers from the demux and poll node
 * counters. Read-only view for the show command. */
typedef struct
{
  u64 rx;	    /* packets that reached the demux nodes */
  u64 offloaded;    /* enqueued to SEC */
  u64 handoff;	    /* sent to the SA's pinned worker */
  u64 fallback;	    /* routed to the software path */
  u64 cop_fallback; /* fell back because a crypto op could not be allocated */
  u64 enq_drop;	    /* dropped because the SEC queue-pair was full */
  u64 dequeued;	    /* completions taken back from SEC */
  u64 auth_fail;    /* SEC reported an authentication failure */
  u64 status_fail;  /* SEC reported any other operation failure */
  /* PMD-side qp counters (rte_cryptodev_stats_get, device-wide). Cross-checked
   * against the plugin totals to localize an enqueue wedge: pmd_enq_err climbing
   * while pmd_deq trails pmd_enq points at the queue-pair/portal, not the plugin. */
  u64 pmd_enq;	    /* FDs the PMD accepted (enqueued_count) */
  u64 pmd_enq_err;  /* FDs the PMD could not post (enqueue_err_count) */
  u64 pmd_deq;	    /* completions the PMD returned (dequeued_count) */
  u64 pmd_deq_err;  /* error completions (dequeue_err_count) */
} dpaa2_ipsec_stats_t;

/* Sum the demux + poll node counters across all workers into *s. Defined in the
 * node file, which owns the counter indices. */
void dpaa2_ipsec_get_stats (dpaa2_ipsec_stats_t *s);

#endif /* __DPAA2_IPSEC_H__ */
