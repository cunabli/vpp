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

#define DPAA2_IPSEC_INVALID_U16 ((u16) ~0)

/* Per-SA routing decision, cached by sa_index. UNDECIDED means not yet
 * resolved; the decision is taken lazily (on session create / first packet). */
typedef enum
{
  DPAA2_IPSEC_ROUTE_UNDECIDED = 0,
  DPAA2_IPSEC_ROUTE_OFFLOAD,
  DPAA2_IPSEC_ROUTE_FALLBACK,
} dpaa2_ipsec_route_decision_t;

/* Why an SA is on the fallback path -- surfaced by the show command to prove
 * unsupported configs fall back rather than run with weaker security. NONE
 * means the SA is offloaded. */
#define foreach_dpaa2_ipsec_fallback_reason                                   \
  _ (NONE, "offloaded")                                                       \
  _ (DISABLED, "SEC ESP offload disabled by configuration")                   \
  _ (NO_SECURITY_DEV, "no SECURITY-capable cryptodev for this SA")            \
  _ (UNSUPPORTED_CONFIG, "SA config not accepted by rte_security")            \
  _ (WINDOW_TOO_LARGE, "anti-replay window exceeds device maximum")           \
  _ (FAMILY_UNPROVEN, "IPv6 tunnel not yet proven on this device")            \
  _ (SESSION_CREATE_FAILED, "rte_security session create failed")

typedef enum
{
#define _(f, s) DPAA2_IPSEC_FALLBACK_##f,
  foreach_dpaa2_ipsec_fallback_reason
#undef _
    DPAA2_IPSEC_FALLBACK_N_REASON,
} dpaa2_ipsec_fallback_reason_t;

/* Per-SA routing cache entry (vec indexed by sa_index). */
typedef struct
{
  u8 decision; /* dpaa2_ipsec_route_decision_t */
  u8 reason;   /* dpaa2_ipsec_fallback_reason_t */
} dpaa2_ipsec_sa_route_t;

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
 * has no SEC queue-pair. */
typedef struct
{
  u16 dev_id;
  u16 qp_id;
} dpaa2_ipsec_worker_t;

typedef struct
{
  dpaa2_ipsec_dev_t *devs;	    /* per-device capability records */
  dpaa2_ipsec_worker_t *workers;    /* per-thread SEC placement, by thread */
  dpaa2_ipsec_sa_route_t *sa_route; /* per-SA routing cache, by sa_index */

  /* When set, SEC ESP offload is disabled and every SA uses the async fallback;
   * default 0 (offload enabled, capability-only). Global on/off lever -- there
   * is deliberately no per-packet size gate (see the file header). */
  u8 offload_disabled;
  u8 have_security_dev; /* scan found a SECURITY-capable device */

  vlib_log_class_t log_class;
} dpaa2_ipsec_main_t;

extern dpaa2_ipsec_main_t dpaa2_ipsec_main;

/* Enumerate rte_cryptodevs into per-device capability records; sets
 * have_security_dev. Safe to call when no crypto device exists (no-op). */
void dpaa2_ipsec_scan_devs (void);

/* Assign each vlib worker a SEC queue-pair on a SECURITY-capable device and
 * compute each device's base_qp offset past the async engine's claim. */
void dpaa2_ipsec_place_workers (void);

#endif /* __DPAA2_IPSEC_H__ */
