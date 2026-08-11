/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Carlos Aguado.
 *
 * DPAA2 IPsec full-ESP protocol offload: session management.
 *
 * Registers as an ESP offload provider so the core signals it on every SA add
 * and delete. On add of an SA it can offload, it builds an rte_security
 * lookaside-protocol session -- carrying the SA's real ESN, anti-replay window,
 * UDP-encap and tunnel TTL/DSCP/DF settings, never a weaker hardcoded default --
 * and caches it by sa_index. On delete it destroys that session, so the session
 * lifetime is exactly the SA lifetime and nothing leaks.
 *
 * SAs the device cannot honour (transport mode, IPv6 tunnel until proven, an
 * over-large anti-replay window, an unsupported algorithm, no SECURITY device)
 * are declined here and left on the async cryptodev fallback path -- reported,
 * never silently downgraded.
 */

#include <vlib/vlib.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_funcs.h>

#include <dpdk/device/dpdk.h>
#undef always_inline
#include <rte_cryptodev.h>
#include <rte_security.h>
#include <rte_crypto_sym.h>
#include <rte_mempool.h>
#include <rte_config.h>

#include "dpaa2_ipsec.h"

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#define log_notice(...)                                                       \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, dpaa2_ipsec_main.log_class, __VA_ARGS__)
#define log_debug(...)                                                        \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dpaa2_ipsec_main.log_class, __VA_ARGS__)

#define DPAA2_IPSEC_N_SESSIONS 4096

static_always_inline int
alg_is_aead (ipsec_crypto_alg_t a)
{
  return (a == IPSEC_CRYPTO_ALG_AES_GCM_128 ||
	  a == IPSEC_CRYPTO_ALG_AES_GCM_192 ||
	  a == IPSEC_CRYPTO_ALG_AES_GCM_256);
}

/* Build the AEAD (AES-GCM) crypto xform from the SA. Returns 0 on success,
 * -1 if the algorithm is not one we offload. */
static int
build_aead_xform (struct rte_crypto_sym_xform *x, ipsec_sa_t *sa, int is_out)
{
  if (!alg_is_aead (sa->crypto_alg))
    return -1;

  x->type = RTE_CRYPTO_SYM_XFORM_AEAD;
  x->aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
  x->aead.op =
    is_out ? RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT;
  x->aead.key.data = sa->crypto_key.data;
  x->aead.key.length = sa->crypto_key.len;
  /* Lookaside-protocol: the PMD generates and places the ESP IV, so iv.offset
   * is not a per-op buffer offset here; only the length matters. GCM nonce is
   * 4B salt + 8B IV = 12B. */
  x->aead.iv.offset = 0;
  x->aead.iv.length = 12;
  x->aead.digest_length = 16;
  /* ESP AAD is the ESP header (SPI+seq), 8B, or 12B with extended seq. */
  x->aead.aad_length = ipsec_sa_is_set_USE_ESN (sa) ? 12 : 8;
  x->next = NULL;
  return 0;
}

static int
build_cipher_xform (struct rte_crypto_sym_xform *x, ipsec_sa_t *sa, int is_out)
{
  enum rte_crypto_cipher_algorithm algo;
  u16 iv_len;

  switch (sa->crypto_alg)
    {
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
      algo = RTE_CRYPTO_CIPHER_AES_CBC;
      iv_len = 16;
      break;
    case IPSEC_CRYPTO_ALG_AES_CTR_128:
    case IPSEC_CRYPTO_ALG_AES_CTR_192:
    case IPSEC_CRYPTO_ALG_AES_CTR_256:
      algo = RTE_CRYPTO_CIPHER_AES_CTR;
      iv_len = 16;
      break;
    case IPSEC_CRYPTO_ALG_DES_CBC:
      algo = RTE_CRYPTO_CIPHER_DES_CBC;
      iv_len = 8;
      break;
    case IPSEC_CRYPTO_ALG_3DES_CBC:
      algo = RTE_CRYPTO_CIPHER_3DES_CBC;
      iv_len = 8;
      break;
    default:
      return -1;
    }

  x->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  x->cipher.algo = algo;
  x->cipher.op =
    is_out ? RTE_CRYPTO_CIPHER_OP_ENCRYPT : RTE_CRYPTO_CIPHER_OP_DECRYPT;
  x->cipher.key.data = sa->crypto_key.data;
  x->cipher.key.length = sa->crypto_key.len;
  x->cipher.iv.offset = 0;
  x->cipher.iv.length = iv_len;
  x->next = NULL;
  return 0;
}

static int
build_auth_xform (struct rte_crypto_sym_xform *x, ipsec_sa_t *sa, int is_out)
{
  enum rte_crypto_auth_algorithm algo;
  u16 digest;

  switch (sa->integ_alg)
    {
    case IPSEC_INTEG_ALG_SHA1_96:
      algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
      digest = 12;
      break;
    case IPSEC_INTEG_ALG_SHA_256_128:
      algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
      digest = 16;
      break;
    case IPSEC_INTEG_ALG_SHA_384_192:
      algo = RTE_CRYPTO_AUTH_SHA384_HMAC;
      digest = 24;
      break;
    case IPSEC_INTEG_ALG_SHA_512_256:
      algo = RTE_CRYPTO_AUTH_SHA512_HMAC;
      digest = 32;
      break;
    default:
      /* md5-96 and the truncated sha-256-96 are not offloaded (the latter is
       * documented not to work with lookaside proto); fall back. */
      return -1;
    }

  x->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  x->auth.algo = algo;
  x->auth.op = is_out ? RTE_CRYPTO_AUTH_OP_GENERATE : RTE_CRYPTO_AUTH_OP_VERIFY;
  x->auth.key.data = sa->integ_key.data;
  x->auth.key.length = sa->integ_key.len;
  x->auth.digest_length = digest;
  x->next = NULL;
  return 0;
}

/* Assemble the crypto xform chain for the SA into caller-provided storage: one
 * xform for AEAD, a two-link chain (ordered per direction) for cipher+auth.
 * Returns the head, or 0 if any algorithm is unsupported. */
static struct rte_crypto_sym_xform *
build_crypto_xform (struct rte_crypto_sym_xform *primary,
		    struct rte_crypto_sym_xform *secondary, ipsec_sa_t *sa,
		    int is_out)
{
  if (alg_is_aead (sa->crypto_alg))
    return build_aead_xform (primary, sa, is_out) ? 0 : primary;

  if (build_cipher_xform (primary, sa, is_out) ||
      build_auth_xform (secondary, sa, is_out))
    return 0;

  /* Encrypt-then-... on egress cipher first; on ingress authenticate first. */
  if (is_out)
    {
      primary->next = secondary;
      return primary;
    }
  secondary->next = primary;
  return secondary;
}

/* The anti-replay window the SA requested, read from its inbound runtime state
 * (every SA has one, allocated regardless of direction). 0 when anti-replay is off.
 * Do NOT gate on IS_INBOUND: a tunnel-protect sa-in is not flagged inbound -- its
 * role is assigned by the protect, not by `ipsec sa add ... inbound` -- so that gate
 * would drop the window to 0 and leave the SEC session with no replay check (the PMD
 * arms its ARS window only for a non-zero replay_win_sz). Gate on USE_ANTI_REPLAY,
 * the real config bit; the caller applies the window to the ingress session only. */
static u32
sa_anti_replay_window (ipsec_sa_t *sa)
{
  ipsec_sa_inb_rt_t *irt;

  if (!ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
    return 0;

  irt = ipsec_sa_get_inb_rt (sa);
  return irt ? irt->anti_replay_window_size : 0;
}

int
dpaa2_ipsec_offload_gate (ipsec_sa_t *sa, dpaa2_ipsec_fallback_reason_t *reason)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  struct rte_crypto_sym_xform a, b;

  /* Both tunnel families are offered to the device: v6 was unproven, not
   * unsupported, so we no longer refuse it here -- if SEC cannot build a v6
   * session, session-create fails and the SA falls back with SESSION_CREATE_FAILED
   * (a dynamic, per-device gate). build_crypto_xform doubles as the algorithm
   * validator: nonzero => the alg maps to a session we can build. */
  int alg_offloadable =
    build_crypto_xform (&a, &b, sa, 1 /* is_out, just to validate */) != 0;

  /* Reduce the SA + device state to the plain inputs of the pure predicate,
   * which takes no packet size/rate (routing cannot be steered by traffic). */
  return dpaa2_ipsec_gate_decide (
    dm->offload_disabled, dm->have_security_dev,
    sa->protocol == IPSEC_PROTOCOL_ESP, ipsec_sa_is_set_IS_TUNNEL (sa),
    alg_offloadable, sa_anti_replay_window (sa), reason);
}

/* Lazily create the shared rte_security session mempool on the SECURITY device.
 * Returns 0 on success. */
static int
ensure_session_pool (void)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  void *sec_ctx;
  struct rte_mempool *mp;
  unsigned sess_sz;

  if (dm->session_pool)
    return 0;

  sec_ctx = rte_cryptodev_get_sec_ctx (dm->sec_dev_id);
  if (!sec_ctx)
    return -1;

  sess_sz = rte_security_session_get_size (sec_ctx);
  mp = rte_mempool_create ("dpaa2_ipsec_sess", DPAA2_IPSEC_N_SESSIONS, sess_sz,
			   0, 0, NULL, NULL, NULL, NULL,
			   rte_cryptodev_socket_id (dm->sec_dev_id), 0);
  if (!mp)
    return -1;

  dm->session_pool = mp;
  return 0;
}

/* Build and create the rte_security lookaside-protocol session for an SA in one
 * direction. SEC sessions are directional, so a tunnel-protect SA used both ways
 * needs both; the caller builds one per direction. */
static void *
session_create (ipsec_sa_t *sa, int is_out)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  struct rte_crypto_sym_xform primary = { 0 }, secondary = { 0 }, *xfs;
  struct rte_security_session_conf conf = { 0 };
  void *sec_ctx;

  xfs = build_crypto_xform (&primary, &secondary, sa, is_out);
  if (!xfs)
    return NULL;

  if (ensure_session_pool ())
    return NULL;

  conf.action_type = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL;
  conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
  conf.crypto_xform = xfs;
  conf.ipsec.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
  conf.ipsec.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
  conf.ipsec.direction = is_out ? RTE_SECURITY_IPSEC_SA_DIR_EGRESS
				: RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
  conf.ipsec.spi = sa->spi;
  /* salt is stored in network byte order on the SA, and the dpaa2_sec PMD copies
   * conf.ipsec.salt's raw 4 bytes straight into the GCM nonce prefix
   * (memcpy(gcm.salt, &ipsec_xform->salt, 4), dpaa2_sec_dpseci.c). So pass it RAW
   * -- byte-swapping here reverses the nonce salt and every GCM ICV fails (CBC has
   * no salt, so it was unaffected, which masked this until the KAT). */
  conf.ipsec.salt = sa->salt;

  /* Real security semantics from the SA -- not zeroed defaults. */
  conf.ipsec.options.esn = ipsec_sa_is_set_USE_ESN (sa) ? 1 : 0;
  conf.ipsec.options.udp_encap = ipsec_sa_is_set_UDP_ENCAP (sa) ? 1 : 0;
  conf.ipsec.options.copy_df =
    (sa->tunnel.t_encap_decap_flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DF) ? 1
									      : 0;
  conf.ipsec.options.copy_dscp =
    (sa->tunnel.t_encap_decap_flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
      ? 1
      : 0;
  /* Anti-replay is an ingress-only check (egress assigns the sequence, never
   * replay-checks it), so arm the window on the INGRESS session only. */
  conf.ipsec.replay_win_sz = is_out ? 0 : sa_anti_replay_window (sa);

  /* Outer header: match the SA's tunnel family. The dpaa2_sec descriptor carries
   * the whole outer, so a v6 tunnel must build a v6 conf -- populating the v4
   * union arm for a v6 SA would emit a bogus 20-byte v4 outer over a v6 inner. */
  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
    {
      conf.ipsec.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV6;
      clib_memcpy_fast (&conf.ipsec.tunnel.ipv6.src_addr,
			&sa->tunnel.t_src.ip.ip6, 16);
      clib_memcpy_fast (&conf.ipsec.tunnel.ipv6.dst_addr,
			&sa->tunnel.t_dst.ip.ip6, 16);
      conf.ipsec.tunnel.ipv6.dscp = sa->tunnel.t_dscp;
      conf.ipsec.tunnel.ipv6.hlimit =
	sa->tunnel.t_hop_limit ? sa->tunnel.t_hop_limit : 64;
    }
  else
    {
      conf.ipsec.tunnel.type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
      clib_memcpy_fast (&conf.ipsec.tunnel.ipv4.src_ip,
			&sa->tunnel.t_src.ip.ip4.as_u32, 4);
      clib_memcpy_fast (&conf.ipsec.tunnel.ipv4.dst_ip,
			&sa->tunnel.t_dst.ip.ip4.as_u32, 4);
      conf.ipsec.tunnel.ipv4.dscp = sa->tunnel.t_dscp;
      /* Outer TTL from config; copy-from-inner default (64) when not set. */
      conf.ipsec.tunnel.ipv4.ttl =
	sa->tunnel.t_hop_limit ? sa->tunnel.t_hop_limit : 64;
    }

  sec_ctx = rte_cryptodev_get_sec_ctx (dm->sec_dev_id);
  return rte_security_session_create (sec_ctx, &conf, dm->session_pool);
}

static void
sa_session_cache_set (u32 sa_index, void *egress, void *ingress,
		      dpaa2_ipsec_route_decision_t decision, u8 reason)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;

  vec_validate (dm->sa_session, sa_index);
  vec_validate (dm->sa_route, sa_index);
  /* Fresh slot: new sessions, zero in-flight. A previous tenant's still-draining
   * sessions live on their owning worker's pending-destroy list, keyed by pointer,
   * not in this slot -- so reusing the slot here can never disturb them. */
  dm->sa_session[sa_index] = (dpaa2_ipsec_sa_sess_t){
    .egress = egress,
    .ingress = ingress,
  };
  dm->sa_route[sa_index].decision = decision;
  dm->sa_route[sa_index].reason = reason;
}

/* Tear down one direction's session on SA delete. If SEC holds no ops for it,
 * destroy now. Otherwise hand it to its owning worker's pending-destroy list, which
 * frees it once its own ops drain -- destroying now would rte_free() the flow context
 * SEC is still reading (a use-after-free). Runs under the worker barrier, so the
 * inflight snapshot is stable and the append is race-free. */
static void
dpaa2_ipsec_defer_or_destroy (u32 sa_index, void *session, int is_ingress,
			      u32 inflight)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  void *sec_ctx = rte_cryptodev_get_sec_ctx (dm->sec_dev_id);

  if (inflight == 0)
    {
      rte_security_session_destroy (sec_ctx, session);
      return;
    }

  /* The direction's pinned worker (set on first packet; always valid when
   * inflight>0) owns the queue-pair these ops complete on, so its poll node is the
   * one that will retire the session. */
  clib_thread_index_t ti =
    is_ingress ? ipsec_sa_get_inb_rt_by_index (sa_index)->thread_index
	       : ipsec_sa_get_outb_rt_by_index (sa_index)->thread_index;
  if (ti == (clib_thread_index_t) ~0 || ti >= vec_len (dm->workers))
    {
      /* No owning worker to drain it (should not happen with inflight>0). A safe
       * leak beats a use-after-free: leave the session allocated. */
      log_notice ("SA %u: %u ops in flight but no owning worker; leaking session",
		  sa_index, inflight);
      return;
    }
  dpaa2_ipsec_pending_destroy_t p = {
    .session = session,
    .remaining = inflight,
    .is_ingress = (u8) is_ingress,
  };
  vec_add1 (dm->workers[ti].pending_destroy, p);
  dm->sessions_deferred += 1;
}

/* --- ESP offload provider callbacks --- */

static int
dpaa2_ipsec_check_support (ipsec_sa_t *sa)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  dpaa2_ipsec_fallback_reason_t reason;

  /* First SA add is a safe point to scan and place workers: the cryptodev
   * engine has configured and started the device by now, claiming its
   * queue-pairs, so base_qp lands past them. */
  if (!dm->scanned)
    {
      dpaa2_ipsec_scan_devs ();
      dpaa2_ipsec_place_workers ();
      dm->scanned = 1;
    }

  return dpaa2_ipsec_offload_gate (sa, &reason);
}

static void
dpaa2_ipsec_session_add_del (u32 sa_index, int is_add)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  void *sec_ctx = rte_cryptodev_get_sec_ctx (dm->sec_dev_id);

  if (is_add)
    {
      /* Reached only when check_support accepted the SA. Build one session per
       * direction: the SA may be sa-out on one tunnel and sa-in on another, and
       * SEC sessions are directional. */
      ipsec_sa_t *sa = ipsec_sa_get (sa_index);
      void *egress = session_create (sa, 1 /* is_out */);
      void *ingress = session_create (sa, 0 /* is_out */);

      if (!egress || !ingress)
	{
	  /* Offload only if both directions build; offloading one while the
	   * other silently double-transforms would corrupt traffic. Destroy the
	   * survivor and leave the whole SA on fallback. */
	  if (egress)
	    rte_security_session_destroy (sec_ctx, egress);
	  if (ingress)
	    rte_security_session_destroy (sec_ctx, ingress);
	  sa_session_cache_set (sa_index, NULL, NULL,
				DPAA2_IPSEC_ROUTE_FALLBACK,
				DPAA2_IPSEC_FALLBACK_SESSION_CREATE_FAILED);
	  log_notice ("SA %u: security session create failed, using fallback",
		      sa_index);
	  return;
	}

      sa_session_cache_set (sa_index, egress, ingress,
			    DPAA2_IPSEC_ROUTE_OFFLOAD,
			    DPAA2_IPSEC_FALLBACK_NONE);
      log_debug ("SA %u: offload sessions created (egress+ingress)", sa_index);
    }
  else
    {
      /* Broadcast delete: only act if we owned sessions for this SA. */
      if (sa_index >= vec_len (dm->sa_session) ||
	  (!dm->sa_session[sa_index].egress &&
	   !dm->sa_session[sa_index].ingress))
	return;

      /* Destroy each direction now if idle, else defer it to its owning worker's
       * pending-destroy list (keyed by session pointer). Then CLEAR the slot: the
       * deferred sessions no longer live here, they live on the worker list, so the
       * slot is immediately safe to reuse. A straggler for a deferred session is
       * matched by pointer against that list, never against whatever SA reuses this
       * slot -- so the reused SA's in-flight counters are never corrupted (no
       * second-order use-after-free) and the old session is freed exactly when its
       * last op drains (no leak). */
      dpaa2_ipsec_sa_sess_t *s = &dm->sa_session[sa_index];
      u64 deferred = dm->sessions_deferred;
      if (s->egress)
	dpaa2_ipsec_defer_or_destroy (sa_index, s->egress, 0, s->egress_inflight);
      if (s->ingress)
	dpaa2_ipsec_defer_or_destroy (sa_index, s->ingress, 1, s->ingress_inflight);

      *s = (dpaa2_ipsec_sa_sess_t){ 0 };
      dm->sa_route[sa_index].decision = DPAA2_IPSEC_ROUTE_UNDECIDED;
      dm->sa_route[sa_index].reason = DPAA2_IPSEC_FALLBACK_NONE;

      if (dm->sessions_deferred != deferred)
	log_debug ("SA %u: session teardown deferred until in-flight ops drain",
		   sa_index);
      else
	log_debug ("SA %u: offload sessions destroyed", sa_index);
    }
}

void
dpaa2_ipsec_session_init (void)
{
  ipsec_esp_offload_provider_t provider = {
    .name = "dpaa2-sec",
    .check_support = dpaa2_ipsec_check_support,
    .session_add_del = dpaa2_ipsec_session_add_del,
  };

  ipsec_register_esp_offload_provider (vlib_get_main (), &provider);
}
