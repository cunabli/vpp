/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Carlos Aguado.
 *
 * DPAA2 IPsec full-ESP protocol offload: device scan, worker placement, and
 * startup.conf configuration.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>

/* Include the plugin header (and the vnet headers it pulls in, which use the
 * always_inline macro) before DPDK undefines that macro for its own headers. */
#include "ipsec.h"
/* The ESP offload provider registration API; also uses the always_inline
 * macro, so keep it above the undef. */
#include <vnet/ipsec/ipsec.h>

#include <dpdk/device/dpdk.h>
#undef always_inline
#include <rte_cryptodev.h>
#include <rte_config.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

dpaa2_ipsec_main_t dpaa2_ipsec_main;

VLIB_REGISTER_LOG_CLASS (dpaa2_ipsec_log, static) = {
  .class_name = "dpdk",
  .subclass_name = "dpaa2-ipsec",
};

#define log_notice(...)                                                       \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, dpaa2_ipsec_log.class, __VA_ARGS__)
#define log_debug(...)                                                        \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dpaa2_ipsec_log.class, __VA_ARGS__)

void
dpaa2_ipsec_scan_devs (void)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  u32 n = rte_cryptodev_count ();

  vec_reset_length (dm->devs);
  dm->have_security_dev = 0;
  dm->sec_dev_id = DPAA2_IPSEC_INVALID_U16;

  for (u32 i = 0; i < n; i++)
    {
      struct rte_cryptodev_info info;
      dpaa2_ipsec_dev_t *dev;

      rte_cryptodev_info_get (i, &info);

      vec_add2 (dm->devs, dev, 1);
      dev->dev_id = i;
      dev->driver_id = info.driver_id;
      dev->numa = rte_cryptodev_socket_id (i);
      dev->max_qp = info.max_nb_queue_pairs;
      dev->feature_flags = info.feature_flags;
      dev->name = rte_cryptodev_name_get (i);
      dev->security = (info.feature_flags & RTE_CRYPTODEV_FF_SECURITY) ? 1 : 0;
      dev->base_qp = DPAA2_IPSEC_INVALID_U16;
      dev->n_offload_qp = 0;

      if (dev->security)
	{
	  dm->have_security_dev = 1;
	  if (dm->sec_dev_id == DPAA2_IPSEC_INVALID_U16)
	    dm->sec_dev_id = i;
	}

      log_debug ("cryptodev %u (%s): %u qp, protocol offload %s", i,
		 dev->name, dev->max_qp,
		 dev->security ? "supported" : "not supported");
    }

  if (!dm->have_security_dev)
    log_notice ("no SECURITY-capable cryptodev found; all SAs use fallback");
}

/* Pin each worker to one queue-pair (the SPSC invariant). This also delivers
 * hardware completion stashing for free: the DPAA2 bus sets each DPIO portal's stash
 * destination to the core of the thread that first drives it
 * (dpaa2_configure_stashing -> dpio_set_stashing_destination, an internal DPDK
 * symbol not callable from here). Because a worker both enqueues (demux) and
 * dequeues (poll node) its own queue-pair, the portal affines to that worker's
 * core and SEC stashes completions straight into it -- no plugin code, and no
 * device/init.c change; it falls out of keeping one worker to one queue-pair. */
void
dpaa2_ipsec_place_workers (void)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 skip_main = vlib_num_workers () > 0;
  u32 n_workers = tm->n_vlib_mains - skip_main;
  dpaa2_ipsec_dev_t *dev;
  u32 worker = 0; /* relative worker index, 0 .. n_workers-1 */

  /* Every worker starts with no SEC queue-pair; SAs on an unplaced worker fall
   * back. */
  vec_validate (dm->workers, tm->n_vlib_mains - 1);
  for (u32 t = 0; t < vec_len (dm->workers); t++)
    {
      dm->workers[t].dev_id = DPAA2_IPSEC_INVALID_U16;
      dm->workers[t].qp_id = DPAA2_IPSEC_INVALID_U16;
    }
  vec_reset_length (dm->qp_workers);
  dm->qp_rr = 0;

  /* The async cryptodev engine claims one queue-pair per worker starting at
   * queue-pair 0, so offload attaches past that: base_qp = n_workers, and the
   * remaining queue-pairs [n_workers .. max_qp-1] are ours. If the device was
   * not provisioned with enough queue-pairs for both engines, offload gets none
   * and those workers stay on fallback -- a graceful degrade, never a
   * double-configure of the device. */
  vec_foreach (dev, dm->devs)
    {
      if (!dev->security)
	continue;

      dev->base_qp = n_workers;
      dev->n_offload_qp =
	(dev->max_qp > n_workers) ? (dev->max_qp - n_workers) : 0;

      for (u16 q = 0; q < dev->n_offload_qp && worker < n_workers; q++, worker++)
	{
	  u32 t = worker + skip_main; /* vlib thread index */
	  dm->workers[t].dev_id = dev->dev_id;
	  dm->workers[t].qp_id = dev->base_qp + q;
	  vec_add1 (dm->qp_workers, (u16) t);
	  log_debug ("worker thread %u -> SEC dev %u qp %u", t, dev->dev_id,
		     dev->base_qp + q);
	}
    }

  if (dm->have_security_dev && worker == 0)
    log_notice ("SECURITY-capable device present but no queue-pairs left for "
		"offload; all SAs use fallback");
}

u16
dpaa2_ipsec_assign_offload_thread (u32 thread_index)
{
  dpaa2_ipsec_main_t *dm = &dpaa2_ipsec_main;
  u32 i;

  if (thread_index < vec_len (dm->workers) &&
      dm->workers[thread_index].dev_id != DPAA2_IPSEC_INVALID_U16)
    return (u16) thread_index;

  if (vec_len (dm->qp_workers) == 0)
    return (u16) thread_index; /* no qp owner; the SA falls back on this worker */

  i = clib_atomic_fetch_add (&dm->qp_rr, 1) % vec_len (dm->qp_workers);
  return dm->qp_workers[i];
}

static clib_error_t *
dpaa2_ipsec_init (vlib_main_t *vm)
{
  dpaa2_ipsec_main.log_class = dpaa2_ipsec_log.class;
  return 0;
}

VLIB_INIT_FUNCTION (dpaa2_ipsec_init);
