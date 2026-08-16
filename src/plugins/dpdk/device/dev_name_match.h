/*
 * dev_name_match.h - bus-qualified device name key/match helpers
 *
 * Freestanding: no VPP or DPDK includes, so the key build and match are
 * unit-testable on the host with plain cc (see test_dev_name_match.c). PCI and
 * VMBUS devices are keyed by their bus address, but the fslmc bus exposes no
 * such address, so its devices are matched by "<bus>:<name>" (e.g.
 * "fslmc:dpni.7"). Namespacing by bus keeps a leaf name like "dpni.7" from
 * cross-matching the same name on another bus.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __included_dpdk_dev_name_match_h__
#define __included_dpdk_dev_name_match_h__

#include <string.h>
#include <stdbool.h>
#include <stddef.h>

/* Build "<bus>:<name>" into out. Returns true on success, false (out empty) if
 * the key plus its NUL would not fit out_sz. */
static inline bool
dpdk_dev_name_key (const char *bus, const char *name, char *out, size_t out_sz)
{
  size_t bus_len = strlen (bus);
  size_t name_len = strlen (name);

  if (out_sz == 0)
    return false;
  /* bus + ':' + name + '\0' */
  if (bus_len + 1 + name_len + 1 > out_sz)
    {
      out[0] = '\0';
      return false;
    }

  memcpy (out, bus, bus_len);
  out[bus_len] = ':';
  memcpy (out + bus_len + 1, name, name_len);
  out[bus_len + 1 + name_len] = '\0';
  return true;
}

/* True iff key equals "<bus>:<name>" exactly. Compares the bus prefix, the ':'
 * separator, and the name tail without rebuilding the key. */
static inline bool
dpdk_dev_name_match (const char *key, const char *bus, const char *name)
{
  size_t bus_len = strlen (bus);

  if (strncmp (key, bus, bus_len) != 0)
    return false;
  if (key[bus_len] != ':')
    return false;
  return strcmp (key + bus_len + 1, name) == 0;
}

#endif /* __included_dpdk_dev_name_match_h__ */
