/* $NetBSD$ */

/*-
 * Copyright (c) 2026 Matthias Petermann
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/types.h>

#include <sys/callout.h>
#include <sys/cell.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/timevar.h>

#include <netinet/in.h>

#include <secmodel/cell/cell.h>
#include <secmodel/secmodel.h>

#include <secmodel/cell/secmodel_cell_int.h>

secmodel_t cell_sm;
kauth_key_t cell_key;

static kauth_listener_t l_process;
static kauth_listener_t l_cred;
static kauth_listener_t l_system;
static kauth_listener_t l_network;

/*
 * Big picture for newcomers:
 *
 * This file implements a kernel security model that groups processes into
 * "cells" and then applies isolation policy per cell id.
 *
 * The core idea is intentionally simple:
 * 1) Each credential gets one integer cell id via kauth specificdata.
 * 2) Global policy/configuration for each cell id lives in `cell_list`.
 * 3) kauth listeners consult both pieces to allow/deny actions.
 *
 * Why this split exists:
 * - Credential data must be tiny and cheap to copy on fork/exec paths.
 * - Rich per-cell metadata (names, counters, profile) is shared global state.
 * - This keeps process credential operations fast while still allowing
 *   userland management via sysctl.
 *
 * TODO(next): Replace linear cell lookup with an id-indexed structure
 * (for example a hash table or pserialize-friendly map) once cell counts grow.
 * The current LIST walk is simple and robust but O(n) on every lookup.
 */
struct cell_list_head cell_list = LIST_HEAD_INITIALIZER(cell_list);
kmutex_t cell_lock;
static cellid_t cell_next_id = 1;
static struct callout cell_cpu_account_ch;

static uint64_t secmodel_cell_uptime_now_ns(void) {
  struct timespec ts;

  getnanouptime(&ts);
  if (ts.tv_sec < 0)
    return 0;

  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Locking contract (important for deadlock avoidance):
 *
 * - If code needs both process lists and cell metadata, lock order is always:
 *     proc_lock -> cell_lock
 * - Never grab proc_lock while already holding cell_lock.
 *
 * Why: lots of process-manipulating kernel paths already use proc_lock. If we
 * invert the order in one place, rare deadlocks can appear under load and are
 * extremely hard to debug.
 */

struct cell_entry *secmodel_cell_lookup(cellid_t);
static void secmodel_cell_cpu_account_tick(void *);

void secmodel_cell_assert_cell_lock_held(void) {

  KASSERT(mutex_owned(&cell_lock));
}

/*
 * Snapshot sampler used by list/stats exports.
 *
 * The model intentionally avoids hot-path admission hooks and keeps runtime
 * accounting in this periodic pass. Counters are best-effort snapshots.
 * CPU is exported as windowed metrics: last 1s tick delta and rolling 10s
 * average of per-second deltas.
 */
static void secmodel_cell_cpu_account_tick(void *arg) {
  struct cell_entry *entry;
  struct proc *p;
  uint64_t ticks;
  cellid_t id;

  (void)arg;

  mutex_enter(&cell_lock);
  LIST_FOREACH(entry, &cell_list, ce_entry) {
    entry->ce_cpu_ticks_1s = 0;
    entry->ce_proc_current = 0;
    entry->ce_refcount = 0;
    entry->ce_memory_current = 0;
  }
  mutex_exit(&cell_lock);

  mutex_enter(&proc_lock);
  mutex_enter(&cell_lock);
  KASSERT(mutex_owned(&proc_lock));
  secmodel_cell_assert_cell_lock_held();
  PROCLIST_FOREACH(p, &allproc) {
    id = secmodel_cell_cred_id(p->p_cred);
    if (id == CELLID_HOST)
      continue;
    ticks = p->p_uticks + p->p_sticks + p->p_iticks;
    entry = secmodel_cell_lookup(id);
    if (entry != NULL) {
      entry->ce_cpu_ticks_1s += ticks;
      entry->ce_proc_current++;
      entry->ce_refcount++;
      if (p->p_vmspace != NULL)
        entry->ce_memory_current += p->p_vmspace->vm_map.size;
    }
  }
  PROCLIST_FOREACH(p, &zombproc) {
    id = secmodel_cell_cred_id(p->p_cred);
    if (id == CELLID_HOST)
      continue;
    entry = secmodel_cell_lookup(id);
    if (entry != NULL) {
      entry->ce_refcount++;
    }
  }
  LIST_FOREACH(entry, &cell_list, ce_entry) {
    uint64_t current_total;
    uint64_t delta;
    uint64_t old;

    current_total = entry->ce_cpu_ticks_1s;
    if (current_total >= entry->ce_cpu_ticks_prev_total)
      delta = current_total - entry->ce_cpu_ticks_prev_total;
    else
      delta = 0;
    entry->ce_cpu_ticks_prev_total = current_total;

    old = 0;
    if (entry->ce_cpu_ticks_ring_count <
        __arraycount(entry->ce_cpu_ticks_ring)) {
      entry->ce_cpu_ticks_ring_count++;
    } else {
      old = entry->ce_cpu_ticks_ring[entry->ce_cpu_ticks_ring_idx];
    }
    entry->ce_cpu_ticks_ring[entry->ce_cpu_ticks_ring_idx] = delta;
    entry->ce_cpu_ticks_ring_idx = (entry->ce_cpu_ticks_ring_idx + 1) %
                                   __arraycount(entry->ce_cpu_ticks_ring);

    KASSERT(entry->ce_cpu_ticks_ring_sum >= old);
    entry->ce_cpu_ticks_ring_sum -= old;
    entry->ce_cpu_ticks_ring_sum += delta;

    entry->ce_cpu_ticks_1s = delta;
    entry->ce_cpu_ticks_10s =
        entry->ce_cpu_ticks_ring_sum / entry->ce_cpu_ticks_ring_count;
  }
  mutex_exit(&cell_lock);
  mutex_exit(&proc_lock);

  callout_schedule(&cell_cpu_account_ch, hz);
}

/*
 * Fetch the cell id associated with a credential. The value lives in the
 * secmodel-specific kauth data slot.
 */
cellid_t secmodel_cell_cred_id(kauth_cred_t cred) {
  void *data;

  data = kauth_cred_getdata(cred, cell_key);
  return (cellid_t)(uintptr_t)data;
}

/*
 * Set the cell id on a credential. This is the only state we store for
 * membership; all policy checks rely on this value.
 */
void secmodel_cell_cred_setid(kauth_cred_t cred, cellid_t id) {
  kauth_cred_setdata(cred, cell_key, (void *)(uintptr_t)id);
}

/*
 * Host credentials are those with cell id 0.
 */
bool secmodel_cell_is_host_cred(kauth_cred_t cred) {
  return secmodel_cell_cred_id(cred) == CELLID_HOST;
}

/*
 * Host root (euid 0, cell id 0) bypasses cell restrictions.
 */
bool secmodel_cell_is_host_root(kauth_cred_t cred) {
  return kauth_cred_geteuid(cred) == 0 && secmodel_cell_is_host_cred(cred);
}

/*
 * Determine whether a credential can interact with a target process.
 * Host root can always interact. Otherwise, both must be in the same cell.
 */
bool secmodel_cell_match(kauth_cred_t cred, struct proc *p) {
  if (cred == NULL || p == NULL || p->p_cred == NULL)
    return false;

  if (secmodel_cell_is_host_root(cred))
    return true;

  return secmodel_cell_cred_id(cred) == secmodel_cell_cred_id(p->p_cred);
}

/*
 * Look up a cell entry by id. Callers must hold cell_lock.
 */
struct cell_entry *secmodel_cell_lookup(cellid_t id) {
  struct cell_entry *entry;

  secmodel_cell_assert_cell_lock_held();

  /*
   * Linear scan is acceptable for small cell counts and keeps code easy to
   * audit. It is not ideal for very large fleets.
   */
  LIST_FOREACH(entry, &cell_list, ce_entry) {
    if (entry->ce_id == id)
      return entry;
  }

  return NULL;
}

/*
 * Look up a cell entry by configured name. Callers must hold cell_lock.
 */
static struct cell_entry *secmodel_cell_lookup_name(const char *name) {
  struct cell_entry *entry;

  secmodel_cell_assert_cell_lock_held();

  LIST_FOREACH(entry, &cell_list, ce_entry) {
    if (strcmp(entry->ce_name, name) == 0)
      return entry;
  }

  return NULL;
}

/*
 * Fetch the normalized policy configuration for an existing cell id.
 */
bool secmodel_cell_get_config(cellid_t id, struct cell_config *config) {
  struct cell_entry *entry;

  if (id == CELLID_HOST)
    return false;

  mutex_enter(&cell_lock);
  entry = secmodel_cell_lookup(id);
  if (entry == NULL) {
    mutex_exit(&cell_lock);
    return false;
  }
  config->cc_profile = entry->ce_profile;
  mutex_exit(&cell_lock);

  return true;
}

/*
 * Create a new cell id. The id is monotonic, starting at 1, and 0 is reserved
 * for the host. Returns the new id to the caller.
 */
int secmodel_cell_create(const struct cell_create *create,
                         const struct cell_config *config, cellid_t *idp) {
  struct cell_entry *entry;
  cellid_t id;

  mutex_enter(&cell_lock);
  if (create != NULL && create->cc_name[0] != '\0' &&
      secmodel_cell_lookup_name(create->cc_name) != NULL) {
    mutex_exit(&cell_lock);
    return EEXIST;
  }

  if (create != NULL && (create->cc_flags & CELL_CREATE_PORTS) != 0) {
    size_t i;

    for (i = 0; i < create->cc_nports; i++) {
      if (create->cc_ports[i] == 0) {
        mutex_exit(&cell_lock);
        return EINVAL;
      }
      if (secmodel_cell_port_reserved_any(htons(create->cc_ports[i]))) {
        mutex_exit(&cell_lock);
        return EEXIST;
      }
    }
  }

  /*
   * `cell_next_id` wrap to 0 would collide with the reserved host id.
   * We fail hard with EOVERFLOW instead of trying to recycle ids silently.
   */
  if (cell_next_id == 0) {
    mutex_exit(&cell_lock);
    return EOVERFLOW;
  }

  /*
   * IDs are monotonic for predictability in logs and tooling.
   *
   * TODO(next): consider generation counters if id reuse is introduced later,
   * to avoid stale userland references accidentally pointing to new cells.
   */
  id = cell_next_id++;

  entry = kmem_zalloc(sizeof(*entry), KM_SLEEP);
  entry->ce_id = id;
  entry->ce_created_ns = secmodel_cell_uptime_now_ns();
  if (create != NULL) {
    entry->ce_create_flags = create->cc_flags;
    strlcpy(entry->ce_name, create->cc_name, sizeof(entry->ce_name));
    strlcpy(entry->ce_root, create->cc_root, sizeof(entry->ce_root));
    if ((create->cc_flags & CELL_CREATE_PORTS) != 0) {
      entry->ce_nports = create->cc_nports;
      memcpy(entry->ce_ports, create->cc_ports, sizeof(create->cc_ports));
    }
    if ((create->cc_flags & CELL_CREATE_RLIMIT_NOFILE) != 0)
      entry->ce_rlimit_nofile = create->cc_rlimit_nofile;
    if ((create->cc_flags & CELL_CREATE_RLIMIT_AS) != 0)
      entry->ce_rlimit_as = create->cc_rlimit_as;
    if ((create->cc_flags & CELL_CREATE_RLIMIT_CORE) != 0)
      entry->ce_rlimit_core = create->cc_rlimit_core;
  }
  if (config != NULL) {
    entry->ce_profile = config->cc_profile;
  } else {
    entry->ce_profile = CELL_PROFILE_POLICY_HIGH;
  }
  LIST_INSERT_HEAD(&cell_list, entry, ce_entry);
  mutex_exit(&cell_lock);

  *idp = id;
  return 0;
}

/*
 * Check whether the given cell id owns a specific reserved local port.
 */
bool secmodel_cell_port_reserved_by_id(cellid_t id, in_port_t lport) {
  struct cell_entry *entry;
  size_t i;

  secmodel_cell_assert_cell_lock_held();

  entry = secmodel_cell_lookup(id);
  if (entry == NULL)
    return false;

  for (i = 0; i < entry->ce_nports; i++) {
    if (htons(entry->ce_ports[i]) == lport)
      return true;
  }

  return false;
}

/*
 * Check whether any configured cell reserves the supplied local port.
 */
bool secmodel_cell_port_reserved_any(in_port_t lport) {
  struct cell_entry *entry;
  size_t i;

  secmodel_cell_assert_cell_lock_held();

  LIST_FOREACH(entry, &cell_list, ce_entry) {
    for (i = 0; i < entry->ce_nports; i++) {
      if (htons(entry->ce_ports[i]) == lport)
        return true;
    }
  }

  return false;
}

/*
 * Extract local bind port from IPv4/IPv6 sockaddr payloads.
 */
bool secmodel_cell_addr_port(const struct sockaddr *sa, in_port_t *port) {
  const struct sockaddr_in *sin;
  const struct sockaddr_in6 *sin6;

  if (sa == NULL || port == NULL)
    return false;

  switch (sa->sa_family) {
  case AF_INET:
    sin = (const struct sockaddr_in *)sa;
    *port = sin->sin_port;
    return true;
  case AF_INET6:
    sin6 = (const struct sockaddr_in6 *)sa;
    *port = sin6->sin6_port;
    return true;
  default:
    return false;
  }
}

/*
 * Check whether any cell ids still exist.
 */
bool secmodel_cell_has_entries(void) {
  bool has_entries;

  mutex_enter(&cell_lock);
  has_entries = LIST_FIRST(&cell_list) != NULL;
  mutex_exit(&cell_lock);

  return has_entries;
}

/*
 * Check whether any process (including zombies) currently belongs to the
 * specified cell id. Used to prevent destroying active cells.
 */
bool secmodel_cell_has_processes(cellid_t id) {
  struct proc *p;
  bool found = false;

  /*
   * This is an O(number-of-processes) safety check.
   *
   * Why it is done this way: correctness first; destroy must refuse while any
   * member still exists (including zombies), so we scan both lists.
   *
   * TODO(next): maintain per-cell live membership counters with precise
   * lifetime hooks to avoid full scans at destroy time.
   */
  mutex_enter(&proc_lock);
  PROCLIST_FOREACH(p, &allproc) {
    if (secmodel_cell_cred_id(p->p_cred) == id) {
      found = true;
      break;
    }
  }
  if (!found) {
    PROCLIST_FOREACH(p, &zombproc) {
      if (secmodel_cell_cred_id(p->p_cred) == id) {
        found = true;
        break;
      }
    }
  }
  mutex_exit(&proc_lock);

  return found;
}

/*
 * Remove a cell entry. This does not touch processes; callers should ensure
 * there are no remaining members before destroying.
 */
int secmodel_cell_destroy(cellid_t id) {
  struct cell_entry *entry;

  mutex_enter(&cell_lock);
  entry = secmodel_cell_lookup(id);
  if (entry == NULL) {
    mutex_exit(&cell_lock);
    return ENOENT;
  }

  LIST_REMOVE(entry, ce_entry);
  mutex_exit(&cell_lock);

  kmem_free(entry, sizeof(*entry));
  return 0;
}

/*
 * Move the calling process into the specified cell id.
 *
 * This is a privileged operation: only host root can enter (and only into
 * an existing cell). The cell id is stored in the process credentials to
 * ensure it follows the process and its children.
 */
int secmodel_cell_enter(struct lwp *l, cellid_t id) {
  struct proc *p;
  kauth_cred_t cred, ncred;
  cellid_t cur;

  p = l->l_proc;
  proc_crmod_enter();
  cred = p->p_cred;
  cur = secmodel_cell_cred_id(cred);

  /*
   * Phase 1 validate, phase 2 commit:
   * - We first validate policy/existence.
   * - Then we re-enter credential modification and re-validate before commit.
   *
   * Why duplicate checks: another thread could change credentials or destroy a
   * cell between validation and commit. Re-check keeps this race safe.
   */
  if (!secmodel_cell_is_host_root(l->l_cred)) {
    proc_crmod_leave(cred, NULL, false);
    return EPERM;
  }

  if (cur != CELLID_HOST && cur != id) {
    proc_crmod_leave(cred, NULL, false);
    return EPERM;
  }

  if (id != CELLID_HOST) {
    mutex_enter(&cell_lock);
    if (secmodel_cell_lookup(id) == NULL) {
      mutex_exit(&cell_lock);
      proc_crmod_leave(cred, NULL, false);
      return ENOENT;
    }
    mutex_exit(&cell_lock);
  }
  proc_crmod_leave(cred, NULL, false);

  if (cur == id) {
    return 0;
  }

  /*
   * TODO(next): this is still a TOCTOU-style two-phase pattern. It is safe due
   * to revalidation, but not elegant. Investigate whether proc credential
   * framework can support a single transaction-style update helper.
   */

  proc_crmod_enter();
  cred = p->p_cred;
  cur = secmodel_cell_cred_id(cred);
  if (!secmodel_cell_is_host_root(l->l_cred)) {
    proc_crmod_leave(cred, NULL, false);
    return EPERM;
  }
  if (cur != CELLID_HOST && cur != id) {
    proc_crmod_leave(cred, NULL, false);
    return EPERM;
  }
  if (id != CELLID_HOST) {
    mutex_enter(&cell_lock);
    if (secmodel_cell_lookup(id) == NULL) {
      mutex_exit(&cell_lock);
      proc_crmod_leave(cred, NULL, false);
      return ENOENT;
    }
    mutex_exit(&cell_lock);
  }
  ncred = kauth_cred_alloc();
  kauth_cred_clone(cred, ncred);
  secmodel_cell_cred_setid(ncred, id);
  proc_crmod_leave(ncred, cred, true);

  return 0;
}

/*
 * Initialize secmodel cell structures and register per-credential storage.
 */
int secmodel_cell_init(void) {
  int error;

  mutex_init(&cell_lock, MUTEX_DEFAULT, IPL_NONE);
  callout_init(&cell_cpu_account_ch, CALLOUT_MPSAFE);
  callout_setfunc(&cell_cpu_account_ch, secmodel_cell_cpu_account_tick, NULL);

  error = kauth_register_key(cell_sm, &cell_key);
  if (error != 0) {
    printf("secmodel_cell: unable to register kauth key\n");
    callout_destroy(&cell_cpu_account_ch);
    mutex_destroy(&cell_lock);
    return error;
  }

  return 0;
}

/*
 * Register kauth listeners for process checks and credential lifecycle hooks.
 */
void secmodel_cell_start(void) {
  l_process =
      kauth_listen_scope(KAUTH_SCOPE_PROCESS, secmodel_cell_process_cb, NULL);
  l_cred = kauth_listen_scope(KAUTH_SCOPE_CRED, secmodel_cell_cred_cb, NULL);
  l_system =
      kauth_listen_scope(KAUTH_SCOPE_SYSTEM, secmodel_cell_system_cb, NULL);
  l_network =
      kauth_listen_scope(KAUTH_SCOPE_NETWORK, secmodel_cell_network_cb, NULL);
  callout_schedule(&cell_cpu_account_ch, hz);
}

/*
 * Unregister listeners and clean up cell data.
 */
void secmodel_cell_stop(void) {
  struct cell_entry *entry;

  if (l_process != NULL) {
    kauth_unlisten_scope(l_process);
    l_process = NULL;
  }
  if (l_cred != NULL) {
    kauth_unlisten_scope(l_cred);
    l_cred = NULL;
  }
  if (l_system != NULL) {
    kauth_unlisten_scope(l_system);
    l_system = NULL;
  }
  if (l_network != NULL) {
    kauth_unlisten_scope(l_network);
    l_network = NULL;
  }
  callout_halt(&cell_cpu_account_ch, NULL);
  callout_destroy(&cell_cpu_account_ch);
  kauth_deregister_key(cell_key);

  mutex_enter(&cell_lock);
  while ((entry = LIST_FIRST(&cell_list)) != NULL) {
    LIST_REMOVE(entry, ce_entry);
    kmem_free(entry, sizeof(*entry));
  }
  mutex_exit(&cell_lock);
  mutex_destroy(&cell_lock);
}
