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

#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <secmodel/cell/secmodel_cell_int.h>

/*
 * Management plane overview:
 *
 * This file exposes the stable userland ABI under security.models.cell.* and
 * translates sysctl payloads into state-engine calls in secmodel_cell.c.
 *
 * Division of responsibility:
 * - Here: input validation, privilege checks, copyin/copyout framing.
 * - secmodel_cell.c: transactional create/destroy/enter state changes.
 * - secmodel_cell_policy.c: authorization decisions at runtime hooks.
 */

/*
 * Validate caller-supplied cell creation flags.
 *
 * This keeps the write-side ABI strict: unknown bits are rejected so future
 * extensions cannot be accidentally accepted with unexpected semantics.
 */
static int secmodel_cell_validate_create_flags(uint32_t flags) {
  if ((flags & ~(CELL_CREATE_PROFILE | CELL_CREATE_PORTS |
                 CELL_CREATE_RLIMIT_NOFILE | CELL_CREATE_RLIMIT_AS |
                 CELL_CREATE_RLIMIT_CORE)) != 0)
    return EINVAL;

  return 0;
}

/*
 * Validate optional supervised-process rlimit settings in cell_create.
 */
static int
secmodel_cell_validate_create_rlimits(const struct cell_create *create) {
  if ((create->cc_flags & CELL_CREATE_RLIMIT_NOFILE) == 0 &&
      create->cc_rlimit_nofile != 0)
    return EINVAL;
  if ((create->cc_flags & CELL_CREATE_RLIMIT_AS) == 0 &&
      create->cc_rlimit_as != 0)
    return EINVAL;
  if ((create->cc_flags & CELL_CREATE_RLIMIT_CORE) == 0 &&
      create->cc_rlimit_core != 0)
    return EINVAL;

  return 0;
}

/*
 * Validate optional reserved-port list in cell_create.
 */
static int
secmodel_cell_validate_create_ports(const struct cell_create *create) {
  size_t i;
  size_t j;

  if ((create->cc_flags & CELL_CREATE_PORTS) == 0)
    return create->cc_nports == 0 ? 0 : EINVAL;

  if (create->cc_nports == 0 || create->cc_nports > CELL_PORTS_MAX)
    return EINVAL;

  for (i = 0; i < create->cc_nports; i++) {
    if (create->cc_ports[i] == 0)
      return EINVAL;
    for (j = i + 1; j < create->cc_nports; j++) {
      if (create->cc_ports[i] == create->cc_ports[j])
        return EINVAL;
    }
  }

  return 0;
}

/*
 * Translate cell_create into internal policy config.
 */
static int secmodel_cell_build_config(const struct cell_create *create,
                                      struct cell_config *config) {
  uint32_t flags;

  flags = create->cc_flags;
  memset(config, 0, sizeof(*config));
  config->cc_profile = CELL_PROFILE_POLICY_HIGH;

  if ((flags & CELL_CREATE_PROFILE) != 0) {
    switch (create->cc_profile) {
    case CELL_PROFILE_LOW:
      config->cc_profile = CELL_PROFILE_POLICY_LOW;
      break;
    case CELL_PROFILE_MEDIUM:
      config->cc_profile = CELL_PROFILE_POLICY_MEDIUM;
      break;
    case CELL_PROFILE_HIGH:
      config->cc_profile = CELL_PROFILE_POLICY_HIGH;
      break;
    default:
      return EINVAL;
    }
  }

  return 0;
}

/*
 * Validate fixed-size string field from userland payload.
 *
 * We require a NUL terminator within bounds so later C-string operations do
 * not read beyond the payload.
 */
static int secmodel_cell_validate_text_field(const char *s, size_t n) {
  size_t len;
  size_t i;

  if (s == NULL || n == 0)
    return EINVAL;
  len = strnlen(s, n);
  if (len == n)
    return EINVAL;

  for (i = 0; i < len; i++) {
    if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] == 0x7f)
      return EINVAL;
  }

  return 0;
}

static int secmodel_cell_validate_name(const char *name, size_t n) {
  size_t i;
  size_t len;

  if (secmodel_cell_validate_text_field(name, n) != 0)
    return EINVAL;
  len = strnlen(name, n);
  for (i = 0; i < len; i++) {
    if (!((name[i] >= 'a' && name[i] <= 'z') ||
          (name[i] >= 'A' && name[i] <= 'Z') ||
          (name[i] >= '0' && name[i] <= '9') || name[i] == '.' ||
          name[i] == '_' || name[i] == '-'))
      return EINVAL;
  }

  return 0;
}

/*
 * sysctl handler for security.models.cell.create
 *
 * Writing a value allocates a new cell id. The newly created id is returned
 * to userland.
 */
static int secmodel_cell_sysctl_create(SYSCTLFN_ARGS) {
  uint32_t id;
  int error;
  struct cell_create create;
  struct cell_config config;

  if (newp == NULL)
    return EINVAL;

  if (!secmodel_cell_is_host_root(l->l_cred))
    return EPERM;

  /* Creation returns an id; never commit state if it cannot be returned. */
  if (oldp == NULL || *oldlenp < sizeof(create))
    return ENOMEM;

  if (newlen != sizeof(create))
    return EINVAL;

  error = sysctl_copyin(l, newp, &create, sizeof(create));
  if (error != 0)
    return error;

  error = secmodel_cell_validate_create_flags(create.cc_flags);
  if (error != 0)
    return error;

  error = secmodel_cell_validate_create_ports(&create);
  if (error != 0)
    return error;

  error = secmodel_cell_validate_create_rlimits(&create);
  if (error != 0)
    return error;

  error = secmodel_cell_build_config(&create, &config);
  if (error != 0)
    return error;

  if (create.cc_name[0] == '\0' || create.cc_root[0] == '\0')
    return EINVAL;
  error = secmodel_cell_validate_name(create.cc_name, sizeof(create.cc_name));
  if (error != 0)
    return error;
  error = secmodel_cell_validate_text_field(create.cc_root,
                                            sizeof(create.cc_root));
  if (error != 0)
    return error;

  error = secmodel_cell_create(&create, &config, &id);

  if (error != 0)
    return error;

  create.cc_id = id;
  *oldlenp = sizeof(create);
  error = sysctl_copyout(l, &create, oldp, sizeof(create));
  if (error != 0) {
    (void)secmodel_cell_destroy(id);
    return error;
  }

  log(LOG_INFO,
      "secmodel_cell: created cell id=%u name=\"%s\" root=\"%s\" "
      "profile=%u by pid=%d euid=%u\n",
      id, create.cc_name, create.cc_root, (unsigned)config.cc_profile,
      l->l_proc->p_pid, kauth_cred_geteuid(l->l_cred));
  return 0;
}

/*
 * sysctl handler for security.models.cell.destroy
 *
 * Writing a cell id destroys it if there are no remaining processes.
 */
static int secmodel_cell_sysctl_destroy(SYSCTLFN_ARGS) {
  uint32_t id;
  int error;

  if (newp == NULL)
    return EINVAL;

  if (!secmodel_cell_is_host_root(l->l_cred))
    return EPERM;

  if (newlen < sizeof(id))
    return EINVAL;

  error = sysctl_copyin(l, newp, &id, sizeof(id));
  if (error != 0)
    return error;

  if (id == CELLID_HOST)
    return EINVAL;

  error = secmodel_cell_destroy(id);
  if (error != 0)
    return error;

  log(LOG_INFO, "secmodel_cell: destroyed cell id=%u by pid=%d euid=%u\n", id,
      l->l_proc->p_pid, kauth_cred_geteuid(l->l_cred));

  return 0;
}

/*
 * sysctl handler for security.models.cell.id
 *
 * Reading returns the current process cell id. Writing an id requests the
 * process to enter that cell.
 */
static int secmodel_cell_sysctl_id(SYSCTLFN_ARGS) {
  cellid_t id;
  int error;
  struct sysctlnode node;

  if (!secmodel_cell_is_host_root(l->l_cred))
    return EPERM;

  id = secmodel_cell_cred_id(l->l_cred);

  node = *rnode;
  node.sysctl_data = &id;
  node.sysctl_size = sizeof(id);

  error = sysctl_lookup(SYSCTLFN_CALL(&node));
  if (error || newp == NULL)
    return error;

  /* Commit semantics (hold/state checks) are handled inside secmodel_cell_enter. */
  return secmodel_cell_enter(l, id);
}

/*
 * sysctl handler for security.models.cell.list
 *
 * Reading returns an array of cell_info entries with snapshot counters.
 * Access is allowed from host credentials (cell id 0), including
 * unprivileged host users.
 */
static int secmodel_cell_sysctl_list(SYSCTLFN_ARGS) {
  struct cell_entry *entry;
  struct cell_info *entries;
  size_t count, i, needed, used;
  uint64_t seq;
  int error;

  if (newp != NULL)
    return EPERM;
  if (!secmodel_cell_is_host_cred(l->l_cred))
    return EPERM;

  for (;;) {
    /*
     * Snapshot path intentionally avoids proc_lock and only copies sampled
     * counters from cell entries, keeping stats sysctl reads bounded.
     */
    mutex_enter(&cell_lock);
    seq = cell_list_seq;
    count = 0;
    LIST_FOREACH(entry, &cell_list, ce_entry) {
      if (entry->ce_state == CELL_STATE_ACTIVE)
        count++;
    }
    if (count > (size_t)-1 / sizeof(*entries)) {
      mutex_exit(&cell_lock);
      return EOVERFLOW;
    }
    needed = count * sizeof(*entries);

    if (oldp == NULL) {
      mutex_exit(&cell_lock);
      *oldlenp = needed;
      return 0;
    }

    if (count == 0) {
      mutex_exit(&cell_lock);
      *oldlenp = 0;
      return 0;
    }
    mutex_exit(&cell_lock);

    if (*oldlenp < needed)
      return ENOMEM;

    entries = kmem_zalloc(needed, KM_SLEEP);

    mutex_enter(&cell_lock);
    /* Sequence mismatch means list changed while unlocked for allocation. */
    if (seq != cell_list_seq) {
      mutex_exit(&cell_lock);
      kmem_free(entries, needed);
      continue;
    }
    i = 0;
    LIST_FOREACH(entry, &cell_list, ce_entry) {
      if (entry->ce_state != CELL_STATE_ACTIVE)
        continue;
      KASSERT(i < count);
      entries[i].ci_id = entry->ce_id;
      entries[i].ci_create_flags = entry->ce_create_flags;
      entries[i].ci_refcount = entry->ce_refcount;
      entries[i].ci_proc_current = entry->ce_proc_current;
      entries[i].ci_memory_current = entry->ce_memory_current;
      entries[i].ci_created_ns = entry->ce_created_ns;
      entries[i].ci_cpu_ticks_1s = entry->ce_cpu_ticks_1s;
      entries[i].ci_cpu_ticks_10s = entry->ce_cpu_ticks_10s;
      entries[i].ci_rlimit_nofile = entry->ce_rlimit_nofile;
      entries[i].ci_rlimit_as = entry->ce_rlimit_as;
      entries[i].ci_rlimit_core = entry->ce_rlimit_core;
      strlcpy(entries[i].ci_name, entry->ce_name, sizeof(entries[i].ci_name));
      strlcpy(entries[i].ci_root, entry->ce_root, sizeof(entries[i].ci_root));
      i++;
    }
    mutex_exit(&cell_lock);

    KASSERT(i == count);
    used = count * sizeof(*entries);

    error = sysctl_copyout(l, entries, oldp, used);
    if (error == 0)
      *oldlenp = used;

    kmem_free(entries, needed);
    return error;
  }
}

/*
 * Create the sysctl tree for cell controls under security.models.cell.
 */
SYSCTL_SETUP(sysctl_security_cell_setup, "secmodel_cell sysctl") {
  const struct sysctlnode *rnode;

  /*
   * ABI note: node names under security.models.cell.* are consumed by
   * usr.sbin/cellctl and should remain stable for compatibility.
   */
  sysctl_createv(clog, 0, NULL, &rnode, CTLFLAG_PERMANENT, CTLTYPE_NODE,
                 "models", NULL, NULL, 0, NULL, 0, CTL_SECURITY, CTL_CREATE,
                 CTL_EOL);

  sysctl_createv(clog, 0, &rnode, &rnode, CTLFLAG_PERMANENT, CTLTYPE_NODE,
                 "cell", SYSCTL_DESCR("Cell security model"), NULL, 0, NULL, 0,
                 CTL_CREATE, CTL_EOL);

  sysctl_createv(clog, 0, &rnode, NULL, CTLFLAG_PERMANENT, CTLTYPE_STRING,
                 "name", NULL, NULL, 0, __UNCONST(SECMODEL_CELL_NAME), 0,
                 CTL_CREATE, CTL_EOL);

  sysctl_createv(clog, 0, &rnode, NULL, CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
                 CTLTYPE_INT, "id", SYSCTL_DESCR("Current process cell id"),
                 secmodel_cell_sysctl_id, 0, NULL, 0, CTL_CREATE, CTL_EOL);

  sysctl_createv(clog, 0, &rnode, NULL, CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
                 CTLTYPE_STRUCT, "create", SYSCTL_DESCR("Create a new cell id"),
                 secmodel_cell_sysctl_create, 0, NULL, 0, CTL_CREATE, CTL_EOL);

  sysctl_createv(clog, 0, &rnode, NULL, CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
                 CTLTYPE_INT, "destroy",
                 SYSCTL_DESCR("Destroy a cell id with no processes"),
                 secmodel_cell_sysctl_destroy, 0, NULL, 0, CTL_CREATE, CTL_EOL);

  sysctl_createv(clog, 0, &rnode, NULL, CTLFLAG_PERMANENT | CTLFLAG_READONLY,
                 CTLTYPE_STRUCT, "list", SYSCTL_DESCR("List active cell ids"),
                 secmodel_cell_sysctl_list, 0, NULL, 0, CTL_CREATE, CTL_EOL);
}
