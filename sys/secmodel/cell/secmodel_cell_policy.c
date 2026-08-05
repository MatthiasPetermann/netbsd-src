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

#include <sys/atomic.h>
#include <sys/kauth.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <secmodel/cell/secmodel_cell_int.h>

/*
 * Policy layer overview:
 *
 * This file is intentionally decision-focused.  Each callback follows the
 * same order: identify the caller's cell, evaluate its scope-specific rule,
 * then audit a denial.  It does not mutate membership or lifecycle state.
 *
 * Any destroy/enter race safety is handled in the state engine
 * (secmodel_cell.c). Here we only allow/deny/defer.
 *
 * Profile matrix ("deny" means this model returns KAUTH_RESULT_DENY):
 *
 * Scope       LOW                    MEDIUM                 HIGH
 * process     cross-cell targets     cross-cell targets      cross-cell targets
 * network     reserved-port nonowner reserved-port nonowner  reserved-port nonowner
 * system      private sysctls        LOW + host admin,       MEDIUM + SYSVIPC
 *                                     mounts, sysctl writes
 * device      defer                  deny all                deny all
 * machdep     defer                  deny all                deny all
 *
 * All unlisted operations defer to the other installed security models.
 */

/*
 * Shared deny path: account event, emit rate-limited audit, return DENY.
 */
static int secmodel_cell_deny_event(uint64_t *counter,
                                    enum cell_deny_scope scope,
                                    kauth_cred_t cred, kauth_action_t action,
                                    uintptr_t req) {
  atomic_inc_64(counter);
  secmodel_cell_deny_audit(scope, cred, action, req);
  return KAUTH_RESULT_DENY;
}

/* Return false for host credentials and cells being destroyed. */
static bool secmodel_cell_get_profile(kauth_cred_t cred,
                                      struct cell_config *config) {
  if (secmodel_cell_is_host_cred(cred))
    return false;

  return secmodel_cell_get_config(secmodel_cell_cred_id(cred), config);
}

static int secmodel_cell_deny_process(kauth_cred_t cred,
                                      kauth_action_t action, uintptr_t req) {
  return secmodel_cell_deny_event(&cell_deny_process, CELL_DENY_SCOPE_PROCESS,
                                  cred, action, req);
}

static int secmodel_cell_deny_system(kauth_cred_t cred, kauth_action_t action,
                                     uintptr_t req) {
  return secmodel_cell_deny_event(&cell_deny_system, CELL_DENY_SCOPE_SYSTEM,
                                  cred, action, req);
}

static int secmodel_cell_deny_network(kauth_cred_t cred,
                                      kauth_action_t action, uintptr_t req) {
  return secmodel_cell_deny_event(&cell_deny_network, CELL_DENY_SCOPE_NETWORK,
                                  cred, action, req);
}

/*
 * Process actions whose target process must stay cell-local.
 *
 * Keeping this list in one helper prevents switch duplication in the callback.
 */
static bool secmodel_cell_is_process_scoped_action(kauth_action_t action) {
  switch (action) {
  case KAUTH_PROCESS_CANSEE:
  case KAUTH_PROCESS_CORENAME:
  case KAUTH_PROCESS_KEVENT_FILTER:
  case KAUTH_PROCESS_KTRACE:
  case KAUTH_PROCESS_NICE:
  case KAUTH_PROCESS_PROCFS:
  case KAUTH_PROCESS_PTRACE:
  case KAUTH_PROCESS_RLIMIT:
  case KAUTH_PROCESS_SCHEDULER_GETAFFINITY:
  case KAUTH_PROCESS_SCHEDULER_SETAFFINITY:
  case KAUTH_PROCESS_SCHEDULER_GETPARAM:
  case KAUTH_PROCESS_SCHEDULER_SETPARAM:
  case KAUTH_PROCESS_SETID:
  case KAUTH_PROCESS_SIGNAL:
  case KAUTH_PROCESS_STOPFLAG:
    return true;
  default:
    return false;
  }
}

/*
 * Device and machine-dependent operations affect global host state.  They
 * have no cell-local resource namespace, so they cannot be safely delegated.
 */
static int secmodel_cell_host_global_cb(kauth_cred_t cred,
                                        kauth_action_t action) {
  struct cell_config config;

  if (!secmodel_cell_get_profile(cred, &config))
    return KAUTH_RESULT_DEFER;

  switch (config.cc_profile) {
  case CELL_PROFILE_POLICY_LOW:
    return KAUTH_RESULT_DEFER;
  case CELL_PROFILE_POLICY_MEDIUM:
  case CELL_PROFILE_POLICY_HIGH:
    return secmodel_cell_deny_system(cred, action, 0);
  default:
    return secmodel_cell_deny_system(cred, action, 0);
  }
}

int secmodel_cell_machdep_cb(kauth_cred_t cred, kauth_action_t action,
                             void *cookie, void *arg0, void *arg1, void *arg2,
                             void *arg3) {
  (void)cookie;
  (void)arg0;
  (void)arg1;
  (void)arg2;
  (void)arg3;
  return secmodel_cell_host_global_cb(cred, action);
}

int secmodel_cell_device_cb(kauth_cred_t cred, kauth_action_t action,
                            void *cookie, void *arg0, void *arg1, void *arg2,
                            void *arg3) {
  (void)cookie;
  (void)arg0;
  (void)arg1;
  (void)arg2;
  (void)arg3;
  return secmodel_cell_host_global_cb(cred, action);
}

/*
 * Shared deny matrix for system-scope actions that are never delegated to cell
 * members when profile >= MEDIUM.
 */
static bool secmodel_cell_system_action_always_denied(kauth_action_t action) {
  switch (action) {
  case KAUTH_SYSTEM_MODULE:
  case KAUTH_SYSTEM_MKNOD:
  case KAUTH_SYSTEM_FILEHANDLE:
  case KAUTH_SYSTEM_CHROOT:
  case KAUTH_SYSTEM_REBOOT:
  case KAUTH_SYSTEM_SWAPCTL:
  case KAUTH_SYSTEM_ACCOUNTING:
  case KAUTH_SYSTEM_CPU:
  case KAUTH_SYSTEM_PSET:
  case KAUTH_SYSTEM_TIME:
  case KAUTH_SYSTEM_SEMAPHORE:
  case KAUTH_SYSTEM_MQUEUE:
  case KAUTH_SYSTEM_DEVMAPPER:
  case KAUTH_SYSTEM_INTR:
  case KAUTH_SYSTEM_KERNADDR:
    return true;
  default:
    return false;
  }
}

/*
 * Mount operations denied inside celled context for profile >= MEDIUM.
 */
static bool secmodel_cell_is_mount_req_denied(enum kauth_system_req req) {
  switch (req) {
  case KAUTH_REQ_SYSTEM_MOUNT_DEVICE:
  case KAUTH_REQ_SYSTEM_MOUNT_NEW:
  case KAUTH_REQ_SYSTEM_MOUNT_UNMOUNT:
  case KAUTH_REQ_SYSTEM_MOUNT_UPDATE:
  case KAUTH_REQ_SYSTEM_MOUNT_UMAP:
    return true;
  default:
    return false;
  }
}

/*
 * Sysctl write operations denied inside celled context for profile >= MEDIUM.
 */
static bool secmodel_cell_is_sysctl_req_denied(enum kauth_system_req req) {
  switch (req) {
  case KAUTH_REQ_SYSTEM_SYSCTL_ADD:
  case KAUTH_REQ_SYSTEM_SYSCTL_DELETE:
  case KAUTH_REQ_SYSTEM_SYSCTL_MODIFY:
    return true;
  default:
    return false;
  }
}

/* System policy table.  Callbacks only turn a true result into an audit. */
static bool secmodel_cell_system_denies(enum cell_policy_profile profile,
                                        kauth_action_t action,
                                        enum kauth_system_req req) {
  bool is_private_sysctl;
  bool is_host_admin;
  bool is_mount_change;
  bool is_sysctl_write;

  is_private_sysctl =
      action == KAUTH_SYSTEM_SYSCTL && req == KAUTH_REQ_SYSTEM_SYSCTL_PRVT;
  is_host_admin = secmodel_cell_system_action_always_denied(action);
  is_mount_change =
      action == KAUTH_SYSTEM_MOUNT && secmodel_cell_is_mount_req_denied(req);
  is_sysctl_write =
      action == KAUTH_SYSTEM_SYSCTL && secmodel_cell_is_sysctl_req_denied(req);

  switch (profile) {
  case CELL_PROFILE_POLICY_LOW:
    return is_private_sysctl;
  case CELL_PROFILE_POLICY_MEDIUM:
    return is_private_sysctl || is_host_admin || is_mount_change ||
           is_sysctl_write;
  case CELL_PROFILE_POLICY_HIGH:
    return is_private_sysctl || is_host_admin || is_mount_change ||
           is_sysctl_write || action == KAUTH_SYSTEM_SYSVIPC;
  default:
    /* Invalid profiles are rejected at create time; fail closed if corrupted. */
    return true;
  }
}

/*
 * kauth(9) listener for network scope.
 */
int secmodel_cell_network_cb(kauth_cred_t cred, kauth_action_t action,
                             void *cookie, void *arg0, void *arg1, void *arg2,
                             void *arg3) {
  enum kauth_network_req req;
  in_port_t lport;
  cellid_t id;

  (void)cookie;
  (void)arg1;
  (void)arg3;

  if (action != KAUTH_NETWORK_BIND)
    return KAUTH_RESULT_DEFER;

  req = (enum kauth_network_req)(uintptr_t)arg0;
  if (req != KAUTH_REQ_NETWORK_BIND_PORT &&
      req != KAUTH_REQ_NETWORK_BIND_PRIVPORT)
    return KAUTH_RESULT_DEFER;

  if (!secmodel_cell_addr_port((const struct sockaddr *)arg2, &lport))
    return KAUTH_RESULT_DEFER;
  if (lport == 0)
    return KAUTH_RESULT_DEFER;

  /*
   * Port policy model:
   * - if no cell reserves this port, defer to normal kernel policy
   * - if reserved, only the owning cell may bind it
   *
   * This prevents accidental or malicious cross-cell port hijacking.
   */
  id = secmodel_cell_cred_id(cred);

  mutex_enter(&cell_lock);
  if (!secmodel_cell_port_reserved_any(lport)) {
    mutex_exit(&cell_lock);
    return KAUTH_RESULT_DEFER;
  }
  if (secmodel_cell_port_reserved_by_id(id, lport)) {
    mutex_exit(&cell_lock);
    return KAUTH_RESULT_ALLOW;
  }
  mutex_exit(&cell_lock);

  return secmodel_cell_deny_network(cred, action, (uintptr_t)req);
}

/*
 * kauth(9) listener for system scope.
 *
 * Denies host-level administrative actions for celled credentials while
 * deferring host credentials and host root to other security models.
 */
int secmodel_cell_system_cb(kauth_cred_t cred, kauth_action_t action,
                            void *cookie, void *arg0, void *arg1, void *arg2,
                            void *arg3) {
  enum kauth_system_req req;
  struct cell_config config;

  (void)cookie;
  (void)arg1;
  (void)arg2;
  (void)arg3;

  if (!secmodel_cell_get_profile(cred, &config))
    return KAUTH_RESULT_DEFER;

  req = (enum kauth_system_req)(uintptr_t)arg0;
  if (!secmodel_cell_system_denies(config.cc_profile, action, req))
    return KAUTH_RESULT_DEFER;

  return secmodel_cell_deny_system(cred, action, (uintptr_t)req);
}

/*
 * kauth(9) listener for process scope.
 *
 * Enforces cell-local process visibility/signal policy.
 */
int secmodel_cell_process_cb(kauth_cred_t cred, kauth_action_t action,
                             void *cookie, void *arg0, void *arg1, void *arg2,
                             void *arg3) {
  struct proc *p;
  (void)cookie;
  (void)arg2;
  (void)arg3;

  /* Fast reject for actions not governed by cell-local process matching. */
  if (!secmodel_cell_is_process_scoped_action(action))
    return KAUTH_RESULT_DEFER;

  p = arg0;
  if (p == NULL || p->p_cred == NULL)
    return KAUTH_RESULT_DEFER;
  if (!secmodel_cell_match(cred, p))
    return secmodel_cell_deny_process(cred, action, (uintptr_t)arg1);

  return KAUTH_RESULT_DEFER;
}

/*
 * kauth(9) listener for credential scope.
 *
 * Initializes new credentials to host cell (id 0) and preserves the cell id
 * when credentials are copied.
 */
int secmodel_cell_cred_cb(kauth_cred_t cred, kauth_action_t action,
                          void *cookie, void *arg0, void *arg1, void *arg2,
                          void *arg3) {
  (void)cookie;
  (void)arg1;
  (void)arg2;
  (void)arg3;

  switch (action) {
  case KAUTH_CRED_INIT:
    if (cred == NULL)
      return KAUTH_RESULT_DEFER;
    secmodel_cell_cred_setid(cred, CELLID_HOST);
    return KAUTH_RESULT_ALLOW;
  case KAUTH_CRED_COPY:
    if (arg0 == NULL || cred == NULL)
      return KAUTH_RESULT_DEFER;
    secmodel_cell_cred_setid((kauth_cred_t)arg0, secmodel_cell_cred_id(cred));
    return KAUTH_RESULT_ALLOW;
  default:
    return KAUTH_RESULT_DEFER;
  }
}
