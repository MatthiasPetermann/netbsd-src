/* $NetBSD$ */
/*-
 * Copyright (c) 2026
 * The NetBSD Foundation, Inc.
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

#include <sys/types.h>
#include <sys/kauth.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <secmodel/jail/secmodel_jail_int.h>

int
secmodel_jail_network_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	enum kauth_network_req req;
	in_port_t lport;
	jailid_t id;

	(void)cookie;
	(void)arg1;
	(void)arg3;

	if (action != KAUTH_NETWORK_BIND)
		return KAUTH_RESULT_DEFER;

	req = (enum kauth_network_req)(uintptr_t)arg0;
	if (req != KAUTH_REQ_NETWORK_BIND_PORT &&
	    req != KAUTH_REQ_NETWORK_BIND_PRIVPORT)
		return KAUTH_RESULT_DEFER;

	if (!secmodel_jail_addr_port((const struct sockaddr *)arg2, &lport))
		return KAUTH_RESULT_DEFER;
	if (lport == 0)
		return KAUTH_RESULT_DEFER;

	/*
	 * Port policy model:
	 * - if no jail reserves this port, defer to normal kernel policy
	 * - if reserved, only the owning jail may bind it
	 *
	 * This prevents accidental or malicious cross-jail port hijacking.
	 */
	id = secmodel_jail_cred_id(cred);

	mutex_enter(&jail_lock);
	if (!secmodel_jail_port_reserved_any(lport)) {
		mutex_exit(&jail_lock);
		return KAUTH_RESULT_DEFER;
	}
	if (secmodel_jail_port_reserved_by_id(id, lport)) {
		mutex_exit(&jail_lock);
		return KAUTH_RESULT_ALLOW;
	}
	mutex_exit(&jail_lock);

	return KAUTH_RESULT_DENY;
}

/*
 * kauth(9) listener for system scope.
 *
 * Denies host-level administrative actions for jailed credentials while
 * deferring host credentials and host root to other security models.
 */
int
secmodel_jail_system_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	enum kauth_system_req req;
	struct jail_config config;

	(void)cookie;
	(void)arg1;
	(void)arg2;
	(void)arg3;

	if (secmodel_jail_is_host_root(cred))
		return KAUTH_RESULT_DEFER;

	if (secmodel_jail_cred_id(cred) == JAILID_HOST)
		return KAUTH_RESULT_DEFER;

	if (!secmodel_jail_get_config(secmodel_jail_cred_id(cred), &config))
		return KAUTH_RESULT_DEFER;

	req = (enum kauth_system_req)(uintptr_t)arg0;

	/*
	 * Always deny private sysctl reads from jail context, regardless of
	 * policy profile. This keeps private nodes (for example kern.msgbuf)
	 * inaccessible to jailed credentials.
	 */
	if (action == KAUTH_SYSTEM_SYSCTL &&
	    req == KAUTH_REQ_SYSTEM_SYSCTL_PRVT)
		return KAUTH_RESULT_DENY;

	/*
	 * Profile handling strategy:
	 * - LOW: mostly defer, only absolute jail invariants are enforced.
	 * - MEDIUM/HIGH: progressively deny broader host-admin capabilities.
	 *
	 * Why defer: secmodel_jail should compose with other security models instead
	 * of claiming all decisions unconditionally.
	 */
	if (config.jc_profile == JAIL_PROFILE_POLICY_LOW)
		return KAUTH_RESULT_DEFER;

	switch (action) {
	case KAUTH_SYSTEM_MOUNT: /* Deny mounting/unmounting or mount reconfiguration inside jail. */
		switch (req) {
		case KAUTH_REQ_SYSTEM_MOUNT_DEVICE: /* Block use of raw block devices as mount sources. */
		case KAUTH_REQ_SYSTEM_MOUNT_NEW: /* Block creation of new mounts. */
		case KAUTH_REQ_SYSTEM_MOUNT_UNMOUNT: /* Block unmounting existing filesystems. */
		case KAUTH_REQ_SYSTEM_MOUNT_UPDATE: /* Block remount/update flag changes. */
		case KAUTH_REQ_SYSTEM_MOUNT_UMAP: /* Block uid/gid remapping mount operations. */
			return KAUTH_RESULT_DENY;
		default:
			return KAUTH_RESULT_DEFER;
		}

	case KAUTH_SYSTEM_MODULE: /* Block loading/unloading kernel modules from jail context. */
	case KAUTH_SYSTEM_MKNOD: /* Block creation of device special files. */
	case KAUTH_SYSTEM_FILEHANDLE: /* Block generation/use of kernel file handles. */
	case KAUTH_SYSTEM_CHROOT: /* Block nested chroot/fchroot privilege operations. */
	case KAUTH_SYSTEM_REBOOT: /* Block reboot or halt style host control actions. */
	case KAUTH_SYSTEM_SWAPCTL: /* Block swap device/table administration. */
	case KAUTH_SYSTEM_ACCOUNTING: /* Block kernel process accounting configuration. */
	case KAUTH_SYSTEM_CPU: /* Block global CPU administrative state changes. */
	case KAUTH_SYSTEM_PSET: /* Block processor-set management and binding controls. */
	case KAUTH_SYSTEM_TIME: /* Block host clock/ntp/timecounter administration. */
	case KAUTH_SYSTEM_SEMAPHORE: /* Block global kernel semaphore administration. */
	case KAUTH_SYSTEM_MQUEUE: /* Block POSIX message queue subsystem administration. */
	case KAUTH_SYSTEM_DEVMAPPER: /* Block device-mapper table/control operations. */
	case KAUTH_SYSTEM_INTR: /* Block interrupt affinity and routing controls. */
	case KAUTH_SYSTEM_KERNADDR: /* Block privileged kernel address disclosure access. */
		return KAUTH_RESULT_DENY;

	case KAUTH_SYSTEM_SYSVIPC: /* Block SysV IPC administrative bypass/override controls. */
		if (config.jc_profile == JAIL_PROFILE_POLICY_MEDIUM)
			return KAUTH_RESULT_DEFER;
		return KAUTH_RESULT_DENY;

	case KAUTH_SYSTEM_SYSCTL: /* Constrain jail writes to global kernel sysctl tree. */
		switch (req) {
		case KAUTH_REQ_SYSTEM_SYSCTL_ADD: /* Block runtime creation of sysctl nodes. */
		case KAUTH_REQ_SYSTEM_SYSCTL_DELETE: /* Block runtime deletion of sysctl nodes. */
		case KAUTH_REQ_SYSTEM_SYSCTL_MODIFY: /* Block writes to privileged sysctl values. */
			return KAUTH_RESULT_DENY;
		default:
			return KAUTH_RESULT_DEFER;
		}

	default:
		return KAUTH_RESULT_DEFER;
	}
}

/*
 * kauth(9) listener for process scope.
 *
 * Enforces jail-local process visibility/signal policy.
 */
int
secmodel_jail_process_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	struct proc *p;
	(void)cookie;
	(void)arg1;
	(void)arg2;
	(void)arg3;

	switch (action) {
	case KAUTH_PROCESS_FORK: {
		jailid_t id;
		struct jail_entry *entry;
		uint64_t current;
		uint64_t proc_max;

		id = secmodel_jail_cred_id(cred);
		if (id == JAILID_HOST)
			return KAUTH_RESULT_DEFER;

		/*
		 * Read jail-local fork policy first. This cheap check avoids walking
		 * allproc/zombproc when process limits are disabled for this jail.
		 */
		proc_max = 0;
		mutex_enter(&jail_lock);
		entry = secmodel_jail_lookup(id);
		if (entry != NULL) {
			if (entry->je_cpu_over_quota) {
				entry->je_throttle_cpu++;
				mutex_exit(&jail_lock);
				return KAUTH_RESULT_DENY;
			}
			proc_max = entry->je_proc_max;
		}
		mutex_exit(&jail_lock);

		if (proc_max == 0)
			return KAUTH_RESULT_DEFER;

		current = 0;
		/*
		 * TODO(next): replace full process walks with maintained counters updated
		 * on fork/exit hooks. Current behavior is correct but scales poorly on
		 * systems with very high process counts.
		 */
		mutex_enter(&proc_lock);
		PROCLIST_FOREACH(p, &allproc) {
			if (secmodel_jail_cred_id(p->p_cred) == id)
				current++;
		}
		PROCLIST_FOREACH(p, &zombproc) {
			if (secmodel_jail_cred_id(p->p_cred) == id)
				current++;
		}
		mutex_exit(&proc_lock);

		/*
		 * Revalidate under jail_lock: jail policy may have changed while we
		 * counted processes, and the jail could have been destroyed/recreated.
		 */
		mutex_enter(&jail_lock);
		entry = secmodel_jail_lookup(id);
		if (entry != NULL) {
			if (entry->je_cpu_over_quota) {
				entry->je_throttle_cpu++;
				mutex_exit(&jail_lock);
				return KAUTH_RESULT_DENY;
			}
			entry->je_proc_current = current;
			if (entry->je_proc_max != 0 && current >= entry->je_proc_max) {
				entry->je_deny_proc++;
				mutex_exit(&jail_lock);
				return KAUTH_RESULT_DENY;
			}
		}
		mutex_exit(&jail_lock);
		return KAUTH_RESULT_DEFER;
	}
	case KAUTH_PROCESS_CANSEE:
	case KAUTH_PROCESS_SIGNAL:
		p = arg0;
		if (!secmodel_jail_match(cred, p))
			return KAUTH_RESULT_DENY;
		return KAUTH_RESULT_DEFER;
	default:
		return KAUTH_RESULT_DEFER;
	}
}

/*
 * kauth(9) listener for credential scope.
 *
 * Initializes new credentials to host jail (id 0) and preserves the jail id
 * when credentials are copied.
 */
int
secmodel_jail_cred_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	(void)cookie;
	(void)arg1;
	(void)arg2;
	(void)arg3;

	switch (action) {
	case KAUTH_CRED_INIT:
		secmodel_jail_cred_setid(cred, JAILID_HOST);
		return KAUTH_RESULT_ALLOW;
	case KAUTH_CRED_COPY:
		secmodel_jail_cred_setid(arg0, secmodel_jail_cred_id(cred));
		return KAUTH_RESULT_ALLOW;
	default:
		return KAUTH_RESULT_DEFER;
	}
}

