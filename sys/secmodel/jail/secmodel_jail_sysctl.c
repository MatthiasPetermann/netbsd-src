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
#include <sys/sysctl.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/syslog.h>

#include <secmodel/jail/secmodel_jail_int.h>

/*
 * sysctl handler for security.models.jail.create
 *
 * Writing a value allocates a new jail id. The newly created id is returned
 * to userland.
 */
static int
secmodel_jail_sysctl_create(SYSCTLFN_ARGS)
{
	uint32_t id;
	int error;
	struct jail_create create;
	struct jail_config config;
	struct jail_config *configp;
	uint32_t flags;

	if (newp == NULL)
		return EINVAL;

	if (!secmodel_jail_is_host_root(l->l_cred))
		return EPERM;

	if (newlen == sizeof(create)) {
		error = sysctl_copyin(l, newp, &create, sizeof(create));
		if (error != 0)
			return error;

		flags = create.jc_flags;
		if ((flags & ~(JAIL_CREATE_CPU_QUOTA |
		    JAIL_CREATE_CPU_PERIOD |
				    JAIL_CREATE_MEMORY_MAX |
		    JAIL_CREATE_PROC_MAX |
		    JAIL_CREATE_FD_MAX |
		    JAIL_CREATE_SOCKBUF_MAX |
		    JAIL_CREATE_PROFILE |
		    JAIL_CREATE_PORTS)) != 0)
			return EINVAL;
		if ((flags & JAIL_CREATE_PORTS) != 0) {
			size_t i, j;

			if (create.jc_nports == 0 || create.jc_nports > JAIL_PORTS_MAX)
				return EINVAL;
			for (i = 0; i < create.jc_nports; i++) {
				if (create.jc_ports[i] == 0)
					return EINVAL;
				for (j = i + 1; j < create.jc_nports; j++) {
					if (create.jc_ports[i] == create.jc_ports[j])
						return EINVAL;
				}
			}
		} else if (create.jc_nports != 0) {
			return EINVAL;
		}

		memset(&config, 0, sizeof(config));
		config.jc_profile = JAIL_PROFILE_POLICY_HIGH;
		if ((flags & JAIL_CREATE_PROFILE) != 0) {
			switch (create.jc_profile) {
			case JAIL_PROFILE_LOW:
				config.jc_profile = JAIL_PROFILE_POLICY_LOW;
				break;
			case JAIL_PROFILE_MEDIUM:
				config.jc_profile = JAIL_PROFILE_POLICY_MEDIUM;
				break;
			case JAIL_PROFILE_HIGH:
				config.jc_profile = JAIL_PROFILE_POLICY_HIGH;
				break;
			default:
				return EINVAL;
			}
		}
		if ((flags & JAIL_CREATE_CPU_QUOTA) != 0) {
			if (create.jc_cpu_quota == 0)
				return EINVAL;
			config.jc_cpu_quota = create.jc_cpu_quota;
		}
		if ((flags & JAIL_CREATE_CPU_PERIOD) != 0) {
			if (create.jc_cpu_period == 0)
				return EINVAL;
			config.jc_cpu_period = create.jc_cpu_period;
		}
		if ((flags & JAIL_CREATE_MEMORY_MAX) != 0) {
			if (create.jc_memory_max == 0)
				return EINVAL;
			config.jc_memory_max = create.jc_memory_max;
		}
		if ((flags & JAIL_CREATE_PROC_MAX) != 0) {
			if (create.jc_proc_max == 0)
				return EINVAL;
			config.jc_proc_max = create.jc_proc_max;
		}
		if ((flags & JAIL_CREATE_FD_MAX) != 0) {
			if (create.jc_fd_max == 0)
				return EINVAL;
			config.jc_fd_max = create.jc_fd_max;
		}
		if ((flags & JAIL_CREATE_SOCKBUF_MAX) != 0) {
			if (create.jc_sockbuf_max == 0)
				return EINVAL;
			config.jc_sockbuf_max = create.jc_sockbuf_max;
		}
		if ((config.jc_cpu_quota != 0 && config.jc_cpu_period == 0) ||
		    (config.jc_cpu_quota == 0 && config.jc_cpu_period != 0))
			return EINVAL;
		configp = &config;
	} else {
		return EINVAL;
	}

	if (create.jc_name[0] == '\0' || create.jc_root[0] == '\0')
		return EINVAL;
	if (memchr(create.jc_name, '\n', sizeof(create.jc_name)) != NULL ||
	    memchr(create.jc_root, '\n', sizeof(create.jc_root)) != NULL)
		return EINVAL;
	error = secmodel_jail_create(&create, configp, &id);

	if (error != 0)
		return error;

	log(LOG_INFO,
	    "secmodel_jail: created jail id=%u name=\"%s\" root=\"%s\" profile=%u by pid=%d euid=%u\n",
	    id, create.jc_name, create.jc_root,
	    (unsigned)configp->jc_profile, l->l_proc->p_pid,
	    kauth_cred_geteuid(l->l_cred));
	create.jc_id = id;
	if (oldp == NULL) {
		*oldlenp = sizeof(create);
		return 0;
	}

	if (*oldlenp < sizeof(create))
		return ENOMEM;

	*oldlenp = sizeof(create);
	return sysctl_copyout(l, &create, oldp, sizeof(create));
}

/*
 * sysctl handler for security.models.jail.destroy
 *
 * Writing a jail id destroys it if there are no remaining processes.
 */
static int
secmodel_jail_sysctl_destroy(SYSCTLFN_ARGS)
{
	uint32_t id;
	int error;

	if (newp == NULL)
		return EINVAL;

	if (!secmodel_jail_is_host_root(l->l_cred))
		return EPERM;

	if (newlen < sizeof(id))
		return EINVAL;

	error = sysctl_copyin(l, newp, &id, sizeof(id));
	if (error != 0)
		return error;

	if (id == JAILID_HOST)
		return EINVAL;

	if (secmodel_jail_has_processes(id))
		return EBUSY;

	error = secmodel_jail_destroy(id);
	if (error != 0)
		return error;

	log(LOG_INFO,
	    "secmodel_jail: destroyed jail id=%u by pid=%d euid=%u\n",
	    id, l->l_proc->p_pid, kauth_cred_geteuid(l->l_cred));

	return 0;
}

/*
 * sysctl handler for security.models.jail.id
 *
 * Reading returns the current process jail id. Writing an id requests the
 * process to enter that jail.
 */
static int
secmodel_jail_sysctl_id(SYSCTLFN_ARGS)
{
	jailid_t id;
	int error;
	struct sysctlnode node;

	if (!secmodel_jail_is_host_root(l->l_cred))
		return EPERM;

	id = secmodel_jail_cred_id(l->l_cred);

	node = *rnode;
	node.sysctl_data = &id;
	node.sysctl_size = sizeof(id);

	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return error;

	return secmodel_jail_enter(l, id);
}

/*
 * sysctl handler for security.models.jail.list
 *
 * Reading returns an array of jail_info entries with sampled process counts.
 */
static int
secmodel_jail_sysctl_list(SYSCTLFN_ARGS)
{
	struct jail_entry *entry;
	struct jail_info *entries;
	size_t count, i, needed, used;
	int error;
	bool retry;

	if (newp != NULL)
		return EPERM;
	if (!secmodel_jail_is_host_cred(l->l_cred))
		return EPERM;

	retry = false;
again:
	/*
	 * Snapshot path intentionally avoids proc_lock and only copies sampled
	 * counters from jail entries, keeping stats sysctl reads bounded.
	 */
	mutex_enter(&jail_lock);
	count = 0;
	LIST_FOREACH(entry, &jail_list, je_entry)
		count++;
	needed = count * sizeof(*entries);

	if (oldp == NULL) {
		mutex_exit(&jail_lock);
		*oldlenp = needed;
		return 0;
	}

	if (count == 0) {
		mutex_exit(&jail_lock);
		*oldlenp = 0;
		return 0;
	}
	mutex_exit(&jail_lock);

	if (*oldlenp < needed)
		return ENOMEM;

	entries = kmem_zalloc(needed, KM_SLEEP);

	mutex_enter(&jail_lock);
	i = 0;
	LIST_FOREACH(entry, &jail_list, je_entry) {
		if (i >= count) {
			retry = true;
			break;
		}
		entries[i].ji_id = entry->je_id;
		entries[i].ji_refcount = entry->je_refcount;
		entries[i].ji_cpu_quota = entry->je_cpu_quota;
		entries[i].ji_cpu_period = entry->je_cpu_period;
		entries[i].ji_memory_max = entry->je_memory_max;
		entries[i].ji_proc_max = entry->je_proc_max;
		entries[i].ji_fd_max = entry->je_fd_max;
		entries[i].ji_sockbuf_max = entry->je_sockbuf_max;
		entries[i].ji_proc_current = entry->je_proc_current;
		entries[i].ji_fd_current = entry->je_fd_current;
		entries[i].ji_sockbuf_current = entry->je_sockbuf_current;
		entries[i].ji_memory_current = entry->je_memory_current;
		entries[i].ji_cpu_usage = entry->je_cpu_usage;
		entries[i].ji_deny_proc = entry->je_deny_proc;
		entries[i].ji_deny_fd = entry->je_deny_fd;
		entries[i].ji_deny_sockbuf = entry->je_deny_sockbuf;
		entries[i].ji_deny_memory = entry->je_deny_memory;
		entries[i].ji_throttle_cpu = entry->je_throttle_cpu;
		strlcpy(entries[i].ji_name, entry->je_name,
		    sizeof(entries[i].ji_name));
		strlcpy(entries[i].ji_root, entry->je_root,
		    sizeof(entries[i].ji_root));
		i++;
	}
	mutex_exit(&jail_lock);

	if (retry) {
		/*
		 * The list changed while copying. We intentionally retry to present a
		 * coherent snapshot rather than returning a partially mixed generation.
		 *
		 * TODO(next): consider lockless snapshot generation with sequence counters
		 * to avoid retries under heavy jail churn.
		 */
		kmem_free(entries, needed);
		retry = false;
		goto again;
	}

	used = i * sizeof(*entries);

	error = 0;
	for (i = 0; i < used / sizeof(*entries); i++) {
		error = sysctl_copyout(l, &entries[i], oldp,
		    sizeof(*entries));
		if (error != 0)
			break;
		oldp = (char *)oldp + sizeof(*entries);
	}

	if (error == 0)
		*oldlenp = used;

	kmem_free(entries, needed);
	return error;
}

/*
 * Create the sysctl tree for jail controls under security.models.jail.
 */
SYSCTL_SETUP(sysctl_security_jail_setup, "secmodel_jail sysctl")
{
	const struct sysctlnode *rnode;

	sysctl_createv(clog, 0, NULL, &rnode,
	       CTLFLAG_PERMANENT,
	       CTLTYPE_NODE, "models", NULL,
	       NULL, 0, NULL, 0,
	       CTL_SECURITY, CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, &rnode,
	       CTLFLAG_PERMANENT,
	       CTLTYPE_NODE, "jail",
	       SYSCTL_DESCR("Jail security model"),
	       NULL, 0, NULL, 0,
	       CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	       CTLFLAG_PERMANENT,
	       CTLTYPE_STRING, "name", NULL,
	       NULL, 0, __UNCONST(SECMODEL_JAIL_NAME), 0,
	       CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
	       CTLTYPE_INT, "id",
	       SYSCTL_DESCR("Current process jail id"),
	       secmodel_jail_sysctl_id, 0, NULL, 0,
	       CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
	       CTLTYPE_INT, "create",
	       SYSCTL_DESCR("Create a new jail id"),
	       secmodel_jail_sysctl_create, 0, NULL, 0,
	       CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
	       CTLTYPE_INT, "destroy",
	       SYSCTL_DESCR("Destroy a jail id with no processes"),
	       secmodel_jail_sysctl_destroy, 0, NULL, 0,
	       CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	       CTLFLAG_PERMANENT|CTLFLAG_READONLY,
	       CTLTYPE_STRUCT, "list",
	       SYSCTL_DESCR("List active jail ids"),
	       secmodel_jail_sysctl_list, 0, NULL, 0,
	       CTL_CREATE, CTL_EOL);

}

