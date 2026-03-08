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
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <secmodel/cell/secmodel_cell_int.h>

/*
 * Validate caller-supplied cell creation flags.
 *
 * This keeps the write-side ABI strict: unknown bits are rejected so future
 * extensions cannot be accidentally accepted with unexpected semantics.
 */
static int
secmodel_cell_validate_create_flags(uint32_t flags)
{
	if ((flags & ~(CELL_CREATE_PROFILE |
	    CELL_CREATE_PORTS)) != 0)
		return EINVAL;

	return 0;
}

/*
 * Validate optional reserved-port list in cell_create.
 */
static int
secmodel_cell_validate_create_ports(const struct cell_create *create)
{
	size_t i;
	size_t j;

	if ((create->jc_flags & CELL_CREATE_PORTS) == 0)
		return create->jc_nports == 0 ? 0 : EINVAL;

	if (create->jc_nports == 0 || create->jc_nports > CELL_PORTS_MAX)
		return EINVAL;

	for (i = 0; i < create->jc_nports; i++) {
		if (create->jc_ports[i] == 0)
			return EINVAL;
		for (j = i + 1; j < create->jc_nports; j++) {
			if (create->jc_ports[i] == create->jc_ports[j])
				return EINVAL;
		}
	}

	return 0;
}

/*
 * Translate cell_create into internal policy config.
 */
static int
secmodel_cell_build_config(const struct cell_create *create,
    struct cell_config *config)
{
	uint32_t flags;

	flags = create->jc_flags;
	memset(config, 0, sizeof(*config));
	config->jc_profile = CELL_PROFILE_POLICY_HIGH;

	if ((flags & CELL_CREATE_PROFILE) != 0) {
		switch (create->jc_profile) {
		case CELL_PROFILE_LOW:
			config->jc_profile = CELL_PROFILE_POLICY_LOW;
			break;
		case CELL_PROFILE_MEDIUM:
			config->jc_profile = CELL_PROFILE_POLICY_MEDIUM;
			break;
		case CELL_PROFILE_HIGH:
			config->jc_profile = CELL_PROFILE_POLICY_HIGH;
			break;
		default:
			return EINVAL;
		}
	}

	return 0;
}

/*
 * sysctl handler for security.models.cell.create
 *
 * Writing a value allocates a new cell id. The newly created id is returned
 * to userland.
 */
static int
secmodel_cell_sysctl_create(SYSCTLFN_ARGS)
{
	uint32_t id;
	int error;
	struct cell_create create;
	struct cell_config config;

	if (newp == NULL)
		return EINVAL;

	if (!secmodel_cell_is_host_root(l->l_cred))
		return EPERM;

	if (newlen != sizeof(create))
		return EINVAL;

	error = sysctl_copyin(l, newp, &create, sizeof(create));
	if (error != 0)
		return error;

	error = secmodel_cell_validate_create_flags(create.jc_flags);
	if (error != 0)
		return error;

	error = secmodel_cell_validate_create_ports(&create);
	if (error != 0)
		return error;

	error = secmodel_cell_build_config(&create, &config);
	if (error != 0)
		return error;

	if (create.jc_name[0] == '\0' || create.jc_root[0] == '\0')
		return EINVAL;
	if (memchr(create.jc_name, '\n', sizeof(create.jc_name)) != NULL ||
	    memchr(create.jc_root, '\n', sizeof(create.jc_root)) != NULL)
		return EINVAL;
	error = secmodel_cell_create(&create, &config, &id);

	if (error != 0)
		return error;

	log(LOG_INFO,
	    "secmodel_cell: created cell id=%u name=\"%s\" root=\"%s\" "
	    "profile=%u by pid=%d euid=%u\n",
	    id, create.jc_name, create.jc_root,
	    (unsigned)config.jc_profile, l->l_proc->p_pid,
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
 * sysctl handler for security.models.cell.destroy
 *
 * Writing a cell id destroys it if there are no remaining processes.
 */
static int
secmodel_cell_sysctl_destroy(SYSCTLFN_ARGS)
{
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

	if (secmodel_cell_has_processes(id))
		return EBUSY;

	error = secmodel_cell_destroy(id);
	if (error != 0)
		return error;

	log(LOG_INFO,
	    "secmodel_cell: destroyed cell id=%u by pid=%d euid=%u\n",
	    id, l->l_proc->p_pid, kauth_cred_geteuid(l->l_cred));

	return 0;
}

/*
 * sysctl handler for security.models.cell.id
 *
 * Reading returns the current process cell id. Writing an id requests the
 * process to enter that cell.
 */
static int
secmodel_cell_sysctl_id(SYSCTLFN_ARGS)
{
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

	return secmodel_cell_enter(l, id);
}

/*
 * sysctl handler for security.models.cell.list
 *
 * Reading returns an array of cell_info entries with snapshot counters.
 */
static int
secmodel_cell_sysctl_list(SYSCTLFN_ARGS)
{
	struct cell_entry *entry;
	struct cell_info *entries;
	size_t count, i, needed, used;
	int error;
	bool retry;

	if (newp != NULL)
		return EPERM;
	if (!secmodel_cell_is_host_root(l->l_cred))
		return EPERM;

	retry = false;
again:
	/*
	 * Snapshot path intentionally avoids proc_lock and only copies sampled
	 * counters from cell entries, keeping stats sysctl reads bounded.
	 */
	mutex_enter(&cell_lock);
	count = 0;
	LIST_FOREACH(entry, &cell_list, ce_entry)
		count++;
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
	i = 0;
	LIST_FOREACH(entry, &cell_list, ce_entry) {
		if (i >= count) {
			retry = true;
			break;
		}
		entries[i].ji_id = entry->ce_id;
		entries[i].ji_refcount = entry->ce_refcount;
		entries[i].ji_proc_current = entry->ce_proc_current;
		entries[i].ji_memory_current = entry->ce_memory_current;
		entries[i].ji_cpu_ticks_1s = entry->ce_cpu_ticks_1s;
		entries[i].ji_cpu_ticks_10s = entry->ce_cpu_ticks_10s;
		strlcpy(entries[i].ji_name, entry->ce_name,
		    sizeof(entries[i].ji_name));
		strlcpy(entries[i].ji_root, entry->ce_root,
		    sizeof(entries[i].ji_root));
		i++;
	}
	mutex_exit(&cell_lock);

	if (retry) {
		/*
		 * The list changed while copying. We intentionally retry to present a
		 * coherent snapshot rather than returning a partially mixed generation.
		 *
		 * TODO(next): consider lockless snapshot generation with sequence counters
		 * to avoid retries under heavy cell churn.
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
 * Create the sysctl tree for cell controls under security.models.cell.
 */
SYSCTL_SETUP(sysctl_security_cell_setup, "secmodel_cell sysctl")
{
	const struct sysctlnode *rnode;

	sysctl_createv(clog, 0, NULL, &rnode,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "models", NULL,
	    NULL, 0, NULL, 0,
	    CTL_SECURITY, CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, &rnode,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "cell",
	    SYSCTL_DESCR("Cell security model"),
	    NULL, 0, NULL, 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_STRING, "name", NULL,
	    NULL, 0, __UNCONST(SECMODEL_CELL_NAME), 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "id",
	    SYSCTL_DESCR("Current process cell id"),
	    secmodel_cell_sysctl_id, 0, NULL, 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_STRUCT, "create",
	    SYSCTL_DESCR("Create a new cell id"),
	    secmodel_cell_sysctl_create, 0, NULL, 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE,
	    CTLTYPE_INT, "destroy",
	    SYSCTL_DESCR("Destroy a cell id with no processes"),
	    secmodel_cell_sysctl_destroy, 0, NULL, 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READONLY,
	    CTLTYPE_STRUCT, "list",
	    SYSCTL_DESCR("List active cell ids"),
	    secmodel_cell_sysctl_list, 0, NULL, 0,
	    CTL_CREATE, CTL_EOL);

}
