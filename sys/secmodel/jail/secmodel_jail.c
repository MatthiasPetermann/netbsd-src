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
 *
 * secmodel_jail, jailctl, and jailmgr designed and implemented by
 * Matthias Petermann, inspired by FreeBSD jails.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/mutex.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/jail.h>

#include <netinet/in.h>

#include <secmodel/secmodel.h>
#include <secmodel/jail/jail.h>

MODULE(MODULE_CLASS_SECMODEL, secmodel_jail, NULL);

static kauth_listener_t l_process;
static kauth_listener_t l_cred;
static kauth_listener_t l_system;
static kauth_listener_t l_network;

static secmodel_t jail_sm;
static kauth_key_t jail_key;

struct jail_config;

enum jail_policy_profile {
	JAIL_PROFILE_POLICY_LOW = JAIL_PROFILE_LOW,
	JAIL_PROFILE_POLICY_MEDIUM = JAIL_PROFILE_MEDIUM,
	JAIL_PROFILE_POLICY_HIGH = JAIL_PROFILE_HIGH,
};

static int	secmodel_jail_system_cb(kauth_cred_t, kauth_action_t, void *,
		    void *, void *, void *, void *);
static int	secmodel_jail_network_cb(kauth_cred_t, kauth_action_t, void *,
		    void *, void *, void *, void *);
static bool	secmodel_jail_port_reserved_by_id(jailid_t, in_port_t);
static bool	secmodel_jail_port_reserved_any(in_port_t);
static bool	secmodel_jail_addr_port(const struct sockaddr *, in_port_t *);
static bool	secmodel_jail_has_entries(void);

/*
 * Each jail is tracked by an entry in a global list. The entry only stores the
 * jail id and is used for creation/destruction and sysctl listing. Actual
 * membership is stored per-credential via kauth specificdata.
 */
struct jail_entry {
	jailid_t je_id;
	char je_name[JAIL_NAME_MAX + 1];
	char je_root[JAIL_ROOT_MAX + 1];
	uint64_t je_cpu_quota;
	uint64_t je_cpu_period;
	uint64_t je_cpu_weight;
	uint64_t je_memory_max;
	uint64_t je_proc_max;
	uint64_t je_fd_max;
	uint64_t je_sockbuf_max;
	enum jail_policy_profile je_profile;
	uint64_t je_proc_current;
	uint64_t je_fd_current;
	uint64_t je_sockbuf_current;
	uint64_t je_memory_current;
	uint64_t je_cpu_usage;
	uint64_t je_deny_proc;
	uint64_t je_deny_fd;
	uint64_t je_deny_sockbuf;
	uint64_t je_deny_memory;
	uint64_t je_throttle_cpu;
	uint16_t je_nports;
	uint16_t je_ports[JAIL_PORTS_MAX];
	LIST_ENTRY(jail_entry) je_entry;
};

static LIST_HEAD(, jail_entry) jail_list =
    LIST_HEAD_INITIALIZER(jail_list);
static kmutex_t jail_lock;
static jailid_t jail_next_id = 1;

static struct jail_entry *secmodel_jail_lookup(jailid_t);

struct jail_config {
	uint64_t jc_cpu_quota;
	uint64_t jc_cpu_period;
	uint64_t jc_cpu_weight;
	uint64_t jc_memory_max;
	uint64_t jc_proc_max;
	uint64_t jc_fd_max;
	uint64_t jc_sockbuf_max;
	enum jail_policy_profile jc_profile;
};

/*
 * Fetch the jail id associated with a credential. The value lives in the
 * secmodel-specific kauth data slot.
 */
static jailid_t
secmodel_jail_cred_id(kauth_cred_t cred)
{
	void *data;

	data = kauth_cred_getdata(cred, jail_key);
	return (jailid_t)(uintptr_t)data;
}

/*
 * Set the jail id on a credential. This is the only state we store for
 * membership; all policy checks rely on this value.
 */
static void
secmodel_jail_cred_setid(kauth_cred_t cred, jailid_t id)
{
	kauth_cred_setdata(cred, jail_key, (void *)(uintptr_t)id);
}

bool
secmodel_jail_cred_matches(kauth_cred_t cred, const char *name)
{
	const struct jail_entry *entry;
	jailid_t id;
	bool match;

	id = secmodel_jail_cred_id(cred);
	if (name == NULL) {
		match = id == JAILID_HOST;
		log(LOG_DEBUG,
		    "secmodel_jail debug: cred_matches id=%u name=<none> match=%d\n",
		    (unsigned)id, match);
		return match;
	}

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		log(LOG_DEBUG,
		    "secmodel_jail debug: cred_matches id=%u name=\"%s\" match=0 (entry missing)\n",
		    (unsigned)id, name);
		return false;
	}
	if (strcmp(entry->je_name, name) != 0) {
		mutex_exit(&jail_lock);
		log(LOG_DEBUG,
		    "secmodel_jail debug: cred_matches id=%u name=\"%s\" entry=\"%s\" match=0\n",
		    (unsigned)id, name, entry->je_name);
		return false;
	}
	mutex_exit(&jail_lock);
	log(LOG_DEBUG,
	    "secmodel_jail debug: cred_matches id=%u name=\"%s\" match=1\n",
	    (unsigned)id, name);
	return true;
}

/*
 * Host root (euid 0, jail id 0) bypasses jail restrictions.
 */
static bool
secmodel_jail_is_host_root(kauth_cred_t cred)
{
	return kauth_cred_geteuid(cred) == 0 &&
	    secmodel_jail_cred_id(cred) == JAILID_HOST;
}

/*
 * Determine whether a credential can interact with a target process.
 * Host root can always interact. Otherwise, both must be in the same jail.
 */
static bool
secmodel_jail_match(kauth_cred_t cred, struct proc *p)
{
	if (secmodel_jail_is_host_root(cred))
		return true;

	return secmodel_jail_cred_id(cred) ==
	    secmodel_jail_cred_id(p->p_cred);
}

/*
 * Look up a jail entry by id. Callers must hold jail_lock.
 */
static struct jail_entry *
secmodel_jail_lookup(jailid_t id)
{
	struct jail_entry *entry;

	LIST_FOREACH(entry, &jail_list, je_entry) {
		if (entry->je_id == id)
			return entry;
	}

	return NULL;
}

static struct jail_entry *
secmodel_jail_lookup_name(const char *name)
{
	struct jail_entry *entry;

	LIST_FOREACH(entry, &jail_list, je_entry) {
		if (strcmp(entry->je_name, name) == 0)
			return entry;
	}

	return NULL;
}

static bool
secmodel_jail_get_config(jailid_t id, struct jail_config *config)
{
	struct jail_entry *entry;

	if (id == JAILID_HOST)
		return false;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		return false;
	}
	config->jc_cpu_quota = entry->je_cpu_quota;
	config->jc_cpu_period = entry->je_cpu_period;
	config->jc_cpu_weight = entry->je_cpu_weight;
	config->jc_memory_max = entry->je_memory_max;
	config->jc_proc_max = entry->je_proc_max;
	config->jc_fd_max = entry->je_fd_max;
	config->jc_sockbuf_max = entry->je_sockbuf_max;
	config->jc_profile = entry->je_profile;
	mutex_exit(&jail_lock);

	return true;
}

/*
 * Create a new jail id. The id is monotonic, starting at 1, and 0 is reserved
 * for the host. Returns the new id to the caller.
 */
static int
secmodel_jail_create(const struct jail_create *create,
    const struct jail_config *config, jailid_t *idp)
{
	struct jail_entry *entry;
	jailid_t id;

	mutex_enter(&jail_lock);
	if (create != NULL && create->jc_name[0] != '\0' &&
	    secmodel_jail_lookup_name(create->jc_name) != NULL) {
		mutex_exit(&jail_lock);
		return EEXIST;
	}

	if (create != NULL &&
	    (create->jc_flags & JAIL_CREATE_PORTS) != 0) {
		size_t i;

		for (i = 0; i < create->jc_nports; i++) {
			if (create->jc_ports[i] == 0) {
				mutex_exit(&jail_lock);
				return EINVAL;
			}
			if (secmodel_jail_port_reserved_any(htons(create->jc_ports[i]))) {
				mutex_exit(&jail_lock);
				return EEXIST;
			}
		}
	}

	if (jail_next_id == 0) {
		mutex_exit(&jail_lock);
		return EOVERFLOW;
	}

	id = jail_next_id++;

	entry = kmem_zalloc(sizeof(*entry), KM_SLEEP);
	entry->je_id = id;
	if (create != NULL) {
		strlcpy(entry->je_name, create->jc_name, sizeof(entry->je_name));
		strlcpy(entry->je_root, create->jc_root, sizeof(entry->je_root));
		if ((create->jc_flags & JAIL_CREATE_PORTS) != 0) {
			entry->je_nports = create->jc_nports;
			memcpy(entry->je_ports, create->jc_ports,
			    sizeof(create->jc_ports));
		}
	}
	if (config != NULL) {
		entry->je_cpu_quota = config->jc_cpu_quota;
		entry->je_cpu_period = config->jc_cpu_period;
		entry->je_cpu_weight = config->jc_cpu_weight;
		entry->je_memory_max = config->jc_memory_max;
		entry->je_proc_max = config->jc_proc_max;
		entry->je_fd_max = config->jc_fd_max;
		entry->je_sockbuf_max = config->jc_sockbuf_max;
		entry->je_profile = config->jc_profile;
	} else {
		entry->je_profile = JAIL_PROFILE_POLICY_HIGH;
	}
	LIST_INSERT_HEAD(&jail_list, entry, je_entry);
	mutex_exit(&jail_lock);

	*idp = id;
	return 0;
}

static bool
secmodel_jail_port_reserved_by_id(jailid_t id, in_port_t lport)
{
	struct jail_entry *entry;
	size_t i;

	entry = secmodel_jail_lookup(id);
	if (entry == NULL)
		return false;

	for (i = 0; i < entry->je_nports; i++) {
		if (htons(entry->je_ports[i]) == lport)
			return true;
	}

	return false;
}

static bool
secmodel_jail_port_reserved_any(in_port_t lport)
{
	struct jail_entry *entry;
	size_t i;

	LIST_FOREACH(entry, &jail_list, je_entry) {
		for (i = 0; i < entry->je_nports; i++) {
			if (htons(entry->je_ports[i]) == lport)
				return true;
		}
	}

	return false;
}

static bool
secmodel_jail_addr_port(const struct sockaddr *sa, in_port_t *port)
{
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
 * Check whether any jail ids still exist.
 */
static bool
secmodel_jail_has_entries(void)
{
	bool has_entries;

	mutex_enter(&jail_lock);
	has_entries = LIST_FIRST(&jail_list) != NULL;
	mutex_exit(&jail_lock);

	return has_entries;
}

/*
 * Check whether any process (including zombies) currently belongs to the
 * specified jail id. Used to prevent destroying active jails.
 */
static bool
secmodel_jail_has_processes(jailid_t id)
{
	struct proc *p;
	bool found = false;

	mutex_enter(&proc_lock);
	PROCLIST_FOREACH(p, &allproc) {
		if (secmodel_jail_cred_id(p->p_cred) == id) {
			found = true;
			break;
		}
	}
	if (!found) {
		PROCLIST_FOREACH(p, &zombproc) {
			if (secmodel_jail_cred_id(p->p_cred) == id) {
				found = true;
				break;
			}
		}
	}
	mutex_exit(&proc_lock);

	return found;
}

/*
 * Remove a jail entry. This does not touch processes; callers should ensure
 * there are no remaining members before destroying.
 */
static int
secmodel_jail_destroy(jailid_t id)
{
	struct jail_entry *entry;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		return ENOENT;
	}

	LIST_REMOVE(entry, je_entry);
	mutex_exit(&jail_lock);

	kmem_free(entry, sizeof(*entry));
	return 0;
}

/*
 * Move the calling process into the specified jail id.
 *
 * This is a privileged operation: only host root can enter (and only into
 * an existing jail). The jail id is stored in the process credentials to
 * ensure it follows the process and its children.
 */
static int
secmodel_jail_enter(struct lwp *l, jailid_t id)
{
	struct proc *p;
	kauth_cred_t cred, ncred;
	jailid_t cur;

	p = l->l_proc;
	proc_crmod_enter();
	cred = p->p_cred;
	cur = secmodel_jail_cred_id(cred);

	if (!secmodel_jail_is_host_root(l->l_cred)) {
		proc_crmod_leave(cred, NULL, false);
		return EPERM;
	}

	if (cur != JAILID_HOST && cur != id) {
		proc_crmod_leave(cred, NULL, false);
		return EPERM;
	}

	if (id != JAILID_HOST) {
		mutex_enter(&jail_lock);
		if (secmodel_jail_lookup(id) == NULL) {
			mutex_exit(&jail_lock);
			proc_crmod_leave(cred, NULL, false);
			return ENOENT;
		}
		mutex_exit(&jail_lock);
	}
	proc_crmod_leave(cred, NULL, false);

	if (cur == id) {
		return 0;
	}

	proc_crmod_enter();
	cred = p->p_cred;
	cur = secmodel_jail_cred_id(cred);
	if (!secmodel_jail_is_host_root(l->l_cred)) {
		proc_crmod_leave(cred, NULL, false);
		return EPERM;
	}
	if (cur != JAILID_HOST && cur != id) {
		proc_crmod_leave(cred, NULL, false);
		return EPERM;
	}
	if (id != JAILID_HOST) {
		mutex_enter(&jail_lock);
		if (secmodel_jail_lookup(id) == NULL) {
			mutex_exit(&jail_lock);
			proc_crmod_leave(cred, NULL, false);
			return ENOENT;
		}
		mutex_exit(&jail_lock);
	}
	ncred = kauth_cred_alloc();
	kauth_cred_clone(cred, ncred);
	secmodel_jail_cred_setid(ncred, id);
	proc_crmod_leave(ncred, cred, true);

	return 0;
}

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
		    JAIL_CREATE_CPU_WEIGHT |
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
		if ((flags & JAIL_CREATE_CPU_WEIGHT) != 0)
			config.jc_cpu_weight = create.jc_cpu_weight;
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
 * Reading returns an array of jail_info entries with current process counts.
 */
static int
secmodel_jail_sysctl_list(SYSCTLFN_ARGS)
{
	struct jail_entry *entry;
	struct jail_info *entries;
	size_t count, i, needed;
	int error;
	struct proc *p;

	if (newp != NULL)
		return EPERM;
	if (!secmodel_jail_is_host_root(l->l_cred))
		return EPERM;

	mutex_enter(&jail_lock);
	count = 0;
	LIST_FOREACH(entry, &jail_list, je_entry)
		count++;

	if (count == 0) {
		mutex_exit(&jail_lock);
		*oldlenp = 0;
		return 0;
	}

	entries = kmem_zalloc(count * sizeof(*entries), KM_SLEEP);
	i = 0;
	LIST_FOREACH(entry, &jail_list, je_entry) {
		entries[i].ji_id = entry->je_id;
		entries[i].ji_refcount = 0;
		entries[i].ji_cpu_quota = entry->je_cpu_quota;
		entries[i].ji_cpu_period = entry->je_cpu_period;
		entries[i].ji_cpu_weight = entry->je_cpu_weight;
		entries[i].ji_memory_max = entry->je_memory_max;
		entries[i].ji_proc_max = entry->je_proc_max;
		entries[i].ji_fd_max = entry->je_fd_max;
		entries[i].ji_sockbuf_max = entry->je_sockbuf_max;
		entries[i].ji_proc_current = 0;
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

	mutex_enter(&proc_lock);
	PROCLIST_FOREACH(p, &allproc) {
		jailid_t id;

		id = secmodel_jail_cred_id(p->p_cred);
		for (i = 0; i < count; i++) {
			if (entries[i].ji_id == id) {
				entries[i].ji_refcount++;
				entries[i].ji_proc_current++;
				break;
			}
		}
	}
	PROCLIST_FOREACH(p, &zombproc) {
		jailid_t id;

		id = secmodel_jail_cred_id(p->p_cred);
		for (i = 0; i < count; i++) {
			if (entries[i].ji_id == id) {
				entries[i].ji_refcount++;
				entries[i].ji_proc_current++;
				break;
			}
		}
	}
	mutex_exit(&proc_lock);

	needed = count * sizeof(*entries);
	if (oldp == NULL) {
		*oldlenp = needed;
		kmem_free(entries, needed);
		return 0;
	}

	if (*oldlenp < needed) {
		kmem_free(entries, needed);
		return ENOMEM;
	}

	error = 0;
	for (i = 0; i < count; i++) {
		error = sysctl_copyout(l, &entries[i], oldp,
		    sizeof(*entries));
		if (error != 0)
			break;
		oldp = (char *)oldp + sizeof(*entries);
	}

	if (error == 0)
		*oldlenp = needed;

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

/*
 * Initialize secmodel jail structures and register per-credential storage.
 */
void
secmodel_jail_init(void)
{
	mutex_init(&jail_lock, MUTEX_DEFAULT, IPL_NONE);
	if (kauth_register_key(jail_sm, &jail_key) != 0)
		printf("secmodel_jail: unable to register kauth key\n");
}

/*
 * Register kauth listeners for process checks and credential lifecycle hooks.
 */
void
secmodel_jail_start(void)
{
	l_process = kauth_listen_scope(KAUTH_SCOPE_PROCESS,
	    secmodel_jail_process_cb, NULL);
	l_cred = kauth_listen_scope(KAUTH_SCOPE_CRED,
	    secmodel_jail_cred_cb, NULL);
	l_system = kauth_listen_scope(KAUTH_SCOPE_SYSTEM,
	    secmodel_jail_system_cb, NULL);
	l_network = kauth_listen_scope(KAUTH_SCOPE_NETWORK,
	    secmodel_jail_network_cb, NULL);
}

/*
 * Unregister listeners and clean up jail data.
 */
void
secmodel_jail_stop(void)
{
	struct jail_entry *entry;

	kauth_unlisten_scope(l_process);
	kauth_unlisten_scope(l_cred);
	kauth_unlisten_scope(l_system);
	kauth_unlisten_scope(l_network);
	kauth_deregister_key(jail_key);

	mutex_enter(&jail_lock);
	while ((entry = LIST_FIRST(&jail_list)) != NULL) {
		LIST_REMOVE(entry, je_entry);
		kmem_free(entry, sizeof(*entry));
	}
	mutex_exit(&jail_lock);
	mutex_destroy(&jail_lock);
}

static int
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
static int
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

	if (config.jc_profile == JAIL_PROFILE_POLICY_LOW)
		return KAUTH_RESULT_DEFER;

	req = (enum kauth_system_req)(uintptr_t)arg0;

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
		case KAUTH_REQ_SYSTEM_SYSCTL_PRVT: /* Block reads of private/protected sysctls. */
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

		id = secmodel_jail_cred_id(cred);
		if (id == JAILID_HOST)
			return KAUTH_RESULT_DEFER;

		current = 0;
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

		mutex_enter(&jail_lock);
		entry = secmodel_jail_lookup(id);
		if (entry != NULL) {
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

static int
secmodel_jail_eval(const char *what, void *arg, void *ret)
{
	const struct secmodel_jail_eval_cred_matches_args *a;
	bool *matchp;

	if (strcasecmp(what, SECMODEL_JAIL_EVAL_CRED_MATCHES) != 0)
		return ENOENT;
	if (arg == NULL || ret == NULL)
		return EINVAL;

	a = arg;
	matchp = ret;
	log(LOG_DEBUG,
	    "secmodel_jail debug: eval what=\"%s\" cred_matches name=%s\n",
	    what, a->name ? a->name : "<none>");
	*matchp = secmodel_jail_cred_matches(a->cred, a->name);
	log(LOG_DEBUG,
	    "secmodel_jail debug: eval result what=\"%s\" match=%d\n",
	    what, *matchp);
	return 0;
}

/*
 * Module command handler: register/deregister the security model.
 */
static int
secmodel_jail_modcmd(modcmd_t cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MODULE_CMD_INIT:
		error = secmodel_register(&jail_sm,
		    SECMODEL_JAIL_ID, SECMODEL_JAIL_NAME,
		    NULL, secmodel_jail_eval, NULL);
		if (error != 0)
			printf("secmodel_jail_modcmd::init: "
			    "secmodel_register returned %d\n", error);

		secmodel_jail_init();
		secmodel_jail_start();
		log(LOG_INFO, "secmodel_jail: loaded\n");
		break;

	case MODULE_CMD_FINI:
		if (secmodel_jail_has_entries())
			return EBUSY;

		log(LOG_INFO, "secmodel_jail: unloading\n");
		secmodel_jail_stop();

		error = secmodel_deregister(jail_sm);
		if (error != 0)
			printf("secmodel_jail_modcmd::fini: "
			    "secmodel_deregister returned %d\n", error);
		break;

	default:
		error = ENOTTY;
		break;
	}

	return error;
}
