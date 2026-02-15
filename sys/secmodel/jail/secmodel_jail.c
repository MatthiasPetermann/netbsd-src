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
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/jail.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <uvm/uvm_extern.h>

#include <secmodel/secmodel.h>
#include <secmodel/jail/jail.h>

MODULE(MODULE_CLASS_SECMODEL, secmodel_jail, NULL);

static kauth_listener_t l_process;
static kauth_listener_t l_cred;

static secmodel_t jail_sm;
static kauth_key_t jail_key;

struct jail_config;

enum jail_resource_mode {
	JAIL_RESOURCE_RLIMIT = 0,
	JAIL_RESOURCE_AGGREGATE = 1,
};

#define	JAIL_CPU_MS_PER_SEC	1000ULL

static int jail_resource_mode = JAIL_RESOURCE_AGGREGATE;

static int	secmodel_jail_sysctl_resource_mode(SYSCTLFN_ARGS);
static rlim_t	secmodel_jail_cpu_ms_to_rlimit(uint64_t);
static uint64_t	secmodel_jail_proc_as_bytes(struct proc *);
static uint64_t	secmodel_jail_proc_cpu_ms(struct proc *);
static void	secmodel_jail_usage(jailid_t, uint64_t *, uint64_t *);
static bool	secmodel_jail_over_limit(jailid_t, const struct jail_config *,
		    struct proc *);
static int	secmodel_jail_enforce_memlimit(struct proc *, size_t);
static void	secmodel_jail_log_veto(const char *, jailid_t,
		    const struct jail_config *, uint64_t, uint64_t);

static struct timeval secmodel_jail_veto_log_last;
static const struct timeval secmodel_jail_veto_log_interval = { 5, 0 };

/*
 * Each jail is tracked by an entry in a global list. The entry only stores the
 * jail id and is used for creation/destruction and sysctl listing. Actual
 * membership is stored per-credential via kauth specificdata.
 */
struct jail_entry {
	jailid_t je_id;
	char je_name[JAIL_NAME_MAX + 1];
	char je_root[JAIL_ROOT_MAX + 1];
	bool je_has_cpu_limit;
	bool je_has_mem_limit;
	rlim_t je_cpu_limit;
	rlim_t je_mem_limit;
	LIST_ENTRY(jail_entry) je_entry;
};

static LIST_HEAD(, jail_entry) jail_list =
    LIST_HEAD_INITIALIZER(jail_list);
static kmutex_t jail_lock;
static jailid_t jail_next_id = 1;

static struct jail_entry *secmodel_jail_lookup(jailid_t);

struct jail_config {
	bool jc_has_cpu_limit;
	bool jc_has_mem_limit;
	rlim_t jc_cpu_limit;
	rlim_t jc_mem_limit;
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

	id = secmodel_jail_cred_id(cred);
	if (name == NULL) {
		return id == JAILID_HOST;
	}

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		return false;
	}
	if (strcmp(entry->je_name, name) != 0) {
		mutex_exit(&jail_lock);
		return false;
	}
	mutex_exit(&jail_lock);
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
	config->jc_has_cpu_limit = entry->je_has_cpu_limit;
	config->jc_has_mem_limit = entry->je_has_mem_limit;
	config->jc_cpu_limit = entry->je_cpu_limit;
	config->jc_mem_limit = entry->je_mem_limit;
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
	}
	if (config != NULL) {
		entry->je_has_cpu_limit = config->jc_has_cpu_limit;
		entry->je_has_mem_limit = config->jc_has_mem_limit;
		entry->je_cpu_limit = config->jc_cpu_limit;
		entry->je_mem_limit = config->jc_mem_limit;
	}
	LIST_INSERT_HEAD(&jail_list, entry, je_entry);
	mutex_exit(&jail_lock);

	*idp = id;
	return 0;
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
	struct jail_config config;
	int error;
	bool has_config;

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

	has_config = secmodel_jail_get_config(id, &config);
	if (has_config && jail_resource_mode == JAIL_RESOURCE_RLIMIT &&
	    (config.jc_has_cpu_limit || config.jc_has_mem_limit)) {
		struct rlimit lim;

		if (config.jc_has_cpu_limit) {
			lim.rlim_cur =
			    secmodel_jail_cpu_ms_to_rlimit(config.jc_cpu_limit);
			lim.rlim_max = lim.rlim_cur;
			error = dosetrlimit(l, p, RLIMIT_CPU, &lim);
			if (error != 0)
				return error;
		}
		if (config.jc_has_mem_limit) {
			lim.rlim_cur = config.jc_mem_limit;
			lim.rlim_max = config.jc_mem_limit;
			error = dosetrlimit(l, p, RLIMIT_AS, &lim);
			if (error != 0)
				return error;
		}
	}

	if (has_config && jail_resource_mode == JAIL_RESOURCE_AGGREGATE &&
	    secmodel_jail_over_limit(id, &config, cur == id ? NULL : p)) {
		uint64_t cpu_ms = 0, mem_bytes = 0;

		secmodel_jail_usage(id, &cpu_ms, &mem_bytes);
		secmodel_jail_log_veto("enter", id, &config, cpu_ms, mem_bytes);
		return EAGAIN;
	}

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


static uint64_t
secmodel_jail_proc_as_bytes(struct proc *p)
{
	struct vmspace *vm;

	KASSERT(mutex_owned(p->p_lock));

	vm = p->p_vmspace;
	if (vm == NULL)
		return 0;

	return (uint64_t)vm->vm_map.size;
}

static uint64_t
secmodel_jail_proc_cpu_ms(struct proc *p)
{
	struct timeval tv;

	KASSERT(mutex_owned(p->p_lock));
	bintime2timeval(&p->p_rtime, &tv);

	return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

static rlim_t
secmodel_jail_cpu_ms_to_rlimit(uint64_t cpu_ms)
{
	uint64_t secs;

	if (cpu_ms == 0)
		return 0;

	secs = (cpu_ms + (JAIL_CPU_MS_PER_SEC - 1)) / JAIL_CPU_MS_PER_SEC;
	if (secs > (uint64_t)RLIM_INFINITY)
		return RLIM_INFINITY;

	return (rlim_t)secs;
}

static void
secmodel_jail_usage(jailid_t id, uint64_t *cpu_ms, uint64_t *mem_bytes)
{
	struct proc *p;

	if (cpu_ms != NULL)
		*cpu_ms = 0;
	if (mem_bytes != NULL)
		*mem_bytes = 0;

	mutex_enter(&proc_lock);
	PROCLIST_FOREACH(p, &allproc) {
		if (secmodel_jail_cred_id(p->p_cred) != id)
			continue;

		mutex_enter(p->p_lock);
		if (cpu_ms != NULL)
			*cpu_ms += secmodel_jail_proc_cpu_ms(p);
		if (mem_bytes != NULL)
			*mem_bytes += secmodel_jail_proc_as_bytes(p);
		mutex_exit(p->p_lock);
	}
	mutex_exit(&proc_lock);
}

static bool
secmodel_jail_over_limit(jailid_t id, const struct jail_config *config,
    struct proc *newproc)
{
	uint64_t cpu_ms;
	uint64_t mem_bytes;

	/*
	 * Evaluate limits against a jail-wide aggregate snapshot.  This is
	 * intentionally done in terms of per-process accounting data so that
	 * all enforcement points (enter/fork/grow) use the same policy.
	 *
	 * CPU is admission-oriented in aggregate mode: once over the jail
	 * aggregate limit, enter/fork can be denied, but existing runnable
	 * members are not asynchronously signalled from this path.
	 */
	secmodel_jail_usage(id, &cpu_ms, &mem_bytes);

	if (newproc != NULL) {
		mutex_enter(newproc->p_lock);
		cpu_ms += secmodel_jail_proc_cpu_ms(newproc);
		mem_bytes += secmodel_jail_proc_as_bytes(newproc);
		mutex_exit(newproc->p_lock);
	}

	if (config->jc_has_cpu_limit && cpu_ms >= config->jc_cpu_limit)
		return true;
	if (config->jc_has_mem_limit && mem_bytes >= config->jc_mem_limit)
		return true;

	return false;
}



static void
secmodel_jail_log_veto(const char *where, jailid_t id,
    const struct jail_config *config, uint64_t cpu_ms, uint64_t mem_bytes)
{

	if (!ratecheck(&secmodel_jail_veto_log_last,
	    &secmodel_jail_veto_log_interval))
		return;

	log(LOG_INFO,
	    "secmodel_jail: resource veto at %s for jail id=%u "
	    "(cpu=%jums%s, mem=%juB%s)\n",
	    where, id, (uintmax_t)cpu_ms,
	    config->jc_has_cpu_limit ? "" : ", no cpu limit",
	    (uintmax_t)mem_bytes,
	    config->jc_has_mem_limit ? "" : ", no mem limit");
}


static int
secmodel_jail_enforce_memlimit(struct proc *p, size_t grow)
{
	struct jail_config config;
	jailid_t id;
	uint64_t mem_bytes;

	if (p == NULL || grow == 0)
		return 0;
	if (jail_resource_mode != JAIL_RESOURCE_AGGREGATE)
		return 0;

	mutex_enter(p->p_lock);
	id = secmodel_jail_cred_id(p->p_cred);
	mutex_exit(p->p_lock);
	if (id == JAILID_HOST)
		return 0;
	if (!secmodel_jail_get_config(id, &config) || !config.jc_has_mem_limit)
		return 0;

	secmodel_jail_usage(id, NULL, &mem_bytes);
	if (mem_bytes + (uint64_t)grow > config.jc_mem_limit) {
		secmodel_jail_log_veto("uvm_grow", id, &config, 0,
		    mem_bytes + (uint64_t)grow);
		return ENOMEM;
	}

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
	uint32_t dummy;
	struct jail_create create;
	struct jail_config config;
	struct jail_config *configp;
	uint32_t flags;

	if (newp == NULL)
		return EINVAL;

	if (!secmodel_jail_is_host_root(l->l_cred))
		return EPERM;

	if (newlen == sizeof(dummy)) {
		error = sysctl_copyin(l, newp, &dummy, sizeof(dummy));
		if (error != 0)
			return error;
		configp = NULL;
	} else if (newlen == sizeof(create)) {
		error = sysctl_copyin(l, newp, &create, sizeof(create));
		if (error != 0)
			return error;

		flags = create.jc_flags;
		if ((flags & ~(JAIL_CREATE_MEMLIMIT |
		    JAIL_CREATE_CPULIMIT)) != 0)
			return EINVAL;

		memset(&config, 0, sizeof(config));
		if ((flags & JAIL_CREATE_MEMLIMIT) != 0) {
			if (create.jc_mem_limit == 0)
				return EINVAL;
			config.jc_has_mem_limit = true;
			config.jc_mem_limit = (rlim_t)create.jc_mem_limit;
		}
		if ((flags & JAIL_CREATE_CPULIMIT) != 0) {
			if (create.jc_cpu_limit == 0)
				return EINVAL;
			config.jc_has_cpu_limit = true;
			config.jc_cpu_limit = (rlim_t)create.jc_cpu_limit;
		}
		configp = &config;
	} else {
		return EINVAL;
	}

	if (newlen == sizeof(create)) {
		if (create.jc_name[0] == '\0' || create.jc_root[0] == '\0')
			return EINVAL;
		if (memchr(create.jc_name, '\n', sizeof(create.jc_name)) != NULL ||
		    memchr(create.jc_root, '\n', sizeof(create.jc_root)) != NULL)
			return EINVAL;
		error = secmodel_jail_create(&create, configp, &id);
	} else {
		error = secmodel_jail_create(NULL, configp, &id);
	}

	if (error != 0)
		return error;

	if (newlen == sizeof(create)) {
		log(LOG_INFO,
		    "secmodel_jail: created jail id=%u name=\"%s\" root=\"%s\" by pid=%d euid=%u\n",
		    id, create.jc_name, create.jc_root, l->l_proc->p_pid,
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

	log(LOG_INFO,
	    "secmodel_jail: created jail id=%u by pid=%d euid=%u\n",
	    id, l->l_proc->p_pid, kauth_cred_geteuid(l->l_cred));

	if (oldp == NULL) {
		*oldlenp = 0;
		return 0;
	}

	if (*oldlenp < sizeof(id))
		return ENOMEM;

	*oldlenp = sizeof(id);
	return sysctl_copyout(l, &id, oldp, sizeof(id));
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

static int
secmodel_jail_sysctl_resource_mode(SYSCTLFN_ARGS)
{
	struct sysctlnode node;
	int mode;
	int error;

	if (!secmodel_jail_is_host_root(l->l_cred))
		return EPERM;

	mode = jail_resource_mode;
	node = *rnode;
	node.sysctl_data = &mode;
	node.sysctl_size = sizeof(mode);

	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error != 0 || newp == NULL)
		return error;

	if (mode != JAIL_RESOURCE_RLIMIT && mode != JAIL_RESOURCE_AGGREGATE)
		return EINVAL;

	/*
	 * Mode changes affect future checks.  Existing process RLIMIT values are
	 * left untouched; RLIMIT mode applies limits when a process enters a jail,
	 * while aggregate mode relies on jail-wide admission/memory-growth checks.
	 */
	jail_resource_mode = mode;
	return 0;
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

	sysctl_createv(clog, 0, &rnode, NULL,
	       CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
	       CTLTYPE_INT, "resource_mode",
	       SYSCTL_DESCR("Resource limit mode: 0=rlimit per-process, "
	       "1=aggregate per-jail"),
	       secmodel_jail_sysctl_resource_mode, 0, NULL, 0,
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
	uvm_proc_jail_memlimit_check = secmodel_jail_enforce_memlimit;
}

/*
 * Unregister listeners and clean up jail data.
 */
void
secmodel_jail_stop(void)
{
	struct jail_entry *entry;

	if (uvm_proc_jail_memlimit_check == secmodel_jail_enforce_memlimit)
		uvm_proc_jail_memlimit_check = NULL;

	kauth_unlisten_scope(l_process);
	kauth_unlisten_scope(l_cred);
	kauth_deregister_key(jail_key);

	mutex_enter(&jail_lock);
	while ((entry = LIST_FIRST(&jail_list)) != NULL) {
		LIST_REMOVE(entry, je_entry);
		kmem_free(entry, sizeof(*entry));
	}
	mutex_exit(&jail_lock);
	mutex_destroy(&jail_lock);
}

/*
 * kauth(9) listener for process scope.
 *
 * Enforces jail-local process visibility/signal policy and, in aggregate
 * resource mode, performs admission control for fork(2).
 *
 * Note that aggregate CPU enforcement is intentionally admission-based here:
 * once a process is running, no per-tick jail-wide CPU throttling or kill
 * action is performed by this model.  Runtime CPU signalling semantics are
 * provided only by per-process RLIMIT_CPU in RLIMIT mode.
 */
int
secmodel_jail_process_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	struct proc *p;
	struct jail_config config;
	jailid_t id;

	(void)cookie;
	(void)arg1;
	(void)arg2;
	(void)arg3;

	switch (action) {
	case KAUTH_PROCESS_FORK:
		if (jail_resource_mode != JAIL_RESOURCE_AGGREGATE)
			return KAUTH_RESULT_DEFER;
		if (secmodel_jail_is_host_root(cred))
			return KAUTH_RESULT_DEFER;
		id = secmodel_jail_cred_id(cred);
		if (!secmodel_jail_get_config(id, &config))
			return KAUTH_RESULT_DEFER;
		if (!config.jc_has_cpu_limit && !config.jc_has_mem_limit)
			return KAUTH_RESULT_DEFER;
		if (secmodel_jail_over_limit(id, &config, NULL)) {
			uint64_t cpu_ms = 0, mem_bytes = 0;

			secmodel_jail_usage(id, &cpu_ms, &mem_bytes);
			secmodel_jail_log_veto("fork", id, &config, cpu_ms,
			    mem_bytes);
			return KAUTH_RESULT_DENY;
		}
		return KAUTH_RESULT_DEFER;
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
	*matchp = secmodel_jail_cred_matches(a->cred, a->name);
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
		log(LOG_INFO, "secmodel_jail: loaded (resource_mode=%d)\n",
		    jail_resource_mode);
		break;

	case MODULE_CMD_FINI:
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
