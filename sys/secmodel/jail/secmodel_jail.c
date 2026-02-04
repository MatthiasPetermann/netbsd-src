/* $NetBSD$ */
/*-
 * Copyright (c) 2025
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
#include <sys/param.h>
#include <sys/kauth.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/mutex.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/jail.h>

#include <secmodel/secmodel.h>
#include <secmodel/jail/jail.h>

MODULE(MODULE_CLASS_SECMODEL, secmodel_jail, NULL);

static kauth_listener_t l_process;
static kauth_listener_t l_cred;

static secmodel_t jail_sm;
static kauth_key_t jail_key;

/*
 * Each jail is tracked by an entry in a global list. The entry only stores the
 * jail id and is used for creation/destruction and sysctl listing. Actual
 * membership is stored per-credential via kauth specificdata.
 */
struct jail_entry {
	jailid_t je_id;
	LIST_ENTRY(jail_entry) je_entry;
};

static LIST_HEAD(, jail_entry) jail_list =
    LIST_HEAD_INITIALIZER(jail_list);
static kmutex_t jail_lock;
static jailid_t jail_next_id = 1;

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

/*
 * Create a new jail id. The id is monotonic, starting at 1, and 0 is reserved
 * for the host. Returns the new id to the caller.
 */
static int
secmodel_jail_create(jailid_t *idp)
{
	struct jail_entry *entry;
	jailid_t id;

	mutex_enter(&jail_lock);
	if (jail_next_id == 0) {
		mutex_exit(&jail_lock);
		return EOVERFLOW;
	}

	id = jail_next_id++;
	entry = kmem_zalloc(sizeof(*entry), KM_SLEEP);
	entry->je_id = id;
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

	if (cur == id) {
		proc_crmod_leave(cred, NULL, false);
		return 0;
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
	uint32_t dummy;

	if (newp == NULL)
		return EINVAL;

	if (!secmodel_jail_is_host_root(l->l_cred))
		return EPERM;

	if (newlen < sizeof(dummy))
		return EINVAL;

	error = sysctl_copyin(l, newp, &dummy, sizeof(dummy));
	if (error != 0)
		return error;

	error = secmodel_jail_create(&id);
	if (error != 0)
		return error;

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

	return secmodel_jail_destroy(id);
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

	id = secmodel_jail_cred_id(l->l_cred);

	node = *rnode;
	node.sysctl_data = &id;
	node.sysctl_size = sizeof(id);

	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return error;

	if (!secmodel_jail_is_host_root(l->l_cred))
		return EPERM;

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
 * Enforces that signals and process visibility are limited to the same jail,
 * except for host root which is allowed everywhere.
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
		    NULL, NULL, NULL);
		if (error != 0)
			printf("secmodel_jail_modcmd::init: "
			    "secmodel_register returned %d\n", error);

		secmodel_jail_init();
		secmodel_jail_start();
		break;

	case MODULE_CMD_FINI:
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
