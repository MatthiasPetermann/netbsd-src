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
#include <sys/atomic.h>
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
#include <sys/callout.h>

#include <netinet/in.h>

#include <secmodel/secmodel.h>
#include <secmodel/jail/jail.h>

#include <secmodel/jail/secmodel_jail_int.h>

secmodel_t jail_sm;
kauth_key_t jail_key;

static kauth_listener_t l_process;
static kauth_listener_t l_cred;
static kauth_listener_t l_system;
static kauth_listener_t l_network;

/*
 * Big picture for newcomers:
 *
 * This file implements a kernel security model that groups processes into
 * "jails" and then applies policy/rate limits per jail id.
 *
 * The core idea is intentionally simple:
 * 1) Each credential gets one integer jail id via kauth specificdata.
 * 2) Global policy/configuration for each jail id lives in `jail_list`.
 * 3) kauth listeners consult both pieces to allow/deny actions.
 *
 * Why this split exists:
 * - Credential data must be tiny and cheap to copy on fork/exec paths.
 * - Rich per-jail metadata (limits, names, counters) is shared global state.
 * - This keeps process credential operations fast while still allowing
 *   userland management via sysctl.
 *
 * TODO(next): Replace linear jail lookup with an id-indexed structure
 * (for example a hash table or pserialize-friendly map) once jail counts grow.
 * The current LIST walk is simple and robust but O(n) on every lookup.
 */
LIST_HEAD(, jail_entry) jail_list =
    LIST_HEAD_INITIALIZER(jail_list);
kmutex_t jail_lock;
static jailid_t jail_next_id = 1;
static struct callout jail_cpu_account_ch;
unsigned int jail_cpu_limits_active;

/*
 * Locking contract (important for deadlock avoidance):
 *
 * - If code needs both process lists and jail metadata, lock order is always:
 *     proc_lock -> jail_lock
 * - Never grab proc_lock while already holding jail_lock.
 *
 * Why: lots of process-manipulating kernel paths already use proc_lock. If we
 * invert the order in one place, rare deadlocks can appear under load and are
 * extremely hard to debug.
 */

struct jail_entry *secmodel_jail_lookup(jailid_t);
static void secmodel_jail_cpu_account_tick(void *);

void
secmodel_jail_assert_jail_lock_held(void)
{

	KASSERT(mutex_owned(&jail_lock));
}

bool
secmodel_jail_cpu_limit_enabled(const struct jail_entry *entry)
{

	return entry->je_cpu_quota != 0 && entry->je_cpu_period != 0;
}

/*
 * Generic helper for jail-scoped "current + delta <= limit" admission.
 *
 * A limit value of zero means "unlimited" for that specific resource.
 *
 * Why this helper exists:
 * - all limit checks should share identical overflow-safe arithmetic
 * - duplicated ad-hoc checks are error-prone in kernel code
 */
static bool
secmodel_jail_within_limit(uint64_t current, uint64_t delta, uint64_t limit)
{

	if (limit == 0)
		return true;
	if (delta > UINT64_MAX - current)
		return false;
	return current + delta <= limit;
}

/*
 * Stage 1 + 2 CPU controller:
 * - Stage 1: account per-jail CPU ticks from process statclock counters.
 * - Stage 2: maintain quota/period windows and an over-quota state that is
 *   consumed by admission checks (currently fork-time throttling gate).
 * - Also samples per-jail process/ref counters consumed by list sysctl reads,
 *   so stats polling never walks allproc/zombproc from sysctl context.
 *
 * Why this is timer-based instead of exact real-time enforcement:
 * - exact CPU policing in scheduler hot paths is invasive and expensive
 * - this approach is intentionally conservative and low-overhead
 * - it gives predictable behavior with minimal impact on non-jailed workloads
 *
 * TODO(next): move from 1Hz coarse windows to scheduler-integrated usage
 * buckets (or shorter adaptive intervals) for smoother throttling decisions.
 */
static void
secmodel_jail_cpu_account_tick(void *arg)
{
	struct jail_entry *entry;
	struct proc *p;
	time_t now;
	uint64_t ticks;
	jailid_t id;

	(void)arg;
	now = time_second;

	mutex_enter(&jail_lock);
	LIST_FOREACH(entry, &jail_list, je_entry) {
		entry->je_cpu_total_ticks = 0;
		entry->je_proc_current = 0;
		entry->je_refcount = 0;
	}
	mutex_exit(&jail_lock);

	mutex_enter(&proc_lock);
	mutex_enter(&jail_lock);
	KASSERT(mutex_owned(&proc_lock));
	secmodel_jail_assert_jail_lock_held();
	PROCLIST_FOREACH(p, &allproc) {
		id = secmodel_jail_cred_id(p->p_cred);
		if (id == JAILID_HOST)
			continue;
		ticks = p->p_uticks + p->p_sticks + p->p_iticks;
		entry = secmodel_jail_lookup(id);
		if (entry != NULL) {
			entry->je_cpu_total_ticks += ticks;
			entry->je_proc_current++;
			entry->je_refcount++;
		}
	}
	PROCLIST_FOREACH(p, &zombproc) {
		id = secmodel_jail_cred_id(p->p_cred);
		if (id == JAILID_HOST)
			continue;
		entry = secmodel_jail_lookup(id);
		if (entry != NULL) {
			entry->je_proc_current++;
			entry->je_refcount++;
		}
	}
	mutex_exit(&jail_lock);
	mutex_exit(&proc_lock);

	mutex_enter(&jail_lock);
	LIST_FOREACH(entry, &jail_list, je_entry) {
		uint64_t delta_ticks;
		time_t period_s;

		delta_ticks = 0;
		if (entry->je_cpu_total_ticks >= entry->je_cpu_usage)
			delta_ticks = entry->je_cpu_total_ticks - entry->je_cpu_usage;
		entry->je_cpu_usage = entry->je_cpu_total_ticks;

		if (!secmodel_jail_cpu_limit_enabled(entry))
			continue;

		period_s = (time_t)((entry->je_cpu_period + 999999ULL) / 1000000ULL);
		if (period_s <= 0)
			period_s = 1;

		if (entry->je_cpu_window_start == 0 ||
		    now - entry->je_cpu_window_start >= period_s) {
			entry->je_cpu_window_start = now;
			entry->je_cpu_used_window = 0;
			entry->je_cpu_over_quota = false;
		}

		entry->je_cpu_used_window += delta_ticks;
		if (entry->je_cpu_used_window >= entry->je_cpu_quota) {
			if (!entry->je_cpu_over_quota)
				entry->je_throttle_cpu++;
			entry->je_cpu_over_quota = true;
		}
	}
	mutex_exit(&jail_lock);

	callout_schedule(&jail_cpu_account_ch, hz);
}

bool
secmodel_jail_memory_admit(kauth_cred_t cred, uint64_t current, uint64_t delta)
{
	struct jail_entry *entry;
	jailid_t id;

	id = secmodel_jail_cred_id(cred);
	if (id == JAILID_HOST)
		return true;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		return true;
	}
	entry->je_memory_current = current;
	if (!secmodel_jail_within_limit(current, delta, entry->je_memory_max)) {
		entry->je_deny_memory++;
		mutex_exit(&jail_lock);
		return false;
	}
	mutex_exit(&jail_lock);
	return true;
}

void
secmodel_jail_memory_set_current(kauth_cred_t cred, uint64_t current)
{
	struct jail_entry *entry;
	jailid_t id;

	id = secmodel_jail_cred_id(cred);
	if (id == JAILID_HOST)
		return;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry != NULL)
		entry->je_memory_current = current;
	mutex_exit(&jail_lock);
}

bool
secmodel_jail_fd_admit(kauth_cred_t cred, uint64_t current, uint64_t delta)
{
	struct jail_entry *entry;
	jailid_t id;

	id = secmodel_jail_cred_id(cred);
	if (id == JAILID_HOST)
		return true;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		return true;
	}
	entry->je_fd_current = current;
	if (!secmodel_jail_within_limit(current, delta, entry->je_fd_max)) {
		entry->je_deny_fd++;
		mutex_exit(&jail_lock);
		return false;
	}
	mutex_exit(&jail_lock);
	return true;
}

void
secmodel_jail_fd_set_current(kauth_cred_t cred, uint64_t current)
{
	struct jail_entry *entry;
	jailid_t id;

	id = secmodel_jail_cred_id(cred);
	if (id == JAILID_HOST)
		return;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry != NULL)
		entry->je_fd_current = current;
	mutex_exit(&jail_lock);
}

bool
secmodel_jail_sockbuf_charge(kauth_cred_t cred, uint64_t bytes)
{
	struct jail_entry *entry;
	jailid_t id;

	id = secmodel_jail_cred_id(cred);
	if (id == JAILID_HOST || bytes == 0)
		return true;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		return true;
	}
	if (!secmodel_jail_within_limit(entry->je_sockbuf_current, bytes,
	    entry->je_sockbuf_max)) {
		entry->je_deny_sockbuf++;
		mutex_exit(&jail_lock);
		return false;
	}
	entry->je_sockbuf_current += bytes;
	mutex_exit(&jail_lock);
	return true;
}

bool
secmodel_jail_cpu_can_run(kauth_cred_t cred)
{
	struct jail_entry *entry;
	jailid_t id;

	id = secmodel_jail_cred_id(cred);
	if (id == JAILID_HOST)
		return true;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		return true;
	}
	if (entry->je_cpu_over_quota) {
		entry->je_throttle_cpu++;
		mutex_exit(&jail_lock);
		return false;
	}
	mutex_exit(&jail_lock);
	return true;
}

int
secmodel_jail_cpu_can_run_try(kauth_cred_t cred, bool *okp)
{
	struct jail_entry *entry;
	jailid_t id;

	id = secmodel_jail_cred_id(cred);
	if (id == JAILID_HOST) {
		*okp = true;
		return 0;
	}

	/*
	 * Fast path: if no jail has CPU quota configured, skip lock traffic in
	 * the scheduler path and allow execution immediately.
	 *
	 * Why this matters: this function may be queried in hot scheduling paths.
	 * Even one extra contested mutex can affect whole-system latency.
	 */
	if (atomic_load_acquire(&jail_cpu_limits_active) == 0) {
		*okp = true;
		return 0;
	}

	if (!mutex_tryenter(&jail_lock))
		return EBUSY;

	entry = secmodel_jail_lookup(id);
	if (entry == NULL) {
		mutex_exit(&jail_lock);
		*okp = true;
		return 0;
	}
	if (entry->je_cpu_over_quota) {
		entry->je_throttle_cpu++;
		mutex_exit(&jail_lock);
		*okp = false;
		return 0;
	}
	mutex_exit(&jail_lock);
	*okp = true;
	return 0;
}

void
secmodel_jail_sockbuf_uncharge(kauth_cred_t cred, uint64_t bytes)
{
	struct jail_entry *entry;
	jailid_t id;

	id = secmodel_jail_cred_id(cred);
	if (id == JAILID_HOST || bytes == 0)
		return;

	mutex_enter(&jail_lock);
	entry = secmodel_jail_lookup(id);
	if (entry != NULL) {
		if (bytes >= entry->je_sockbuf_current)
			entry->je_sockbuf_current = 0;
		else
			entry->je_sockbuf_current -= bytes;
	}
	mutex_exit(&jail_lock);
}

/*
 * Fetch the jail id associated with a credential. The value lives in the
 * secmodel-specific kauth data slot.
 */
jailid_t
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
void
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

	/*
	 * This function is intentionally verbose in logging because it is used by
	 * userland tooling/debug flows where "why did this not match" matters.
	 */
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
 * Host credentials are those with jail id 0.
 */
bool
secmodel_jail_is_host_cred(kauth_cred_t cred)
{
	return secmodel_jail_cred_id(cred) == JAILID_HOST;
}

/*
 * Host root (euid 0, jail id 0) bypasses jail restrictions.
 */
bool
secmodel_jail_is_host_root(kauth_cred_t cred)
{
	return kauth_cred_geteuid(cred) == 0 &&
	    secmodel_jail_is_host_cred(cred);
}

/*
 * Determine whether a credential can interact with a target process.
 * Host root can always interact. Otherwise, both must be in the same jail.
 */
bool
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
struct jail_entry *
secmodel_jail_lookup(jailid_t id)
{
	struct jail_entry *entry;

	secmodel_jail_assert_jail_lock_held();

	/*
	 * Linear scan is acceptable for small jail counts and keeps code easy to
	 * audit. It is not ideal for very large fleets.
	 */
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

	secmodel_jail_assert_jail_lock_held();

	LIST_FOREACH(entry, &jail_list, je_entry) {
		if (strcmp(entry->je_name, name) == 0)
			return entry;
	}

	return NULL;
}

bool
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
int
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

	/*
	 * `jail_next_id` wrap to 0 would collide with the reserved host id.
	 * We fail hard with EOVERFLOW instead of trying to recycle ids silently.
	 */
	if (jail_next_id == 0) {
		mutex_exit(&jail_lock);
		return EOVERFLOW;
	}

	/*
	 * IDs are monotonic for predictability in logs and tooling.
	 *
	 * TODO(next): consider generation counters if id reuse is introduced later,
	 * to avoid stale userland references accidentally pointing to new jails.
	 */
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
				entry->je_memory_max = config->jc_memory_max;
		entry->je_proc_max = config->jc_proc_max;
		entry->je_fd_max = config->jc_fd_max;
		entry->je_sockbuf_max = config->jc_sockbuf_max;
		entry->je_profile = config->jc_profile;
	} else {
		entry->je_profile = JAIL_PROFILE_POLICY_HIGH;
	}
	if (secmodel_jail_cpu_limit_enabled(entry))
		atomic_inc_uint(&jail_cpu_limits_active);
	LIST_INSERT_HEAD(&jail_list, entry, je_entry);
	mutex_exit(&jail_lock);

	*idp = id;
	return 0;
}

bool
secmodel_jail_port_reserved_by_id(jailid_t id, in_port_t lport)
{
	struct jail_entry *entry;
	size_t i;

	secmodel_jail_assert_jail_lock_held();

	entry = secmodel_jail_lookup(id);
	if (entry == NULL)
		return false;

	for (i = 0; i < entry->je_nports; i++) {
		if (htons(entry->je_ports[i]) == lport)
			return true;
	}

	return false;
}

bool
secmodel_jail_port_reserved_any(in_port_t lport)
{
	struct jail_entry *entry;
	size_t i;

	secmodel_jail_assert_jail_lock_held();

	LIST_FOREACH(entry, &jail_list, je_entry) {
		for (i = 0; i < entry->je_nports; i++) {
			if (htons(entry->je_ports[i]) == lport)
				return true;
		}
	}

	return false;
}

bool
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
bool
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
bool
secmodel_jail_has_processes(jailid_t id)
{
	struct proc *p;
	bool found = false;

	/*
	 * This is an O(number-of-processes) safety check.
	 *
	 * Why it is done this way: correctness first; destroy must refuse while any
	 * member still exists (including zombies), so we scan both lists.
	 *
	 * TODO(next): maintain per-jail live membership counters with precise
	 * lifetime hooks to avoid full scans at destroy time.
	 */
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
int
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
	if (secmodel_jail_cpu_limit_enabled(entry)) {
		KASSERT(jail_cpu_limits_active != 0);
		atomic_dec_uint(&jail_cpu_limits_active);
	}
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
int
secmodel_jail_enter(struct lwp *l, jailid_t id)
{
	struct proc *p;
	kauth_cred_t cred, ncred;
	jailid_t cur;

	p = l->l_proc;
	proc_crmod_enter();
	cred = p->p_cred;
	cur = secmodel_jail_cred_id(cred);

	/*
	 * Phase 1 validate, phase 2 commit:
	 * - We first validate policy/existence.
	 * - Then we re-enter credential modification and re-validate before commit.
	 *
	 * Why duplicate checks: another thread could change credentials or destroy a
	 * jail between validation and commit. Re-check keeps this race safe.
	 */
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

	/*
	 * TODO(next): this is still a TOCTOU-style two-phase pattern. It is safe due
	 * to revalidation, but not elegant. Investigate whether proc credential
	 * framework can support a single transaction-style update helper.
	 */

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
 * Initialize secmodel jail structures and register per-credential storage.
 */
void
secmodel_jail_init(void)
{
	mutex_init(&jail_lock, MUTEX_DEFAULT, IPL_NONE);
	jail_cpu_limits_active = 0;
	callout_init(&jail_cpu_account_ch, CALLOUT_MPSAFE);
	callout_setfunc(&jail_cpu_account_ch, secmodel_jail_cpu_account_tick,
	    NULL);
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
	callout_schedule(&jail_cpu_account_ch, hz);
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
	callout_halt(&jail_cpu_account_ch, NULL);
	callout_destroy(&jail_cpu_account_ch);
	kauth_deregister_key(jail_key);

	mutex_enter(&jail_lock);
	while ((entry = LIST_FIRST(&jail_list)) != NULL) {
		LIST_REMOVE(entry, je_entry);
		if (secmodel_jail_cpu_limit_enabled(entry)) {
			KASSERT(jail_cpu_limits_active != 0);
			atomic_dec_uint(&jail_cpu_limits_active);
		}
		kmem_free(entry, sizeof(*entry));
	}
	mutex_exit(&jail_lock);
	mutex_destroy(&jail_lock);
}
