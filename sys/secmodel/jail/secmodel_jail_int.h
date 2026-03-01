/* $NetBSD$ */

#ifndef _SECMODEL_JAIL_INT_H_
#define _SECMODEL_JAIL_INT_H_

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/kauth.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/jail.h>

#include <secmodel/secmodel.h>
#include <secmodel/jail/jail.h>

enum jail_policy_profile {
	JAIL_PROFILE_POLICY_LOW = JAIL_PROFILE_LOW,
	JAIL_PROFILE_POLICY_MEDIUM = JAIL_PROFILE_MEDIUM,
	JAIL_PROFILE_POLICY_HIGH = JAIL_PROFILE_HIGH,
};

struct jail_entry {
	jailid_t je_id;
	char je_name[JAIL_NAME_MAX + 1];
	char je_root[JAIL_ROOT_MAX + 1];
	uint64_t je_cpu_quota;
	uint64_t je_cpu_period;
	uint64_t je_memory_max;
	uint64_t je_proc_max;
	uint64_t je_fd_max;
	uint64_t je_sockbuf_max;
	enum jail_policy_profile je_profile;
	uint64_t je_proc_current;
	uint64_t je_refcount;
	uint64_t je_fd_current;
	uint64_t je_sockbuf_current;
	uint64_t je_memory_current;
	uint64_t je_cpu_usage;
	uint64_t je_cpu_used_window;
	uint64_t je_cpu_total_ticks;
	time_t je_cpu_window_start;
	bool je_cpu_over_quota;
	uint64_t je_deny_proc;
	uint64_t je_deny_fd;
	uint64_t je_deny_sockbuf;
	uint64_t je_deny_memory;
	uint64_t je_throttle_cpu;
	uint16_t je_nports;
	uint16_t je_ports[JAIL_PORTS_MAX];
	LIST_ENTRY(jail_entry) je_entry;
};

struct jail_config {
	uint64_t jc_cpu_quota;
	uint64_t jc_cpu_period;
	uint64_t jc_memory_max;
	uint64_t jc_proc_max;
	uint64_t jc_fd_max;
	uint64_t jc_sockbuf_max;
	enum jail_policy_profile jc_profile;
};

extern LIST_HEAD(, jail_entry) jail_list;
extern kmutex_t jail_lock;
extern secmodel_t jail_sm;
extern kauth_key_t jail_key;
extern unsigned int jail_cpu_limits_active;

void secmodel_jail_assert_jail_lock_held(void);
bool secmodel_jail_cpu_limit_enabled(const struct jail_entry *);

jailid_t secmodel_jail_cred_id(kauth_cred_t);
void secmodel_jail_cred_setid(kauth_cred_t, jailid_t);
bool secmodel_jail_is_host_cred(kauth_cred_t);
bool secmodel_jail_is_host_root(kauth_cred_t);
bool secmodel_jail_match(kauth_cred_t, struct proc *);

struct jail_entry *secmodel_jail_lookup(jailid_t);
bool secmodel_jail_get_config(jailid_t, struct jail_config *);
bool secmodel_jail_port_reserved_by_id(jailid_t, in_port_t);
bool secmodel_jail_port_reserved_any(in_port_t);
bool secmodel_jail_addr_port(const struct sockaddr *, in_port_t *);
bool secmodel_jail_has_entries(void);
bool secmodel_jail_has_processes(jailid_t);

int secmodel_jail_create(const struct jail_create *,
    const struct jail_config *, jailid_t *);
int secmodel_jail_destroy(jailid_t);
int secmodel_jail_enter(struct lwp *, jailid_t);

bool secmodel_jail_memory_admit(kauth_cred_t, uint64_t, uint64_t);
void secmodel_jail_memory_set_current(kauth_cred_t, uint64_t);
bool secmodel_jail_fd_admit(kauth_cred_t, uint64_t, uint64_t);
void secmodel_jail_fd_set_current(kauth_cred_t, uint64_t);
bool secmodel_jail_sockbuf_charge(kauth_cred_t, uint64_t);
void secmodel_jail_sockbuf_uncharge(kauth_cred_t, uint64_t);
bool secmodel_jail_cpu_can_run(kauth_cred_t);
int secmodel_jail_cpu_can_run_try(kauth_cred_t, bool *);

int secmodel_jail_system_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);
int secmodel_jail_network_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);

int secmodel_jail_eval(const char *, void *, void *);
int secmodel_jail_setinfo_adapter(void *);

#endif /* !_SECMODEL_JAIL_INT_H_ */
