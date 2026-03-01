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
	/* Stable jail identifier (0 is reserved for host, entries start at 1). */
	jailid_t je_id;
	/* Administrative display name. */
	char je_name[JAIL_NAME_MAX + 1];
	/* Configured root path metadata for userland tooling and reporting. */
	char je_root[JAIL_ROOT_MAX + 1];
	/* CPU quota in scheduler ticks per configured period. */
	uint64_t je_cpu_quota;
	/* CPU accounting period in microseconds. */
	uint64_t je_cpu_period;
	/* Upper bound for memory usage accounting (0 means unlimited). */
	uint64_t je_memory_max;
	/* Upper bound for process count (0 means unlimited). */
	uint64_t je_proc_max;
	/* Upper bound for file descriptor usage (0 means unlimited). */
	uint64_t je_fd_max;
	/* Upper bound for socket-buffer usage (0 means unlimited). */
	uint64_t je_sockbuf_max;
	/* System policy profile controlling kauth deny/defer behavior. */
	enum jail_policy_profile je_profile;
	/* Sampled process count used for list exports and admission checks. */
	uint64_t je_proc_current;
	/* Sampled references (allproc + zombproc membership snapshot). */
	uint64_t je_refcount;
	/* Last observed file descriptor usage. */
	uint64_t je_fd_current;
	/* Current charged socket-buffer bytes. */
	uint64_t je_sockbuf_current;
	/* Last observed memory usage. */
	uint64_t je_memory_current;
	/* Last sampled cumulative CPU ticks across member processes. */
	uint64_t je_cpu_usage;
	/* CPU ticks consumed in the current quota window. */
	uint64_t je_cpu_used_window;
	/* Total sampled CPU ticks from process counters in latest pass. */
	uint64_t je_cpu_total_ticks;
	/* Start timestamp for current quota window. */
	time_t je_cpu_window_start;
	/* Set when quota is exceeded during current period window. */
	bool je_cpu_over_quota;
	/* Count of denied fork admissions due to process limit. */
	uint64_t je_deny_proc;
	/* Count of denied file descriptor admissions. */
	uint64_t je_deny_fd;
	/* Count of denied socket-buffer charges. */
	uint64_t je_deny_sockbuf;
	/* Count of denied memory admissions. */
	uint64_t je_deny_memory;
	/* Count of CPU throttle deny events. */
	uint64_t je_throttle_cpu;
	/* Number of reserved listening ports owned by this jail. */
	uint16_t je_nports;
	/* Reserved listening ports (host byte order as configured by userland). */
	uint16_t je_ports[JAIL_PORTS_MAX];
	/* Link in global jail_list. */
	LIST_ENTRY(jail_entry) je_entry;
};

/*
 * Internal normalized configuration used during create and policy lookup.
 */
struct jail_config {
	/* CPU quota in scheduler ticks per period. */
	uint64_t jc_cpu_quota;
	/* CPU quota period in microseconds. */
	uint64_t jc_cpu_period;
	/* Memory limit (0 means unlimited). */
	uint64_t jc_memory_max;
	/* Process-count limit (0 means unlimited). */
	uint64_t jc_proc_max;
	/* File descriptor limit (0 means unlimited). */
	uint64_t jc_fd_max;
	/* Socket-buffer limit (0 means unlimited). */
	uint64_t jc_sockbuf_max;
	/* Jail policy profile. */
	enum jail_policy_profile jc_profile;
};

LIST_HEAD(jail_list_head, jail_entry);

extern struct jail_list_head jail_list;
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

int secmodel_jail_system_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);
int secmodel_jail_network_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);

int secmodel_jail_eval(const char *, void *, void *);
int secmodel_jail_setinfo_adapter(void *);
int secmodel_jail_init(void);

#endif /* !_SECMODEL_JAIL_INT_H_ */
