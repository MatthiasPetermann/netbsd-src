/* $NetBSD$ */

#ifndef _SECMODEL_CELL_INT_H_
#define _SECMODEL_CELL_INT_H_

#include <sys/cell.h>
#include <sys/kauth.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <secmodel/cell/cell.h>
#include <secmodel/secmodel.h>

enum cell_policy_profile {
  CELL_PROFILE_POLICY_LOW = CELL_PROFILE_LOW,
  CELL_PROFILE_POLICY_MEDIUM = CELL_PROFILE_MEDIUM,
  CELL_PROFILE_POLICY_HIGH = CELL_PROFILE_HIGH,
};

struct cell_entry {
  /* Stable cell identifier (0 is reserved for host, entries start at 1). */
  cellid_t ce_id;
  /* Administrative display name. */
  char ce_name[CELL_NAME_MAX + 1];
  /* Configured root path metadata for userland tooling and reporting. */
  char ce_root[CELL_ROOT_MAX + 1];
  /* Creation timestamp in monotonic nanoseconds since boot. */
  uint64_t ce_created_ns;
  /* System policy profile controlling kauth deny/defer behavior. */
  enum cell_policy_profile ce_profile;
  /* Sampled process count from allproc (excludes zombies). */
  uint64_t ce_proc_current;
  /* Sampled references (allproc + zombproc membership snapshot). */
  uint64_t ce_refcount;
  /* Sampled virtual-memory usage across member processes. */
  uint64_t ce_memory_current;
  /* CPU ticks consumed over the last 1s snapshot window. */
  uint64_t ce_cpu_ticks_1s;
  /* Rolling 10s average of per-second CPU ticks. */
  uint64_t ce_cpu_ticks_10s;
  /* Previous sampled cumulative CPU ticks used to derive window deltas. */
  uint64_t ce_cpu_ticks_prev_total;
  /* Ring buffer of recent 1s CPU tick deltas. */
  uint64_t ce_cpu_ticks_ring[10];
  /* Running sum for ce_cpu_ticks_ring. */
  uint64_t ce_cpu_ticks_ring_sum;
  /* Current write position in ce_cpu_ticks_ring. */
  uint8_t ce_cpu_ticks_ring_idx;
  /* Number of valid samples currently in ce_cpu_ticks_ring. */
  uint8_t ce_cpu_ticks_ring_count;
  /* Number of reserved listening ports owned by this cell. */
  uint16_t ce_nports;
  /* Reserved listening ports (host byte order as configured by userland). */
  uint16_t ce_ports[CELL_PORTS_MAX];
  /* Create-time flags copied from struct cell_create. */
  uint32_t ce_create_flags;
  /* Optional supervised process limits (CELL_RLIMIT_INFINITY = unlimited). */
  uint64_t ce_rlimit_nofile;
  uint64_t ce_rlimit_as;
  uint64_t ce_rlimit_core;
  /* Link in global cell_list. */
  LIST_ENTRY(cell_entry) ce_entry;
};

/*
 * Internal normalized configuration used during create and policy lookup.
 */
struct cell_config {
  /* Cell policy profile. */
  enum cell_policy_profile cc_profile;
};

LIST_HEAD(cell_list_head, cell_entry);

extern struct cell_list_head cell_list;
extern kmutex_t cell_lock;
extern secmodel_t cell_sm;
extern kauth_key_t cell_key;

void secmodel_cell_assert_cell_lock_held(void);

cellid_t secmodel_cell_cred_id(kauth_cred_t);
void secmodel_cell_cred_setid(kauth_cred_t, cellid_t);
bool secmodel_cell_is_host_cred(kauth_cred_t);
bool secmodel_cell_is_host_root(kauth_cred_t);
bool secmodel_cell_match(kauth_cred_t, struct proc *);

struct cell_entry *secmodel_cell_lookup(cellid_t);
bool secmodel_cell_get_config(cellid_t, struct cell_config *);
bool secmodel_cell_port_reserved_by_id(cellid_t, in_port_t);
bool secmodel_cell_port_reserved_any(in_port_t);
bool secmodel_cell_addr_port(const struct sockaddr *, in_port_t *);
bool secmodel_cell_has_entries(void);
bool secmodel_cell_has_processes(cellid_t);

int secmodel_cell_create(const struct cell_create *, const struct cell_config *,
                         cellid_t *);
int secmodel_cell_destroy(cellid_t);
int secmodel_cell_enter(struct lwp *, cellid_t);

int secmodel_cell_system_cb(kauth_cred_t, kauth_action_t, void *, void *,
                            void *, void *, void *);
int secmodel_cell_network_cb(kauth_cred_t, kauth_action_t, void *, void *,
                             void *, void *, void *);
int secmodel_cell_process_cb(kauth_cred_t, kauth_action_t, void *, void *,
                             void *, void *, void *);
int secmodel_cell_cred_cb(kauth_cred_t, kauth_action_t, void *, void *, void *,
                          void *, void *);

int secmodel_cell_init(void);

#endif /* !_SECMODEL_CELL_INT_H_ */
