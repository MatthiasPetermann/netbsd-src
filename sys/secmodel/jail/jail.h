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

#ifndef _SECMODEL_JAIL_JAIL_H_
#define _SECMODEL_JAIL_JAIL_H_

#include <sys/types.h>

#include <secmodel/secmodel.h>

/*
 * secmodel_jail enforces process visibility/signal delivery and
 * jail-safe system authorization restrictions based on a jail id stored in
 * credentials. Host root (jail id 0) bypasses these checks.
 */
#define SECMODEL_JAIL_ID   "org.netbsd.secmodel.jail"
#define SECMODEL_JAIL_NAME "NetBSD Jail"

void secmodel_jail_init(void);
void secmodel_jail_start(void);
void secmodel_jail_stop(void);

int secmodel_jail_process_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);
int secmodel_jail_cred_cb(kauth_cred_t, kauth_action_t, void *,
    void *, void *, void *, void *);

bool secmodel_jail_cred_matches(kauth_cred_t, const char *);

#define SECMODEL_JAIL_EVAL_CRED_MATCHES "cred-matches"
#define SECMODEL_JAIL_EVAL_MEMORY_ADMIT "memory-admit"
#define SECMODEL_JAIL_EVAL_MEMORY_SET_CURRENT "memory-set-current"
#define SECMODEL_JAIL_EVAL_FD_ADMIT "fd-admit"
#define SECMODEL_JAIL_EVAL_FD_SET_CURRENT "fd-set-current"
#define SECMODEL_JAIL_EVAL_SOCKBUF_CHARGE "sockbuf-charge"
#define SECMODEL_JAIL_EVAL_SOCKBUF_UNCHARGE "sockbuf-uncharge"
#define SECMODEL_JAIL_EVAL_CPU_CAN_RUN "cpu-can-run"

struct secmodel_jail_eval_cred_matches_args {
	kauth_cred_t cred;
	const char *name;
};

struct secmodel_jail_eval_admit_args {
	kauth_cred_t cred;
	uint64_t current;
	uint64_t delta;
};

struct secmodel_jail_eval_set_current_args {
	kauth_cred_t cred;
	uint64_t current;
};

struct secmodel_jail_eval_sockbuf_charge_args {
	kauth_cred_t cred;
	uint64_t bytes;
};

struct secmodel_jail_eval_cpu_can_run_args {
	kauth_cred_t cred;
};

#endif /* !_SECMODEL_JAIL_JAIL_H_ */
