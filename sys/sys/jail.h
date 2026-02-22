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

#ifndef _SYS_JAIL_H_
#define _SYS_JAIL_H_

#include <sys/types.h>
#include <sys/stdbool.h>

typedef uint32_t jailid_t;

#define JAIL_NAME_MAX 63
#define JAIL_ROOT_MAX 255

#define JAILID_HOST 0

#define JAIL_CREATE_CPU_QUOTA	0x00000001
#define JAIL_CREATE_CPU_PERIOD	0x00000002
#define JAIL_CREATE_CPU_WEIGHT	0x00000004
#define JAIL_CREATE_MEMORY_MAX	0x00000008
#define JAIL_CREATE_PROC_MAX	0x00000010
#define JAIL_CREATE_FD_MAX	0x00000020
#define JAIL_CREATE_SOCKBUF_MAX	0x00000040
#define JAIL_CREATE_PROFILE	0x00000080
#define JAIL_CREATE_PORTS	0x00000100

#define JAIL_PORTS_MAX	32

#define JAIL_PROFILE_LOW	0
#define JAIL_PROFILE_MEDIUM	1
#define JAIL_PROFILE_HIGH	2

struct jail_create {
	uint32_t jc_flags;
	uint32_t jc_id;
	uint32_t jc_profile;
	uint64_t jc_cpu_quota;
	uint64_t jc_cpu_period;
	uint64_t jc_cpu_weight;
	uint64_t jc_memory_max;
	uint64_t jc_proc_max;
	uint64_t jc_fd_max;
	uint64_t jc_sockbuf_max;
	uint16_t jc_nports;
	uint16_t jc_ports[JAIL_PORTS_MAX];
	char jc_name[JAIL_NAME_MAX + 1];
	char jc_root[JAIL_ROOT_MAX + 1];
};

struct jail_info {
	jailid_t ji_id;
	uint32_t ji_refcount;
	char ji_name[JAIL_NAME_MAX + 1];
	char ji_root[JAIL_ROOT_MAX + 1];
	uint64_t ji_cpu_quota;
	uint64_t ji_cpu_period;
	uint64_t ji_cpu_weight;
	uint64_t ji_memory_max;
	uint64_t ji_proc_max;
	uint64_t ji_fd_max;
	uint64_t ji_sockbuf_max;
	uint64_t ji_proc_current;
	uint64_t ji_fd_current;
	uint64_t ji_sockbuf_current;
	uint64_t ji_memory_current;
	uint64_t ji_cpu_usage;
	uint64_t ji_deny_proc;
	uint64_t ji_deny_fd;
	uint64_t ji_deny_sockbuf;
	uint64_t ji_deny_memory;
	uint64_t ji_throttle_cpu;
};

#endif /* !_SYS_JAIL_H_ */
