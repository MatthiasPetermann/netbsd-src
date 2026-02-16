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

#ifndef _SYS_JAIL_H_
#define _SYS_JAIL_H_

#include <sys/types.h>
#include <sys/stdbool.h>

typedef uint32_t jailid_t;

#define JAIL_NAME_MAX 63
#define JAIL_ROOT_MAX 255

#define JAILID_HOST 0

#define JAIL_CREATE_MEMLIMIT	0x00000001
#define JAIL_CREATE_CPULIMIT	0x00000002
struct jail_create {
	uint32_t jc_flags;
	uint32_t jc_id;
	uint64_t jc_mem_limit;
	uint64_t jc_cpu_limit;
	char jc_name[JAIL_NAME_MAX + 1];
	char jc_root[JAIL_ROOT_MAX + 1];
};

struct jail_info {
	jailid_t ji_id;
	uint32_t ji_refcount;
	char ji_name[JAIL_NAME_MAX + 1];
	char ji_root[JAIL_ROOT_MAX + 1];
};

#endif /* !_SYS_JAIL_H_ */
