/* $NetBSD$ */

/*-
 * Copyright (c) 2026 Matthias Petermann
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

#ifndef _SYS_CELL_H_
#define _SYS_CELL_H_

#include <sys/stdbool.h>
#include <sys/types.h>

typedef uint32_t cellid_t;

#define CELL_NAME_MAX 63
#define CELL_ROOT_MAX 255

#define CELLID_HOST 0

#define CELL_CREATE_PROFILE 0x00000001
#define CELL_CREATE_PORTS 0x00000002
#define CELL_CREATE_RLIMIT_NOFILE 0x00000004
#define CELL_CREATE_RLIMIT_AS 0x00000008
#define CELL_CREATE_RLIMIT_CORE 0x00000010

#define CELL_PORTS_MAX 32

#define CELL_PROFILE_LOW 0
#define CELL_PROFILE_MEDIUM 1
#define CELL_PROFILE_HIGH 2

#define CELL_RLIMIT_INFINITY ((uint64_t)~0ULL)

/*
 * Userland-to-kernel payload for creating a credential-scoped policy domain.
 * cc_root identifies the launch root that cellctl(8) must chroot(2) into before
 * it can assign membership; it does not create a filesystem namespace.
 */
struct cell_create {
  uint32_t cc_flags;
  uint32_t cc_id;
  uint32_t cc_profile;
  uint16_t cc_nports;
  uint16_t cc_ports[CELL_PORTS_MAX];
  uint64_t cc_rlimit_nofile;
  uint64_t cc_rlimit_as;
  uint64_t cc_rlimit_core;
  char cc_name[CELL_NAME_MAX + 1];
  char cc_root[CELL_ROOT_MAX + 1];
};

/*
 * Read-only cell snapshot exported through security.models.cell.list.
 * CPU fields are windowed tick metrics: 1s delta and rolling 10s average.
 */
struct cell_info {
  cellid_t ci_id;
  uint32_t ci_create_flags;
  uint64_t ci_refcount;
  char ci_name[CELL_NAME_MAX + 1];
  char ci_root[CELL_ROOT_MAX + 1];
  /* Cell creation timestamp in monotonic nanoseconds since boot. */
  uint64_t ci_created_ns;
  uint64_t ci_proc_current;
  uint64_t ci_memory_current;
  uint64_t ci_cpu_ticks_1s;
  uint64_t ci_cpu_ticks_10s;
  uint64_t ci_rlimit_nofile;
  uint64_t ci_rlimit_as;
  uint64_t ci_rlimit_core;
};

#endif /* !_SYS_CELL_H_ */
