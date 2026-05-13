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

#ifndef _SECMODEL_CELL_CELL_H_
#define _SECMODEL_CELL_CELL_H_

#include <sys/kauth.h>
#include <sys/types.h>

#include <secmodel/secmodel.h>

/*
 * Public module identity + lifecycle API for secmodel_cell.
 *
 * Runtime model summary:
 * - Every credential carries one cell id (CELLID_HOST == 0 for host context).
 * - kauth(9) listeners use that id to enforce process/system/network policy.
 * - Host root (euid 0 in host cell) is intentionally exempt to preserve
 *   administrative control and recovery paths.
 *
 * This header stays intentionally small and stable because userland tooling
 * (for example cellctl via sysctl tree naming) depends on a predictable module
 * identity and startup contract.
 */
#define SECMODEL_CELL_ID "org.netbsd.secmodel.cell"
#define SECMODEL_CELL_NAME "Modern NetBSD: Cells"

/* Initialize in-kernel state (locks, callouts, kauth key registration). */
int secmodel_cell_init(void);
/* Start listeners/callouts after successful module registration. */
int secmodel_cell_start(void);
/* Stop listeners and release all cell runtime resources. */
void secmodel_cell_stop(void);

#endif /* !_SECMODEL_CELL_CELL_H_ */
