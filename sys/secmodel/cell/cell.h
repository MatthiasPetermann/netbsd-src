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
 * secmodel_cell, cellctl, and cellmgr designed and implemented by
 * Matthias Petermann, inspired by FreeBSD cells.
 */

#ifndef _SECMODEL_CELL_CELL_H_
#define _SECMODEL_CELL_CELL_H_

#include <sys/types.h>
#include <sys/kauth.h>

#include <secmodel/secmodel.h>

/*
 * secmodel_cell enforces process visibility/signal delivery and
 * cell-safe system authorization restrictions based on a cell id stored in
 * credentials. Host root (cell id 0) bypasses these checks.
 */
#define SECMODEL_CELL_ID	"org.netbsd.secmodel.cell"
#define SECMODEL_CELL_NAME "NetBSD Cell"

int secmodel_cell_init(void);
void secmodel_cell_start(void);
void secmodel_cell_stop(void);

#endif /* !_SECMODEL_CELL_CELL_H_ */
