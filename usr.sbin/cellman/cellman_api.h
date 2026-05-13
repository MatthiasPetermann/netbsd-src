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

/*
 * Layer: cellman public API contract layer.
 *
 * Define the stable userland API surface exposed to CLI/TUI integration points.
 *
 * Extension guidance: Add externally consumed API contracts here; keep backend
 * internals in command/api private headers.
 */

#ifndef CELLMAN_API_H
#define CELLMAN_API_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Public command-interface API used by the CLI and external frontends.
 * This header defines the intended frontend boundary for libcellman
 * consumers (for example cellman and cellui).
 *
 * The argv slices accepted by these functions mirror CLI syntax after
 * removing the program name and, for per-command entrypoints, after removing
 * the top-level command token.
 */

struct cellman_api_options {
	const char *dsl_dir;
};

struct cellman_api_result {
	int exit_code;
	char *error;
};

enum cellman_api_storage_kind {
	CELLMAN_API_STORAGE_VOLUME = 0,
	CELLMAN_API_STORAGE_OVERLAY,
};

struct cellman_api_cell_row {
	char *name;
	char *state;
	char *cid;
	bool running;
	bool manifest_present;
	char *refs;
	char *procs;
	char *root;
	char *autostart;
	char *profile;
	char *reserved_ports;
	char *rlimit_nofile;
	char *rlimit_as;
	char *rlimit_core;
	char *supervise_cmd;
	char *cpu1s;
	char *cpu10s;
	char *memory;
	char *age;
};

struct cellman_api_cell_list {
	struct cellman_api_cell_row *items;
	size_t len;
};

struct cellman_api_storage_row {
	enum cellman_api_storage_kind kind;
	char *name;
	char *state;
	bool manifest_present;
	bool runtime_present;
	bool mounted;
	char *refs;
	char *mode;
	char *path;
	char *used_by;
};

struct cellman_api_storage_list {
	struct cellman_api_storage_row *items;
	size_t len;
};

struct cellman_api_backup_row {
	char *name;
	char *timestamp;
	char *size;
	char *archive;
};

struct cellman_api_backup_list {
	struct cellman_api_backup_row *items;
	size_t len;
};

void	cellman_api_result_init(struct cellman_api_result *);
void	cellman_api_result_reset(struct cellman_api_result *);

const char *cellman_api_default_dsl_dir(void);

int	cellman_api_dispatch(int, char *[], const struct cellman_api_options *,
	    struct cellman_api_result *);

int	cellman_api_apply(int, char *[], const struct cellman_api_options *,
	    struct cellman_api_result *);
int	cellman_api_cell(int, char *[], const struct cellman_api_options *,
	    struct cellman_api_result *);
int	cellman_api_volume(int, char *[], const struct cellman_api_options *,
	    struct cellman_api_result *);
int	cellman_api_system(int, char *[], const struct cellman_api_options *,
	    struct cellman_api_result *);

int	cellman_api_apply_all(const struct cellman_api_options *,
	    struct cellman_api_result *);
int	cellman_api_cell_start(const struct cellman_api_options *, const char *,
	    bool, struct cellman_api_result *);
int	cellman_api_cell_stop(const struct cellman_api_options *, const char *,
	    bool, struct cellman_api_result *);
int	cellman_api_cell_restart(const struct cellman_api_options *, const char *,
	    bool, struct cellman_api_result *);
int	cellman_api_cell_shell(const struct cellman_api_options *, const char *,
	    struct cellman_api_result *);

int	cellman_api_backup_create(enum cellman_api_storage_kind, const char *,
	    const struct cellman_api_options *, struct cellman_api_result *);
int	cellman_api_backup_restore(enum cellman_api_storage_kind, const char *,
	    const char *, bool, bool, const struct cellman_api_options *,
	    struct cellman_api_result *);
int	cellman_api_backup_delete(enum cellman_api_storage_kind, const char *,
	    const char *, bool, bool, const struct cellman_api_options *,
	    struct cellman_api_result *);

int	cellman_api_read_cells_merged(const struct cellman_api_options *,
	    struct cellman_api_cell_list *, char **);
void	cellman_api_cell_list_free(struct cellman_api_cell_list *);

int	cellman_api_read_storage_merged(const struct cellman_api_options *,
	    struct cellman_api_storage_list *, char **);
void	cellman_api_storage_list_free(struct cellman_api_storage_list *);

int	cellman_api_read_backups(enum cellman_api_storage_kind, const char *,
	    struct cellman_api_backup_list *, char **);
void	cellman_api_backup_list_free(struct cellman_api_backup_list *);

#endif /* CELLMAN_API_H */
