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
 * Layer: cellman command backend private contract layer.
 *
 * Define shared backend-private structs and helper prototypes reused across
 * command backend split files.
 *
 * Extension guidance: Add private cross-file backend contracts here; avoid
 * leaking these interfaces into public headers.
 */

#ifndef CELLMAN_COMMAND_BACKEND_INTERNAL_H
#define CELLMAN_COMMAND_BACKEND_INTERNAL_H

#include "../cellman.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * Shared read view selector for list/show/fields command families.
 */
enum read_view {
	READ_VIEW_MERGED = 0,
	READ_VIEW_DESIRED,
	READ_VIEW_RUNTIME,
	READ_VIEW_COMPACT,
};

/*
 * Runtime cell snapshot as returned by cellctl list/stats.
 */
struct runtime_cell {
	char *cid;
	char *name;
	char *refs;
	char *procs;
	char *cpu1s;
	char *cpu10s;
	char *memory;
	char *age;
	char *root;
};

struct runtime_cell_list {
	struct runtime_cell *items;
	size_t len;
	size_t cap;
};

/*
 * User-selected output field configuration for cell and volume snapshots.
 */
struct cell_output_fields {
	const char *names[25];
	int indexes[25];
	size_t len;
};

struct volume_output_fields {
	const char *names[8];
	int indexes[8];
	size_t len;
};

struct cell_snapshot_row {
	char *cols[25];
};

struct cell_snapshot_table {
	struct cell_snapshot_row *items;
	size_t len;
	size_t cap;
};

struct volume_snapshot_row {
	char *cols[8];
};

struct volume_snapshot_table {
	struct volume_snapshot_row *items;
	size_t len;
	size_t cap;
};

typedef int (*cellman_subcommand_handler)(int, char *[], const char *,
    char **);

struct cellman_subcommand {
	const char *name;
	cellman_subcommand_handler handler;
};

struct cellman_read_options {
	enum read_view view;
	const char *requested_fields;
	bool tsv;
	bool no_header;
};

int	cellman_dispatch_subcommand(const char *, int, char *[], const char *,
	    const struct cellman_subcommand *, size_t, char **);
void	cellman_read_options_init(struct cellman_read_options *);
int	cellman_parse_list_options(int, char *[], struct cellman_read_options *,
	    const char *, char **);
int	cellman_parse_show_options(int, char *[], const char **,
	    struct cellman_read_options *, const char *, char **);
int	cellman_parse_fields_options(int, char *[], enum read_view *, bool *,
	    bool *, const char *, char **);

int	cellman_backend_set_desired_mutation_error(const char *, char **);

int	run_argv(const char *const [], char **);
int	load_runtime_cells(struct runtime_cell_list *, char **);
int	load_runtime_stats(struct runtime_cell_list *, char **);
void	runtime_cell_list_free(struct runtime_cell_list *);
bool	runtime_cell_is_running(const struct runtime_cell_list *, const char *);
struct runtime_cell *runtime_cell_find(struct runtime_cell_list *, const char *);
int	parse_read_view(const char *, enum read_view *, char **);

int	cell_fields_parse(const char *, enum read_view,
	    struct cell_output_fields *, char **);
int	volume_fields_parse(const char *, enum read_view,
	    struct volume_output_fields *, char **);
void	cell_fields_supported(enum read_view, struct cellman_string_list *);
void	volume_fields_supported(enum read_view,
	    struct cellman_string_list *);
int	build_cell_snapshot_table(const struct cellman_state *,
	    struct runtime_cell_list *, struct cell_snapshot_table *, char **);
int	build_volume_snapshot_table(const struct cellman_state *,
	    struct volume_snapshot_table *, char **);
int	print_cell_table(const struct cell_snapshot_table *,
	    const struct cell_output_fields *, bool, bool);
int	print_volume_table(const struct volume_snapshot_table *,
	    const struct volume_output_fields *, bool, bool);
int	print_fields_output(const struct cellman_string_list *, bool, bool);
void	cell_snapshot_table_free(struct cell_snapshot_table *);
void	volume_snapshot_table_free(struct volume_snapshot_table *);

int	cmd_cell_list(int, char *[], const char *, char **);
int	cmd_cell_show(int, char *[], const char *, char **);
int	cmd_cell_fields(int, char *[], const char *, char **);
int	cmd_cell_lifecycle(const char *, int, char *[], const char *, char **);
int	cmd_cell_shell(int, char *[], const char *, char **);
int	cmd_cell_plan_run(int, char *[], const char *, char **);
int	cmd_cell_remove(int, char *[], const char *, char **);

int	cmd_volume_list(int, char *[], const char *, char **);
int	cmd_volume_show(int, char *[], const char *, char **);
int	cmd_volume_fields(int, char *[], const char *, char **);
int	cmd_volume_create(int, char *[], const char *, char **);
int	cmd_volume_remove(int, char *[], const char *, char **);

int	cmd_system_bootstrap(int, char *[], const char *, char **);
int	cmd_system_reset(int, char *[], const char *, char **);

int	mkdir_p_local(const char *, mode_t, char **);
void	remove_tree(const char *);
bool	path_is_same_or_child(const char *, const char *);
int	ensure_rc_conf_cellman(char **);
int	ensure_modules_conf_secmodel(char **);
int	ensure_secmodel_cell_loaded(char **);
int	fetch_release_sets(const char *, const char *, bool,
	    char **, char **, char **, char **, char **);
int	ensure_base_writable_links(const char *, char **);
int	build_base_layer(const char *, const char *, const char *, bool,
	    char **);
int	write_default_cellman_conf(const char *, const char *, char **);

#endif /* CELLMAN_COMMAND_BACKEND_INTERNAL_H */
