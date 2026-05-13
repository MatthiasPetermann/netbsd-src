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
 * Layer: cellman command routing layer.
 *
 * Handle cell subcommand routing and cell-focused read command frontends.
 *
 * Extension guidance: Add cell command routing/UX here; keep mutation/runtime
 * implementation in backend/runtime modules.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "../cellman.h"
#include "command_backend.h"
#include "command_backend_internal.h"
#include "command_backup_cli.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
 * Cell read commands are grouped here so list/show/fields and the route
 * table can be understood in one place.
 */
int
cmd_cell_list(int argc, char *argv[], const char *dsl_dir, char **err)
{
	struct cellman_state state;
	struct runtime_cell_list runtime;
	struct cell_snapshot_table table;
	struct cell_output_fields fields;
	struct cellman_read_options options;

	cellman_state_init(&state);
	memset(&runtime, 0, sizeof(runtime));
	memset(&table, 0, sizeof(table));
	memset(&fields, 0, sizeof(fields));
	cellman_read_options_init(&options);
	options.view = READ_VIEW_COMPACT;
	if (cellman_parse_list_options(argc, argv, &options,
	    "usage: cell list [--view compact|desired|runtime|merged] [-o fields] [-T] [-H]",
	    err) != 0)
		goto fail;

	if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
		goto fail;
	if (load_runtime_cells(&runtime, err) != 0)
		goto fail;
	if (load_runtime_stats(&runtime, err) != 0)
		goto fail;
	if (cell_fields_parse(options.requested_fields, options.view, &fields,
	    err) != 0)
		goto fail;
	if (build_cell_snapshot_table(&state, &runtime, &table, err) != 0)
		goto fail;

	if (print_cell_table(&table, &fields, options.tsv,
	    options.no_header) != 0)
		goto fail;

	cell_snapshot_table_free(&table);
	runtime_cell_list_free(&runtime);
	cellman_state_free(&state);
	return 0;
fail:
	cell_snapshot_table_free(&table);
	runtime_cell_list_free(&runtime);
	cellman_state_free(&state);
	return 1;
}

int
cmd_cell_show(int argc, char *argv[], const char *dsl_dir, char **err)
{
	struct cellman_state state;
	struct runtime_cell_list runtime;
	struct cell_snapshot_table table;
	struct cell_output_fields fields;
	struct cell_snapshot_table one;
	struct cellman_read_options options;
	const char *name;
	size_t i;
	size_t row_idx;

	cellman_read_options_init(&options);
	if (cellman_parse_show_options(argc, argv, &name, &options,
	    "usage: cell show <name> [--view compact|desired|runtime|merged] [-o fields] [-T] [-H]",
	    err) != 0)
		return 1;

	cellman_state_init(&state);
	memset(&runtime, 0, sizeof(runtime));
	memset(&table, 0, sizeof(table));
	memset(&fields, 0, sizeof(fields));
	memset(&one, 0, sizeof(one));

	if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
		goto fail;
	if (load_runtime_cells(&runtime, err) != 0)
		goto fail;
	if (load_runtime_stats(&runtime, err) != 0)
		goto fail;
	if (cell_fields_parse(options.requested_fields, options.view,
	    &fields, err) != 0)
		goto fail;
	if (build_cell_snapshot_table(&state, &runtime, &table, err) != 0)
		goto fail;

	row_idx = (size_t)-1;
	for (i = 0; i < table.len; i++) {
		if (strcmp(table.items[i].cols[0], name) == 0) {
			row_idx = i;
			break;
		}
	}
	if (row_idx == (size_t)-1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "unknown cell: %s", name);
		goto fail;
	}

	one.items = &table.items[row_idx];
	one.len = 1;
	one.cap = 1;
	if (print_cell_table(&one, &fields, options.tsv,
	    options.no_header) != 0)
		goto fail;

	cell_snapshot_table_free(&table);
	runtime_cell_list_free(&runtime);
	cellman_state_free(&state);
	return 0;
fail:
	cell_snapshot_table_free(&table);
	runtime_cell_list_free(&runtime);
	cellman_state_free(&state);
	return 1;
}

int
cmd_cell_fields(int argc, char *argv[], const char *dsl_dir, char **err)
{
	struct cellman_string_list fields;
	enum read_view view;
	bool tsv;
	bool no_header;

	(void)dsl_dir;

	memset(&fields, 0, sizeof(fields));
	if (cellman_parse_fields_options(argc, argv, &view, &tsv,
	    &no_header,
	    "usage: cell fields [--view compact|desired|runtime|merged] [-T] [-H]",
	    err) != 0)
		goto fail;

	cell_fields_supported(view, &fields);
	if (print_fields_output(&fields, tsv, no_header) != 0)
		goto fail;
	cellman_string_list_free(&fields);
	return 0;

fail:
	cellman_string_list_free(&fields);
	return 1;
}

int
cmd_cell_shell(int argc, char *argv[], const char *dsl_dir, char **err)
{
	const char **exec_argv;
	const char *pkg_path_env;
	char *pkg_path_conf;
	char *saved_pkg_path;
	bool pkg_path_had_previous;
	bool pkg_path_overridden;
	int i;
	int rc;

	(void)dsl_dir;

	if (argc < 1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "usage: cell shell <name> [command ...]");
		return 1;
	}

	exec_argv = calloc((size_t)argc + 3, sizeof(*exec_argv));
	if (exec_argv == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return 1;
	}

	pkg_path_conf = NULL;
	saved_pkg_path = NULL;
	pkg_path_had_previous = false;
	pkg_path_overridden = false;
	pkg_path_env = getenv("PKG_PATH");
	if (pkg_path_env == NULL || pkg_path_env[0] == '\0') {
		if (cellman_conf_get("PKG_PATH", &pkg_path_conf, err) != 0) {
			free(exec_argv);
			return 1;
		}

		if (pkg_path_conf != NULL && pkg_path_conf[0] != '\0') {
			if (pkg_path_env != NULL) {
				saved_pkg_path = cellman_strdup(pkg_path_env, err);
				if (saved_pkg_path == NULL) {
					free(pkg_path_conf);
					free(exec_argv);
					return 1;
				}
				pkg_path_had_previous = true;
			}

			if (setenv("PKG_PATH", pkg_path_conf, 1) != 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "setenv PKG_PATH failed: %s", strerror(errno));
				free(saved_pkg_path);
				free(pkg_path_conf);
				free(exec_argv);
				return 1;
			}
			pkg_path_overridden = true;
		}
	}

	exec_argv[0] = "cellctl";
	exec_argv[1] = "exec";
	exec_argv[2] = argv[0];
	if (argc == 1) {
		exec_argv[3] = NULL;
	} else {
		for (i = 1; i < argc; i++)
			exec_argv[i + 2] = argv[i];
		exec_argv[argc + 2] = NULL;
	}

	rc = run_argv(exec_argv, err) == 0 ? 0 : 1;

	if (pkg_path_overridden) {
		if (pkg_path_had_previous)
			(void)setenv("PKG_PATH", saved_pkg_path, 1);
		else
			(void)unsetenv("PKG_PATH");
	}

	free(saved_pkg_path);
	free(pkg_path_conf);
	free(exec_argv);
	return rc;
}

static int
cmd_cell_start(int argc, char *argv[], const char *dsl_dir, char **err)
{
	return cmd_cell_lifecycle("start", argc, argv, dsl_dir, err);
}

static int
cmd_cell_stop(int argc, char *argv[], const char *dsl_dir, char **err)
{
	return cmd_cell_lifecycle("stop", argc, argv, dsl_dir, err);
}

static int
cmd_cell_restart(int argc, char *argv[], const char *dsl_dir, char **err)
{
	return cmd_cell_lifecycle("restart", argc, argv, dsl_dir, err);
}

static int
cmd_cell_backup(int argc, char *argv[], const char *dsl_dir, char **err)
{
	(void)dsl_dir;
	return cellman_command_cell_backup(argc, argv, err);
}

static int
cmd_cell_plan(int argc, char *argv[], const char *dsl_dir, char **err)
{
	if (argc >= 1 && strcmp(argv[0], "run") == 0)
		return cmd_cell_plan_run(argc - 1, &argv[1], dsl_dir, err);
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "usage: cell plan run <name> [--file apply.lua] [--ephemeral]");
	return 1;
}

static int
cmd_cell_desired_mutation(int argc, char *argv[], const char *dsl_dir,
    char **err)
{
	(void)argc;
	(void)argv;
	(void)dsl_dir;
	return cellman_backend_set_desired_mutation_error("cell", err);
}

int
cellman_command_backend_cell(int argc, char *argv[], const char *dsl_dir,
    char **err)
{
	/*
	 * Declarative subcommand table keeps routing close to the command names and
	 * avoids long if/else chains.
	 */
	static const struct cellman_subcommand routes[] = {
		{ "list", cmd_cell_list },
		{ "show", cmd_cell_show },
		{ "fields", cmd_cell_fields },
		{ "shell", cmd_cell_shell },
		{ "start", cmd_cell_start },
		{ "stop", cmd_cell_stop },
		{ "restart", cmd_cell_restart },
		{ "remove", cmd_cell_remove },
		{ "backup", cmd_cell_backup },
		{ "plan", cmd_cell_plan },
		{ "create", cmd_cell_desired_mutation },
		{ "set", cmd_cell_desired_mutation },
		{ "edit", cmd_cell_desired_mutation },
	};

	return cellman_dispatch_subcommand("cell", argc, argv, dsl_dir, routes,
	    sizeof(routes) / sizeof(routes[0]), err);
}
