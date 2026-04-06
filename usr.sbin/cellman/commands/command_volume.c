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
 * Handle volume subcommand routing and volume read command frontends.
 *
 * Extension guidance: Add volume command routing/UX here; keep runtime
 * mutation details in backend/runtime modules.
 */

#include "../cellman.h"
#include "command_backend.h"
#include "command_backend_internal.h"
#include "command_backup_cli.h"

#include <string.h>

/*
 * Volume command implementations live in this module next to routing, so the
 * full flow for `volume ...` can be traced without jumping across files.
 */
int
cmd_volume_list(int argc, char *argv[], const char *dsl_dir, char **err)
{
	struct cellman_state state;
	struct volume_snapshot_table table;
	struct volume_output_fields fields;
	struct cellman_read_options options;

	cellman_state_init(&state);
	memset(&table, 0, sizeof(table));
	memset(&fields, 0, sizeof(fields));
	cellman_read_options_init(&options);
	if (cellman_parse_list_options(argc, argv, &options,
	    "usage: volume list [--view desired|runtime|merged] [-o fields] [-T] [-H]",
	    err) != 0)
		goto fail;

	if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
		goto fail;
	if (volume_fields_parse(options.requested_fields, options.view, &fields,
	    err) != 0)
		goto fail;
	if (build_volume_snapshot_table(&state, &table, err) != 0)
		goto fail;

	if (print_volume_table(&table, &fields, options.tsv,
	    options.no_header) != 0)
		goto fail;

	volume_snapshot_table_free(&table);
	cellman_state_free(&state);
	return 0;
fail:
	volume_snapshot_table_free(&table);
	cellman_state_free(&state);
	return 1;
}

int
cmd_volume_show(int argc, char *argv[], const char *dsl_dir, char **err)
{
	struct cellman_state state;
	struct volume_snapshot_table table;
	struct volume_output_fields fields;
	struct volume_snapshot_table one;
	struct cellman_read_options options;
	const char *name;
	size_t i;
	size_t row_idx;

	cellman_read_options_init(&options);
	if (cellman_parse_show_options(argc, argv, &name, &options,
	    "usage: volume show <name> [--view desired|runtime|merged] [-o fields] [-T] [-H]",
	    err) != 0)
		return 1;

	cellman_state_init(&state);
	memset(&table, 0, sizeof(table));
	memset(&fields, 0, sizeof(fields));
	memset(&one, 0, sizeof(one));

	if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
		goto fail;
	if (volume_fields_parse(options.requested_fields, options.view,
	    &fields, err) != 0)
		goto fail;
	if (build_volume_snapshot_table(&state, &table, err) != 0)
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
			*err = cellman_xasprintf(NULL, "unknown volume: %s", name);
		goto fail;
	}

	one.items = &table.items[row_idx];
	one.len = 1;
	one.cap = 1;
	if (print_volume_table(&one, &fields, options.tsv,
	    options.no_header) != 0)
		goto fail;

	volume_snapshot_table_free(&table);
	cellman_state_free(&state);
	return 0;
fail:
	volume_snapshot_table_free(&table);
	cellman_state_free(&state);
	return 1;
}

int
cmd_volume_fields(int argc, char *argv[], const char *dsl_dir, char **err)
{
	struct cellman_string_list fields;
	enum read_view view;
	bool tsv;
	bool no_header;

	(void)dsl_dir;

	memset(&fields, 0, sizeof(fields));
	if (cellman_parse_fields_options(argc, argv, &view, &tsv,
	    &no_header,
	    "usage: volume fields [--view desired|runtime|merged] [-T] [-H]",
	    err) != 0)
		goto fail;
	if (view == READ_VIEW_COMPACT) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "volume: view 'compact' is not supported");
		goto fail;
	}

	volume_fields_supported(view, &fields);
	if (print_fields_output(&fields, tsv, no_header) != 0)
		goto fail;

	cellman_string_list_free(&fields);
	return 0;
fail:
	cellman_string_list_free(&fields);
	return 1;
}

int
cmd_volume_create(int argc, char *argv[], const char *dsl_dir, char **err)
{
	const char *name;
	const char *mode;
	int i;

	(void)dsl_dir;

	name = NULL;
	mode = NULL;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mode") == 0) {
			if (i + 1 >= argc)
				goto badopt;
			mode = argv[++i];
			continue;
		}
		if (argv[i][0] == '-')
			goto badopt;
		if (name != NULL)
			goto badopt;
		name = argv[i];
	}

	if (name == NULL)
		goto badopt;

	if (cellman_volume_ensure(name, mode, true, false, true, err) != 0)
		return 1;

	(void)cellman_payload_printf("ok volume create name=%s\n", name);
	return 0;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "usage: volume create <name> [-m mode]");
	return 1;
}

int
cmd_volume_remove(int argc, char *argv[], const char *dsl_dir, char **err)
{
	struct cellman_state state;
	const char *target;
	bool yes;
	bool need_state;
	int i;
	size_t removed;
	int rc;

	target = NULL;
	yes = false;
	need_state = false;
	removed = 0;
	rc = 1;
	cellman_state_init(&state);

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--yes") == 0) {
			yes = true;
			continue;
		}
		if (argv[i][0] == '-') {
			if (target == NULL && (strcmp(argv[i], "--all") == 0 ||
			    strcmp(argv[i], "--orphans") == 0)) {
				target = argv[i];
				continue;
			}
			goto badopt;
		}
		if (target != NULL)
			goto badopt;
		target = argv[i];
	}

	if (target == NULL)
		goto badopt;

	if (strcmp(target, "--all") == 0 || strcmp(target, "--orphans") == 0) {
		if (!yes) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "volume remove %s requires --yes in runtime mode", target);
			goto done;
		}
	}

	if (strcmp(target, "--all") == 0) {
		if (cellman_volume_remove_all(NULL, false, false, true,
		    &removed, err) != 0)
			goto done;
		(void)cellman_payload_printf("ok volume remove all removed=%zu\n",
		    removed);
		rc = 0;
		goto done;
	}

	if (strcmp(target, "--orphans") == 0) {
		need_state = true;
		if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
			goto done;
		if (cellman_volume_remove_all(&state, true, false, true,
		    &removed, err) != 0)
			goto done;
		(void)cellman_payload_printf(
		    "ok volume remove orphans removed=%zu\n", removed);
		rc = 0;
		goto done;
	}

	if (cellman_volume_remove_one(target, false, true, true, err) != 0)
		goto done;
	(void)cellman_payload_printf("ok volume remove name=%s\n", target);
	rc = 0;
	goto done;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "usage: volume remove <name|--all|--orphans> [--yes]");
	rc = 1;

done:
	if (need_state)
		cellman_state_free(&state);
	return rc;
}

static int
cmd_volume_backup(int argc, char *argv[], const char *dsl_dir, char **err)
{
	(void)dsl_dir;
	return cellman_command_volume_backup(argc, argv, err);
}

static int
cmd_volume_desired_mutation(int argc, char *argv[], const char *dsl_dir,
    char **err)
{
	(void)argc;
	(void)argv;
	(void)dsl_dir;
	return cellman_backend_set_desired_mutation_error("volume", err);
}

int
cellman_command_backend_volume(int argc, char *argv[], const char *dsl_dir,
    char **err)
{
	/*
	 * Declarative subcommand table keeps routing close to the command names and
	 * avoids long if/else chains.
	 */
	static const struct cellman_subcommand routes[] = {
		{ "list", cmd_volume_list },
		{ "show", cmd_volume_show },
		{ "fields", cmd_volume_fields },
		{ "create", cmd_volume_create },
		{ "remove", cmd_volume_remove },
		{ "backup", cmd_volume_backup },
		{ "set", cmd_volume_desired_mutation },
		{ "edit", cmd_volume_desired_mutation },
	};

	return cellman_dispatch_subcommand("volume", argc, argv, dsl_dir,
	    routes, sizeof(routes) / sizeof(routes[0]), err);
}
