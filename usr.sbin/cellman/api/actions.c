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
 * Layer: cellman API facade layer.
 *
 * Translate high-level API requests into backend command invocations and
 * normalize action results.
 *
 * Extension guidance: Add API-level orchestration glue here; keep
 * resource-specific execution details in command/backend runtime modules.
 */

#include "cmd_internal.h"

#include <stdlib.h>
#include <string.h>

static int	run_cell_lifecycle(const char *, const char *, bool,
	    const struct cellman_api_options *, struct cellman_api_result *);
static int	run_backup_subcommand(enum cellman_api_storage_kind,
	    const char *, const char *, const char *, bool, bool,
	    const struct cellman_api_options *, struct cellman_api_result *);
static void	free_owned_argv(char **, int, int);
static int	append_owned_arg(char **, int *, int, const char *,
	    struct cellman_api_result *);

static void
free_owned_argv(char **argv, int argc, int maxargc)
{
	int limit;
	int i;

	if (argv == NULL || argc <= 0 || maxargc <= 0)
		return;

	limit = argc;
	if (limit > maxargc)
		limit = maxargc;

	for (i = 0; i < limit; i++)
		free(argv[i]);
}

static int
append_owned_arg(char **argv, int *argc, int max, const char *value,
    struct cellman_api_result *result)
{
	char *dup;
	char *err;

	if (argv == NULL || argc == NULL || value == NULL)
		return cellman_api_set_error_take(result, 1,
		    cellman_xasprintf(NULL, "invalid api argv append"));
	if (*argc >= max)
		return cellman_api_set_error_take(result, 1,
		    cellman_xasprintf(NULL, "too many api arguments"));

	err = NULL;
	dup = cellman_strdup(value, &err);
	if (dup == NULL)
		return cellman_api_set_error_take(result, 1,
		    err != NULL ? err : cellman_xasprintf(NULL, "out of memory"));

	argv[*argc] = dup;
	(*argc)++;
	return 0;
}

int
cellman_api_apply_all(const struct cellman_api_options *options,
    struct cellman_api_result *result)
{
	char all_opt[] = "--all";
	char *argv[2];

	argv[0] = all_opt;
	argv[1] = NULL;
	return cellman_api_apply(1, argv, options, result);
}

static int
run_cell_lifecycle(const char *verb, const char *name, bool all,
    const struct cellman_api_options *options,
    struct cellman_api_result *result)
{
	char *argv[3];
	int argc;
	int max_args;
	int rc;

	memset(argv, 0, sizeof(argv));
	argc = 0;
	max_args = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

	if (verb == NULL || verb[0] == '\0')
		return cellman_api_set_error_take(result, 1,
		    cellman_xasprintf(NULL, "invalid lifecycle verb"));

	if (!all && (name == NULL || name[0] == '\0'))
		return cellman_api_set_error_take(result, 1,
		    cellman_xasprintf(NULL, "missing cell name"));

	if (append_owned_arg(argv, &argc, max_args, verb, result) != 0)
		return 1;
	if (append_owned_arg(argv, &argc, max_args, all ? "--all" : name,
	    result) != 0) {
		free_owned_argv(argv, argc, (int)(sizeof(argv) / sizeof(argv[0])));
		return 1;
	}
	argv[2] = NULL;
	rc = cellman_api_cell(2, argv, options, result);
	free_owned_argv(argv, argc, (int)(sizeof(argv) / sizeof(argv[0])));
	return rc;
}

int
cellman_api_cell_start(const struct cellman_api_options *options,
    const char *name, bool all, struct cellman_api_result *result)
{
	return run_cell_lifecycle("start", name, all, options, result);
}

int
cellman_api_cell_stop(const struct cellman_api_options *options,
    const char *name, bool all, struct cellman_api_result *result)
{
	return run_cell_lifecycle("stop", name, all, options, result);
}

int
cellman_api_cell_restart(const struct cellman_api_options *options,
    const char *name, bool all, struct cellman_api_result *result)
{
	return run_cell_lifecycle("restart", name, all, options, result);
}

int
cellman_api_cell_shell(const struct cellman_api_options *options,
    const char *name, struct cellman_api_result *result)
{
	char *argv[3];
	int argc;
	int max_args;
	int rc;

	memset(argv, 0, sizeof(argv));
	argc = 0;
	max_args = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

	if (name == NULL || name[0] == '\0')
		return cellman_api_set_error_take(result, 1,
		    cellman_xasprintf(NULL, "missing cell name"));

	if (append_owned_arg(argv, &argc, max_args, "shell", result) != 0)
		return 1;
	if (append_owned_arg(argv, &argc, max_args, name, result) != 0) {
		free_owned_argv(argv, argc, (int)(sizeof(argv) / sizeof(argv[0])));
		return 1;
	}
	argv[2] = NULL;
	rc = cellman_api_cell(2, argv, options, result);
	free_owned_argv(argv, argc, (int)(sizeof(argv) / sizeof(argv[0])));
	return rc;
}

static int
run_backup_subcommand(enum cellman_api_storage_kind kind,
    const char *sub, const char *name, const char *archive, bool latest,
    bool yes, const struct cellman_api_options *options,
    struct cellman_api_result *result)
{
	char *argv[8];
	int argc;
	int max_args;
	int rc;

	memset(argv, 0, sizeof(argv));
	max_args = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

	if (sub == NULL || sub[0] == '\0' || name == NULL || name[0] == '\0')
		return cellman_api_set_error_take(result, 1,
		    cellman_xasprintf(NULL, "invalid backup arguments"));

	argc = 0;
	if (append_owned_arg(argv, &argc, max_args, "backup", result) != 0)
		return 1;
	if (append_owned_arg(argv, &argc, max_args, sub, result) != 0)
		goto fail;
	if (append_owned_arg(argv, &argc, max_args, name, result) != 0)
		goto fail;

	if (strcmp(sub, "restore") == 0 || strcmp(sub, "delete") == 0) {
		if (latest) {
			if (append_owned_arg(argv, &argc, max_args, "--latest", result) !=
			    0)
				goto fail;
		} else if (archive != NULL && archive[0] != '\0') {
			if (append_owned_arg(argv, &argc, max_args, "--from", result) != 0)
				goto fail;
			if (append_owned_arg(argv, &argc, max_args, archive, result) != 0)
				goto fail;
		}
		if (yes) {
			if (append_owned_arg(argv, &argc, max_args, "--yes", result) != 0)
				goto fail;
		}
	}

	argv[argc] = NULL;

	if (kind == CELLMAN_API_STORAGE_OVERLAY)
		rc = cellman_api_cell(argc, argv, options, result);
	else
		rc = cellman_api_volume(argc, argv, options, result);

	free_owned_argv(argv, argc, (int)(sizeof(argv) / sizeof(argv[0])));
	return rc;

fail:
	free_owned_argv(argv, argc, (int)(sizeof(argv) / sizeof(argv[0])));
	return 1;
}

int
cellman_api_backup_create(enum cellman_api_storage_kind kind,
    const char *name, const struct cellman_api_options *options,
    struct cellman_api_result *result)
{
	return run_backup_subcommand(kind, "create", name, NULL, false, false,
	    options, result);
}

int
cellman_api_backup_restore(enum cellman_api_storage_kind kind,
    const char *name, const char *archive, bool latest, bool yes,
    const struct cellman_api_options *options,
    struct cellman_api_result *result)
{
	return run_backup_subcommand(kind, "restore", name, archive, latest, yes,
	    options, result);
}

int
cellman_api_backup_delete(enum cellman_api_storage_kind kind,
    const char *name, const char *archive, bool latest, bool yes,
    const struct cellman_api_options *options,
    struct cellman_api_result *result)
{
	return run_backup_subcommand(kind, "delete", name, archive, latest, yes,
	    options, result);
}
