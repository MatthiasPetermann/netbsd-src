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
 * Layer: cellman API command layer.
 *
 * Route API command names to concrete handler functions using table-driven
 * dispatch.
 *
 * Extension guidance: Extend API command routing tables here; avoid embedding
 * business logic in the dispatcher.
 */

#include "cmd_internal.h"

#include <stdlib.h>
#include <string.h>

enum api_command_kind {
	API_CMD_APPLY = 0,
	API_CMD_CELL,
	API_CMD_VOLUME,
	API_CMD_SYSTEM,
	API_CMD_CELL_ALIAS,
};

struct api_command_route {
	const char *name;
	enum api_command_kind kind;
	const char *alias_subcommand;
};

static int dispatch_cell_alias(const char *, int, char *[],
    const struct cellman_api_options *, struct cellman_api_result *);

static const struct api_command_route api_routes[] = {
	{ "apply", API_CMD_APPLY, NULL },
	{ "cell", API_CMD_CELL, NULL },
	{ "volume", API_CMD_VOLUME, NULL },
	{ "system", API_CMD_SYSTEM, NULL },
	{ "start", API_CMD_CELL_ALIAS, "start" },
	{ "stop", API_CMD_CELL_ALIAS, "stop" },
	{ "restart", API_CMD_CELL_ALIAS, "restart" },
	{ "list", API_CMD_CELL_ALIAS, "list" },
	{ "shell", API_CMD_CELL_ALIAS, "shell" },
};

static int
dispatch_cell_alias(const char *subcommand, int argc, char *argv[],
    const struct cellman_api_options *options,
    struct cellman_api_result *result)
{
	char **cell_argv;
	char *alias_argv0;
	char *err;
	int rc;
	size_t i;

	if (subcommand == NULL || subcommand[0] == '\0') {
		err = cellman_xasprintf(NULL, "invalid cell alias");
		return cellman_api_set_error_take(result, 1, err);
	}

	cell_argv = calloc((size_t)argc + 1, sizeof(*cell_argv));
	if (cell_argv == NULL) {
		err = cellman_xasprintf(NULL, "out of memory");
		return cellman_api_set_error_take(result, 1, err);
	}
	alias_argv0 = cellman_strdup(subcommand, &err);
	if (alias_argv0 == NULL) {
		free(cell_argv);
		if (err == NULL)
			err = cellman_xasprintf(NULL, "out of memory");
		return cellman_api_set_error_take(result, 1, err);
	}

	cell_argv[0] = alias_argv0;
	for (i = 0; i < (size_t)argc; i++)
		cell_argv[i + 1] = argv[i];

	rc = cellman_api_cell(argc + 1, cell_argv, options, result);
	free(alias_argv0);
	free(cell_argv);
	return rc;
}

/*
 * Dispatch a top-level API command to its module handler.
 */
int
cellman_api_dispatch(int argc, char *argv[],
    const struct cellman_api_options *options,
    struct cellman_api_result *result)
{
	char *err;
	size_t i;

	cellman_api_result_prepare(result);

	if (argc <= 0 || argv == NULL) {
		err = cellman_xasprintf(NULL, "missing command arguments");
		return cellman_api_set_error_take(result, 1, err);
	}

	for (i = 0; i < sizeof(api_routes) / sizeof(api_routes[0]); i++) {
		if (strcmp(argv[0], api_routes[i].name) != 0)
			continue;

		switch (api_routes[i].kind) {
		case API_CMD_APPLY:
			return cellman_api_apply(argc - 1, &argv[1], options, result);
		case API_CMD_CELL:
			return cellman_api_cell(argc - 1, &argv[1], options, result);
		case API_CMD_VOLUME:
			return cellman_api_volume(argc - 1, &argv[1], options, result);
		case API_CMD_SYSTEM:
			return cellman_api_system(argc - 1, &argv[1], options, result);
		case API_CMD_CELL_ALIAS:
			return dispatch_cell_alias(api_routes[i].alias_subcommand,
			    argc - 1, &argv[1], options, result);
		}
	}

	err = cellman_xasprintf(NULL, "unsupported command: %s", argv[0]);
	return cellman_api_set_error_take(result, 1, err);
}
