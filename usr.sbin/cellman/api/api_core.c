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
 * Provide the stable API entrypoint and response framing shared by CLI and TUI
 * clients.
 *
 * Extension guidance: Extend cross-client API behavior here; keep subcommand
 * semantics in cmd_* API modules.
 */

#include "cmd_internal.h"
#include "../commands/command_dispatch.h"

#include <stdlib.h>

/*
 * Initialize a result object with safe defaults.
 */
void
cellman_api_result_init(struct cellman_api_result *result)
{
	if (result == NULL)
		return;

	result->exit_code = 1;
	result->error = NULL;
}

/*
 * Release owned result memory and reset to success state.
 */
void
cellman_api_result_reset(struct cellman_api_result *result)
{
	if (result == NULL)
		return;

	free(result->error);
	result->error = NULL;
	result->exit_code = 0;
}

/*
 * Prepare a result object for a fresh command execution.
 */
void
cellman_api_result_prepare(struct cellman_api_result *result)
{
	if (result == NULL)
		return;

	free(result->error);
	result->error = NULL;
	result->exit_code = 1;
}

/*
 * Store an owned error string and return the provided code.
 */
int
cellman_api_set_error_take(struct cellman_api_result *result, int rc,
    char *error)
{
	if (result == NULL) {
		free(error);
		return rc;
	}

	free(result->error);
	result->error = error;
	result->exit_code = rc;
	return rc;
}

/*
 * Resolve the default DSL directory from environment or fallback.
 */
const char *
cellman_api_default_dsl_dir(void)
{
	const char *dir;

	dir = getenv("CELLMAN_DSL_DIR");
	if (dir == NULL || dir[0] == '\0')
		return "/etc/cellman";
	return dir;
}

/*
 * Resolve effective DSL directory from options or defaults.
 */
const char *
cellman_api_effective_dsl_dir(const struct cellman_api_options *options)
{
	if (options != NULL && options->dsl_dir != NULL &&
	    options->dsl_dir[0] != '\0')
		return options->dsl_dir;
	return cellman_api_default_dsl_dir();
}

/*
 * Run one command by prepending its top-level token.
 */
int
cellman_api_run_command(const char *prefix, int argc, char *argv[],
    const struct cellman_api_options *options, struct cellman_api_result *result)
{
	char **dispatch_argv;
	char *dispatch_prefix;
	char *err;
	int rc;
	size_t i;

	if (prefix == NULL || prefix[0] == '\0') {
		err = cellman_xasprintf(NULL, "invalid command prefix");
		return cellman_api_set_error_take(result, 1, err);
	}
	if (argc < 0) {
		err = cellman_xasprintf(NULL, "invalid command arguments");
		return cellman_api_set_error_take(result, 1, err);
	}
	if (argc > 0 && argv == NULL) {
		err = cellman_xasprintf(NULL, "missing command arguments");
		return cellman_api_set_error_take(result, 1, err);
	}

	dispatch_argv = calloc((size_t)argc + 2, sizeof(*dispatch_argv));
	if (dispatch_argv == NULL) {
		err = cellman_xasprintf(NULL, "out of memory");
		return cellman_api_set_error_take(result, 1, err);
	}

	dispatch_prefix = cellman_strdup(prefix, &err);
	if (dispatch_prefix == NULL) {
		free(dispatch_argv);
		if (err == NULL)
			err = cellman_xasprintf(NULL, "out of memory");
		return cellman_api_set_error_take(result, 1, err);
	}

	dispatch_argv[0] = dispatch_prefix;
	for (i = 0; i < (size_t)argc; i++)
		dispatch_argv[i + 1] = argv[i];

	err = NULL;
	rc = cellman_cli_command_dispatch(argc + 1, dispatch_argv,
	    cellman_api_effective_dsl_dir(options), &err);
	free(dispatch_prefix);
	free(dispatch_argv);

	if (err != NULL)
		return cellman_api_set_error_take(result, rc != 0 ? rc : 1, err);
	return cellman_api_set_error_take(result, rc, NULL);
}
