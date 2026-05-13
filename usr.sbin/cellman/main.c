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
 * Layer: cellman executable entry layer.
 *
 * Initialize process context and hand off command-line execution into the API
 * dispatch path.
 *
 * Extension guidance: Keep startup and top-level process behavior here; move
 * command semantics into API/command layers.
 */

#include "cellman_api.h"

#include <stdio.h>
#include <stdlib.h>

static void usage(void);

static const char *progname = "cellman";

/*
 * Program entrypoint.
 *
 * CLI argument handling stays intentionally thin and delegates command
 * execution to the library API so alternate frontends (for example cellui)
 * can share identical behavior.
 */
int
main(int argc, char *argv[])
{
	struct cellman_api_options options;
	struct cellman_api_result result;
	int rc;

	if (argc > 0 && argv[0] != NULL && argv[0][0] != '\0')
		progname = argv[0];

	if (argc < 2)
		usage();

	options.dsl_dir = NULL;
	cellman_api_result_init(&result);
	rc = cellman_api_dispatch(argc - 1, &argv[1], &options, &result);
	if (result.error != NULL)
		(void)fprintf(stderr, "%s: %s\n", progname, result.error);
	cellman_api_result_reset(&result);

	return rc;
}

/*
 * Print CLI usage and terminate with non-zero status.
 */
static void
usage(void)
{
	(void)fprintf(stderr,
	    "usage:\n"
	    "  %s apply [--all|<name>...] [--dry-run] [--force] [--restart-changed] [--silent|-v|-vv]\n"
	    "  %s cell <list|show|fields|start|stop|restart|shell|remove|backup|plan> ...\n"
	    "  %s volume <list|show|fields|create|remove|backup> ...\n"
	    "  %s system <bootstrap|reset> ...\n"
	    "\n"
	    "  %s list  [cell list options]\n"
	    "  %s start <name>|--all\n"
	    "  %s stop  <name>|--all\n"
	    "  %s restart <name>|--all\n"
	    "  %s shell <name> [command ...]\n"
	    "\n"
	    "default spec dir: /etc/cellman (override with CELLMAN_DSL_DIR)\n",
	    progname, progname, progname, progname,
	    progname, progname, progname, progname, progname);
	exit(1);
}
