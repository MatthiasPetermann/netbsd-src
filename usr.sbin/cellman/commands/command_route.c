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
 * Resolve command aliases and route names to backend command groups.
 *
 * Extension guidance: Add route table or alias behavior here; keep command
 * execution logic in backend modules.
 */

#include "command_backend_internal.h"

#include <string.h>

/*
 * Dispatch one resource subcommand via a static command table.
 */
int
cellman_dispatch_subcommand(const char *resource, int argc, char *argv[],
    const char *dsl_dir, const struct cellman_subcommand *routes,
    size_t route_len, char **err)
{
	size_t i;

	if (argc < 1) {
		if (err != NULL) {
			if (resource == NULL)
				*err = cellman_xasprintf(NULL, "missing command arguments");
			else
				*err = cellman_xasprintf(NULL,
				    "usage: %s <subcommand> ...", resource);
		}
		return 1;
	}

	for (i = 0; i < route_len; i++) {
		if (strcmp(argv[0], routes[i].name) == 0)
			return routes[i].handler(argc - 1, &argv[1], dsl_dir, err);
	}

	if (err != NULL) {
		if (resource == NULL)
			*err = cellman_xasprintf(NULL, "unsupported command: %s",
			    argv[0]);
		else
			*err = cellman_xasprintf(NULL,
			    "unsupported %s subcommand: %s", resource, argv[0]);
	}
	return 1;
}
