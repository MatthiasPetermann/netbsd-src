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
 * Handle system command family routing and high-level CLI-facing system
 * operations.
 *
 * Extension guidance: Add system command route UX here; keep bootstrap/reset
 * execution details in backend/system modules.
 */

#include "../cellman.h"
#include "command_backend.h"
#include "command_backend_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

/*
 * System commands are collected in this module so bootstrap/reset behavior and
 * route dispatch are visible in one read path.
 */
int
cmd_system_bootstrap(int argc, char *argv[], const char *dsl_dir, char **err)
{
	bool include_xbase;
	struct utsname uts;
	char *base_set;
	char *etc_set;
	char *xbase_set;
	char *set_dir;
	const char *dirs[] = {
		"/var/cellman",
		"/var/cellman/cells",
		"/var/cellman/volumes",
		"/var/cellman/state",
		"/var/cellman/releases",
		"/var/cellman/base",
		"/var/backups/cellman",
		"/var/backups/cellman/volumes",
		"/var/backups/cellman/overlays",
		"/etc/cellman",
	};
	size_t i;

	(void)dsl_dir;

	include_xbase = false;
	base_set = NULL;
	etc_set = NULL;
	xbase_set = NULL;
	set_dir = NULL;

	for (i = 0; i < (size_t)argc; i++) {
		if (strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--xbase") == 0) {
			include_xbase = true;
			continue;
		}
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "usage: system bootstrap [--xbase]");
		return 1;
	}

	if (geteuid() != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "must be root");
		return 1;
	}

	if (uname(&uts) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "uname failed: %s", strerror(errno));
		return 1;
	}

	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		if (mkdir_p_local(dirs[i], 0755, err) != 0)
			return 1;
	}

	if (ensure_rc_conf_cellman(err) != 0 ||
	    ensure_secmodel_cell_loaded(err) != 0 ||
	    ensure_modules_conf_secmodel(err) != 0 ||
	    write_default_cellman_conf(uts.release, uts.machine, err) != 0 ||
	    fetch_release_sets(uts.release, uts.machine, include_xbase,
	    &base_set, &etc_set, &xbase_set, &set_dir, err) != 0 ||
	    build_base_layer(uts.release, uts.machine, set_dir, include_xbase,
	    err) != 0) {
		free(base_set);
		free(etc_set);
		free(xbase_set);
		free(set_dir);
		return 1;
	}

	free(base_set);
	free(etc_set);
	free(xbase_set);
	free(set_dir);

	(void)cellman_payload_printf("ok bootstrap release=%s arch=%s xbase=%s\n",
	    uts.release, uts.machine, include_xbase ? "YES" : "NO");
	return 0;
}

int
cmd_system_reset(int argc, char *argv[], const char *dsl_dir, char **err)
{
	bool yes;
	bool reset_cells;
	bool reset_volumes;
	int i;

	yes = false;
	reset_cells = false;
	reset_volumes = false;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--cells") == 0) {
			reset_cells = true;
			continue;
		}
		if (strcmp(argv[i], "--volumes") == 0) {
			reset_volumes = true;
			continue;
		}
		if (strcmp(argv[i], "--yes") == 0) {
			yes = true;
			continue;
		}
		goto badopt;
	}

	if (!yes) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "system reset requires --yes in runtime mode");
		return 1;
	}

	if (!reset_cells && !reset_volumes) {
		reset_cells = true;
		reset_volumes = true;
	}

	if (dsl_dir != NULL && dsl_dir[0] != '\0') {
		if (reset_cells &&
		    path_is_same_or_child(dsl_dir, "/var/cellman/cells")) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "refusing system reset --cells: DSL directory is inside runtime cells tree: %s",
				    dsl_dir);
			return 1;
		}
		if (reset_volumes &&
		    path_is_same_or_child(dsl_dir, "/var/cellman/volumes")) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "refusing system reset --volumes: DSL directory is inside runtime volumes tree: %s",
				    dsl_dir);
			return 1;
		}
	}

	if (reset_cells) {
		char stop_all[] = "--all";
		char *stop_argv[1];

		stop_argv[0] = stop_all;
		if (cmd_cell_lifecycle("stop", 1, stop_argv, dsl_dir, err) != 0)
			return 1;
	}

	if (reset_cells)
		remove_tree("/var/cellman/cells");
	if (reset_volumes)
		remove_tree("/var/cellman/volumes");

	(void)cellman_payload_printf("ok reset runtime\n");
	return 0;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "usage: system reset [--cells] [--volumes] [--yes]");
	return 1;
}

int
cellman_command_backend_system(int argc, char *argv[], const char *dsl_dir,
    char **err)
{
	/*
	 * Declarative subcommand table keeps routing close to the command names and
	 * avoids long if/else chains.
	 */
	static const struct cellman_subcommand routes[] = {
		{ "bootstrap", cmd_system_bootstrap },
		{ "reset", cmd_system_reset },
	};

	return cellman_dispatch_subcommand("system", argc, argv, dsl_dir,
	    routes, sizeof(routes) / sizeof(routes[0]), err);
}
