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
 * Layer: cellman command CLI adapter layer.
 *
 * Parse backup CLI argument shapes and forward validated requests to runtime
 * backup operations.
 *
 * Extension guidance: Add CLI-only backup command UX and validation here; keep
 * archive/mount logic in runtime_backup.c.
 */

#include "../cellman.h"
#include "command_backup_cli.h"

#include <stdbool.h>
#include <string.h>

/*
 * Dispatch cell backup operations for create/list/restore/delete.
 */
int
cellman_command_cell_backup(int argc, char *argv[], char **err)
{
	const char *sub;

	if (argc < 1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "usage: cell backup <create|list|restore|delete> ...");
		return 1;
	}

	sub = argv[0];
	if (strcmp(sub, "create") == 0) {
		if (argc != 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "usage: cell backup create <name>");
			return 1;
		}
		return cellman_backup_cell_create(argv[1], err) == 0 ? 0 : 1;
	}

	if (strcmp(sub, "list") == 0) {
		bool tsv;
		bool no_header;
		const char *name;
		int i;

		if (argc < 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "usage: cell backup list <name> [-T] [-H]");
			return 1;
		}

		name = argv[1];
		tsv = false;
		no_header = false;
		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "-T") == 0) {
				tsv = true;
				continue;
			}
			if (strcmp(argv[i], "-H") == 0) {
				no_header = true;
				continue;
			}
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "usage: cell backup list <name> [-T] [-H]");
			return 1;
		}

		return cellman_backup_cell_list(name, tsv, no_header, err) == 0 ? 0 : 1;
	}

	if (strcmp(sub, "restore") == 0 || strcmp(sub, "delete") == 0) {
		const char *name;
		const char *archive;
		const char *usage;
		bool latest;
		bool yes;
		int i;

		usage = (strcmp(sub, "restore") == 0) ?
		    "usage: cell backup restore <name> [--from archive|--latest] [--yes]" :
		    "usage: cell backup delete <name> [--from archive|--latest] [--yes]";

		if (argc < 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s", usage);
			return 1;
		}

		name = argv[1];
		archive = NULL;
		latest = false;
		yes = false;

		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--from") == 0) {
				if (i + 1 >= argc)
					goto bad_backup_opt;
				archive = argv[++i];
				continue;
			}
			if (strcmp(argv[i], "--latest") == 0) {
				latest = true;
				continue;
			}
			if (strcmp(argv[i], "--yes") == 0) {
				yes = true;
				continue;
			}
			if (argv[i][0] == '-' || archive != NULL)
				goto bad_backup_opt;
			archive = argv[i];
		}

		if (strcmp(sub, "restore") == 0) {
			return cellman_backup_cell_restore(name, archive, latest,
			    yes, err) == 0 ? 0 : 1;
		}

		return cellman_backup_cell_delete(name, archive, latest, yes, err) == 0 ?
		    0 : 1;

bad_backup_opt:
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s", usage);
		return 1;
	}

	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "unknown cell backup command: %s", sub);
	return 1;
}

/*
 * Dispatch volume backup operations for create/list/restore/delete.
 */
int
cellman_command_volume_backup(int argc, char *argv[], char **err)
{
	const char *sub;

	if (argc < 1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "usage: volume backup <create|list|restore|delete> ...");
		return 1;
	}

	sub = argv[0];
	if (strcmp(sub, "create") == 0) {
		if (argc != 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "usage: volume backup create <name>");
			return 1;
		}
		return cellman_backup_volume_create(argv[1], err) == 0 ? 0 : 1;
	}

	if (strcmp(sub, "list") == 0) {
		bool tsv;
		bool no_header;
		const char *name;
		int i;

		if (argc < 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "usage: volume backup list <name> [-T] [-H]");
			return 1;
		}

		name = argv[1];
		tsv = false;
		no_header = false;
		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "-T") == 0) {
				tsv = true;
				continue;
			}
			if (strcmp(argv[i], "-H") == 0) {
				no_header = true;
				continue;
			}
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "usage: volume backup list <name> [-T] [-H]");
			return 1;
		}

		return cellman_backup_volume_list(name, tsv, no_header, err) == 0 ?
		    0 : 1;
	}

	if (strcmp(sub, "restore") == 0 || strcmp(sub, "delete") == 0) {
		const char *name;
		const char *archive;
		const char *usage;
		bool latest;
		bool yes;
		int i;

		usage = (strcmp(sub, "restore") == 0) ?
		    "usage: volume backup restore <name> [--from archive|--latest] [--yes]" :
		    "usage: volume backup delete <name> [--from archive|--latest] [--yes]";

		if (argc < 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s", usage);
			return 1;
		}

		name = argv[1];
		archive = NULL;
		latest = false;
		yes = false;

		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--from") == 0) {
				if (i + 1 >= argc)
					goto bad_backup_opt;
				archive = argv[++i];
				continue;
			}
			if (strcmp(argv[i], "--latest") == 0) {
				latest = true;
				continue;
			}
			if (strcmp(argv[i], "--yes") == 0) {
				yes = true;
				continue;
			}
			if (argv[i][0] == '-' || archive != NULL)
				goto bad_backup_opt;
			archive = argv[i];
		}

		if (strcmp(sub, "restore") == 0) {
			return cellman_backup_volume_restore(name, archive, latest,
			    yes, err) == 0 ? 0 : 1;
		}

		return cellman_backup_volume_delete(name, archive, latest, yes, err) ==
		    0 ? 0 : 1;

bad_backup_opt:
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s", usage);
		return 1;
	}

	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "unknown volume backup command: %s", sub);
	return 1;
}
