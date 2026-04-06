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
 * Layer: cellman runtime volume layer.
 *
 * Implement runtime volume creation, inspection, and removal primitives with
 * safety checks.
 *
 * Extension guidance: Add volume runtime primitives here; keep CLI/API routing
 * behavior in command and API layers.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "cellman.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Validate volume identifiers against the shared resource-name policy.
 */
static bool
volume_name_valid(const char *name)
{
	size_t i;

	if (name == NULL || name[0] == '\0')
		return false;

	for (i = 0; name[i] != '\0'; i++) {
		if (!(isalnum((unsigned char)name[i]) || name[i] == '.' ||
		    name[i] == '_' || name[i] == '-'))
			return false;
	}

	return true;
}

/*
 * Check whether a desired-state volume document exists for name.
 */
static bool
state_has_volume(const struct cellman_state *state, const char *name)
{
	size_t i;

	if (state == NULL || name == NULL)
		return false;

	for (i = 0; i < state->volumes.len; i++) {
		if (strcmp(state->volumes.items[i].u.volume.name, name) == 0)
			return true;
	}

	return false;
}

/*
 * Ensure the runtime volume parent directories exist.
 */
static int
ensure_volume_root_dirs(char **err)
{
	const char *const dirs[] = {
		"/var/cellman",
		"/var/cellman/volumes",
	};
	struct stat st;
	size_t i;

	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		if (mkdir(dirs[i], 0755) != 0) {
			if (errno != EEXIST) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "cannot create %s: %s", dirs[i], strerror(errno));
				return -1;
			}
			if (stat(dirs[i], &st) != 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "cannot stat %s: %s", dirs[i], strerror(errno));
				return -1;
			}
			if (!S_ISDIR(st.st_mode)) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "runtime volume root is not a directory: %s",
					    dirs[i]);
				return -1;
			}
		}
	}

	return 0;
}

/*
 * Parse optional octal mode text for runtime chmod operations.
 */
static int
parse_mode(const char *mode_s, mode_t *mode_out, bool *has_mode, char **err)
{
	unsigned long v;
	char *end;

	if (mode_out == NULL || has_mode == NULL)
		return -1;

	*mode_out = 0;
	*has_mode = false;
	if (mode_s == NULL || mode_s[0] == '\0')
		return 0;

	errno = 0;
	v = strtoul(mode_s, &end, 8);
	if (errno != 0 || end == mode_s || *end != '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid volume mode: %s", mode_s);
		return -1;
	}

	*mode_out = (mode_t)v;
	*has_mode = true;
	return 0;
}

/*
 * Recursively remove a filesystem tree rooted at path.
 */
static int
remove_tree_path(const char *path, char **err)
{
	struct stat st;

	if (path == NULL || path[0] == '\0')
		return 0;

	if (lstat(path, &st) != 0) {
		if (errno == ENOENT)
			return 0;
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot stat %s: %s", path,
			    strerror(errno));
		return -1;
	}

	if (S_ISDIR(st.st_mode)) {
		DIR *dp;
		struct dirent *de;

		dp = opendir(path);
		if (dp == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cannot open %s: %s", path,
				    strerror(errno));
			return -1;
		}

		while ((de = readdir(dp)) != NULL) {
			char *child;
			int rc;

			if (strcmp(de->d_name, ".") == 0 ||
			    strcmp(de->d_name, "..") == 0)
				continue;

			child = cellman_path_join(path, de->d_name, err);
			if (child == NULL) {
				(void)closedir(dp);
				return -1;
			}

			rc = remove_tree_path(child, err);
			free(child);
			if (rc != 0) {
				(void)closedir(dp);
				return -1;
			}
		}
		(void)closedir(dp);

		if (rmdir(path) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cannot remove %s: %s", path,
				    strerror(errno));
			return -1;
		}
		return 0;
	}

	if (unlink(path) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot remove %s: %s", path,
			    strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Build the canonical runtime directory path for one volume.
 */
int
cellman_volume_path(const char *name, char **path_out, char **err)
{
	if (path_out == NULL)
		return -1;
	*path_out = NULL;

	if (!volume_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid volume name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	*path_out = cellman_xasprintf(NULL, "/var/cellman/volumes/%s", name);
	if (*path_out == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	return 0;
}

/*
 * Probe whether a runtime volume directory exists.
 */
int
cellman_volume_exists(const char *name, bool *exists_out, char **err)
{
	char *path;
	struct stat st;

	if (exists_out == NULL)
		return -1;
	*exists_out = false;

	path = NULL;
	if (cellman_volume_path(name, &path, err) != 0)
		return -1;

	if (stat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "runtime volume path is not a directory: %s", path);
			free(path);
			return -1;
		}
		*exists_out = true;
		free(path);
		return 0;
	}

	if (errno != ENOENT) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot stat %s: %s", path,
			    strerror(errno));
		free(path);
		return -1;
	}

	free(path);
	return 0;
}

/*
 * Ensure one runtime volume directory exists and apply optional mode.
 */
int
cellman_volume_ensure(const char *name, const char *mode_s,
    bool create_if_missing, bool dry_run, bool verbose, char **err)
{
	char *path;
	bool exists;
	mode_t mode;
	bool has_mode;

	path = NULL;
	if (ensure_volume_root_dirs(err) != 0)
		return -1;

	if (cellman_volume_path(name, &path, err) != 0)
		return -1;

	if (parse_mode(mode_s, &mode, &has_mode, err) != 0) {
		free(path);
		return -1;
	}

	if (cellman_volume_exists(name, &exists, err) != 0) {
		free(path);
		return -1;
	}

	if (!exists && !create_if_missing) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "runtime volume not found: %s", name);
		free(path);
		return -1;
	}

	if (verbose) {
		cellman_log_info("volume runtime ensure %s%s%s", path,
		    has_mode ? " mode=" : "",
		    has_mode ? mode_s : "");
	}

	if (!dry_run && !exists) {
		if (mkdir(path, 0755) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cannot create %s: %s", path,
				    strerror(errno));
			free(path);
			return -1;
		}
	}

	if (!dry_run && has_mode) {
		if (chmod(path, mode) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cannot chmod %s: %s", path,
				    strerror(errno));
			free(path);
			return -1;
		}
	}

	free(path);
	return 0;
}

/*
 * Remove one runtime volume directory tree.
 */
int
cellman_volume_remove_one(const char *name, bool dry_run, bool verbose,
    bool require_existing, char **err)
{
	char *path;
	bool exists;

	path = NULL;
	if (cellman_volume_path(name, &path, err) != 0)
		return -1;

	if (cellman_volume_exists(name, &exists, err) != 0) {
		free(path);
		return -1;
	}

	if (!exists) {
		if (require_existing) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "runtime volume not found: %s", name);
			free(path);
			return -1;
		}
		free(path);
		return 0;
	}

	if (verbose)
		cellman_log_info("volume runtime remove %s", path);

	if (!dry_run && remove_tree_path(path, err) != 0) {
		free(path);
		return -1;
	}

	free(path);
	return 0;
}

/*
 * Remove all runtime volume directories or only runtime orphans.
 */
int
cellman_volume_remove_all(const struct cellman_state *state,
    bool only_orphans, bool dry_run, bool verbose, size_t *removed_out,
    char **err)
{
	const char *root;
	DIR *dp;
	struct dirent *de;
	size_t removed;

	root = "/var/cellman/volumes";
	removed = 0;
	if (removed_out != NULL)
		*removed_out = 0;

	dp = opendir(root);
	if (dp == NULL) {
		if (errno == ENOENT)
			return 0;
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot open %s: %s", root,
			    strerror(errno));
		return -1;
	}

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		char *path;

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		if (!volume_name_valid(de->d_name)) {
			cellman_log_warn("skipping invalid runtime volume directory name: %s",
			    de->d_name);
			continue;
		}
		if (only_orphans && state_has_volume(state, de->d_name))
			continue;

		path = cellman_xasprintf(NULL, "%s/%s", root, de->d_name);
		if (path == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			(void)closedir(dp);
			return -1;
		}
		if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
			free(path);
			continue;
		}
		free(path);

		if (cellman_volume_remove_one(de->d_name, dry_run, verbose,
		    false, err) != 0) {
			(void)closedir(dp);
			return -1;
		}
		removed++;
	}

	(void)closedir(dp);
	if (removed_out != NULL)
		*removed_out = removed;
	return 0;
}
