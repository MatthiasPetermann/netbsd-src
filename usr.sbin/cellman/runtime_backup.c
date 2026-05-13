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
 * Layer: cellman runtime backup layer.
 *
 * Implement backup/create/list/restore/delete flows for volumes and cell
 * overlays.
 *
 * Extension guidance: Add backup runtime behavior here; keep backup CLI
 * argument parsing in command backup adapter modules.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "cellman.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define CELLMAN_BACKUP_ROOT "/var/backups/cellman"

enum backup_kind {
	BACKUP_KIND_VOLUME = 0,
	BACKUP_KIND_OVERLAY,
};

struct backup_entry {
	char *timestamp;
	off_t size;
	char *archive_path;
};

struct backup_entry_list {
	struct backup_entry *items;
	size_t len;
	size_t cap;
};

/*
 * Validate resource names against the shared identifier policy.
 */
static bool
resource_name_valid(const char *name)
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
 * Compare backup entries by timestamp descending for list output.
 */
static int
backup_entry_compare_desc(const void *a, const void *b)
{
	const struct backup_entry *ap;
	const struct backup_entry *bp;

	ap = a;
	bp = b;
	return strcmp(bp->timestamp, ap->timestamp);
}

/*
 * Release all memory owned by a backup entry list.
 */
static void
backup_entry_list_free(struct backup_entry_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++) {
		free(list->items[i].timestamp);
		free(list->items[i].archive_path);
	}

	free(list->items);
	list->items = NULL;
	list->len = 0;
	list->cap = 0;
}

void
cellman_backup_record_list_free(struct cellman_backup_record_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++) {
		free(list->items[i].timestamp);
		free(list->items[i].size);
		free(list->items[i].archive);
	}

	free(list->items);
	list->items = NULL;
	list->len = 0;
}

static int
backup_record_list_from_entries(const struct backup_entry_list *entries,
    struct cellman_backup_record_list *out, char **err)
{
	struct cellman_backup_record *items;
	size_t i;

	if (out == NULL || entries == NULL)
		return -1;

	out->items = NULL;
	out->len = 0;

	if (entries->len == 0)
		return 0;

	items = calloc(entries->len, sizeof(*items));
	if (items == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	for (i = 0; i < entries->len; i++) {
		items[i].timestamp = cellman_strdup(entries->items[i].timestamp, err);
		items[i].size = cellman_xasprintf(NULL, "%lld",
		    (long long)entries->items[i].size);
		items[i].archive = cellman_strdup(entries->items[i].archive_path, err);
		if (items[i].timestamp == NULL || items[i].size == NULL ||
		    items[i].archive == NULL) {
			size_t j;

			for (j = 0; j <= i; j++) {
				free(items[j].timestamp);
				free(items[j].size);
				free(items[j].archive);
			}
			free(items);
			if (err != NULL && *err == NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return -1;
		}
	}

	out->items = items;
	out->len = entries->len;
	return 0;
}

/*
 * Append one archive metadata row to a backup entry list.
 */
static int
backup_entry_list_add(struct backup_entry_list *list, const char *timestamp,
    off_t size, const char *archive_path, char **err)
{
	struct backup_entry *next;

	if (list == NULL)
		return -1;

	if (list->len == list->cap) {
		size_t new_cap;

		new_cap = (list->cap == 0) ? 8 : list->cap * 2;
		next = realloc(list->items, new_cap * sizeof(*next));
		if (next == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return -1;
		}
		list->items = next;
		list->cap = new_cap;
	}

	list->items[list->len].timestamp = cellman_strdup(timestamp, err);
	if (list->items[list->len].timestamp == NULL)
		return -1;

	list->items[list->len].archive_path = cellman_strdup(archive_path, err);
	if (list->items[list->len].archive_path == NULL) {
		free(list->items[list->len].timestamp);
		list->items[list->len].timestamp = NULL;
		return -1;
	}

	list->items[list->len].size = size;
	list->len++;
	return 0;
}

/*
 * Return the directory suffix for one backup kind.
 */
static const char *
backup_kind_subdir(enum backup_kind kind)
{
	switch (kind) {
	case BACKUP_KIND_VOLUME:
		return "volumes";
	case BACKUP_KIND_OVERLAY:
		return "overlays";
	default:
		return NULL;
	}
}

/*
 * Return human-visible kind labels for payload and error messages.
 */
static const char *
backup_kind_label(enum backup_kind kind)
{
	switch (kind) {
	case BACKUP_KIND_VOLUME:
		return "volume";
	case BACKUP_KIND_OVERLAY:
		return "overlay";
	default:
		return "backup";
	}
}

/*
 * Ensure the process runs with root privileges for destructive operations.
 */
static int
require_root(char **err)
{
	if (geteuid() == 0)
		return 0;

	if (err != NULL)
		*err = cellman_xasprintf(NULL, "must be root");
	return -1;
}

/*
 * Remove a filesystem tree recursively.
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
 * Remove all entries inside a directory while preserving the directory itself.
 */
static int
clear_directory_contents(const char *dir_path, char **err)
{
	DIR *dp;
	struct dirent *de;

	if (dir_path == NULL || dir_path[0] == '\0' || strcmp(dir_path, "/") == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "refusing to clear unsafe directory path: %s",
			    dir_path != NULL ? dir_path : "");
		return -1;
	}

	dp = opendir(dir_path);
	if (dp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot open %s: %s", dir_path,
			    strerror(errno));
		return -1;
	}

	while ((de = readdir(dp)) != NULL) {
		char *entry;
		int rc;

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;

		entry = cellman_path_join(dir_path, de->d_name, err);
		if (entry == NULL) {
			(void)closedir(dp);
			return -1;
		}
		rc = remove_tree_path(entry, err);
		free(entry);
		if (rc != 0) {
			(void)closedir(dp);
			return -1;
		}
	}

	(void)closedir(dp);
	return 0;
}

/*
 * Resolve one existing filesystem path to an absolute canonical form.
 */
static int
canonicalize_existing_path(const char *path, char **resolved_out, char **err)
{
	char resolved[PATH_MAX];

	if (resolved_out == NULL)
		return -1;
	*resolved_out = NULL;

	if (path == NULL || path[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid path");
		return -1;
	}

	if (realpath(path, resolved) == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot resolve %s: %s", path,
			    strerror(errno));
		return -1;
	}

	*resolved_out = cellman_strdup(resolved, err);
	return *resolved_out != NULL ? 0 : -1;
}

/*
 * Format a sortable backup timestamp (YYYYmmddHHMMSS).
 */
static int
backup_timestamp(char out[15], char **err)
{
	time_t now;
	struct tm tmv;
	size_t n;

	now = time(NULL);
	if (now == (time_t)-1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "time failed");
		return -1;
	}

	if (localtime_r(&now, &tmv) == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "localtime_r failed");
		return -1;
	}

	n = strftime(out, 15, "%Y%m%d%H%M%S", &tmv);
	if (n != 14) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "strftime failed for backup timestamp");
		return -1;
	}

	return 0;
}

/*
 * Build the primary backup directory path for one kind.
 */
static int
backup_dir_for_kind(enum backup_kind kind, char **out, char **err)
{
	const char *subdir;

	if (out == NULL)
		return -1;
	*out = NULL;

	subdir = backup_kind_subdir(kind);
	if (subdir == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid backup kind");
		return -1;
	}

	*out = cellman_xasprintf(NULL, "%s/%s", CELLMAN_BACKUP_ROOT, subdir);
	if (*out == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	return 0;
}

/*
 * Collect all search roots for one backup kind.
 */
static int
backup_search_dirs_for_kind(enum backup_kind kind,
    struct cellman_string_list *dirs, char **err)
{
	char *primary;

	if (dirs == NULL)
		return -1;
	memset(dirs, 0, sizeof(*dirs));

	primary = NULL;
	if (backup_dir_for_kind(kind, &primary, err) != 0)
		return -1;

	if (cellman_string_list_add(dirs, primary, err) != 0) {
		free(primary);
		cellman_string_list_free(dirs);
		return -1;
	}
	free(primary);

	if (kind == BACKUP_KIND_VOLUME) {
		if (cellman_string_list_add(dirs, CELLMAN_BACKUP_ROOT, err) != 0) {
			cellman_string_list_free(dirs);
			return -1;
		}
	}

	return 0;
}

/*
 * Ensure the primary backup directory exists when write access is required.
 */
static int
ensure_backup_layout(enum backup_kind kind, bool write_mode, char **err)
{
	char *dir;
	struct stat st;

	dir = NULL;
	if (backup_dir_for_kind(kind, &dir, err) != 0)
		return -1;

	if (write_mode) {
		if (cellman_mkdir_p(dir, 0755, err) != 0) {
			free(dir);
			return -1;
		}
		free(dir);
		return 0;
	}

	if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "backup directory not found for %s: %s",
			    backup_kind_label(kind), dir);
		free(dir);
		return -1;
	}

	free(dir);
	return 0;
}

/*
 * Validate archive basename pattern and optionally extract timestamp text.
 */
static bool
archive_name_matches(const char *name, const char *base, char **timestamp_out)
{
	size_t name_len;
	const char *prefix;
	const char *ts;
	size_t i;
	const char *suffix;

	if (timestamp_out != NULL)
		*timestamp_out = NULL;

	if (name == NULL || base == NULL)
		return false;

	name_len = strlen(name);
	prefix = name;
	if (strncmp(base, prefix, name_len) != 0)
		return false;
	if (base[name_len] != '_')
		return false;

	ts = base + name_len + 1;
	for (i = 0; i < 14; i++) {
		if (!isdigit((unsigned char)ts[i]))
			return false;
	}

	suffix = ts + 14;
	if (strcmp(suffix, ".tar.gz") != 0)
		return false;

	if (timestamp_out != NULL) {
		*timestamp_out = cellman_strndup(ts, 14, NULL);
		if (*timestamp_out == NULL)
			return false;
	}

	return true;
}

/*
 * Enumerate all matching archives for a resource name and kind.
 */
static int
collect_archives(enum backup_kind kind, const char *name,
    struct backup_entry_list *entries, char **err)
{
	struct cellman_string_list dirs;
	size_t i;

	if (entries == NULL)
		return -1;
	memset(entries, 0, sizeof(*entries));

	if (backup_search_dirs_for_kind(kind, &dirs, err) != 0)
		return -1;

	for (i = 0; i < dirs.len; i++) {
		DIR *dp;
		struct dirent *de;

		dp = opendir(dirs.items[i]);
		if (dp == NULL)
			continue;

		while ((de = readdir(dp)) != NULL) {
			char *timestamp;
			char *full;
			struct stat st;

			timestamp = NULL;
			if (!archive_name_matches(name, de->d_name, &timestamp)) {
				free(timestamp);
				continue;
			}

			full = cellman_path_join(dirs.items[i], de->d_name, err);
			if (full == NULL) {
				free(timestamp);
				(void)closedir(dp);
				cellman_string_list_free(&dirs);
				backup_entry_list_free(entries);
				return -1;
			}

			if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
				free(timestamp);
				free(full);
				continue;
			}

			if (backup_entry_list_add(entries, timestamp, st.st_size, full,
			    err) != 0) {
				free(timestamp);
				free(full);
				(void)closedir(dp);
				cellman_string_list_free(&dirs);
				backup_entry_list_free(entries);
				return -1;
			}

			free(timestamp);
			free(full);
		}

		(void)closedir(dp);
	}

	if (entries->len > 1) {
		qsort(entries->items, entries->len, sizeof(entries->items[0]),
		    backup_entry_compare_desc);
	}

	cellman_string_list_free(&dirs);
	return 0;
}

/*
 * Resolve one archive path by optional explicit argument or latest selection.
 */
static int
resolve_archive(enum backup_kind kind, const char *name, const char *archive_arg,
    bool latest, char **archive_path, char **err)
{
	struct backup_entry_list entries;
	struct cellman_string_list dirs;
	size_t i;

	if (archive_path == NULL)
		return -1;
	*archive_path = NULL;

	if (latest || archive_arg == NULL || archive_arg[0] == '\0') {
		if (collect_archives(kind, name, &entries, err) != 0)
			return -1;
		if (entries.len == 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "no backups found for %s %s",
				    backup_kind_label(kind), name);
			backup_entry_list_free(&entries);
			return -1;
		}
		*archive_path = cellman_strdup(entries.items[0].archive_path, err);
		backup_entry_list_free(&entries);
		return *archive_path != NULL ? 0 : -1;
	}

	if (access(archive_arg, R_OK) == 0) {
		struct stat st;

		if (stat(archive_arg, &st) != 0 || !S_ISREG(st.st_mode)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "backup archive is not a regular file: %s", archive_arg);
			return -1;
		}
		*archive_path = cellman_strdup(archive_arg, err);
		return *archive_path != NULL ? 0 : -1;
	}

	if (backup_search_dirs_for_kind(kind, &dirs, err) != 0)
		return -1;

	for (i = 0; i < dirs.len; i++) {
		char *candidate;
		struct stat st;

		candidate = cellman_path_join(dirs.items[i], archive_arg, err);
		if (candidate == NULL) {
			cellman_string_list_free(&dirs);
			return -1;
		}
		if (access(candidate, R_OK) == 0 && stat(candidate, &st) == 0 &&
		    S_ISREG(st.st_mode)) {
			*archive_path = candidate;
			cellman_string_list_free(&dirs);
			return 0;
		}
		free(candidate);
	}

	cellman_string_list_free(&dirs);
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "backup archive not found or unreadable: %s", archive_arg);
	return -1;
}

/*
 * Determine whether a runtime cell currently exists in cellctl list output.
 */
static int
is_cell_running(const char *name, bool *running_out, char **err)
{
	char *raw;
	char *line;
	char *saveptr;

	if (running_out == NULL)
		return -1;
	*running_out = false;

	raw = NULL;
	if (cellman_exec_run_capture((const char *const[]){ "cellctl", "list",
	    "-T", "-H", NULL }, &raw, err) != 0) {
		if (err != NULL && *err != NULL && strstr(*err, "permission") != NULL) {
			free(*err);
			*err = NULL;
			return 0;
		}
		return -1;
	}

	saveptr = NULL;
	line = strtok_r(raw, "\n", &saveptr);
	while (line != NULL) {
		char *cid;
		char *cell_name;
		char *tab;

		cid = line;
		tab = strchr(cid, '\t');
		if (tab != NULL) {
			*tab = '\0';
			cell_name = tab + 1;
			tab = strchr(cell_name, '\t');
			if (tab != NULL)
				*tab = '\0';
			if (strcmp(cell_name, name) == 0) {
				*running_out = true;
				break;
			}
		}

		line = strtok_r(NULL, "\n", &saveptr);
	}

	free(raw);
	return 0;
}

/*
 * Validate that an archive path is located under an allowed backup root.
 */
static bool
archive_in_allowed_dir(enum backup_kind kind, const char *archive_path)
{
	struct cellman_string_list dirs;
	size_t i;
	bool ok;
	char *resolved;

	ok = false;
	resolved = NULL;
	if (canonicalize_existing_path(archive_path, &resolved, NULL) != 0)
		return false;

	if (backup_search_dirs_for_kind(kind, &dirs, NULL) != 0)
		goto done;

	for (i = 0; i < dirs.len; i++) {
		if (cellman_path_is_same_or_child(resolved, dirs.items[i])) {
			ok = true;
			break;
		}
	}

	cellman_string_list_free(&dirs);

done:
	free(resolved);
	return ok;
}

/*
 * Validate naming and allowed-root constraints for one resolved archive path.
 */
static int
validate_archive_path(enum backup_kind kind, const char *name,
    const char *archive_path, const char *op, char **err)
{
	const char *base;

	if (archive_path == NULL || archive_path[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s backup %s: archive path is empty",
			    backup_kind_label(kind), op);
		return -1;
	}

	base = strrchr(archive_path, '/');
	base = base != NULL ? base + 1 : archive_path;
	if (!archive_name_matches(name, base, NULL)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "refusing %s backup %s for archive with invalid name pattern: %s",
			    backup_kind_label(kind), op, archive_path);
		return -1;
	}

	if (!archive_in_allowed_dir(kind, archive_path)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "refusing %s backup %s outside allowed backup directories: %s",
			    backup_kind_label(kind), op, archive_path);
		return -1;
	}

	return 0;
}

/*
 * Create a temporary directory under /tmp with mkdtemp.
 */
static int
mktemp_dir(const char *prefix, char **out, char **err)
{
	char template_buf[PATH_MAX];
	const char *p;

	if (out == NULL)
		return -1;
	*out = NULL;

	p = prefix != NULL ? prefix : "/tmp/cellman-backup";
	if (snprintf(template_buf, sizeof(template_buf), "%s.XXXXXX", p) >=
	    (int)sizeof(template_buf)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "temporary path too long");
		return -1;
	}

	if (mkdtemp(template_buf) == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "mkdtemp failed for %s: %s", template_buf, strerror(errno));
		return -1;
	}

	*out = cellman_strdup(template_buf, err);
	return *out != NULL ? 0 : -1;
}

/*
 * Create a volume runtime backup archive.
 */
int
cellman_backup_volume_create(const char *name, char **err)
{
	char *volume_path;
	bool exists;
	char *backup_dir;
	char timestamp[15];
	char *archive_path;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid volume name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	if (require_root(err) != 0)
		return -1;

	volume_path = NULL;
	if (cellman_volume_path(name, &volume_path, err) != 0)
		return -1;
	if (cellman_volume_exists(name, &exists, err) != 0) {
		free(volume_path);
		return -1;
	}
	if (!exists) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "runtime volume not found: %s", name);
		free(volume_path);
		return -1;
	}

	if (ensure_backup_layout(BACKUP_KIND_VOLUME, true, err) != 0) {
		free(volume_path);
		return -1;
	}

	if (backup_timestamp(timestamp, err) != 0) {
		free(volume_path);
		return -1;
	}

	backup_dir = NULL;
	archive_path = NULL;
	if (backup_dir_for_kind(BACKUP_KIND_VOLUME, &backup_dir, err) != 0) {
		free(volume_path);
		return -1;
	}

	archive_path = cellman_xasprintf(NULL, "%s/%s_%s.tar.gz", backup_dir,
	    name, timestamp);
	free(backup_dir);
	if (archive_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		free(volume_path);
		return -1;
	}

	if (access(archive_path, F_OK) == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "backup archive already exists: %s", archive_path);
		free(archive_path);
		free(volume_path);
		return -1;
	}

	if (cellman_exec_run((const char *const[]){ "tar", "-czpf", archive_path,
	    "-C", volume_path, ".", NULL }, err) != 0) {
		(void)unlink(archive_path);
		free(archive_path);
		free(volume_path);
		return -1;
	}

	free(volume_path);
	(void)cellman_payload_printf("Created volume backup %s\n", archive_path);
	free(archive_path);
	return 0;
}

int
cellman_backup_volume_query(const char *name,
    struct cellman_backup_record_list *out, char **err)
{
	struct backup_entry_list entries;
	int rc;

	if (out == NULL)
		return -1;
	out->items = NULL;
	out->len = 0;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid volume name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	if (collect_archives(BACKUP_KIND_VOLUME, name, &entries, err) != 0)
		return -1;

	rc = backup_record_list_from_entries(&entries, out, err);
	backup_entry_list_free(&entries);
	return rc;
}

/*
 * List volume backup archives in table or TSV form.
 */
int
cellman_backup_volume_list(const char *name, bool tsv, bool no_header,
    char **err)
{
	struct backup_entry_list entries;
	size_t i;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid volume name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	if (!tsv && no_header) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "-H requires -T");
		return -1;
	}

	if (collect_archives(BACKUP_KIND_VOLUME, name, &entries, err) != 0)
		return -1;

	if (tsv) {
		if (!no_header)
			(void)cellman_payload_printf("volume\ttimestamp\tsize\tarchive\n");
		for (i = 0; i < entries.len; i++) {
			(void)cellman_payload_printf("%s\t%s\t%lld\t%s\n", name,
			    entries.items[i].timestamp,
			    (long long)entries.items[i].size,
			    entries.items[i].archive_path);
		}
	} else {
		(void)cellman_payload_printf("%-24s %-14s %-12s %s\n",
		    "VOLUME", "TIMESTAMP", "SIZE", "ARCHIVE");
		for (i = 0; i < entries.len; i++) {
			(void)cellman_payload_printf("%-24s %-14s %-12lld %s\n", name,
			    entries.items[i].timestamp,
			    (long long)entries.items[i].size,
			    entries.items[i].archive_path);
		}
	}

	backup_entry_list_free(&entries);
	return 0;
}

/*
 * Restore volume runtime contents from a backup archive.
 */
int
cellman_backup_volume_restore(const char *name, const char *archive_arg,
    bool latest, bool yes, char **err)
{
	char *archive_path;
	char *volume_path;
	bool mounted;
	char *restore_tmp;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid volume name: %s",
			    name != NULL ? name : "");
		return -1;
	}
	if (latest && archive_arg != NULL && archive_arg[0] != '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "volume backup restore: --latest cannot be combined with explicit archive path");
		return -1;
	}
	if (!yes) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "volume backup restore requires --yes in runtime mode");
		return -1;
	}
	if (require_root(err) != 0)
		return -1;

	archive_path = NULL;
	volume_path = NULL;
	restore_tmp = NULL;

	if (resolve_archive(BACKUP_KIND_VOLUME, name, archive_arg, latest,
	    &archive_path, err) != 0)
		goto fail;
	if (validate_archive_path(BACKUP_KIND_VOLUME, name, archive_path,
	    "restore", err) != 0)
		goto fail;

	if (cellman_volume_path(name, &volume_path, err) != 0)
		goto fail;

	if (cellman_is_path_mounted(volume_path, &mounted, err) != 0)
		goto fail;
	if (mounted) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cannot restore runtime volume %s: currently mounted", name);
		goto fail;
	}

	if (cellman_mkdir_p(volume_path, 0755, err) != 0)
		goto fail;
	if (!cellman_path_is_same_or_child(volume_path, "/var/cellman/volumes")) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "refusing to restore into unsafe volume path: %s", volume_path);
		goto fail;
	}

	if (mktemp_dir("/tmp/cellman-volume-restore", &restore_tmp, err) != 0)
		goto fail;

	if (cellman_exec_run((const char *const[]){ "tar", "-xzpf", archive_path,
	    "-C", restore_tmp, NULL }, err) != 0)
		goto fail;

	if (clear_directory_contents(volume_path, err) != 0)
		goto fail;

	{
		char *srcdot;

		srcdot = cellman_xasprintf(NULL, "%s/.", restore_tmp);
		if (srcdot == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			goto fail;
		}
		if (cellman_exec_run((const char *const[]){ "cp", "-Rp", srcdot,
		    volume_path, NULL }, err) != 0) {
			free(srcdot);
			goto fail;
		}
		free(srcdot);
	}

	(void)cellman_payload_printf("Restored volume %s from %s\n", name,
	    archive_path);

	if (restore_tmp != NULL)
		(void)remove_tree_path(restore_tmp, NULL);
	free(archive_path);
	free(volume_path);
	free(restore_tmp);
	return 0;

fail:
	if (restore_tmp != NULL)
		(void)remove_tree_path(restore_tmp, NULL);
	free(archive_path);
	free(volume_path);
	free(restore_tmp);
	return -1;
}

/*
 * Delete one volume backup archive.
 */
int
cellman_backup_volume_delete(const char *name, const char *archive_arg,
    bool latest, bool yes, char **err)
{
	char *archive_path;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid volume name: %s",
			    name != NULL ? name : "");
		return -1;
	}
	if (latest && archive_arg != NULL && archive_arg[0] != '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "volume backup delete: --latest cannot be combined with explicit archive path");
		return -1;
	}
	if (!yes) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "volume backup delete requires --yes in runtime mode");
		return -1;
	}
	if (require_root(err) != 0)
		return -1;

	archive_path = NULL;
	if (resolve_archive(BACKUP_KIND_VOLUME, name, archive_arg, latest,
	    &archive_path, err) != 0)
		return -1;
	if (validate_archive_path(BACKUP_KIND_VOLUME, name, archive_path,
	    "delete", err) != 0) {
		free(archive_path);
		return -1;
	}

	if (unlink(archive_path) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "failed to delete backup archive: %s",
			    archive_path);
		free(archive_path);
		return -1;
	}

	(void)cellman_payload_printf("Deleted volume backup %s\n", archive_path);
	free(archive_path);
	return 0;
}

/*
 * Build standard runtime paths for one cell overlay.
 */
static int
cell_overlay_paths(const char *name, char **cell_dir, char **overlay_dir,
    char **root_overlay, char **err)
{
	if (cell_dir != NULL)
		*cell_dir = NULL;
	if (overlay_dir != NULL)
		*overlay_dir = NULL;
	if (root_overlay != NULL)
		*root_overlay = NULL;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	if (cell_dir != NULL) {
		*cell_dir = cellman_xasprintf(NULL, "/var/cellman/cells/%s", name);
		if (*cell_dir == NULL)
			goto oom;
	}

	if (overlay_dir != NULL) {
		*overlay_dir = cellman_xasprintf(NULL, "/var/cellman/cells/%s/overlay",
		    name);
		if (*overlay_dir == NULL)
			goto oom;
	}

	if (root_overlay != NULL) {
		*root_overlay = cellman_xasprintf(NULL,
		    "/var/cellman/cells/%s/root/.overlay", name);
		if (*root_overlay == NULL)
			goto oom;
	}

	return 0;

oom:
	if (err != NULL)
		*err = cellman_xasprintf(NULL, "out of memory");
	free(*cell_dir);
	free(*overlay_dir);
	free(*root_overlay);
	if (cell_dir != NULL)
		*cell_dir = NULL;
	if (overlay_dir != NULL)
		*overlay_dir = NULL;
	if (root_overlay != NULL)
		*root_overlay = NULL;
	return -1;
}

/*
 * Create an overlay backup archive.
 */
int
cellman_backup_cell_create(const char *name, char **err)
{
	char *cell_dir;
	char *overlay_dir;
	char *root_overlay;
	bool running;
	bool mounted;
	char *backup_dir;
	char timestamp[15];
	char *archive_path;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}
	if (require_root(err) != 0)
		return -1;

	cell_dir = NULL;
	overlay_dir = NULL;
	root_overlay = NULL;
	backup_dir = NULL;
	archive_path = NULL;

	if (cell_overlay_paths(name, &cell_dir, &overlay_dir, &root_overlay,
	    err) != 0)
		goto fail;

	if (access(overlay_dir, F_OK) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "runtime overlay not found: %s", name);
		goto fail;
	}

	if (is_cell_running(name, &running, err) != 0)
		goto fail;
	if (cellman_is_path_mounted(root_overlay, &mounted, err) != 0)
		goto fail;
	if (running || mounted) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cannot backup overlay %s: cell is running or overlay is mounted",
			    name);
		goto fail;
	}

	if (ensure_backup_layout(BACKUP_KIND_OVERLAY, true, err) != 0)
		goto fail;
	if (backup_timestamp(timestamp, err) != 0)
		goto fail;
	if (backup_dir_for_kind(BACKUP_KIND_OVERLAY, &backup_dir, err) != 0)
		goto fail;

	archive_path = cellman_xasprintf(NULL, "%s/%s_%s.tar.gz", backup_dir,
	    name, timestamp);
	if (archive_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}
	if (access(archive_path, F_OK) == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "backup archive already exists: %s", archive_path);
		goto fail;
	}

	if (cellman_exec_run((const char *const[]){ "tar", "-czpf", archive_path,
	    "-C", overlay_dir, ".", NULL }, err) != 0) {
		(void)unlink(archive_path);
		goto fail;
	}

	(void)cellman_payload_printf("Created overlay backup %s\n", archive_path);

	free(cell_dir);
	free(overlay_dir);
	free(root_overlay);
	free(backup_dir);
	free(archive_path);
	return 0;

fail:
	free(cell_dir);
	free(overlay_dir);
	free(root_overlay);
	free(backup_dir);
	free(archive_path);
	return -1;
}

int
cellman_backup_cell_query(const char *name,
    struct cellman_backup_record_list *out, char **err)
{
	struct backup_entry_list entries;
	int rc;

	if (out == NULL)
		return -1;
	out->items = NULL;
	out->len = 0;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	if (collect_archives(BACKUP_KIND_OVERLAY, name, &entries, err) != 0)
		return -1;

	rc = backup_record_list_from_entries(&entries, out, err);
	backup_entry_list_free(&entries);
	return rc;
}

/*
 * List overlay backup archives for one cell.
 */
int
cellman_backup_cell_list(const char *name, bool tsv, bool no_header, char **err)
{
	struct backup_entry_list entries;
	size_t i;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}
	if (!tsv && no_header) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "-H requires -T");
		return -1;
	}

	if (collect_archives(BACKUP_KIND_OVERLAY, name, &entries, err) != 0)
		return -1;

	if (tsv) {
		if (!no_header)
			(void)cellman_payload_printf("cell\ttimestamp\tsize\tarchive\n");
		for (i = 0; i < entries.len; i++) {
			(void)cellman_payload_printf("%s\t%s\t%lld\t%s\n", name,
			    entries.items[i].timestamp,
			    (long long)entries.items[i].size,
			    entries.items[i].archive_path);
		}
	} else {
		(void)cellman_payload_printf("%-24s %-14s %-12s %s\n",
		    "CELL", "TIMESTAMP", "SIZE", "ARCHIVE");
		for (i = 0; i < entries.len; i++) {
			(void)cellman_payload_printf("%-24s %-14s %-12lld %s\n", name,
			    entries.items[i].timestamp,
			    (long long)entries.items[i].size,
			    entries.items[i].archive_path);
		}
	}

	backup_entry_list_free(&entries);
	return 0;
}

/*
 * Restore overlay contents from backup archive.
 */
int
cellman_backup_cell_restore(const char *name, const char *archive_arg,
    bool latest, bool yes, char **err)
{
	char *archive_path;
	char *cell_dir;
	char *overlay_dir;
	char *root_overlay;
	bool running;
	bool mounted;
	char *restore_tmp;
	char *srcdot;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}
	if (latest && archive_arg != NULL && archive_arg[0] != '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cell backup restore: --latest cannot be combined with explicit archive path");
		return -1;
	}
	if (!yes) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cell backup restore requires --yes in runtime mode");
		return -1;
	}
	if (require_root(err) != 0)
		return -1;

	archive_path = NULL;
	cell_dir = NULL;
	overlay_dir = NULL;
	root_overlay = NULL;
	restore_tmp = NULL;
	srcdot = NULL;

	if (resolve_archive(BACKUP_KIND_OVERLAY, name, archive_arg, latest,
	    &archive_path, err) != 0)
		goto fail;
	if (validate_archive_path(BACKUP_KIND_OVERLAY, name, archive_path,
	    "restore", err) != 0)
		goto fail;

	if (cell_overlay_paths(name, &cell_dir, &overlay_dir, &root_overlay,
	    err) != 0)
		goto fail;

	if (is_cell_running(name, &running, err) != 0)
		goto fail;
	if (cellman_is_path_mounted(root_overlay, &mounted, err) != 0)
		goto fail;
	if (running || mounted) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cannot restore overlay %s: cell is running or overlay is mounted",
			    name);
		goto fail;
	}

	if (cellman_mkdir_p(cell_dir, 0755, err) != 0 ||
	    cellman_mkdir_p(overlay_dir, 0755, err) != 0)
		goto fail;
	if (!cellman_path_is_same_or_child(overlay_dir, "/var/cellman/cells")) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "refusing to restore into unsafe overlay path: %s", overlay_dir);
		goto fail;
	}

	if (mktemp_dir("/tmp/cellman-overlay-restore", &restore_tmp, err) != 0)
		goto fail;
	if (cellman_exec_run((const char *const[]){ "tar", "-xzpf", archive_path,
	    "-C", restore_tmp, NULL }, err) != 0)
		goto fail;

	if (clear_directory_contents(overlay_dir, err) != 0)
		goto fail;

	srcdot = cellman_xasprintf(NULL, "%s/.", restore_tmp);
	if (srcdot == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}
	if (cellman_exec_run((const char *const[]){ "cp", "-Rp", srcdot,
	    overlay_dir, NULL }, err) != 0)
		goto fail;

	(void)cellman_payload_printf("Restored overlay %s from %s\n", name,
	    archive_path);

	if (restore_tmp != NULL)
		(void)remove_tree_path(restore_tmp, NULL);
	free(archive_path);
	free(cell_dir);
	free(overlay_dir);
	free(root_overlay);
	free(restore_tmp);
	free(srcdot);
	return 0;

fail:
	if (restore_tmp != NULL)
		(void)remove_tree_path(restore_tmp, NULL);
	free(archive_path);
	free(cell_dir);
	free(overlay_dir);
	free(root_overlay);
	free(restore_tmp);
	free(srcdot);
	return -1;
}

/*
 * Delete one overlay backup archive.
 */
int
cellman_backup_cell_delete(const char *name, const char *archive_arg,
    bool latest, bool yes, char **err)
{
	char *archive_path;

	if (!resource_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}
	if (latest && archive_arg != NULL && archive_arg[0] != '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cell backup delete: --latest cannot be combined with explicit archive path");
		return -1;
	}
	if (!yes) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cell backup delete requires --yes in runtime mode");
		return -1;
	}
	if (require_root(err) != 0)
		return -1;

	archive_path = NULL;
	if (resolve_archive(BACKUP_KIND_OVERLAY, name, archive_arg, latest,
	    &archive_path, err) != 0)
		return -1;
	if (validate_archive_path(BACKUP_KIND_OVERLAY, name, archive_path,
	    "delete", err) != 0) {
		free(archive_path);
		return -1;
	}

	if (unlink(archive_path) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "failed to delete backup archive: %s",
			    archive_path);
		free(archive_path);
		return -1;
	}

	(void)cellman_payload_printf("Deleted overlay backup %s\n", archive_path);
	free(archive_path);
	return 0;
}
