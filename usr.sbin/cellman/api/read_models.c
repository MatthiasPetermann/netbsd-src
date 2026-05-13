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
 * Layer: cellman API read-model layer.
 *
 * Build read-model responses used by API consumers for cell and volume
 * projections.
 *
 * Extension guidance: Extend read-model payload shape here; keep raw snapshot
 * collection in command runtime snapshot modules.
 */

#include "cmd_internal.h"
#include "../commands/command_backend_internal.h"

#include <stdlib.h>
#include <string.h>

enum {
	CELL_COL_NAME = 0,
	CELL_COL_RUNNING = 1,
	CELL_COL_STATE = 2,
	CELL_COL_CID = 3,
	CELL_COL_REFS = 4,
	CELL_COL_PROCS = 5,
	CELL_COL_CPU1S = 6,
	CELL_COL_CPU10S = 7,
	CELL_COL_MEMORY = 8,
	CELL_COL_AGE = 9,
	CELL_COL_ROOT = 10,
	CELL_COL_AUTOSTART = 11,
	CELL_COL_PROFILE = 12,
	CELL_COL_RESERVED_PORTS = 13,
	CELL_COL_RLIMIT_NOFILE = 14,
	CELL_COL_RLIMIT_AS = 15,
	CELL_COL_RLIMIT_CORE = 16,
	CELL_COL_SUPERVISE_CMD = 19,
};

enum {
	VOL_COL_NAME = 0,
	VOL_COL_STATE = 1,
	VOL_COL_MODE = 2,
	VOL_COL_PATH = 3,
	VOL_COL_MOUNTED = 4,
	VOL_COL_REFS = 5,
	VOL_COL_USED_BY = 6,
};

static int	copy_string(char **, const char *, char **);
static bool	parse_bool_text(const char *, bool *);
static bool	cell_state_manifest_present(const char *, bool *);
static bool	volume_state_manifest_present(const char *, bool *);
static bool	volume_state_runtime_present(const char *, bool *);
static int	overlay_path_from_root(const char *, char **, char **);
static void	free_cell_row(struct cellman_api_cell_row *);
static void	free_storage_row(struct cellman_api_storage_row *);
static void	free_backup_row(struct cellman_api_backup_row *);
static int	compare_storage_rows(const void *, const void *);

static int
copy_string(char **dst, const char *src, char **err)
{
	char *copy;

	if (dst == NULL)
		return -1;

	copy = cellman_strdup(src != NULL ? src : "", err);
	if (copy == NULL)
		return -1;

	*dst = copy;
	return 0;
}

static bool
parse_bool_text(const char *value, bool *out)
{
	if (out == NULL)
		return false;

	if (value == NULL || value[0] == '\0') {
		*out = false;
		return true;
	}
	if (strcmp(value, "1") == 0 || strcmp(value, "YES") == 0 ||
	    strcmp(value, "yes") == 0 || strcmp(value, "true") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(value, "0") == 0 || strcmp(value, "NO") == 0 ||
	    strcmp(value, "no") == 0 || strcmp(value, "false") == 0) {
		*out = false;
		return true;
	}

	return false;
}

static bool
cell_state_manifest_present(const char *state, bool *out)
{
	if (state == NULL || out == NULL)
		return false;

	if (strcmp(state, "managed") == 0 || strcmp(state, "parked") == 0 ||
	    strcmp(state, "pending") == 0 || strcmp(state, "declared") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(state, "orphaned") == 0 || strcmp(state, "absent") == 0) {
		*out = false;
		return true;
	}

	return false;
}

static bool
volume_state_manifest_present(const char *state, bool *out)
{
	if (state == NULL || out == NULL)
		return false;

	if (strcmp(state, "managed") == 0 || strcmp(state, "pending") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(state, "orphaned") == 0 || strcmp(state, "absent") == 0) {
		*out = false;
		return true;
	}

	return false;
}

static bool
volume_state_runtime_present(const char *state, bool *out)
{
	if (state == NULL || out == NULL)
		return false;

	if (strcmp(state, "managed") == 0 || strcmp(state, "orphaned") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(state, "pending") == 0 || strcmp(state, "absent") == 0) {
		*out = false;
		return true;
	}

	return false;
}

static int
overlay_path_from_root(const char *root, char **path_out, char **err)
{
	const char *path;
	size_t len;

	if (path_out == NULL)
		return -1;
	*path_out = NULL;

	path = root != NULL ? root : "";
	if (path[0] == '\0' || strcmp(path, "-") == 0)
		return copy_string(path_out, "", err);

	len = strlen(path);
	if (len >= 5 && strcmp(path + len - 5, "/root") == 0) {
		*path_out = cellman_xasprintf(NULL, "%.*s/overlay", (int)(len - 5),
		    path);
	} else {
		*path_out = cellman_xasprintf(NULL, "%s/overlay", path);
	}

	if (*path_out == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	return 0;
}

static void
free_cell_row(struct cellman_api_cell_row *row)
{
	if (row == NULL)
		return;

	free(row->name);
	free(row->state);
	free(row->cid);
	free(row->refs);
	free(row->procs);
	free(row->root);
	free(row->autostart);
	free(row->profile);
	free(row->reserved_ports);
	free(row->rlimit_nofile);
	free(row->rlimit_as);
	free(row->rlimit_core);
	free(row->supervise_cmd);
	free(row->cpu1s);
	free(row->cpu10s);
	free(row->memory);
	free(row->age);
}

void
cellman_api_cell_list_free(struct cellman_api_cell_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++)
		free_cell_row(&list->items[i]);

	free(list->items);
	list->items = NULL;
	list->len = 0;
}

static void
free_storage_row(struct cellman_api_storage_row *row)
{
	if (row == NULL)
		return;

	free(row->name);
	free(row->state);
	free(row->refs);
	free(row->mode);
	free(row->path);
	free(row->used_by);
}

void
cellman_api_storage_list_free(struct cellman_api_storage_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++)
		free_storage_row(&list->items[i]);

	free(list->items);
	list->items = NULL;
	list->len = 0;
}

static void
free_backup_row(struct cellman_api_backup_row *row)
{
	if (row == NULL)
		return;

	free(row->name);
	free(row->timestamp);
	free(row->size);
	free(row->archive);
}

void
cellman_api_backup_list_free(struct cellman_api_backup_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++)
		free_backup_row(&list->items[i]);

	free(list->items);
	list->items = NULL;
	list->len = 0;
}

int
cellman_api_read_cells_merged(const struct cellman_api_options *options,
    struct cellman_api_cell_list *out, char **err)
{
	struct cellman_state state;
	struct runtime_cell_list runtime;
	struct cell_snapshot_table table;
	const char *dsl_dir;
	struct cellman_api_cell_row *items;
	size_t i;

	if (out == NULL)
		return -1;
	out->items = NULL;
	out->len = 0;

	cellman_state_init(&state);
	memset(&runtime, 0, sizeof(runtime));
	memset(&table, 0, sizeof(table));
	items = NULL;

	dsl_dir = cellman_api_effective_dsl_dir(options);
	if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
		goto fail;
	if (load_runtime_cells(&runtime, err) != 0)
		goto fail;
	if (load_runtime_stats(&runtime, err) != 0)
		goto fail;
	if (build_cell_snapshot_table(&state, &runtime, &table, err) != 0)
		goto fail;

	if (table.len == 0) {
		runtime_cell_list_free(&runtime);
		cell_snapshot_table_free(&table);
		cellman_state_free(&state);
		return 0;
	}

	items = calloc(table.len, sizeof(*items));
	if (items == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}

	for (i = 0; i < table.len; i++) {
		bool running;
		bool manifest_present;

		if (!parse_bool_text(table.items[i].cols[CELL_COL_RUNNING], &running) ||
		    !cell_state_manifest_present(table.items[i].cols[CELL_COL_STATE],
		    &manifest_present)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "invalid internal cell snapshot");
			goto fail;
		}

		items[i].running = running;
		items[i].manifest_present = manifest_present;
		if (copy_string(&items[i].name,
		    table.items[i].cols[CELL_COL_NAME], err) != 0 ||
		    copy_string(&items[i].state,
		    table.items[i].cols[CELL_COL_STATE], err) != 0 ||
		    copy_string(&items[i].cid,
		    table.items[i].cols[CELL_COL_CID], err) != 0 ||
		    copy_string(&items[i].refs,
		    table.items[i].cols[CELL_COL_REFS], err) != 0 ||
		    copy_string(&items[i].procs,
		    table.items[i].cols[CELL_COL_PROCS], err) != 0 ||
		    copy_string(&items[i].root,
		    table.items[i].cols[CELL_COL_ROOT], err) != 0 ||
		    copy_string(&items[i].autostart,
		    table.items[i].cols[CELL_COL_AUTOSTART], err) != 0 ||
		    copy_string(&items[i].profile,
		    table.items[i].cols[CELL_COL_PROFILE], err) != 0 ||
		    copy_string(&items[i].reserved_ports,
		    table.items[i].cols[CELL_COL_RESERVED_PORTS], err) != 0 ||
		    copy_string(&items[i].rlimit_nofile,
		    table.items[i].cols[CELL_COL_RLIMIT_NOFILE], err) != 0 ||
		    copy_string(&items[i].rlimit_as,
		    table.items[i].cols[CELL_COL_RLIMIT_AS], err) != 0 ||
		    copy_string(&items[i].rlimit_core,
		    table.items[i].cols[CELL_COL_RLIMIT_CORE], err) != 0 ||
		    copy_string(&items[i].supervise_cmd,
		    table.items[i].cols[CELL_COL_SUPERVISE_CMD], err) != 0 ||
		    copy_string(&items[i].cpu1s,
		    table.items[i].cols[CELL_COL_CPU1S], err) != 0 ||
		    copy_string(&items[i].cpu10s,
		    table.items[i].cols[CELL_COL_CPU10S], err) != 0 ||
		    copy_string(&items[i].memory,
		    table.items[i].cols[CELL_COL_MEMORY], err) != 0 ||
		    copy_string(&items[i].age,
		    table.items[i].cols[CELL_COL_AGE], err) != 0)
			goto fail;
	}

	out->items = items;
	out->len = table.len;

	runtime_cell_list_free(&runtime);
	cell_snapshot_table_free(&table);
	cellman_state_free(&state);
	return 0;

fail:
	if (items != NULL) {
		struct cellman_api_cell_list tmp;

		tmp.items = items;
		tmp.len = table.len;
		cellman_api_cell_list_free(&tmp);
	}
	runtime_cell_list_free(&runtime);
	cell_snapshot_table_free(&table);
	cellman_state_free(&state);
	return -1;
}

static int
compare_storage_rows(const void *a, const void *b)
{
	const struct cellman_api_storage_row *ra;
	const struct cellman_api_storage_row *rb;

	ra = a;
	rb = b;
	if (ra->kind != rb->kind)
		return (int)ra->kind - (int)rb->kind;

	return strcmp(ra->name != NULL ? ra->name : "",
	    rb->name != NULL ? rb->name : "");
}

int
cellman_api_read_storage_merged(const struct cellman_api_options *options,
    struct cellman_api_storage_list *out, char **err)
{
	struct cellman_state state;
	struct runtime_cell_list runtime;
	struct volume_snapshot_table volumes;
	struct cell_snapshot_table cells;
	const char *dsl_dir;
	struct cellman_api_storage_row *items;
	size_t total;
	size_t i;
	size_t idx;

	if (out == NULL)
		return -1;
	out->items = NULL;
	out->len = 0;

	cellman_state_init(&state);
	memset(&runtime, 0, sizeof(runtime));
	memset(&volumes, 0, sizeof(volumes));
	memset(&cells, 0, sizeof(cells));
	items = NULL;
	total = 0;

	dsl_dir = cellman_api_effective_dsl_dir(options);
	if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
		goto fail;
	if (build_volume_snapshot_table(&state, &volumes, err) != 0)
		goto fail;
	if (load_runtime_cells(&runtime, err) != 0)
		goto fail;
	if (load_runtime_stats(&runtime, err) != 0)
		goto fail;
	if (build_cell_snapshot_table(&state, &runtime, &cells, err) != 0)
		goto fail;

	total = volumes.len + cells.len;
	if (total == 0) {
		runtime_cell_list_free(&runtime);
		cell_snapshot_table_free(&cells);
		volume_snapshot_table_free(&volumes);
		cellman_state_free(&state);
		return 0;
	}

	items = calloc(total, sizeof(*items));
	if (items == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}

	idx = 0;
	for (i = 0; i < volumes.len; i++, idx++) {
		bool mounted;
		bool manifest_present;
		bool runtime_present;

		if (!parse_bool_text(volumes.items[i].cols[VOL_COL_MOUNTED],
		    &mounted) ||
		    !volume_state_manifest_present(volumes.items[i].cols[VOL_COL_STATE],
		    &manifest_present) ||
		    !volume_state_runtime_present(volumes.items[i].cols[VOL_COL_STATE],
		    &runtime_present)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid internal volume snapshot");
			goto fail;
		}

		items[idx].kind = CELLMAN_API_STORAGE_VOLUME;
		items[idx].manifest_present = manifest_present;
		items[idx].runtime_present = runtime_present;
		items[idx].mounted = mounted;
		if (copy_string(&items[idx].name, volumes.items[i].cols[VOL_COL_NAME],
		    err) != 0 ||
		    copy_string(&items[idx].state, volumes.items[i].cols[VOL_COL_STATE],
		    err) != 0 ||
		    copy_string(&items[idx].refs, volumes.items[i].cols[VOL_COL_REFS],
		    err) != 0 ||
		    copy_string(&items[idx].mode, volumes.items[i].cols[VOL_COL_MODE],
		    err) != 0 ||
		    copy_string(&items[idx].path, volumes.items[i].cols[VOL_COL_PATH],
		    err) != 0 ||
		    copy_string(&items[idx].used_by,
		    volumes.items[i].cols[VOL_COL_USED_BY], err) != 0)
			goto fail;
	}

	for (i = 0; i < cells.len; i++, idx++) {
		bool running;
		bool manifest_present;
		const char *root;

		if (!parse_bool_text(cells.items[i].cols[CELL_COL_RUNNING], &running) ||
		    !cell_state_manifest_present(cells.items[i].cols[CELL_COL_STATE],
		    &manifest_present)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid internal overlay snapshot");
			goto fail;
		}

		root = cells.items[i].cols[CELL_COL_ROOT];
		items[idx].kind = CELLMAN_API_STORAGE_OVERLAY;
		items[idx].manifest_present = manifest_present;
		items[idx].runtime_present = root != NULL && root[0] != '\0' &&
		    strcmp(root, "-") != 0;
		items[idx].mounted = running;
		if (copy_string(&items[idx].name, cells.items[i].cols[CELL_COL_NAME],
		    err) != 0 ||
		    copy_string(&items[idx].state, cells.items[i].cols[CELL_COL_STATE],
		    err) != 0 ||
		    copy_string(&items[idx].refs, "-", err) != 0 ||
		    copy_string(&items[idx].mode, "-", err) != 0 ||
		    copy_string(&items[idx].used_by,
		    cells.items[i].cols[CELL_COL_NAME], err) != 0 ||
		    overlay_path_from_root(root, &items[idx].path, err) != 0)
			goto fail;
	}

	qsort(items, total, sizeof(*items), compare_storage_rows);
	out->items = items;
	out->len = total;

	runtime_cell_list_free(&runtime);
	cell_snapshot_table_free(&cells);
	volume_snapshot_table_free(&volumes);
	cellman_state_free(&state);
	return 0;

fail:
	if (items != NULL) {
		struct cellman_api_storage_list tmp;

		tmp.items = items;
		tmp.len = total;
		cellman_api_storage_list_free(&tmp);
	}
	runtime_cell_list_free(&runtime);
	cell_snapshot_table_free(&cells);
	volume_snapshot_table_free(&volumes);
	cellman_state_free(&state);
	return -1;
}

int
cellman_api_read_backups(enum cellman_api_storage_kind kind,
    const char *name, struct cellman_api_backup_list *out, char **err)
{
	struct cellman_backup_record_list records;
	struct cellman_api_backup_row *items;
	size_t i;
	int rc;

	if (out == NULL)
		return -1;
	out->items = NULL;
	out->len = 0;
	items = NULL;

	records.items = NULL;
	records.len = 0;

	if (kind == CELLMAN_API_STORAGE_OVERLAY)
		rc = cellman_backup_cell_query(name, &records, err);
	else
		rc = cellman_backup_volume_query(name, &records, err);
	if (rc != 0)
		return -1;

	if (records.len == 0) {
		cellman_backup_record_list_free(&records);
		return 0;
	}

	items = calloc(records.len, sizeof(*items));
	if (items == NULL) {
		cellman_backup_record_list_free(&records);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	for (i = 0; i < records.len; i++) {
		if (copy_string(&items[i].name, name, err) != 0 ||
		    copy_string(&items[i].timestamp, records.items[i].timestamp,
		    err) != 0 ||
		    copy_string(&items[i].size, records.items[i].size, err) != 0 ||
		    copy_string(&items[i].archive, records.items[i].archive,
		    err) != 0) {
			struct cellman_api_backup_list tmp;

			tmp.items = items;
			tmp.len = records.len;
			cellman_api_backup_list_free(&tmp);
			cellman_backup_record_list_free(&records);
			if (err != NULL && *err == NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return -1;
		}
	}

	out->items = items;
	out->len = records.len;
	cellman_backup_record_list_free(&records);
	return 0;
}
