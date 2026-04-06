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
 * Layer: cellman runtime snapshot ingestion layer.
 *
 * Collect and normalize runtime snapshots from cellctl list/stats output into
 * backend tables.
 *
 * Extension guidance: Extend runtime snapshot parsing here; keep
 * projection/render output logic in backend read-model code.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "../cellman.h"
#include "command_backend.h"
#include "command_backend_internal.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Append one runtime row to the dynamic runtime snapshot list.
 */
static int
runtime_cell_list_add(struct runtime_cell_list *list,
    const struct runtime_cell *src, char **err)
{
	struct runtime_cell *next;

	if (list->len == list->cap) {
		size_t next_cap;

		next_cap = list->cap == 0 ? 8 : list->cap * 2;
		next = realloc(list->items, next_cap * sizeof(*next));
		if (next == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return -1;
		}
		list->items = next;
		list->cap = next_cap;
	}

	list->items[list->len] = *src;
	list->len++;
	return 0;
}

/*
 * Split one tab-separated row in place and return the parsed column count.
 */
static int
split_tsv_columns(char *line, char **cols, size_t cap)
{
	char *cur;
	char *tab;
	int i;
	int ncols;

	if (line == NULL || cols == NULL || cap == 0)
		return 0;

	for (i = 0; i < (int)cap; i++)
		cols[i] = NULL;

	cur = line;
	ncols = 1;
	for (i = 0; i < (int)cap; i++) {
		cols[i] = cur;
		tab = strchr(cur, '\t');
		if (tab == NULL)
			break;
		*tab = '\0';
		cur = tab + 1;
		ncols++;
	}

	return ncols;
}

/*
 * Free every runtime cell row and reset the list back to an empty state.
 */
void
runtime_cell_list_free(struct runtime_cell_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++) {
		free(list->items[i].cid);
		free(list->items[i].name);
		free(list->items[i].refs);
		free(list->items[i].procs);
		free(list->items[i].cpu1s);
		free(list->items[i].cpu10s);
		free(list->items[i].memory);
		free(list->items[i].age);
		free(list->items[i].root);
	}
	free(list->items);
	list->items = NULL;
	list->len = 0;
	list->cap = 0;
}

/*
 * Find one runtime row by cell name.
 */
struct runtime_cell *
runtime_cell_find(struct runtime_cell_list *list, const char *name)
{
	size_t i;

	if (list == NULL || name == NULL)
		return NULL;

	for (i = 0; i < list->len; i++) {
		if (strcmp(list->items[i].name, name) == 0)
			return &list->items[i];
	}

	return NULL;
}

/*
 * Report whether one runtime snapshot currently contains the target name.
 */
bool
runtime_cell_is_running(const struct runtime_cell_list *list, const char *name)
{
	size_t i;

	if (list == NULL || name == NULL)
		return false;

	for (i = 0; i < list->len; i++) {
		if (strcmp(list->items[i].name, name) == 0)
			return true;
	}

	return false;
}

/*
 * Load runtime cells from `cellctl list -T -H`.
 */
int
load_runtime_cells(struct runtime_cell_list *out, char **err)
{
	char *raw;
	char *line;
	char *saveptr;
	char *parse_err;

	memset(out, 0, sizeof(*out));
	raw = NULL;
	parse_err = NULL;

	if (cellman_exec_run_capture((const char *const[]){ "cellctl", "list",
	    "-T", "-H", NULL }, &raw, err) != 0) {
		if (err != NULL && *err != NULL && strstr(*err, "permission") != NULL) {
			/*
			 * Keep read commands usable for non-privileged contexts by treating
			 * inaccessible runtime state as empty snapshot.
			 */
			free(*err);
			*err = NULL;
			return 0;
		}
		return -1;
	}

	saveptr = NULL;
	line = strtok_r(raw, "\n", &saveptr);
	while (line != NULL) {
		char *cols[9];
		int ncols;
		struct runtime_cell row;

		ncols = split_tsv_columns(line, cols, 9);
		if (ncols != 6 && ncols != 9) {
			parse_err = cellman_xasprintf(NULL,
			    "runtime: unexpected TSV schema from cellctl list -T");
			free(raw);
			runtime_cell_list_free(out);
			if (err != NULL)
				*err = parse_err;
			else
				free(parse_err);
			return -1;
		}

		if (cols[0] != NULL && cols[1] != NULL) {
			memset(&row, 0, sizeof(row));
			row.cid = cellman_strdup(cols[0], err);
			row.name = cellman_strdup(cols[1], err);
			row.refs = cellman_strdup(cols[2] != NULL ? cols[2] : "", err);
			row.procs = cellman_strdup(cols[3] != NULL ? cols[3] : "", err);
			row.cpu1s = cellman_strdup("", err);
			row.cpu10s = cellman_strdup("", err);
			row.memory = cellman_strdup("", err);
			row.age = cellman_strdup(cols[4] != NULL ? cols[4] : "", err);
			row.root = cellman_strdup(cols[5] != NULL ? cols[5] : "", err);
			if (row.cid == NULL || row.name == NULL || row.refs == NULL ||
			    row.procs == NULL || row.cpu1s == NULL ||
			    row.cpu10s == NULL || row.memory == NULL ||
			    row.age == NULL || row.root == NULL) {
				free(row.cid);
				free(row.name);
				free(row.refs);
				free(row.procs);
				free(row.cpu1s);
				free(row.cpu10s);
				free(row.memory);
				free(row.age);
				free(row.root);
				free(raw);
				runtime_cell_list_free(out);
				return -1;
			}
			if (runtime_cell_list_add(out, &row, err) != 0) {
				free(row.cid);
				free(row.name);
				free(row.refs);
				free(row.procs);
				free(row.cpu1s);
				free(row.cpu10s);
				free(row.memory);
				free(row.age);
				free(row.root);
				free(raw);
				runtime_cell_list_free(out);
				return -1;
			}
		}

		line = strtok_r(NULL, "\n", &saveptr);
	}

	free(raw);
	return 0;
}

/*
 * Enrich runtime rows with counters from `cellctl stats -T -H`.
 */
int
load_runtime_stats(struct runtime_cell_list *out, char **err)
{
	char *raw;
	char *line;
	char *saveptr;

	raw = NULL;
	if (out == NULL)
		return -1;

	if (cellman_exec_run_capture((const char *const[]){ "cellctl", "stats",
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
		char *cols[9];
		int ncols;
		struct runtime_cell *row;

		ncols = split_tsv_columns(line, cols, 9);
		if (ncols != 9) {
			free(raw);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "runtime: unexpected TSV schema from cellctl stats -T");
			return -1;
		}

		row = runtime_cell_find(out, cols[1]);
		if (row != NULL) {
			char *cpu1s;
			char *cpu10s;
			char *memory;
			char *procs;
			char *refs;
			char *age;

			cpu1s = cellman_strdup(cols[2] != NULL ? cols[2] : "", err);
			cpu10s = cellman_strdup(cols[3] != NULL ? cols[3] : "", err);
			procs = cellman_strdup(cols[4] != NULL ? cols[4] : "", err);
			refs = cellman_strdup(cols[5] != NULL ? cols[5] : "", err);
			memory = cellman_strdup(cols[6] != NULL ? cols[6] : "", err);
			age = cellman_strdup(cols[7] != NULL ? cols[7] : "", err);
			if (cpu1s == NULL || cpu10s == NULL || procs == NULL ||
			    refs == NULL || memory == NULL || age == NULL) {
				free(cpu1s);
				free(cpu10s);
				free(procs);
				free(refs);
				free(memory);
				free(age);
				free(raw);
				return -1;
			}

			free(row->cpu1s);
			free(row->cpu10s);
			free(row->procs);
			free(row->refs);
			free(row->memory);
			free(row->age);
			row->cpu1s = cpu1s;
			row->cpu10s = cpu10s;
			row->procs = procs;
			row->refs = refs;
			row->memory = memory;
			row->age = age;
		}

		line = strtok_r(NULL, "\n", &saveptr);
	}

	free(raw);
	return 0;
}
