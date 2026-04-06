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
 * Layer: cellman desired-state assembly layer.
 *
 * Discover DSL files, enforce deterministic ordering, and assemble state
 * collections for cells/volumes/applies.
 *
 * Extension guidance: Add desired-state loading/validation behavior here; keep
 * runtime reconciliation in backend apply/lifecycle modules.
 */

#include "cellman.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void
doc_list_free(struct cellman_doc_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++)
		cellman_doc_free(&list->items[i]);
	free(list->items);
	list->items = NULL;
	list->len = 0;
	list->cap = 0;
}

static bool
doc_name_valid(const char *name)
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

static bool
path_has_lua_suffix(const char *path)
{
	size_t len;

	if (path == NULL)
		return false;

	len = strlen(path);
	if (len < 4)
		return false;

	return strcmp(path + len - 4, ".lua") == 0;
}

static int
compare_cstr_ptr(const void *a, const void *b)
{
	const char *const *ap = a;
	const char *const *bp = b;

	return strcmp(*ap, *bp);
}

static int
doc_list_append_move(struct cellman_doc_list *list, struct cellman_doc *doc,
    char **err)
{
	size_t new_cap;
	struct cellman_doc *new_items;

	if (list == NULL || doc == NULL)
		return -1;

	if (list->len == list->cap) {
		if (list->cap > SIZE_MAX / 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "document list capacity overflow");
			return -1;
		}
		new_cap = (list->cap == 0) ? 8 : list->cap * 2;
		if (new_cap > SIZE_MAX / sizeof(*new_items)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "document list size overflow");
			return -1;
		}
		new_items = realloc(list->items, new_cap * sizeof(*new_items));
		if (new_items == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return -1;
		}
		list->items = new_items;
		list->cap = new_cap;
	}

	list->items[list->len++] = *doc;
	cellman_doc_init(doc);
	return 0;
}

static const struct cellman_doc *
doc_list_find_name(const struct cellman_doc_list *list, const char *name)
{
	size_t i;
	const char *doc_name;

	if (list == NULL || name == NULL)
		return NULL;

	for (i = 0; i < list->len; i++) {
		switch (list->items[i].kind) {
		case CELLMAN_DOC_CELL:
			doc_name = list->items[i].u.cell.name;
			break;
		case CELLMAN_DOC_VOLUME:
			doc_name = list->items[i].u.volume.name;
			break;
		case CELLMAN_DOC_APPLY:
			doc_name = list->items[i].u.apply.name;
			break;
		case CELLMAN_DOC_NONE:
		default:
			doc_name = NULL;
			break;
		}

		if (doc_name != NULL && strcmp(doc_name, name) == 0)
			return &list->items[i];
	}

	return NULL;
}

static const char *
doc_name_for_kind(const struct cellman_doc *doc)
{
	if (doc == NULL)
		return NULL;

	switch (doc->kind) {
	case CELLMAN_DOC_CELL:
		return doc->u.cell.name;
	case CELLMAN_DOC_VOLUME:
		return doc->u.volume.name;
	case CELLMAN_DOC_APPLY:
		return doc->u.apply.name;
	case CELLMAN_DOC_NONE:
	default:
		break;
	}

	return NULL;
}

static struct cellman_doc_list *
state_list_for_kind(struct cellman_state *state, enum cellman_doc_kind kind)
{
	if (state == NULL)
		return NULL;

	switch (kind) {
	case CELLMAN_DOC_CELL:
		return &state->cells;
	case CELLMAN_DOC_VOLUME:
		return &state->volumes;
	case CELLMAN_DOC_APPLY:
		return &state->applies;
	case CELLMAN_DOC_NONE:
	default:
		break;
	}

	return NULL;
}

static int
collect_lua_files(const char *dir, struct cellman_string_list *files, char **err)
{
	DIR *dp;
	struct dirent *de;

	dp = opendir(dir);
	if (dp == NULL) {
		if (errno == ENOENT)
			return 0;
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot open %s: %s", dir,
			    strerror(errno));
		return -1;
	}

	while ((de = readdir(dp)) != NULL) {
		char *path;
		struct stat st;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (!path_has_lua_suffix(de->d_name))
			continue;

		path = cellman_path_join(dir, de->d_name, err);
		if (path == NULL) {
			(void)closedir(dp);
			return -1;
		}

		if (stat(path, &st) == -1) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cannot stat %s: %s", path,
				    strerror(errno));
			free(path);
			(void)closedir(dp);
			return -1;
		}

		if (S_ISREG(st.st_mode)) {
			if (cellman_string_list_add(files, path, err) != 0) {
				free(path);
				(void)closedir(dp);
				return -1;
			}
		}

		free(path);
	}

	(void)closedir(dp);

	if (files->len > 1) {
		qsort(files->items, files->len, sizeof(files->items[0]),
		    compare_cstr_ptr);
	}

	return 0;
}

void
cellman_state_init(struct cellman_state *state)
{
	if (state == NULL)
		return;
	memset(state, 0, sizeof(*state));
}

void
cellman_state_free(struct cellman_state *state)
{
	if (state == NULL)
		return;

	doc_list_free(&state->cells);
	doc_list_free(&state->volumes);
	doc_list_free(&state->applies);
}

int
cellman_state_load_dir(const char *dir, struct cellman_state *state, char **err)
{
	struct cellman_string_list files;
	size_t i;
	int rc;

	if (err != NULL)
		*err = NULL;

	if (dir == NULL || dir[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "dsl directory path is empty");
		return -1;
	}

	if (state == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "internal error: state is NULL");
		return -1;
	}

	cellman_state_free(state);
	cellman_state_init(state);
	memset(&files, 0, sizeof(files));

	if (collect_lua_files(dir, &files, err) != 0)
		goto fail;

	for (i = 0; i < files.len; i++) {
		struct cellman_doc_list docs;
		size_t j;
		char *load_err;

		memset(&docs, 0, sizeof(docs));
		load_err = NULL;

		rc = cellman_dsl_load_file_all(files.items[i], &docs, &load_err);
		if (rc != 0) {
			if (err != NULL) {
				*err = cellman_xasprintf(NULL, "failed to load %s: %s",
				    files.items[i], load_err != NULL ? load_err :
				    "unknown error");
			}
			free(load_err);
			goto fail;
		}

		for (j = 0; j < docs.len; j++) {
			struct cellman_doc *doc;
			struct cellman_doc_list *list;
			const struct cellman_doc *dup;
			const char *name;

			doc = &docs.items[j];
			name = doc_name_for_kind(doc);
			if (!doc_name_valid(name)) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "%s: invalid %s name '%s' (allowed: A-Za-z0-9._-)",
					    files.items[i], cellman_doc_kind_name(doc->kind),
					    name != NULL ? name : "");
				doc_list_free(&docs);
				goto fail;
			}

			list = state_list_for_kind(state, doc->kind);
			if (list == NULL) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "%s: unsupported document kind", files.items[i]);
				doc_list_free(&docs);
				goto fail;
			}

			dup = doc_list_find_name(list, name);
			if (dup != NULL) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "%s: duplicate %s '%s' (already defined in %s)",
					    files.items[i], cellman_doc_kind_name(doc->kind),
					    name,
					    dup->source_path != NULL ? dup->source_path : "unknown");
				doc_list_free(&docs);
				goto fail;
			}

			if (doc_list_append_move(list, doc, err) != 0) {
				doc_list_free(&docs);
				goto fail;
			}
		}

		doc_list_free(&docs);
	}

	cellman_string_list_free(&files);
	return 0;

fail:
	cellman_string_list_free(&files);
	cellman_state_free(state);
	return -1;
}
