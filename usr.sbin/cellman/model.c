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
 * Layer: cellman IR model layer.
 *
 * Implement initialization, ownership, copy/move, and debug dump helpers for
 * IR documents.
 *
 * Extension guidance: Add IR lifecycle behavior here; keep DSL parsing and
 * execution logic in their dedicated layers.
 */

#include "cellman.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static bool
grow_action_array(struct cellman_action_list *list, size_t want, char **err)
{
	size_t new_cap;
	struct cellman_action *new_items;

	if (list->cap >= want)
		return true;

	new_cap = (list->cap == 0) ? 8 : list->cap;
	while (new_cap < want) {
		if (new_cap > SIZE_MAX / 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "action list capacity overflow");
			return false;
		}
		new_cap *= 2;
	}

	if (new_cap > SIZE_MAX / sizeof(*new_items)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "action list size overflow");
		return false;
	}

	new_items = realloc(list->items, new_cap * sizeof(*new_items));
	if (new_items == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return false;
	}

	list->items = new_items;
	list->cap = new_cap;
	return true;
}

static void
cellman_action_free(struct cellman_action *action)
{
	if (action == NULL)
		return;

	switch (action->kind) {
	case CELLMAN_ACTION_PKG:
		cellman_string_list_free(&action->u.pkg.packages);
		break;
	case CELLMAN_ACTION_EXEC:
		free(action->u.exec.command);
		break;
	case CELLMAN_ACTION_DIR:
		free(action->u.dir.path);
		free(action->u.dir.mode);
		free(action->u.dir.owner);
		free(action->u.dir.group);
		break;
	case CELLMAN_ACTION_LINE:
		free(action->u.line.path);
		free(action->u.line.text);
		break;
	case CELLMAN_ACTION_SYMLINK:
		free(action->u.symlink.target);
		free(action->u.symlink.linkpath);
		break;
	case CELLMAN_ACTION_COPY:
		free(action->u.copy.source);
		free(action->u.copy.target);
		free(action->u.copy.mode);
		free(action->u.copy.owner);
		free(action->u.copy.group);
		break;
	case CELLMAN_ACTION_UNTAR:
		free(action->u.untar.source);
		free(action->u.untar.target);
		break;
	case CELLMAN_ACTION_FILE:
		free(action->u.file.path);
		free(action->u.file.content);
		free(action->u.file.mode);
		free(action->u.file.owner);
		free(action->u.file.group);
		break;
	case CELLMAN_ACTION_PATCH:
		free(action->u.patch.path);
		free(action->u.patch.content);
		break;
	case CELLMAN_ACTION_TEMPLATE:
		free(action->u.templ.source);
		free(action->u.templ.target);
		free(action->u.templ.mode);
		free(action->u.templ.owner);
		free(action->u.templ.group);
		free(action->u.templ.tokens_text);
		cellman_kv_list_free(&action->u.templ.tokens);
		cellman_kv_list_free(&action->u.templ.token_env);
		break;
	case CELLMAN_ACTION_SCRIPT:
		free(action->u.script.path);
		free(action->u.script.cwd);
		cellman_string_list_free(&action->u.script.args);
		cellman_kv_list_free(&action->u.script.env);
		break;
	case CELLMAN_ACTION_NONE:
	default:
		break;
	}

	memset(action, 0, sizeof(*action));
}

void
cellman_doc_init(struct cellman_doc *doc)
{
	memset(doc, 0, sizeof(*doc));
	doc->kind = CELLMAN_DOC_NONE;
}

static void
cellman_cell_doc_free(struct cellman_cell_doc *cell)
{
	free(cell->name);
	free(cell->profile);
	free(cell->reserved_ports);
	free(cell->rlimit_nofile);
	free(cell->rlimit_as);
	free(cell->rlimit_core);
	free(cell->supervise_cmd);
	free(cell->supervise_run_as);
	free(cell->supervise_log_facility);
	free(cell->supervise_stdout_level);
	free(cell->supervise_stderr_level);
	free(cell->supervise_log_tag);
	free(cell->healthcheck_cmd);
	cellman_string_list_free(&cell->depends_on);
	cellman_string_list_free(&cell->mounts);
}

static void
cellman_volume_doc_free(struct cellman_volume_doc *volume)
{
	free(volume->name);
	free(volume->mode);
}

static void
cellman_apply_doc_free(struct cellman_apply_doc *apply)
{
	size_t i;

	free(apply->name);
	for (i = 0; i < apply->actions.len; i++)
		cellman_action_free(&apply->actions.items[i]);
	free(apply->actions.items);
	apply->actions.items = NULL;
	apply->actions.len = 0;
	apply->actions.cap = 0;
}

void
cellman_doc_free(struct cellman_doc *doc)
{
	if (doc == NULL)
		return;

	free(doc->source_path);
	free(doc->source_dir);
	doc->source_path = NULL;
	doc->source_dir = NULL;

	switch (doc->kind) {
	case CELLMAN_DOC_CELL:
		cellman_cell_doc_free(&doc->u.cell);
		break;
	case CELLMAN_DOC_VOLUME:
		cellman_volume_doc_free(&doc->u.volume);
		break;
	case CELLMAN_DOC_APPLY:
		cellman_apply_doc_free(&doc->u.apply);
		break;
	case CELLMAN_DOC_NONE:
	default:
		break;
	}

	cellman_doc_init(doc);
}

int
cellman_doc_set_source(struct cellman_doc *doc, const char *path, char **err)
{
	char *path_copy;
	char *dir_copy;

	path_copy = cellman_strdup(path, err);
	if (path_copy == NULL)
		return -1;

	dir_copy = cellman_dirname_dup(path, err);
	if (dir_copy == NULL) {
		free(path_copy);
		return -1;
	}

	free(doc->source_path);
	free(doc->source_dir);
	doc->source_path = path_copy;
	doc->source_dir = dir_copy;
	return 0;
}

const char *
cellman_doc_kind_name(enum cellman_doc_kind kind)
{
	switch (kind) {
	case CELLMAN_DOC_CELL:
		return "cell";
	case CELLMAN_DOC_VOLUME:
		return "volume";
	case CELLMAN_DOC_APPLY:
		return "apply";
	case CELLMAN_DOC_NONE:
	default:
		return "none";
	}
}

const char *
cellman_action_kind_name(enum cellman_action_kind kind)
{
	switch (kind) {
	case CELLMAN_ACTION_PKG:
		return "pkg";
	case CELLMAN_ACTION_EXEC:
		return "exec";
	case CELLMAN_ACTION_DIR:
		return "dir";
	case CELLMAN_ACTION_LINE:
		return "line";
	case CELLMAN_ACTION_SYMLINK:
		return "symlink";
	case CELLMAN_ACTION_COPY:
		return "copy";
	case CELLMAN_ACTION_UNTAR:
		return "untar";
	case CELLMAN_ACTION_FILE:
		return "file";
	case CELLMAN_ACTION_PATCH:
		return "patch";
	case CELLMAN_ACTION_TEMPLATE:
		return "template";
	case CELLMAN_ACTION_SCRIPT:
		return "script";
	case CELLMAN_ACTION_NONE:
	default:
		return "none";
	}
}

int
cellman_action_list_append_move(struct cellman_action_list *list,
    struct cellman_action *action, char **err)
{
	if (list == NULL || action == NULL)
		return -1;

	if (!grow_action_array(list, list->len + 1, err))
		return -1;

	list->items[list->len++] = *action;
	memset(action, 0, sizeof(*action));
	return 0;
}

void
cellman_tokens_init(struct cellman_tokens *tokens)
{
	if (tokens == NULL)
		return;
	memset(tokens, 0, sizeof(*tokens));
}

void
cellman_tokens_free(struct cellman_tokens *tokens)
{
	if (tokens == NULL)
		return;
	cellman_kv_list_free(&tokens->pairs);
}

int
cellman_tokens_set(struct cellman_tokens *tokens, const char *name,
    const char *value, char **err)
{
	size_t i;
	char *new_value;

	if (tokens == NULL || name == NULL)
		return -1;

	for (i = 0; i < tokens->pairs.len; i++) {
		if (strcmp(tokens->pairs.items[i].key, name) == 0) {
			new_value = cellman_strdup(value, err);
			if (new_value == NULL)
				return -1;
			free(tokens->pairs.items[i].value);
			tokens->pairs.items[i].value = new_value;
			return 0;
		}
	}

	return cellman_kv_list_add(&tokens->pairs, name, value, err);
}

const char *
cellman_tokens_get(const struct cellman_tokens *tokens, const char *name)
{
	if (tokens == NULL)
		return NULL;
	return cellman_kv_list_get(&tokens->pairs, name);
}

static void
dump_string_list(FILE *out, const char *key, const struct cellman_string_list *l)
{
	size_t i;

	(void)fprintf(out, "%s=", key);
	for (i = 0; i < l->len; i++) {
		if (i != 0)
			(void)fputs(",", out);
		(void)fputs(l->items[i], out);
	}
	(void)fputc('\n', out);
}

void
cellman_doc_dump(FILE *out, const struct cellman_doc *doc)
{
	size_t i;

	if (out == NULL || doc == NULL)
		return;

	(void)fprintf(out, "kind=%s\n", cellman_doc_kind_name(doc->kind));
	(void)fprintf(out, "source=%s\n",
	    doc->source_path != NULL ? doc->source_path : "");

	switch (doc->kind) {
	case CELLMAN_DOC_CELL:
		(void)fprintf(out, "name=%s\n", doc->u.cell.name);
		(void)fprintf(out, "autostart=%s\n",
		    doc->u.cell.autostart_set ?
		    (doc->u.cell.autostart ? "YES" : "NO") : "(unset)");
		(void)fprintf(out, "supervise_cmd=%s\n",
		    doc->u.cell.supervise_cmd != NULL ? doc->u.cell.supervise_cmd : "");
		dump_string_list(out, "depends_on", &doc->u.cell.depends_on);
		dump_string_list(out, "mounts", &doc->u.cell.mounts);
		break;
	case CELLMAN_DOC_VOLUME:
		(void)fprintf(out, "name=%s\n", doc->u.volume.name);
		(void)fprintf(out, "mode=%s\n",
		    doc->u.volume.mode != NULL ? doc->u.volume.mode : "");
		break;
	case CELLMAN_DOC_APPLY:
		(void)fprintf(out, "name=%s\n", doc->u.apply.name);
		(void)fprintf(out, "actions=%zu\n", doc->u.apply.actions.len);
		for (i = 0; i < doc->u.apply.actions.len; i++) {
			(void)fprintf(out, "action[%zu]=%s\n", i,
			    cellman_action_kind_name(doc->u.apply.actions.items[i].kind));
		}
		break;
	case CELLMAN_DOC_NONE:
	default:
		break;
	}
}
