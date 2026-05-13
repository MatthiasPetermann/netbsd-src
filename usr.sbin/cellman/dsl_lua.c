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
 * Layer: cellman DSL parser layer.
 *
 * Parse Lua DSL manifests into validated in-memory IR documents and action
 * lists.
 *
 * Extension guidance: Add DSL schema extensions here; keep runtime execution
 * semantics in apply/backend modules.
 */

#include "cellman.h"

#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

struct cellman_lua_ctx {
	struct cellman_doc *doc;
	struct cellman_doc_list *docs;
	bool defined;
};

static bool parse_action_table(lua_State *, int, struct cellman_action *, char **);
static void copy_opt_field_raw(lua_State *, int, int, const char *);
static int lua_error_take(lua_State *, char *, const char *);

static void
doc_list_clear(struct cellman_doc_list *list)
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
				*err = cellman_xasprintf(NULL,
				    "document list capacity overflow");
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

static bool
token_name_valid(const char *name)
{
	size_t i;

	if (name == NULL || name[0] == '\0')
		return false;

	for (i = 0; name[i] != '\0'; i++) {
		if (!(isalnum((unsigned char)name[i]) || name[i] == '_'))
			return false;
	}

	return true;
}

static int
lua_error_take(lua_State *L, char *msg, const char *fallback)
{
	const char *text;

	text = msg != NULL ? msg : (fallback != NULL ? fallback : "lua error");
	lua_pushstring(L, text);
	free(msg);

	return lua_error(L);
}

static bool
fetch_string_field(lua_State *L, int tidx, const char *key, bool required,
    char **out, char **err)
{
	int abs_tidx;
	char *copy;

	abs_tidx = lua_absindex(L, tidx);
	lua_getfield(L, abs_tidx, key);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		if (required) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "missing required key '%s'", key);
			return false;
		}
		return true;
	}

	if (!lua_isstring(L, -1)) {
		lua_pop(L, 1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "key '%s' must be string", key);
		return false;
	}

	copy = cellman_strdup(lua_tostring(L, -1), err);
	lua_pop(L, 1);
	if (copy == NULL)
		return false;

	free(*out);
	*out = copy;
	return true;
}

static bool
fetch_bool_field(lua_State *L, int tidx, const char *key, bool *present,
    bool *value, char **err)
{
	int abs_tidx;

	abs_tidx = lua_absindex(L, tidx);
	lua_getfield(L, abs_tidx, key);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		if (present != NULL)
			*present = false;
		return true;
	}

	if (!lua_isboolean(L, -1)) {
		lua_pop(L, 1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "key '%s' must be boolean", key);
		return false;
	}

	if (present != NULL)
		*present = true;
	if (value != NULL)
		*value = lua_toboolean(L, -1);
	lua_pop(L, 1);
	return true;
}

static bool
fetch_uint_field(lua_State *L, int tidx, const char *key, bool required,
    unsigned int *value, char **err)
{
	int abs_tidx;
	lua_Integer v;
	int ok;

	abs_tidx = lua_absindex(L, tidx);
	lua_getfield(L, abs_tidx, key);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		if (required) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "missing required key '%s'", key);
			return false;
		}
		return true;
	}

	v = lua_tointegerx(L, -1, &ok);
	if (!ok || v < 0 || (uint64_t)v > UINT_MAX) {
		lua_pop(L, 1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "key '%s' must be non-negative integer", key);
		return false;
	}

	*value = (unsigned int)v;
	lua_pop(L, 1);
	return true;
}

static bool
parse_string_array(lua_State *L, int idx, struct cellman_string_list *list,
    char **err)
{
	size_t i;
	size_t n;
	int abs_idx;

	abs_idx = lua_absindex(L, idx);
	if (!lua_istable(L, abs_idx)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "expected array table");
		return false;
	}

	n = lua_rawlen(L, abs_idx);
	for (i = 1; i <= n; i++) {
		lua_rawgeti(L, abs_idx, (lua_Integer)i);
		if (!lua_isstring(L, -1)) {
			lua_pop(L, 1);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "array item %zu must be string", i);
			return false;
		}
		if (cellman_string_list_add(list, lua_tostring(L, -1), err) != 0) {
			lua_pop(L, 1);
			return false;
		}
		lua_pop(L, 1);
	}

	return true;
}

static bool
fetch_string_array_field(lua_State *L, int tidx, const char *key,
    struct cellman_string_list *list, char **err)
{
	int abs_tidx;
	bool ok;

	abs_tidx = lua_absindex(L, tidx);
	lua_getfield(L, abs_tidx, key);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return true;
	}

	ok = parse_string_array(L, -1, list, err);
	lua_pop(L, 1);
	return ok;
}

static bool
parse_env_table(lua_State *L, int idx, struct cellman_kv_list *env, char **err)
{
	int abs_idx;

	abs_idx = lua_absindex(L, idx);
	if (!lua_istable(L, abs_idx)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "env must be table");
		return false;
	}

	lua_pushnil(L);
	while (lua_next(L, abs_idx) != 0) {
		const char *k;
		const char *v;

		if (!lua_isstring(L, -2) || !lua_isstring(L, -1)) {
			lua_pop(L, 2);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "env keys and values must be strings");
			return false;
		}

		k = lua_tostring(L, -2);
		v = lua_tostring(L, -1);
		if (!cellman_env_name_valid(k)) {
			lua_pop(L, 2);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid environment variable name: %s", k);
			return false;
		}

		if (cellman_kv_list_add(env, k, v, err) != 0) {
			lua_pop(L, 2);
			return false;
		}

		lua_pop(L, 1);
	}

	return true;
}

static bool
parse_template_tokens_table(lua_State *L, int idx,
    struct cellman_kv_list *tokens, struct cellman_kv_list *token_env,
    char **err)
{
	int abs_idx;

	abs_idx = lua_absindex(L, idx);
	if (!lua_istable(L, abs_idx)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "template tokens must be table");
		return false;
	}

	lua_pushnil(L);
	while (lua_next(L, abs_idx) != 0) {
		const char *token_name;

		if (!lua_isstring(L, -2)) {
			lua_pop(L, 2);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "template token names must be strings");
			return false;
		}

		token_name = lua_tostring(L, -2);
		if (!token_name_valid(token_name)) {
			lua_pop(L, 2);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid token name: %s", token_name);
			return false;
		}

		if (lua_isstring(L, -1)) {
			const char *value;

			value = lua_tostring(L, -1);
			if (cellman_kv_list_add(tokens, token_name, value, err) != 0) {
				lua_pop(L, 2);
				return false;
			}
		} else if (lua_istable(L, -1)) {
			const char *env_name;

			lua_getfield(L, -1, "__cellman_from_env");
			if (!lua_isstring(L, -1)) {
				lua_pop(L, 3);
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "template token '%s' must be string or from_env(\"ENV\")",
					    token_name);
				return false;
			}
			env_name = lua_tostring(L, -1);
			if (!cellman_env_name_valid(env_name)) {
				lua_pop(L, 3);
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "invalid environment variable name in from_env: %s",
					    env_name);
				return false;
			}
			if (cellman_kv_list_add(token_env, token_name, env_name, err) != 0) {
				lua_pop(L, 3);
				return false;
			}
			lua_pop(L, 1);
		} else {
			lua_pop(L, 2);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "template token '%s' must be string or from_env(\"ENV\")",
				    token_name);
			return false;
		}

		lua_pop(L, 1);
	}

	return true;
}

static bool
parse_cell_table(lua_State *L, int table_idx, const char *name,
    struct cellman_cell_doc *cell, char **err)
{
	int abs_idx;

	abs_idx = lua_absindex(L, table_idx);
	if (!lua_istable(L, abs_idx)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cell definition must be table");
		return false;
	}

	cell->name = cellman_strdup(name, err);
	if (cell->name == NULL)
		return false;

	if (!fetch_bool_field(L, abs_idx, "autostart", &cell->autostart_set,
	    &cell->autostart, err))
		return false;

	if (!fetch_string_array_field(L, abs_idx, "depends_on", &cell->depends_on,
	    err))
		return false;

	if (!fetch_string_array_field(L, abs_idx, "mounts", &cell->mounts, err))
		return false;

	if (!fetch_string_field(L, abs_idx, "healthcheck", false,
	    &cell->healthcheck_cmd, err))
		return false;

	lua_getfield(L, abs_idx, "create");
	if (!lua_isnil(L, -1)) {
		if (!lua_istable(L, -1)) {
			lua_pop(L, 1);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "create section must be table");
			return false;
		}
		if (!fetch_string_field(L, -1, "profile", false,
		    &cell->profile, err) ||
		    !fetch_string_field(L, -1, "reserved_ports", false,
		    &cell->reserved_ports, err) ||
		    !fetch_string_field(L, -1, "rlimit_nofile", false,
		    &cell->rlimit_nofile, err) ||
		    !fetch_string_field(L, -1, "rlimit_as", false,
		    &cell->rlimit_as, err) ||
		    !fetch_string_field(L, -1, "rlimit_core", false,
		    &cell->rlimit_core, err)) {
			lua_pop(L, 1);
			return false;
		}
	}
	lua_pop(L, 1);

	lua_getfield(L, abs_idx, "supervise");
	if (!lua_isnil(L, -1)) {
		if (!lua_istable(L, -1)) {
			lua_pop(L, 1);
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "supervise section must be table");
			return false;
		}

		if (!fetch_string_field(L, -1, "cmd", false,
		    &cell->supervise_cmd, err) ||
		    !fetch_string_field(L, -1, "run_as", false,
		    &cell->supervise_run_as, err)) {
			lua_pop(L, 1);
			return false;
		}

		lua_getfield(L, -1, "log");
		if (!lua_isnil(L, -1)) {
			if (!lua_istable(L, -1)) {
				lua_pop(L, 2);
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "supervise.log must be table");
				return false;
			}
			if (!fetch_string_field(L, -1, "facility", false,
			    &cell->supervise_log_facility, err) ||
			    !fetch_string_field(L, -1, "stdout_level", false,
			    &cell->supervise_stdout_level, err) ||
			    !fetch_string_field(L, -1, "stderr_level", false,
			    &cell->supervise_stderr_level, err) ||
			    !fetch_string_field(L, -1, "tag", false,
			    &cell->supervise_log_tag, err)) {
				lua_pop(L, 2);
				return false;
			}
		}
		lua_pop(L, 1);
	}
	lua_pop(L, 1);

	return true;
}

static bool
parse_volume_table(lua_State *L, int table_idx, const char *name,
    struct cellman_volume_doc *volume, char **err)
{
	if (!lua_istable(L, table_idx)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "volume definition must be table");
		return false;
	}

	volume->name = cellman_strdup(name, err);
	if (volume->name == NULL)
		return false;

	if (!fetch_string_field(L, table_idx, "mode", false, &volume->mode, err))
		return false;

	return true;
}

static bool
parse_action_pkg(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	lua_getfield(L, idx, "packages");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "pkg action requires packages array");
		return false;
	}
	if (!parse_string_array(L, -1, &action->u.pkg.packages, err)) {
		lua_pop(L, 1);
		return false;
	}
	lua_pop(L, 1);
	if (action->u.pkg.packages.len == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "pkg action requires at least one package");
		return false;
	}
	return true;
}

static bool
parse_action_exec(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	return fetch_string_field(L, idx, "command", true,
	    &action->u.exec.command, err);
}

static bool
parse_action_dir(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	return fetch_string_field(L, idx, "path", true, &action->u.dir.path, err) &&
	    fetch_string_field(L, idx, "mode", false, &action->u.dir.mode, err) &&
	    fetch_string_field(L, idx, "owner", false, &action->u.dir.owner, err) &&
	    fetch_string_field(L, idx, "group", false, &action->u.dir.group, err);
}

static bool
parse_action_line(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	return fetch_string_field(L, idx, "path", true, &action->u.line.path, err) &&
	    fetch_string_field(L, idx, "text", true, &action->u.line.text, err);
}

static bool
parse_action_symlink(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	return fetch_string_field(L, idx, "target", true,
	    &action->u.symlink.target, err) &&
	    fetch_string_field(L, idx, "linkpath", true,
	    &action->u.symlink.linkpath, err);
}

static bool
parse_action_copy(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	return fetch_string_field(L, idx, "source", true,
	    &action->u.copy.source, err) &&
	    fetch_string_field(L, idx, "target", true,
	    &action->u.copy.target, err) &&
	    fetch_string_field(L, idx, "mode", false,
	    &action->u.copy.mode, err) &&
	    fetch_string_field(L, idx, "owner", false,
	    &action->u.copy.owner, err) &&
	    fetch_string_field(L, idx, "group", false,
	    &action->u.copy.group, err);
}

static bool
parse_action_untar(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	return fetch_string_field(L, idx, "source", true,
	    &action->u.untar.source, err) &&
	    fetch_string_field(L, idx, "target", true,
	    &action->u.untar.target, err) &&
	    fetch_uint_field(L, idx, "strip", false,
	    &action->u.untar.strip_components, err);
}

static bool
parse_action_file(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	return fetch_string_field(L, idx, "path", true,
	    &action->u.file.path, err) &&
	    fetch_string_field(L, idx, "content", true,
	    &action->u.file.content, err) &&
	    fetch_string_field(L, idx, "mode", false,
	    &action->u.file.mode, err) &&
	    fetch_string_field(L, idx, "owner", false,
	    &action->u.file.owner, err) &&
	    fetch_string_field(L, idx, "group", false,
	    &action->u.file.group, err);
}

static bool
parse_action_patch(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	return fetch_string_field(L, idx, "path", true,
	    &action->u.patch.path, err) &&
	    fetch_string_field(L, idx, "content", true,
	    &action->u.patch.content, err) &&
	    fetch_uint_field(L, idx, "strip", false,
	    &action->u.patch.strip_components, err);
}

static bool
parse_action_template(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	int abs_idx;

	abs_idx = lua_absindex(L, idx);

	if (!fetch_string_field(L, idx, "source", true,
	    &action->u.templ.source, err) ||
	    !fetch_string_field(L, idx, "target", true,
	    &action->u.templ.target, err) ||
	    !fetch_string_field(L, idx, "mode", false,
	    &action->u.templ.mode, err) ||
	    !fetch_string_field(L, idx, "owner", false,
	    &action->u.templ.owner, err) ||
	    !fetch_string_field(L, idx, "group", false,
	    &action->u.templ.group, err))
		return false;

	lua_getfield(L, abs_idx, "tokens");
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
	} else if (lua_istable(L, -1)) {
		if (!parse_template_tokens_table(L, -1, &action->u.templ.tokens,
		    &action->u.templ.token_env, err)) {
			lua_pop(L, 1);
			return false;
		}
		lua_pop(L, 1);
	} else {
		lua_pop(L, 1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "template tokens must be table (values: string or from_env(\"ENV\"))");
		return false;
	}

	lua_getfield(L, abs_idx, "token_env");
	if (!lua_isnil(L, -1)) {
		lua_pop(L, 1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "template token_env is deprecated; use tokens = { name = from_env(\"ENV\") }");
		return false;
	}
	lua_pop(L, 1);

	lua_getfield(L, abs_idx, "env_tokens");
	if (!lua_isnil(L, -1)) {
		lua_pop(L, 1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "template env_tokens is deprecated; use tokens = { name = from_env(\"ENV\") }");
		return false;
	}
	lua_pop(L, 1);

	return true;
}

static bool
parse_action_script(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	action->u.script.timeout_seconds = 0;
	action->u.script.ignore_exit = false;

	if (!fetch_string_field(L, idx, "path", true,
	    &action->u.script.path, err) ||
	    !fetch_string_field(L, idx, "cwd", false,
	    &action->u.script.cwd, err) ||
	    !fetch_uint_field(L, idx, "timeout", false,
	    &action->u.script.timeout_seconds, err) ||
	    !fetch_bool_field(L, idx, "ignore_exit", NULL,
	    &action->u.script.ignore_exit, err))
		return false;

	lua_getfield(L, idx, "args");
	if (!lua_isnil(L, -1)) {
		if (!parse_string_array(L, -1, &action->u.script.args, err)) {
			lua_pop(L, 1);
			return false;
		}
	}
	lua_pop(L, 1);

	lua_getfield(L, idx, "env");
	if (!lua_isnil(L, -1)) {
		if (!parse_env_table(L, -1, &action->u.script.env, err)) {
			lua_pop(L, 1);
			return false;
		}
	}
	lua_pop(L, 1);

	return true;
}

static bool
parse_action_table(lua_State *L, int idx, struct cellman_action *action,
    char **err)
{
	char *kind;
	bool ok;

	kind = NULL;
	memset(action, 0, sizeof(*action));

	if (!lua_istable(L, idx)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "action must be table");
		return false;
	}

	if (!fetch_string_field(L, idx, "kind", true, &kind, err))
		return false;

	if (strcmp(kind, "pkg") == 0) {
		action->kind = CELLMAN_ACTION_PKG;
		ok = parse_action_pkg(L, idx, action, err);
	} else if (strcmp(kind, "exec") == 0) {
		action->kind = CELLMAN_ACTION_EXEC;
		ok = parse_action_exec(L, idx, action, err);
	} else if (strcmp(kind, "dir") == 0) {
		action->kind = CELLMAN_ACTION_DIR;
		ok = parse_action_dir(L, idx, action, err);
	} else if (strcmp(kind, "line") == 0) {
		action->kind = CELLMAN_ACTION_LINE;
		ok = parse_action_line(L, idx, action, err);
	} else if (strcmp(kind, "symlink") == 0) {
		action->kind = CELLMAN_ACTION_SYMLINK;
		ok = parse_action_symlink(L, idx, action, err);
	} else if (strcmp(kind, "copy") == 0) {
		action->kind = CELLMAN_ACTION_COPY;
		ok = parse_action_copy(L, idx, action, err);
	} else if (strcmp(kind, "untar") == 0) {
		action->kind = CELLMAN_ACTION_UNTAR;
		ok = parse_action_untar(L, idx, action, err);
	} else if (strcmp(kind, "file") == 0) {
		action->kind = CELLMAN_ACTION_FILE;
		ok = parse_action_file(L, idx, action, err);
	} else if (strcmp(kind, "patch") == 0) {
		action->kind = CELLMAN_ACTION_PATCH;
		ok = parse_action_patch(L, idx, action, err);
	} else if (strcmp(kind, "template") == 0) {
		action->kind = CELLMAN_ACTION_TEMPLATE;
		ok = parse_action_template(L, idx, action, err);
	} else if (strcmp(kind, "script") == 0) {
		action->kind = CELLMAN_ACTION_SCRIPT;
		ok = parse_action_script(L, idx, action, err);
	} else {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "unknown action kind: %s", kind);
		ok = false;
	}

	free(kind);
	return ok;
}

static bool
parse_apply_table(lua_State *L, int table_idx, const char *name,
    struct cellman_apply_doc *apply, char **err)
{
	int actions_idx;
	bool actions_on_stack;
	size_t i;
	size_t n;

	if (!lua_istable(L, table_idx)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "apply definition must be table");
		return false;
	}

	apply->name = cellman_strdup(name, err);
	if (apply->name == NULL)
		return false;

	actions_on_stack = false;
	lua_getfield(L, table_idx, "actions");
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		actions_idx = lua_absindex(L, table_idx);
	} else if (lua_istable(L, -1)) {
		actions_idx = lua_absindex(L, -1);
		actions_on_stack = true;
	} else {
		lua_pop(L, 1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "apply actions section must be array table when present");
		return false;
	}

	n = lua_rawlen(L, actions_idx);
	for (i = 1; i <= n; i++) {
		struct cellman_action action;

		lua_rawgeti(L, actions_idx, (lua_Integer)i);
		if (!parse_action_table(L, -1, &action, err)) {
			lua_pop(L, 1);
			if (actions_on_stack)
				lua_pop(L, 1);
			return false;
		}
		if (cellman_action_list_append_move(&apply->actions, &action, err) != 0) {
			lua_pop(L, 1);
			if (actions_on_stack)
				lua_pop(L, 1);
			return false;
		}
		lua_pop(L, 1);
	}

	if (actions_on_stack)
		lua_pop(L, 1);
	return true;
}

static int
l_doc_cell(lua_State *L)
{
	struct cellman_lua_ctx *ctx;
	const char *name;
	struct cellman_doc tmp;
	char *err;

	ctx = lua_touserdata(L, lua_upvalueindex(1));
	if (ctx->docs == NULL && ctx->defined)
		return luaL_error(L, "only one top-level definition is allowed");

	name = luaL_checkstring(L, 1);
	luaL_checktype(L, 2, LUA_TTABLE);

	cellman_doc_init(&tmp);
	tmp.kind = CELLMAN_DOC_CELL;
	err = NULL;
	if (!parse_cell_table(L, 2, name, &tmp.u.cell, &err)) {
		cellman_doc_free(&tmp);
		return lua_error_take(L, err, "invalid cell doc");
	}

	if (ctx->docs != NULL) {
		err = NULL;
		if (doc_list_append_move(ctx->docs, &tmp, &err) != 0) {
			cellman_doc_free(&tmp);
			return lua_error_take(L, err, "out of memory");
		}
	} else {
		cellman_doc_free(ctx->doc);
		*ctx->doc = tmp;
	}
	ctx->defined = true;
	return 0;
}

static int
push_mount_spec(lua_State *L, const char *source, bool require_absolute_source)
{
	const char *target;
	const char *mode;

	target = NULL;
	mode = "rw";

	if (require_absolute_source && source[0] != '/')
		return luaL_error(L, "host mount source must be absolute path");

	luaL_checktype(L, 2, LUA_TTABLE);
	lua_getfield(L, 2, "target");
	if (!lua_isstring(L, -1)) {
		lua_pop(L, 1);
		return luaL_error(L, "mount options require string target");
	}
	target = lua_tostring(L, -1);
	lua_pop(L, 1);

	if (target[0] != '/')
		return luaL_error(L, "mount target must be absolute path");

	lua_getfield(L, 2, "mode");
	if (!lua_isnil(L, -1)) {
		if (!lua_isstring(L, -1)) {
			lua_pop(L, 1);
			return luaL_error(L, "mount mode must be string ro|rw");
		}
		mode = lua_tostring(L, -1);
	}
	lua_pop(L, 1);

	if (strcmp(mode, "ro") != 0 && strcmp(mode, "rw") != 0)
		return luaL_error(L, "mount mode must be ro or rw");

	lua_pushfstring(L, "%s:%s:%s", source, target, mode);
	return 1;
}

static bool
table_has_string_key(lua_State *L, int table_idx, const char *key)
{
	bool present;

	lua_getfield(L, table_idx, key);
	present = lua_isstring(L, -1);
	lua_pop(L, 1);
	return present;
}

static int
l_doc_volume(lua_State *L)
{
	struct cellman_lua_ctx *ctx;
	const char *name;
	struct cellman_doc tmp;
	char *err;

	name = luaL_checkstring(L, 1);
	luaL_checktype(L, 2, LUA_TTABLE);

	/*
	 * Overload volume():
	 * - top-level: volume("name", { mode = "0755" })
	 * - cell mount entry: volume("data", { target = "/data", mode = "rw" })
	 */
	if (table_has_string_key(L, 2, "target"))
		return push_mount_spec(L, name, false);

	ctx = lua_touserdata(L, lua_upvalueindex(1));
	if (ctx->docs == NULL && ctx->defined)
		return luaL_error(L, "only one top-level definition is allowed");

	cellman_doc_init(&tmp);
	tmp.kind = CELLMAN_DOC_VOLUME;
	err = NULL;
	if (!parse_volume_table(L, 2, name, &tmp.u.volume, &err)) {
		cellman_doc_free(&tmp);
		return lua_error_take(L, err, "invalid volume doc");
	}

	if (ctx->docs != NULL) {
		err = NULL;
		if (doc_list_append_move(ctx->docs, &tmp, &err) != 0) {
			cellman_doc_free(&tmp);
			return lua_error_take(L, err, "out of memory");
		}
	} else {
		cellman_doc_free(ctx->doc);
		*ctx->doc = tmp;
	}
	ctx->defined = true;
	return 0;
}

static int
l_mount_host(lua_State *L)
{
	const char *source;

	source = luaL_checkstring(L, 1);
	return push_mount_spec(L, source, true);
}

static int
l_doc_apply(lua_State *L)
{
	struct cellman_lua_ctx *ctx;
	const char *name;
	struct cellman_doc tmp;
	char *err;

	ctx = lua_touserdata(L, lua_upvalueindex(1));
	if (ctx->docs == NULL && ctx->defined)
		return luaL_error(L, "only one top-level definition is allowed");

	name = luaL_checkstring(L, 1);
	luaL_checktype(L, 2, LUA_TTABLE);

	cellman_doc_init(&tmp);
	tmp.kind = CELLMAN_DOC_APPLY;
	err = NULL;
	if (!parse_apply_table(L, 2, name, &tmp.u.apply, &err)) {
		cellman_doc_free(&tmp);
		return lua_error_take(L, err, "invalid apply doc");
	}

	if (ctx->docs != NULL) {
		err = NULL;
		if (doc_list_append_move(ctx->docs, &tmp, &err) != 0) {
			cellman_doc_free(&tmp);
			return lua_error_take(L, err, "out of memory");
		}
	} else {
		cellman_doc_free(ctx->doc);
		*ctx->doc = tmp;
	}
	ctx->defined = true;
	return 0;
}

static void
table_set_string(lua_State *L, int table_idx, const char *key, const char *value)
{
	int abs_idx;

	abs_idx = lua_absindex(L, table_idx);
	lua_pushstring(L, value);
	lua_setfield(L, abs_idx, key);
}

static bool
copy_opt_string(lua_State *L, int opts_idx, int out_idx, const char *key)
{
	int aopts;
	int aout;

	aopts = lua_absindex(L, opts_idx);
	aout = lua_absindex(L, out_idx);

	lua_getfield(L, aopts, key);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return true;
	}
	if (!lua_isstring(L, -1)) {
		lua_pop(L, 1);
		return false;
	}
	lua_setfield(L, aout, key);
	return true;
}

static int
l_action_pkg(lua_State *L)
{
	int top;
	int i;

	top = lua_gettop(L);
	if (top < 1)
		return luaL_error(L, "pkg requires at least one package");

	lua_newtable(L);
	table_set_string(L, -1, "kind", "pkg");

	lua_newtable(L);
	if (top == 1 && lua_istable(L, 1)) {
		size_t n;

		n = lua_rawlen(L, 1);
		for (i = 1; (size_t)i <= n; i++) {
			lua_rawgeti(L, 1, i);
			if (!lua_isstring(L, -1))
				return luaL_error(L, "pkg list entries must be strings");
			lua_rawseti(L, -2, i);
		}
	} else {
		for (i = 1; i <= top; i++) {
			if (!lua_isstring(L, i))
				return luaL_error(L, "pkg arguments must be strings");
			lua_pushvalue(L, i);
			lua_rawseti(L, -2, i);
		}
	}
	lua_setfield(L, -2, "packages");

	return 1;
}

static int
l_action_exec(lua_State *L)
{
	const char *cmd;

	cmd = luaL_checkstring(L, 1);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "exec");
	table_set_string(L, -1, "command", cmd);
	return 1;
}

static int
l_action_dir(lua_State *L)
{
	const char *path;

	path = luaL_checkstring(L, 1);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "dir");
	table_set_string(L, -1, "path", path);
	if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
		luaL_checktype(L, 2, LUA_TTABLE);
		if (!copy_opt_string(L, 2, -1, "mode") ||
		    !copy_opt_string(L, 2, -1, "owner") ||
		    !copy_opt_string(L, 2, -1, "group"))
			return luaL_error(L, "dir options mode/owner/group must be strings");
	}
	return 1;
}

static int
l_action_line(lua_State *L)
{
	const char *path;
	const char *text;

	path = luaL_checkstring(L, 1);
	text = luaL_checkstring(L, 2);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "line");
	table_set_string(L, -1, "path", path);
	table_set_string(L, -1, "text", text);
	return 1;
}

static int
l_action_symlink(lua_State *L)
{
	const char *target;
	const char *linkpath;

	target = luaL_checkstring(L, 1);
	linkpath = luaL_checkstring(L, 2);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "symlink");
	table_set_string(L, -1, "target", target);
	table_set_string(L, -1, "linkpath", linkpath);
	return 1;
}

static int
l_action_copy(lua_State *L)
{
	const char *source;
	const char *target;

	source = luaL_checkstring(L, 1);
	target = luaL_checkstring(L, 2);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "copy");
	table_set_string(L, -1, "source", source);
	table_set_string(L, -1, "target", target);
	if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
		luaL_checktype(L, 3, LUA_TTABLE);
		if (!copy_opt_string(L, 3, -1, "mode") ||
		    !copy_opt_string(L, 3, -1, "owner") ||
		    !copy_opt_string(L, 3, -1, "group"))
			return luaL_error(L,
			    "copy options mode/owner/group must be strings");
	}
	return 1;
}

static int
l_action_untar(lua_State *L)
{
	const char *source;
	const char *target;

	source = luaL_checkstring(L, 1);
	target = luaL_checkstring(L, 2);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "untar");
	table_set_string(L, -1, "source", source);
	table_set_string(L, -1, "target", target);
	if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
		luaL_checktype(L, 3, LUA_TTABLE);
		lua_getfield(L, 3, "strip");
		if (!lua_isnil(L, -1)) {
			if (!lua_isinteger(L, -1))
				return luaL_error(L, "untar option strip must be integer");
			lua_setfield(L, -2, "strip");
		} else {
			lua_pop(L, 1);
		}
	}
	return 1;
}

static int
l_action_file(lua_State *L)
{
	const char *path;
	const char *content;

	path = luaL_checkstring(L, 1);
	content = luaL_checkstring(L, 2);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "file");
	table_set_string(L, -1, "path", path);
	table_set_string(L, -1, "content", content);
	if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
		luaL_checktype(L, 3, LUA_TTABLE);
		if (!copy_opt_string(L, 3, -1, "mode") ||
		    !copy_opt_string(L, 3, -1, "owner") ||
		    !copy_opt_string(L, 3, -1, "group"))
			return luaL_error(L,
			    "file options mode/owner/group must be strings");
	}
	return 1;
}

static int
l_action_patch(lua_State *L)
{
	const char *path;
	const char *content;

	path = luaL_checkstring(L, 1);
	content = luaL_checkstring(L, 2);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "patch");
	table_set_string(L, -1, "path", path);
	table_set_string(L, -1, "content", content);
	if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
		luaL_checktype(L, 3, LUA_TTABLE);
		lua_getfield(L, 3, "strip");
		if (!lua_isnil(L, -1)) {
			if (!lua_isinteger(L, -1))
				return luaL_error(L, "patch option strip must be integer");
			lua_setfield(L, -2, "strip");
		} else {
			lua_pop(L, 1);
		}
	}
	return 1;
}

static int
l_action_template(lua_State *L)
{
	const char *source;
	const char *target;

	source = luaL_checkstring(L, 1);
	target = luaL_checkstring(L, 2);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "template");
	table_set_string(L, -1, "source", source);
	table_set_string(L, -1, "target", target);
	if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
		luaL_checktype(L, 3, LUA_TTABLE);
		if (!copy_opt_string(L, 3, -1, "mode") ||
		    !copy_opt_string(L, 3, -1, "owner") ||
		    !copy_opt_string(L, 3, -1, "group"))
			return luaL_error(L,
			    "template options mode/owner/group must be strings");
		lua_getfield(L, 3, "token_env");
		if (!lua_isnil(L, -1))
			return luaL_error(L,
			    "template token_env is deprecated; use tokens={name=from_env(\"ENV\")}"
			    );
		lua_pop(L, 1);
		lua_getfield(L, 3, "env_tokens");
		if (!lua_isnil(L, -1))
			return luaL_error(L,
			    "template env_tokens is deprecated; use tokens={name=from_env(\"ENV\")}"
			    );
		lua_pop(L, 1);
		copy_opt_field_raw(L, 3, -1, "tokens");
	}
	return 1;
}

static int
l_token_from_env(lua_State *L)
{
	const char *env_name;

	env_name = luaL_checkstring(L, 1);
	lua_newtable(L);
	table_set_string(L, -1, "__cellman_from_env", env_name);
	return 1;
}

static void
copy_opt_field_raw(lua_State *L, int opts_idx, int out_idx, const char *key)
{
	int aopts;
	int aout;

	aopts = lua_absindex(L, opts_idx);
	aout = lua_absindex(L, out_idx);

	lua_getfield(L, aopts, key);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	lua_setfield(L, aout, key);
}

static int
l_action_script(lua_State *L)
{
	const char *path;

	path = luaL_checkstring(L, 1);
	lua_newtable(L);
	table_set_string(L, -1, "kind", "script");
	table_set_string(L, -1, "path", path);
	if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
		luaL_checktype(L, 2, LUA_TTABLE);
		copy_opt_field_raw(L, 2, -1, "args");
		copy_opt_field_raw(L, 2, -1, "env");
		copy_opt_field_raw(L, 2, -1, "cwd");
		copy_opt_field_raw(L, 2, -1, "timeout");
		copy_opt_field_raw(L, 2, -1, "ignore_exit");
	}
	return 1;
}

static void
register_builder(lua_State *L, const char *name, lua_CFunction fn,
    struct cellman_lua_ctx *ctx)
{
	lua_pushlightuserdata(L, ctx);
	lua_pushcclosure(L, fn, 1);
	lua_setglobal(L, name);
}

static void
register_action(lua_State *L, const char *name, lua_CFunction fn)
{
	lua_pushcfunction(L, fn);
	lua_setglobal(L, name);
}

static void
sandbox_lua(lua_State *L)
{
	static const char *const blocked_globals[] = {
		"dofile",
		"load",
		"loadfile",
		"require",
		"collectgarbage",
		"module",
	};
	static const char *const blocked_libs[] = {
		"os",
		"io",
		"debug",
		"package",
	};
	size_t i;

	luaL_openlibs(L);

	for (i = 0; i < sizeof(blocked_globals) / sizeof(blocked_globals[0]); i++) {
		lua_pushnil(L);
		lua_setglobal(L, blocked_globals[i]);
	}

	for (i = 0; i < sizeof(blocked_libs) / sizeof(blocked_libs[0]); i++) {
		lua_pushnil(L);
		lua_setglobal(L, blocked_libs[i]);
	}
}

static int
dsl_load_file_common(const char *path, struct cellman_lua_ctx *ctx, char **err)
{
	lua_State *L;
	const char *lua_err;
	size_t i;

	if (err != NULL)
		*err = NULL;

	L = luaL_newstate();
	if (L == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "failed to initialize lua state");
		return -1;
	}

	sandbox_lua(L);
	register_builder(L, "cell", l_doc_cell, ctx);
	register_builder(L, "volume", l_doc_volume, ctx);
	register_builder(L, "apply", l_doc_apply, ctx);

	register_action(L, "pkg", l_action_pkg);
	register_action(L, "exec", l_action_exec);
	register_action(L, "dir", l_action_dir);
	register_action(L, "line", l_action_line);
	register_action(L, "symlink", l_action_symlink);
	register_action(L, "copy", l_action_copy);
	register_action(L, "untar", l_action_untar);
	register_action(L, "file", l_action_file);
	register_action(L, "patch", l_action_patch);
	register_action(L, "template", l_action_template);
	register_action(L, "from_env", l_token_from_env);
	register_action(L, "script", l_action_script);
	register_action(L, "host", l_mount_host);

	if (luaL_loadfile(L, path) != LUA_OK || lua_pcall(L, 0, 0, 0) != LUA_OK) {
		lua_err = lua_tostring(L, -1);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s",
			    lua_err != NULL ? lua_err : "lua execution failed");
		lua_close(L);
		if (ctx->docs != NULL)
			doc_list_clear(ctx->docs);
		if (ctx->doc != NULL)
			cellman_doc_free(ctx->doc);
		return -1;
	}

	if (!ctx->defined) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "dsl did not define cell(), volume(), or apply()");
		lua_close(L);
		if (ctx->docs != NULL)
			doc_list_clear(ctx->docs);
		if (ctx->doc != NULL)
			cellman_doc_free(ctx->doc);
		return -1;
	}

	if (ctx->docs != NULL) {
		for (i = 0; i < ctx->docs->len; i++) {
			if (cellman_doc_set_source(&ctx->docs->items[i], path, err) != 0) {
				lua_close(L);
				doc_list_clear(ctx->docs);
				return -1;
			}
		}
	} else {
		if (cellman_doc_set_source(ctx->doc, path, err) != 0) {
			lua_close(L);
			cellman_doc_free(ctx->doc);
			return -1;
		}
	}

	lua_close(L);
	return 0;
}

int
cellman_dsl_load_file(const char *path, struct cellman_doc *doc, char **err)
{
	struct cellman_lua_ctx ctx;

	if (err != NULL)
		*err = NULL;

	cellman_doc_free(doc);

	ctx.doc = doc;
	ctx.docs = NULL;
	ctx.defined = false;

	if (dsl_load_file_common(path, &ctx, err) != 0) {
		cellman_doc_free(doc);
		return -1;
	}

	return 0;
}

int
cellman_dsl_load_file_all(const char *path, struct cellman_doc_list *docs,
    char **err)
{
	struct cellman_lua_ctx ctx;

	if (err != NULL)
		*err = NULL;

	if (docs == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "internal error: docs is NULL");
		return -1;
	}

	doc_list_clear(docs);

	ctx.doc = NULL;
	ctx.docs = docs;
	ctx.defined = false;

	if (dsl_load_file_common(path, &ctx, err) != 0) {
		doc_list_clear(docs);
		return -1;
	}

	return 0;
}
