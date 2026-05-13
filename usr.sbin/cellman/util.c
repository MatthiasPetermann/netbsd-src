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
 * Layer: cellman shared utility layer.
 *
 * Provide shared string/path/list helpers and config lookup utilities reused
 * across modules.
 *
 * Extension guidance: Add generic helper routines here; keep
 * subsystem-specific logic in the corresponding subsystem files.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "cellman.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Grow dynamic arrays geometrically with overflow guards. */
static bool
grow_array(void **ptr, size_t *cap, size_t elem_size, size_t want, char **err)
{
	size_t new_cap;
	void *new_ptr;

	if (*cap >= want)
		return true;

	new_cap = (*cap == 0) ? 8 : *cap;
	while (new_cap < want) {
		if (new_cap > SIZE_MAX / 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "array capacity overflow");
			return false;
		}
		new_cap *= 2;
	}

	if (elem_size != 0 && new_cap > SIZE_MAX / elem_size) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "array size overflow");
		return false;
	}

	new_ptr = realloc(*ptr, new_cap * elem_size);
	if (new_ptr == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return false;
	}

	*ptr = new_ptr;
	*cap = new_cap;
	return true;
}

/* Duplicate an entire string with common error mapping. */
char *
cellman_strdup(const char *src, char **err)
{
	char *copy;

	if (src == NULL)
		src = "";

	copy = strdup(src);
	if (copy == NULL && err != NULL)
		*err = cellman_xasprintf(NULL, "out of memory");
	return copy;
}

/* Duplicate at most len bytes and NUL-terminate the result. */
char *
cellman_strndup(const char *src, size_t len, char **err)
{
	char *copy;

	if (src == NULL)
		src = "";

	copy = malloc(len + 1);
	if (copy == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return NULL;
	}

	memcpy(copy, src, len);
	copy[len] = '\0';
	return copy;
}

/* Allocate and format a string similarly to asprintf(3). */
char *
cellman_xasprintf(char **out_opt, const char *fmt, ...)
{
	va_list ap;
	va_list ap2;
	char *buf;
	int n;

	if (fmt == NULL)
		fmt = "";

	va_start(ap, fmt);
	va_copy(ap2, ap);
	n = vsnprintf(NULL, 0, fmt, ap2);
	va_end(ap2);
	if (n < 0) {
		va_end(ap);
		return NULL;
	}

	buf = malloc((size_t)n + 1);
	if (buf == NULL) {
		va_end(ap);
		return NULL;
	}

	(void)vsnprintf(buf, (size_t)n + 1, fmt, ap);
	va_end(ap);

	if (out_opt != NULL)
		*out_opt = buf;
	return buf;
}

/* Return directory component of path as a newly allocated string. */
char *
cellman_dirname_dup(const char *path, char **err)
{
	const char *slash;

	if (path == NULL || *path == '\0')
		return cellman_strdup(".", err);

	slash = strrchr(path, '/');
	if (slash == NULL)
		return cellman_strdup(".", err);
	if (slash == path)
		return cellman_strdup("/", err);

	return cellman_strndup(path, (size_t)(slash - path), err);
}

/* Join left and right into one normalized path string. */
char *
cellman_path_join(const char *left, const char *right, char **err)
{
	char *joined;
	size_t llen;
	size_t rlen;
	bool need_slash;

	if (left == NULL)
		left = "";
	if (right == NULL)
		right = "";

	if (*right == '/')
		return cellman_strdup(right, err);

	llen = strlen(left);
	rlen = strlen(right);
	need_slash = (llen > 0 && left[llen - 1] != '/');

	if (llen > SIZE_MAX - rlen - 2) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "path join overflow");
		return NULL;
	}

	joined = malloc(llen + rlen + (need_slash ? 2 : 1));
	if (joined == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return NULL;
	}

	memcpy(joined, left, llen);
	if (need_slash)
		joined[llen++] = '/';
	memcpy(joined + llen, right, rlen);
	joined[llen + rlen] = '\0';

	return joined;
}

/* Validate process environment variable identifiers. */
bool
cellman_env_name_valid(const char *name)
{
	size_t i;

	if (name == NULL || name[0] == '\0')
		return false;

	if (!(isalpha((unsigned char)name[0]) || name[0] == '_'))
		return false;

	for (i = 1; name[i] != '\0'; i++) {
		if (!(isalnum((unsigned char)name[i]) || name[i] == '_'))
			return false;
	}

	return true;
}

/* Append one string value to a growable list. */
int
cellman_string_list_add(struct cellman_string_list *list, const char *value,
    char **err)
{
	char *copy;

	if (list == NULL)
		return -1;

	copy = cellman_strdup(value, err);
	if (copy == NULL)
		return -1;

	if (!grow_array((void **)&list->items, &list->cap, sizeof(*list->items),
	    list->len + 1, err)) {
		free(copy);
		return -1;
	}

	list->items[list->len++] = copy;
	return 0;
}

/* Release all memory owned by a string list. */
void
cellman_string_list_free(struct cellman_string_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++)
		free(list->items[i]);
	free(list->items);
	list->items = NULL;
	list->len = 0;
	list->cap = 0;
}

/* Append one key/value pair to a growable map list. */
int
cellman_kv_list_add(struct cellman_kv_list *list, const char *key,
    const char *value, char **err)
{
	char *kcopy;
	char *vcopy;

	if (list == NULL)
		return -1;

	kcopy = cellman_strdup(key, err);
	if (kcopy == NULL)
		return -1;

	vcopy = cellman_strdup(value, err);
	if (vcopy == NULL) {
		free(kcopy);
		return -1;
	}

	if (!grow_array((void **)&list->items, &list->cap, sizeof(*list->items),
	    list->len + 1, err)) {
		free(kcopy);
		free(vcopy);
		return -1;
	}

	list->items[list->len].key = kcopy;
	list->items[list->len].value = vcopy;
	list->len++;
	return 0;
}

/* Look up a value by key in a key/value list. */
const char *
cellman_kv_list_get(const struct cellman_kv_list *list, const char *key)
{
	size_t i;

	if (list == NULL || key == NULL)
		return NULL;

	for (i = 0; i < list->len; i++) {
		if (strcmp(list->items[i].key, key) == 0)
			return list->items[i].value;
	}

	return NULL;
}

/* Release all memory owned by a key/value list. */
void
cellman_kv_list_free(struct cellman_kv_list *list)
{
	size_t i;

	if (list == NULL)
		return;

	for (i = 0; i < list->len; i++) {
		free(list->items[i].key);
		free(list->items[i].value);
	}

	free(list->items);
	list->items = NULL;
	list->len = 0;
	list->cap = 0;
}

/* Parse key=value input into separately allocated key and value strings. */
bool
cellman_split_kv(const char *input, char **key_out, char **value_out,
    char **err)
{
	const char *eq;

	if (key_out == NULL || value_out == NULL)
		return false;

	*key_out = NULL;
	*value_out = NULL;

	if (input == NULL || *input == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing key=value");
		return false;
	}

	eq = strchr(input, '=');
	if (eq == NULL || eq == input) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid key=value: %s", input);
		return false;
	}

	*key_out = cellman_strndup(input, (size_t)(eq - input), err);
	if (*key_out == NULL)
		return false;

	*value_out = cellman_strdup(eq + 1, err);
	if (*value_out == NULL) {
		free(*key_out);
		*key_out = NULL;
		return false;
	}

	return true;
}

char *
cellman_release_major_minor(const char *release, char **err)
{
	const char *src;
	char *normalized;
	char *fallback;
	size_t len;

	src = release != NULL ? release : "";
	len = 0;
	while (src[len] != '\0') {
		if (!(isdigit((unsigned char)src[len]) || src[len] == '.'))
			break;
		len++;
	}

	while (len > 0 && src[len - 1] == '.')
		len--;

	if (len == 0)
		return cellman_strdup(src, err);

	normalized = cellman_strndup(src, len, err);
	if (normalized != NULL)
		return normalized;

	if (err != NULL && *err != NULL) {
		fallback = *err;
		*err = NULL;
		free(fallback);
	}
	return cellman_strdup(src, err);
}

static char *
trim_ws_inplace(char *text)
{
	char *end;

	if (text == NULL)
		return NULL;

	while (*text != '\0' && isspace((unsigned char)*text))
		text++;

	end = text + strlen(text);
	while (end > text && isspace((unsigned char)end[-1]))
		*--end = '\0';

	return text;
}

int
cellman_conf_get(const char *key, char **value_out, char **err)
{
	FILE *fp;
	char *line;
	size_t cap;

	if (value_out == NULL)
		return -1;
	*value_out = NULL;

	if (key == NULL || key[0] == '\0' || !cellman_env_name_valid(key)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid config key: %s",
			    key != NULL ? key : "");
		return -1;
	}

	fp = fopen("/etc/cellman.conf", "r");
	if (fp == NULL) {
		if (errno == ENOENT)
			return 0;
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot read /etc/cellman.conf: %s",
			    strerror(errno));
		return -1;
	}

	line = NULL;
	cap = 0;
	while (getline(&line, &cap, fp) != -1) {
		char *p;
		char *eq;
		char *name;
		char *value;

		p = trim_ws_inplace(line);
		if (p == NULL || p[0] == '\0' || p[0] == '#')
			continue;

		eq = strchr(p, '=');
		if (eq == NULL)
			continue;
		*eq = '\0';

		name = trim_ws_inplace(p);
		if (name == NULL || strcmp(name, key) != 0)
			continue;

		value = trim_ws_inplace(eq + 1);

		if (value[0] == '\'' || value[0] == '"') {
			char quote;
			char *endq;

			quote = value[0];
			value++;
			endq = strchr(value, quote);
			if (endq != NULL)
				*endq = '\0';
		} else {
			char *comment;

			comment = strchr(value, '#');
			if (comment != NULL)
				*comment = '\0';
			value = trim_ws_inplace(value);
		}

		*value_out = cellman_strdup(value, err);
		if (*value_out == NULL) {
			free(line);
			(void)fclose(fp);
			return -1;
		}
		break;
	}

	free(line);
	(void)fclose(fp);
	return 0;
}
