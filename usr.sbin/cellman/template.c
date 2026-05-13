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
 * Layer: cellman template expansion layer.
 *
 * Implement token-based template rendering used by DSL actions and config
 * generation paths.
 *
 * Extension guidance: Add generic template syntax/expansion behavior here;
 * keep action-specific rendering policy in apply modules.
 */

#include "cellman.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

static bool
append_bytes(char **buf, size_t *len, size_t *cap, const char *src,
    size_t src_len, char **err)
{
	size_t need;
	char *new_buf;
	size_t new_cap;

	if (*buf == NULL || *cap == 0)
		return false;

	if (*len > SIZE_MAX - src_len - 1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "template output overflow");
		return false;
	}

	need = *len + src_len + 1;
	if (need > *cap) {
		new_cap = *cap;
		while (new_cap < need) {
			if (new_cap > SIZE_MAX / 2) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "template buffer overflow");
				return false;
			}
			new_cap *= 2;
		}
		new_buf = realloc(*buf, new_cap);
		if (new_buf == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return false;
		}
		*buf = new_buf;
		*cap = new_cap;
	}

	memcpy(*buf + *len, src, src_len);
	*len += src_len;
	(*buf)[*len] = '\0';
	return true;
}

int
cellman_template_expand(const char *input, const struct cellman_tokens *tokens,
    char **output, char **err)
{
	char *rendered;
	size_t rendered_len;
	size_t rendered_cap;
	const char *p;

	if (output == NULL)
		return -1;

	*output = NULL;
	if (err != NULL)
		*err = NULL;

	if (input == NULL)
		input = "";

	rendered_cap = strlen(input) + 32;
	if (rendered_cap < 64)
		rendered_cap = 64;
	rendered = calloc(1, rendered_cap);
	if (rendered == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}
	rendered_len = 0;

	for (p = input; *p != '\0';) {
		const char *open;

		open = strstr(p, "{{");
		if (open == NULL) {
			if (!append_bytes(&rendered, &rendered_len, &rendered_cap, p,
			    strlen(p), err))
				goto fail;
			break;
		}

		if (!append_bytes(&rendered, &rendered_len, &rendered_cap, p,
		    (size_t)(open - p), err))
			goto fail;

		{
			const char *close;
			const char *token_start;
			const char *token_end;
			char *token;
			const char *value;

			close = strstr(open + 2, "}}");
			if (close == NULL) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "unterminated template token");
				goto fail;
			}

			token_start = open + 2;
			token_end = close;
			while (token_start < token_end &&
			    isspace((unsigned char)*token_start))
				token_start++;
			while (token_end > token_start &&
			    isspace((unsigned char)token_end[-1]))
				token_end--;

			token = cellman_strndup(token_start,
			    (size_t)(token_end - token_start), err);
			if (token == NULL)
				goto fail;

			if (!token_name_valid(token)) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "invalid template token: %s", token);
				free(token);
				goto fail;
			}

			value = cellman_tokens_get(tokens, token);
			if (value == NULL) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "unknown template token: %s", token);
				free(token);
				goto fail;
			}

			if (!append_bytes(&rendered, &rendered_len, &rendered_cap, value,
			    strlen(value), err)) {
				free(token);
				goto fail;
			}

			free(token);
			p = close + 2;
		}
	}

	*output = rendered;
	return 0;

fail:
	free(rendered);
	return -1;
}
