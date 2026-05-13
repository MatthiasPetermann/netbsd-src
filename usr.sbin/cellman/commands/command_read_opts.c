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
 * Layer: cellman read-option parsing layer.
 *
 * Parse common read/list/show/fields CLI options and normalize read view
 * selection.
 *
 * Extension guidance: Add shared read option parsing here; avoid duplicating
 * flag parsing in resource command modules.
 */

#include "command_backend_internal.h"

#include <string.h>

void
cellman_read_options_init(struct cellman_read_options *options)
{
	if (options == NULL)
		return;

	options->view = READ_VIEW_MERGED;
	options->requested_fields = NULL;
	options->tsv = false;
	options->no_header = false;
}

int
cellman_parse_list_options(int argc, char *argv[],
    struct cellman_read_options *options, const char *usage, char **err)
{
	size_t i;

	if (options == NULL)
		return 1;

	for (i = 0; i < (size_t)argc; i++) {
		if (strcmp(argv[i], "-T") == 0) {
			options->tsv = true;
			continue;
		}
		if (strcmp(argv[i], "-H") == 0) {
			options->no_header = true;
			continue;
		}
		if (strcmp(argv[i], "--view") == 0) {
			if (i + 1 >= (size_t)argc)
				goto badopt;
			if (parse_read_view(argv[++i], &options->view, err) != 0)
				return 1;
			continue;
		}
		if (strcmp(argv[i], "-o") == 0) {
			if (i + 1 >= (size_t)argc)
				goto badopt;
			options->requested_fields = argv[++i];
			continue;
		}
		goto badopt;
	}

	if (!options->tsv && options->no_header)
		goto badopt;
	return 0;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL, "%s", usage);
	return 1;
}

int
cellman_parse_show_options(int argc, char *argv[], const char **name_out,
    struct cellman_read_options *options, const char *usage, char **err)
{
	size_t i;

	if (name_out == NULL || options == NULL)
		return 1;

	if (argc < 1)
		goto badopt;

	*name_out = argv[0];
	for (i = 1; i < (size_t)argc; i++) {
		if (strcmp(argv[i], "--view") == 0) {
			if (i + 1 >= (size_t)argc)
				goto badopt;
			if (parse_read_view(argv[++i], &options->view, err) != 0)
				return 1;
			continue;
		}
		if (strcmp(argv[i], "-o") == 0) {
			if (i + 1 >= (size_t)argc)
				goto badopt;
			options->requested_fields = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "-T") == 0) {
			options->tsv = true;
			continue;
		}
		if (strcmp(argv[i], "-H") == 0) {
			options->no_header = true;
			continue;
		}
		goto badopt;
	}

	if (!options->tsv && options->no_header)
		goto badopt;
	return 0;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL, "%s", usage);
	return 1;
}

int
cellman_parse_fields_options(int argc, char *argv[], enum read_view *view,
    bool *tsv, bool *no_header, const char *usage, char **err)
{
	int i;

	if (view == NULL || tsv == NULL || no_header == NULL)
		return 1;

	*view = READ_VIEW_MERGED;
	*tsv = false;
	*no_header = false;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--view") == 0) {
			if (i + 1 >= argc)
				goto badopt;
			if (parse_read_view(argv[++i], view, err) != 0)
				return 1;
			continue;
		}
		if (strcmp(argv[i], "-T") == 0) {
			*tsv = true;
			continue;
		}
		if (strcmp(argv[i], "-H") == 0) {
			*no_header = true;
			continue;
		}
		goto badopt;
	}

	if (!*tsv && *no_header)
		goto badopt;
	return 0;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL, "%s", usage);
	return 1;
}
