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
 * Layer: cellman shared filesystem utility layer.
 *
 * Provide reusable mkdir/path-safety/mount-state/file-io helpers used across
 * backend/runtime modules.
 *
 * Extension guidance: Add generic filesystem helpers here; keep
 * command-specific policies in backend command modules.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "cellman.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Ensure each path component exists, mirroring mkdir -p semantics.
 */
int
cellman_mkdir_p(const char *path, mode_t mode, char **err)
{
	char *tmp;
	char *p;

	if (path == NULL || path[0] == '\0')
		return 0;

	tmp = cellman_strdup(path, err);
	if (tmp == NULL)
		return -1;

	for (p = tmp + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "mkdir %s failed: %s", tmp,
				    strerror(errno));
			free(tmp);
			return -1;
		}
		*p = '/';
	}

	if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "mkdir %s failed: %s", tmp,
			    strerror(errno));
		free(tmp);
		return -1;
	}

	free(tmp);
	return 0;
}

/*
 * Check whether candidate equals base or is nested below it.
 */
bool
cellman_path_is_same_or_child(const char *candidate, const char *base)
{
	size_t blen;

	if (candidate == NULL || base == NULL)
		return false;

	blen = strlen(base);
	while (blen > 1 && base[blen - 1] == '/')
		blen--;

	if (blen == 0)
		return false;
	if (strncmp(candidate, base, blen) != 0)
		return false;
	if (candidate[blen] == '\0')
		return true;
	return candidate[blen] == '/';
}

/*
 * Inspect mount(8) output and report whether one path is mounted.
 */
int
cellman_is_path_mounted(const char *path, bool *mounted_out, char **err)
{
	char *raw;
	char *line;
	char *saveptr;
	size_t path_len;

	if (mounted_out == NULL)
		return -1;
	*mounted_out = false;

	if (path == NULL || path[0] == '\0')
		return 0;
	path_len = strlen(path);

	raw = NULL;
	if (cellman_exec_run_capture((const char *const[]){ "mount", NULL }, &raw,
	    err) != 0)
		return -1;

	saveptr = NULL;
	line = strtok_r(raw, "\n", &saveptr);
	while (line != NULL) {
		char *on;
		char *type;
		size_t src_len;
		size_t tgt_len;

		on = strstr(line, " on ");
		if (on == NULL) {
			line = strtok_r(NULL, "\n", &saveptr);
			continue;
		}
		type = strstr(on + 4, " type ");
		if (type == NULL) {
			line = strtok_r(NULL, "\n", &saveptr);
			continue;
		}

		src_len = (size_t)(on - line);
		tgt_len = (size_t)(type - (on + 4));
		if ((src_len == path_len && strncmp(line, path, src_len) == 0) ||
		    (tgt_len == path_len && strncmp(on + 4, path, tgt_len) == 0)) {
			*mounted_out = true;
			break;
		}

		line = strtok_r(NULL, "\n", &saveptr);
	}

	free(raw);
	return 0;
}

/*
 * Read one optional text file and return NULL when the file is absent.
 */
int
cellman_read_optional_text_file(const char *path, char **out, char **err)
{
	int fd;
	char *buf;
	size_t cap;
	size_t len;
	ssize_t nr;

	if (out == NULL)
		return -1;
	*out = NULL;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot open %s: %s", path,
			    strerror(errno));
		return -1;
	}

	cap = 4096;
	len = 0;
	buf = malloc(cap);
	if (buf == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		(void)close(fd);
		return -1;
	}

	for (;;) {
		if (cap - len <= 1) {
			char *next;
			size_t next_cap;

			if (cap > SIZE_MAX / 2) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "out of memory");
				free(buf);
				(void)close(fd);
				return -1;
			}
			next_cap = cap * 2;
			next = realloc(buf, next_cap);
			if (next == NULL) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "out of memory");
				free(buf);
				(void)close(fd);
				return -1;
			}
			buf = next;
			cap = next_cap;
		}

		nr = read(fd, buf + len, cap - len - 1);
		if (nr < 0) {
			if (errno == EINTR)
				continue;
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cannot read %s: %s", path,
				    strerror(errno));
			free(buf);
			(void)close(fd);
			return -1;
		}
		if (nr == 0)
			break;
		len += (size_t)nr;
	}

	buf[len] = '\0';
	(void)close(fd);
	*out = buf;
	return 0;
}

/*
 * Write text content atomically by recreating the target file contents.
 */
int
cellman_write_text_file(const char *path, const char *content, char **err)
{
	char *dir;
	FILE *fp;

	dir = cellman_dirname_dup(path, err);
	if (dir == NULL)
		return -1;
	if (cellman_mkdir_p(dir, 0755, err) != 0) {
		free(dir);
		return -1;
	}
	free(dir);

	fp = fopen(path, "w");
	if (fp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot write %s: %s", path,
			    strerror(errno));
		return -1;
	}

	if (content != NULL && content[0] != '\0' &&
	    fwrite(content, 1, strlen(content), fp) != strlen(content)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot write %s: %s", path,
			    strerror(errno));
		(void)fclose(fp);
		return -1;
	}

	if (fclose(fp) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot close %s: %s", path,
			    strerror(errno));
		return -1;
	}

	return 0;
}
