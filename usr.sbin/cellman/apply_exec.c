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
 * Layer: cellman apply orchestration layer.
 *
 * Own apply runtime initialization, high-level action dispatch, and apply
 * entrypoints used by backend flows.
 *
 * Extension guidance: Add orchestration-level behavior here; keep token
 * composition and action implementations in split apply submodules.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "cellman.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * Native apply runtime.
 *
 * This module executes validated DSL IR directly.
 */

struct run_identity {
	char *uid;
	char *gid;
	char *groups;
};

struct apply_runtime {
	char *cell_name;
	char *cell_root;
	char *manifest_dir;
	char *release;
	char *arch;
	char *pkg_path;
	struct run_identity run_id;
	bool dry_run;
	bool verbose;
	bool forward_output;
};

struct strbuf {
	char *buf;
	size_t len;
	size_t cap;
};

static int wait_for_child(pid_t, unsigned int, int *, bool *, char **);
static bool action_status_ok(int);

static bool strbuf_init(struct strbuf *, char **);
static void strbuf_reset(struct strbuf *);
static bool strbuf_append_n(struct strbuf *, const char *, size_t, char **);
static bool strbuf_append(struct strbuf *, const char *, char **);
static char *shell_quote(const char *, char **);

static char *trim_ws_inplace(char *);
static bool token_name_valid(const char *);

static int read_text_file(const char *, char **, char **);
static int mkdir_p(const char *, mode_t, char **);
static int ensure_parent_dir(const char *, char **);
static char *map_cell_path(const struct apply_runtime *, const char *, char **);
static int copy_file(const char *, const char *, char **);

static void run_identity_free(struct run_identity *);
static int run_identity_init(struct run_identity *, char **);
static bool id_token_valid(const char *);
static int parse_id_value(const char *, unsigned long *);
static int resolve_cell_user_uid(const struct apply_runtime *, const char *,
    uid_t *, char **);
static int resolve_cell_group_gid(const struct apply_runtime *, const char *,
    gid_t *, char **);
static int resolve_uid(const struct apply_runtime *, const struct run_identity *,
    const char *, uid_t *,
    char **);
static int resolve_gid(const struct apply_runtime *, const struct run_identity *,
    const char *, gid_t *,
    char **);
static int apply_mode_owner_group(const char *, const char *, const char *,
    const char *, const struct apply_runtime *, char **);

static int tokens_set_checked(struct cellman_tokens *, const char *,
    const char *, char **);
static int tokens_clone(struct cellman_tokens *, const struct cellman_tokens *,
    char **);
static int tokens_merge_map(struct cellman_tokens *, const struct cellman_kv_list *,
    char **);
static int tokens_merge_text(struct cellman_tokens *, const char *, char **);
static int tokens_merge_env_map(struct cellman_tokens *,
    const struct cellman_kv_list *, char **);
static int runtime_tokens_build(const struct apply_runtime *,
    const struct cellman_tokens *, struct cellman_tokens *, char **);

static int render_template_value(const char *, const struct cellman_tokens *,
    char **, char **);
static int render_optional_value(const char *, const struct cellman_tokens *,
    char **, char **);
static int resolve_source_path(const struct cellman_doc *, const char *,
    char **, char **);

static int run_spawn(char *const [], const struct cellman_kv_list *,
    const char *, const char *, size_t, unsigned int, bool, int *, bool *,
    char **);
static int run_spawn_checked(char *const [], const struct cellman_kv_list *,
    const char *, const char *, size_t, unsigned int, bool, bool, char **);
static int resolve_runtime_pkg_path(const char *, const char *, char **, char **);
static int append_export(struct strbuf *, const char *, const char *, char **);
static int run_cell_shell_command(const struct apply_runtime *, const char *,
    const char *, const struct cellman_kv_list *, const char *, size_t,
    unsigned int, bool, char **);
static int ensure_cell_certctl_rehash(const struct apply_runtime *, char **);

static int run_pkg_action(const struct cellman_action_pkg *,
    const struct cellman_tokens *, const struct apply_runtime *, char **);
static int run_exec_action(const struct cellman_action_exec *,
    const struct cellman_tokens *, const struct apply_runtime *, char **);
static int run_dir_action(const struct cellman_action_dir *,
    const struct cellman_tokens *, const struct apply_runtime *, char **);
static int run_line_action(const struct cellman_action_line *,
    const struct cellman_tokens *, const struct apply_runtime *, char **);
static int run_symlink_action(const struct cellman_action_symlink *,
    const struct cellman_tokens *, const struct apply_runtime *, char **);
static int run_copy_action(const struct cellman_doc *,
    const struct cellman_action_copy *, const struct cellman_tokens *,
    const struct apply_runtime *, char **);
static int run_untar_action(const struct cellman_doc *,
    const struct cellman_action_untar *, const struct cellman_tokens *,
    const struct apply_runtime *, char **);
static int run_file_action(const struct cellman_action_file *,
    const struct cellman_tokens *, const struct apply_runtime *, char **);
static int run_patch_action(const struct cellman_action_patch *,
    const struct cellman_tokens *, const struct apply_runtime *, char **);
static int run_template_action(const struct cellman_doc *,
    const struct cellman_action_template *, const struct cellman_tokens *,
    const struct apply_runtime *, char **);
static int run_script_action(const struct cellman_doc *,
    const struct cellman_action_script *, const struct cellman_tokens *,
    const struct apply_runtime *, char **);

static int apply_runtime_init(struct apply_runtime *, const struct cellman_doc *,
    const char *, const char *, bool, bool, bool, char **);
static void apply_runtime_free(struct apply_runtime *);

static int
wait_for_child(pid_t pid, unsigned int timeout, int *status_out, bool *timed_out,
    char **err)
{
	struct timespec started;
	int status;

	if (status_out == NULL || timed_out == NULL)
		return -1;

	*timed_out = false;
	if (clock_gettime(CLOCK_MONOTONIC, &started) == -1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "clock_gettime failed: %s",
			    strerror(errno));
		return -1;
	}

	for (;;) {
		pid_t rv;

		rv = waitpid(pid, &status, timeout == 0 ? 0 : WNOHANG);
		if (rv == pid) {
			*status_out = status;
			return 0;
		}
		if (rv == -1) {
			if (errno == EINTR)
				continue;
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "waitpid failed: %s",
				    strerror(errno));
			return -1;
		}
		if (timeout == 0)
			continue;

		{
			struct timespec now;
			time_t elapsed;
			struct timespec pause = {
				.tv_sec = 0,
				.tv_nsec = 100000000,
			};

			if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "clock_gettime failed: %s", strerror(errno));
				return -1;
			}

			elapsed = now.tv_sec - started.tv_sec;
			if ((unsigned int)elapsed >= timeout) {
				*timed_out = true;
				if (kill(pid, SIGTERM) == -1 && errno != ESRCH) {
					if (err != NULL)
						*err = cellman_xasprintf(NULL,
						    "kill(SIGTERM) failed: %s", strerror(errno));
					return -1;
				}
				(void)nanosleep(&pause, NULL);
				if (waitpid(pid, &status, WNOHANG) != pid)
					(void)kill(pid, SIGKILL);
				(void)waitpid(pid, &status, 0);
				*status_out = status;
				return 0;
			}

			(void)nanosleep(&pause, NULL);
		}
	}
}

/* Return true when a child process exits with status 0. */
static bool
action_status_ok(int status)
{
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Initialize a growable string buffer used by shell command builders. */
static bool
strbuf_init(struct strbuf *sb, char **err)
{
	if (sb == NULL)
		return false;

	memset(sb, 0, sizeof(*sb));
	sb->cap = 256;
	sb->buf = calloc(1, sb->cap);
	if (sb->buf == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return false;
	}

	return true;
}

/* Release the storage owned by a string buffer and reset its fields. */
static void
strbuf_reset(struct strbuf *sb)
{
	if (sb == NULL)
		return;

	free(sb->buf);
	sb->buf = NULL;
	sb->len = 0;
	sb->cap = 0;
}

/* Append a byte range into a string buffer, expanding capacity as needed. */
static bool
strbuf_append_n(struct strbuf *sb, const char *data, size_t n, char **err)
{
	char *next;
	size_t need;
	size_t cap;

	if (sb == NULL || sb->buf == NULL)
		return false;
	if (data == NULL)
		data = "";

	if (sb->len > SIZE_MAX - n - 1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "string buffer overflow");
		return false;
	}

	need = sb->len + n + 1;
	cap = sb->cap;
	while (cap < need) {
		if (cap > SIZE_MAX / 2) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "string buffer overflow");
			return false;
		}
		cap *= 2;
	}

	if (cap != sb->cap) {
		next = realloc(sb->buf, cap);
		if (next == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return false;
		}
		sb->buf = next;
		sb->cap = cap;
	}

	memcpy(sb->buf + sb->len, data, n);
	sb->len += n;
	sb->buf[sb->len] = '\0';
	return true;
}

/* Append a NUL-terminated string into a string buffer. */
static bool
strbuf_append(struct strbuf *sb, const char *data, char **err)
{
	return strbuf_append_n(sb, data, strlen(data), err);
}

/* Quote a value for safe single-quoted POSIX shell interpolation. */
static char *
shell_quote(const char *value, char **err)
{
	struct strbuf sb;
	size_t i;

	if (value == NULL)
		value = "";

	if (!strbuf_init(&sb, err))
		return NULL;
	if (!strbuf_append_n(&sb, "'", 1, err)) {
		strbuf_reset(&sb);
		return NULL;
	}

	for (i = 0; value[i] != '\0'; i++) {
		if (value[i] == '\'') {
			if (!strbuf_append(&sb, "'\\''", err)) {
				strbuf_reset(&sb);
				return NULL;
			}
		} else {
			if (!strbuf_append_n(&sb, &value[i], 1, err)) {
				strbuf_reset(&sb);
				return NULL;
			}
		}
	}

	if (!strbuf_append_n(&sb, "'", 1, err)) {
		strbuf_reset(&sb);
		return NULL;
	}

	return sb.buf;
}

/* Trim leading and trailing ASCII whitespace in-place. */
static char *
trim_ws_inplace(char *s)
{
	char *end;

	if (s == NULL)
		return s;

	while (*s != '\0' && isspace((unsigned char)*s))
		s++;

	end = s + strlen(s);
	while (end > s && isspace((unsigned char)end[-1]))
		end--;
	*end = '\0';

	return s;
}

/* Validate token identifiers (alnum and underscore only). */
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

/* Read an entire text file into a heap buffer. */
static int
read_text_file(const char *path, char **content_out, char **err)
{
	FILE *fp;
	char *buf;
	size_t len;
	size_t cap;

	if (content_out == NULL)
		return -1;
	*content_out = NULL;

	fp = fopen(path, "r");
	if (fp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot read %s: %s", path,
			    strerror(errno));
		return -1;
	}

	cap = 4096;
	len = 0;
	buf = calloc(1, cap);
	if (buf == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		(void)fclose(fp);
		return -1;
	}

	for (;;) {
		size_t nr;

		if (len == cap - 1) {
			size_t next_cap;
			char *next;

			next_cap = cap * 2;
			next = realloc(buf, next_cap);
			if (next == NULL) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "out of memory");
				free(buf);
				(void)fclose(fp);
				return -1;
			}
			memset(next + cap, 0, next_cap - cap);
			buf = next;
			cap = next_cap;
		}

		nr = fread(buf + len, 1, cap - len - 1, fp);
		len += nr;
		buf[len] = '\0';

		if (nr == 0)
			break;
	}

	if (ferror(fp)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot read %s: %s", path,
			    strerror(errno));
		free(buf);
		(void)fclose(fp);
		return -1;
	}

	if (fclose(fp) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot close %s: %s", path,
			    strerror(errno));
		free(buf);
		return -1;
	}

	*content_out = buf;
	return 0;
}

/* Create all missing path components, similar to `mkdir -p`. */
static int
mkdir_p(const char *path, mode_t mode, char **err)
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

/* Ensure the parent directory for a file path exists. */
static int
ensure_parent_dir(const char *path, char **err)
{
	char *dup;
	char *slash;
	int rc;

	dup = cellman_strdup(path, err);
	if (dup == NULL)
		return -1;

	slash = strrchr(dup, '/');
	if (slash == NULL || slash == dup) {
		free(dup);
		return 0;
	}
	*slash = '\0';
	rc = mkdir_p(dup, 0755, err);
	free(dup);
	return rc;
}

/* Resolve an absolute in-cell path into the host-side root path. */
static char *
map_cell_path(const struct apply_runtime *runtime, const char *target, char **err)
{
	if (runtime == NULL || runtime->cell_root == NULL ||
	    target == NULL || target[0] != '/') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "target path must be absolute in apply action: %s",
			    target != NULL ? target : "");
		return NULL;
	}

	return cellman_path_join(runtime->cell_root, target + 1, err);
}

/* Copy one file using read/write loops without external tools. */
static int
copy_file(const char *src, const char *dst, char **err)
{
	int in_fd;
	int out_fd;
	char buf[32768];
	ssize_t nr;

	in_fd = open(src, O_RDONLY);
	if (in_fd < 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "open %s failed: %s", src,
			    strerror(errno));
		return -1;
	}

	out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out_fd < 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "open %s failed: %s", dst,
			    strerror(errno));
		(void)close(in_fd);
		return -1;
	}

	while ((nr = read(in_fd, buf, sizeof(buf))) > 0) {
		size_t off;

		off = 0;
		while (off < (size_t)nr) {
			ssize_t nw;

			nw = write(out_fd, buf + off, (size_t)nr - off);
			if (nw < 0) {
				if (errno == EINTR)
					continue;
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "write %s failed: %s", dst, strerror(errno));
				(void)close(in_fd);
				(void)close(out_fd);
				return -1;
			}
			off += (size_t)nw;
		}
	}

	if (nr < 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "read %s failed: %s", src,
			    strerror(errno));
		(void)close(in_fd);
		(void)close(out_fd);
		return -1;
	}

	if (close(in_fd) != 0 || close(out_fd) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "close failed while copying %s", dst);
		return -1;
	}

	return 0;
}

/* Release run-identity strings captured for action execution. */
static void
run_identity_free(struct run_identity *id)
{
	if (id == NULL)
		return;

	free(id->uid);
	free(id->gid);
	free(id->groups);
	id->uid = NULL;
	id->gid = NULL;
	id->groups = NULL;
}

/* Initialize run identity from environment or current process ids. */
static int
run_identity_init(struct run_identity *id, char **err)
{
	const char *env_uid;
	const char *env_gid;
	const char *env_groups;
	int ng;
	gid_t *groups;
	int i;
	struct strbuf sb;

	if (id == NULL)
		return -1;
	memset(id, 0, sizeof(*id));

	env_uid = getenv("CELLMAN_RUN_UID");
	env_gid = getenv("CELLMAN_RUN_GID");
	env_groups = getenv("CELLMAN_RUN_GROUPS");

	if (env_uid != NULL && env_uid[0] != '\0')
		id->uid = cellman_strdup(env_uid, err);
	else
		id->uid = cellman_xasprintf(NULL, "%lu", (unsigned long)getuid());
	if (id->uid == NULL)
		goto oom;

	if (env_gid != NULL && env_gid[0] != '\0')
		id->gid = cellman_strdup(env_gid, err);
	else
		id->gid = cellman_xasprintf(NULL, "%lu", (unsigned long)getgid());
	if (id->gid == NULL)
		goto oom;

	if (env_groups != NULL && env_groups[0] != '\0') {
		id->groups = cellman_strdup(env_groups, err);
		if (id->groups == NULL)
			goto oom;
		return 0;
	}

	ng = getgroups(0, NULL);
	if (ng <= 0) {
		id->groups = cellman_strdup(id->gid, err);
		if (id->groups == NULL)
			goto oom;
		return 0;
	}

	groups = calloc((size_t)ng, sizeof(*groups));
	if (groups == NULL)
		goto oom;

	if (getgroups(ng, groups) < 0) {
		free(groups);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "getgroups failed: %s",
			    strerror(errno));
		return -1;
	}

	if (!strbuf_init(&sb, err)) {
		free(groups);
		return -1;
	}

	for (i = 0; i < ng; i++) {
		char *g;

		if (i != 0 && !strbuf_append_n(&sb, ",", 1, err)) {
			strbuf_reset(&sb);
			free(groups);
			return -1;
		}
		g = cellman_xasprintf(NULL, "%lu", (unsigned long)groups[i]);
		if (g == NULL || !strbuf_append(&sb, g, err)) {
			free(g);
			strbuf_reset(&sb);
			free(groups);
			goto oom;
		}
		free(g);
	}

	id->groups = sb.buf;
	free(groups);
	return 0;

oom:
	if (err != NULL && *err == NULL)
		*err = cellman_xasprintf(NULL, "out of memory");
	run_identity_free(id);
	return -1;
}

/* Validate owner/group tokens used in chown/chgrp resolution. */
static bool
id_token_valid(const char *value)
{
	size_t i;

	if (value == NULL || value[0] == '\0')
		return false;

	for (i = 0; value[i] != '\0'; i++) {
		if (!(isalnum((unsigned char)value[i]) || value[i] == '_' ||
		    value[i] == '-' || value[i] == '.'))
			return false;
	}

	return true;
}

/* Parse a numeric uid/gid specification into an unsigned long. */
static int
parse_id_value(const char *value, unsigned long *id)
{
	char *end;
	unsigned long v;

	if (value == NULL || value[0] == '\0' || id == NULL)
		return -1;

	errno = 0;
	v = strtoul(value, &end, 10);
	if (errno != 0 || end == value || *end != '\0')
		return -1;

	*id = v;
	return 0;
}

static int
resolve_cell_user_uid(const struct apply_runtime *runtime, const char *user,
    uid_t *uid_out, char **err)
{
	char *passwd_path;
	FILE *fp;
	char *line;
	size_t cap;
	int found;

	if (uid_out == NULL)
		return -1;
	if (runtime == NULL || runtime->cell_root == NULL ||
	    runtime->cell_root[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing cell root");
		return -1;
	}
	if (!id_token_valid(user)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid owner: %s",
			    user != NULL ? user : "");
		return -1;
	}

	passwd_path = cellman_xasprintf(NULL, "%s/etc/passwd", runtime->cell_root);
	if (passwd_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}
	if (access(passwd_path, R_OK) != 0) {
		free(passwd_path);
		passwd_path = cellman_xasprintf(NULL, "%s/etc/master.passwd",
		    runtime->cell_root);
		if (passwd_path == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return -1;
		}
	}

	fp = fopen(passwd_path, "r");
	if (fp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cannot open cell passwd database %s: %s", passwd_path,
			    strerror(errno));
		free(passwd_path);
		return -1;
	}

	line = NULL;
	cap = 0;
	found = 0;
	while (getline(&line, &cap, fp) != -1) {
		char *dup;
		char *saveptr;
		char *name;
		char *uid_s;
		unsigned long uid_v;

		if (line[0] == '#' || line[0] == '\n')
			continue;

		dup = cellman_strdup(line, NULL);
		if (dup == NULL)
			continue;

		saveptr = NULL;
		name = strtok_r(dup, ":\n", &saveptr);
		(void)strtok_r(NULL, ":\n", &saveptr);
		uid_s = strtok_r(NULL, ":\n", &saveptr);

		if (name != NULL && uid_s != NULL && strcmp(name, user) == 0 &&
		    parse_id_value(uid_s, &uid_v) == 0) {
			*uid_out = (uid_t)uid_v;
			found = 1;
			free(dup);
			break;
		}

		free(dup);
	}

	free(line);
	(void)fclose(fp);
	if (!found) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cannot resolve owner '%s' in %s", user, passwd_path);
		free(passwd_path);
		return -1;
	}

	free(passwd_path);
	return 0;
}

static int
resolve_cell_group_gid(const struct apply_runtime *runtime, const char *group,
    gid_t *gid_out, char **err)
{
	char *group_path;
	FILE *fp;
	char *line;
	size_t cap;
	int found;

	if (gid_out == NULL)
		return -1;
	if (runtime == NULL || runtime->cell_root == NULL ||
	    runtime->cell_root[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing cell root");
		return -1;
	}
	if (!id_token_valid(group)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid group: %s",
			    group != NULL ? group : "");
		return -1;
	}

	group_path = cellman_xasprintf(NULL, "%s/etc/group", runtime->cell_root);
	if (group_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	fp = fopen(group_path, "r");
	if (fp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cannot open cell group database %s: %s", group_path,
			    strerror(errno));
		free(group_path);
		return -1;
	}

	line = NULL;
	cap = 0;
	found = 0;
	while (getline(&line, &cap, fp) != -1) {
		char *dup;
		char *saveptr;
		char *name;
		char *gid_s;
		unsigned long gid_v;

		if (line[0] == '#' || line[0] == '\n')
			continue;

		dup = cellman_strdup(line, NULL);
		if (dup == NULL)
			continue;

		saveptr = NULL;
		name = strtok_r(dup, ":\n", &saveptr);
		(void)strtok_r(NULL, ":\n", &saveptr);
		gid_s = strtok_r(NULL, ":\n", &saveptr);

		if (name != NULL && gid_s != NULL && strcmp(name, group) == 0 &&
		    parse_id_value(gid_s, &gid_v) == 0) {
			*gid_out = (gid_t)gid_v;
			found = 1;
			free(dup);
			break;
		}

		free(dup);
	}

	free(line);
	(void)fclose(fp);
	if (!found) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cannot resolve group '%s' in %s", group, group_path);
		free(group_path);
		return -1;
	}

	free(group_path);
	return 0;
}

static int
resolve_uid(const struct apply_runtime *runtime, const struct run_identity *id,
    const char *spec, uid_t *uid, char **err)
{
	unsigned long v;
	const char *val;

	if (uid == NULL)
		return -1;

	val = spec;
	if (val == NULL || val[0] == '\0') {
		*uid = (uid_t)-1;
		return 0;
	}
	if (id != NULL && strcmp(val, "@run_uid") == 0)
		val = id->uid;

	if (parse_id_value(val, &v) == 0) {
		*uid = (uid_t)v;
		return 0;
	}

	if (runtime != NULL)
		return resolve_cell_user_uid(runtime, val, uid, err);

	if (err != NULL)
		*err = cellman_xasprintf(NULL, "cannot resolve owner: %s", val);
	return -1;
}

static int
resolve_gid(const struct apply_runtime *runtime, const struct run_identity *id,
    const char *spec, gid_t *gid, char **err)
{
	unsigned long v;
	const char *val;

	if (gid == NULL)
		return -1;

	val = spec;
	if (val == NULL || val[0] == '\0') {
		*gid = (gid_t)-1;
		return 0;
	}
	if (id != NULL && strcmp(val, "@run_gid") == 0)
		val = id->gid;

	if (parse_id_value(val, &v) == 0) {
		*gid = (gid_t)v;
		return 0;
	}

	if (runtime != NULL)
		return resolve_cell_group_gid(runtime, val, gid, err);

	if (err != NULL)
		*err = cellman_xasprintf(NULL, "cannot resolve group: %s", val);
	return -1;
}

static int
apply_mode_owner_group(const char *path, const char *mode_s, const char *owner_s,
    const char *group_s, const struct apply_runtime *runtime, char **err)
{
	uid_t uid;
	gid_t gid;

	if (runtime->dry_run)
		return 0;

	if (mode_s != NULL && mode_s[0] != '\0') {
		unsigned long m;
		char *end;

		errno = 0;
		m = strtoul(mode_s, &end, 8);
		if (errno != 0 || end == mode_s || *end != '\0') {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "invalid mode: %s", mode_s);
			return -1;
		}
		if (chmod(path, (mode_t)m) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "chmod %s failed: %s", path,
				    strerror(errno));
			return -1;
		}
	}

	uid = (uid_t)-1;
	gid = (gid_t)-1;
	if (resolve_uid(runtime, &runtime->run_id, owner_s, &uid, err) != 0 ||
	    resolve_gid(runtime, &runtime->run_id, group_s, &gid, err) != 0)
		return -1;

	if ((uid != (uid_t)-1 || gid != (gid_t)-1) && chown(path, uid, gid) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "chown %s failed: %s", path,
			    strerror(errno));
		return -1;
	}

	if (runtime->verbose)
		cellman_log_info("applied ownership/mode: %s", path);

	return 0;
}

/* Token merge/build layer is intentionally split out for readability. */
#include "apply_exec_tokens.inc"

/* Action handler layer is intentionally split out for readability. */
#include "apply_exec_actions.inc"

static int
apply_runtime_init(struct apply_runtime *runtime, const struct cellman_doc *doc,
    const char *cell_name, const char *cell_root, bool dry_run, bool verbose,
    bool forward_output, char **err)
{
	struct utsname uts;

	if (runtime == NULL || doc == NULL || doc->kind != CELLMAN_DOC_APPLY) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid apply runtime init");
		return -1;
	}

	memset(runtime, 0, sizeof(*runtime));
	runtime->dry_run = dry_run;
	runtime->verbose = verbose;
	runtime->forward_output = forward_output;

	runtime->cell_name = cellman_strdup(
	    cell_name != NULL && cell_name[0] != '\0' ? cell_name : doc->u.apply.name,
	    err);
	if (runtime->cell_name == NULL)
		goto fail;

	if (cell_root != NULL && cell_root[0] != '\0') {
		runtime->cell_root = cellman_strdup(cell_root, err);
	} else {
		runtime->cell_root = cellman_xasprintf(NULL,
		    "/var/cellman/cells/%s/root", runtime->cell_name);
	}
	if (runtime->cell_root == NULL) {
		if (err != NULL && *err == NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}

	runtime->manifest_dir = cellman_strdup(
	    doc->source_dir != NULL ? doc->source_dir : ".", err);
	if (runtime->manifest_dir == NULL)
		goto fail;

	if (uname(&uts) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "uname failed: %s", strerror(errno));
		goto fail;
	}

	runtime->release = cellman_strdup(uts.release, err);
	runtime->arch = cellman_strdup(uts.machine, err);
	if (runtime->release == NULL || runtime->arch == NULL)
		goto fail;

	if (resolve_runtime_pkg_path(runtime->release, runtime->arch,
	    &runtime->pkg_path, err) != 0)
		goto fail;

	if (run_identity_init(&runtime->run_id, err) != 0)
		goto fail;

	return 0;

fail:
	apply_runtime_free(runtime);
	return -1;
}

/* Release all allocations owned by apply runtime state. */
static void
apply_runtime_free(struct apply_runtime *runtime)
{
	if (runtime == NULL)
		return;

	free(runtime->cell_name);
	free(runtime->cell_root);
	free(runtime->manifest_dir);
	free(runtime->release);
	free(runtime->arch);
	free(runtime->pkg_path);
	run_identity_free(&runtime->run_id);
	memset(runtime, 0, sizeof(*runtime));
}

int
cellman_apply_run_named(const struct cellman_doc *doc,
    const struct cellman_tokens *tokens, const char *cell_name,
    const char *cell_root, bool dry_run, bool verbose, bool forward_output,
    char **err)
{
	struct apply_runtime runtime;
	struct cellman_tokens runtime_tokens;
	size_t i;

	if (err != NULL)
		*err = NULL;

	if (doc == NULL || doc->kind != CELLMAN_DOC_APPLY) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "apply runner requires apply document");
		return -1;
	}

	if (apply_runtime_init(&runtime, doc, cell_name, cell_root, dry_run,
	    verbose, forward_output, err) != 0)
		return -1;

	if (runtime_tokens_build(&runtime, tokens, &runtime_tokens, err) != 0) {
		apply_runtime_free(&runtime);
		return -1;
	}

	if (ensure_cell_certctl_rehash(&runtime, err) != 0) {
		cellman_tokens_free(&runtime_tokens);
		apply_runtime_free(&runtime);
		return -1;
	}

	/*
	 * Action dispatch is intentionally centralized here so additional frontends
	 * (for example future UI-integrated paths) can reuse one execution engine.
	 */

	for (i = 0; i < doc->u.apply.actions.len; i++) {
		const struct cellman_action *action;
		int rc;

		action = &doc->u.apply.actions.items[i];
		switch (action->kind) {
		case CELLMAN_ACTION_PKG:
			rc = run_pkg_action(&action->u.pkg, &runtime_tokens, &runtime,
			    err);
			break;
		case CELLMAN_ACTION_EXEC:
			rc = run_exec_action(&action->u.exec, &runtime_tokens, &runtime,
			    err);
			break;
		case CELLMAN_ACTION_DIR:
			rc = run_dir_action(&action->u.dir, &runtime_tokens, &runtime,
			    err);
			break;
		case CELLMAN_ACTION_LINE:
			rc = run_line_action(&action->u.line, &runtime_tokens, &runtime,
			    err);
			break;
		case CELLMAN_ACTION_SYMLINK:
			rc = run_symlink_action(&action->u.symlink, &runtime_tokens,
			    &runtime, err);
			break;
		case CELLMAN_ACTION_COPY:
			rc = run_copy_action(doc, &action->u.copy, &runtime_tokens,
			    &runtime, err);
			break;
		case CELLMAN_ACTION_UNTAR:
			rc = run_untar_action(doc, &action->u.untar, &runtime_tokens,
			    &runtime, err);
			break;
		case CELLMAN_ACTION_FILE:
			rc = run_file_action(&action->u.file, &runtime_tokens, &runtime,
			    err);
			break;
		case CELLMAN_ACTION_PATCH:
			rc = run_patch_action(&action->u.patch, &runtime_tokens, &runtime,
			    err);
			break;
		case CELLMAN_ACTION_TEMPLATE:
			rc = run_template_action(doc, &action->u.templ, &runtime_tokens,
			    &runtime, err);
			break;
		case CELLMAN_ACTION_SCRIPT:
			rc = run_script_action(doc, &action->u.script, &runtime_tokens,
			    &runtime, err);
			break;
		case CELLMAN_ACTION_NONE:
		default:
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "runner does not execute action type '%s'",
				    cellman_action_kind_name(action->kind));
			rc = -1;
			break;
		}

		if (rc != 0) {
			char *prefixed;

			if (err != NULL && *err != NULL) {
				prefixed = cellman_xasprintf(NULL,
				    "apply %s action %zu (%s): %s",
				    doc->u.apply.name != NULL ? doc->u.apply.name : "",
				    i + 1, cellman_action_kind_name(action->kind), *err);
				if (prefixed != NULL) {
					free(*err);
					*err = prefixed;
				}
			}
			cellman_tokens_free(&runtime_tokens);
			apply_runtime_free(&runtime);
			return -1;
		}
	}

	cellman_tokens_free(&runtime_tokens);
	apply_runtime_free(&runtime);
	return 0;
}

int
cellman_apply_run_plan(const struct cellman_doc *doc,
    const struct cellman_tokens *tokens, bool dry_run, char **err)
{
	if (doc == NULL || doc->kind != CELLMAN_DOC_APPLY) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "apply runner requires apply document");
		return -1;
	}

	return cellman_apply_run_named(doc, tokens, doc->u.apply.name, NULL,
	    dry_run, true, true, err);
}
