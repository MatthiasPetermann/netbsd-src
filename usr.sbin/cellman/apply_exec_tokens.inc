/*	$NetBSD$	*/
/*-
 * Copyright (c) 2026
 * The NetBSD Foundation, Inc.
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
 *
 * secmodel_cell, cellctl, and cellman designed and implemented by
 * Matthias Petermann, inspired by FreeBSD cells.
 */

/*
 * Layer: cellman control plane, apply token composition layer.
 *
 * This file is included by apply_exec.c to keep one translation unit while
 * separating token merge/build responsibilities from action handlers.
 *
 * Put extensions here when they change token validation, token merge sources,
 * or runtime token assembly semantics used by apply actions.
 */

static int
tokens_set_checked(struct cellman_tokens *tokens, const char *key,
    const char *value, char **err)
{
	if (!token_name_valid(key)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid token name: %s",
			    key != NULL ? key : "");
		return -1;
	}

	return cellman_tokens_set(tokens, key, value, err);
}

static int
tokens_clone(struct cellman_tokens *dst, const struct cellman_tokens *src,
    char **err)
{
	size_t i;

	if (dst == NULL)
		return -1;

	cellman_tokens_init(dst);
	if (src == NULL)
		return 0;

	for (i = 0; i < src->pairs.len; i++) {
		if (tokens_set_checked(dst, src->pairs.items[i].key,
		    src->pairs.items[i].value, err) != 0) {
			cellman_tokens_free(dst);
			return -1;
		}
	}

	return 0;
}

static int
tokens_merge_map(struct cellman_tokens *dst, const struct cellman_kv_list *map,
    char **err)
{
	size_t i;

	if (dst == NULL || map == NULL)
		return 0;

	for (i = 0; i < map->len; i++) {
		if (tokens_set_checked(dst, map->items[i].key,
		    map->items[i].value, err) != 0)
			return -1;
	}

	return 0;
}

/* Parse newline-delimited `key=value` text and merge into token map. */
static int
tokens_merge_text(struct cellman_tokens *dst, const char *text, char **err)
{
	const char *p;

	if (dst == NULL || text == NULL || text[0] == '\0')
		return 0;

	p = text;
	for (;;) {
		const char *line_end;
		size_t len;
		char *raw;
		char *line;
		char *eq;
		char *key;
		char *value;

		line_end = strchr(p, '\n');
		len = line_end != NULL ? (size_t)(line_end - p) : strlen(p);

		raw = cellman_strndup(p, len, err);
		if (raw == NULL)
			return -1;

		line = trim_ws_inplace(raw);
		if (line[0] != '\0' && line[0] != '#') {
			eq = strchr(line, '=');
			if (eq == NULL || eq == line) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "invalid template token line (expected key=value): %s",
					    line);
				free(raw);
				return -1;
			}
			*eq = '\0';
			key = trim_ws_inplace(line);
			value = trim_ws_inplace(eq + 1);
			if (key[0] == '\0') {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "invalid template token line with empty key");
				free(raw);
				return -1;
			}
			if (tokens_set_checked(dst, key, value, err) != 0) {
				free(raw);
				return -1;
			}
		}

		free(raw);
		if (line_end == NULL)
			break;
		p = line_end + 1;
	}

	return 0;
}

static int
tokens_merge_env_map(struct cellman_tokens *dst,
    const struct cellman_kv_list *map, char **err)
{
	size_t i;

	if (dst == NULL || map == NULL)
		return 0;

	for (i = 0; i < map->len; i++) {
		const char *token_name;
		const char *env_name;
		const char *env_value;

		token_name = map->items[i].key;
		env_name = map->items[i].value;
		if (!token_name_valid(token_name)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid token name in token_env: %s",
				    token_name != NULL ? token_name : "");
			return -1;
		}
		if (!cellman_env_name_valid(env_name)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid environment variable name in token_env: %s",
				    env_name != NULL ? env_name : "");
			return -1;
		}

		env_value = getenv(env_name);
		if (env_value == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "environment variable not set for token_env: %s",
				    env_name);
			return -1;
		}

		if (tokens_set_checked(dst, token_name, env_value, err) != 0)
			return -1;
	}

	return 0;
}

static int
runtime_tokens_build(const struct apply_runtime *runtime,
    const struct cellman_tokens *overrides, struct cellman_tokens *out,
    char **err)
{
	size_t i;

	if (out == NULL || runtime == NULL)
		return -1;

	cellman_tokens_init(out);

	if (tokens_set_checked(out, "cell_name", runtime->cell_name, err) != 0 ||
	    tokens_set_checked(out, "cell_root", runtime->cell_root, err) != 0 ||
	    tokens_set_checked(out, "manifest_dir", runtime->manifest_dir, err) != 0 ||
	    tokens_set_checked(out, "release", runtime->release, err) != 0 ||
	    tokens_set_checked(out, "arch", runtime->arch, err) != 0 ||
	    tokens_set_checked(out, "run_uid", runtime->run_id.uid, err) != 0 ||
	    tokens_set_checked(out, "run_gid", runtime->run_id.gid, err) != 0 ||
	    tokens_set_checked(out, "run_groups", runtime->run_id.groups, err) != 0) {
		cellman_tokens_free(out);
		return -1;
	}

	if (overrides == NULL)
		return 0;

	for (i = 0; i < overrides->pairs.len; i++) {
		if (tokens_set_checked(out, overrides->pairs.items[i].key,
		    overrides->pairs.items[i].value, err) != 0) {
			cellman_tokens_free(out);
			return -1;
		}
	}

	return 0;
}

static int
render_template_value(const char *input, const struct cellman_tokens *tokens,
    char **output, char **err)
{
	return cellman_template_expand(input, tokens, output, err);
}

static int
render_optional_value(const char *input, const struct cellman_tokens *tokens,
    char **output, char **err)
{
	if (output == NULL)
		return -1;
	*output = NULL;

	if (input == NULL || input[0] == '\0')
		return 0;

	return render_template_value(input, tokens, output, err);
}

static int
resolve_source_path(const struct cellman_doc *doc, const char *source,
    char **resolved, char **err)
{
	if (resolved == NULL)
		return -1;
	*resolved = NULL;

	if (source == NULL || source[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "empty source path");
		return -1;
	}

	if (source[0] == '/') {
		*resolved = cellman_strdup(source, err);
		return *resolved != NULL ? 0 : -1;
	}

	*resolved = cellman_path_join(
	    doc != NULL && doc->source_dir != NULL ? doc->source_dir : ".",
	    source, err);
	return *resolved != NULL ? 0 : -1;
}

static int
run_spawn(char *const argv[], const struct cellman_kv_list *env,
    const char *cwd, const char *stdin_data, size_t stdin_len,
    unsigned int timeout_seconds, bool forward_output, int *status_out,
    bool *timed_out, char **err)
{
	int inpipe[2];
	int nullfd;
	pid_t pid;
	bool use_stdin;

	if (status_out == NULL || timed_out == NULL)
		return -1;

	use_stdin = stdin_data != NULL;
	if (use_stdin) {
		if (pipe(inpipe) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "pipe failed: %s", strerror(errno));
			return -1;
		}
	}

	pid = fork();
	if (pid == -1) {
		if (use_stdin) {
			(void)close(inpipe[0]);
			(void)close(inpipe[1]);
		}
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "fork failed: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		size_t i;

		nullfd = -1;

		if (use_stdin) {
			(void)close(inpipe[1]);
			if (dup2(inpipe[0], STDIN_FILENO) == -1)
				_exit(126);
			(void)close(inpipe[0]);
		}

		if (!forward_output) {
			nullfd = open("/dev/null", O_WRONLY);
			if (nullfd == -1)
				_exit(126);
			if (dup2(nullfd, STDOUT_FILENO) == -1 ||
			    dup2(nullfd, STDERR_FILENO) == -1)
				_exit(126);
			(void)close(nullfd);
		}

		if (cwd != NULL && cwd[0] != '\0' && chdir(cwd) == -1)
			_exit(126);

		if (env != NULL) {
			for (i = 0; i < env->len; i++) {
				if (setenv(env->items[i].key, env->items[i].value, 1) != 0)
					_exit(126);
			}
		}

		execvp(argv[0], argv);
		_exit(127);
	}

	if (use_stdin) {
		size_t off;

		(void)close(inpipe[0]);
		off = 0;
		while (off < stdin_len) {
			ssize_t wr;

			wr = write(inpipe[1], stdin_data + off, stdin_len - off);
			if (wr < 0) {
				if (errno == EINTR)
					continue;
				(void)close(inpipe[1]);
				(void)waitpid(pid, NULL, 0);
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "write to child failed: %s", strerror(errno));
				return -1;
			}
			off += (size_t)wr;
		}
		(void)close(inpipe[1]);
	}

	if (wait_for_child(pid, timeout_seconds, status_out, timed_out, err) != 0)
		return -1;

	return 0;
}

static int
run_spawn_checked(char *const argv[], const struct cellman_kv_list *env,
    const char *cwd, const char *stdin_data, size_t stdin_len,
    unsigned int timeout_seconds, bool ignore_exit, bool forward_output,
    char **err)
{
	int status;
	bool timed_out;

	if (run_spawn(argv, env, cwd, stdin_data, stdin_len, timeout_seconds,
	    forward_output, &status, &timed_out, err) != 0)
		return -1;

	if (timed_out) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "command timed out after %u seconds", timeout_seconds);
		return -1;
	}

	if (action_status_ok(status))
		return 0;

	if (ignore_exit) {
		cellman_log_warn("command failed but ignore_exit=true (status=%d)",
		    status);
		return 0;
	}

	if (WIFEXITED(status)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "command failed with exit status %d", WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "command terminated by signal %d", WTERMSIG(status));
	} else {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "command failed (status=%d)", status);
	}

	return -1;
}

static int
resolve_runtime_pkg_path(const char *release, const char *arch,
    char **pkg_path_out, char **err)
{
	const char *env_pkg_path;
	char *conf_pkg_path;
	char *pkg_release;
	char *pkg_path;

	if (pkg_path_out == NULL)
		return -1;
	*pkg_path_out = NULL;

	env_pkg_path = getenv("PKG_PATH");
	if (env_pkg_path != NULL && env_pkg_path[0] != '\0') {
		*pkg_path_out = cellman_strdup(env_pkg_path, err);
		return *pkg_path_out != NULL ? 0 : -1;
	}

	conf_pkg_path = NULL;
	if (cellman_conf_get("PKG_PATH", &conf_pkg_path, err) != 0)
		return -1;
	if (conf_pkg_path != NULL && conf_pkg_path[0] != '\0') {
		*pkg_path_out = conf_pkg_path;
		return 0;
	}
	free(conf_pkg_path);

	pkg_release = cellman_release_major_minor(release != NULL ? release : "",
	    err);
	if (pkg_release == NULL)
		return -1;

	pkg_path = cellman_xasprintf(NULL,
	    "http://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/%s/%s/All",
	    arch != NULL ? arch : "", pkg_release);
	free(pkg_release);
	if (pkg_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	*pkg_path_out = pkg_path;
	return 0;
}

/* Append a validated `export KEY='value';` fragment to shell command text. */
static int
append_export(struct strbuf *cmd, const char *key, const char *value, char **err)
{
	char *qvalue;

	if (!cellman_env_name_valid(key)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid env name: %s",
			    key != NULL ? key : "");
		return -1;
	}

	qvalue = shell_quote(value, err);
	if (qvalue == NULL)
		return -1;

	if (!strbuf_append(cmd, "export ", err) ||
	    !strbuf_append(cmd, key, err) ||
	    !strbuf_append(cmd, "=", err) ||
	    !strbuf_append(cmd, qvalue, err) ||
	    !strbuf_append(cmd, "; ", err)) {
		free(qvalue);
		return -1;
	}

	free(qvalue);
	return 0;
}

static int
run_cell_shell_command(const struct apply_runtime *runtime, const char *command,
    const char *cwd, const struct cellman_kv_list *extra_env,
    const char *stdin_data, size_t stdin_len, unsigned int timeout_seconds,
    bool ignore_exit, char **err)
{
	struct strbuf wrapped;
	char *qcwd;
	char *argv_exec[7];
	char arg_cellctl[] = "cellctl";
	char arg_exec[] = "exec";
	char arg_sh[] = "/bin/sh";
	char arg_c[] = "-c";
	size_t i;
	int rc;

	/*
	 * Keep one shell entrypoint for cell execution so action implementations
	 * do not duplicate run-identity export, cwd handling, or stdin plumbing.
	 */

	qcwd = NULL;
	if (runtime == NULL || runtime->cell_name == NULL ||
	    command == NULL || command[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell shell command");
		return -1;
	}

	if (!strbuf_init(&wrapped, err))
		return -1;

	if (append_export(&wrapped, "PKG_PATH", runtime->pkg_path, err) != 0 ||
	    append_export(&wrapped, "CELLMAN_RUN_UID", runtime->run_id.uid,
	    err) != 0 ||
	    append_export(&wrapped, "CELLMAN_RUN_GID", runtime->run_id.gid, err) != 0 ||
	    append_export(&wrapped, "CELLMAN_RUN_GROUPS", runtime->run_id.groups,
	    err) != 0)
		goto fail;

	if (extra_env != NULL) {
		for (i = 0; i < extra_env->len; i++) {
			if (append_export(&wrapped, extra_env->items[i].key,
			    extra_env->items[i].value, err) != 0)
				goto fail;
		}
	}

	if (cwd != NULL && cwd[0] != '\0') {
		qcwd = shell_quote(cwd, err);
		if (qcwd == NULL)
			goto fail;
		if (!strbuf_append(&wrapped, "cd ", err) ||
		    !strbuf_append(&wrapped, qcwd, err) ||
		    !strbuf_append(&wrapped, " || exit 1; ", err))
			goto fail;
	}

	if (!strbuf_append(&wrapped, command, err))
		goto fail;

	if (runtime->verbose)
		cellman_log_info("cell exec %s: %s", runtime->cell_name, command);

	argv_exec[0] = arg_cellctl;
	argv_exec[1] = arg_exec;
	argv_exec[2] = runtime->cell_name;
	argv_exec[3] = arg_sh;
	argv_exec[4] = arg_c;
	argv_exec[5] = wrapped.buf;
	argv_exec[6] = NULL;

	rc = run_spawn_checked(argv_exec, NULL, NULL, stdin_data, stdin_len,
	    timeout_seconds, ignore_exit, runtime->forward_output, err);

	free(qcwd);
	strbuf_reset(&wrapped);
	return rc;

fail:
	free(qcwd);
	strbuf_reset(&wrapped);
	return -1;
}

/* Refresh certctl hashes inside the target cell before apply actions run. */
static int
ensure_cell_certctl_rehash(const struct apply_runtime *runtime, char **err)
{
	const char *cmd;

	if (runtime == NULL)
		return -1;
	if (runtime->dry_run)
		return 0;

	cmd = "if [ -x /usr/sbin/certctl ]; then /usr/sbin/certctl rehash; "
	    "else echo 'missing /usr/sbin/certctl in cell' >&2; exit 1; fi";
	if (run_cell_shell_command(runtime, cmd, NULL, NULL, NULL, 0, 0, false,
	    err) != 0) {
		if (err != NULL && *err != NULL) {
			char *prefixed;

			prefixed = cellman_xasprintf(NULL,
			    "certctl rehash failed in cell %s: %s",
			    runtime->cell_name != NULL ? runtime->cell_name : "",
			    *err);
			if (prefixed != NULL) {
				free(*err);
				*err = prefixed;
			}
		}
		return -1;
	}

	return 0;
}
