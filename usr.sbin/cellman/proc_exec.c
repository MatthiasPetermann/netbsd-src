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
 * Layer: cellman shared process execution utility layer.
 *
 * Provide reusable subprocess execution/capture helpers and PATH command
 * discovery.
 *
 * Extension guidance: Add generic process/spawn helpers here; keep
 * command/action-specific process composition in higher layers.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "cellman.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Count argv entries until the trailing NULL terminator.
 */
static size_t
exec_argv_count(const char *const argv[])
{
	size_t argc;

	argc = 0;
	if (argv == NULL)
		return 0;

	while (argv[argc] != NULL)
		argc++;

	return argc;
}

/*
 * Duplicate one argv array so child exec handling never mutates caller memory.
 */
static char **
exec_argv_dup(const char *const argv[], char **err)
{
	char **dup;
	size_t argc;
	size_t i;

	argc = exec_argv_count(argv);
	dup = calloc(argc + 1, sizeof(*dup));
	if (dup == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return NULL;
	}

	for (i = 0; i < argc; i++) {
		dup[i] = strdup(argv[i]);
		if (dup[i] == NULL) {
			size_t j;

			for (j = 0; j < i; j++)
				free(dup[j]);
			free(dup);
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return NULL;
		}
	}
	dup[argc] = NULL;

	return dup;
}

/*
 * Wait for one child and return a stable status value.
 */
static int
wait_child_status(pid_t pid, int *status_out, char **err)
{
	int status;

	if (status_out == NULL)
		return -1;

	for (;;) {
		if (waitpid(pid, &status, 0) != -1)
			break;
		if (errno != EINTR) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "waitpid failed: %s",
				    strerror(errno));
			return -1;
		}
	}

	*status_out = status;
	return 0;
}

/*
 * Execute one argv vector and require a zero exit status.
 */
int
cellman_exec_run(const char *const argv[], char **err)
{
	pid_t pid;
	int status;

	if (argv == NULL || argv[0] == NULL || argv[0][0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid command");
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "fork failed: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		char **exec_argv;

		exec_argv = exec_argv_dup(argv, NULL);
		if (exec_argv == NULL)
			_exit(127);

		execvp(exec_argv[0], exec_argv);
		_exit(127);
	}

	if (wait_child_status(pid, &status, err) != 0)
		return -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "command failed: %s", argv[0]);
		return -1;
	}

	return 0;
}

/*
 * Execute one argv vector while capturing merged stdout and stderr output.
 */
int
cellman_exec_run_capture(const char *const argv[], char **out, char **err)
{
	int pipefd[2];
	pid_t pid;
	int status;
	struct stat st;
	char *buf;
	size_t len;
	size_t cap;
	ssize_t nr;

	if (out == NULL)
		return -1;
	*out = NULL;

	if (argv == NULL || argv[0] == NULL || argv[0][0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid command");
		return -1;
	}

	if (pipe(pipefd) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "pipe failed: %s", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		(void)close(pipefd[0]);
		(void)close(pipefd[1]);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "fork failed: %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		char **exec_argv;

		(void)close(pipefd[0]);
		(void)dup2(pipefd[1], STDOUT_FILENO);
		(void)dup2(pipefd[1], STDERR_FILENO);
		(void)close(pipefd[1]);

		exec_argv = exec_argv_dup(argv, NULL);
		if (exec_argv == NULL)
			_exit(127);

		execvp(exec_argv[0], exec_argv);
		_exit(127);
	}

	(void)close(pipefd[1]);
	if (fstat(pipefd[0], &st) == 0 && st.st_size > 0)
		cap = (size_t)st.st_size + 1;
	else
		cap = 1024;

	buf = calloc(1, cap);
	if (buf == NULL) {
		(void)close(pipefd[0]);
		(void)waitpid(pid, NULL, 0);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	len = 0;
	for (;;) {
		if (len == cap - 1) {
			size_t next_cap;
			char *next;

			next_cap = cap * 2;
			next = realloc(buf, next_cap);
			if (next == NULL) {
				free(buf);
				(void)close(pipefd[0]);
				(void)waitpid(pid, NULL, 0);
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "out of memory");
				return -1;
			}
			buf = next;
			cap = next_cap;
		}

		nr = read(pipefd[0], buf + len, cap - len - 1);
		if (nr < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			(void)close(pipefd[0]);
			(void)waitpid(pid, NULL, 0);
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "read failed: %s",
				    strerror(errno));
			return -1;
		}
		if (nr == 0)
			break;
		len += (size_t)nr;
		buf[len] = '\0';
	}

	(void)close(pipefd[0]);
	if (wait_child_status(pid, &status, err) != 0) {
		free(buf);
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s", buf);
		free(buf);
		return -1;
	}

	*out = buf;
	return 0;
}

/*
 * Check whether one executable name is reachable through PATH lookup.
 */
bool
cellman_exec_command_exists(const char *cmd)
{
	const char *path_env;
	char *path_copy;
	char *dir;
	char *saveptr;
	bool found;

	if (cmd == NULL || cmd[0] == '\0')
		return false;

	if (strchr(cmd, '/') != NULL)
		return access(cmd, X_OK) == 0;

	path_env = getenv("PATH");
	if (path_env == NULL || path_env[0] == '\0')
		path_env = "/sbin:/bin:/usr/sbin:/usr/bin";

	path_copy = cellman_strdup(path_env, NULL);
	if (path_copy == NULL)
		return false;

	found = false;
	saveptr = NULL;
	dir = strtok_r(path_copy, ":", &saveptr);
	while (dir != NULL) {
		char *candidate;
		const char *base;

		base = dir[0] == '\0' ? "." : dir;
		candidate = cellman_xasprintf(NULL, "%s/%s", base, cmd);
		if (candidate != NULL) {
			if (access(candidate, X_OK) == 0)
				found = true;
			free(candidate);
			if (found)
				break;
		}
		dir = strtok_r(NULL, ":", &saveptr);
	}

	free(path_copy);
	return found;
}
