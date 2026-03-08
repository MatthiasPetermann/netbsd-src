/* $NetBSD$ */
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
 * secmodel_cell, cellctl, and cellmgr designed and implemented by
 * Matthias Petermann, inspired by FreeBSD cells.
 */

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD$");
#endif /* not lint */

#include <sys/types.h>
#include <sys/cell.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <paths.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define CELLCTL_LOG_MAX 511
#define CELLCTL_TAG_MAX 63

static void	usage(void) __dead;

static void	cell_exec(cellid_t, const char *, char *[]);
static void	cell_run_monitor_once(cellid_t, const char *, int, int, pid_t,
			    int, int, int *);
static void	cell_supervise_loop(cellid_t, const char *, const char *,
			    const char *, char *[], int, int, int);
static void	cell_spawn_detached(cellid_t, const char *, const char *,
			    const char *, char *[], int, int, int);
static int	parse_log_facility(const char *);
static int	parse_log_level(const char *);
static int	parse_log_level_arg(const char *);
static uint32_t	parse_profile(const char *);
static void	parse_port_list(struct cell_create *, const char *);
static void	sanitize_field(const char *, char *, size_t);
static void	cell_stats(bool, bool, bool);
static void	prom_escape_label(const char *, char *, size_t);
static bool	cell_lookup_by_name(const char *, struct cell_info *);
static bool	cell_lookup_by_id(cellid_t, struct cell_info *);
static void	log_stream_data(int, const char *, cellid_t, const char *,
		    char *, size_t *, const char *, size_t);
static cellid_t	resolve_cell_target(const char *, struct cell_info *);

static volatile sig_atomic_t monitor_shutdown_requested;

/*
 * Signal handler used by supervise mode monitor process.
 *
 * We only set a flag here to keep the handler async-signal-safe; the actual
 * shutdown sequence (TERM/KILL and wait logic) is performed in the main loop.
 */
static void
monitor_signal_handler(int signo)
{
	(void)signo;
	monitor_shutdown_requested = 1;
}

static struct cell_info *
cell_fetch_list(size_t *countp)
{
	struct cell_info *entries;
	size_t len;

	/*
	 * Two-pass sysctl pattern: first query required length, then allocate and
	 * fetch the current cell table snapshot.
	 */
	len = 0;
	if (sysctlbyname("security.models.cell.list", NULL, &len,
	    NULL, 0) == -1)
		err(1, "list cells");

	if (len == 0) {
		*countp = 0;
		return NULL;
	}

	if (len % sizeof(*entries) != 0)
		errx(1, "unexpected cell list length");

	entries = calloc(1, len);
	if (entries == NULL)
		err(1, "calloc");

	if (sysctlbyname("security.models.cell.list", entries, &len,
	    NULL, 0) == -1)
		err(1, "list cells");

	*countp = len / sizeof(*entries);
	return entries;
}

static cellid_t
cell_create(const struct cell_create *create)
{
	cellid_t id;
	struct cell_create req;
	size_t len;

	/* Structured create payload is mandatory in the cell-native ABI. */
	id = 0;
	if (create == NULL)
		errx(1, "internal error: create payload is required");

	req = *create;
	len = sizeof(req);
	if (sysctlbyname("security.models.cell.create", &req, &len,
	    &req, sizeof(req)) == -1)
		err(1, "create cell");
	id = req.jc_id;

	return id;
}

static void
cell_destroy(cellid_t id)
{
	if (sysctlbyname("security.models.cell.destroy", NULL, 0,
	    &id, sizeof(id)) == -1)
		err(1, "destroy cell %" PRIu32, id);
}

static void
cell_enter(cellid_t id)
{
	if (sysctlbyname("security.models.cell.id", NULL, 0,
	    &id, sizeof(id)) == -1)
		err(1, "enter cell %" PRIu32, id);
}

static void
cell_list(void)
{
	struct cell_info *entries;
	size_t count, i;

	entries = cell_fetch_list(&count);
	if (count == 0) {
		printf("no cells\n");
		return;
	}

	printf("%-8s %-8s %-8s %-16s %s\n",
	    "ID", "REFS", "PROCS", "NAME", "ROOT");
	for (i = 0; i < count; i++) {
		printf("%-8" PRIu32 " %-8" PRIu64 " %-8" PRIu64 " %-16s %s\n",
		    entries[i].ji_id, entries[i].ji_refcount,
		    entries[i].ji_proc_current,
		    entries[i].ji_name[0] != '\0' ? entries[i].ji_name : "-",
		    entries[i].ji_root[0] != '\0' ? entries[i].ji_root : "-");
	}

	free(entries);
}

static void
cell_stats(bool prometheus, bool verbose, bool http_header)
{
	struct cell_info *entries;
	size_t count, i;

	entries = cell_fetch_list(&count);
	if (prometheus && http_header) {
		printf("HTTP/1.1 200 OK\r\n");
		printf("Content-Type: text/plain\r\n\r\n");
	}
	if (count == 0) {
		if (!prometheus)
			printf("no cells\n");
		return;
	}

	if (!prometheus) {
		if (!verbose) {
			printf("%-8s %-16s %-10s %-10s %-8s %-12s\n",
			    "ID", "NAME", "CPU1S", "CPU10S", "PROC", "MEMORY");
			for (i = 0; i < count; i++) {
				printf("%-8" PRIu32 " %-16s %-10" PRIu64 " %-10" PRIu64
				    " %-8" PRIu64 " %-12" PRIu64 "\n",
				    entries[i].ji_id,
				    entries[i].ji_name[0] != '\0' ? entries[i].ji_name : "-",
				    entries[i].ji_cpu_ticks_1s,
				    entries[i].ji_cpu_ticks_10s,
				    entries[i].ji_proc_current,
				    entries[i].ji_memory_current);
			}
		} else {
			printf("%-8s %-16s %-24s %-10s %-10s %-8s %-8s %-12s\n",
			    "ID", "NAME", "ROOT", "CPU1S", "CPU10S", "PROC",
			    "REFS", "MEMORY");
			for (i = 0; i < count; i++) {
				printf("%-8" PRIu32 " %-16s %-24s %-10" PRIu64
				    " %-10" PRIu64 " %-8" PRIu64 " %-8" PRIu64
				    " %-12" PRIu64 "\n",
				    entries[i].ji_id,
				    entries[i].ji_name[0] != '\0' ? entries[i].ji_name : "-",
				    entries[i].ji_root[0] != '\0' ? entries[i].ji_root : "-",
				    entries[i].ji_cpu_ticks_1s,
				    entries[i].ji_cpu_ticks_10s,
				    entries[i].ji_proc_current,
				    entries[i].ji_refcount,
				    entries[i].ji_memory_current);
			}
		}
		free(entries);
		return;
	}

	printf("# TYPE cell_cpu_ticks_1s gauge\n");
	printf("# TYPE cell_cpu_ticks_10s_avg gauge\n");
	printf("# TYPE cell_processes_current gauge\n");
	printf("# TYPE cell_references_current gauge\n");
	printf("# TYPE cell_memory_vmsize_bytes gauge\n");

	for (i = 0; i < count; i++) {
		char name[(CELL_NAME_MAX + 1) * 2 + 1];
		char root[(CELL_ROOT_MAX + 1) * 2 + 1];

		prom_escape_label(entries[i].ji_name, name, sizeof(name));
		prom_escape_label(entries[i].ji_root, root, sizeof(root));

		printf("cell_cpu_ticks_1s{cid=\"%" PRIu32
		    "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
		    entries[i].ji_id, name, root, entries[i].ji_cpu_ticks_1s);
		printf("cell_cpu_ticks_10s_avg{cid=\"%" PRIu32
		    "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
		    entries[i].ji_id, name, root, entries[i].ji_cpu_ticks_10s);
		printf("cell_processes_current{cid=\"%" PRIu32
		    "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
		    entries[i].ji_id, name, root, entries[i].ji_proc_current);
		printf("cell_references_current{cid=\"%" PRIu32
		    "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
		    entries[i].ji_id, name, root, entries[i].ji_refcount);
		printf("cell_memory_vmsize_bytes{cid=\"%" PRIu32
		    "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
		    entries[i].ji_id, name, root, entries[i].ji_memory_current);
	}

	free(entries);
}

static void
sanitize_field(const char *src, char *dst, size_t dsz)
{
	size_t i, j;

	for (i = 0, j = 0; src[i] != '\0' && j + 1 < dsz; i++) {
		if (src[i] == '\n' || src[i] == '\r' || src[i] == '\t')
			dst[j++] = ' ';
		else
			dst[j++] = src[i];
	}
	dst[j] = '\0';
}

static void
prom_escape_label(const char *src, char *dst, size_t dsz)
{
	size_t i, j;

	for (i = 0, j = 0; src[i] != '\0' && j + 1 < dsz; i++) {
		if ((src[i] == '\\' || src[i] == '"') && j + 2 < dsz) {
			dst[j++] = '\\';
			dst[j++] = src[i];
		} else if (src[i] == '\n' && j + 2 < dsz) {
			dst[j++] = '\\';
			dst[j++] = 'n';
		} else if (src[i] == '\r' || src[i] == '\t') {
			dst[j++] = ' ';
		} else {
			dst[j++] = src[i];
		}
	}
	dst[j] = '\0';
}

static bool
cell_lookup_by_id(cellid_t id, struct cell_info *jip)
{
	struct cell_info *entries;
	size_t count, i;

	entries = cell_fetch_list(&count);
	for (i = 0; i < count; i++) {
		if (entries[i].ji_id == id) {
			*jip = entries[i];
			free(entries);
			return true;
		}
	}
	free(entries);
	return false;
}

static bool
cell_lookup_by_name(const char *name, struct cell_info *jip)
{
	struct cell_info *entries;
	size_t count, i;

	entries = cell_fetch_list(&count);
	for (i = 0; i < count; i++) {
		if (strcmp(entries[i].ji_name, name) == 0) {
			*jip = entries[i];
			free(entries);
			return true;
		}
	}
	free(entries);
	return false;
}

static void
cell_exec(cellid_t id, const char *root, char *cmd[])
{
	const char *shell;

	/*
	 * Execution order matters:
	 * 1) enter cell filesystem view via chroot
	 * 2) switch cell membership in kernel via sysctl
	 * 3) exec workload/shell with both constraints in effect
	 */
	if (chdir(root) == -1 || chroot(".") == -1)
		err(1, "%s", root);

	if (chdir("/") == -1)
		err(1, "/");

	cell_enter(id);

	if (cmd != NULL) {
		execvp(cmd[0], cmd);
		err(1, "%s", cmd[0]);
	}

	if ((shell = getenv("SHELL")) == NULL)
		shell = _PATH_BSHELL;
	execlp(shell, shell, "-i", NULL);
	err(1, "%s", shell);
}

static void
log_stream_data(int priority, const char *stream, cellid_t id, const char *name,
    char *linebuf, size_t *usedp, const char *chunk, size_t chunklen)
{
	size_t used;
	size_t i;

	/*
	 * Convert an arbitrary byte stream into syslog lines while preserving
	 * partial-line state across read(2) calls.
	 */
	used = *usedp;
	for (i = 0; i < chunklen; i++) {
		if (chunk[i] == '\n') {
			syslog(priority, "cell=%s cid=%" PRIu32 " %s: %.*s",
			    name, id, stream, (int)used, linebuf);
			used = 0;
			continue;
		}
		if (used + 1 >= CELLCTL_LOG_MAX) {
			syslog(priority, "cell=%s cid=%" PRIu32 " %s: %.*s",
			    name, id, stream, (int)used, linebuf);
			used = 0;
		}
		linebuf[used++] = chunk[i];
	}

	*usedp = used;
}

static void
cell_run_monitor_once(cellid_t id, const char *name, int outfd, int errfd,
    pid_t child, int stdout_priority, int stderr_priority, int *statusp)
{
	const int kill_grace_ms = 5000;
	char outline[CELLCTL_LOG_MAX];
	char errline[CELLCTL_LOG_MAX];
	struct timespec now;
	struct timespec shutdown_deadline;
	size_t outused, errused;
	bool outopen, erropen;
	bool sent_sigterm, sent_sigkill;
	bool have_deadline;
	int flags;

	/*
	 * Monitor one supervised child execution:
	 * - forward stdout/stderr to syslog with cell context
	 * - on shutdown request, terminate process group gracefully then forcefully
	 */
	sent_sigterm = false;
	sent_sigkill = false;
	have_deadline = false;

	flags = fcntl(outfd, F_GETFL, 0);
	if (flags == -1)
		warn("fcntl outfd F_GETFL");
	else if (fcntl(outfd, F_SETFL, flags | O_NONBLOCK) == -1)
		warn("fcntl outfd O_NONBLOCK");
	flags = fcntl(errfd, F_GETFL, 0);
	if (flags == -1)
		warn("fcntl errfd F_GETFL");
	else if (fcntl(errfd, F_SETFL, flags | O_NONBLOCK) == -1)
		warn("fcntl errfd O_NONBLOCK");

	outused = 0;
	errused = 0;
	outopen = true;
	erropen = true;

	while (outopen || erropen) {
		struct pollfd pfd[2];
		int nfd, rv, i, timeout_ms;

		if (monitor_shutdown_requested && !sent_sigterm) {
			if (kill(-child, SIGTERM) == -1 && errno != ESRCH)
				warn("kill(SIGTERM, -%jd)", (intmax_t)child);
			sent_sigterm = true;
			if (clock_gettime(CLOCK_MONOTONIC, &shutdown_deadline) == -1)
				err(1, "clock_gettime");
			shutdown_deadline.tv_sec += kill_grace_ms / 1000;
			shutdown_deadline.tv_nsec += (kill_grace_ms % 1000) * 1000000L;
			if (shutdown_deadline.tv_nsec >= 1000000000L) {
				shutdown_deadline.tv_sec++;
				shutdown_deadline.tv_nsec -= 1000000000L;
			}
			have_deadline = true;
		}

		timeout_ms = 500;
		if (have_deadline && !sent_sigkill) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
				err(1, "clock_gettime");
			if (now.tv_sec > shutdown_deadline.tv_sec ||
			    (now.tv_sec == shutdown_deadline.tv_sec &&
			    now.tv_nsec >= shutdown_deadline.tv_nsec)) {
				if (kill(-child, SIGKILL) == -1 && errno != ESRCH)
					warn("kill(SIGKILL, -%jd)", (intmax_t)child);
				sent_sigkill = true;
				timeout_ms = 0;
			} else {
				long sec, nsec;

				sec = shutdown_deadline.tv_sec - now.tv_sec;
				nsec = shutdown_deadline.tv_nsec - now.tv_nsec;
				if (nsec < 0) {
					sec--;
					nsec += 1000000000L;
				}
				timeout_ms = (int)(sec * 1000 + nsec / 1000000L);
				if (timeout_ms < 0)
					timeout_ms = 0;
				if (timeout_ms > 500)
					timeout_ms = 500;
			}
		}

		nfd = 0;
		if (outopen) {
			pfd[nfd].fd = outfd;
			pfd[nfd].events = POLLIN;
			nfd++;
		}
		if (erropen) {
			pfd[nfd].fd = errfd;
			pfd[nfd].events = POLLIN;
			nfd++;
		}

		rv = poll(pfd, (nfds_t)nfd, timeout_ms);
		if (rv < 0) {
			if (errno == EINTR)
				continue;
			warn("poll");
			break;
		}
		if (rv == 0)
			continue;

		for (i = 0; i < nfd; i++) {
			bool *openp;

			openp = pfd[i].fd == outfd ? &outopen : &erropen;

			if (*openp == false)
				continue;
			if ((pfd[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0)
				continue;

			for (;;) {
				char buf[512];
				ssize_t n;

				n = read(pfd[i].fd, buf, sizeof(buf));
				if (n > 0) {
					if (pfd[i].fd == outfd)
						log_stream_data(stdout_priority, "stdout", id, name,
						    outline, &outused, buf, (size_t)n);
					else
						log_stream_data(stderr_priority, "stderr", id, name,
						    errline, &errused, buf, (size_t)n);
					continue;
				}

				if (n == 0) {
					*openp = false;
					close(pfd[i].fd);
					break;
				}

				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;

				warn("read");
				*openp = false;
				close(pfd[i].fd);
				break;
			}
		}
	}

	if (outused > 0)
		syslog(stdout_priority, "cell=%s cid=%" PRIu32 " stdout: %.*s",
		    name, id, (int)outused, outline);
	if (errused > 0)
		syslog(stderr_priority, "cell=%s cid=%" PRIu32 " stderr: %.*s",
		    name, id, (int)errused, errline);

	if (waitpid(child, statusp, 0) == -1 && errno != ECHILD)
		warn("waitpid %jd", (intmax_t)child);
}

static void
cell_supervise_loop(cellid_t id, const char *root, const char *name,
    const char *logtag, char *cmd[], int facility, int stdout_priority,
    int stderr_priority)
{
	struct sigaction sa;
	int next_backoff_sec;

	setproctitle("cellctl supervise cell=%s cid=%" PRIu32, name, id);
	openlog(logtag, LOG_PID | LOG_NDELAY, facility);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = monitor_signal_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGTERM, &sa, NULL) == -1 ||
	    sigaction(SIGINT, &sa, NULL) == -1 ||
	    sigaction(SIGQUIT, &sa, NULL) == -1)
		err(1, "sigaction");

	/*
	 * Keep supervise mode detached from caller terminal/session lifetime.
	 * If started via rc(8), startup completion can trigger SIGHUP delivery
	 * to background jobs; treating SIGHUP as shutdown would stop the cell.
	 */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGHUP, &sa, NULL) == -1)
		err(1, "sigaction");

	monitor_shutdown_requested = 0;
	next_backoff_sec = 1;

	for (;;) {
		int outpipe[2], errpipe[2], status;
		struct timespec started, elapsed;
		pid_t child;

		if (monitor_shutdown_requested)
			break;

		if (pipe(outpipe) == -1 || pipe(errpipe) == -1)
			err(1, "pipe");

		if (clock_gettime(CLOCK_MONOTONIC, &started) == -1)
			err(1, "clock_gettime");

		child = fork();
		if (child == -1)
			err(1, "fork");
		if (child == 0) {
			int devnull;

			close(outpipe[0]);
			close(errpipe[0]);
			if (setsid() == -1)
				err(1, "setsid");
			devnull = open(_PATH_DEVNULL, O_RDONLY);
			if (devnull == -1)
				err(1, "%s", _PATH_DEVNULL);
			if (dup2(devnull, STDIN_FILENO) == -1 ||
			    dup2(outpipe[1], STDOUT_FILENO) == -1 ||
			    dup2(errpipe[1], STDERR_FILENO) == -1)
				err(1, "dup2");
			if (devnull > STDERR_FILENO)
				close(devnull);
			close(outpipe[1]);
			close(errpipe[1]);
			cell_exec(id, root, cmd);
		}

		close(outpipe[1]);
		close(errpipe[1]);

		syslog(LOG_INFO, "cell=%s cid=%" PRIu32 " starting supervised command",
		    name, id);
		status = 0;
		cell_run_monitor_once(id, name, outpipe[0], errpipe[0], child,
		    stdout_priority, stderr_priority, &status);

		if (monitor_shutdown_requested) {
			syslog(LOG_NOTICE,
			    "cell=%s cid=%" PRIu32 " supervise shutdown requested",
			    name, id);
			break;
		}

		if (WIFEXITED(status)) {
			syslog(LOG_WARNING,
			    "cell=%s cid=%" PRIu32 " supervised command exited status=%d",
			    name, id, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			syslog(LOG_WARNING,
			    "cell=%s cid=%" PRIu32 " supervised command killed by signal=%d",
			    name, id, WTERMSIG(status));
		} else {
			syslog(LOG_WARNING,
			    "cell=%s cid=%" PRIu32 " supervised command ended unexpectedly",
			    name, id);
		}

		if (clock_gettime(CLOCK_MONOTONIC, &elapsed) == -1)
			err(1, "clock_gettime");
		elapsed.tv_sec -= started.tv_sec;
		elapsed.tv_nsec -= started.tv_nsec;
		if (elapsed.tv_nsec < 0) {
			elapsed.tv_sec--;
			elapsed.tv_nsec += 1000000000L;
		}

		if (elapsed.tv_sec >= 30)
			next_backoff_sec = 1;

		syslog(LOG_NOTICE,
		    "cell=%s cid=%" PRIu32 " restarting supervised command in %d seconds",
		    name, id, next_backoff_sec);

		{
			int delay_sec;

			for (delay_sec = next_backoff_sec;
			    delay_sec > 0 && !monitor_shutdown_requested;
			    delay_sec--) {
				struct timespec delay = { .tv_sec = 1, .tv_nsec = 0 };

				if (nanosleep(&delay, NULL) == -1 && errno != EINTR)
					warn("nanosleep");
			}
		}

		if (elapsed.tv_sec < 30) {
			next_backoff_sec *= 2;
			if (next_backoff_sec > 10)
				next_backoff_sec = 10;
		}
	}

	closelog();
	_exit(0);
}

static void
cell_spawn_detached(cellid_t id, const char *root, const char *name,
    const char *logtag, char *cmd[], int facility, int stdout_priority,
    int stderr_priority)
{
	int devnull;
	pid_t mgr;

	/*
	 * Supervise mode daemonizes itself so callers (for example rc(8) helpers)
	 * do not need nohup/background wrappers.
	 */
	mgr = fork();
	if (mgr == -1)
		err(1, "fork");
	if (mgr == 0) {
		mgr = fork();
		if (mgr == -1)
			err(1, "fork");
		if (mgr != 0)
			_exit(0);

		if (setsid() == -1)
			err(1, "setsid");
		devnull = open(_PATH_DEVNULL, O_RDWR);
		if (devnull == -1)
			err(1, "%s", _PATH_DEVNULL);
		if (dup2(devnull, STDIN_FILENO) == -1 ||
		    dup2(devnull, STDOUT_FILENO) == -1 ||
		    dup2(devnull, STDERR_FILENO) == -1)
			err(1, "dup2");
		if (devnull > STDERR_FILENO)
			close(devnull);
		cell_supervise_loop(id, root, name, logtag, cmd,
		    facility, stdout_priority, stderr_priority);
	}
	printf("cell %" PRIu32 "\n", id);
}

static int
parse_log_facility(const char *name)
{
	static const struct {
		const char *name;
		int facility;
	} facs[] = {
		{ "auth", LOG_AUTH },
		{ "authpriv", LOG_AUTHPRIV },
		{ "cron", LOG_CRON },
		{ "daemon", LOG_DAEMON },
		{ "ftp", LOG_FTP },
		{ "kern", LOG_KERN },
		{ "lpr", LOG_LPR },
		{ "mail", LOG_MAIL },
		{ "news", LOG_NEWS },
		{ "syslog", LOG_SYSLOG },
		{ "user", LOG_USER },
		{ "uucp", LOG_UUCP },
		{ "local0", LOG_LOCAL0 },
		{ "local1", LOG_LOCAL1 },
		{ "local2", LOG_LOCAL2 },
		{ "local3", LOG_LOCAL3 },
		{ "local4", LOG_LOCAL4 },
		{ "local5", LOG_LOCAL5 },
		{ "local6", LOG_LOCAL6 },
		{ "local7", LOG_LOCAL7 },
	};
	size_t i;

	for (i = 0; i < __arraycount(facs); i++) {
		if (strcmp(name, facs[i].name) == 0)
			return facs[i].facility;
	}

	errx(1, "invalid log facility: %s", name);
	/* NOTREACHED */
}

static int
parse_log_level(const char *name)
{
	static const struct {
		const char *name;
		int level;
	} levels[] = {
		{ "emerg", LOG_EMERG },
		{ "alert", LOG_ALERT },
		{ "crit", LOG_CRIT },
		{ "err", LOG_ERR },
		{ "warning", LOG_WARNING },
		{ "notice", LOG_NOTICE },
		{ "info", LOG_INFO },
		{ "debug", LOG_DEBUG },
	};
	size_t i;

	for (i = 0; i < __arraycount(levels); i++) {
		if (strcmp(name, levels[i].name) == 0)
			return levels[i].level;
	}

	errx(1, "invalid log level: %s", name);
	/* NOTREACHED */
}

static int
parse_log_level_arg(const char *arg)
{
	long num;
	char *endp;

	errno = 0;
	num = strtol(arg, &endp, 0);
	if (errno == 0 && *arg != '\0' && *endp == '\0') {
		if (num < LOG_EMERG || num > LOG_DEBUG)
			errx(1, "log level out of range: %s", arg);
		return (int)num;
	}

	return parse_log_level(arg);
}

static uint32_t
parse_profile(const char *arg)
{
	if (strcmp(arg, "low") == 0)
		return CELL_PROFILE_LOW;
	if (strcmp(arg, "medium") == 0)
		return CELL_PROFILE_MEDIUM;
	if (strcmp(arg, "high") == 0)
		return CELL_PROFILE_HIGH;

	errx(1, "invalid profile '%s' (expected low|medium|high)", arg);
	return CELL_PROFILE_HIGH;
}

static void
parse_port_list(struct cell_create *create, const char *arg)
{
	char *list, *tok, *sp;
	unsigned long port;

	list = strdup(arg);
	if (list == NULL)
		err(1, "strdup");

	for (tok = strtok_r(list, ",", &sp); tok != NULL;
	    tok = strtok_r(NULL, ",", &sp)) {
		char *endp;
		size_t i;

		errno = 0;
		port = strtoul(tok, &endp, 10);
		if (errno != 0 || *tok == '\0' || *endp != '\0' ||
		    port == 0 || port > UINT16_MAX) {
			free(list);
			errx(1, "invalid reserved port: %s", tok);
		}
		for (i = 0; i < create->jc_nports; i++) {
			if (create->jc_ports[i] == (uint16_t)port) {
				free(list);
				errx(1, "duplicate reserved port: %lu", port);
			}
		}
		if (create->jc_nports >= CELL_PORTS_MAX) {
			free(list);
			errx(1, "too many reserved ports (max %u)", CELL_PORTS_MAX);
		}
		create->jc_ports[create->jc_nports++] = (uint16_t)port;
	}

	free(list);
	if (create->jc_nports > 0)
		create->jc_flags |= CELL_CREATE_PORTS;
}

static int
getnum(const char *str, uintmax_t *num)
{
	char *ep;

	errno = 0;
	*num = strtoumax(str, &ep, 0);
	if (str[0] == '\0' || *ep != '\0') {
		errno = EINVAL;
		return -1;
	}

	if (errno == ERANGE && *num == UINTMAX_MAX)
		return -1;

	return 0;
}

static cellid_t
resolve_cell_target(const char *arg, struct cell_info *ji)
{
	uintmax_t num;

	/* Prefer numeric ID lookup, then fall back to exact-name lookup. */
	if (getnum(arg, &num) == 0 && num <= UINT32_MAX) {
		if (!cell_lookup_by_id((cellid_t)num, ji))
			errx(1, "cell %" PRIu32 " not found", (cellid_t)num);
		return (cellid_t)num;
	}

	if (cell_lookup_by_name(arg, ji))
		return ji->ji_id;

	errx(1, "cell '%s' not found", arg);
}

int
main(int argc, char *argv[])
{
	cellid_t id;
	const char *root;
	const char *name;
	struct cell_info ji;

	if (argc < 2)
		usage();

	if (strcmp(argv[1], "create") == 0) {
		struct cell_create create;
		int ch;

		memset(&create, 0, sizeof(create));
		name = NULL;
		create.jc_profile = CELL_PROFILE_HIGH;
		optind = 2;
		while ((ch = getopt(argc, argv, "n:l:r:")) != -1) {
			switch (ch) {
			case 'n':
				name = optarg;
				break;
			case 'l':
				create.jc_flags |= CELL_CREATE_PROFILE;
				create.jc_profile = parse_profile(optarg);
				break;
			case 'r':
				parse_port_list(&create, optarg);
				break;
			default:
				usage();
			}
		}

		if (optind >= argc || name == NULL || argc != optind + 1)
			usage();
		if (strlen(name) > CELL_NAME_MAX)
			errx(1, "name too long");

		if (cell_lookup_by_name(name, &ji))
			errx(1, "name already exists: %s", name);

		root = argv[optind];
		sanitize_field(name, create.jc_name, sizeof(create.jc_name));
		sanitize_field(root, create.jc_root, sizeof(create.jc_root));
		id = cell_create(&create);
		printf("cell %" PRIu32 "\n", id);
		return 0;
	}

	if (strcmp(argv[1], "supervise") == 0) {
		char **cmd;
		int ch;
		int facility, stdout_level, stderr_level;
		char logtag[CELLCTL_TAG_MAX + 1];

		facility = LOG_DAEMON;
		stdout_level = LOG_NOTICE;
		stderr_level = LOG_ERR;
		strlcpy(logtag, "cellctl", sizeof(logtag));
		optind = 2;
		while ((ch = getopt(argc, argv, "f:t:o:e:")) != -1) {
			switch (ch) {
			case 'f':
				facility = parse_log_facility(optarg);
				break;
			case 'o':
				stdout_level = parse_log_level_arg(optarg);
				break;
			case 'e':
				stderr_level = parse_log_level_arg(optarg);
				break;
			case 't':
				sanitize_field(optarg, logtag, sizeof(logtag));
				if (logtag[0] == '\0')
					errx(1, "invalid log tag");
				break;
			default:
				usage();
			}
		}

		if (optind >= argc)
			usage();

		id = resolve_cell_target(argv[optind++], &ji);
		if (optind >= argc)
			errx(1, "supervise requires command [args...]");
		cmd = &argv[optind];

		cell_spawn_detached(id, ji.ji_root, ji.ji_name, logtag, cmd,
		    facility, facility | stdout_level, facility | stderr_level);
		return 0;
	}

	if (strcmp(argv[1], "destroy") == 0) {
		if (argc != 3)
			usage();

		id = resolve_cell_target(argv[2], &ji);
		cell_destroy(id);
		return 0;
	}

	if (strcmp(argv[1], "exec") == 0) {
		if (argc < 3)
			usage();

		id = resolve_cell_target(argv[2], &ji);

		cell_exec(id, ji.ji_root, argc > 3 ? &argv[3] : NULL);
		/* NOTREACHED */
	}

	if (strcmp(argv[1], "list") == 0) {
		if (argc != 2)
			usage();

		cell_list();
		return 0;
	}

	if (strcmp(argv[1], "stats") == 0) {
		bool prometheus, verbose, http_header;
		int ch;

		prometheus = false;
		verbose = false;
		http_header = false;
		optind = 2;
		while ((ch = getopt(argc, argv, "Pvh")) != -1) {
			switch (ch) {
			case 'P':
				prometheus = true;
				break;
			case 'v':
				verbose = true;
				break;
			case 'h':
				http_header = true;
				break;
			default:
				usage();
			}
		}
		if (optind != argc)
			usage();
		if (http_header && !prometheus)
			errx(1, "-h requires -P");

		cell_stats(prometheus, verbose, http_header);
		return 0;
	}

	usage();
	/* NOTREACHED */
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s create [-l low|medium|high] [-r port[,port...]] "
	    "-n name <root>\n"
	    "       %s supervise [-f facility] [-o stdout-level] "
	    "[-e stderr-level] [-t tag] <cell-id|name> <command [args...]>\n"
	    "       %s exec <cell-id|name> [command [args...]]\n"
	    "       %s destroy <cell-id|name>\n"
	    "       %s list\n"
	    "       %s stats [-P] [-v] [-h]\n",
	    getprogname(), getprogname(), getprogname(), getprogname(),
	    getprogname(), getprogname());
	exit(EXIT_FAILURE);
}
