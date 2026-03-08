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
 * svcmgr designed and implemented by Matthias Petermann,
 * inspired by runit.
 */

#include <sys/cdefs.h>
#ifndef __RCSID
#define __RCSID(x) extern const int __svcmgr_no_rcsid
#endif
#ifndef lint
__RCSID("$NetBSD$");
#endif /* not lint */

#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SVCMGR_LINE_MAX	4096
#define SVCMGR_CHUNK_SIZE 512
#define SVCMGR_KILL_GRACE_MS 5000

struct stream_state {
	int fd;
	bool open;
	char line[SVCMGR_LINE_MAX];
	size_t used;
};

struct service {
	char *tag;
	char *cmd;
	pid_t pid;
	bool running;
	struct stream_state out;
	struct stream_state err;
};

static volatile sig_atomic_t shutdown_requested;
static const char *progname = "svcmgr";

/*
 * Keep the signal handler async-signal-safe by only toggling a flag.
 * The monitor loop performs the actual shutdown sequencing.
 */
static void
signal_handler(int signo)
{

	(void)signo;
	shutdown_requested = 1;
}

static void
usage(void)
{

	fprintf(stderr, "usage: %s [-c config]\n", progname);
	exit(1);
}

static void
set_nonblocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
		err(1, "fcntl(F_GETFL)");
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "fcntl(F_SETFL)");
}

static bool
is_blank_or_comment(const char *s)
{

	while (*s != '\0') {
		if (isspace((unsigned char)*s)) {
			s++;
			continue;
		}
		return *s == '#';
	}
	return true;
}

static void
parse_config_line(char *line, char **tagp, char **cmdp)
{
	char *tag, *cmd;

	/*
	 * Configuration format:
	 *   <logtag><space-or-tab><command ...>
	 * Any isspace(3) separator is accepted, including tabs.
	 */
	while (isspace((unsigned char)*line))
		line++;
	tag = line;
	while (*line != '\0' && !isspace((unsigned char)*line))
		line++;
	if (*line == '\0')
		errx(1, "invalid config line: missing command");
	*line++ = '\0';
	while (isspace((unsigned char)*line))
		line++;
	if (*line == '\0')
		errx(1, "invalid config line: missing command");
	cmd = line;

	*tagp = tag;
	*cmdp = cmd;
}

static struct service *
load_config(const char *path, size_t *nsvcp)
{
	FILE *fp;
	struct service *svcs;
	size_t nsvc, cap;
	char *line;
	size_t linesz;
	ssize_t nread;

	fp = fopen(path, "r");
	if (fp == NULL)
		err(1, "%s", path);

	svcs = NULL;
	nsvc = 0;
	cap = 0;
	line = NULL;
	linesz = 0;

	/*
	 * Read line-by-line so we can preserve the original command text
	 * (everything after the first separator) exactly as configured.
	 */
	while ((nread = getline(&line, &linesz, fp)) != -1) {
		char *tag, *cmd;

		if (nread > 0 && line[nread - 1] == '\n')
			line[nread - 1] = '\0';
		if (is_blank_or_comment(line))
			continue;

		if (cap == nsvc) {
			struct service *tmp;
			size_t ncap = cap == 0 ? 8 : cap * 2;

			tmp = realloc(svcs, ncap * sizeof(*svcs));
			if (tmp == NULL)
				err(1, "realloc");
			svcs = tmp;
			cap = ncap;
		}

		parse_config_line(line, &tag, &cmd);
		svcs[nsvc].tag = strdup(tag);
		svcs[nsvc].cmd = strdup(cmd);
		if (svcs[nsvc].tag == NULL || svcs[nsvc].cmd == NULL)
			err(1, "strdup");
		svcs[nsvc].pid = -1;
		svcs[nsvc].running = false;
		svcs[nsvc].out.fd = -1;
		svcs[nsvc].out.open = false;
		svcs[nsvc].out.used = 0;
		svcs[nsvc].err.fd = -1;
		svcs[nsvc].err.open = false;
		svcs[nsvc].err.used = 0;
		nsvc++;
	}

	if (ferror(fp) != 0)
		err(1, "%s", path);
	if (fclose(fp) == EOF)
		err(1, "%s", path);
	free(line);

	if (nsvc == 0)
		errx(1, "%s: no services configured", path);

	*nsvcp = nsvc;
	return svcs;
}

static struct service *
service_by_pid(struct service *svcs, size_t nsvc, pid_t pid)
{
	size_t i;

	for (i = 0; i < nsvc; i++) {
		if (svcs[i].pid == pid)
			return &svcs[i];
	}
	return NULL;
}

static size_t
running_services(struct service *svcs, size_t nsvc)
{
	size_t i, running;

	running = 0;
	for (i = 0; i < nsvc; i++) {
		if (svcs[i].running)
			running++;
	}
	return running;
}

static bool
any_open_streams(struct service *svcs, size_t nsvc)
{
	size_t i;

	for (i = 0; i < nsvc; i++) {
		if (svcs[i].out.open || svcs[i].err.open)
			return true;
	}
	return false;
}

static void
emit_line(FILE *fp, const char *tag, const char *line)
{

	if (fprintf(fp, "%s %s\n", tag, line) < 0)
		err(1, "fprintf");
	if (fflush(fp) == EOF)
		err(1, "fflush");
}

static void
flush_stream_buffer(FILE *fp, struct service *svc, struct stream_state *st)
{

	if (st->used == 0)
		return;
	st->line[st->used] = '\0';
	emit_line(fp, svc->tag, st->line);
	st->used = 0;
}

static void
process_stream_chunk(FILE *fp, struct service *svc, struct stream_state *st,
    const char *buf, size_t len)
{
	size_t i;

	/*
	 * Convert an arbitrary byte stream into newline-delimited records.
	 * Partial lines are kept in the per-stream buffer until complete.
	 */
	for (i = 0; i < len; i++) {
		if (buf[i] == '\n') {
			flush_stream_buffer(fp, svc, st);
			continue;
		}
		if (st->used + 1 >= sizeof(st->line))
			flush_stream_buffer(fp, svc, st);
		st->line[st->used++] = buf[i];
	}
}

static void
close_stream(struct service *svc, struct stream_state *st, FILE *fp)
{

	if (!st->open)
		return;
	if (close(st->fd) == -1)
		warn("close");
	st->open = false;
	st->fd = -1;
	flush_stream_buffer(fp, svc, st);
}

static void
spawn_service(struct service *svc)
{
	int outpipe[2], errpipe[2];
	pid_t pid;

	if (pipe(outpipe) == -1)
		err(1, "pipe");
	if (pipe(errpipe) == -1)
		err(1, "pipe");

	pid = fork();
	if (pid == -1)
		err(1, "fork");
	if (pid == 0) {
		int devnull;

		/*
		 * Isolate each service in its own session/process-group so
		 * shutdown signals can target the complete service tree.
		 */
		if (setsid() == -1)
			err(1, "setsid");
		close(outpipe[0]);
		close(errpipe[0]);
		devnull = open("/dev/null", O_RDONLY);
		if (devnull == -1)
			err(1, "/dev/null");
		if (dup2(devnull, STDIN_FILENO) == -1 ||
		    dup2(outpipe[1], STDOUT_FILENO) == -1 ||
		    dup2(errpipe[1], STDERR_FILENO) == -1)
			err(1, "dup2");
		if (devnull > STDERR_FILENO)
			close(devnull);
		close(outpipe[1]);
		close(errpipe[1]);

		execl("/bin/sh", "sh", "-c", svc->cmd, (char *)NULL);
		err(1, "execl /bin/sh");
	}

	close(outpipe[1]);
	close(errpipe[1]);
	set_nonblocking(outpipe[0]);
	set_nonblocking(errpipe[0]);

	svc->pid = pid;
	svc->running = true;
	svc->out.fd = outpipe[0];
	svc->out.open = true;
	svc->out.used = 0;
	svc->err.fd = errpipe[0];
	svc->err.open = true;
	svc->err.used = 0;
}

static void
reap_children(struct service *svcs, size_t nsvc)
{
	int status;
	pid_t pid;

	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid > 0) {
			struct service *svc = service_by_pid(svcs, nsvc, pid);
			if (svc != NULL)
				svc->running = false;
			continue;
		}
		if (pid == 0)
			return;
		if (errno == EINTR)
			continue;
		if (errno == ECHILD)
			return;
		warn("waitpid");
		return;
	}
}

static void
send_signal_to_running(struct service *svcs, size_t nsvc, int signo,
    bool *sent_flag)
{
	size_t i;

	for (i = 0; i < nsvc; i++) {
		if (!svcs[i].running)
			continue;
		if (kill(-svcs[i].pid, signo) == -1 && errno != ESRCH)
			warn("kill(%d, -%jd)", signo, (intmax_t)svcs[i].pid);
		if (sent_flag != NULL)
			sent_flag[i] = true;
	}
}

static void
monitor_services(struct service *svcs, size_t nsvc)
{
	bool term_sent_global, kill_sent_global;
	struct timespec deadline;
	bool have_deadline;

	term_sent_global = false;
	kill_sent_global = false;
	have_deadline = false;

	/*
	 * Event loop responsibilities:
	 *  - drain child stdout/stderr without blocking
	 *  - emit complete tagged lines with immediate flush
	 *  - on shutdown: SIGTERM first, then SIGKILL after grace period
	 */
	while (running_services(svcs, nsvc) > 0 || any_open_streams(svcs, nsvc)) {
		struct pollfd *pfds;
		size_t i, nfd;
		int timeout_ms, rv;

		reap_children(svcs, nsvc);

		if (shutdown_requested && !term_sent_global) {
			send_signal_to_running(svcs, nsvc, SIGTERM, NULL);
			if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
				err(1, "clock_gettime");
			deadline.tv_sec += SVCMGR_KILL_GRACE_MS / 1000;
			deadline.tv_nsec +=
			    (SVCMGR_KILL_GRACE_MS % 1000) * 1000000L;
			if (deadline.tv_nsec >= 1000000000L) {
				deadline.tv_sec++;
				deadline.tv_nsec -= 1000000000L;
			}
			have_deadline = true;
			term_sent_global = true;
		}

		timeout_ms = 500;
		if (have_deadline && !kill_sent_global) {
			struct timespec now;
			long sec, nsec;

			if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
				err(1, "clock_gettime");
			if (now.tv_sec > deadline.tv_sec ||
			    (now.tv_sec == deadline.tv_sec &&
			    now.tv_nsec >= deadline.tv_nsec)) {
				send_signal_to_running(svcs, nsvc, SIGKILL, NULL);
				kill_sent_global = true;
				timeout_ms = 0;
			} else {
				sec = deadline.tv_sec - now.tv_sec;
				nsec = deadline.tv_nsec - now.tv_nsec;
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
		for (i = 0; i < nsvc; i++) {
			if (svcs[i].out.open)
				nfd++;
			if (svcs[i].err.open)
				nfd++;
		}
		if (nfd == 0) {
			if (timeout_ms > 0) {
				struct timespec delay;
				delay.tv_sec = timeout_ms / 1000;
				delay.tv_nsec = (timeout_ms % 1000) * 1000000L;
				(void)nanosleep(&delay, NULL);
			}
			continue;
		}

		pfds = calloc(nfd, sizeof(*pfds));
		if (pfds == NULL)
			err(1, "calloc");

		nfd = 0;
		for (i = 0; i < nsvc; i++) {
			if (svcs[i].out.open) {
				pfds[nfd].fd = svcs[i].out.fd;
				pfds[nfd].events = POLLIN;
				nfd++;
			}
			if (svcs[i].err.open) {
				pfds[nfd].fd = svcs[i].err.fd;
				pfds[nfd].events = POLLIN;
				nfd++;
			}
		}

		rv = poll(pfds, nfd, timeout_ms);
		if (rv < 0) {
			if (errno == EINTR) {
				free(pfds);
				continue;
			}
			warn("poll");
			free(pfds);
			continue;
		}

		if (rv > 0) {
			for (i = 0; i < nfd; i++) {
				size_t s;
				bool is_err;
				struct stream_state *st;
				FILE *fp;
				char buf[SVCMGR_CHUNK_SIZE];
				ssize_t n;

				if ((pfds[i].revents &
				    (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0)
					continue;

				for (s = 0; s < nsvc; s++) {
					if (svcs[s].out.open && svcs[s].out.fd == pfds[i].fd)
						break;
					if (svcs[s].err.open && svcs[s].err.fd == pfds[i].fd)
						break;
				}
				if (s == nsvc)
					continue;

				is_err = (svcs[s].err.open && svcs[s].err.fd == pfds[i].fd);
				st = is_err ? &svcs[s].err : &svcs[s].out;
				fp = is_err ? stderr : stdout;

				for (;;) {
					n = read(st->fd, buf, sizeof(buf));
					if (n > 0) {
						process_stream_chunk(fp, &svcs[s], st,
						    buf, (size_t)n);
						continue;
					}
					if (n == 0) {
						close_stream(&svcs[s], st, fp);
						break;
					}
					if (errno == EINTR)
						continue;
					if (errno == EAGAIN || errno == EWOULDBLOCK)
						break;
					warn("read");
					close_stream(&svcs[s], st, fp);
					break;
				}
			}
		}
		free(pfds);
	}

	reap_children(svcs, nsvc);
}

int
main(int argc, char *argv[])
{
	if (argc > 0 && argv[0] != NULL && argv[0][0] != '\0')
		progname = argv[0];
	const char *config;
	struct sigaction sa;
	struct service *svcs;
	size_t nsvc, i;
	int ch;

	config = "/etc/svcmgr.conf";
	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			config = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGTERM, &sa, NULL) == -1 ||
	    sigaction(SIGINT, &sa, NULL) == -1 ||
	    sigaction(SIGQUIT, &sa, NULL) == -1)
		err(1, "sigaction");

	svcs = load_config(config, &nsvc);
	for (i = 0; i < nsvc; i++)
		spawn_service(&svcs[i]);

	monitor_services(svcs, nsvc);

	for (i = 0; i < nsvc; i++) {
		free(svcs[i].tag);
		free(svcs[i].cmd);
	}
	free(svcs);

	return 0;
}
