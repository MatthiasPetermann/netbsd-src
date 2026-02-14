/* $NetBSD$ */
/*-
 * Copyright (c) 2025
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
 */

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD$");
#endif /* not lint */

#include <sys/types.h>
#include <sys/jail.h>
#include <sys/sysctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
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
#include <sys/wait.h>

#define JAILCTL_LOG_MAX 511
#define JAILCTL_TAG_MAX 63

static void	usage(void) __dead;

static void	jail_exec(jailid_t, const char *, char *[]);
static void	jail_run_monitor(jailid_t, const char *, const char *, int, int,
		    pid_t, int, int);
static void	jail_spawn_detached(jailid_t, const char *, const char *,
		    const char *, char *[], int, int);
static int	parse_log_facility(const char *);
static int	parse_log_level(const char *);
static int	parse_log_priority(const char *);
static void	parse_port_list(struct jail_create *, const char *);
static void	sanitize_field(const char *, char *, size_t);
static bool	jail_lookup_by_name(const char *, struct jail_info *);
static bool	jail_lookup_by_id(jailid_t, struct jail_info *);
static void	log_stream_data(int, const char *, jailid_t, const char *,
		    char *, size_t *, const char *, size_t);
static jailid_t	resolve_jail_target(const char *, struct jail_info *);

static volatile sig_atomic_t monitor_shutdown_requested;

static void
monitor_signal_handler(int signo)
{
	(void)signo;
	monitor_shutdown_requested = 1;
}

static struct jail_info *
jail_fetch_list(size_t *countp)
{
	struct jail_info *entries;
	size_t len;

	len = 0;
	if (sysctlbyname("security.models.jail.list", NULL, &len,
	    NULL, 0) == -1)
		err(1, "list jails");

	if (len == 0) {
		*countp = 0;
		return NULL;
	}

	if (len % sizeof(*entries) != 0)
		errx(1, "unexpected jail list length");

	entries = calloc(1, len);
	if (entries == NULL)
		err(1, "calloc");

	if (sysctlbyname("security.models.jail.list", entries, &len,
	    NULL, 0) == -1)
		err(1, "list jails");

	*countp = len / sizeof(*entries);
	return entries;
}

static jailid_t
jail_create(const struct jail_create *create)
{
	jailid_t id;
	size_t len;
	int one;

	id = 0;
	if (create != NULL) {
		struct jail_create req;

		req = *create;
		len = sizeof(req);
		if (sysctlbyname("security.models.jail.create", &req, &len,
		    &req, sizeof(req)) == -1)
			err(1, "create jail");
		id = req.jc_id;
	} else {
		len = sizeof(id);
		one = 1;
		if (sysctlbyname("security.models.jail.create", &id, &len,
		    &one, sizeof(one)) == -1)
			err(1, "create jail");
	}

	return id;
}

static void
jail_destroy(jailid_t id)
{
	if (sysctlbyname("security.models.jail.destroy", NULL, 0,
	    &id, sizeof(id)) == -1)
		err(1, "destroy jail %" PRIu32, id);
}

static void
jail_enter(jailid_t id)
{
	if (sysctlbyname("security.models.jail.id", NULL, 0,
	    &id, sizeof(id)) == -1)
		err(1, "enter jail %" PRIu32, id);
}

static void
jail_list(void)
{
	struct jail_info *entries;
	size_t count, i;

	entries = jail_fetch_list(&count);
	if (count == 0) {
		printf("no jails\n");
		return;
	}

	printf("%-8s %-8s %-16s %s\n", "ID", "PROCS", "NAME", "ROOT");
	for (i = 0; i < count; i++) {
		printf("%-8" PRIu32 " %-8" PRIu32 " %-16s %s\n",
		    entries[i].ji_id, entries[i].ji_refcount,
		    entries[i].ji_name[0] != '\0' ? entries[i].ji_name : "-",
		    entries[i].ji_root[0] != '\0' ? entries[i].ji_root : "-");
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

static bool
jail_lookup_by_id(jailid_t id, struct jail_info *jip)
{
	struct jail_info *entries;
	size_t count, i;

	entries = jail_fetch_list(&count);
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
jail_lookup_by_name(const char *name, struct jail_info *jip)
{
	struct jail_info *entries;
	size_t count, i;

	entries = jail_fetch_list(&count);
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
jail_exec(jailid_t id, const char *root, char *cmd[])
{
	const char *shell;

	if (chdir(root) == -1 || chroot(".") == -1)
		err(1, "%s", root);

	if (chdir("/") == -1)
		err(1, "/");

	jail_enter(id);

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
log_stream_data(int priority, const char *stream, jailid_t id, const char *name,
    char *linebuf, size_t *usedp, const char *chunk, size_t chunklen)
{
	size_t used;
	size_t i;

	used = *usedp;
	for (i = 0; i < chunklen; i++) {
		if (chunk[i] == '\n') {
			syslog(priority, "jail=%s jid=%" PRIu32 " %s: %.*s",
			    name, id, stream, (int)used, linebuf);
			used = 0;
			continue;
		}
		if (used + 1 >= JAILCTL_LOG_MAX) {
			syslog(priority, "jail=%s jid=%" PRIu32 " %s: %.*s",
			    name, id, stream, (int)used, linebuf);
			used = 0;
		}
		linebuf[used++] = chunk[i];
	}

	*usedp = used;
}

static void
jail_run_monitor(jailid_t id, const char *name, const char *logtag,
    int outfd, int errfd,
    pid_t child, int facility, int stdout_level)
{
	const int kill_grace_ms = 5000;
	char outline[JAILCTL_LOG_MAX];
	char errline[JAILCTL_LOG_MAX];
	struct sigaction sa;
	struct timespec now;
	struct timespec shutdown_deadline;
	size_t outused, errused;
	bool outopen, erropen;
	bool sent_sigterm, sent_sigkill;
	bool have_deadline;
	int stderr_level;
	int status;

	setproctitle("jailctl supervise jail=%s jid=%" PRIu32, name, id);
	openlog(logtag, LOG_PID | LOG_NDELAY, facility);
	stderr_level = stdout_level < LOG_ERR ? stdout_level : LOG_ERR;

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
	 * to background jobs; treating SIGHUP as shutdown would stop the jail.
	 */
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGHUP, &sa, NULL) == -1)
		err(1, "sigaction");

	monitor_shutdown_requested = 0;
	sent_sigterm = false;
	sent_sigkill = false;
	have_deadline = false;

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
			char buf[512];
			ssize_t n;
			bool *openp;

			openp = pfd[i].fd == outfd ? &outopen : &erropen;

			if (*openp == false)
				continue;

			if ((pfd[i].revents & POLLIN) == 0) {
				if ((pfd[i].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
					*openp = false;
					close(pfd[i].fd);
				}
				continue;
			}

			n = read(pfd[i].fd, buf, sizeof(buf));
			if (n == 0) {
				*openp = false;
				close(pfd[i].fd);
				continue;
			}
			if (n < 0) {
				if (errno == EINTR)
					continue;
				warn("read");
				*openp = false;
				close(pfd[i].fd);
				continue;
			}

			if (pfd[i].fd == outfd)
				log_stream_data(stdout_level, "stdout", id, name,
				    outline, &outused, buf, (size_t)n);
			else
				log_stream_data(stderr_level, "stderr", id, name,
				    errline, &errused, buf, (size_t)n);
		}
	}

	if (outused > 0)
		syslog(stdout_level, "jail=%s jid=%" PRIu32 " stdout: %.*s",
		    name, id, (int)outused, outline);
	if (errused > 0)
		syslog(stderr_level, "jail=%s jid=%" PRIu32 " stderr: %.*s",
		    name, id, (int)errused, errline);

	if (waitpid(child, &status, 0) == -1 && errno != ECHILD)
		warn("waitpid %jd", (intmax_t)child);

	closelog();
	_exit(0);
}

static void
jail_spawn_detached(jailid_t id, const char *root, const char *name,
    const char *logtag, char *cmd[], int facility, int stdout_level)
{
	int outpipe[2], errpipe[2], devnull;
	pid_t child, mgr;

	if (pipe(outpipe) == -1 || pipe(errpipe) == -1)
		err(1, "pipe");

	mgr = fork();
	if (mgr == -1)
		err(1, "fork");
	if (mgr == 0) {
		child = fork();
		if (child == -1)
			err(1, "fork");
		if (child == 0) {
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
			jail_exec(id, root, cmd);
		}

		close(outpipe[1]);
		close(errpipe[1]);
		jail_run_monitor(id, name, logtag, outpipe[0], errpipe[0], child,
		    facility, stdout_level);
	}

	close(outpipe[0]);
	close(outpipe[1]);
	close(errpipe[0]);
	close(errpipe[1]);
	printf("jail %" PRIu32 "\n", id);
}

static int
parse_log_facility(const char *name)
{
	struct {
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
}

static int
parse_log_level(const char *name)
{
	struct {
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
}

static int
parse_log_priority(const char *arg)
{
	char pri[64], *dot;
	long num;
	char *endp;

	if (strlen(arg) >= sizeof(pri))
		errx(1, "priority too long: %s", arg);
	strlcpy(pri, arg, sizeof(pri));

	errno = 0;
	num = strtol(pri, &endp, 0);
	if (errno == 0 && *pri != '\0' && *endp == '\0') {
		if (num < 0 || num > (LOG_FACMASK | LOG_PRIMASK))
			errx(1, "priority out of range: %s", arg);
		return (int)num;
	}

	dot = strchr(pri, '.');
	if (dot == NULL || dot == pri || dot[1] == '\0')
		errx(1, "invalid priority: %s (expected facility.level)", arg);
	*dot++ = '\0';

	return parse_log_facility(pri) | parse_log_level(dot);
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

static void
parse_port_list(struct jail_create *create, const char *arg)
{
	char *copy, *tok, *cp;
	uintmax_t num;

	copy = strdup(arg);
	if (copy == NULL)
		err(1, "strdup");
	cp = copy;

	while ((tok = strsep(&cp, ",")) != NULL) {
		if (*tok == '\0')
			errx(1, "invalid port list: %s", arg);
		if (getnum(tok, &num) == -1 || num == 0 || num > UINT16_MAX)
			errx(1, "invalid port: %s", tok);
		if (create->jc_nports >= __arraycount(create->jc_ports))
			errx(1, "too many allowed ports (max %zu)",
			    __arraycount(create->jc_ports));
		create->jc_ports[create->jc_nports++] = (uint16_t)num;
	}

	free(copy);
}

static jailid_t
resolve_jail_target(const char *arg, struct jail_info *ji)
{
	uintmax_t num;

	if (getnum(arg, &num) == 0 && num <= UINT32_MAX) {
		if (!jail_lookup_by_id((jailid_t)num, ji))
			errx(1, "jail %" PRIu32 " not found", (jailid_t)num);
		return (jailid_t)num;
	}

	if (jail_lookup_by_name(arg, ji))
		return ji->ji_id;

	errx(1, "jail '%s' not found", arg);
}

int
main(int argc, char *argv[])
{
	jailid_t id;
	const char *root;
	const char *name;
	struct jail_info ji;

	if (argc < 2)
		usage();

	if (strcmp(argv[1], "create") == 0) {
		struct jail_create create;
		char *endp;
		uintmax_t num;
		int ch;

		memset(&create, 0, sizeof(create));
		name = NULL;
		optind = 2;
		while ((ch = getopt(argc, argv, "c:m:n:p:")) != -1) {
			switch (ch) {
			case 'c':
				errno = 0;
				num = strtoumax(optarg, &endp, 0);
				if (errno != 0 || *endp != '\0')
					errx(1, "invalid cpu limit: %s", optarg);
				create.jc_flags |= JAIL_CREATE_CPULIMIT;
				create.jc_cpu_limit = num;
				break;
			case 'm':
				errno = 0;
				num = strtoumax(optarg, &endp, 0);
				if (errno != 0 || *endp != '\0')
					errx(1, "invalid memory limit: %s", optarg);
				create.jc_flags |= JAIL_CREATE_MEMLIMIT;
				create.jc_mem_limit = num;
				break;
			case 'n':
				name = optarg;
				break;
			case 'p':
				create.jc_flags |= JAIL_CREATE_PORTS;
				parse_port_list(&create, optarg);
				break;
			default:
				usage();
			}
		}

		if (optind >= argc || name == NULL || argc != optind + 1)
			usage();
		if ((create.jc_flags & JAIL_CREATE_PORTS) != 0 &&
		    create.jc_nports == 0)
			errx(1, "-p requires at least one port");
		if (strlen(name) > JAIL_NAME_MAX)
			errx(1, "name too long");

		if (jail_lookup_by_name(name, &ji))
			errx(1, "name already exists: %s", name);

		root = argv[optind];
		sanitize_field(name, create.jc_name, sizeof(create.jc_name));
		sanitize_field(root, create.jc_root, sizeof(create.jc_root));
		id = jail_create(&create);
		printf("jail %" PRIu32 "\n", id);
		return 0;
	}

	if (strcmp(argv[1], "supervise") == 0) {
		char **cmd;
		int ch, priority;
		char logtag[JAILCTL_TAG_MAX + 1];

		priority = LOG_DAEMON | LOG_NOTICE;
		strlcpy(logtag, "jailctl", sizeof(logtag));
		optind = 2;
		while ((ch = getopt(argc, argv, "p:t:")) != -1) {
			switch (ch) {
			case 'p':
				priority = parse_log_priority(optarg);
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

		id = resolve_jail_target(argv[optind++], &ji);
		if (optind >= argc)
			errx(1, "supervise requires command [args...]");
		cmd = &argv[optind];

		jail_spawn_detached(id, ji.ji_root, ji.ji_name, logtag, cmd,
		    LOG_FAC(priority), LOG_PRI(priority));
		return 0;
	}

	if (strcmp(argv[1], "destroy") == 0) {
		if (argc != 3)
			usage();

		id = resolve_jail_target(argv[2], &ji);
		jail_destroy(id);
		return 0;
	}

	if (strcmp(argv[1], "exec") == 0) {
		if (argc < 3)
			usage();

		id = resolve_jail_target(argv[2], &ji);

		jail_exec(id, ji.ji_root, argc > 3 ? &argv[3] : NULL);
	}

	if (strcmp(argv[1], "list") == 0) {
		if (argc != 2)
			usage();

		jail_list();
		return 0;
	}

	usage();
	/* NOTREACHED */
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s create [-c cpu-ms] [-m bytes] [-p ports] -n name <root>\n"
	    "       %s supervise [-p pri] [-t tag] <jail-id|name> <command [args...]>\n"
	    "       %s exec <jail-id|name> [command [args...]]\n"
	    "       %s destroy <jail-id|name>\n"
	    "       %s list\n",
	    getprogname(), getprogname(), getprogname(), getprogname(),
	    getprogname());
	exit(1);
}
