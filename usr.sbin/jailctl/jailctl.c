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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <paths.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>
#include <sys/wait.h>

#define JAILCTL_STATEDIR "/var/run/jailctl"
#define JAILCTL_CMD_MAX 511
#define JAILCTL_DETACH_KEY 0x1d	/* Ctrl-] */

struct jail_context {
	jailid_t	id;
	char		command[JAILCTL_CMD_MAX + 1];
	char		sockpath[PATH_MAX];
};

static void	usage(void) __dead;

static void	jail_attach(const struct jail_context *);
static void	jail_exec(jailid_t, const char *, char *[]);
static void	jail_run_manager(const struct jail_context *, int, pid_t);
static void	jail_spawn_detached(jailid_t, const char *, const struct jail_context *, char *[]);
static void	path_context(jailid_t, char *, size_t);
static void	path_socket(jailid_t, char *, size_t);
static void	sanitize_field(const char *, char *, size_t);
static bool	context_load(jailid_t, struct jail_context *);
static bool	jail_lookup_by_name(const char *, struct jail_info *);
static bool	jail_lookup_by_id(jailid_t, struct jail_info *);
static bool	context_save(const struct jail_context *);
static void	context_delete(jailid_t);
static void	build_command_line(int, char *[], char *, size_t);
static jailid_t	resolve_jail_target(const char *, struct jail_info *);

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
path_context(jailid_t id, char *path, size_t sz)
{

	(void)snprintf(path, sz, "%s/%" PRIu32 ".ctx", JAILCTL_STATEDIR, id);
}

static void
path_socket(jailid_t id, char *path, size_t sz)
{

	(void)snprintf(path, sz, "%s/%" PRIu32 ".sock", JAILCTL_STATEDIR, id);
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
context_save(const struct jail_context *ctx)
{
	char path[PATH_MAX];
	FILE *fp;

	if (mkdir(JAILCTL_STATEDIR, 0700) == -1 && errno != EEXIST)
		err(1, "mkdir %s", JAILCTL_STATEDIR);

	path_context(ctx->id, path, sizeof(path));
	fp = fopen(path, "w");
	if (fp == NULL)
		err(1, "%s", path);

	if (fprintf(fp, "command=%s\nsock=%s\n",
	    ctx->command, ctx->sockpath) < 0)
		err(1, "write %s", path);

	if (fclose(fp) == EOF)
		err(1, "close %s", path);

	return true;
}

static bool
context_load(jailid_t id, struct jail_context *ctx)
{
	char path[PATH_MAX], line[PATH_MAX + JAILCTL_CMD_MAX + 32];
	FILE *fp;

	memset(ctx, 0, sizeof(*ctx));
	ctx->id = id;
	path_context(id, path, sizeof(path));
	fp = fopen(path, "r");
	if (fp == NULL)
		return false;

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *eq, *nl;

		eq = strchr(line, '=');
		if (eq == NULL)
			continue;
		*eq++ = '\0';
		nl = strchr(eq, '\n');
		if (nl != NULL)
			*nl = '\0';

		if (strcmp(line, "command") == 0)
			strlcpy(ctx->command, eq, sizeof(ctx->command));
		else if (strcmp(line, "sock") == 0)
			strlcpy(ctx->sockpath, eq, sizeof(ctx->sockpath));
	}

	(void)fclose(fp);
	return ctx->sockpath[0] != '\0';
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
context_delete(jailid_t id)
{
	char path[PATH_MAX], sock[PATH_MAX];

	path_context(id, path, sizeof(path));
	if (unlink(path) == -1 && errno != ENOENT)
		warn("unlink %s", path);

	path_socket(id, sock, sizeof(sock));
	if (unlink(sock) == -1 && errno != ENOENT)
		warn("unlink %s", sock);
}

static void
build_command_line(int argc, char *argv[], char *dst, size_t dsz)
{
	size_t used;
	int i;

	if (argc <= 0) {
		dst[0] = '\0';
		return;
	}

	used = 0;
	for (i = 0; i < argc; i++) {
		int n;

		n = snprintf(dst + used, dsz - used, "%s%s",
		    i == 0 ? "" : " ", argv[i]);
		if (n < 0 || (size_t)n >= dsz - used)
			break;
		used += (size_t)n;
	}

	dst[dsz - 1] = '\0';
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
jail_run_manager(const struct jail_context *ctx, int pty_master, pid_t child)
{
	int server, client;
	struct sockaddr_un sun;

	server = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, ctx->sockpath, sizeof(sun.sun_path));
	unlink(ctx->sockpath);

	if (bind(server, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "bind %s", ctx->sockpath);
	if (listen(server, 1) == -1)
		err(1, "listen %s", ctx->sockpath);

	for (;;) {
		struct pollfd pfd;
		int rv, status;

		if (waitpid(child, &status, WNOHANG) == child)
			break;

		pfd.fd = server;
		pfd.events = POLLIN;
		rv = poll(&pfd, 1, 500);
		if (rv <= 0)
			continue;

		client = accept(server, NULL, NULL);
		if (client == -1)
			continue;

		for (;;) {
			struct pollfd io[2];
			char buf[4096];
			ssize_t n;

			io[0].fd = client;
			io[0].events = POLLIN;
			io[1].fd = pty_master;
			io[1].events = POLLIN;

			rv = poll(io, 2, 500);
			if (rv == -1 && errno == EINTR)
				continue;
			if (rv <= 0) {
				if (waitpid(child, &status, WNOHANG) == child)
					goto out;
				continue;
			}

			if (io[0].revents & POLLIN) {
				n = read(client, buf, sizeof(buf));
				if (n <= 0 || write(pty_master, buf, (size_t)n) == -1)
					break;
			}

			if (io[1].revents & POLLIN) {
				n = read(pty_master, buf, sizeof(buf));
				if (n <= 0 || write(client, buf, (size_t)n) == -1)
					break;
			}
		}

		close(client);
	}
out:
	close(server);
	close(pty_master);
	context_delete(ctx->id);
	_exit(0);
}

static void
jail_spawn_detached(jailid_t id, const char *root, const struct jail_context *ctx, char *cmd[])
{
	int mfd, sfd;
	pid_t child, mgr;

	if (openpty(&mfd, &sfd, NULL, NULL, NULL) == -1)
		err(1, "openpty");

	child = fork();
	if (child == -1)
		err(1, "fork");
	if (child == 0) {
		close(mfd);
		if (setsid() == -1)
			err(1, "setsid");
		if (ioctl(sfd, TIOCSCTTY, 0) == -1)
			err(1, "TIOCSCTTY");
		if (dup2(sfd, STDIN_FILENO) == -1 ||
		    dup2(sfd, STDOUT_FILENO) == -1 ||
		    dup2(sfd, STDERR_FILENO) == -1)
			err(1, "dup2");
		if (sfd > STDERR_FILENO)
			close(sfd);
		jail_exec(id, root, cmd);
	}

	close(sfd);

	mgr = fork();
	if (mgr == -1)
		err(1, "fork");
	if (mgr == 0)
		jail_run_manager(ctx, mfd, child);

	close(mfd);
	printf("jail %" PRIu32 "\n", id);
}

static void
jail_attach(const struct jail_context *ctx)
{
	int fd, rv;
	struct sockaddr_un sun;
	struct termios oldt, raw;
	bool tty;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, ctx->sockpath, sizeof(sun.sun_path));

	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect %s", ctx->sockpath);

	tty = isatty(STDIN_FILENO);
	if (tty && tcgetattr(STDIN_FILENO, &oldt) == 0) {
		raw = oldt;
		cfmakeraw(&raw);
		(void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
	}

	for (;;) {
		struct pollfd io[2];
		char buf[4096];
		ssize_t n;

		io[0].fd = STDIN_FILENO;
		io[0].events = POLLIN;
		io[1].fd = fd;
		io[1].events = POLLIN;

		rv = poll(io, 2, -1);
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv <= 0)
			break;

		if (io[0].revents & POLLIN) {
			ssize_t i;

			n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n <= 0)
				break;

			for (i = 0; i < n; i++) {
				if ((unsigned char)buf[i] == JAILCTL_DETACH_KEY)
					break;
			}

			if (i > 0 && write(fd, buf, (size_t)i) == -1)
				break;

			if (i < n)
				break;
		}

		if (io[1].revents & POLLIN) {
			n = read(fd, buf, sizeof(buf));
			if (n <= 0 || write(STDOUT_FILENO, buf, (size_t)n) == -1)
				break;
		}
	}

	if (tty)
		(void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
	close(fd);
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
	const char *shell;
	char cmdbuf[JAILCTL_CMD_MAX + 1];
	struct jail_context ctx;
	struct jail_info ji;

	if (argc < 2)
		usage();

	if (strcmp(argv[1], "create") == 0) {
		struct jail_create create;
		char *endp;
		uintmax_t num;
		struct in_addr addr;
		int ch;

		memset(&create, 0, sizeof(create));
		name = NULL;
		optind = 2;
		while ((ch = getopt(argc, argv, "c:i:m:n:")) != -1) {
			switch (ch) {
			case 'c':
				errno = 0;
				num = strtoumax(optarg, &endp, 0);
				if (errno != 0 || *endp != '\0')
					errx(1, "invalid cpu limit: %s", optarg);
				create.jc_flags |= JAIL_CREATE_CPULIMIT;
				create.jc_cpu_limit = num;
				break;
			case 'i':
				if (inet_pton(AF_INET, optarg, &addr) != 1)
					errx(1, "invalid IPv4 address: %s", optarg);
				create.jc_flags |= JAIL_CREATE_BIND4;
				create.jc_bind4 = addr.s_addr;
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
			default:
				usage();
			}
		}

		if (optind >= argc || name == NULL)
			usage();
		if (strlen(name) > JAIL_NAME_MAX)
			errx(1, "name too long");

		if (jail_lookup_by_name(name, &ji))
			errx(1, "name already exists: %s", name);

		root = argv[optind];
		sanitize_field(name, create.jc_name, sizeof(create.jc_name));
		sanitize_field(root, create.jc_root, sizeof(create.jc_root));
		id = jail_create(&create);

		memset(&ctx, 0, sizeof(ctx));
		ctx.id = id;
		if (argc > optind + 1) {
			build_command_line(argc - (optind + 1), &argv[optind + 1],
			    cmdbuf, sizeof(cmdbuf));
			sanitize_field(cmdbuf, cmdbuf, sizeof(cmdbuf));
		} else {
			if ((shell = getenv("SHELL")) == NULL)
				shell = _PATH_BSHELL;
			sanitize_field(shell, cmdbuf, sizeof(cmdbuf));
		}
		strlcpy(ctx.command, cmdbuf, sizeof(ctx.command));
		path_socket(id, ctx.sockpath, sizeof(ctx.sockpath));
		(void)context_save(&ctx);

		jail_spawn_detached(id, create.jc_root, &ctx,
		    argc > optind + 1 ? &argv[optind + 1] : NULL);
		return 0;
	}

	if (strcmp(argv[1], "destroy") == 0) {
		if (argc != 3)
			usage();

		id = resolve_jail_target(argv[2], &ji);
		jail_destroy(id);
		context_delete(id);
		return 0;
	}

	if (strcmp(argv[1], "exec") == 0) {
		if (argc < 3)
			usage();

		id = resolve_jail_target(argv[2], &ji);

		jail_exec(id, ji.ji_root, argc > 3 ? &argv[3] : NULL);
	}

	if (strcmp(argv[1], "attach") == 0) {
		if (argc != 3)
			usage();

		id = resolve_jail_target(argv[2], &ji);
		if (!context_load(id, &ctx))
			errx(1, "context for jail %" PRIu32 " not found", id);
		jail_attach(&ctx);
		return 0;
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
	    "usage: %s create [-c cpu-ms] [-i ipv4] [-m bytes] -n name <root> "
	    "[command [args...]]\n"
	    "       %s attach <jail-id|name>\n"
	    "       %s exec <jail-id|name> [command [args...]]\n"
	    "       %s destroy <jail-id|name>\n"
	    "       %s list\n",
	    getprogname(), getprogname(), getprogname(), getprogname(),
	    getprogname());
	exit(1);
}
