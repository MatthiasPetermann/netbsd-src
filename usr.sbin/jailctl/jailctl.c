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
#include <inttypes.h>
#include <paths.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void	usage(void) __dead;

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
jail_create(void)
{
	jailid_t id;
	size_t len;
	int one;

	id = 0;
	len = sizeof(id);
	one = 1;
	if (sysctlbyname("security.models.jail.create", &id, &len,
	    &one, sizeof(one)) == -1)
		err(1, "create jail");

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

	printf("%-8s %-8s\n", "ID", "PROCS");
	for (i = 0; i < count; i++)
		printf("%-8" PRIu32 " %-8" PRIu32 "\n",
		    entries[i].ji_id, entries[i].ji_refcount);

	free(entries);
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
parse_jailid(const char *arg)
{
	uintmax_t num;

	if (getnum(arg, &num) == -1)
		errx(1, "invalid jail id: %s", arg);

	if (num > UINT32_MAX)
		errx(1, "jail id out of range: %s", arg);

	return (jailid_t)num;
}

int
main(int argc, char *argv[])
{
	jailid_t id;
	struct jail_info *entries;
	const char *root;
	const char *shell;
	size_t count, i;
	bool found;

	if (argc < 2)
		usage();

	if (strcmp(argv[1], "create") == 0) {
		if (argc < 3)
			usage();

		root = argv[2];
		id = jail_create();

		if (chdir(root) == -1 || chroot(".") == -1)
			err(1, "%s", root);

		if (chdir("/") == -1)
			err(1, "/");

		jail_enter(id);

		printf("jail %" PRIu32 "\n", id);
		fflush(stdout);

		if (argc > 3) {
			execvp(argv[3], &argv[3]);
			err(1, "%s", argv[3]);
		}

		if ((shell = getenv("SHELL")) == NULL)
			shell = _PATH_BSHELL;
		execlp(shell, shell, "-i", NULL);
		err(1, "%s", shell);
	}

	if (strcmp(argv[1], "destroy") == 0) {
		if (argc != 3)
			usage();

		id = parse_jailid(argv[2]);
		jail_destroy(id);
		return 0;
	}

	if (strcmp(argv[1], "enter") == 0) {
		if (argc < 4)
			usage();

		id = parse_jailid(argv[2]);
		root = argv[3];
		found = false;

		entries = jail_fetch_list(&count);
		for (i = 0; i < count; i++) {
			if (entries[i].ji_id == id) {
				found = true;
				break;
			}
		}
		free(entries);

		if (!found)
			errx(1, "jail %" PRIu32 " not found", id);

		if (chdir(root) == -1 || chroot(".") == -1)
			err(1, "%s", root);

		if (chdir("/") == -1)
			err(1, "/");

		jail_enter(id);

		if (argc > 4) {
			execvp(argv[4], &argv[4]);
			err(1, "%s", argv[4]);
		}

		if ((shell = getenv("SHELL")) == NULL)
			shell = _PATH_BSHELL;
		execlp(shell, shell, "-i", NULL);
		err(1, "%s", shell);
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
	    "usage: %s create <root> [command [args...]]\n"
	    "       %s enter <jail-id> <root> [command [args...]]\n"
	    "       %s destroy <jail-id>\n"
	    "       %s list\n",
	    getprogname(), getprogname(), getprogname(), getprogname());
	exit(1);
}
