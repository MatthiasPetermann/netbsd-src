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
 * Layer: cellman system bootstrap execution layer.
 *
 * Implement bootstrap/reset primitives, module enablement, and base release
 * set preparation steps.
 *
 * Extension guidance: Add bootstrap mechanics here; keep unrelated command
 * routing in command_system.c.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "../cellman.h"
#include "command_backend.h"
#include "command_backend_internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Keep command discovery logic centralized through shared PATH probing.
 */
static bool
command_exists_in_path(const char *cmd)
{
	return cellman_exec_command_exists(cmd);
}

/*
 * Convert mutable filesystem paths in the base layer into overlay symlinks.
 */
int
ensure_base_writable_links(const char *base_layer, char **err)
{
	const char *to_remove[] = {
		"etc", "var", "tmp", "home", "root", "usr/pkg", "opt",
		".cshrc", ".profile",
	};
	const struct {
		const char *link;
		const char *target;
	} links[] = {
		{ "etc", ".overlay/etc" },
		{ "var", ".overlay/var" },
		{ "tmp", ".overlay/tmp" },
		{ "home", ".overlay/home" },
		{ "root", ".overlay/root" },
		{ ".cshrc", ".overlay/.cshrc" },
		{ ".profile", ".overlay/.profile" },
		{ "usr/pkg", "../.overlay/usr/pkg" },
		{ "opt", ".overlay/opt" },
	};
	char *path;
	size_t i;

	if (base_layer == NULL || base_layer[0] == '\0')
		return -1;
	if (access(base_layer, F_OK) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing %s; run bootstrap first",
			    base_layer);
		return -1;
	}

	path = cellman_xasprintf(NULL, "%s/.overlay", base_layer);
	if (path == NULL)
		return -1;
	if (cellman_mkdir_p(path, 0755, err) != 0) {
		free(path);
		return -1;
	}
	free(path);

	path = cellman_xasprintf(NULL, "%s/usr", base_layer);
	if (path == NULL)
		return -1;
	if (cellman_mkdir_p(path, 0755, err) != 0) {
		free(path);
		return -1;
	}
	free(path);

	for (i = 0; i < sizeof(to_remove) / sizeof(to_remove[0]); i++) {
		path = cellman_xasprintf(NULL, "%s/%s", base_layer, to_remove[i]);
		if (path == NULL)
			return -1;
		remove_tree(path);
		free(path);
	}

	for (i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
		path = cellman_xasprintf(NULL, "%s/%s", base_layer, links[i].link);
		if (path == NULL)
			return -1;
		if (symlinkat(links[i].target, AT_FDCWD, path) != 0 &&
		    errno != EEXIST) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cannot symlink %s -> %s: %s",
				    path, links[i].target, strerror(errno));
			free(path);
			return -1;
		}
		free(path);
	}

	return 0;
}

/*
 * Ensure rc.conf enables the cellman service.
 */
int
ensure_rc_conf_cellman(char **err)
{
	char *raw;
	char *dup;
	char *line;
	char *saveptr;
	bool has_yes;
	char *content;

	raw = NULL;
	dup = NULL;
	content = NULL;

	if (cellman_read_optional_text_file("/etc/rc.conf", &raw, err) != 0)
		return -1;

	has_yes = false;
	if (raw != NULL) {
		dup = cellman_strdup(raw, NULL);
		if (dup == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			free(raw);
			return -1;
		}

		saveptr = NULL;
		line = strtok_r(dup, "\n", &saveptr);
		while (line != NULL) {
			char *p;

			p = line;
			while (*p != '\0' && isspace((unsigned char)*p))
				p++;
			if (strncmp(p, "cellman=", 8) == 0 && strcmp(p + 8, "YES") == 0) {
				has_yes = true;
				break;
			}
			line = strtok_r(NULL, "\n", &saveptr);
		}
	}

	if (!has_yes) {
		if (raw == NULL || raw[0] == '\0')
			content = cellman_strdup("cellman=YES\n", err);
		else
			content = cellman_xasprintf(NULL, "%s%s%s", raw,
			    raw[strlen(raw) - 1] == '\n' ? "" : "\n", "cellman=YES\n");
		if (content == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			free(raw);
			free(dup);
			return -1;
		}
		if (cellman_write_text_file("/etc/rc.conf", content, err) != 0) {
			free(raw);
			free(dup);
			free(content);
			return -1;
		}
	}

	free(raw);
	free(dup);
	free(content);
	return 0;
}

/*
 * Ensure modules.conf lists secmodel_cell for automatic module loading.
 */
int
ensure_modules_conf_secmodel(char **err)
{
	char *raw;
	char *dup;
	char *line;
	char *saveptr;
	bool has_module;
	char *content;

	raw = NULL;
	dup = NULL;
	content = NULL;

	if (cellman_read_optional_text_file("/etc/modules.conf", &raw, err) != 0)
		return -1;

	has_module = false;
	if (raw != NULL) {
		dup = cellman_strdup(raw, NULL);
		if (dup == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			free(raw);
			return -1;
		}

		saveptr = NULL;
		line = strtok_r(dup, "\n", &saveptr);
		while (line != NULL) {
			char *p;
			size_t n;

			p = line;
			while (*p != '\0' && isspace((unsigned char)*p))
				p++;
			n = strlen(p);
			while (n > 0 && isspace((unsigned char)p[n - 1]))
				p[--n] = '\0';
			if (strcmp(p, "secmodel_cell") == 0) {
				has_module = true;
				break;
			}
			line = strtok_r(NULL, "\n", &saveptr);
		}
	}

	if (!has_module) {
		if (raw == NULL || raw[0] == '\0')
			content = cellman_strdup("secmodel_cell\n", err);
		else
			content = cellman_xasprintf(NULL, "%s%s%s", raw,
			    raw[strlen(raw) - 1] == '\n' ? "" : "\n", "secmodel_cell\n");
		if (content == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			free(raw);
			free(dup);
			return -1;
		}
		if (cellman_write_text_file("/etc/modules.conf", content, err) != 0) {
			free(raw);
			free(dup);
			free(content);
			return -1;
		}
	}

	free(raw);
	free(dup);
	free(content);
	return 0;
}

/*
 * Load secmodel_cell immediately when it is not currently present.
 */
int
ensure_secmodel_cell_loaded(char **err)
{
	char *raw;
	char *runerr;

	if (!command_exists_in_path("modstat") || !command_exists_in_path("modload")) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "missing required tool: modstat/modload");
		return -1;
	}

	raw = NULL;
	runerr = NULL;
	if (cellman_exec_run_capture((const char *const[]){ "modstat", NULL },
	    &raw, &runerr) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s",
			    runerr != NULL ? runerr : "modstat failed");
		free(raw);
		free(runerr);
		return -1;
	}
	free(runerr);
	runerr = NULL;

	if (raw == NULL || strstr(raw, "secmodel_cell") == NULL) {
		if (cellman_exec_run((const char *const[]){ "modload", "secmodel_cell",
		    NULL }, &runerr) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "modload secmodel_cell failed");
			free(raw);
			free(runerr);
			return -1;
		}
	}

	free(raw);
	free(runerr);
	return 0;
}

/*
 * Fetch release set archives and return resolved local file paths.
 */
int
fetch_release_sets(const char *release, const char *arch, bool include_xbase,
    char **base_set_out, char **etc_set_out, char **xbase_set_out,
    char **set_dir_out, char **err)
{
	const char *mirror_env;
	char *mirror_conf;
	char *set_dir;
	char *base_set;
	char *etc_set;
	char *xbase_set;
	char *mirror;
	char *base_url;
	char *etc_url;
	char *xbase_url;
	bool use_ftp;
	bool use_curl;
	char *runerr;

	if (base_set_out != NULL)
		*base_set_out = NULL;
	if (etc_set_out != NULL)
		*etc_set_out = NULL;
	if (xbase_set_out != NULL)
		*xbase_set_out = NULL;
	if (set_dir_out != NULL)
		*set_dir_out = NULL;

	if (release == NULL || arch == NULL || release[0] == '\0' || arch[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid release/arch for bootstrap");
		return -1;
	}

	set_dir = cellman_xasprintf(NULL, "/var/cellman/releases/%s/%s", release,
	    arch);
	mirror_conf = NULL;
	base_set = cellman_xasprintf(NULL, "%s/base.tar.xz", set_dir != NULL ?
	    set_dir : "");
	etc_set = cellman_xasprintf(NULL, "%s/etc.tar.xz", set_dir != NULL ?
	    set_dir : "");
	xbase_set = cellman_xasprintf(NULL, "%s/xbase.tar.xz", set_dir != NULL ?
	    set_dir : "");
	if (set_dir == NULL || base_set == NULL || etc_set == NULL ||
	    xbase_set == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		free(set_dir);
		free(base_set);
		free(etc_set);
		free(xbase_set);
		return -1;
	}

	if (cellman_mkdir_p(set_dir, 0755, err) != 0) {
		free(set_dir);
		free(base_set);
		free(etc_set);
		free(xbase_set);
		return -1;
	}

	mirror_env = getenv("NETBSD_MIRROR");
	if (cellman_conf_get("NETBSD_MIRROR", &mirror_conf, err) != 0) {
		free(set_dir);
		free(base_set);
		free(etc_set);
		free(xbase_set);
		return -1;
	}

	if (mirror_env != NULL && mirror_env[0] != '\0')
		mirror = cellman_strdup(mirror_env, err);
	else if (mirror_conf != NULL && mirror_conf[0] != '\0')
		mirror = cellman_strdup(mirror_conf, err);
	else
		mirror = cellman_xasprintf(NULL,
		    "https://cdn.netbsd.org/pub/NetBSD/NetBSD-%s/%s/binary/sets",
		    release, arch);
	free(mirror_conf);
	mirror_conf = NULL;
	if (mirror == NULL) {
		free(set_dir);
		free(base_set);
		free(etc_set);
		free(xbase_set);
		return -1;
	}

	base_url = cellman_xasprintf(NULL, "%s/base.tar.xz", mirror);
	etc_url = cellman_xasprintf(NULL, "%s/etc.tar.xz", mirror);
	xbase_url = cellman_xasprintf(NULL, "%s/xbase.tar.xz", mirror);
	if (base_url == NULL || etc_url == NULL || xbase_url == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		free(set_dir);
		free(base_set);
		free(etc_set);
		free(xbase_set);
		free(mirror);
		free(base_url);
		free(etc_url);
		free(xbase_url);
		return -1;
	}

	use_ftp = command_exists_in_path("ftp");
	use_curl = command_exists_in_path("curl");
	if (!use_ftp && !use_curl) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "need ftp(1) or curl to fetch sets");
		free(set_dir);
		free(base_set);
		free(etc_set);
		free(xbase_set);
		free(mirror);
		free(base_url);
		free(etc_url);
		free(xbase_url);
		return -1;
	}

	runerr = NULL;
	if (use_ftp) {
		if (cellman_exec_run((const char *const[]){ "ftp", "-V", "-o",
		    base_set, base_url, NULL }, &runerr) != 0 ||
		    cellman_exec_run((const char *const[]){ "ftp", "-V", "-o",
		    etc_set, etc_url, NULL }, &runerr) != 0 ||
		    (include_xbase && cellman_exec_run((const char *const[]){ "ftp",
		    "-V", "-o", xbase_set, xbase_url, NULL }, &runerr) != 0)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "ftp fetch failed");
			free(runerr);
			free(set_dir);
			free(base_set);
			free(etc_set);
			free(xbase_set);
			free(mirror);
			free(base_url);
			free(etc_url);
			free(xbase_url);
			return -1;
		}
	} else {
		if (cellman_exec_run((const char *const[]){ "curl", "-fL", "-o",
		    base_set, base_url, NULL }, &runerr) != 0 ||
		    cellman_exec_run((const char *const[]){ "curl", "-fL", "-o",
		    etc_set, etc_url, NULL }, &runerr) != 0 ||
		    (include_xbase && cellman_exec_run((const char *const[]){ "curl",
		    "-fL", "-o", xbase_set, xbase_url, NULL }, &runerr) != 0)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "curl fetch failed");
			free(runerr);
			free(set_dir);
			free(base_set);
			free(etc_set);
			free(xbase_set);
			free(mirror);
			free(base_url);
			free(etc_url);
			free(xbase_url);
			return -1;
		}
	}

	free(runerr);
	free(mirror);
	free(base_url);
	free(etc_url);
	free(xbase_url);

	if (set_dir_out != NULL)
		*set_dir_out = set_dir;
	else
		free(set_dir);
	if (base_set_out != NULL)
		*base_set_out = base_set;
	else
		free(base_set);
	if (etc_set_out != NULL)
		*etc_set_out = etc_set;
	else
		free(etc_set);
	if (xbase_set_out != NULL)
		*xbase_set_out = include_xbase ? xbase_set : NULL;
	if (!include_xbase || xbase_set_out == NULL)
		free(xbase_set);

	return 0;
}

/*
 * Build one reusable base layer from downloaded release sets.
 */
int
build_base_layer(const char *release, const char *arch, const char *set_dir,
    bool include_xbase, char **err)
{
	char *base_set;
	char *xbase_set;
	char *base_layer;
	char *runerr;

	base_set = cellman_xasprintf(NULL, "%s/base.tar.xz", set_dir != NULL ?
	    set_dir : "");
	xbase_set = cellman_xasprintf(NULL, "%s/xbase.tar.xz", set_dir != NULL ?
	    set_dir : "");
	base_layer = cellman_xasprintf(NULL, "/var/cellman/base/%s-%s", release,
	    arch);
	if (base_set == NULL || xbase_set == NULL || base_layer == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		free(base_set);
		free(xbase_set);
		free(base_layer);
		return -1;
	}

	if (access(base_set, R_OK) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing %s", base_set);
		free(base_set);
		free(xbase_set);
		free(base_layer);
		return -1;
	}
	if (include_xbase && access(xbase_set, R_OK) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing %s", xbase_set);
		free(base_set);
		free(xbase_set);
		free(base_layer);
		return -1;
	}

	if (cellman_mkdir_p(base_layer, 0755, err) != 0) {
		free(base_set);
		free(xbase_set);
		free(base_layer);
		return -1;
	}

	runerr = NULL;
	if (cellman_exec_run((const char *const[]){ "tar", "-xzp", "-f",
	    base_set, "-C", base_layer, NULL }, &runerr) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s",
			    runerr != NULL ? runerr : "extract base set failed");
		free(runerr);
		free(base_set);
		free(xbase_set);
		free(base_layer);
		return -1;
	}
	free(runerr);
	runerr = NULL;

	if (include_xbase &&
	    cellman_exec_run((const char *const[]){ "tar", "-xzp", "-f",
	    xbase_set, "-C", base_layer, NULL }, &runerr) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s",
			    runerr != NULL ? runerr : "extract xbase set failed");
		free(runerr);
		free(base_set);
		free(xbase_set);
		free(base_layer);
		return -1;
	}
	free(runerr);

	if (ensure_base_writable_links(base_layer, err) != 0) {
		free(base_set);
		free(xbase_set);
		free(base_layer);
		return -1;
	}

	free(base_set);
	free(xbase_set);
	free(base_layer);
	return 0;
}

/*
 * Write a starter `/etc/cellman.conf` when no configuration exists yet.
 */
int
write_default_cellman_conf(const char *release, const char *arch, char **err)
{
	char *content;
	char *pkg_release;
	char *pkg_path;

	if (access("/etc/cellman.conf", R_OK) == 0)
		return 0;

	pkg_release = cellman_release_major_minor(release != NULL ? release : "",
	    err);
	if (pkg_release == NULL)
		return -1;

	pkg_path = cellman_xasprintf(NULL,
	    "http://cdn.NetBSD.org/pub/pkgsrc/packages/NetBSD/%s/%s/All",
	    arch != NULL ? arch : "", pkg_release);
	if (pkg_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		free(pkg_release);
		return -1;
	}

	content = cellman_xasprintf(NULL,
	    "# autogenerated by cellman bootstrap\n"
	    "\n"
	    "RELEASE=%s\n"
	    "MACHINE_ARCH=%s\n"
	    "\n"
	    "# Optional override for fetching NetBSD base sets in system bootstrap.\n"
	    "# If empty, cellman uses:\n"
	    "# https://cdn.netbsd.org/pub/NetBSD/NetBSD-${RELEASE}/${MACHINE_ARCH}/binary/sets\n"
	    "NETBSD_MIRROR=\"\"\n"
	    "\n"
	    "# Package source used for apply pkg/exec/script actions inside cells.\n"
	    "PKG_PATH=%s\n"
	    "\n"
	    "CELL_BASE_DIR=/var/cellman/base\n"
	    "CELL_DATA_DIR=/var/cellman/cells\n"
	    "CELL_VOLUME_DIR=/var/cellman/volumes\n"
	    "CELL_BACKUP_DIR=/var/backups/cellman\n"
	    "CELL_RELEASE_DIR=/var/cellman/releases\n"
	    "CELL_ALLOW_HOST_MOUNTS=NO\n",
	    release != NULL ? release : "", arch != NULL ? arch : "", pkg_path);
	if (content == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		free(pkg_release);
		free(pkg_path);
		return -1;
	}

	if (cellman_write_text_file("/etc/cellman.conf", content, err) != 0) {
		free(content);
		free(pkg_release);
		free(pkg_path);
		return -1;
	}

	free(content);
	free(pkg_release);
	free(pkg_path);
	return 0;
}
