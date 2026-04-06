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
 * Layer: cellman command backend execution layer.
 *
 * Implement core desired/runtime reconciliation, lifecycle operations, read
 * views, and safety checks.
 *
 * Extension guidance: Add backend behavior here when it spans multiple command
 * families; keep routing/option parsing in dedicated command modules.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "../cellman.h"
#include "command_backend.h"
#include "command_backend_internal.h"
#include "command_backup_cli.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>

/*
 * Shared runtime helpers plus apply/cell lifecycle execution paths.
 *
 * Top-level and resource subcommand routing live in the dedicated dispatcher
 * modules under commands/.
 */

static int run_argv_capture(const char *const [], char **, char **);
static bool destroy_error_is_busy(const char *);
static int run_cellctl_destroy(const char *, bool, char **);
static int stop_runtime_cell_name(const char *, const char *, char **);
static int stop_runtime_cell_doc(const struct runtime_cell *, char **);
static int stop_supervise_monitor(const char *, const char *, char **);
static bool runtime_name_valid(const char *);
static int cell_runtime_exists(const char *, bool *, char **);
static int state_find_volume(const struct cellman_state *, const char *);

static bool field_name_token_valid(const char *);
static int split_csv_field_tokens(const char *, struct cellman_string_list *,
    char **);
static int join_string_list_csv(const struct cellman_string_list *, char **,
    char **);
static int compare_cstr_ptr(const void *, const void *);
static bool string_list_contains(const struct cellman_string_list *,
    const char *);
static int is_path_mounted(const char *, bool *, char **);
static int parse_mount_spec(const char *, char **, char **, bool *, bool *,
    char **);
static int host_mounts_allowed(bool *, char **);
static int mount_target_source(const char *, bool *, char **, char **);
static int setup_cell_local_dev_runtime(const char *, const char *,
    const char *, char **);
static int mount_cell_root_runtime(const struct cellman_doc *, const char *,
    char **);
static int mount_cell_volumes_runtime(const struct cellman_state *,
    const struct cellman_doc *, const char *, char **);
static int unmount_under_root(const char *, char **);
static int unmount_cell_mounts_name(const char *, char **);
static bool run_as_ident_valid(const char *);
static int parse_numeric_id(const char *, unsigned long *, const char *,
    char **);
static int gid_list_add_unique(struct cellman_string_list *, unsigned long,
    char **);
static int add_gid_tokens_from_text(const char *, struct cellman_string_list *,
    char **);
static int add_host_user_groups(const char *, struct cellman_string_list *,
    char **);
static bool csv_member_contains(const char *, const char *);
static int add_cell_user_groups(const char *, const char *, gid_t,
    struct cellman_string_list *, char **);
static int resolve_host_group_gid(const char *, gid_t *, char **);
static int resolve_cell_user_ids(const char *, const char *, uid_t *, gid_t *,
    char **);
static int resolve_cell_group_gid(const char *, const char *, gid_t *, char **);
static int resolve_supervise_run_as(const char *, const char *, uid_t *,
    gid_t *, char **, char **);

static void cell_snapshot_row_free(struct cell_snapshot_row *);
static int cell_snapshot_table_add(struct cell_snapshot_table *,
    struct cell_snapshot_row *, char **);
static void volume_snapshot_row_free(struct volume_snapshot_row *);
static int volume_snapshot_table_add(struct volume_snapshot_table *,
    struct volume_snapshot_row *, char **);
static int build_cell_dependency_order(const struct cellman_state *,
    const struct cellman_doc ***, size_t *, char **);
static int mark_cell_needed(const struct cellman_state *, int, bool *, char **);
static int ensure_cell_state_dir(const char *, char **);
static int read_optional_text_file(const char *, char **, char **);
static int write_text_file(const char *, const char *, char **);
static void hash64_init(uint64_t *);
static void hash64_update_bytes(uint64_t *, const void *, size_t);
static void hash64_update_str(uint64_t *, const char *);
static int hash64_update_file(uint64_t *, const char *, char **);
static int hash64_hex(uint64_t, char **, char **);
static void hash64_update_string_list(uint64_t *,
    const struct cellman_string_list *);
static void hash64_update_kv_list(uint64_t *, const struct cellman_kv_list *);
static int resolve_doc_source_path(const struct cellman_doc *, const char *,
    char **, char **);
static int compute_cell_config_hashes(const struct cellman_doc *, char **,
    char **, char **);
static int compute_apply_doc_hash(const struct cellman_doc *, char **, char **);
static int compute_volume_mode_change(const char *, const char *, bool *,
    char **);
static bool cell_autostart_desired(const struct cellman_doc *);
static int read_cell_state_hash(const char *, const char *, char **, char **);
static int write_cell_state_hash(const char *, const char *, const char *,
    char **);
static int remove_cell_state_hash(const char *, const char *, char **);
static int run_cell_healthcheck(const struct cellman_doc *, char **);
static int apply_run_for_cell(const struct cellman_doc *, const struct cellman_doc *,
    const char *, bool, bool, bool, char **);
static int start_cells_with_dependencies(const char *, const char *, bool,
    bool, char **);

/*
 * Preserve the legacy command helper entry point for command modules.
 */
int
run_argv(const char *const argv[], char **err)
{
	/* Keep existing call sites stable while delegating to shared exec helpers. */
	return cellman_exec_run(argv, err);
}

/*
 * Preserve local capture helper naming while routing to shared exec code.
 */
static int
run_argv_capture(const char *const argv[], char **out, char **err)
{
	/* Keep local helper name stable while using shared capture implementation. */
	return cellman_exec_run_capture(argv, out, err);
}

static bool
destroy_error_is_busy(const char *msg)
{
	if (msg == NULL)
		return false;

	return strstr(msg, "Device busy") != NULL ||
	    strstr(msg, "device busy") != NULL ||
	    strstr(msg, "EBUSY") != NULL ||
	    strstr(msg, "busy") != NULL;
}

static int
run_cellctl_destroy(const char *target, bool log_retries, char **err)
{
	const int max_attempts = 20;
	const char *destroy_argv[] = { "cellctl", "destroy", NULL, NULL };
	struct timespec pause;
	int attempt;

	if (err != NULL)
		*err = NULL;
	if (target == NULL || target[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell target");
		return -1;
	}

	pause.tv_sec = 0;
	pause.tv_nsec = 200 * 1000 * 1000;

	destroy_argv[2] = target;
	for (attempt = 1; attempt <= max_attempts; attempt++) {
		char *cmd_out;
		char *cmd_err;
		const char *msg;
		bool retry_busy;

		cmd_out = NULL;
		cmd_err = NULL;
		if (run_argv_capture(destroy_argv, &cmd_out, &cmd_err) == 0) {
			free(cmd_out);
			return 0;
		}

		msg = cmd_err != NULL ? cmd_err :
		    (cmd_out != NULL ? cmd_out : "cellctl destroy failed");
		retry_busy = attempt < max_attempts && destroy_error_is_busy(msg);
		if (retry_busy) {
			if (log_retries) {
				cellman_log_warn("cell destroy %s failed with busy state; retry %d/%d",
				    target, attempt + 1, max_attempts);
			}
			free(cmd_out);
			free(cmd_err);
			(void)nanosleep(&pause, NULL);
			continue;
		}

		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s", msg);
		free(cmd_out);
		free(cmd_err);
		return -1;
	}

	if (err != NULL)
		*err = cellman_xasprintf(NULL, "cellctl destroy failed");
	return -1;
}

static int
stop_supervise_monitor(const char *name, const char *cid, char **err)
{
	char *raw;
	char *runerr;
	char *pattern;
	char *line;
	char *saveptr;
	pid_t pid;
	struct timespec pause;

	(void)err;
	if (name == NULL || name[0] == '\0' || cid == NULL || cid[0] == '\0')
		return 0;

	raw = NULL;
	runerr = NULL;
	pattern = cellman_xasprintf(NULL, "cellctl supervise cell=%s cid=%s", name,
	    cid);
	if (pattern == NULL)
		return 0;

	if (run_argv_capture((const char *const[]){ "ps", "-axo", "pid,command",
	    NULL }, &raw, &runerr) != 0) {
		free(raw);
		free(runerr);
		free(pattern);
		return 0;
	}
	free(runerr);
	runerr = NULL;

	pid = -1;
	saveptr = NULL;
	line = strtok_r(raw, "\n", &saveptr);
	while (line != NULL) {
		char *p;
		char *endp;
		long lpid;

		p = line;
		while (*p != '\0' && isspace((unsigned char)*p))
			p++;

		errno = 0;
		lpid = strtol(p, &endp, 10);
		if (errno == 0 && endp != p && lpid > 1) {
			while (*endp != '\0' && isspace((unsigned char)*endp))
				endp++;
			if (strstr(endp, pattern) != NULL) {
				pid = (pid_t)lpid;
				break;
			}
		}

		line = strtok_r(NULL, "\n", &saveptr);
	}

	free(raw);
	free(pattern);

	if (pid <= 1)
		return 0;

	(void)kill(pid, SIGTERM);
	pause.tv_sec = 1;
	pause.tv_nsec = 0;
	(void)nanosleep(&pause, NULL);
	if (kill(pid, SIGKILL) != 0 && errno != ESRCH)
		return -1;
	return 0;
}

static int
stop_runtime_cell_name(const char *name, const char *cid, char **err)
{
	char *runerr;
	const char *target;

	if (name == NULL || name[0] == '\0')
		return 0;

	(void)stop_supervise_monitor(name, cid, NULL);

	target = (cid != NULL && cid[0] != '\0') ? cid : name;
	runerr = NULL;
	if (run_cellctl_destroy(target, true, &runerr) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s",
			    runerr != NULL ? runerr : "cellctl destroy failed");
		free(runerr);
		return -1;
	}
	free(runerr);

	if (unmount_cell_mounts_name(name, err) != 0)
		return -1;

	return 0;
}

static int
stop_runtime_cell_doc(const struct runtime_cell *row, char **err)
{
	if (row == NULL)
		return 0;
	return stop_runtime_cell_name(row->name, row->cid, err);
}

void
remove_tree(const char *path)
{
	struct stat st;

	if (path == NULL)
		return;

	if (lstat(path, &st) != 0)
		return;

	if (S_ISDIR(st.st_mode)) {
		DIR *dp;
		struct dirent *de;

		dp = opendir(path);
		if (dp != NULL) {
			while ((de = readdir(dp)) != NULL) {
				char *child;

				if (strcmp(de->d_name, ".") == 0 ||
				    strcmp(de->d_name, "..") == 0)
					continue;
				child = cellman_path_join(path, de->d_name, NULL);
				if (child != NULL) {
					remove_tree(child);
					free(child);
				}
			}
			(void)closedir(dp);
		}
		(void)rmdir(path);
		return;
	}

	(void)unlink(path);
}

static int
state_find_apply(const struct cellman_state *state, const char *name)
{
	size_t i;

	for (i = 0; i < state->applies.len; i++) {
		if (strcmp(state->applies.items[i].u.apply.name, name) == 0)
			return (int)i;
	}

	return -1;
}

static int
state_find_cell(const struct cellman_state *state, const char *name)
{
	size_t i;

	for (i = 0; i < state->cells.len; i++) {
		if (strcmp(state->cells.items[i].u.cell.name, name) == 0)
			return (int)i;
	}

	return -1;
}

static int
state_find_volume(const struct cellman_state *state, const char *name)
{
	size_t i;

	for (i = 0; i < state->volumes.len; i++) {
		if (strcmp(state->volumes.items[i].u.volume.name, name) == 0)
			return (int)i;
	}

	return -1;
}

struct cell_field_def {
	const char *name;
	bool in_desired;
	bool in_runtime;
	bool in_compact;
	int index;
};

struct volume_field_def {
	const char *name;
	bool in_desired;
	bool in_runtime;
	int index;
};

static const struct cell_field_def cell_field_defs[] = {
	{ "name", true, true, true, 0 },
	{ "running", false, true, true, 1 },
	{ "state", true, true, true, 2 },
	{ "cid", false, true, true, 3 },
	{ "refs", false, true, false, 4 },
	{ "procs", false, true, true, 5 },
	{ "cpu1s", false, true, false, 6 },
	{ "cpu10s", false, true, false, 7 },
	{ "memory", false, true, false, 8 },
	{ "age", false, true, true, 9 },
	{ "root", false, true, false, 10 },
	{ "autostart", true, false, true, 11 },
	{ "profile", true, false, false, 12 },
	{ "reserved_ports", true, false, true, 13 },
	{ "rlimit_nofile", true, false, false, 14 },
	{ "rlimit_as", true, false, false, 15 },
	{ "rlimit_core", true, false, false, 16 },
	{ "depends_on", true, false, false, 17 },
	{ "healthcheck", true, false, false, 18 },
	{ "supervise_cmd", true, false, false, 19 },
	{ "volume_mounts", true, false, false, 20 },
	{ "apply_present", true, false, false, 21 },
	{ "supervise_run_as", true, true, false, 22 },
};

static const struct volume_field_def volume_field_defs[] = {
	{ "name", true, true, 0 },
	{ "state", true, true, 1 },
	{ "mode", true, false, 2 },
	{ "path", false, true, 3 },
	{ "mounted", false, true, 4 },
	{ "refs", true, true, 5 },
	{ "used_by", true, true, 6 },
};

static const char *const cell_default_fields_desired =
	"name,state,autostart,profile,reserved_ports,"
	"rlimit_nofile,rlimit_as,rlimit_core,depends_on,"
	"healthcheck,volume_mounts,supervise_cmd,supervise_run_as,"
	"apply_present";
static const char *const cell_default_fields_runtime =
	"name,state,running,cid,procs,refs,cpu1s,cpu10s,memory,age,root,"
	"supervise_run_as";
static const char *const cell_default_fields_compact =
	"name,state,running,cid,procs,age,autostart,reserved_ports";
static const char *const cell_default_fields_merged =
	"name,state,running,cid,procs,refs,cpu1s,cpu10s,memory,age,"
	"autostart,profile,reserved_ports,rlimit_nofile,"
	"rlimit_as,rlimit_core,root,supervise_cmd,supervise_run_as,"
	"apply_present";

static const char *const volume_default_fields_desired =
	"name,state,mode,refs,used_by";
static const char *const volume_default_fields_runtime =
	"name,state,path,mounted,refs,used_by";
static const char *const volume_default_fields_merged =
	"name,state,refs,mounted,mode,path,used_by";

int
parse_read_view(const char *value, enum read_view *view, char **err)
{
	if (view == NULL)
		return -1;

	if (value == NULL || strcmp(value, "merged") == 0) {
		*view = READ_VIEW_MERGED;
		return 0;
	}
	if (strcmp(value, "desired") == 0) {
		*view = READ_VIEW_DESIRED;
		return 0;
	}
	if (strcmp(value, "runtime") == 0) {
		*view = READ_VIEW_RUNTIME;
		return 0;
	}
	if (strcmp(value, "compact") == 0) {
		*view = READ_VIEW_COMPACT;
		return 0;
	}

	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "invalid view '%s' (expected merged|desired|runtime|compact)",
		    value);
	return -1;
}

static bool
field_name_token_valid(const char *token)
{
	size_t i;

	if (token == NULL || token[0] == '\0')
		return false;

	for (i = 0; token[i] != '\0'; i++) {
		if (!(islower((unsigned char)token[i]) ||
		    isdigit((unsigned char)token[i]) || token[i] == '_'))
			return false;
	}

	return true;
}

static int
split_csv_field_tokens(const char *csv, struct cellman_string_list *out,
    char **err)
{
	char *copy;
	char *tok;
	char *save;

	if (out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));

	if (csv == NULL || csv[0] == '\0')
		return 0;

	copy = cellman_strdup(csv, err);
	if (copy == NULL)
		return -1;

	save = NULL;
	tok = strtok_r(copy, ",", &save);
	while (tok != NULL) {
		if (!field_name_token_valid(tok)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid field token '%s'", tok);
			free(copy);
			cellman_string_list_free(out);
			return -1;
		}

		if (cellman_string_list_add(out, tok, err) != 0) {
			free(copy);
			cellman_string_list_free(out);
			return -1;
		}
		tok = strtok_r(NULL, ",", &save);
	}

	free(copy);
	return 0;
}

static int
join_string_list_csv(const struct cellman_string_list *items, char **out,
    char **err)
{
	size_t i;
	size_t len;
	char *buf;
	size_t off;

	if (out == NULL)
		return -1;
	*out = NULL;

	if (items == NULL || items->len == 0) {
		*out = cellman_strdup("", err);
		return *out != NULL ? 0 : -1;
	}

	len = 1;
	for (i = 0; i < items->len; i++)
		len += strlen(items->items[i]) + (i == 0 ? 0 : 1);

	buf = calloc(1, len);
	if (buf == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	off = 0;
	for (i = 0; i < items->len; i++) {
		size_t part;

		if (i != 0)
			buf[off++] = ',';
		part = strlen(items->items[i]);
		memcpy(buf + off, items->items[i], part);
		off += part;
	}
	buf[off] = '\0';

	*out = buf;
	return 0;
}

static int
compare_cstr_ptr(const void *a, const void *b)
{
	const char *const *ap;
	const char *const *bp;

	ap = a;
	bp = b;
	return strcmp(*ap, *bp);
}

static const char *
read_view_name(enum read_view view)
{
	switch (view) {
	case READ_VIEW_DESIRED:
		return "desired";
	case READ_VIEW_RUNTIME:
		return "runtime";
	case READ_VIEW_COMPACT:
		return "compact";
	case READ_VIEW_MERGED:
	default:
		return "merged";
	}
}

static bool
string_list_contains(const struct cellman_string_list *list, const char *value)
{
	size_t i;

	if (list == NULL || value == NULL)
		return false;

	for (i = 0; i < list->len; i++) {
		if (strcmp(list->items[i], value) == 0)
			return true;
	}

	return false;
}

/*
 * Query mount state through the shared mount inspection helper.
 */
static int
is_path_mounted(const char *path, bool *mounted_out, char **err)
{
	return cellman_is_path_mounted(path, mounted_out, err);
}

/*
 * Keep path safety checks centralized in one shared implementation.
 */
bool
path_is_same_or_child(const char *child, const char *parent)
{
	return cellman_path_is_same_or_child(child, parent);
}

static bool
run_as_ident_valid(const char *value)
{
	size_t i;

	if (value == NULL || value[0] == '\0')
		return false;
	for (i = 0; value[i] != '\0'; i++) {
		if (!(isalnum((unsigned char)value[i]) || value[i] == '.' ||
		    value[i] == '_' || value[i] == '-'))
			return false;
	}
	return true;
}

static int
parse_numeric_id(const char *text, unsigned long *out, const char *label,
    char **err)
{
	unsigned long v;
	char *end;

	if (text == NULL || text[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing %s", label);
		return -1;
	}

	errno = 0;
	v = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid %s: %s", label, text);
		return -1;
	}

	if (out != NULL)
		*out = v;
	return 0;
}

static int
gid_list_add_unique(struct cellman_string_list *list, unsigned long gid_v,
    char **err)
{
	char *gid_s;

	if (list == NULL)
		return -1;

	gid_s = cellman_xasprintf(NULL, "%lu", gid_v);
	if (gid_s == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	if (!string_list_contains(list, gid_s) &&
	    cellman_string_list_add(list, gid_s, err) != 0) {
		free(gid_s);
		return -1;
	}

	free(gid_s);
	return 0;
}

static int
add_gid_tokens_from_text(const char *text, struct cellman_string_list *out,
    char **err)
{
	char *dup;
	char *tok;
	char *saveptr;

	if (text == NULL || out == NULL)
		return -1;

	dup = cellman_strdup(text, err);
	if (dup == NULL)
		return -1;

	saveptr = NULL;
	tok = strtok_r(dup, " \t\r\n", &saveptr);
	while (tok != NULL) {
		unsigned long gid_v;

		if (parse_numeric_id(tok, &gid_v, "gid", err) != 0) {
			free(dup);
			return -1;
		}
		if (gid_list_add_unique(out, gid_v, err) != 0) {
			free(dup);
			return -1;
		}
		tok = strtok_r(NULL, " \t\r\n", &saveptr);
	}

	free(dup);
	return 0;
}

static int
add_host_user_groups(const char *user, struct cellman_string_list *out,
    char **err)
{
	char *raw;
	char *runerr;

	if (user == NULL || out == NULL)
		return -1;

	raw = NULL;
	runerr = NULL;
	if (run_argv_capture((const char *const[]){ "id", "-G",
	    user, NULL }, &raw, &runerr) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s",
			    runerr != NULL ? runerr : "failed to resolve host groups");
		free(raw);
		free(runerr);
		return -1;
	}

	if (add_gid_tokens_from_text(raw, out, err) != 0) {
		free(raw);
		free(runerr);
		return -1;
	}

	free(raw);
	free(runerr);
	return 0;
}

static bool
csv_member_contains(const char *csv, const char *name)
{
	char *dup;
	char *tok;
	char *saveptr;
	bool found;

	if (csv == NULL || name == NULL || name[0] == '\0')
		return false;

	dup = cellman_strdup(csv, NULL);
	if (dup == NULL)
		return false;

	found = false;
	saveptr = NULL;
	tok = strtok_r(dup, ",", &saveptr);
	while (tok != NULL) {
		if (strcmp(tok, name) == 0) {
			found = true;
			break;
		}
		tok = strtok_r(NULL, ",", &saveptr);
	}

	free(dup);
	return found;
}

static int
add_cell_user_groups(const char *root, const char *user, gid_t primary_gid,
    struct cellman_string_list *out, char **err)
{
	char *group_path;
	FILE *fp;
	char *line;
	size_t cap;

	if (root == NULL || user == NULL || out == NULL)
		return -1;

	if (gid_list_add_unique(out, (unsigned long)primary_gid, err) != 0)
		return -1;

	group_path = cellman_xasprintf(NULL, "%s/etc/group", root);
	if (group_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	fp = fopen(group_path, "r");
	if (fp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "unable to open cell group database %s: %s", group_path,
			    strerror(errno));
		free(group_path);
		return -1;
	}

	line = NULL;
	cap = 0;
	while (getline(&line, &cap, fp) != -1) {
		char *dup;
		char *saveptr;
		char *gid_s;
		char *members;
		unsigned long gid_v;

		if (line[0] == '#' || line[0] == '\n')
			continue;

		dup = cellman_strdup(line, NULL);
		if (dup == NULL)
			continue;

		saveptr = NULL;
		(void)strtok_r(dup, ":\n", &saveptr);
		(void)strtok_r(NULL, ":\n", &saveptr);
		gid_s = strtok_r(NULL, ":\n", &saveptr);
		members = strtok_r(NULL, ":\n", &saveptr);

		if (gid_s == NULL || members == NULL ||
		    !csv_member_contains(members, user) ||
		    parse_numeric_id(gid_s, &gid_v, "gid", NULL) != 0) {
			free(dup);
			continue;
		}

		if (gid_list_add_unique(out, gid_v, err) != 0) {
			free(dup);
			free(line);
			(void)fclose(fp);
			free(group_path);
			return -1;
		}

		free(dup);
	}

	free(line);
	(void)fclose(fp);
	free(group_path);
	return 0;
}

static int
resolve_host_group_gid(const char *group, gid_t *gid_out, char **err)
{
	struct group *gr;
	unsigned long gid_v;

	if (gid_out == NULL)
		return -1;

	if (group == NULL || group[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "empty host group");
		return -1;
	}

	if (parse_numeric_id(group, &gid_v, "gid", NULL) == 0) {
		*gid_out = (gid_t)gid_v;
		return 0;
	}

	gr = getgrnam(group);
	if (gr == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "unable to resolve host group '%s'", group);
		return -1;
	}

	*gid_out = gr->gr_gid;
	return 0;
}

static int
resolve_cell_user_ids(const char *root, const char *user, uid_t *uid_out,
    gid_t *gid_out, char **err)
{
	char *passwd_path;
	FILE *fp;
	char *line;
	size_t cap;
	int found;

	if (uid_out == NULL || gid_out == NULL)
		return -1;

	if (!run_as_ident_valid(user)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell user in run_as: %s",
			    user != NULL ? user : "");
		return -1;
	}

	passwd_path = cellman_xasprintf(NULL, "%s/etc/passwd", root);
	if (passwd_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}
	if (access(passwd_path, R_OK) != 0) {
		free(passwd_path);
		passwd_path = cellman_xasprintf(NULL, "%s/etc/master.passwd", root);
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
			    "unable to open cell passwd database %s: %s", passwd_path,
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
		char *gid_s;
		char *tok;
		unsigned long uid_v;
		unsigned long gid_v;

		if (line[0] == '#' || line[0] == '\n')
			continue;

		dup = cellman_strdup(line, NULL);
		if (dup == NULL)
			continue;

		saveptr = NULL;
		name = strtok_r(dup, ":\n", &saveptr);
		(void)strtok_r(NULL, ":\n", &saveptr);
		uid_s = strtok_r(NULL, ":\n", &saveptr);
		gid_s = strtok_r(NULL, ":\n", &saveptr);
		tok = strtok_r(NULL, ":\n", &saveptr);
		(void)tok;

		if (name != NULL && uid_s != NULL && gid_s != NULL &&
		    strcmp(name, user) == 0 &&
		    parse_numeric_id(uid_s, &uid_v, "cell uid", NULL) == 0 &&
		    parse_numeric_id(gid_s, &gid_v, "cell gid", NULL) == 0) {
			*uid_out = (uid_t)uid_v;
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
			    "unable to resolve cell user '%s' in %s", user, passwd_path);
		free(passwd_path);
		return -1;
	}

	free(passwd_path);
	return 0;
}

static int
resolve_cell_group_gid(const char *root, const char *group, gid_t *gid_out,
    char **err)
{
	char *group_path;
	FILE *fp;
	char *line;
	size_t cap;
	int found;
	unsigned long gid_v;

	if (gid_out == NULL)
		return -1;

	if (group == NULL || group[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "empty cell group");
		return -1;
	}

	if (parse_numeric_id(group, &gid_v, "gid", NULL) == 0) {
		*gid_out = (gid_t)gid_v;
		return 0;
	}

	if (!run_as_ident_valid(group)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell group in run_as: %s",
			    group);
		return -1;
	}

	group_path = cellman_xasprintf(NULL, "%s/etc/group", root);
	if (group_path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	fp = fopen(group_path, "r");
	if (fp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "unable to open cell group database %s: %s", group_path,
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
		    parse_numeric_id(gid_s, &gid_v, "cell gid", NULL) == 0) {
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
			    "unable to resolve cell group '%s' in %s", group, group_path);
		free(group_path);
		return -1;
	}

	free(group_path);
	return 0;
}

static int
resolve_supervise_run_as(const char *spec, const char *root, uid_t *uid_out,
    gid_t *gid_out, char **groups_out, char **err)
{
	const char *body;
	const char *sep;
	char *first;
	char *second;
	char *groups;
	unsigned long uid_v;
	unsigned long gid_v;
	struct passwd *pw;
	gid_t primary_gid;
	struct cellman_string_list gids;

	if (uid_out == NULL || gid_out == NULL)
		return -1;
	if (groups_out != NULL)
		*groups_out = NULL;

	if (spec == NULL || spec[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "empty run_as specification");
		return -1;
	}

	if (strncmp(spec, "uid:", 4) == 0) {
		body = spec + 4;
		sep = strchr(body, ':');
		if (sep == NULL) {
			if (parse_numeric_id(body, &uid_v, "uid", err) != 0)
				return -1;
			*uid_out = (uid_t)uid_v;
			*gid_out = (gid_t)uid_v;
			return 0;
		}
		if (strchr(sep + 1, ':') != NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid run_as '%s' (expected uid:uid[:gid])", spec);
			return -1;
		}
		first = cellman_strndup(body, (size_t)(sep - body), err);
		second = cellman_strdup(sep + 1, err);
		if (first == NULL || second == NULL) {
			free(first);
			free(second);
			return -1;
		}
		if (parse_numeric_id(first, &uid_v, "uid", err) != 0 ||
		    parse_numeric_id(second, &gid_v, "gid", err) != 0) {
			free(first);
			free(second);
			return -1;
		}
		free(first);
		free(second);
		*uid_out = (uid_t)uid_v;
		*gid_out = (gid_t)gid_v;
		return 0;
	}

	if (strncmp(spec, "host:", 5) == 0) {
		memset(&gids, 0, sizeof(gids));
		groups = NULL;
		body = spec + 5;
		sep = strchr(body, ':');
		if (sep != NULL && strchr(sep + 1, ':') != NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid run_as '%s' (expected host:user[:group])", spec);
			return -1;
		}
		if (sep == NULL) {
			first = cellman_strdup(body, err);
			second = NULL;
		} else {
			first = cellman_strndup(body, (size_t)(sep - body), err);
			second = cellman_strdup(sep + 1, err);
		}
		if (first == NULL || (sep != NULL && second == NULL)) {
			free(first);
			free(second);
			return -1;
		}
		if (!run_as_ident_valid(first) ||
		    (second != NULL && !run_as_ident_valid(second))) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid run_as '%s' (host user/group token)", spec);
			free(first);
			free(second);
			return -1;
		}
		pw = getpwnam(first);
		if (pw == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "unable to resolve host user '%s'", first);
			free(first);
			free(second);
			return -1;
		}
		*uid_out = pw->pw_uid;
		*gid_out = pw->pw_gid;
		if (second != NULL && second[0] != '\0' &&
		    resolve_host_group_gid(second, gid_out, err) != 0) {
			free(first);
			free(second);
			return -1;
		}
		if (add_host_user_groups(first, &gids, err) != 0) {
			cellman_string_list_free(&gids);
			free(first);
			free(second);
			return -1;
		}
		if (gid_list_add_unique(&gids, (unsigned long)*gid_out, err) != 0 ||
		    join_string_list_csv(&gids, &groups, err) != 0) {
			cellman_string_list_free(&gids);
			free(first);
			free(second);
			free(groups);
			return -1;
		}
		if (groups != NULL && groups[0] == '\0') {
			free(groups);
			groups = NULL;
		}
		if (groups_out != NULL)
			*groups_out = groups;
		else
			free(groups);
		cellman_string_list_free(&gids);
		free(first);
		free(second);
		return 0;
	}

	if (strncmp(spec, "cell:", 5) == 0) {
		memset(&gids, 0, sizeof(gids));
		groups = NULL;
		body = spec + 5;
		sep = strchr(body, ':');
		if (sep != NULL && strchr(sep + 1, ':') != NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "invalid run_as '%s' (expected cell:user[:group])", spec);
			return -1;
		}
		if (sep == NULL) {
			first = cellman_strdup(body, err);
			second = NULL;
		} else {
			first = cellman_strndup(body, (size_t)(sep - body), err);
			second = cellman_strdup(sep + 1, err);
		}
		if (first == NULL || (sep != NULL && second == NULL)) {
			free(first);
			free(second);
			return -1;
		}

		if (resolve_cell_user_ids(root, first, uid_out, &primary_gid, err) != 0) {
			free(first);
			free(second);
			return -1;
		}
		*gid_out = primary_gid;
		if (second != NULL && second[0] != '\0' &&
		    resolve_cell_group_gid(root, second, gid_out, err) != 0) {
			free(first);
			free(second);
			return -1;
		}
		if (add_cell_user_groups(root, first, primary_gid, &gids, err) != 0 ||
		    gid_list_add_unique(&gids, (unsigned long)*gid_out, err) != 0 ||
		    join_string_list_csv(&gids, &groups, err) != 0) {
			cellman_string_list_free(&gids);
			free(first);
			free(second);
			free(groups);
			return -1;
		}
		if (groups != NULL && groups[0] == '\0') {
			free(groups);
			groups = NULL;
		}
		if (groups_out != NULL)
			*groups_out = groups;
		else
			free(groups);
		cellman_string_list_free(&gids);

		free(first);
		free(second);
		return 0;
	}

	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "invalid run_as '%s' (expected host:user[:group], cell:user[:group], or uid:uid[:gid])",
		    spec);
	return -1;
}

static int
parse_mount_spec(const char *spec, char **source_out, char **target_out,
    bool *readonly_out, bool *host_source_out, char **err)
{
	const char *first;
	const char *second;
	const char *mode;
	char *source;
	char *target;

	if (source_out == NULL || target_out == NULL || readonly_out == NULL ||
	    host_source_out == NULL)
		return -1;
	*source_out = NULL;
	*target_out = NULL;
	*readonly_out = false;
	*host_source_out = false;

	if (spec == NULL || spec[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "empty mount specification");
		return -1;
	}

	first = strchr(spec, ':');
	if (first == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "invalid mount specification '%s' (expected source:/target[:ro|rw])",
			    spec);
		return -1;
	}

	second = strchr(first + 1, ':');
	if (second != NULL && strchr(second + 1, ':') != NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "invalid mount specification '%s' (too many ':')", spec);
		return -1;
	}

	source = cellman_strndup(spec, (size_t)(first - spec), err);
	if (source == NULL)
		return -1;
	if (second == NULL)
		target = cellman_strdup(first + 1, err);
	else
		target = cellman_strndup(first + 1, (size_t)(second - (first + 1)), err);
	if (target == NULL) {
		free(source);
		return -1;
	}
	mode = second != NULL ? second + 1 : "rw";

	if (source[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "mount source cannot be empty");
		free(source);
		free(target);
		return -1;
	}

	if (source[0] == '/') {
		if (strcmp(source, "/") == 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "host mount source is not allowed: %s", source);
			free(source);
			free(target);
			return -1;
		}
		*host_source_out = true;
	} else if (!runtime_name_valid(source)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "invalid volume mount source: %s", source);
		free(source);
		free(target);
		return -1;
	}

	if (target[0] != '/') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "mount target must be absolute: %s", target);
		free(source);
		free(target);
		return -1;
	}
	if (strcmp(target, "/") == 0 || strcmp(target, "/dev") == 0 ||
	    strncmp(target, "/dev/", 5) == 0 || strcmp(target, "/.overlay") == 0 ||
	    strncmp(target, "/.overlay/", 10) == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "mount target is not allowed: %s", target);
		free(source);
		free(target);
		return -1;
	}

	if (strcmp(mode, "ro") == 0)
		*readonly_out = true;
	else if (strcmp(mode, "rw") != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "mount mode must be ro or rw: %s", mode);
		free(source);
		free(target);
		return -1;
	}

	*source_out = source;
	*target_out = target;
	return 0;
}

static int
host_mounts_allowed(bool *allowed_out, char **err)
{
	const char *env;
	char *conf_value;
	bool allowed;

	if (allowed_out == NULL)
		return -1;
	*allowed_out = false;

	env = getenv("CELL_ALLOW_HOST_MOUNTS");
	if (env != NULL && strcmp(env, "YES") == 0) {
		*allowed_out = true;
		return 0;
	}

	conf_value = NULL;
	if (cellman_conf_get("CELL_ALLOW_HOST_MOUNTS", &conf_value, err) != 0)
		return -1;

	allowed = conf_value != NULL && strcmp(conf_value, "YES") == 0;
	free(conf_value);
	*allowed_out = allowed;
	return 0;
}

/*
 * Keep historical mkdir_p_local API while using the shared mkdir -p helper.
 */
int
mkdir_p_local(const char *path, mode_t mode, char **err)
{
	return cellman_mkdir_p(path, mode, err);
}

static int
mount_target_source(const char *target, bool *mounted_out, char **source_out,
    char **err)
{
	char *raw;
	char *line;
	char *saveptr;

	if (mounted_out == NULL || source_out == NULL)
		return -1;
	*mounted_out = false;
	*source_out = NULL;

	raw = NULL;
	if (run_argv_capture((const char *const[]){ "mount", NULL }, &raw,
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
		if (tgt_len == strlen(target) &&
		    strncmp(on + 4, target, tgt_len) == 0) {
			*mounted_out = true;
			*source_out = cellman_strndup(line, src_len, err);
			free(raw);
			if (*source_out == NULL)
				return -1;
			return 0;
		}

		line = strtok_r(NULL, "\n", &saveptr);
	}

	free(raw);
	return 0;
}

/*
 * Build a minimal per-cell /dev setup.
 *
 * Mirrors the earlier manager model: mount tmpfs on /dev, create baseline
 * nodes via
 * MAKEDEV std ptm, then mount ptyfs on /dev/pts.
 */
static int
setup_cell_local_dev_runtime(const char *root, const char *release,
    const char *arch, char **err)
{
	char *dev;
	char *pts;
	char *makedev;
	char *etc_set;
	char *makedev_cmd;
	char *source;
	char *runerr;
	bool mounted;

	dev = NULL;
	pts = NULL;
	makedev = NULL;
	etc_set = NULL;
	makedev_cmd = NULL;
	source = NULL;
	runerr = NULL;
	mounted = false;

	if (root == NULL || root[0] == '\0' || release == NULL ||
	    release[0] == '\0' || arch == NULL || arch[0] == '\0')
		return -1;

	if (!cellman_exec_command_exists("mount_tmpfs")) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "missing required tool: mount_tmpfs");
		goto fail;
	}

	dev = cellman_xasprintf(NULL, "%s/dev", root);
	if (dev == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}
	if (mkdir_p_local(dev, 0755, err) != 0)
		goto fail;

	if (mount_target_source(dev, &mounted, &source, err) != 0)
		goto fail;
	if (mounted) {
		if (source == NULL || strcmp(source, "tmpfs") != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "/dev already mounted with different source: %s", dev);
			goto fail;
		}
	} else {
		if (run_argv((const char *const[]){ "mount_tmpfs", "-s", "8m",
		    "tmpfs", dev, NULL }, &runerr) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "mount tmpfs on /dev failed");
			goto fail;
		}
	}
	free(source);
	source = NULL;
	free(runerr);
	runerr = NULL;

	makedev = cellman_xasprintf(NULL, "%s/MAKEDEV", dev);
	etc_set = cellman_xasprintf(NULL, "/var/cellman/releases/%s/%s/etc.tar.xz",
	    release, arch);
	if (makedev == NULL || etc_set == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}

	if (access(makedev, R_OK) != 0) {
		if (access(etc_set, R_OK) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "missing %s; run system bootstrap", etc_set);
			goto fail;
		}
		if (run_argv((const char *const[]){ "tar", "-xzp", "-f", etc_set,
		    "-C", root, "./dev/MAKEDEV", NULL }, &runerr) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "failed to extract /dev/MAKEDEV");
			goto fail;
		}
		free(runerr);
		runerr = NULL;

		if (chmod(makedev, 0555) != 0 && errno != ENOENT) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "chmod %s failed: %s", makedev,
				    strerror(errno));
			goto fail;
		}
	}

	makedev_cmd = cellman_xasprintf(NULL,
	    "cd %s && sh ./MAKEDEV std ptm", dev);
	if (makedev_cmd == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}
	if (run_argv((const char *const[]){ "sh", "-c", makedev_cmd, NULL },
	    &runerr) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "%s",
			    runerr != NULL ? runerr : "failed to initialize /dev device nodes");
		goto fail;
	}
	free(runerr);
	runerr = NULL;

	pts = cellman_xasprintf(NULL, "%s/pts", dev);
	if (pts == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}
	if (mkdir_p_local(pts, 0755, err) != 0)
		goto fail;

	if (mount_target_source(pts, &mounted, &source, err) != 0)
		goto fail;
	if (mounted) {
		if (source == NULL || strcmp(source, "ptyfs") != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "/dev/pts already mounted with different source: %s", pts);
			goto fail;
		}
	} else {
		if (run_argv((const char *const[]){ "mount", "-t", "ptyfs", "ptyfs",
		    pts, NULL }, &runerr) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "mount ptyfs on /dev/pts failed");
			goto fail;
		}
	}

	free(dev);
	free(pts);
	free(makedev);
	free(etc_set);
	free(makedev_cmd);
	free(source);
	free(runerr);
	return 0;

fail:
	free(dev);
	free(pts);
	free(makedev);
	free(etc_set);
	free(makedev_cmd);
	free(source);
	free(runerr);
	return -1;
}

static int
mount_cell_root_runtime(const struct cellman_doc *doc, const char *root,
    char **err)
{
	const char *overlay_subdirs[] = {
		"etc",
		"var",
		"tmp",
		"home",
		"root",
		"usr/pkg",
		"opt",
		"var/run",
		"var/log",
	};
	struct utsname uts;
	char *base_layer;
	char *overlay_dir;
	char *overlay_mount;
	char *source;
	char *path;
	char *etc_set;
	char *runerr;
	bool mounted;
	size_t i;

	base_layer = NULL;
	overlay_dir = NULL;
	overlay_mount = NULL;
	source = NULL;
	path = NULL;
	etc_set = NULL;
	runerr = NULL;
	mounted = false;

	if (doc == NULL || doc->kind != CELLMAN_DOC_CELL || root == NULL ||
	    root[0] == '\0')
		return -1;

	if (uname(&uts) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "uname failed: %s", strerror(errno));
		goto fail;
	}

	base_layer = cellman_xasprintf(NULL, "/var/cellman/base/%s-%s",
	    uts.release, uts.machine);
	overlay_dir = cellman_xasprintf(NULL, "/var/cellman/cells/%s/overlay",
	    doc->u.cell.name);
	overlay_mount = cellman_xasprintf(NULL, "%s/.overlay", root);
	if (base_layer == NULL || overlay_dir == NULL || overlay_mount == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}

	if (ensure_base_writable_links(base_layer, err) != 0)
		goto fail;

	if (mkdir_p_local(root, 0755, err) != 0 ||
	    mkdir_p_local(overlay_dir, 0755, err) != 0)
		goto fail;

	for (i = 0; i < sizeof(overlay_subdirs) / sizeof(overlay_subdirs[0]); i++) {
		path = cellman_xasprintf(NULL, "%s/%s", overlay_dir,
		    overlay_subdirs[i]);
		if (path == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			goto fail;
		}
		if (mkdir_p_local(path, 0755, err) != 0)
			goto fail;
		free(path);
		path = NULL;
	}

	path = cellman_xasprintf(NULL, "%s/tmp", overlay_dir);
	if (path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}
	if (chmod(path, 01777) != 0 && errno != ENOENT) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "chmod %s failed: %s", path,
			    strerror(errno));
		goto fail;
	}
	free(path);
	path = NULL;

	path = cellman_xasprintf(NULL, "%s/etc/rc.conf", overlay_dir);
	if (path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}
	if (access(path, R_OK) != 0) {
		etc_set = cellman_xasprintf(NULL, "/var/cellman/releases/%s/%s/etc.tar.xz",
		    uts.release, uts.machine);
		if (etc_set == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			goto fail;
		}
		if (access(etc_set, R_OK) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "missing %s; run system bootstrap", etc_set);
			goto fail;
		}
		if (run_argv((const char *const[]){ "tar", "-xzp", "-f", etc_set,
		    "-C", overlay_dir, "./.cshrc", "./.profile", "./etc", "./root",
		    "./var", NULL }, &runerr) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "failed to initialize overlay etc");
			goto fail;
		}
		free(runerr);
		runerr = NULL;
	}
	free(path);
	path = NULL;

	{
		struct stat host_st;

		path = cellman_xasprintf(NULL, "%s/etc/resolv.conf", overlay_dir);
		if (path == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			goto fail;
		}
		if (access(path, F_OK) != 0 && access("/etc/resolv.conf", R_OK) == 0) {
			if (run_argv((const char *const[]){ "cp", "/etc/resolv.conf", path,
			    NULL }, &runerr) != 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "%s",
					    runerr != NULL ? runerr :
					    "failed to copy host resolv.conf into cell overlay");
				goto fail;
			}
			free(runerr);
			runerr = NULL;
		}
		free(path);
		path = NULL;

		path = cellman_xasprintf(NULL, "%s/etc/localtime", overlay_dir);
		if (path == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			goto fail;
		}
		if (access(path, F_OK) != 0 &&
		    (lstat("/etc/localtime", &host_st) == 0 ||
		    stat("/etc/localtime", &host_st) == 0)) {
			if (run_argv((const char *const[]){ "cp", "-P", "/etc/localtime",
			    path, NULL }, &runerr) != 0) {
				free(runerr);
				runerr = NULL;
				if (run_argv((const char *const[]){ "cp", "/etc/localtime", path,
				    NULL }, &runerr) != 0) {
					if (err != NULL)
						*err = cellman_xasprintf(NULL, "%s",
						    runerr != NULL ? runerr :
						    "failed to copy host localtime into cell overlay");
					goto fail;
				}
			}
			free(runerr);
			runerr = NULL;
		}
		free(path);
		path = NULL;
	}

	if (mount_target_source(root, &mounted, &source, err) != 0)
		goto fail;
	if (mounted) {
		if (source == NULL || strcmp(source, base_layer) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "cell root already mounted with different source: %s", root);
			goto fail;
		}
	} else {
		if (run_argv((const char *const[]){ "mount", "-t", "null", "-o",
		    "ro", base_layer, root, NULL }, &runerr) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "mount base layer failed");
			goto fail;
		}
		free(runerr);
		runerr = NULL;
	}
	free(source);
	source = NULL;

	if (mkdir_p_local(overlay_mount, 0755, err) != 0)
		goto fail;

	if (mount_target_source(overlay_mount, &mounted, &source, err) != 0)
		goto fail;
	if (mounted) {
		if (source == NULL || strcmp(source, overlay_dir) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "overlay mountpoint already mounted with different source: %s",
				    overlay_mount);
			goto fail;
		}
	} else {
		if (run_argv((const char *const[]){ "mount", "-t", "null",
		    overlay_dir, overlay_mount, NULL }, &runerr) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    runerr != NULL ? runerr : "mount overlay failed");
			goto fail;
		}
		free(runerr);
		runerr = NULL;
	}

	if (setup_cell_local_dev_runtime(root, uts.release, uts.machine, err) != 0)
		goto fail;

	free(base_layer);
	free(overlay_dir);
	free(overlay_mount);
	free(source);
	free(path);
	free(etc_set);
	free(runerr);
	return 0;

fail:
	free(base_layer);
	free(overlay_dir);
	free(overlay_mount);
	free(source);
	free(path);
	free(etc_set);
	free(runerr);
	return -1;
}

static int
mount_cell_volumes_runtime(const struct cellman_state *state,
    const struct cellman_doc *doc, const char *root, char **err)
{
	struct cellman_string_list seen_targets;
	struct cellman_string_list mounted_paths;
	bool host_allowed;
	bool host_checked;
	size_t i;

	if (state == NULL || doc == NULL || root == NULL)
		return -1;

	memset(&seen_targets, 0, sizeof(seen_targets));
	memset(&mounted_paths, 0, sizeof(mounted_paths));
	host_allowed = false;
	host_checked = false;

	for (i = 0; i < doc->u.cell.mounts.len; i++) {
		char *source;
		char *target;
		bool readonly;
		bool host_source;
		char *source_path;
		char *target_mount;
		bool mounted;
		char *mounted_source;
		char *runerr;
		size_t j;

		source = NULL;
		target = NULL;
		source_path = NULL;
		target_mount = NULL;
		mounted_source = NULL;
		mounted = false;
		runerr = NULL;

		if (parse_mount_spec(doc->u.cell.mounts.items[i], &source, &target,
		    &readonly, &host_source, err) != 0)
			goto fail;

		for (j = 0; j < seen_targets.len; j++) {
			if (path_is_same_or_child(target, seen_targets.items[j]) ||
			    path_is_same_or_child(seen_targets.items[j], target)) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "overlapping mount targets are not allowed: %s and %s",
					    target, seen_targets.items[j]);
				goto fail;
			}
		}
		if (cellman_string_list_add(&seen_targets, target, err) != 0)
			goto fail;

		if (host_source) {
			struct stat st;

			if (!host_checked) {
				if (host_mounts_allowed(&host_allowed, err) != 0)
					goto fail;
				host_checked = true;
			}
			if (!host_allowed) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "host-path mounts are disabled (set CELL_ALLOW_HOST_MOUNTS=YES)");
				goto fail;
			}

			if (stat(source, &st) != 0 || !S_ISDIR(st.st_mode)) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "host mount source is not a directory: %s", source);
				goto fail;
			}
			source_path = cellman_strdup(source, err);
			if (source_path == NULL)
				goto fail;
		} else {
			int vidx;
			const char *mode;

			vidx = state_find_volume(state, source);
			if (vidx < 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "missing referenced volume manifest: %s", source);
				goto fail;
			}

			mode = state->volumes.items[(size_t)vidx].u.volume.mode;
			if (cellman_volume_ensure(source, mode, true, false, false,
			    err) != 0)
				goto fail;
			if (cellman_volume_path(source, &source_path, err) != 0)
				goto fail;
		}

		target_mount = cellman_xasprintf(NULL, "%s%s", root, target);
		if (target_mount == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			goto fail;
		}
		if (mkdir_p_local(target_mount, 0755, err) != 0)
			goto fail;

		if (mount_target_source(target_mount, &mounted, &mounted_source, err) !=
		    0)
			goto fail;
		if (mounted) {
			if (mounted_source == NULL ||
			    strcmp(mounted_source, source_path) != 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "mount target already mounted with different source: %s",
					    target_mount);
				goto fail;
			}
			free(source);
			free(target);
			free(source_path);
			free(target_mount);
			free(mounted_source);
			continue;
		}

		if (readonly) {
			if (run_argv((const char *const[]){ "mount", "-t",
			    "null", "-o", "ro", source_path,
			    target_mount, NULL }, &runerr) != 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "%s",
					    runerr != NULL ? runerr : "mount failed");
				free(runerr);
				goto fail;
			}
		} else {
			if (run_argv((const char *const[]){ "mount", "-t",
			    "null", source_path, target_mount, NULL }, &runerr) != 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "%s",
					    runerr != NULL ? runerr : "mount failed");
				free(runerr);
				goto fail;
			}
		}
		free(runerr);
		runerr = NULL;

		if (cellman_string_list_add(&mounted_paths, target_mount, err) != 0)
			goto fail;

		free(source);
		free(target);
		free(source_path);
		free(target_mount);
		free(mounted_source);
		continue;

fail:
		for (j = mounted_paths.len; j > 0; j--) {
			char *rollback_err;

			rollback_err = NULL;
			(void)run_argv((const char *const[]){ "umount",
			    mounted_paths.items[j - 1], NULL }, &rollback_err);
			free(rollback_err);
		}
		cellman_string_list_free(&mounted_paths);
		cellman_string_list_free(&seen_targets);
		free(source);
		free(target);
		free(source_path);
		free(target_mount);
		free(mounted_source);
		free(runerr);
		return -1;
	}

	cellman_string_list_free(&mounted_paths);
	cellman_string_list_free(&seen_targets);
	return 0;
}

static int
unmount_under_root(const char *root, char **err)
{
	for (;;) {
		char *raw;
		char *line;
		char *saveptr;
		char *best;
		size_t best_len;
		size_t root_len;

		raw = NULL;
		if (run_argv_capture((const char *const[]){ "mount", NULL }, &raw,
		    err) != 0)
			return -1;

		best = NULL;
		best_len = 0;
		root_len = strlen(root);
		saveptr = NULL;
		line = strtok_r(raw, "\n", &saveptr);
		while (line != NULL) {
			char *on;
			char *type;
			char *target;
			size_t target_len;

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

			target = on + 4;
			target_len = (size_t)(type - target);
			if (!(target_len == root_len && strncmp(target, root, root_len) == 0) &&
			    !(target_len > root_len && strncmp(target, root, root_len) == 0 &&
			    target[root_len] == '/')) {
				line = strtok_r(NULL, "\n", &saveptr);
				continue;
			}

			if (target_len > best_len) {
				char *candidate;

				candidate = cellman_strndup(target, target_len, NULL);
				if (candidate != NULL) {
					free(best);
					best = candidate;
					best_len = target_len;
				}
			}

			line = strtok_r(NULL, "\n", &saveptr);
		}

		free(raw);
		if (best == NULL)
			break;

		{
			char *runerr;

			runerr = NULL;
			if (run_argv((const char *const[]){ "umount", best, NULL },
			    &runerr) != 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "%s",
					    runerr != NULL ? runerr : "umount failed");
				free(runerr);
				free(best);
				return -1;
			}
			free(runerr);
		}

		free(best);
	}

	return 0;
}

static int
unmount_cell_mounts_name(const char *name, char **err)
{
	char *root;
	int rc;

	if (!runtime_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	root = cellman_xasprintf(NULL, "/var/cellman/cells/%s/root", name);
	if (root == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	rc = unmount_under_root(root, err);
	free(root);
	return rc;
}

static void
cell_snapshot_row_free(struct cell_snapshot_row *row)
{
	int i;

	if (row == NULL)
		return;

	for (i = 0; i < 25; i++)
		free(row->cols[i]);
	memset(row, 0, sizeof(*row));
}

void
cell_snapshot_table_free(struct cell_snapshot_table *table)
{
	size_t i;

	if (table == NULL)
		return;

	for (i = 0; i < table->len; i++)
		cell_snapshot_row_free(&table->items[i]);
	free(table->items);
	table->items = NULL;
	table->len = 0;
	table->cap = 0;
}

static int
cell_snapshot_table_add(struct cell_snapshot_table *table,
    struct cell_snapshot_row *row, char **err)
{
	struct cell_snapshot_row *next;

	if (table == NULL || row == NULL)
		return -1;

	if (table->len == table->cap) {
		size_t next_cap;

		next_cap = table->cap == 0 ? 8 : table->cap * 2;
		next = realloc(table->items, next_cap * sizeof(*next));
		if (next == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return -1;
		}
		table->items = next;
		table->cap = next_cap;
	}

	table->items[table->len] = *row;
	table->len++;
	memset(row, 0, sizeof(*row));
	return 0;
}

static void
volume_snapshot_row_free(struct volume_snapshot_row *row)
{
	int i;

	if (row == NULL)
		return;

	for (i = 0; i < 8; i++)
		free(row->cols[i]);
	memset(row, 0, sizeof(*row));
}

void
volume_snapshot_table_free(struct volume_snapshot_table *table)
{
	size_t i;

	if (table == NULL)
		return;

	for (i = 0; i < table->len; i++)
		volume_snapshot_row_free(&table->items[i]);
	free(table->items);
	table->items = NULL;
	table->len = 0;
	table->cap = 0;
}

static int
volume_snapshot_table_add(struct volume_snapshot_table *table,
    struct volume_snapshot_row *row, char **err)
{
	struct volume_snapshot_row *next;

	if (table == NULL || row == NULL)
		return -1;

	if (table->len == table->cap) {
		size_t next_cap;

		next_cap = table->cap == 0 ? 8 : table->cap * 2;
		next = realloc(table->items, next_cap * sizeof(*next));
		if (next == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			return -1;
		}
		table->items = next;
		table->cap = next_cap;
	}

	table->items[table->len] = *row;
	table->len++;
	memset(row, 0, sizeof(*row));
	return 0;
}

static const struct cell_field_def *
cell_field_lookup(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof(cell_field_defs) / sizeof(cell_field_defs[0]); i++) {
		if (strcmp(cell_field_defs[i].name, name) == 0)
			return &cell_field_defs[i];
	}

	return NULL;
}

static const struct volume_field_def *
volume_field_lookup(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof(volume_field_defs) / sizeof(volume_field_defs[0]); i++) {
		if (strcmp(volume_field_defs[i].name, name) == 0)
			return &volume_field_defs[i];
	}

	return NULL;
}

void
cell_fields_supported(enum read_view view, struct cellman_string_list *out)
{
	size_t i;

	if (out == NULL)
		return;
	memset(out, 0, sizeof(*out));

	for (i = 0; i < sizeof(cell_field_defs) / sizeof(cell_field_defs[0]); i++) {
		if (view == READ_VIEW_MERGED ||
		    (view == READ_VIEW_DESIRED && cell_field_defs[i].in_desired) ||
		    (view == READ_VIEW_RUNTIME && cell_field_defs[i].in_runtime) ||
		    (view == READ_VIEW_COMPACT && cell_field_defs[i].in_compact))
			(void)cellman_string_list_add(out, cell_field_defs[i].name, NULL);
	}
}

void
volume_fields_supported(enum read_view view, struct cellman_string_list *out)
{
	size_t i;

	if (out == NULL)
		return;
	memset(out, 0, sizeof(*out));

	for (i = 0;
	    i < sizeof(volume_field_defs) / sizeof(volume_field_defs[0]); i++) {
		if (view == READ_VIEW_MERGED ||
		    (view == READ_VIEW_DESIRED && volume_field_defs[i].in_desired) ||
		    (view == READ_VIEW_RUNTIME && volume_field_defs[i].in_runtime))
			(void)cellman_string_list_add(out, volume_field_defs[i].name, NULL);
	}
}

int
cell_fields_parse(const char *requested, enum read_view view,
    struct cell_output_fields *out, char **err)
{
	struct cellman_string_list tokens;
	const char *default_fields;
	size_t i;

	if (out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));

	default_fields = cell_default_fields_merged;
	if (view == READ_VIEW_DESIRED)
		default_fields = cell_default_fields_desired;
	else if (view == READ_VIEW_RUNTIME)
		default_fields = cell_default_fields_runtime;
	else if (view == READ_VIEW_COMPACT)
		default_fields = cell_default_fields_compact;

	if (split_csv_field_tokens(requested != NULL && requested[0] != '\0' ?
	    requested : default_fields, &tokens, err) != 0)
		return -1;

	for (i = 0; i < tokens.len; i++) {
		const struct cell_field_def *def;

		def = cell_field_lookup(tokens.items[i]);
		if (def == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cell: unknown field '%s'",
				    tokens.items[i]);
			cellman_string_list_free(&tokens);
			return -1;
		}
		if ((view == READ_VIEW_DESIRED && !def->in_desired) ||
		    (view == READ_VIEW_RUNTIME && !def->in_runtime) ||
		    (view == READ_VIEW_COMPACT && !def->in_compact)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "cell: field '%s' is not available in view '%s'",
				    tokens.items[i], read_view_name(view));
			cellman_string_list_free(&tokens);
			return -1;
		}
		out->names[out->len] = def->name;
		out->indexes[out->len] = def->index;
		out->len++;
	}

	cellman_string_list_free(&tokens);
	if (out->len == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cell: field list is empty");
		return -1;
	}

	return 0;
}

int
volume_fields_parse(const char *requested, enum read_view view,
    struct volume_output_fields *out, char **err)
{
	struct cellman_string_list tokens;
	const char *default_fields;
	size_t i;

	if (out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));

	if (view == READ_VIEW_COMPACT) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "volume: view '%s' is not supported", read_view_name(view));
		return -1;
	}

	default_fields = volume_default_fields_merged;
	if (view == READ_VIEW_DESIRED)
		default_fields = volume_default_fields_desired;
	else if (view == READ_VIEW_RUNTIME)
		default_fields = volume_default_fields_runtime;

	if (split_csv_field_tokens(requested != NULL && requested[0] != '\0' ?
	    requested : default_fields, &tokens, err) != 0)
		return -1;

	for (i = 0; i < tokens.len; i++) {
		const struct volume_field_def *def;

		def = volume_field_lookup(tokens.items[i]);
		if (def == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "volume: unknown field '%s'",
				    tokens.items[i]);
			cellman_string_list_free(&tokens);
			return -1;
		}
		if ((view == READ_VIEW_DESIRED && !def->in_desired) ||
		    (view == READ_VIEW_RUNTIME && !def->in_runtime)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "volume: field '%s' is not available in view '%s'",
				    tokens.items[i], read_view_name(view));
			cellman_string_list_free(&tokens);
			return -1;
		}
		out->names[out->len] = def->name;
		out->indexes[out->len] = def->index;
		out->len++;
	}

	cellman_string_list_free(&tokens);
	if (out->len == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "volume: field list is empty");
		return -1;
	}

	return 0;
}

static int
cell_row_set(struct cell_snapshot_row *row, int idx, const char *value,
    char **err)
{
	if (row == NULL || idx < 0 || idx >= 25)
		return -1;

	row->cols[idx] = cellman_strdup(value != NULL ? value : "", err);
	return row->cols[idx] != NULL ? 0 : -1;
}

static const char *
cell_snapshot_state(bool manifest_present, bool rendered, bool desired_running)
{
	if (manifest_present) {
		if (rendered)
			return desired_running ? "managed" : "parked";
		return desired_running ? "pending" : "declared";
	}

	if (rendered)
		return "orphaned";
	return "absent";
}

static const char *
volume_snapshot_state(bool manifest_present, bool runtime_present)
{
	if (manifest_present)
		return runtime_present ? "managed" : "pending";

	if (runtime_present)
		return "orphaned";
	return "absent";
}

static int
volume_row_set(struct volume_snapshot_row *row, int idx, const char *value,
    char **err)
{
	if (row == NULL || idx < 0 || idx >= 8)
		return -1;

	row->cols[idx] = cellman_strdup(value != NULL ? value : "", err);
	return row->cols[idx] != NULL ? 0 : -1;
}

int
build_cell_snapshot_table(const struct cellman_state *state,
    struct runtime_cell_list *runtime, struct cell_snapshot_table *out,
    char **err)
{
	struct cellman_string_list names;
	size_t i;

	if (state == NULL || runtime == NULL || out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));
	memset(&names, 0, sizeof(names));

	for (i = 0; i < state->cells.len; i++) {
		if (!string_list_contains(&names, state->cells.items[i].u.cell.name) &&
		    cellman_string_list_add(&names,
		    state->cells.items[i].u.cell.name, err) != 0)
			goto fail;
	}
	for (i = 0; i < runtime->len; i++) {
		if (!string_list_contains(&names, runtime->items[i].name) &&
		    cellman_string_list_add(&names, runtime->items[i].name, err) != 0)
			goto fail;
	}

	if (names.len > 1)
		qsort(names.items, names.len, sizeof(names.items[0]), compare_cstr_ptr);

	for (i = 0; i < names.len; i++) {
		const char *name;
		const struct cellman_doc *doc;
		struct runtime_cell *rt;
		struct cell_snapshot_row row;
		char *depends;
		char *mounts;
		char *root;
		bool rendered;
		bool desired_running;
		bool manifest_present;
		int cidx;
		const char *autostart;
		const char *state_label;
		const char *rlimit_nofile;
		const char *rlimit_as;
		const char *rlimit_core;

		name = names.items[i];
		cidx = state_find_cell(state, name);
		doc = cidx >= 0 ? &state->cells.items[(size_t)cidx] : NULL;
		rt = runtime_cell_find(runtime, name);
		depends = NULL;
		mounts = NULL;
		root = NULL;
		rendered = false;
		memset(&row, 0, sizeof(row));

		if (doc != NULL) {
			if (join_string_list_csv(&doc->u.cell.depends_on, &depends, err) != 0)
				goto row_fail;
			if (join_string_list_csv(&doc->u.cell.mounts, &mounts, err) != 0)
				goto row_fail;
		}

		if (cell_runtime_exists(name, &rendered, err) != 0)
			goto row_fail;

		if (rt != NULL && rt->root != NULL && rt->root[0] != '\0') {
			root = cellman_strdup(rt->root, err);
		} else if (rendered) {
			root = cellman_xasprintf(NULL, "/var/cellman/cells/%s/root", name);
		} else {
			root = cellman_strdup("", err);
		}
		if (root == NULL)
			goto row_fail;

		manifest_present = doc != NULL;
		desired_running = manifest_present && doc->u.cell.autostart_set &&
		    doc->u.cell.autostart;
		autostart = desired_running ? "YES" : "NO";
		state_label = cell_snapshot_state(manifest_present, rendered,
		    desired_running);
		rlimit_nofile = (doc != NULL && doc->u.cell.rlimit_nofile != NULL &&
		    doc->u.cell.rlimit_nofile[0] != '\0') ?
		    doc->u.cell.rlimit_nofile : "unlimited";
		rlimit_as = (doc != NULL && doc->u.cell.rlimit_as != NULL &&
		    doc->u.cell.rlimit_as[0] != '\0') ?
		    doc->u.cell.rlimit_as : "unlimited";
		rlimit_core = (doc != NULL && doc->u.cell.rlimit_core != NULL &&
		    doc->u.cell.rlimit_core[0] != '\0') ?
		    doc->u.cell.rlimit_core : "unlimited";

		if (cell_row_set(&row, 0, name, err) != 0 ||
		    cell_row_set(&row, 1, rt != NULL ? "1" : "0", err) != 0 ||
		    cell_row_set(&row, 2, state_label, err) != 0 ||
		    cell_row_set(&row, 3, rt != NULL ? rt->cid : "", err) != 0 ||
		    cell_row_set(&row, 4, rt != NULL ? rt->refs : "", err) != 0 ||
		    cell_row_set(&row, 5, rt != NULL ? rt->procs : "", err) != 0 ||
		    cell_row_set(&row, 6, rt != NULL ? rt->cpu1s : "", err) != 0 ||
		    cell_row_set(&row, 7, rt != NULL ? rt->cpu10s : "", err) != 0 ||
		    cell_row_set(&row, 8, rt != NULL ? rt->memory : "", err) != 0 ||
		    cell_row_set(&row, 9, rt != NULL ? rt->age : "", err) != 0 ||
		    cell_row_set(&row, 10, root, err) != 0 ||
		    cell_row_set(&row, 11, autostart, err) != 0 ||
		    cell_row_set(&row, 12,
		    doc != NULL ? doc->u.cell.profile : "", err) != 0 ||
		    cell_row_set(&row, 13,
		    doc != NULL ? doc->u.cell.reserved_ports : "", err) != 0 ||
		    cell_row_set(&row, 14, rlimit_nofile, err) != 0 ||
		    cell_row_set(&row, 15, rlimit_as, err) != 0 ||
		    cell_row_set(&row, 16, rlimit_core, err) != 0 ||
		    cell_row_set(&row, 17, depends != NULL ? depends : "", err) != 0 ||
		    cell_row_set(&row, 18,
		    doc != NULL ? doc->u.cell.healthcheck_cmd : "", err) != 0 ||
		    cell_row_set(&row, 19,
		    doc != NULL ? doc->u.cell.supervise_cmd : "", err) != 0 ||
		    cell_row_set(&row, 20, mounts != NULL ? mounts : "", err) != 0 ||
		    cell_row_set(&row, 21,
		    state_find_apply(state, name) >= 0 ? "1" : "0", err) != 0 ||
		    cell_row_set(&row, 22,
		    doc != NULL ? doc->u.cell.supervise_run_as : "", err) != 0)
			goto row_fail;

		if (cell_snapshot_table_add(out, &row, err) != 0)
			goto row_fail;

		free(depends);
		free(mounts);
		free(root);
		continue;

row_fail:
		cell_snapshot_row_free(&row);
		free(depends);
		free(mounts);
		free(root);
		goto fail;
	}

	cellman_string_list_free(&names);
	return 0;

fail:
	cellman_string_list_free(&names);
	cell_snapshot_table_free(out);
	return -1;
}

static int
volume_refs_and_users(const struct cellman_state *state, const char *name,
    char **refs_out, char **used_by_out, char **err)
{
	struct cellman_string_list used_by;
	size_t refs;
	size_t i;

	if (refs_out == NULL || used_by_out == NULL)
		return -1;
	*refs_out = NULL;
	*used_by_out = NULL;
	memset(&used_by, 0, sizeof(used_by));
	refs = 0;

	if (state != NULL) {
		for (i = 0; i < state->cells.len; i++) {
			size_t m;
			bool used;

			used = false;
			for (m = 0; m < state->cells.items[i].u.cell.mounts.len; m++) {
				const char *spec;
				const char *sep;
				size_t src_len;

				spec = state->cells.items[i].u.cell.mounts.items[m];
				if (spec == NULL || spec[0] == '/')
					continue;
				sep = strchr(spec, ':');
				if (sep == NULL)
					continue;
				src_len = (size_t)(sep - spec);
				if (src_len != strlen(name))
					continue;
				if (strncmp(spec, name, src_len) != 0)
					continue;
				used = true;
				refs++;
				break;
			}

			if (used && !string_list_contains(&used_by,
			    state->cells.items[i].u.cell.name) &&
			    cellman_string_list_add(&used_by,
			    state->cells.items[i].u.cell.name, err) != 0) {
				cellman_string_list_free(&used_by);
				return -1;
			}
		}
	}

	*refs_out = cellman_xasprintf(NULL, "%zu", refs);
	if (*refs_out == NULL) {
		cellman_string_list_free(&used_by);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	if (join_string_list_csv(&used_by, used_by_out, err) != 0) {
		free(*refs_out);
		*refs_out = NULL;
		cellman_string_list_free(&used_by);
		return -1;
	}

	cellman_string_list_free(&used_by);
	return 0;
}

int
build_volume_snapshot_table(const struct cellman_state *state,
    struct volume_snapshot_table *out, char **err)
{
	struct cellman_string_list names;
	const char *volroot;
	DIR *dp;
	struct dirent *de;
	size_t i;

	if (state == NULL || out == NULL)
		return -1;
	memset(out, 0, sizeof(*out));
	memset(&names, 0, sizeof(names));

	for (i = 0; i < state->volumes.len; i++) {
		if (!string_list_contains(&names, state->volumes.items[i].u.volume.name) &&
		    cellman_string_list_add(&names,
		    state->volumes.items[i].u.volume.name, err) != 0)
			goto fail;
	}

	volroot = "/var/cellman/volumes";
	dp = opendir(volroot);
	if (dp != NULL) {
		while ((de = readdir(dp)) != NULL) {
			char *path;
			struct stat st;

			if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
				continue;
			if (!runtime_name_valid(de->d_name))
				continue;

			path = cellman_xasprintf(NULL, "%s/%s", volroot, de->d_name);
			if (path == NULL) {
				(void)closedir(dp);
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "out of memory");
				goto fail;
			}
			if (stat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
			    !string_list_contains(&names, de->d_name) &&
			    cellman_string_list_add(&names, de->d_name, err) != 0) {
				free(path);
				(void)closedir(dp);
				goto fail;
			}
			free(path);
		}
		(void)closedir(dp);
	}

	if (names.len > 1)
		qsort(names.items, names.len, sizeof(names.items[0]), compare_cstr_ptr);

	for (i = 0; i < names.len; i++) {
		const char *name;
		const struct cellman_doc *doc;
		struct volume_snapshot_row row;
		const char *state_label;
		int vidx;
		bool runtime;
		bool mounted;
		char *path;
		char *refs;
		char *used_by;

		name = names.items[i];
		vidx = -1;
		doc = NULL;
		for (vidx = 0; vidx < (int)state->volumes.len; vidx++) {
			if (strcmp(state->volumes.items[(size_t)vidx].u.volume.name,
			    name) == 0) {
				doc = &state->volumes.items[(size_t)vidx];
				break;
			}
		}

		runtime = false;
		mounted = false;
		path = NULL;
		refs = NULL;
		used_by = NULL;
		memset(&row, 0, sizeof(row));

		if (cellman_volume_exists(name, &runtime, err) != 0)
			goto volume_row_fail;
		if (cellman_volume_path(name, &path, err) != 0)
			goto volume_row_fail;
		if (runtime && is_path_mounted(path, &mounted, err) != 0)
			goto volume_row_fail;
		if (volume_refs_and_users(state, name, &refs, &used_by, err) != 0)
			goto volume_row_fail;

		state_label = volume_snapshot_state(doc != NULL, runtime);

		if (volume_row_set(&row, 0, name, err) != 0 ||
		    volume_row_set(&row, 1, state_label, err) != 0 ||
		    volume_row_set(&row, 2,
		    doc != NULL ? doc->u.volume.mode : "", err) != 0 ||
		    volume_row_set(&row, 3, path, err) != 0 ||
		    volume_row_set(&row, 4, mounted ? "1" : "0", err) != 0 ||
		    volume_row_set(&row, 5, refs, err) != 0 ||
		    volume_row_set(&row, 6, used_by, err) != 0)
			goto volume_row_fail;

		if (volume_snapshot_table_add(out, &row, err) != 0)
			goto volume_row_fail;

		free(path);
		free(refs);
		free(used_by);
		continue;

volume_row_fail:
		volume_snapshot_row_free(&row);
		free(path);
		free(refs);
		free(used_by);
		goto fail;
	}

	cellman_string_list_free(&names);
	return 0;

fail:
	cellman_string_list_free(&names);
	volume_snapshot_table_free(out);
	return -1;
}

static bool
cell_field_is_bool(const char *field)
{
	return strcmp(field, "running") == 0 ||
	    strcmp(field, "apply_present") == 0;
}

static bool
volume_field_is_bool(const char *field)
{
	return strcmp(field, "mounted") == 0;
}

static const char *
humanize_age(const char *raw, char *buf, size_t buflen)
{
	char *end;
	unsigned long sec;

	if (raw == NULL || raw[0] == '\0')
		return "-";

	errno = 0;
	sec = strtoul(raw, &end, 10);
	if (errno != 0 || end == raw || *end != '\0')
		return raw;

	if (sec < 60) {
		(void)snprintf(buf, buflen, "%lus", sec);
		return buf;
	}
	if (sec < 3600) {
		(void)snprintf(buf, buflen, "%lum%lus", sec / 60, sec % 60);
		return buf;
	}
	if (sec < 86400) {
		(void)snprintf(buf, buflen, "%luh%lum", sec / 3600,
		    (sec % 3600) / 60);
		return buf;
	}
	if (sec < 604800) {
		(void)snprintf(buf, buflen, "%lud%luh", sec / 86400,
		    (sec % 86400) / 3600);
		return buf;
	}

	(void)snprintf(buf, buflen, "%luw%lud", sec / 604800,
	    (sec % 604800) / 86400);
	return buf;
}

static const char *
humanize_cell_value(const char *field, const char *raw, char *buf,
    size_t buflen)
{
	const char *ctx;

	if (raw == NULL || raw[0] == '\0')
		return "-";

	if (cell_field_is_bool(field)) {
		if (strcmp(raw, "1") == 0)
			return "YES";
		if (strcmp(raw, "0") == 0)
			return "NO";
	}

	if (strcmp(field, "age") == 0) {
		ctx = getenv("CELLMAN_CALL_CONTEXT");
		if (ctx == NULL || strcmp(ctx, "ipc") != 0)
			return humanize_age(raw, buf, buflen);
	}

	return raw;
}

static const char *
humanize_volume_value(const char *field, const char *raw)
{
	if (raw == NULL || raw[0] == '\0')
		return "-";

	if (volume_field_is_bool(field)) {
		if (strcmp(raw, "1") == 0)
			return "YES";
		if (strcmp(raw, "0") == 0)
			return "NO";
	}

	return raw;
}

static void
field_to_upper(const char *name, char *out, size_t outsz)
{
	size_t i;

	if (outsz == 0)
		return;

	for (i = 0; i + 1 < outsz && name[i] != '\0'; i++)
		out[i] = (char)toupper((unsigned char)name[i]);
	out[i] = '\0';
}

int
print_cell_table(const struct cell_snapshot_table *table,
    const struct cell_output_fields *fields, bool tsv, bool no_header)
{
	size_t c;
	size_t r;

	if (table == NULL || fields == NULL)
		return 1;

	if (tsv) {
		if (!no_header) {
			for (c = 0; c < fields->len; c++) {
				if (c != 0)
					(void)cellman_payload_printf("\t");
				(void)cellman_payload_printf("%s", fields->names[c]);
			}
			(void)cellman_payload_printf("\n");
		}

		for (r = 0; r < table->len; r++) {
			for (c = 0; c < fields->len; c++) {
				const char *v;

				v = table->items[r].cols[fields->indexes[c]];
				if (c != 0)
					(void)cellman_payload_printf("\t");
				(void)cellman_payload_printf("%s", v != NULL ? v : "");
			}
			(void)cellman_payload_printf("\n");
		}
		return 0;
	}

	{
		size_t widths[25];
		char header[64];
		char agebuf[64];

		for (c = 0; c < fields->len; c++) {
			field_to_upper(fields->names[c], header, sizeof(header));
			widths[c] = strlen(header);
		}

		for (r = 0; r < table->len; r++) {
			for (c = 0; c < fields->len; c++) {
				const char *raw;
				const char *disp;
				size_t dlen;

				raw = table->items[r].cols[fields->indexes[c]];
				disp = humanize_cell_value(fields->names[c], raw, agebuf,
				    sizeof(agebuf));
				dlen = strlen(disp);
				if (dlen > widths[c])
					widths[c] = dlen;
			}
		}

		for (c = 0; c < fields->len; c++) {
			field_to_upper(fields->names[c], header, sizeof(header));
			(void)cellman_payload_printf("%-*s%s", (int)widths[c], header,
			    c + 1 == fields->len ? "\n" : "  ");
		}

		for (r = 0; r < table->len; r++) {
			for (c = 0; c < fields->len; c++) {
				const char *raw;
				const char *disp;

				raw = table->items[r].cols[fields->indexes[c]];
				disp = humanize_cell_value(fields->names[c], raw, agebuf,
				    sizeof(agebuf));
				(void)cellman_payload_printf("%-*s%s", (int)widths[c], disp,
				    c + 1 == fields->len ? "\n" : "  ");
			}
		}
	}

	return 0;
}

int
print_volume_table(const struct volume_snapshot_table *table,
    const struct volume_output_fields *fields, bool tsv, bool no_header)
{
	size_t c;
	size_t r;

	if (table == NULL || fields == NULL)
		return 1;

	if (tsv) {
		if (!no_header) {
			for (c = 0; c < fields->len; c++) {
				if (c != 0)
					(void)cellman_payload_printf("\t");
				(void)cellman_payload_printf("%s", fields->names[c]);
			}
			(void)cellman_payload_printf("\n");
		}

		for (r = 0; r < table->len; r++) {
			for (c = 0; c < fields->len; c++) {
				const char *v;

				v = table->items[r].cols[fields->indexes[c]];
				if (c != 0)
					(void)cellman_payload_printf("\t");
				(void)cellman_payload_printf("%s", v != NULL ? v : "");
			}
			(void)cellman_payload_printf("\n");
		}
		return 0;
	}

	{
		size_t widths[8];
		char header[64];

		for (c = 0; c < fields->len; c++) {
			field_to_upper(fields->names[c], header, sizeof(header));
			widths[c] = strlen(header);
		}

		for (r = 0; r < table->len; r++) {
			for (c = 0; c < fields->len; c++) {
				const char *raw;
				const char *disp;
				size_t dlen;

				raw = table->items[r].cols[fields->indexes[c]];
				disp = humanize_volume_value(fields->names[c], raw);
				dlen = strlen(disp);
				if (dlen > widths[c])
					widths[c] = dlen;
			}
		}

		for (c = 0; c < fields->len; c++) {
			field_to_upper(fields->names[c], header, sizeof(header));
			(void)cellman_payload_printf("%-*s%s", (int)widths[c], header,
			    c + 1 == fields->len ? "\n" : "  ");
		}

		for (r = 0; r < table->len; r++) {
			for (c = 0; c < fields->len; c++) {
				const char *raw;
				const char *disp;

				raw = table->items[r].cols[fields->indexes[c]];
				disp = humanize_volume_value(fields->names[c], raw);
				(void)cellman_payload_printf("%-*s%s", (int)widths[c], disp,
				    c + 1 == fields->len ? "\n" : "  ");
			}
		}
	}

	return 0;
}

int
print_fields_output(const struct cellman_string_list *fields, bool tsv,
    bool no_header)
{
	size_t i;

	if (fields == NULL)
		return 1;

	if (tsv) {
		if (!no_header)
			(void)cellman_payload_printf("field\n");
		for (i = 0; i < fields->len; i++)
			(void)cellman_payload_printf("%s\n", fields->items[i]);
		return 0;
	}

	(void)cellman_payload_printf("%-24s\n", "FIELD");
	for (i = 0; i < fields->len; i++)
		(void)cellman_payload_printf("%-24s\n", fields->items[i]);
	return 0;
}

struct apply_report_col {
	const char *title;
	size_t width;
	size_t min_width;
	bool truncate;
};

static size_t
apply_report_terminal_columns(void)
{
	struct winsize ws;
	const char *env_cols;
	char *endp;
	unsigned long val;

	if (isatty(STDOUT_FILENO) &&
	    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
		return (size_t)ws.ws_col;

	env_cols = getenv("COLUMNS");
	if (env_cols != NULL && env_cols[0] != '\0') {
		errno = 0;
		val = strtoul(env_cols, &endp, 10);
		if (errno == 0 && endp != env_cols && *endp == '\0' && val >= 40)
			return (size_t)val;
	}

	return 120;
}

static size_t
apply_report_table_width(const struct apply_report_col *cols, size_t ncols)
{
	size_t i;
	size_t total;

	total = 1;
	for (i = 0; i < ncols; i++)
		total += cols[i].width + 3;
	return total;
}

static void
apply_report_fit_columns(struct apply_report_col *cols, size_t ncols,
    size_t term_cols)
{
	size_t i;
	size_t total;

	total = apply_report_table_width(cols, ncols);
	while (total > term_cols) {
		size_t idx;
		size_t best;

		idx = ncols;
		best = 0;
		for (i = 0; i < ncols; i++) {
			if (!cols[i].truncate || cols[i].width <= cols[i].min_width)
				continue;
			if (idx == ncols || cols[i].width > best) {
				idx = i;
				best = cols[i].width;
			}
		}
		if (idx == ncols)
			break;
		cols[idx].width--;
		total--;
	}
}

static void
apply_report_print_border_fp(FILE *out, const struct apply_report_col *cols,
    size_t ncols)
{
	size_t c;
	size_t i;

	if (out == NULL)
		out = stdout;

	(void)fputc('+', out);
	for (c = 0; c < ncols; c++) {
		for (i = 0; i < cols[c].width + 2; i++)
			(void)fputc('-', out);
		(void)fputc('+', out);
	}
	(void)fputc('\n', out);
}

static void
apply_report_print_border(const struct apply_report_col *cols, size_t ncols)
{
	apply_report_print_border_fp(stdout, cols, ncols);
}

static void
apply_report_print_cell_fp(FILE *out, const char *text, size_t width,
    bool truncate)
{
	const char *src;
	size_t len;
	size_t i;
	size_t shown;

	if (out == NULL)
		out = stdout;

	src = (text != NULL && text[0] != '\0') ? text : "-";
	len = strlen(src);
	shown = len;
	if (truncate && len > width)
		shown = width;

	if (truncate && len > width && width > 3) {
		shown = width - 3;
		(void)fwrite(src, 1, shown, out);
		(void)fputs("...", out);
	} else {
		(void)fwrite(src, 1, shown, out);
	}

	for (i = (truncate && len > width && width > 3) ? width : shown; i < width;
	    i++)
		(void)fputc(' ', out);
}

static void
apply_report_print_row_fp(FILE *out, const struct apply_report_col *cols,
    size_t ncols, const char *const values[])
{
	size_t c;

	if (out == NULL)
		out = stdout;

	(void)fputc('|', out);
	for (c = 0; c < ncols; c++) {
		(void)fputc(' ', out);
		apply_report_print_cell_fp(out, values[c], cols[c].width,
		    cols[c].truncate);
		(void)fputs(" |", out);
	}
	(void)fputc('\n', out);
}

static void
apply_report_print_row(const struct apply_report_col *cols, size_t ncols,
    const char *const values[])
{
	apply_report_print_row_fp(stdout, cols, ncols, values);
}

static int
cell_dep_visit(const struct cellman_state *state, size_t idx,
    unsigned char *marks, const struct cellman_doc **order, size_t *order_len,
    char **err)
{
	size_t d;
	const struct cellman_doc *doc;

	if (marks[idx] == 2)
		return 0;
	if (marks[idx] == 1) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "dependency cycle detected at cell %s",
			    state->cells.items[idx].u.cell.name);
		return -1;
	}

	marks[idx] = 1;
	doc = &state->cells.items[idx];
	for (d = 0; d < doc->u.cell.depends_on.len; d++) {
		int dep_idx;

		dep_idx = state_find_cell(state, doc->u.cell.depends_on.items[d]);
		if (dep_idx < 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "cell %s depends on missing cell %s",
				    doc->u.cell.name, doc->u.cell.depends_on.items[d]);
			return -1;
		}
		if (cell_dep_visit(state, (size_t)dep_idx, marks, order, order_len,
		    err) != 0)
			return -1;
	}

	marks[idx] = 2;
	order[*order_len] = doc;
	(*order_len)++;
	return 0;
}

static int
build_cell_dependency_order(const struct cellman_state *state,
    const struct cellman_doc ***order_out, size_t *len_out, char **err)
{
	const struct cellman_doc **order;
	unsigned char *marks;
	size_t i;
	size_t len;

	if (order_out == NULL || len_out == NULL || state == NULL)
		return -1;
	*order_out = NULL;
	*len_out = 0;

	if (state->cells.len == 0)
		return 0;

	order = calloc(state->cells.len, sizeof(*order));
	marks = calloc(state->cells.len, sizeof(*marks));
	if (order == NULL || marks == NULL) {
		free(order);
		free(marks);
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	len = 0;
	for (i = 0; i < state->cells.len; i++) {
		if (cell_dep_visit(state, i, marks, order, &len, err) != 0) {
			free(order);
			free(marks);
			return -1;
		}
	}

	free(marks);
	*order_out = order;
	*len_out = len;
	return 0;
}

static int
mark_cell_needed(const struct cellman_state *state, int idx, bool *needed,
    char **err)
{
	const struct cellman_doc *doc;
	size_t d;

	if (idx < 0)
		return -1;
	if (needed[(size_t)idx])
		return 0;
	needed[(size_t)idx] = true;

	doc = &state->cells.items[(size_t)idx];
	for (d = 0; d < doc->u.cell.depends_on.len; d++) {
		int dep_idx;

		dep_idx = state_find_cell(state, doc->u.cell.depends_on.items[d]);
		if (dep_idx < 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "cell %s depends on missing cell %s",
				    doc->u.cell.name, doc->u.cell.depends_on.items[d]);
			return -1;
		}
		if (mark_cell_needed(state, dep_idx, needed, err) != 0)
			return -1;
	}

	return 0;
}

static int
ensure_cell_state_dir(const char *name, char **err)
{
	char *path;
	int rc;

	if (!runtime_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	path = cellman_xasprintf(NULL, "/var/cellman/cells/%s/state", name);
	if (path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	rc = mkdir_p_local(path, 0755, err);
	free(path);
	return rc;
}

/*
 * Use the shared optional file reader from this backend module.
 */
static int
read_optional_text_file(const char *path, char **out, char **err)
{
	return cellman_read_optional_text_file(path, out, err);
}

/*
 * Use the shared text writer to avoid duplicate file I/O logic.
 */
static int
write_text_file(const char *path, const char *content, char **err)
{
	return cellman_write_text_file(path, content, err);
}

static void
hash64_init(uint64_t *h)
{
	if (h != NULL)
		*h = 1469598103934665603ULL;
}

static void
hash64_update_bytes(uint64_t *h, const void *buf, size_t len)
{
	const unsigned char *p;
	size_t i;

	if (h == NULL || buf == NULL)
		return;

	p = buf;
	for (i = 0; i < len; i++) {
		*h ^= (uint64_t)p[i];
		*h *= 1099511628211ULL;
	}
}

static void
hash64_update_str(uint64_t *h, const char *value)
{
	uint64_t len;

	if (value == NULL)
		value = "";
	len = (uint64_t)strlen(value);
	hash64_update_bytes(h, &len, sizeof(len));
	hash64_update_bytes(h, value, (size_t)len);
}

static int
hash64_update_file(uint64_t *h, const char *path, char **err)
{
	int fd;
	unsigned char buf[32768];
	ssize_t nr;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot open %s: %s", path,
			    strerror(errno));
		return -1;
	}

	for (;;) {
		nr = read(fd, buf, sizeof(buf));
		if (nr < 0) {
			if (errno == EINTR)
				continue;
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cannot read %s: %s", path,
				    strerror(errno));
			(void)close(fd);
			return -1;
		}
		if (nr == 0)
			break;
		hash64_update_bytes(h, buf, (size_t)nr);
	}

	(void)close(fd);
	return 0;
}

static int
hash64_hex(uint64_t h, char **out, char **err)
{
	if (out == NULL)
		return -1;
	*out = cellman_xasprintf(NULL, "%016llx", (unsigned long long)h);
	if (*out == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}
	return 0;
}

static void
hash64_update_string_list(uint64_t *h, const struct cellman_string_list *list)
{
	uint64_t len;
	size_t i;

	len = list != NULL ? (uint64_t)list->len : 0;
	hash64_update_bytes(h, &len, sizeof(len));
	if (list == NULL)
		return;
	for (i = 0; i < list->len; i++)
		hash64_update_str(h, list->items[i]);
}

static void
hash64_update_kv_list(uint64_t *h, const struct cellman_kv_list *list)
{
	uint64_t len;
	size_t i;

	len = list != NULL ? (uint64_t)list->len : 0;
	hash64_update_bytes(h, &len, sizeof(len));
	if (list == NULL)
		return;
	for (i = 0; i < list->len; i++) {
		hash64_update_str(h, list->items[i].key);
		hash64_update_str(h, list->items[i].value);
	}
}

static int
resolve_doc_source_path(const struct cellman_doc *doc, const char *source,
    char **resolved, char **err)
{
	if (resolved == NULL)
		return -1;
	*resolved = NULL;

	if (source == NULL || source[0] == '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing source path");
		return -1;
	}

	if (source[0] == '/') {
		*resolved = cellman_strdup(source, err);
		return *resolved != NULL ? 0 : -1;
	}

	if (doc == NULL || doc->source_dir == NULL || doc->source_dir[0] == '\0') {
		*resolved = cellman_strdup(source, err);
		return *resolved != NULL ? 0 : -1;
	}

	*resolved = cellman_path_join(doc->source_dir, source, err);
	return *resolved != NULL ? 0 : -1;
}

static bool
cell_autostart_desired(const struct cellman_doc *doc)
{
	if (doc == NULL || doc->kind != CELLMAN_DOC_CELL)
		return false;
	return doc->u.cell.autostart_set && doc->u.cell.autostart;
}

static int
compute_cell_config_hashes(const struct cellman_doc *cell_doc,
    char **manifest_hash_out, char **service_hash_out, char **policy_hash_out)
{
	uint64_t service_h;
	uint64_t policy_h;
	uint64_t manifest_h;
	uint64_t v;

	if (cell_doc == NULL || cell_doc->kind != CELLMAN_DOC_CELL ||
	    manifest_hash_out == NULL || service_hash_out == NULL ||
	    policy_hash_out == NULL)
		return -1;

	*manifest_hash_out = NULL;
	*service_hash_out = NULL;
	*policy_hash_out = NULL;

	hash64_init(&service_h);
	hash64_update_str(&service_h, "service-v1");
	hash64_update_str(&service_h, cell_doc->u.cell.name);
	hash64_update_str(&service_h,
	    cell_autostart_desired(cell_doc) ? "YES" : "NO");
	hash64_update_str(&service_h, cell_doc->u.cell.supervise_cmd);
	hash64_update_str(&service_h, cell_doc->u.cell.supervise_run_as);
	hash64_update_str(&service_h, cell_doc->u.cell.supervise_log_facility);
	hash64_update_str(&service_h, cell_doc->u.cell.supervise_stdout_level);
	hash64_update_str(&service_h, cell_doc->u.cell.supervise_stderr_level);
	hash64_update_str(&service_h, cell_doc->u.cell.supervise_log_tag);
	hash64_update_str(&service_h, cell_doc->u.cell.healthcheck_cmd);
	hash64_update_string_list(&service_h, &cell_doc->u.cell.depends_on);
	hash64_update_string_list(&service_h, &cell_doc->u.cell.mounts);

	hash64_init(&policy_h);
	hash64_update_str(&policy_h, "policy-v1");
	hash64_update_str(&policy_h, cell_doc->u.cell.name);
	hash64_update_str(&policy_h, cell_doc->u.cell.profile);
	hash64_update_str(&policy_h, cell_doc->u.cell.reserved_ports);
	hash64_update_str(&policy_h, cell_doc->u.cell.rlimit_nofile);
	hash64_update_str(&policy_h, cell_doc->u.cell.rlimit_as);
	hash64_update_str(&policy_h, cell_doc->u.cell.rlimit_core);

	hash64_init(&manifest_h);
	hash64_update_str(&manifest_h, "manifest-v1");
	hash64_update_str(&manifest_h, cell_doc->u.cell.name);
	v = service_h;
	hash64_update_bytes(&manifest_h, &v, sizeof(v));
	v = policy_h;
	hash64_update_bytes(&manifest_h, &v, sizeof(v));

	if (hash64_hex(service_h, service_hash_out, NULL) != 0 ||
	    hash64_hex(policy_h, policy_hash_out, NULL) != 0 ||
	    hash64_hex(manifest_h, manifest_hash_out, NULL) != 0) {
		free(*service_hash_out);
		free(*policy_hash_out);
		free(*manifest_hash_out);
		*service_hash_out = NULL;
		*policy_hash_out = NULL;
		*manifest_hash_out = NULL;
		return -1;
	}

	return 0;
}

static int
compute_apply_doc_hash(const struct cellman_doc *doc, char **hash_out,
    char **err)
{
	uint64_t h;
	size_t i;

	if (hash_out == NULL)
		return -1;
	*hash_out = NULL;

	if (doc == NULL || doc->kind != CELLMAN_DOC_APPLY) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "apply hash requires apply document");
		return -1;
	}

	hash64_init(&h);
	hash64_update_str(&h, "apply-v1");
	hash64_update_str(&h, doc->u.apply.name);
	hash64_update_str(&h, doc->source_path);

	for (i = 0; i < doc->u.apply.actions.len; i++) {
		const struct cellman_action *a;
		uint64_t kind_v;

		a = &doc->u.apply.actions.items[i];
		kind_v = (uint64_t)a->kind;
		hash64_update_bytes(&h, &kind_v, sizeof(kind_v));

		switch (a->kind) {
		case CELLMAN_ACTION_PKG:
			hash64_update_string_list(&h, &a->u.pkg.packages);
			break;
		case CELLMAN_ACTION_EXEC:
			hash64_update_str(&h, a->u.exec.command);
			break;
		case CELLMAN_ACTION_DIR:
			hash64_update_str(&h, a->u.dir.path);
			hash64_update_str(&h, a->u.dir.mode);
			hash64_update_str(&h, a->u.dir.owner);
			hash64_update_str(&h, a->u.dir.group);
			break;
		case CELLMAN_ACTION_LINE:
			hash64_update_str(&h, a->u.line.path);
			hash64_update_str(&h, a->u.line.text);
			break;
		case CELLMAN_ACTION_SYMLINK:
			hash64_update_str(&h, a->u.symlink.target);
			hash64_update_str(&h, a->u.symlink.linkpath);
			break;
		case CELLMAN_ACTION_COPY:
		case CELLMAN_ACTION_UNTAR:
		case CELLMAN_ACTION_TEMPLATE:
		case CELLMAN_ACTION_SCRIPT:
		{
			char *src;
			const char *path_in_doc;

			src = NULL;
			path_in_doc = NULL;
			if (a->kind == CELLMAN_ACTION_COPY) {
				hash64_update_str(&h, a->u.copy.source);
				hash64_update_str(&h, a->u.copy.target);
				hash64_update_str(&h, a->u.copy.mode);
				hash64_update_str(&h, a->u.copy.owner);
				hash64_update_str(&h, a->u.copy.group);
				path_in_doc = a->u.copy.source;
			} else if (a->kind == CELLMAN_ACTION_UNTAR) {
				uint64_t strip_v;

				hash64_update_str(&h, a->u.untar.source);
				hash64_update_str(&h, a->u.untar.target);
				strip_v = (uint64_t)a->u.untar.strip_components;
				hash64_update_bytes(&h, &strip_v, sizeof(strip_v));
				path_in_doc = a->u.untar.source;
			} else if (a->kind == CELLMAN_ACTION_TEMPLATE) {
				hash64_update_str(&h, a->u.templ.source);
				hash64_update_str(&h, a->u.templ.target);
				hash64_update_str(&h, a->u.templ.mode);
				hash64_update_str(&h, a->u.templ.owner);
				hash64_update_str(&h, a->u.templ.group);
				hash64_update_str(&h, a->u.templ.tokens_text);
				hash64_update_kv_list(&h, &a->u.templ.tokens);
				hash64_update_kv_list(&h, &a->u.templ.token_env);
				path_in_doc = a->u.templ.source;
			} else {
				uint64_t timeout_v;
				uint64_t ignore_v;

				hash64_update_str(&h, a->u.script.path);
				hash64_update_str(&h, a->u.script.cwd);
				hash64_update_string_list(&h, &a->u.script.args);
				hash64_update_kv_list(&h, &a->u.script.env);
				timeout_v = (uint64_t)a->u.script.timeout_seconds;
				ignore_v = a->u.script.ignore_exit ? 1ULL : 0ULL;
				hash64_update_bytes(&h, &timeout_v, sizeof(timeout_v));
				hash64_update_bytes(&h, &ignore_v, sizeof(ignore_v));
				path_in_doc = a->u.script.path;
			}

			if (resolve_doc_source_path(doc, path_in_doc, &src, err) != 0)
				return -1;
			hash64_update_str(&h, src);
			if (hash64_update_file(&h, src, err) != 0) {
				free(src);
				return -1;
			}
			free(src);
			break;
		}
		case CELLMAN_ACTION_FILE:
			hash64_update_str(&h, a->u.file.path);
			hash64_update_str(&h, a->u.file.content);
			hash64_update_str(&h, a->u.file.mode);
			hash64_update_str(&h, a->u.file.owner);
			hash64_update_str(&h, a->u.file.group);
			break;
		case CELLMAN_ACTION_PATCH:
		{
			uint64_t strip_v;

			hash64_update_str(&h, a->u.patch.path);
			hash64_update_str(&h, a->u.patch.content);
			strip_v = (uint64_t)a->u.patch.strip_components;
			hash64_update_bytes(&h, &strip_v, sizeof(strip_v));
			break;
		}
		case CELLMAN_ACTION_NONE:
		default:
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "unsupported action kind in apply hash: %d", a->kind);
			return -1;
		}
	}

	return hash64_hex(h, hash_out, err);
}

static int
compute_volume_mode_change(const char *name, const char *mode_s,
    bool *changed_out, char **err)
{
	bool exists;
	char *path;
	struct stat st;
	unsigned long desired;
	char *end;

	if (changed_out == NULL)
		return -1;
	*changed_out = false;

	if (cellman_volume_exists(name, &exists, err) != 0)
		return -1;
	if (!exists) {
		*changed_out = true;
		return 0;
	}

	if (mode_s == NULL || mode_s[0] == '\0')
		return 0;

	path = NULL;
	if (cellman_volume_path(name, &path, err) != 0)
		return -1;
	if (stat(path, &st) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot stat %s: %s", path,
			    strerror(errno));
		free(path);
		return -1;
	}
	free(path);

	errno = 0;
	desired = strtoul(mode_s, &end, 8);
	if (errno != 0 || end == mode_s || *end != '\0') {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid volume mode: %s", mode_s);
		return -1;
	}

	if (((unsigned long)(st.st_mode & 07777U)) != desired)
		*changed_out = true;
	return 0;
}

static int
read_cell_state_hash(const char *name, const char *kind, char **hash_out,
    char **err)
{
	char *path;
	char *raw;
	size_t n;

	if (hash_out == NULL)
		return -1;
	*hash_out = NULL;

	path = cellman_xasprintf(NULL, "/var/cellman/cells/%s/state/%s", name,
	    kind);
	if (path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	raw = NULL;
	if (read_optional_text_file(path, &raw, err) != 0) {
		free(path);
		return -1;
	}
	free(path);

	if (raw == NULL)
		return 0;

	n = strlen(raw);
	while (n > 0 && isspace((unsigned char)raw[n - 1]))
		raw[--n] = '\0';
	*hash_out = raw;
	return 0;
}

static int
write_cell_state_hash(const char *name, const char *kind, const char *hash,
    char **err)
{
	char *path;
	char *line;
	int rc;

	if (ensure_cell_state_dir(name, err) != 0)
		return -1;

	path = cellman_xasprintf(NULL, "/var/cellman/cells/%s/state/%s", name,
	    kind);
	line = cellman_xasprintf(NULL, "%s\n", hash != NULL ? hash : "");
	if (path == NULL || line == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		free(path);
		free(line);
		return -1;
	}

	rc = write_text_file(path, line, err);
	free(path);
	free(line);
	return rc;
}

static int
remove_cell_state_hash(const char *name, const char *kind, char **err)
{
	char *path;

	path = cellman_xasprintf(NULL, "/var/cellman/cells/%s/state/%s", name,
	    kind);
	if (path == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	if (unlink(path) != 0 && errno != ENOENT) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot remove %s: %s", path,
			    strerror(errno));
		free(path);
		return -1;
	}

	free(path);
	return 0;
}

static int
run_cell_healthcheck(const struct cellman_doc *cell_doc, char **err)
{
	char *runout;
	char *runerr;
	const char *name;
	const char *command;
	const char *detail;
	const long retry_delays_ms[] = { 200L, 500L, 1000L };
	struct timespec pause;
	size_t attempt;
	size_t attempts_total;

	if (cell_doc == NULL || cell_doc->kind != CELLMAN_DOC_CELL)
		return -1;
	if (cell_doc->u.cell.healthcheck_cmd == NULL ||
	    cell_doc->u.cell.healthcheck_cmd[0] == '\0')
		return 0;

	name = cell_doc->u.cell.name != NULL ? cell_doc->u.cell.name : "";
	command = cell_doc->u.cell.healthcheck_cmd;
	attempts_total =
	    (sizeof(retry_delays_ms) / sizeof(retry_delays_ms[0])) + 1;
	runout = NULL;
	runerr = NULL;
	for (attempt = 0; attempt < attempts_total; attempt++) {
		free(runout);
		free(runerr);
		runout = NULL;
		runerr = NULL;

		if (run_argv_capture((const char *const[]){ "cellctl", "exec",
		    name, "/bin/sh", "-c", command, NULL }, &runout, &runerr) == 0) {
			free(runout);
			free(runerr);
			return 0;
		}

		if (attempt + 1 >= attempts_total)
			break;

		pause.tv_sec = retry_delays_ms[attempt] / 1000L;
		pause.tv_nsec = (retry_delays_ms[attempt] % 1000L) * 1000000L;
		while (nanosleep(&pause, &pause) != 0) {
			if (errno != EINTR)
				break;
		}
	}

	detail = (runerr != NULL && runerr[0] != '\0') ? runerr :
	    "command exited with non-zero status";
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "cell healthcheck %s failed after %zu attempts: %s (command: %s)",
		    name, attempts_total, detail, command);
	free(runout);
	free(runerr);
	return -1;
}

static int
apply_run_for_cell(const struct cellman_doc *apply_doc,
    const struct cellman_doc *cell_doc, const char *name, bool dry_run,
    bool verbose, bool forward_output, char **err)
{
	char *root;
	uid_t uid;
	gid_t gid;
	char *groups;
	char *uid_s;
	char *gid_s;
	char *saved_uid;
	char *saved_gid;
	char *saved_groups;
	char *run_as_err;
	bool had_uid;
	bool had_gid;
	bool had_groups;
	bool have_run_as_identity;
	int rc;

	root = NULL;
	groups = NULL;
	uid_s = NULL;
	gid_s = NULL;
	saved_uid = NULL;
	saved_gid = NULL;
	saved_groups = NULL;
	run_as_err = NULL;
	had_uid = false;
	had_gid = false;
	had_groups = false;
	have_run_as_identity = false;
	rc = -1;

	if (apply_doc == NULL || apply_doc->kind != CELLMAN_DOC_APPLY ||
	    name == NULL || name[0] == '\0')
		return -1;

	root = cellman_xasprintf(NULL, "/var/cellman/cells/%s/root", name);
	if (root == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto done;
	}

	if (cell_doc != NULL && cell_doc->kind == CELLMAN_DOC_CELL &&
	    cell_doc->u.cell.supervise_run_as != NULL &&
	    cell_doc->u.cell.supervise_run_as[0] != '\0') {
		if (resolve_supervise_run_as(cell_doc->u.cell.supervise_run_as, root,
		    &uid, &gid, &groups, &run_as_err) != 0) {
			if (strncmp(cell_doc->u.cell.supervise_run_as, "cell:", 5) == 0) {
				if (verbose && run_as_err != NULL && run_as_err[0] != '\0') {
					cellman_log_info("apply %s: %s; continuing without run_as identity",
					    name, run_as_err);
				}
				free(run_as_err);
				run_as_err = NULL;
			} else {
				if (err != NULL)
					*err = run_as_err;
				else
					free(run_as_err);
				run_as_err = NULL;
				goto done;
			}
		} else {
			free(run_as_err);
			run_as_err = NULL;
			have_run_as_identity = true;
		}

		if (have_run_as_identity) {
			uid_s = cellman_xasprintf(NULL, "%lu", (unsigned long)uid);
			gid_s = cellman_xasprintf(NULL, "%lu", (unsigned long)gid);
			if (uid_s == NULL || gid_s == NULL) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "out of memory");
				goto done;
			}
		}
	}

	if (getenv("CELLMAN_RUN_UID") != NULL) {
		had_uid = true;
		saved_uid = cellman_strdup(getenv("CELLMAN_RUN_UID"), NULL);
	}
	if (getenv("CELLMAN_RUN_GID") != NULL) {
		had_gid = true;
		saved_gid = cellman_strdup(getenv("CELLMAN_RUN_GID"), NULL);
	}
	if (getenv("CELLMAN_RUN_GROUPS") != NULL) {
		had_groups = true;
		saved_groups = cellman_strdup(getenv("CELLMAN_RUN_GROUPS"), NULL);
	}

	if (uid_s != NULL && setenv("CELLMAN_RUN_UID", uid_s, 1) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "setenv CELLMAN_RUN_UID failed: %s",
			    strerror(errno));
		goto done;
	}
	if (gid_s != NULL && setenv("CELLMAN_RUN_GID", gid_s, 1) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "setenv CELLMAN_RUN_GID failed: %s",
			    strerror(errno));
		goto done;
	}
	if (groups != NULL && groups[0] != '\0' &&
	    setenv("CELLMAN_RUN_GROUPS", groups, 1) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "setenv CELLMAN_RUN_GROUPS failed: %s", strerror(errno));
		goto done;
	}

	rc = cellman_apply_run_named(apply_doc, NULL, name, root, dry_run, verbose,
	    forward_output, err);

done:
	if (had_uid) {
		(void)setenv("CELLMAN_RUN_UID", saved_uid != NULL ? saved_uid : "", 1);
	} else {
		(void)unsetenv("CELLMAN_RUN_UID");
	}
	if (had_gid) {
		(void)setenv("CELLMAN_RUN_GID", saved_gid != NULL ? saved_gid : "", 1);
	} else {
		(void)unsetenv("CELLMAN_RUN_GID");
	}
	if (had_groups) {
		(void)setenv("CELLMAN_RUN_GROUPS",
		    saved_groups != NULL ? saved_groups : "", 1);
	} else {
		(void)unsetenv("CELLMAN_RUN_GROUPS");
	}

	free(saved_uid);
	free(saved_gid);
	free(saved_groups);
	free(uid_s);
	free(gid_s);
	free(groups);
	free(root);
	return rc;
}

int
cellman_backend_set_desired_mutation_error(const char *resource, char **err)
{
	/*
	 * DSL documents are the only source of truth for desired state.
	 * Command paths that would mutate desired state must fail closed.
	 */
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "%s desired-state mutations are not supported; edit /etc/cellman/*.lua",
		    resource);
	return 1;
}

/*
 * Validate runtime resource identifiers against the shared naming policy.
 */
static bool
runtime_name_valid(const char *name)
{
	size_t i;

	if (name == NULL || name[0] == '\0')
		return false;

	for (i = 0; name[i] != '\0'; i++) {
		if (!(isalnum((unsigned char)name[i]) || name[i] == '.' ||
		    name[i] == '_' || name[i] == '-'))
			return false;
	}

	return true;
}

/*
 * Build the canonical runtime directory path for one cell.
 */
static int
cell_runtime_path(const char *name, char **path_out, char **err)
{
	if (path_out == NULL)
		return -1;
	*path_out = NULL;

	if (!runtime_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s",
			    name != NULL ? name : "");
		return -1;
	}

	*path_out = cellman_xasprintf(NULL, "/var/cellman/cells/%s", name);
	if (*path_out == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	return 0;
}

/*
 * Probe whether one runtime cell directory exists.
 */
static int
cell_runtime_exists(const char *name, bool *exists_out, char **err)
{
	char *path;
	struct stat st;

	if (exists_out == NULL)
		return -1;
	*exists_out = false;

	path = NULL;
	if (cell_runtime_path(name, &path, err) != 0)
		return -1;

	if (stat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "runtime cell path is not a directory: %s", path);
			free(path);
			return -1;
		}
		*exists_out = true;
		free(path);
		return 0;
	}

	if (errno != ENOENT) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot stat %s: %s", path,
			    strerror(errno));
		free(path);
		return -1;
	}

	free(path);
	return 0;
}

/*
 * Remove one runtime cell, optionally forcing destroy failures to be ignored.
 */
static int
cell_runtime_remove_one(const char *name, bool force, bool require_existing,
    char **err)
{
	struct runtime_cell_list runtime;
	char *path;
	bool exists;
	char *runerr;
	char *umerr;
	struct stat st;

	memset(&runtime, 0, sizeof(runtime));
	path = NULL;
	runerr = NULL;
	umerr = NULL;

	if (cell_runtime_exists(name, &exists, err) != 0)
		return -1;

	if (load_runtime_cells(&runtime, err) != 0)
		goto fail;

	if (runtime_cell_is_running(&runtime, name)) {
		struct runtime_cell *row;

		row = runtime_cell_find(&runtime, name);
		if (row != NULL)
			(void)stop_supervise_monitor(name, row->cid, NULL);

		if (run_cellctl_destroy(name, true, &runerr) != 0) {
			if (!force) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL, "%s",
					    runerr != NULL ? runerr : "cellctl destroy failed");
				goto fail;
			}
			cellman_log_warn("cell remove --force: ignoring destroy failure for %s: %s",
			    name, runerr != NULL ? runerr : "unknown error");
		}
	}

	if (!exists) {
		if (require_existing) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "runtime state not found: %s", name);
			goto fail;
		}
		runtime_cell_list_free(&runtime);
		free(path);
		free(runerr);
		return 0;
	}

	if (cell_runtime_path(name, &path, err) != 0)
		goto fail;

	if (unmount_cell_mounts_name(name, &umerr) != 0) {
		if (!force) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    umerr != NULL ? umerr : "failed to unmount cell mounts");
			goto fail;
		}
		cellman_log_warn("cell remove --force: ignoring unmount failure for %s: %s",
		    name, umerr != NULL ? umerr : "unknown error");
	}
	free(umerr);
	umerr = NULL;

	remove_tree(path);
	if (lstat(path, &st) == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "failed to remove runtime cell directory: %s", path);
		goto fail;
	}
	if (errno != ENOENT) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot stat %s: %s", path,
			    strerror(errno));
		goto fail;
	}

	runtime_cell_list_free(&runtime);
	free(path);
	free(runerr);
	free(umerr);
	return 0;

fail:
	runtime_cell_list_free(&runtime);
	free(path);
	free(runerr);
	free(umerr);
	return -1;
}

/*
 * Remove all runtime cells or only runtime orphans not present in desired
 * state.
 */
static int
cell_runtime_remove_all(const struct cellman_state *state, bool only_orphans,
    bool force, size_t *removed_out, char **err)
{
	const char *root;
	DIR *dp;
	struct dirent *de;
	size_t removed;

	root = "/var/cellman/cells";
	removed = 0;
	if (removed_out != NULL)
		*removed_out = 0;

	dp = opendir(root);
	if (dp == NULL) {
		if (errno == ENOENT)
			return 0;
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot open %s: %s", root,
			    strerror(errno));
		return -1;
	}

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		char *path;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (!runtime_name_valid(de->d_name)) {
			cellman_log_warn("skipping invalid runtime cell directory name: %s",
			    de->d_name);
			continue;
		}
		if (only_orphans && state_find_cell(state, de->d_name) >= 0)
			continue;

		path = cellman_xasprintf(NULL, "%s/%s", root, de->d_name);
		if (path == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			(void)closedir(dp);
			return -1;
		}
		if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
			free(path);
			continue;
		}
		free(path);

		if (cell_runtime_remove_one(de->d_name, force, false, err) != 0) {
			(void)closedir(dp);
			return -1;
		}
		removed++;
	}

	(void)closedir(dp);
	if (removed_out != NULL)
		*removed_out = removed;
	return 0;
}

/*
 * Execute the top-level apply command in direct mode.
 */
int
cellman_command_backend_apply(int argc, char *argv[], const char *dsl_dir,
    char **err)
{
	struct cellman_state state;
	struct cellman_string_list requested;
	struct cellman_string_list targets;
	const struct cellman_doc **order;
	size_t order_len;
	bool all;
	bool dry_run;
	bool force_apply;
	bool restart_changed;
	bool silent;
	bool would_change;
	bool report_mode;
	bool log_mode;
	bool action_output;
	int verbose_level;
	size_t term_cols;
	struct apply_report_col volume_cols[4];
	struct apply_report_col cell_cols[10];
	struct apply_report_col apply_cols[5];
	struct apply_report_col action_cols[4];
	size_t max_volume_name;
	size_t max_volume_mode;
	size_t max_cell_name;
	size_t max_actions_count;
	size_t max_action_kind;
	size_t max_action_row;
	char *apply_rows_buf;
	char *action_rows_buf;
	size_t apply_rows_len;
	size_t action_rows_len;
	FILE *apply_rows_fp;
	FILE *action_rows_fp;
	const char *phase_mode;
	int i;
	int rc;

	cellman_state_init(&state);
	memset(&requested, 0, sizeof(requested));
	memset(&targets, 0, sizeof(targets));
	order = NULL;
	order_len = 0;
	all = false;
	dry_run = false;
	force_apply = false;
	restart_changed = false;
	silent = false;
	would_change = false;
	report_mode = true;
	log_mode = false;
	action_output = false;
	verbose_level = 0;
	term_cols = 120;
	apply_rows_buf = NULL;
	action_rows_buf = NULL;
	apply_rows_len = 0;
	action_rows_len = 0;
	apply_rows_fp = NULL;
	action_rows_fp = NULL;
	phase_mode = "APPLY";

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--all") == 0) {
			all = true;
			continue;
		}
		if (strcmp(argv[i], "--dry-run") == 0) {
			dry_run = true;
			continue;
		}
		if (strcmp(argv[i], "--force") == 0) {
			force_apply = true;
			continue;
		}
		if (strcmp(argv[i], "--restart-changed") == 0) {
			restart_changed = true;
			continue;
		}
		if (strcmp(argv[i], "--silent") == 0) {
			silent = true;
			continue;
		}
		if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
			if (verbose_level < 2)
				verbose_level++;
			continue;
		}
		if (strcmp(argv[i], "-vv") == 0) {
			verbose_level = 2;
			continue;
		}
		if (argv[i][0] == '-') {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "unknown apply option: %s",
				    argv[i]);
			rc = 1;
			goto done;
		}
		if (cellman_string_list_add(&requested, argv[i], err) != 0) {
			rc = 1;
			goto done;
		}
	}

	if (!dry_run && geteuid() != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "must be root");
		rc = 1;
		goto done;
	}

	if (!cellman_exec_command_exists("cellctl")) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "missing required tool: cellctl");
		rc = 1;
		goto done;
	}

	if (silent && verbose_level > 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "--silent and --verbose are mutually exclusive");
		rc = 1;
		goto done;
	}

	if (cellman_state_load_dir(dsl_dir, &state, err) != 0) {
		rc = 1;
		goto done;
	}

	if (requested.len == 0 && !all)
		all = true;
	if (dry_run)
		phase_mode = "DRY-RUN";

	report_mode = (verbose_level == 0);
	log_mode = (verbose_level >= 1);
	action_output = (verbose_level >= 2);
	term_cols = apply_report_terminal_columns();

	if (all && requested.len > 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cannot combine --all with explicit apply targets");
		rc = 1;
		goto done;
	}

	if (build_cell_dependency_order(&state, &order, &order_len, err) != 0) {
		rc = 1;
		goto done;
	}

	if (all) {
		for (i = 0; i < (int)order_len; i++) {
			if (cellman_string_list_add(&targets, order[i]->u.cell.name,
			    err) != 0) {
				rc = 1;
				goto done;
			}
		}
	} else {
		for (i = 0; i < (int)requested.len; i++) {
			if (state_find_cell(&state, requested.items[i]) < 0) {
				if (err != NULL)
					*err = cellman_xasprintf(NULL,
					    "cell not found in desired state: %s",
					    requested.items[i]);
				rc = 1;
				goto done;
			}
		}

		for (i = 0; i < (int)order_len; i++) {
			const char *name;

			name = order[i]->u.cell.name;
			if (string_list_contains(&requested, name) &&
			    cellman_string_list_add(&targets, name, err) != 0) {
				rc = 1;
				goto done;
			}
		}
	}

	max_volume_name = strlen("VOLUME");
	max_volume_mode = strlen("MODE");
	max_cell_name = strlen("CELL");
	max_actions_count = strlen("ACTIONS");
	max_action_kind = strlen("KIND");
	max_action_row = strlen("ROW");

	for (i = 0; i < (int)state.volumes.len; i++) {
		const struct cellman_doc *vdoc;
		size_t nlen;
		size_t mlen;

		vdoc = &state.volumes.items[(size_t)i];
		nlen = strlen(vdoc->u.volume.name);
		mlen = strlen(vdoc->u.volume.mode != NULL ? vdoc->u.volume.mode : "-");
		if (nlen > max_volume_name)
			max_volume_name = nlen;
		if (mlen > max_volume_mode)
			max_volume_mode = mlen;
	}

	for (i = 0; i < (int)targets.len; i++) {
		int apply_idx;
		const char *name;
		size_t nlen;

		name = targets.items[i];
		nlen = strlen(name);
		if (nlen > max_cell_name)
			max_cell_name = nlen;

		apply_idx = state_find_apply(&state, name);
		if (apply_idx >= 0) {
			size_t j;
			size_t count;
			char count_buf[64];
			char row_buf[64];
			const struct cellman_doc *adoc;

			adoc = &state.applies.items[(size_t)apply_idx];
			count = adoc->u.apply.actions.len;
			(void)snprintf(count_buf, sizeof(count_buf), "%zu", count);
			if (strlen(count_buf) > max_actions_count)
				max_actions_count = strlen(count_buf);

			if (count == 0) {
				if (1 > max_action_row)
					max_action_row = 1;
			} else {
				(void)snprintf(row_buf, sizeof(row_buf), "%zu/%zu", count,
				    count);
				if (strlen(row_buf) > max_action_row)
					max_action_row = strlen(row_buf);
			}

			for (j = 0; j < count; j++) {
				size_t kind_len;

				kind_len = strlen(cellman_action_kind_name(
				    adoc->u.apply.actions.items[j].kind));
				if (kind_len > max_action_kind)
					max_action_kind = kind_len;
			}
		}
	}

	if (!silent && report_mode) {
		char row_buf[64];

		(void)snprintf(row_buf, sizeof(row_buf), "%zu/%zu",
		    state.volumes.len, state.volumes.len);
		volume_cols[0].title = "#";
		volume_cols[0].width = strlen(row_buf);
		if (volume_cols[0].width < strlen(volume_cols[0].title))
			volume_cols[0].width = strlen(volume_cols[0].title);
		volume_cols[0].min_width = 3;
		volume_cols[0].truncate = true;
		volume_cols[1].title = "VOLUME";
		volume_cols[1].width = max_volume_name;
		volume_cols[1].min_width = max_volume_name;
		volume_cols[1].truncate = false;
		volume_cols[2].title = "MODE";
		volume_cols[2].width = max_volume_mode;
		volume_cols[2].min_width = 4;
		volume_cols[2].truncate = true;
		volume_cols[3].title = "CHG";
		volume_cols[3].width = 3;
		volume_cols[3].min_width = 3;
		volume_cols[3].truncate = true;
		apply_report_fit_columns(volume_cols, 4, term_cols);

		(void)snprintf(row_buf, sizeof(row_buf), "%zu/%zu", targets.len,
		    targets.len);
		cell_cols[0].title = "#";
		cell_cols[0].width = strlen(row_buf);
		if (cell_cols[0].width < 3)
			cell_cols[0].width = 3;
		cell_cols[0].min_width = 3;
		cell_cols[0].truncate = true;
		cell_cols[1].title = "CELL";
		cell_cols[1].width = max_cell_name;
		cell_cols[1].min_width = max_cell_name;
		cell_cols[1].truncate = false;
		cell_cols[2].title = "CHG";
		cell_cols[2].width = 3;
		cell_cols[2].min_width = 2;
		cell_cols[2].truncate = true;
		cell_cols[3].title = "APPLY";
		cell_cols[3].width = strlen("UNCHANGED");
		cell_cols[3].min_width = 4;
		cell_cols[3].truncate = true;
		cell_cols[4].title = "CFG";
		cell_cols[4].width = 3;
		cell_cols[4].min_width = 2;
		cell_cols[4].truncate = true;
		cell_cols[5].title = "SVC";
		cell_cols[5].width = 3;
		cell_cols[5].min_width = 2;
		cell_cols[5].truncate = true;
		cell_cols[6].title = "POL";
		cell_cols[6].width = 3;
		cell_cols[6].min_width = 2;
		cell_cols[6].truncate = true;
		cell_cols[7].title = "RT";
		cell_cols[7].width = 2;
		cell_cols[7].min_width = 2;
		cell_cols[7].truncate = true;
		cell_cols[8].title = "RUN";
		cell_cols[8].width = 3;
		cell_cols[8].min_width = 3;
		cell_cols[8].truncate = true;
		cell_cols[9].title = "AUTO";
		cell_cols[9].width = 4;
		cell_cols[9].min_width = 3;
		cell_cols[9].truncate = true;
		apply_report_fit_columns(cell_cols, 10, term_cols);

		apply_cols[0].title = "#";
		apply_cols[0].width = cell_cols[0].width;
		apply_cols[0].min_width = 3;
		apply_cols[0].truncate = true;
		apply_cols[1].title = "CELL";
		apply_cols[1].width = max_cell_name;
		apply_cols[1].min_width = max_cell_name;
		apply_cols[1].truncate = false;
		apply_cols[2].title = "STATE";
		apply_cols[2].width = strlen("UNCHANGED");
		apply_cols[2].min_width = 4;
		apply_cols[2].truncate = true;
		apply_cols[3].title = "ACTIONS";
		apply_cols[3].width = max_actions_count;
		if (apply_cols[3].width < strlen("ACTIONS"))
			apply_cols[3].width = strlen("ACTIONS");
		apply_cols[3].min_width = 3;
		apply_cols[3].truncate = true;
		apply_cols[4].title = "RUN";
		apply_cols[4].width = 3;
		apply_cols[4].min_width = 3;
		apply_cols[4].truncate = true;
		apply_report_fit_columns(apply_cols, 5, term_cols);

		action_cols[0].title = "CELL";
		action_cols[0].width = max_cell_name;
		action_cols[0].min_width = max_cell_name;
		action_cols[0].truncate = false;
		action_cols[1].title = "#";
		action_cols[1].width = max_action_row;
		if (action_cols[1].width < 3)
			action_cols[1].width = 3;
		action_cols[1].min_width = 3;
		action_cols[1].truncate = true;
		action_cols[2].title = "KIND";
		action_cols[2].width = max_action_kind;
		if (action_cols[2].width < 4)
			action_cols[2].width = 4;
		action_cols[2].min_width = 6;
		action_cols[2].truncate = true;
		action_cols[3].title = "RUN";
		action_cols[3].width = 3;
		action_cols[3].min_width = 3;
		action_cols[3].truncate = true;
		apply_report_fit_columns(action_cols, 4, term_cols);

		(void)cellman_payload_printf("APPLY REPORT (%s)\n", phase_mode);
		(void)cellman_payload_printf("[VOLUME]\n");
		apply_report_print_border(volume_cols, 4);
		apply_report_print_row(volume_cols, 4,
		    (const char *const[]){
		    volume_cols[0].title,
		    volume_cols[1].title,
		    volume_cols[2].title,
		    volume_cols[3].title });
		apply_report_print_border(volume_cols, 4);
	} else if (!silent && log_mode) {
		cellman_log_info("apply phase=volume mode=%s total=%zu", phase_mode,
		    state.volumes.len);
	}

	for (i = 0; i < (int)state.volumes.len; i++) {
		const struct cellman_doc *vdoc;
		bool vol_changed;

		vdoc = &state.volumes.items[(size_t)i];
		vol_changed = false;
		if (compute_volume_mode_change(vdoc->u.volume.name, vdoc->u.volume.mode,
		    &vol_changed, err) != 0) {
			rc = 1;
			goto done;
		}
		if (vol_changed)
			would_change = true;

		if (!silent && report_mode) {
			char rowbuf[64];
			const char *const row_values[] = {
			    rowbuf,
			    vdoc->u.volume.name,
			    vdoc->u.volume.mode != NULL ? vdoc->u.volume.mode : "-",
			    vol_changed ? "YES" : "NO"
			};

			(void)snprintf(rowbuf, sizeof(rowbuf), "%d/%zu", i + 1,
			    state.volumes.len);
			apply_report_print_row(volume_cols, 4, row_values);
		} else if (!silent && log_mode) {
			cellman_log_info("apply phase=volume row=%d/%zu name=%s mode=%s changed=%s",
			    i + 1,
			    state.volumes.len,
			    vdoc->u.volume.name,
			    vdoc->u.volume.mode != NULL ? vdoc->u.volume.mode : "-",
			    vol_changed ? "YES" : "NO");
		}

		if (!dry_run && cellman_volume_ensure(vdoc->u.volume.name,
		    vdoc->u.volume.mode, true, false, log_mode && !silent, err) != 0) {
			rc = 1;
			goto done;
		}
	}

	if (!silent && report_mode)
		apply_report_print_border(volume_cols, 4);

	if (!silent && report_mode) {
		(void)cellman_payload_printf("\n[CELL]\n");
		apply_report_print_border(cell_cols, 10);
		apply_report_print_row(cell_cols, 10,
		    (const char *const[]){
		    cell_cols[0].title,
		    cell_cols[1].title,
		    cell_cols[2].title,
		    cell_cols[3].title,
		    cell_cols[4].title,
		    cell_cols[5].title,
		    cell_cols[6].title,
		    cell_cols[7].title,
		    cell_cols[8].title,
		    cell_cols[9].title });
		apply_report_print_border(cell_cols, 10);

		apply_rows_fp = open_memstream(&apply_rows_buf, &apply_rows_len);
		action_rows_fp = open_memstream(&action_rows_buf, &action_rows_len);
		if (apply_rows_fp == NULL || action_rows_fp == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "failed to initialize report buffers");
			rc = 1;
			goto done;
		}
	} else if (!silent && log_mode) {
		cellman_log_info("apply phase=cell mode=%s total=%zu force=%s restart_changed=%s",
		    phase_mode,
		    targets.len,
		    force_apply ? "YES" : "NO",
		    restart_changed ? "YES" : "NO");
	}

	rc = 0;
	for (i = 0; i < (int)targets.len; i++) {
		size_t action_i;
		int cell_idx;
		int apply_idx;
		const struct cellman_doc *cell_doc;
		const struct cellman_doc *apply_doc;
		bool running_before;
		bool running_now;
		bool started_for_apply;
		bool would_run_apply;
		bool autostart;
		bool service_changed;
		bool policy_changed;
		bool config_changed;
		bool apply_needed;
		bool apply_removed;
		bool changed;
		bool runtime_exists;
		bool did_lifecycle;
		const char *apply_state;
		char *manifest_hash;
		char *service_hash;
		char *policy_hash;
		char *apply_hash;
		char *prev_manifest;
		char *prev_service;
		char *prev_policy;
		char *prev_apply;
		char *root;
		char *start_argv[1];
		char *stop_argv[1];
		char *restart_argv[1];

		manifest_hash = NULL;
		service_hash = NULL;
		policy_hash = NULL;
		apply_hash = NULL;
		prev_manifest = NULL;
		prev_service = NULL;
		prev_policy = NULL;
		prev_apply = NULL;

		cell_idx = state_find_cell(&state, targets.items[i]);
		if (cell_idx < 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
			    "cell not found in desired state: %s", targets.items[i]);
			rc = 1;
			break;
		}
		cell_doc = &state.cells.items[(size_t)cell_idx];
		apply_idx = state_find_apply(&state, targets.items[i]);
		apply_doc = apply_idx >= 0 ? &state.applies.items[(size_t)apply_idx] : NULL;

		if (compute_cell_config_hashes(cell_doc, &manifest_hash, &service_hash,
		    &policy_hash) != 0) {
			if (err != NULL && *err == NULL)
				*err = cellman_xasprintf(NULL,
				    "failed to compute config hash for %s", targets.items[i]);
			rc = 1;
			goto loop_done;
		}

		if (read_cell_state_hash(targets.items[i], "manifest.sha256",
		    &prev_manifest, err) != 0 ||
		    read_cell_state_hash(targets.items[i], "service.sha256",
		    &prev_service, err) != 0 ||
		    read_cell_state_hash(targets.items[i], "policy.sha256",
		    &prev_policy, err) != 0 ||
		    read_cell_state_hash(targets.items[i], "apply.sha256",
		    &prev_apply, err) != 0) {
			rc = 1;
			goto loop_done;
		}

		service_changed = prev_service == NULL ||
		    strcmp(prev_service, service_hash) != 0;
		policy_changed = prev_policy == NULL || strcmp(prev_policy, policy_hash) != 0;
		config_changed = prev_manifest == NULL ||
		    strcmp(prev_manifest, manifest_hash) != 0 || service_changed ||
		    policy_changed;

		apply_needed = false;
		apply_removed = false;
		if (apply_doc != NULL) {
			if (compute_apply_doc_hash(apply_doc, &apply_hash, err) != 0) {
				rc = 1;
				goto loop_done;
			}
			apply_needed = force_apply || prev_apply == NULL ||
			    strcmp(prev_apply, apply_hash) != 0;
		} else if (prev_apply != NULL)
			apply_removed = true;

		if (apply_doc == NULL)
			apply_state = apply_removed ? "REMOVED" : "NONE";
		else
			apply_state = apply_needed ? "PENDING" : "UNCHANGED";

		autostart = cell_autostart_desired(cell_doc);
		if (cell_runtime_exists(targets.items[i], &runtime_exists, err) != 0) {
			rc = 1;
			goto loop_done;
		}

		running_before = false;
		{
			struct runtime_cell_list current_runtime;

			memset(&current_runtime, 0, sizeof(current_runtime));
			if (load_runtime_cells(&current_runtime, err) != 0) {
				rc = 1;
				goto loop_done;
			}
			running_before = runtime_cell_is_running(&current_runtime,
			    targets.items[i]);
			runtime_cell_list_free(&current_runtime);
		}

		changed = false;
		if (!runtime_exists || config_changed || apply_needed || apply_removed)
			changed = true;
		if (autostart) {
			if (!running_before || service_changed || policy_changed)
				changed = true;
		} else {
			if (running_before || apply_needed)
				changed = true;
		}

		would_run_apply = (apply_doc != NULL && apply_needed);

		if (!silent && report_mode) {
			char rowbuf[64];
			char actions_buf[64];
			const char *const cell_values[] = {
			    rowbuf,
			    targets.items[i],
			    changed ? "YES" : "NO",
			    apply_state,
			    config_changed ? "YES" : "NO",
			    service_changed ? "YES" : "NO",
			    policy_changed ? "YES" : "NO",
			    runtime_exists ? "YES" : "NO",
			    running_before ? "YES" : "NO",
			    autostart ? "YES" : "NO"
			};
			const char *const apply_values[] = {
			    rowbuf,
			    targets.items[i],
			    apply_state,
			    actions_buf,
			    would_run_apply ? "YES" : "NO"
			};

			(void)snprintf(rowbuf, sizeof(rowbuf), "%d/%zu", i + 1,
			    targets.len);
			(void)snprintf(actions_buf, sizeof(actions_buf), "%zu",
			    apply_doc != NULL ? apply_doc->u.apply.actions.len : 0);

			apply_report_print_row(cell_cols, 10, cell_values);
			apply_report_print_row_fp(apply_rows_fp, apply_cols, 5,
			    apply_values);

			if (apply_doc != NULL && apply_doc->u.apply.actions.len > 0) {
				for (action_i = 0; action_i < apply_doc->u.apply.actions.len;
				    action_i++) {
					const struct cellman_action *action;
					char action_row[64];
					const char *action_values[4];

					action = &apply_doc->u.apply.actions.items[action_i];
					action_values[0] = targets.items[i];
					action_values[1] = action_row;
					action_values[2] = cellman_action_kind_name(action->kind);
					action_values[3] = would_run_apply ? "YES" : "NO";
					(void)snprintf(action_row, sizeof(action_row), "%zu/%zu",
					    action_i + 1, apply_doc->u.apply.actions.len);
					apply_report_print_row_fp(action_rows_fp, action_cols, 4,
					    action_values);
				}
			} else {
				const char *const action_values[] = {
				    targets.items[i],
				    "-",
				    "(none)",
				    "NO"
				};
				apply_report_print_row_fp(action_rows_fp, action_cols, 4,
				    action_values);
			}
		} else if (!silent && log_mode) {
			cellman_log_info("apply phase=cell row=%d/%zu name=%s changed=%s apply=%s cfg=%s svc=%s pol=%s rt=%s run=%s auto=%s",
			    i + 1,
			    targets.len,
			    targets.items[i],
			    changed ? "YES" : "NO",
			    apply_state,
			    config_changed ? "YES" : "NO",
			    service_changed ? "YES" : "NO",
			    policy_changed ? "YES" : "NO",
			    runtime_exists ? "YES" : "NO",
			    running_before ? "YES" : "NO",
			    autostart ? "YES" : "NO");
			cellman_log_info("apply phase=plan row=%d/%zu name=%s state=%s actions=%zu run=%s",
			    i + 1,
			    targets.len,
			    targets.items[i],
			    apply_state,
			    apply_doc != NULL ? apply_doc->u.apply.actions.len : 0,
			    would_run_apply ? "YES" : "NO");
			if (apply_doc != NULL && apply_doc->u.apply.actions.len > 0) {
				for (action_i = 0; action_i < apply_doc->u.apply.actions.len;
				    action_i++) {
					const struct cellman_action *action;

					action = &apply_doc->u.apply.actions.items[action_i];
					cellman_log_info("apply phase=action name=%s row=%zu/%zu kind=%s run=%s",
					    targets.items[i],
					    action_i + 1,
					    apply_doc->u.apply.actions.len,
					    cellman_action_kind_name(action->kind),
					    would_run_apply ? "YES" : "NO");
				}
			} else {
				cellman_log_info("apply phase=action name=%s row=- kind=(none) run=NO",
				    targets.items[i]);
			}
		}

		if (dry_run) {
			if (changed)
				would_change = true;
			goto loop_done;
		}

		root = cellman_xasprintf(NULL, "/var/cellman/cells/%s/root",
		    targets.items[i]);
		if (root == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			rc = 1;
			goto loop_done;
		}
		if (mkdir_p_local(root, 0755, err) != 0) {
			free(root);
			rc = 1;
			goto loop_done;
		}
		free(root);

		running_now = running_before;
		started_for_apply = false;
		did_lifecycle = false;
		start_argv[0] = targets.items[i];
		stop_argv[0] = targets.items[i];
		restart_argv[0] = targets.items[i];

		if (!autostart && running_now) {
			if (cmd_cell_lifecycle("stop", 1, stop_argv, dsl_dir, err) != 0) {
				rc = 1;
				goto loop_done;
			}
			running_now = false;
			did_lifecycle = true;
		}

		if (apply_doc != NULL && apply_needed) {
			if (!running_now) {
				if (start_cells_with_dependencies(dsl_dir, start_argv[0], false,
				    false, err) != 0) {
					rc = 1;
					goto loop_done;
				}
				running_now = true;
				started_for_apply = true;
				did_lifecycle = true;
			}

			if (apply_run_for_cell(apply_doc, cell_doc, targets.items[i], false,
			    log_mode && !silent, action_output && !silent, err) != 0) {
				rc = 1;
				goto loop_done;
			}

			if (autostart) {
				if ((running_before || started_for_apply) &&
				    cmd_cell_lifecycle("restart", 1, restart_argv, dsl_dir,
				    err) != 0) {
					rc = 1;
					goto loop_done;
				}
				if (running_before || started_for_apply)
					did_lifecycle = true;
			} else if (running_now) {
				if (cmd_cell_lifecycle("stop", 1, stop_argv, dsl_dir, err) != 0) {
					rc = 1;
					goto loop_done;
				}
				running_now = false;
				did_lifecycle = true;
			}
		}

		if (autostart) {
			if (!running_now) {
				if (cmd_cell_lifecycle("start", 1, start_argv, dsl_dir, err) != 0) {
					rc = 1;
					goto loop_done;
				}
				running_now = true;
				did_lifecycle = true;
			} else if (!started_for_apply &&
			    (service_changed || (policy_changed && restart_changed))) {
				if (cmd_cell_lifecycle("restart", 1, restart_argv, dsl_dir,
				    err) != 0) {
					rc = 1;
					goto loop_done;
				}
				did_lifecycle = true;
			}
		} else if (running_now) {
			if (cmd_cell_lifecycle("stop", 1, stop_argv, dsl_dir, err) != 0) {
				rc = 1;
				goto loop_done;
			}
			running_now = false;
			did_lifecycle = true;
		}

		if (autostart && running_now && (!did_lifecycle || started_for_apply) &&
		    run_cell_healthcheck(cell_doc, err) != 0) {
			rc = 1;
			goto loop_done;
		}

		if (write_cell_state_hash(targets.items[i], "manifest.sha256",
		    manifest_hash, err) != 0 ||
		    write_cell_state_hash(targets.items[i], "service.sha256",
		    service_hash, err) != 0 ||
		    write_cell_state_hash(targets.items[i], "policy.sha256",
		    policy_hash, err) != 0) {
			rc = 1;
			goto loop_done;
		}

		if (apply_doc != NULL) {
			if (write_cell_state_hash(targets.items[i], "apply.sha256",
			    apply_hash, err) != 0) {
				rc = 1;
				goto loop_done;
			}
		} else if (remove_cell_state_hash(targets.items[i], "apply.sha256",
		    err) != 0) {
			rc = 1;
			goto loop_done;
		}

loop_done:
		free(manifest_hash);
		free(service_hash);
		free(policy_hash);
		free(apply_hash);
		free(prev_manifest);
		free(prev_service);
		free(prev_policy);
		free(prev_apply);
		if (rc != 0)
			break;
	}

	if (!silent && report_mode) {
		apply_report_print_border(cell_cols, 10);
		if (apply_rows_fp != NULL) {
			(void)fflush(apply_rows_fp);
			(void)fclose(apply_rows_fp);
			apply_rows_fp = NULL;
		}
		if (action_rows_fp != NULL) {
			(void)fflush(action_rows_fp);
			(void)fclose(action_rows_fp);
			action_rows_fp = NULL;
		}

		(void)cellman_payload_printf("\n[APPLY]\n");
		apply_report_print_border(apply_cols, 5);
		apply_report_print_row(apply_cols, 5,
		    (const char *const[]){
		    apply_cols[0].title,
		    apply_cols[1].title,
		    apply_cols[2].title,
		    apply_cols[3].title,
		    apply_cols[4].title });
		apply_report_print_border(apply_cols, 5);
		if (apply_rows_buf != NULL)
			(void)fputs(apply_rows_buf, stdout);
		apply_report_print_border(apply_cols, 5);

		(void)cellman_payload_printf("\n[ACTIONS]\n");
		apply_report_print_border(action_cols, 4);
		apply_report_print_row(action_cols, 4,
		    (const char *const[]){
		    action_cols[0].title,
		    action_cols[1].title,
		    action_cols[2].title,
		    action_cols[3].title });
		apply_report_print_border(action_cols, 4);
		if (action_rows_buf != NULL)
			(void)fputs(action_rows_buf, stdout);
		apply_report_print_border(action_cols, 4);
	}

	if (rc == 0 && dry_run && would_change)
		rc = 2;

	if (rc == 0 || rc == 2) {
		(void)cellman_payload_printf("ok apply targets=%zu dry_run=%s\n",
		    targets.len,
		    dry_run ? "YES" : "NO");
		if (rc == 2)
			(void)cellman_payload_printf("dry-run changes=pending\n");
	}

done:
	if (apply_rows_fp != NULL)
		(void)fclose(apply_rows_fp);
	if (action_rows_fp != NULL)
		(void)fclose(action_rows_fp);
	free(apply_rows_buf);
	free(action_rows_buf);
	free(order);
	cellman_string_list_free(&requested);
	cellman_string_list_free(&targets);
	cellman_state_free(&state);
	return rc;
}

static int
cell_start_one(const struct cellman_state *state, const struct cellman_doc *doc,
    const struct runtime_cell_list *runtime, bool run_healthcheck, char **err)
{
	char *root;
	const char *create_argv[20];
	const char *sup_argv[32];
	int idx;
	char *err_local;
	uid_t run_uid;
	gid_t run_gid;
	char *run_uid_s;
	char *run_gid_s;
	char *run_groups;
	char *run_as_err;
	char *cmd_out;
	bool have_run_as;
	bool root_mounted;
	bool created;

	if (state == NULL || doc == NULL)
		return -1;
	if (runtime_cell_is_running(runtime, doc->u.cell.name))
		return 0;

	err_local = NULL;
	run_uid_s = NULL;
	run_gid_s = NULL;
	run_groups = NULL;
	run_as_err = NULL;
	cmd_out = NULL;
	have_run_as = false;
	root_mounted = false;
	created = false;

	root = cellman_xasprintf(NULL, "/var/cellman/cells/%s/root",
	    doc->u.cell.name);
	if (root == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	if (mkdir(root, 0755) != 0 && errno != EEXIST) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot create %s: %s", root,
			    strerror(errno));
		free(root);
		return -1;
	}

	if (mount_cell_root_runtime(doc, root, err) != 0)
		goto fail;
	root_mounted = true;

	if (mount_cell_volumes_runtime(state, doc, root, err) != 0)
		goto fail;

	idx = 0;
	create_argv[idx++] = "cellctl";
	create_argv[idx++] = "create";
	if (doc->u.cell.profile != NULL && doc->u.cell.profile[0] != '\0') {
		create_argv[idx++] = "-l";
		create_argv[idx++] = doc->u.cell.profile;
	}
	if (doc->u.cell.reserved_ports != NULL &&
	    doc->u.cell.reserved_ports[0] != '\0') {
		create_argv[idx++] = "-r";
		create_argv[idx++] = doc->u.cell.reserved_ports;
	}
	if (doc->u.cell.rlimit_nofile != NULL &&
	    doc->u.cell.rlimit_nofile[0] != '\0') {
		create_argv[idx++] = "-N";
		create_argv[idx++] = doc->u.cell.rlimit_nofile;
	}
	if (doc->u.cell.rlimit_as != NULL &&
	    doc->u.cell.rlimit_as[0] != '\0') {
		create_argv[idx++] = "-A";
		create_argv[idx++] = doc->u.cell.rlimit_as;
	}
	if (doc->u.cell.rlimit_core != NULL &&
	    doc->u.cell.rlimit_core[0] != '\0') {
		create_argv[idx++] = "-C";
		create_argv[idx++] = doc->u.cell.rlimit_core;
	}
	create_argv[idx++] = "-n";
	create_argv[idx++] = doc->u.cell.name;
	create_argv[idx++] = root;
	create_argv[idx] = NULL;

	if (run_argv_capture(create_argv, &cmd_out, &err_local) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cell create %s failed: %s",
			    doc->u.cell.name,
			    err_local != NULL ? err_local :
			    (cmd_out != NULL ? cmd_out : "unknown error"));
		free(cmd_out);
		cmd_out = NULL;
		free(err_local);
		err_local = NULL;
		goto fail;
	}
	free(cmd_out);
	cmd_out = NULL;
	free(err_local);
	err_local = NULL;
	created = true;

	if (doc->u.cell.supervise_cmd != NULL && doc->u.cell.supervise_cmd[0] != '\0') {
		if (doc->u.cell.supervise_run_as != NULL &&
		    doc->u.cell.supervise_run_as[0] != '\0') {
			if (resolve_supervise_run_as(doc->u.cell.supervise_run_as, root,
			    &run_uid, &run_gid, &run_groups, &run_as_err) != 0) {
				if (!run_healthcheck &&
				    strncmp(doc->u.cell.supervise_run_as, "cell:", 5) == 0) {
					free(run_as_err);
					run_as_err = NULL;
				} else {
					if (err != NULL)
						*err = run_as_err;
					else
						free(run_as_err);
					run_as_err = NULL;
					goto fail;
				}
			} else {
				free(run_as_err);
				run_as_err = NULL;
				run_uid_s = cellman_xasprintf(NULL, "%lu",
				    (unsigned long)run_uid);
				run_gid_s = cellman_xasprintf(NULL, "%lu",
				    (unsigned long)run_gid);
				if (run_uid_s == NULL || run_gid_s == NULL) {
					if (err != NULL)
						*err = cellman_xasprintf(NULL, "out of memory");
					goto fail;
				}
				have_run_as = true;
			}
		}

		idx = 0;
		sup_argv[idx++] = "cellctl";
		sup_argv[idx++] = "supervise";
		if (doc->u.cell.supervise_log_facility != NULL &&
		    doc->u.cell.supervise_log_facility[0] != '\0') {
			sup_argv[idx++] = "-f";
			sup_argv[idx++] = doc->u.cell.supervise_log_facility;
		}
		if (doc->u.cell.supervise_stdout_level != NULL &&
		    doc->u.cell.supervise_stdout_level[0] != '\0') {
			sup_argv[idx++] = "-o";
			sup_argv[idx++] = doc->u.cell.supervise_stdout_level;
		}
		if (doc->u.cell.supervise_stderr_level != NULL &&
		    doc->u.cell.supervise_stderr_level[0] != '\0') {
			sup_argv[idx++] = "-e";
			sup_argv[idx++] = doc->u.cell.supervise_stderr_level;
		}
		if (doc->u.cell.supervise_log_tag != NULL &&
		    doc->u.cell.supervise_log_tag[0] != '\0') {
			sup_argv[idx++] = "-t";
			sup_argv[idx++] = doc->u.cell.supervise_log_tag;
		}
		if (have_run_as) {
			sup_argv[idx++] = "-U";
			sup_argv[idx++] = run_uid_s;
			sup_argv[idx++] = "-G";
			sup_argv[idx++] = run_gid_s;
			if (run_groups != NULL && run_groups[0] != '\0') {
				sup_argv[idx++] = "-g";
				sup_argv[idx++] = run_groups;
			}
		}
		sup_argv[idx++] = doc->u.cell.name;
		sup_argv[idx++] = "/bin/sh";
		sup_argv[idx++] = "-c";
		sup_argv[idx++] = doc->u.cell.supervise_cmd;
		sup_argv[idx] = NULL;

		if (run_argv_capture(sup_argv, &cmd_out, &err_local) != 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "cell supervise %s failed: %s",
				    doc->u.cell.name,
				    err_local != NULL ? err_local :
				    (cmd_out != NULL ? cmd_out : "unknown error"));
			free(cmd_out);
			cmd_out = NULL;
			free(err_local);
			err_local = NULL;
			goto fail;
		}
		free(cmd_out);
		cmd_out = NULL;
		free(err_local);
		err_local = NULL;
	}

	if (run_healthcheck && doc->u.cell.healthcheck_cmd != NULL &&
	    doc->u.cell.healthcheck_cmd[0] != '\0') {
		if (run_cell_healthcheck(doc, err) != 0) {
			/*
			 * Keep runtime state intact on post-start healthcheck failures.
			 * Apply should fail, but rollback destroy/umount can race with
			 * supervised services and produce noisy EBUSY errors.
			 */
			created = false;
			root_mounted = false;
			goto fail;
		}
		free(err_local);
		err_local = NULL;
	}

	free(run_uid_s);
	free(run_gid_s);
	free(run_groups);
	free(run_as_err);
	free(cmd_out);
	free(root);
	return 0;

fail:
	free(err_local);
	if (created) {
		char *rollback_err;

		rollback_err = NULL;
		(void)run_cellctl_destroy(doc->u.cell.name, false, &rollback_err);
		free(rollback_err);
	}
	if (root_mounted && root != NULL) {
		char *rollback_err;

		rollback_err = NULL;
		(void)unmount_under_root(root, &rollback_err);
		free(rollback_err);
	}
	free(run_uid_s);
	free(run_gid_s);
	free(run_groups);
	free(run_as_err);
	free(cmd_out);
	free(root);
	return -1;
}

static int
start_cells_with_dependencies(const char *dsl_dir, const char *name, bool all,
    bool run_healthcheck, char **err)
{
	struct cellman_state state;
	struct runtime_cell_list runtime;
	const struct cellman_doc **order;
	size_t order_len;
	bool *needed;
	size_t i;

	cellman_state_init(&state);
	memset(&runtime, 0, sizeof(runtime));
	order = NULL;
	order_len = 0;
	needed = NULL;

	if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
		goto fail;
	if (load_runtime_cells(&runtime, err) != 0)
		goto fail;
	if (build_cell_dependency_order(&state, &order, &order_len, err) != 0)
		goto fail;

	if (all) {
		for (i = 0; i < order_len; i++) {
			if (cell_start_one(&state, order[i], &runtime, run_healthcheck,
			    err) != 0)
				goto fail;
		}
	} else {
		int target_idx;

		target_idx = state_find_cell(&state, name);
		if (target_idx < 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "unknown cell: %s", name);
			goto fail;
		}

		needed = calloc(state.cells.len, sizeof(*needed));
		if (needed == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "out of memory");
			goto fail;
		}

		if (mark_cell_needed(&state, target_idx, needed, err) != 0)
			goto fail;

		for (i = 0; i < order_len; i++) {
			int idx;

			idx = state_find_cell(&state, order[i]->u.cell.name);
			if (idx < 0 || !needed[(size_t)idx])
				continue;
			if (cell_start_one(&state, order[i], &runtime, run_healthcheck,
			    err) != 0)
				goto fail;
		}
	}

	free(order);
	free(needed);
	runtime_cell_list_free(&runtime);
	cellman_state_free(&state);
	return 0;

fail:
	free(order);
	free(needed);
	runtime_cell_list_free(&runtime);
	cellman_state_free(&state);
	return 1;
}

int
cmd_cell_lifecycle(const char *op, int argc, char *argv[], const char *dsl_dir,
    char **err)
{
	struct runtime_cell_list runtime;
	bool all;
	const char *name;
	size_t i;

	all = false;
	name = NULL;

	for (i = 0; i < (size_t)argc; i++) {
		if (strcmp(argv[i], "--all") == 0) {
			all = true;
			continue;
		}
		if (argv[i][0] == '-')
			goto badopt;
		if (name == NULL) {
			name = argv[i];
			continue;
		}
		goto badopt;
	}

	if (all == (name != NULL))
		goto badopt;

	if (strcmp(op, "start") == 0)
		return start_cells_with_dependencies(dsl_dir, name, all, true, err);

	if (strcmp(op, "stop") == 0 || strcmp(op, "restart") == 0) {
		memset(&runtime, 0, sizeof(runtime));
		if (load_runtime_cells(&runtime, err) != 0)
			return 1;

		if (all) {
			for (i = 0; i < runtime.len; i++) {
				if (stop_runtime_cell_doc(&runtime.items[i], err) != 0) {
					runtime_cell_list_free(&runtime);
					return 1;
				}
			}
		} else {
			struct runtime_cell *row;

			row = runtime_cell_find(&runtime, name);
			if (row != NULL) {
				if (stop_runtime_cell_doc(row, err) != 0) {
					runtime_cell_list_free(&runtime);
					return 1;
				}
			} else if (unmount_cell_mounts_name(name, err) != 0) {
				runtime_cell_list_free(&runtime);
				return 1;
			}
		}
		runtime_cell_list_free(&runtime);

		if (strcmp(op, "restart") == 0)
			return cmd_cell_lifecycle("start", argc, argv, dsl_dir, err);
		return 0;
	}

	if (err != NULL)
		*err = cellman_xasprintf(NULL, "unsupported lifecycle op: %s", op);
	return 1;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "usage: cell %s <name>|--all", op);
	return 1;
}

/*
 * Run one apply plan for a target cell, optionally from an explicit DSL file.
 * When --ephemeral is set and the cell was started by this command, it is
 * stopped after plan execution.
 */
int
cmd_cell_plan_run(int argc, char *argv[], const char *dsl_dir, char **err)
{
	char *name;
	const char *file;
	bool ephemeral;
	int i;
	struct cellman_state state;
	struct runtime_cell_list runtime;
	struct cellman_doc_list loaded_docs;
	const struct cellman_doc *apply_doc;
	bool started_by_apply;
	char *root;
	int apply_rc;
	int stop_rc;
	int rc;
	size_t loaded_i;

	if (argc < 1)
		goto badopt;

	name = argv[0];
	file = NULL;
	ephemeral = false;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--file") == 0) {
			if (i + 1 >= argc)
				goto badopt;
			file = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--ephemeral") == 0) {
			ephemeral = true;
			continue;
		}
		goto badopt;
	}

	if (!runtime_name_valid(name)) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "invalid cell name: %s", name);
		return 1;
	}

	cellman_state_init(&state);
	memset(&runtime, 0, sizeof(runtime));
	memset(&loaded_docs, 0, sizeof(loaded_docs));
	apply_doc = NULL;
	started_by_apply = false;
	root = NULL;
	apply_rc = 1;
	stop_rc = 0;
	rc = 1;

	if (file != NULL) {
		size_t match_count;

		if (cellman_dsl_load_file_all(file, &loaded_docs, err) != 0)
			goto done;
		match_count = 0;
		for (loaded_i = 0; loaded_i < loaded_docs.len; loaded_i++) {
			if (loaded_docs.items[loaded_i].kind != CELLMAN_DOC_APPLY)
				continue;
			if (strcmp(loaded_docs.items[loaded_i].u.apply.name, name) != 0)
				continue;
			apply_doc = &loaded_docs.items[loaded_i];
			match_count++;
		}
		if (match_count == 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "cell plan run: --file must define apply(\"%s\", ...)",
				    name);
			goto done;
		}
		if (match_count > 1) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "cell plan run: --file defines multiple apply(\"%s\", ...) documents",
				    name);
			goto done;
		}
	} else {
		int apply_idx;

		if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
			goto done;
		apply_idx = state_find_apply(&state, name);
		if (apply_idx < 0) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL,
				    "cell plan run: no apply document found for cell %s", name);
			goto done;
		}
		apply_doc = &state.applies.items[(size_t)apply_idx];
	}

	if (load_runtime_cells(&runtime, err) != 0)
		goto done;

	if (!runtime_cell_is_running(&runtime, name)) {
		if (start_cells_with_dependencies(dsl_dir, name, false, false,
		    err) != 0)
			goto done;
		started_by_apply = true;
	}

	root = cellman_xasprintf(NULL, "/var/cellman/cells/%s/root", name);
	if (root == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto done;
	}

	apply_rc = cellman_apply_run_named(apply_doc, NULL, name, root, false,
	    true, true, err) == 0 ? 0 : 1;

	if (ephemeral && started_by_apply) {
		char *stop_err;
		char *stop_argv[1];

		stop_err = NULL;
		stop_argv[0] = name;
		if (cmd_cell_lifecycle("stop", 1, stop_argv, dsl_dir, &stop_err) !=
		    0) {
			if (apply_rc == 0 && err != NULL)
				*err = cellman_xasprintf(NULL, "%s",
				    stop_err != NULL ? stop_err : "cell stop failed");
			free(stop_err);
			stop_rc = 1;
		}
	}

	if (apply_rc != 0)
		rc = 1;
	else
		rc = stop_rc;

	if (rc == 0)
		(void)cellman_payload_printf("ok cell plan run name=%s\n", name);

done:
	runtime_cell_list_free(&runtime);
	cellman_state_free(&state);
	for (loaded_i = 0; loaded_i < loaded_docs.len; loaded_i++)
		cellman_doc_free(&loaded_docs.items[loaded_i]);
	free(loaded_docs.items);
	free(root);
	return rc;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "usage: cell plan run <name> [--file file.lua] [--ephemeral]");
	return 1;
}

/*
 * Remove runtime cell state for one target, all cells, or runtime orphans.
 */
int
cmd_cell_remove(int argc, char *argv[], const char *dsl_dir, char **err)
{
	struct cellman_state state;
	const char *target;
	bool yes;
	bool force;
	bool need_state;
	int i;
	size_t removed;
	int rc;

	target = NULL;
	yes = false;
	force = false;
	need_state = false;
	removed = 0;
	rc = 1;
	cellman_state_init(&state);

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--yes") == 0) {
			yes = true;
			continue;
		}
		if (strcmp(argv[i], "--force") == 0) {
			force = true;
			continue;
		}
		if (argv[i][0] == '-') {
			if (target == NULL && (strcmp(argv[i], "--all") == 0 ||
			    strcmp(argv[i], "--orphans") == 0)) {
				target = argv[i];
				continue;
			}
			goto badopt;
		}
		if (target != NULL)
			goto badopt;
		target = argv[i];
	}

	if (target == NULL)
		goto badopt;

	if ((strcmp(target, "--all") == 0 || strcmp(target, "--orphans") == 0) &&
	    !yes) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "cell remove %s requires --yes in runtime mode", target);
		goto done;
	}

	if (strcmp(target, "--all") == 0) {
		if (cell_runtime_remove_all(NULL, false, force, &removed, err) != 0)
			goto done;
		(void)cellman_payload_printf(
		    "ok cell remove all removed=%zu\n", removed);
		rc = 0;
		goto done;
	}

	if (strcmp(target, "--orphans") == 0) {
		need_state = true;
		if (cellman_state_load_dir(dsl_dir, &state, err) != 0)
			goto done;
		if (cell_runtime_remove_all(&state, true, force, &removed, err) != 0)
			goto done;
		(void)cellman_payload_printf(
		    "ok cell remove orphans removed=%zu\n", removed);
		rc = 0;
		goto done;
	}

	if (cell_runtime_remove_one(target, force, true, err) != 0)
		goto done;
	(void)cellman_payload_printf("ok cell remove name=%s\n", target);
	rc = 0;
	goto done;

badopt:
	if (err != NULL)
		*err = cellman_xasprintf(NULL,
		    "usage: cell remove <name|--all|--orphans> [--yes] [--force]");
	rc = 1;

done:
	if (need_state)
		cellman_state_free(&state);
	return rc;
}
