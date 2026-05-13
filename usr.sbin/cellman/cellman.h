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
 * Layer: cellman shared model and runtime contract layer.
 *
 * Define core IR structs plus shared utility/runtime interfaces consumed
 * across cellman modules.
 *
 * Extension guidance: Add cross-module contracts here; keep module-private
 * interfaces in local internal headers.
 */

#ifndef CELLMAN_H
#define CELLMAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

enum cellman_doc_kind {
	CELLMAN_DOC_NONE = 0,
	CELLMAN_DOC_CELL,
	CELLMAN_DOC_VOLUME,
	CELLMAN_DOC_APPLY,
};

enum cellman_action_kind {
	CELLMAN_ACTION_NONE = 0,
	CELLMAN_ACTION_PKG,
	CELLMAN_ACTION_EXEC,
	CELLMAN_ACTION_DIR,
	CELLMAN_ACTION_LINE,
	CELLMAN_ACTION_SYMLINK,
	CELLMAN_ACTION_COPY,
	CELLMAN_ACTION_UNTAR,
	CELLMAN_ACTION_FILE,
	CELLMAN_ACTION_PATCH,
	CELLMAN_ACTION_TEMPLATE,
	CELLMAN_ACTION_SCRIPT,
};

struct cellman_string_list {
	char **items;
	size_t len;
	size_t cap;
};

struct cellman_kv_entry {
	char *key;
	char *value;
};

struct cellman_kv_list {
	struct cellman_kv_entry *items;
	size_t len;
	size_t cap;
};

struct cellman_cell_doc {
	char *name;
	bool autostart_set;
	bool autostart;
	char *profile;
	char *reserved_ports;
	char *rlimit_nofile;
	char *rlimit_as;
	char *rlimit_core;
	char *supervise_cmd;
	char *supervise_run_as;
	char *supervise_log_facility;
	char *supervise_stdout_level;
	char *supervise_stderr_level;
	char *supervise_log_tag;
	char *healthcheck_cmd;
	struct cellman_string_list depends_on;
	struct cellman_string_list mounts;
};

struct cellman_volume_doc {
	char *name;
	char *mode;
};

struct cellman_action_pkg {
	struct cellman_string_list packages;
};

struct cellman_action_exec {
	char *command;
};

struct cellman_action_dir {
	char *path;
	char *mode;
	char *owner;
	char *group;
};

struct cellman_action_line {
	char *path;
	char *text;
};

struct cellman_action_symlink {
	char *target;
	char *linkpath;
};

struct cellman_action_copy {
	char *source;
	char *target;
	char *mode;
	char *owner;
	char *group;
};

struct cellman_action_untar {
	char *source;
	char *target;
	unsigned int strip_components;
};

struct cellman_action_file {
	char *path;
	char *content;
	char *mode;
	char *owner;
	char *group;
};

struct cellman_action_patch {
	char *path;
	char *content;
	unsigned int strip_components;
};

struct cellman_action_template {
	char *source;
	char *target;
	char *mode;
	char *owner;
	char *group;
	char *tokens_text;
	struct cellman_kv_list tokens;
	struct cellman_kv_list token_env;
};

struct cellman_action_script {
	char *path;
	struct cellman_string_list args;
	struct cellman_kv_list env;
	char *cwd;
	unsigned int timeout_seconds;
	bool ignore_exit;
};

struct cellman_action {
	enum cellman_action_kind kind;
	union {
		struct cellman_action_pkg pkg;
		struct cellman_action_exec exec;
		struct cellman_action_dir dir;
		struct cellman_action_line line;
		struct cellman_action_symlink symlink;
		struct cellman_action_copy copy;
		struct cellman_action_untar untar;
		struct cellman_action_file file;
		struct cellman_action_patch patch;
		struct cellman_action_template templ;
		struct cellman_action_script script;
	} u;
};

struct cellman_action_list {
	struct cellman_action *items;
	size_t len;
	size_t cap;
};

struct cellman_apply_doc {
	char *name;
	struct cellman_action_list actions;
};

struct cellman_doc {
	enum cellman_doc_kind kind;
	char *source_path;
	char *source_dir;
	union {
		struct cellman_cell_doc cell;
		struct cellman_volume_doc volume;
		struct cellman_apply_doc apply;
	} u;
};

struct cellman_tokens {
	struct cellman_kv_list pairs;
};

struct cellman_doc_list {
	struct cellman_doc *items;
	size_t len;
	size_t cap;
};

struct cellman_state {
	struct cellman_doc_list cells;
	struct cellman_doc_list volumes;
	struct cellman_doc_list applies;
};

struct cellman_backup_record {
	char *timestamp;
	char *size;
	char *archive;
};

struct cellman_backup_record_list {
	struct cellman_backup_record *items;
	size_t len;
};

void	cellman_doc_init(struct cellman_doc *);
void	cellman_doc_free(struct cellman_doc *);
int	cellman_doc_set_source(struct cellman_doc *, const char *, char **);
const char *cellman_doc_kind_name(enum cellman_doc_kind);
const char *cellman_action_kind_name(enum cellman_action_kind);
void	cellman_doc_dump(FILE *, const struct cellman_doc *);

int	cellman_action_list_append_move(struct cellman_action_list *,
	    struct cellman_action *, char **);

void	cellman_tokens_init(struct cellman_tokens *);
void	cellman_tokens_free(struct cellman_tokens *);
int	cellman_tokens_set(struct cellman_tokens *, const char *, const char *,
	    char **);
const char *cellman_tokens_get(const struct cellman_tokens *, const char *);

int	cellman_dsl_load_file(const char *, struct cellman_doc *, char **);
int	cellman_dsl_load_file_all(const char *, struct cellman_doc_list *,
	    char **);

void	cellman_state_init(struct cellman_state *);
void	cellman_state_free(struct cellman_state *);
int	cellman_state_load_dir(const char *, struct cellman_state *, char **);

int	cellman_template_expand(const char *, const struct cellman_tokens *,
	    char **, char **);

int	cellman_apply_run_plan(const struct cellman_doc *,
	    const struct cellman_tokens *, bool, char **);

int	cellman_apply_run_named(const struct cellman_doc *,
	    const struct cellman_tokens *, const char *, const char *,
	    bool, bool, bool, char **);

int	cellman_volume_path(const char *, char **, char **);
int	cellman_volume_exists(const char *, bool *, char **);
int	cellman_volume_ensure(const char *, const char *, bool,
	    bool, bool, char **);
int	cellman_volume_remove_one(const char *, bool, bool, bool,
	    char **);
int	cellman_volume_remove_all(const struct cellman_state *, bool,
	    bool, bool, size_t *, char **);

int	cellman_backup_volume_create(const char *, char **);
int	cellman_backup_volume_query(const char *,
	    struct cellman_backup_record_list *, char **);
int	cellman_backup_volume_list(const char *, bool, bool, char **);
int	cellman_backup_volume_restore(const char *, const char *, bool, bool,
	    char **);
int	cellman_backup_volume_delete(const char *, const char *, bool, bool,
	    char **);

int	cellman_backup_cell_create(const char *, char **);
int	cellman_backup_cell_query(const char *,
	    struct cellman_backup_record_list *, char **);
int	cellman_backup_cell_list(const char *, bool, bool, char **);
int	cellman_backup_cell_restore(const char *, const char *, bool, bool,
	    char **);
int	cellman_backup_cell_delete(const char *, const char *, bool, bool,
	    char **);
void	cellman_backup_record_list_free(struct cellman_backup_record_list *);

int	cellman_exec_run(const char *const [], char **);
int	cellman_exec_run_capture(const char *const [], char **, char **);
bool	cellman_exec_command_exists(const char *);

int	cellman_mkdir_p(const char *, mode_t, char **);
bool	cellman_path_is_same_or_child(const char *, const char *);
int	cellman_is_path_mounted(const char *, bool *, char **);
int	cellman_read_optional_text_file(const char *, char **, char **);
int	cellman_write_text_file(const char *, const char *, char **);

char	*cellman_strdup(const char *, char **);
char	*cellman_strndup(const char *, size_t, char **);
char	*cellman_xasprintf(char **, const char *, ...)
	    __attribute__((__format__(__printf__, 2, 3)));
char	*cellman_dirname_dup(const char *, char **);
char	*cellman_path_join(const char *, const char *, char **);
bool	cellman_env_name_valid(const char *);

int	cellman_string_list_add(struct cellman_string_list *, const char *,
	    char **);
void	cellman_string_list_free(struct cellman_string_list *);

int	cellman_kv_list_add(struct cellman_kv_list *, const char *, const char *,
	    char **);
const char *cellman_kv_list_get(const struct cellman_kv_list *, const char *);
void	cellman_kv_list_free(struct cellman_kv_list *);

bool	cellman_split_kv(const char *, char **, char **, char **);
char	*cellman_release_major_minor(const char *, char **);
int	cellman_conf_get(const char *, char **, char **);

void	cellman_log_info(const char *, ...)
	    __attribute__((__format__(__printf__, 1, 2)));
void	cellman_log_warn(const char *, ...)
	    __attribute__((__format__(__printf__, 1, 2)));
void	cellman_log_error(const char *, ...)
	    __attribute__((__format__(__printf__, 1, 2)));
void	cellman_log_debug(bool, const char *, ...)
	    __attribute__((__format__(__printf__, 2, 3)));
int	cellman_payload_printf(const char *, ...)
	    __attribute__((__format__(__printf__, 1, 2)));

#endif /* CELLMAN_H */
