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
 * Layer: cellman control plane, apply action execution layer.
 *
 * This file is included by apply_exec.c and contains concrete handlers for
 * each DSL apply action kind (pkg/exec/dir/line/symlink/copy/untar/file/
 * patch/template/script).
 *
 * Put extensions here when adding new action kinds or changing behavior of
 * existing action handlers; keep runtime orchestration in apply_exec.c.
 */

static int
run_pkg_action(const struct cellman_action_pkg *pkg_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char **rendered;
	char **argv;
	char *pkg_env;
	char arg_cellctl[] = "cellctl";
	char arg_exec[] = "exec";
	char arg_env[] = "env";
	char arg_pkg_add[] = "pkg_add";
	size_t arg_base;
	size_t i;
	int rc;

	pkg_env = NULL;

	if (pkg_action == NULL || pkg_action->packages.len == 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "pkg action requires at least one package");
		return -1;
	}

	rendered = calloc(pkg_action->packages.len, sizeof(*rendered));
	if (rendered == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		return -1;
	}

	for (i = 0; i < pkg_action->packages.len; i++) {
		if (render_template_value(pkg_action->packages.items[i], tokens,
		    &rendered[i], err) != 0)
			goto fail;
	}

	if (runtime->dry_run) {
		if (runtime->verbose) {
			struct strbuf msg;

			if (!strbuf_init(&msg, err))
				goto fail;
			if (!strbuf_append(&msg, "dry-run pkg_add in cell ", err) ||
			    !strbuf_append(&msg, runtime->cell_name, err) ||
			    !strbuf_append(&msg, ":", err)) {
				strbuf_reset(&msg);
				goto fail;
			}
			for (i = 0; i < pkg_action->packages.len; i++) {
				if (!strbuf_append(&msg, " ", err) ||
				    !strbuf_append(&msg, rendered[i], err)) {
					strbuf_reset(&msg);
					goto fail;
				}
			}
			cellman_log_info("%s", msg.buf);
			strbuf_reset(&msg);
		}
		for (i = 0; i < pkg_action->packages.len; i++)
			free(rendered[i]);
		free(rendered);
		return 0;
	}

	pkg_env = cellman_xasprintf(NULL, "PKG_PATH=%s",
	    runtime->pkg_path != NULL ? runtime->pkg_path : "");
	if (pkg_env == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto fail;
	}

	argv = calloc(pkg_action->packages.len + 7, sizeof(*argv));
	if (argv == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		free(pkg_env);
		goto fail;
	}

	argv[0] = arg_cellctl;
	argv[1] = arg_exec;
	argv[2] = runtime->cell_name;
	argv[3] = arg_env;
	argv[4] = pkg_env;
	argv[5] = arg_pkg_add;
	arg_base = 6;
	for (i = 0; i < pkg_action->packages.len; i++)
		argv[i + arg_base] = rendered[i];
	argv[pkg_action->packages.len + arg_base] = NULL;

	if (runtime->verbose)
		cellman_log_info("pkg_add in cell %s (PKG_PATH=%s)",
		    runtime->cell_name, runtime->pkg_path != NULL ? runtime->pkg_path : "");

	rc = run_spawn_checked(argv, NULL, NULL, NULL, 0, 0, false,
	    runtime->forward_output, err);
	free(argv);
	free(pkg_env);
	for (i = 0; i < pkg_action->packages.len; i++)
		free(rendered[i]);
	free(rendered);
	return rc;

fail:
	free(pkg_env);
	for (i = 0; i < pkg_action->packages.len; i++)
		free(rendered[i]);
	free(rendered);
	return -1;
}

static int
run_exec_action(const struct cellman_action_exec *exec_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *rendered;
	int rc;

	rendered = NULL;
	if (render_template_value(exec_action->command, tokens, &rendered, err) != 0)
		return -1;

	if (runtime->dry_run) {
		if (runtime->verbose) {
			cellman_log_info("dry-run exec in cell %s: %s",
			    runtime->cell_name, rendered);
		}
		free(rendered);
		return 0;
	}

	rc = run_cell_shell_command(runtime, rendered, NULL, NULL, NULL, 0, 0,
	    false, err);
	free(rendered);
	return rc;
}

static int
run_dir_action(const struct cellman_action_dir *dir_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *path;
	char *mapped;
	char *mode;
	char *owner;
	char *group;

	path = NULL;
	mapped = NULL;
	mode = NULL;
	owner = NULL;
	group = NULL;

	if (render_template_value(dir_action->path, tokens, &path, err) != 0)
		goto fail;
	if (render_optional_value(dir_action->mode, tokens, &mode, err) != 0 ||
	    render_optional_value(dir_action->owner, tokens, &owner, err) != 0 ||
	    render_optional_value(dir_action->group, tokens, &group, err) != 0)
		goto fail;

	mapped = map_cell_path(runtime, path, err);
	if (mapped == NULL)
		goto fail;

	if (runtime->verbose)
		cellman_log_info("dir %s", mapped);

	if (!runtime->dry_run && mkdir_p(mapped, 0755, err) != 0)
		goto fail;

	if (apply_mode_owner_group(mapped, mode, owner, group, runtime, err) != 0)
		goto fail;

	free(path);
	free(mapped);
	free(mode);
	free(owner);
	free(group);
	return 0;

fail:
	free(path);
	free(mapped);
	free(mode);
	free(owner);
	free(group);
	return -1;
}

static int
run_line_action(const struct cellman_action_line *line_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *path;
	char *text;
	char *mapped;
	FILE *fp;
	char *line;
	size_t n;
	bool present;

	path = NULL;
	text = NULL;
	mapped = NULL;
	fp = NULL;
	line = NULL;
	n = 0;
	present = false;

	if (render_template_value(line_action->path, tokens, &path, err) != 0 ||
	    render_template_value(line_action->text, tokens, &text, err) != 0)
		goto fail;

	mapped = map_cell_path(runtime, path, err);
	if (mapped == NULL)
		goto fail;

	if (runtime->verbose)
		cellman_log_info("line %s", mapped);

	if (runtime->dry_run)
		goto done;

	if (ensure_parent_dir(mapped, err) != 0)
		goto fail;

	fp = fopen(mapped, "r");
	if (fp != NULL) {
		while (getline(&line, &n, fp) != -1) {
			char *cur;

			cur = trim_ws_inplace(line);
			if (strcmp(cur, text) == 0) {
				present = true;
				break;
			}
		}
		(void)fclose(fp);
		fp = NULL;
	}

	if (present)
		goto done;

	fp = fopen(mapped, "a");
	if (fp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "open %s failed: %s", mapped,
			    strerror(errno));
		goto fail;
	}
	if (fprintf(fp, "%s\n", text) < 0 || fclose(fp) != 0) {
		fp = NULL;
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "write %s failed: %s", mapped,
			    strerror(errno));
		goto fail;
	}
	fp = NULL;

done:
	free(path);
	free(text);
	free(mapped);
	free(line);
	return 0;

fail:
	if (fp != NULL)
		(void)fclose(fp);
	free(path);
	free(text);
	free(mapped);
	free(line);
	return -1;
}

static int
run_symlink_action(const struct cellman_action_symlink *symlink_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *target;
	char *linkpath;
	char *mapped;
	struct stat st;

	target = NULL;
	linkpath = NULL;
	mapped = NULL;

	if (render_template_value(symlink_action->target, tokens, &target, err) != 0 ||
	    render_template_value(symlink_action->linkpath, tokens, &linkpath,
	    err) != 0)
		goto fail;

	mapped = map_cell_path(runtime, linkpath, err);
	if (mapped == NULL)
		goto fail;

	if (runtime->verbose)
		cellman_log_info("symlink %s -> %s", mapped, target);

	if (runtime->dry_run)
		goto done;

	if (ensure_parent_dir(mapped, err) != 0)
		goto fail;

	if (lstat(mapped, &st) == 0 && unlink(mapped) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "unlink %s failed: %s", mapped,
			    strerror(errno));
		goto fail;
	}

	if (symlinkat(target, AT_FDCWD, mapped) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "symlink %s failed: %s", mapped,
			    strerror(errno));
		goto fail;
	}

done:
	free(target);
	free(linkpath);
	free(mapped);
	return 0;

fail:
	free(target);
	free(linkpath);
	free(mapped);
	return -1;
}

static int
run_copy_action(const struct cellman_doc *doc,
    const struct cellman_action_copy *copy_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *source;
	char *resolved_source;
	char *target;
	char *mapped_target;
	char *mode;
	char *owner;
	char *group;

	source = NULL;
	resolved_source = NULL;
	target = NULL;
	mapped_target = NULL;
	mode = NULL;
	owner = NULL;
	group = NULL;

	if (render_template_value(copy_action->source, tokens, &source, err) != 0 ||
	    render_template_value(copy_action->target, tokens, &target, err) != 0 ||
	    render_optional_value(copy_action->mode, tokens, &mode, err) != 0 ||
	    render_optional_value(copy_action->owner, tokens, &owner, err) != 0 ||
	    render_optional_value(copy_action->group, tokens, &group, err) != 0)
		goto fail;

	if (resolve_source_path(doc, source, &resolved_source, err) != 0)
		goto fail;
	if (access(resolved_source, R_OK) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "COPY source unreadable: %s (%s)",
			    resolved_source, strerror(errno));
		goto fail;
	}

	mapped_target = map_cell_path(runtime, target, err);
	if (mapped_target == NULL)
		goto fail;

	if (runtime->verbose)
		cellman_log_info("copy %s -> %s", resolved_source, mapped_target);

	if (!runtime->dry_run) {
		if (ensure_parent_dir(mapped_target, err) != 0)
			goto fail;
		if (copy_file(resolved_source, mapped_target, err) != 0)
			goto fail;
	}

	if (apply_mode_owner_group(mapped_target, mode, owner, group, runtime,
	    err) != 0)
		goto fail;

	free(source);
	free(resolved_source);
	free(target);
	free(mapped_target);
	free(mode);
	free(owner);
	free(group);
	return 0;

fail:
	free(source);
	free(resolved_source);
	free(target);
	free(mapped_target);
	free(mode);
	free(owner);
	free(group);
	return -1;
}

static int
run_untar_action(const struct cellman_doc *doc,
    const struct cellman_action_untar *untar_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *source;
	char *resolved_source;
	char *target;
	char *mapped_target;
	char strip_arg[32];
	char *argv_tar[7];
	char arg_tar[] = "tar";
	char arg_xf[] = "-xf";
	char arg_C[] = "-C";

	source = NULL;
	resolved_source = NULL;
	target = NULL;
	mapped_target = NULL;

	if (render_template_value(untar_action->source, tokens, &source, err) != 0 ||
	    render_template_value(untar_action->target, tokens, &target, err) != 0)
		goto fail;

	if (resolve_source_path(doc, source, &resolved_source, err) != 0)
		goto fail;
	if (access(resolved_source, R_OK) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "UNTAR source unreadable: %s (%s)",
			    resolved_source, strerror(errno));
		goto fail;
	}

	mapped_target = map_cell_path(runtime, target, err);
	if (mapped_target == NULL)
		goto fail;

	if (runtime->verbose)
		cellman_log_info("untar %s -> %s", resolved_source, mapped_target);

	if (!runtime->dry_run) {
		if (mkdir_p(mapped_target, 0755, err) != 0)
			goto fail;

		argv_tar[0] = arg_tar;
		argv_tar[1] = arg_xf;
		argv_tar[2] = resolved_source;
		argv_tar[3] = arg_C;
		argv_tar[4] = mapped_target;
		if (untar_action->strip_components == 0) {
			argv_tar[5] = NULL;
		} else {
			(void)snprintf(strip_arg, sizeof(strip_arg),
			    "--strip-components=%u", untar_action->strip_components);
			argv_tar[5] = strip_arg;
			argv_tar[6] = NULL;
		}

		if (run_spawn_checked(argv_tar, NULL, NULL, NULL, 0, 0, false,
		    runtime->forward_output, err) != 0)
			goto fail;
	}

	free(source);
	free(resolved_source);
	free(target);
	free(mapped_target);
	return 0;

fail:
	free(source);
	free(resolved_source);
	free(target);
	free(mapped_target);
	return -1;
}

static int
run_file_action(const struct cellman_action_file *file_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *path;
	char *content;
	char *mapped;
	char *mode;
	char *owner;
	char *group;
	FILE *fp;

	path = NULL;
	content = NULL;
	mapped = NULL;
	mode = NULL;
	owner = NULL;
	group = NULL;
	fp = NULL;

	if (render_template_value(file_action->path, tokens, &path, err) != 0 ||
	    render_template_value(file_action->content, tokens, &content, err) != 0 ||
	    render_optional_value(file_action->mode, tokens, &mode, err) != 0 ||
	    render_optional_value(file_action->owner, tokens, &owner, err) != 0 ||
	    render_optional_value(file_action->group, tokens, &group, err) != 0)
		goto fail;

	mapped = map_cell_path(runtime, path, err);
	if (mapped == NULL)
		goto fail;

	if (runtime->verbose)
		cellman_log_info("file %s", mapped);

	if (!runtime->dry_run) {
		if (ensure_parent_dir(mapped, err) != 0)
			goto fail;

		fp = fopen(mapped, "w");
		if (fp == NULL) {
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "open %s failed: %s", mapped,
				    strerror(errno));
			goto fail;
		}
		if (fwrite(content, 1, strlen(content), fp) != strlen(content) ||
		    fclose(fp) != 0) {
			fp = NULL;
			if (err != NULL)
				*err = cellman_xasprintf(NULL, "write %s failed: %s", mapped,
				    strerror(errno));
			goto fail;
		}
		fp = NULL;
	}

	if (apply_mode_owner_group(mapped, mode, owner, group, runtime, err) != 0)
		goto fail;

	free(path);
	free(content);
	free(mapped);
	free(mode);
	free(owner);
	free(group);
	return 0;

fail:
	if (fp != NULL)
		(void)fclose(fp);
	free(path);
	free(content);
	free(mapped);
	free(mode);
	free(owner);
	free(group);
	return -1;
}

static int
run_patch_action(const struct cellman_action_patch *patch_action,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *path;
	char *content;
	char *mapped;
	char strip_arg[32];
	char *argv_patch[5];
	char arg_patch[] = "patch";
	char arg_d[] = "-d";

	path = NULL;
	content = NULL;
	mapped = NULL;

	if (render_template_value(patch_action->path, tokens, &path, err) != 0 ||
	    render_template_value(patch_action->content, tokens, &content, err) != 0)
		goto fail;

	mapped = map_cell_path(runtime, path, err);
	if (mapped == NULL)
		goto fail;

	if (runtime->verbose)
		cellman_log_info("patch -p%u -d %s", patch_action->strip_components,
		    mapped);

	if (runtime->dry_run)
		goto done;

	(void)snprintf(strip_arg, sizeof(strip_arg), "-p%u",
	    patch_action->strip_components);
	argv_patch[0] = arg_patch;
	argv_patch[1] = strip_arg;
	argv_patch[2] = arg_d;
	argv_patch[3] = mapped;
	argv_patch[4] = NULL;

	if (run_spawn_checked(argv_patch, NULL, NULL, content, strlen(content), 0,
	    false, runtime->forward_output, err) != 0)
		goto fail;

done:
	free(path);
	free(content);
	free(mapped);
	return 0;

fail:
	free(path);
	free(content);
	free(mapped);
	return -1;
}

static int
run_template_action(const struct cellman_doc *doc,
    const struct cellman_action_template *templ,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	struct cellman_tokens merged_tokens;
	char *rendered_source;
	char *resolved_source;
	char *raw_content;
	char *rendered_content;
	char *rendered_target;
	char *mapped_target;
	char *rendered_mode;
	char *rendered_owner;
	char *rendered_group;
	FILE *fp;

	rendered_source = NULL;
	resolved_source = NULL;
	raw_content = NULL;
	rendered_content = NULL;
	rendered_target = NULL;
	mapped_target = NULL;
	rendered_mode = NULL;
	rendered_owner = NULL;
	rendered_group = NULL;
	fp = NULL;
	cellman_tokens_init(&merged_tokens);

	if (tokens_clone(&merged_tokens, tokens, err) != 0)
		goto fail;
	if (tokens_merge_map(&merged_tokens, &templ->tokens, err) != 0)
		goto fail;
	if (tokens_merge_text(&merged_tokens, templ->tokens_text, err) != 0)
		goto fail;
	if (tokens_merge_env_map(&merged_tokens, &templ->token_env, err) != 0)
		goto fail;

	if (render_template_value(templ->source, &merged_tokens, &rendered_source,
	    err) != 0)
		goto fail;
	if (resolve_source_path(doc, rendered_source, &resolved_source, err) != 0)
		goto fail;

	if (access(resolved_source, R_OK) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "template source is not readable: %s (%s)", resolved_source,
			    strerror(errno));
		goto fail;
	}

	if (read_text_file(resolved_source, &raw_content, err) != 0)
		goto fail;

	if (render_template_value(raw_content, &merged_tokens, &rendered_content,
	    err) != 0)
		goto fail;
	if (render_template_value(templ->target, &merged_tokens, &rendered_target,
	    err) != 0)
		goto fail;

	if (render_optional_value(templ->mode, &merged_tokens, &rendered_mode,
	    err) != 0 ||
	    render_optional_value(templ->owner, &merged_tokens, &rendered_owner,
	    err) != 0 ||
	    render_optional_value(templ->group, &merged_tokens, &rendered_group,
	    err) != 0)
		goto fail;

	mapped_target = map_cell_path(runtime, rendered_target, err);
	if (mapped_target == NULL)
		goto fail;

	if (runtime->dry_run) {
		if (runtime->verbose) {
			cellman_log_info("dry-run template: %s -> %s", resolved_source,
			    mapped_target);
		}
		goto done;
	}

	if (runtime->verbose)
		cellman_log_info("template: %s -> %s", resolved_source, mapped_target);

	if (ensure_parent_dir(mapped_target, err) != 0)
		goto fail;

	fp = fopen(mapped_target, "w");
	if (fp == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "cannot write %s: %s", mapped_target,
			    strerror(errno));
		goto fail;
	}

	if (fputs(rendered_content, fp) == EOF || fclose(fp) != 0) {
		fp = NULL;
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "failed writing %s: %s",
			    mapped_target, strerror(errno));
		goto fail;
	}
	fp = NULL;

	if (apply_mode_owner_group(mapped_target, rendered_mode, rendered_owner,
	    rendered_group, runtime, err) != 0)
		goto fail;

done:
	free(rendered_source);
	free(resolved_source);
	free(raw_content);
	free(rendered_content);
	free(rendered_target);
	free(mapped_target);
	free(rendered_mode);
	free(rendered_owner);
	free(rendered_group);
	cellman_tokens_free(&merged_tokens);
	return 0;

fail:
	if (fp != NULL)
		(void)fclose(fp);
	free(rendered_source);
	free(resolved_source);
	free(raw_content);
	free(rendered_content);
	free(rendered_target);
	free(mapped_target);
	free(rendered_mode);
	free(rendered_owner);
	free(rendered_group);
	cellman_tokens_free(&merged_tokens);
	return -1;
}

static int
run_script_action(const struct cellman_doc *doc,
    const struct cellman_action_script *script,
    const struct cellman_tokens *tokens, const struct apply_runtime *runtime,
    char **err)
{
	char *rendered_path;
	char *resolved_path;
	char *script_content;
	char *rendered_cwd;
	char **rendered_args;
	struct cellman_kv_list rendered_env;
	size_t i;
	int rc;

	rendered_path = NULL;
	resolved_path = NULL;
	script_content = NULL;
	rendered_cwd = NULL;
	rendered_args = NULL;
	memset(&rendered_env, 0, sizeof(rendered_env));
	rc = -1;

	if (render_template_value(script->path, tokens, &rendered_path, err) != 0)
		goto done;
	if (resolve_source_path(doc, rendered_path, &resolved_path, err) != 0)
		goto done;

	if (access(resolved_path, R_OK) != 0) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL,
			    "script is not readable: %s (%s)", resolved_path,
			    strerror(errno));
		goto done;
	}

	if (render_optional_value(script->cwd, tokens, &rendered_cwd, err) != 0)
		goto done;

	rendered_args = calloc(script->args.len, sizeof(*rendered_args));
	if (script->args.len > 0 && rendered_args == NULL) {
		if (err != NULL)
			*err = cellman_xasprintf(NULL, "out of memory");
		goto done;
	}

	for (i = 0; i < script->args.len; i++) {
		if (render_template_value(script->args.items[i], tokens,
		    &rendered_args[i], err) != 0)
			goto done;
	}

	for (i = 0; i < script->env.len; i++) {
		char *rendered_value;

		rendered_value = NULL;
		if (render_template_value(script->env.items[i].value, tokens,
		    &rendered_value, err) != 0)
			goto done;

		if (cellman_kv_list_add(&rendered_env, script->env.items[i].key,
		    rendered_value, err) != 0) {
			free(rendered_value);
			goto done;
		}
		free(rendered_value);
	}

	if (runtime->dry_run) {
		if (runtime->verbose)
			cellman_log_info("dry-run script: %s", resolved_path);
		rc = 0;
		goto done;
	}

	{
		struct strbuf cmd;

		/*
		 * Execute script content via stdin inside the target cell. This avoids
		 * staging temporary helper files and keeps the runtime path direct.
		 */
		if (read_text_file(resolved_path, &script_content, err) != 0)
			goto done;
		if (!strbuf_init(&cmd, err))
			goto done;

		if (!strbuf_append(&cmd, "/bin/sh -s --", err)) {
			strbuf_reset(&cmd);
			goto done;
		}
		for (i = 0; i < script->args.len; i++) {
			char *qarg;

			qarg = shell_quote(rendered_args[i], err);
			if (qarg == NULL ||
			    !strbuf_append(&cmd, " ", err) ||
			    !strbuf_append(&cmd, qarg, err)) {
				free(qarg);
				strbuf_reset(&cmd);
				goto done;
			}
			free(qarg);
		}

		if (runtime->verbose)
			cellman_log_info("cell script: %s", resolved_path);

		rc = run_cell_shell_command(runtime, cmd.buf, rendered_cwd,
		    &rendered_env, script_content, strlen(script_content),
		    script->timeout_seconds, script->ignore_exit, err);
		strbuf_reset(&cmd);
		goto done;
	}

done:
	free(rendered_path);
	free(resolved_path);
	free(script_content);
	free(rendered_cwd);
	if (rendered_args != NULL) {
		for (i = 0; i < script->args.len; i++)
			free(rendered_args[i]);
	}
	free(rendered_args);
	cellman_kv_list_free(&rendered_env);
	return rc;
}
