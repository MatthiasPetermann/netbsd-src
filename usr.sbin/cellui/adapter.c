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

#define _POSIX_C_SOURCE 200809L

#include "cellui.h"

#include "../cellman/cellman_api.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  CellRow *items;
  size_t len;
  size_t cap;
} RowVec;

typedef struct {
  VolumeRow *items;
  size_t len;
  size_t cap;
} VolumeVec;

typedef struct {
  BackupRow *items;
  size_t len;
  size_t cap;
} BackupVec;

static void rowvec_init(RowVec *v) {
  v->items = NULL;
  v->len = 0;
  v->cap = 0;
}

static CellRow *rowvec_push(RowVec *v) {
  CellRow *row;

  if (v->len == v->cap) {
    size_t next_cap = (v->cap == 0) ? 16 : v->cap * 2;
    CellRow *next_items = realloc(v->items, next_cap * sizeof(*next_items));
    if (next_items == NULL) {
      perror("realloc");
      exit(1);
    }
    v->items = next_items;
    v->cap = next_cap;
  }
  row = &v->items[v->len++];
  memset(row, 0, sizeof(*row));
  return row;
}

static void volumevec_init(VolumeVec *v) {
  v->items = NULL;
  v->len = 0;
  v->cap = 0;
}

static VolumeRow *volumevec_push(VolumeVec *v) {
  VolumeRow *row;

  if (v->len == v->cap) {
    size_t next_cap = (v->cap == 0) ? 16 : v->cap * 2;
    VolumeRow *next_items = realloc(v->items, next_cap * sizeof(*next_items));
    if (next_items == NULL) {
      perror("realloc");
      exit(1);
    }
    v->items = next_items;
    v->cap = next_cap;
  }
  row = &v->items[v->len++];
  memset(row, 0, sizeof(*row));
  return row;
}

static void backupvec_init(BackupVec *v) {
  v->items = NULL;
  v->len = 0;
  v->cap = 0;
}

static BackupRow *backupvec_push(BackupVec *v) {
  BackupRow *row;

  if (v->len == v->cap) {
    size_t next_cap = (v->cap == 0) ? 16 : v->cap * 2;
    BackupRow *next_items = realloc(v->items, next_cap * sizeof(*next_items));
    if (next_items == NULL) {
      perror("realloc");
      exit(1);
    }
    v->items = next_items;
    v->cap = next_cap;
  }
  row = &v->items[v->len++];
  memset(row, 0, sizeof(*row));
  return row;
}

static int cmp_rows_by_name(const void *a, const void *b) {
  const CellRow *ra = a;
  const CellRow *rb = b;
  return strcmp(blank_if(ra->name, ""), blank_if(rb->name, ""));
}

static int cmp_volume_rows_by_name(const void *a, const void *b) {
  const VolumeRow *ra = a;
  const VolumeRow *rb = b;
  int by_kind = strcmp(blank_if(ra->kind, ""), blank_if(rb->kind, ""));
  if (by_kind != 0) {
    return by_kind;
  }
  return strcmp(blank_if(ra->name, ""), blank_if(rb->name, ""));
}

static int api_result_to_status(int rc, struct cellman_api_result *result,
                                char **err_out) {
  *err_out = NULL;
  if (rc != 0) {
    *err_out = xstrdup(blank_if(result->error, "command failed"));
    return 1;
  }
  return 0;
}

static enum cellman_api_storage_kind parse_storage_kind(const char *storage_kind) {
  if (strcmp(blank_if(storage_kind, ""), "overlay") == 0) {
    return CELLMAN_API_STORAGE_OVERLAY;
  }
  return CELLMAN_API_STORAGE_VOLUME;
}

int api_cell_start(const char *name, bool all, char **err_out) {
  struct cellman_api_options options;
  struct cellman_api_result result;
  int rc;

  options.dsl_dir = NULL;
  cellman_api_result_init(&result);
  rc = cellman_api_cell_start(&options, name, all, &result);
  rc = api_result_to_status(rc, &result, err_out);
  cellman_api_result_reset(&result);
  return rc;
}

int api_cell_stop(const char *name, bool all, char **err_out) {
  struct cellman_api_options options;
  struct cellman_api_result result;
  int rc;

  options.dsl_dir = NULL;
  cellman_api_result_init(&result);
  rc = cellman_api_cell_stop(&options, name, all, &result);
  rc = api_result_to_status(rc, &result, err_out);
  cellman_api_result_reset(&result);
  return rc;
}

int api_cell_restart(const char *name, bool all, char **err_out) {
  struct cellman_api_options options;
  struct cellman_api_result result;
  int rc;

  options.dsl_dir = NULL;
  cellman_api_result_init(&result);
  rc = cellman_api_cell_restart(&options, name, all, &result);
  rc = api_result_to_status(rc, &result, err_out);
  cellman_api_result_reset(&result);
  return rc;
}

int api_apply_all(char **err_out) {
  struct cellman_api_options options;
  struct cellman_api_result result;
  int rc;

  options.dsl_dir = NULL;
  cellman_api_result_init(&result);
  rc = cellman_api_apply_all(&options, &result);
  rc = api_result_to_status(rc, &result, err_out);
  cellman_api_result_reset(&result);
  return rc;
}

int api_cell_shell(const char *name, char **err_out) {
  struct cellman_api_options options;
  struct cellman_api_result result;
  int rc;

  options.dsl_dir = NULL;
  cellman_api_result_init(&result);
  rc = cellman_api_cell_shell(&options, name, &result);
  rc = api_result_to_status(rc, &result, err_out);
  cellman_api_result_reset(&result);
  return rc;
}

int api_backup_create(const char *storage_kind, const char *name, char **err_out) {
  struct cellman_api_options options;
  struct cellman_api_result result;
  int rc;

  options.dsl_dir = NULL;
  cellman_api_result_init(&result);
  rc = cellman_api_backup_create(parse_storage_kind(storage_kind), name,
                                 &options, &result);
  rc = api_result_to_status(rc, &result, err_out);
  cellman_api_result_reset(&result);
  return rc;
}

int api_backup_restore(const char *storage_kind, const char *name,
                      const char *archive, char **err_out) {
  struct cellman_api_options options;
  struct cellman_api_result result;
  int rc;

  options.dsl_dir = NULL;
  cellman_api_result_init(&result);
  rc = cellman_api_backup_restore(parse_storage_kind(storage_kind), name,
                                  archive, false, true, &options, &result);
  rc = api_result_to_status(rc, &result, err_out);
  cellman_api_result_reset(&result);
  return rc;
}

int api_backup_delete(const char *storage_kind, const char *name,
                     const char *archive, char **err_out) {
  struct cellman_api_options options;
  struct cellman_api_result result;
  int rc;

  options.dsl_dir = NULL;
  cellman_api_result_init(&result);
  rc = cellman_api_backup_delete(parse_storage_kind(storage_kind), name,
                                 archive, false, true, &options, &result);
  rc = api_result_to_status(rc, &result, err_out);
  cellman_api_result_reset(&result);
  return rc;
}

int load_rows(CellRow **rows_out, size_t *count_out, char **err_out) {
  RowVec out;
  struct cellman_api_cell_list snapshot;

  *rows_out = NULL;
  *count_out = 0;
  *err_out = NULL;
  rowvec_init(&out);
  memset(&snapshot, 0, sizeof(snapshot));

  if (cellman_api_read_cells_merged(NULL, &snapshot, err_out) != 0) {
    char *wrapped = xasprintf("cellman cell read failed: %s",
                              blank_if(*err_out, "command failed"));
    free(*err_out);
    *err_out = wrapped;
    cellman_api_cell_list_free(&snapshot);
    return -1;
  }

  for (size_t i = 0; i < snapshot.len; i++) {
    const struct cellman_api_cell_row *src = &snapshot.items[i];
    CellRow *row;

    row = rowvec_push(&out);
    set_string(&row->name, src->name);
    set_string(&row->state, src->state);
    set_string(&row->cid, src->cid);
    set_string(&row->refs, src->refs);
    set_string(&row->procs, src->procs);
    set_string(&row->root, src->root);
    set_string(&row->autostart, is_blank(src->autostart) ? "NO" : src->autostart);
    set_string(&row->create_profile, src->profile);
    set_string(&row->create_reserved_ports, src->reserved_ports);
    set_string(&row->create_rlimit_nofile, src->rlimit_nofile);
    set_string(&row->create_rlimit_as, src->rlimit_as);
    set_string(&row->create_rlimit_core, src->rlimit_core);
    set_string(&row->supervise_cmd, src->supervise_cmd);
    set_string(&row->cpu1s, src->cpu1s);
    set_string(&row->cpu10s, src->cpu10s);
    set_string(&row->memory, src->memory);
    set_string(&row->age, src->age);
    row->running = src->running;
    row->manifest_present = src->manifest_present;
  }

  if (out.len > 1) {
    qsort(out.items, out.len, sizeof(out.items[0]), cmp_rows_by_name);
  }

  *rows_out = out.items;
  *count_out = out.len;
  cellman_api_cell_list_free(&snapshot);
  return 0;
}

int load_volume_rows(VolumeRow **rows_out, size_t *count_out, char **err_out) {
  VolumeVec out;
  struct cellman_api_storage_list snapshot;

  *rows_out = NULL;
  *count_out = 0;
  *err_out = NULL;
  volumevec_init(&out);
  memset(&snapshot, 0, sizeof(snapshot));

  if (cellman_api_read_storage_merged(NULL, &snapshot, err_out) != 0) {
    char *wrapped = xasprintf("cellman storage read failed: %s",
                              blank_if(*err_out, "command failed"));
    free(*err_out);
    *err_out = wrapped;
    cellman_api_storage_list_free(&snapshot);
    return -1;
  }

  for (size_t i = 0; i < snapshot.len; i++) {
    const struct cellman_api_storage_row *src = &snapshot.items[i];
    VolumeRow *row;

    row = volumevec_push(&out);
    set_string(&row->kind,
               src->kind == CELLMAN_API_STORAGE_OVERLAY ? "overlay" : "volume");
    set_string(&row->name, src->name);
    set_string(&row->state, src->state);
    row->manifest_present = src->manifest_present;
    row->runtime_present = src->runtime_present;
    row->mounted = src->mounted;
    set_string(&row->refs, src->refs);
    set_string(&row->mode, src->mode);
    set_string(&row->path, src->path);
    set_string(&row->used_by, src->used_by);
  }

  if (out.len > 1) {
    qsort(out.items, out.len, sizeof(out.items[0]), cmp_volume_rows_by_name);
  }

  *rows_out = out.items;
  *count_out = out.len;
  cellman_api_storage_list_free(&snapshot);
  return 0;
}

int load_storage_backups(const char *storage_kind, const char *storage_name,
                         BackupRow **rows_out, size_t *count_out,
                         char **err_out) {
  BackupVec out;
  struct cellman_api_backup_list snapshot;
  enum cellman_api_storage_kind kind;

  *rows_out = NULL;
  *count_out = 0;
  *err_out = NULL;
  backupvec_init(&out);
  memset(&snapshot, 0, sizeof(snapshot));

  if (strcmp(blank_if(storage_kind, ""), "overlay") == 0) {
    kind = CELLMAN_API_STORAGE_OVERLAY;
  } else {
    kind = CELLMAN_API_STORAGE_VOLUME;
  }

  if (cellman_api_read_backups(kind, storage_name, &snapshot, err_out) != 0) {
    char *wrapped = xasprintf("cellman %s backup read failed: %s",
                              blank_if(storage_kind, "storage"),
                              blank_if(*err_out, "command failed"));
    free(*err_out);
    *err_out = wrapped;
    cellman_api_backup_list_free(&snapshot);
    return -1;
  }

  for (size_t i = 0; i < snapshot.len; i++) {
    const struct cellman_api_backup_row *src = &snapshot.items[i];
    BackupRow *row;

    row = backupvec_push(&out);
    set_string(&row->volume, src->name);
    set_string(&row->timestamp, src->timestamp);
    set_string(&row->size, src->size);
    set_string(&row->archive, src->archive);
  }

  *rows_out = out.items;
  *count_out = out.len;
  cellman_api_backup_list_free(&snapshot);
  return 0;
}
