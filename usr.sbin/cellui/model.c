#include "cellui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

bool has_color = false;
Model *spinner_model = NULL;

static void sync_bridge_disconnect_state(Model *m) {
  if (command_bridge_is_disconnected()) {
    m->disconnected = true;
    (void)snprintf(m->disconnect_reason, sizeof(m->disconnect_reason), "%s",
                   command_bridge_disconnect_reason());
    return;
  }

  m->disconnected = false;
  m->disconnect_reason[0] = '\0';
}

void free_cell_row(CellRow *row) {
  if (row == NULL) {
    return;
  }
  free(row->name);
  free(row->cid);
  free(row->refs);
  free(row->procs);
  free(row->root);
  free(row->autostart);
  free(row->create_profile);
  free(row->create_reserved_ports);
  free(row->create_rlimit_nofile);
  free(row->create_rlimit_as);
  free(row->create_rlimit_core);
  free(row->supervise_cmd);
  free(row->cpu1s);
  free(row->cpu10s);
  free(row->memory);
  free(row->age);
  memset(row, 0, sizeof(*row));
}

void clear_model_rows(Model *m) {
  size_t i;

  if (m->rows == NULL) {
    m->row_count = 0;
    return;
  }
  for (i = 0; i < m->row_count; i++) {
    free_cell_row(&m->rows[i]);
  }
  free(m->rows);
  m->rows = NULL;
  m->row_count = 0;
}

void free_volume_row(VolumeRow *row) {
  if (row == NULL) {
    return;
  }
  free(row->kind);
  free(row->name);
  free(row->refs);
  free(row->mode);
  free(row->path);
  free(row->used_by);
  memset(row, 0, sizeof(*row));
}

void clear_model_volume_rows(Model *m) {
  size_t i;

  if (m->volume_rows == NULL) {
    m->volume_row_count = 0;
    return;
  }
  for (i = 0; i < m->volume_row_count; i++) {
    free_volume_row(&m->volume_rows[i]);
  }
  free(m->volume_rows);
  m->volume_rows = NULL;
  m->volume_row_count = 0;
}

void free_backup_row(BackupRow *row) {
  if (row == NULL) {
    return;
  }
  free(row->volume);
  free(row->timestamp);
  free(row->size);
  free(row->archive);
  memset(row, 0, sizeof(*row));
}

void clear_model_backups(Model *m) {
  size_t i;

  if (m->backup_rows != NULL) {
    for (i = 0; i < m->backup_row_count; i++) {
      free_backup_row(&m->backup_rows[i]);
    }
    free(m->backup_rows);
  }
  m->backup_rows = NULL;
  m->backup_row_count = 0;
  m->backup_cursor = 0;
  free(m->backup_target_key);
  m->backup_target_key = NULL;
}

void set_status(Model *m, bool is_error, const char *fmt, ...) {
  va_list ap;
  time_t now = time(NULL);

  m->status_is_error = is_error;
  if (is_error) {
    m->status_error_sticky_until = now + STATUS_ERROR_STICKY_SEC;
  } else {
    m->status_error_sticky_until = 0;
  }
  va_start(ap, fmt);
  (void)vsnprintf(m->status, sizeof(m->status), fmt, ap);
  va_end(ap);
}

static bool status_error_sticky_active(const Model *m, time_t now) {
  return m->status_is_error && m->status_error_sticky_until > now;
}

void append_status_output(Model *m, const char *output) {
  char *trimmed;
  char short_out[MAX_STATUS_OUTPUT_CHARS + 1];

  if (is_blank(output)) {
    return;
  }

  trimmed = xstrdup(output);
  {
    char *t = trim_inplace(trimmed);
    if (t != trimmed) {
      memmove(trimmed, t, strlen(t) + 1);
    }
  }
  if (is_blank(trimmed)) {
    free(trimmed);
    return;
  }

  if ((int)strlen(trimmed) > MAX_STATUS_OUTPUT_CHARS) {
    if (MAX_STATUS_OUTPUT_CHARS > 3) {
      memcpy(short_out, trimmed, (size_t)MAX_STATUS_OUTPUT_CHARS - 3);
      strcpy(short_out + MAX_STATUS_OUTPUT_CHARS - 3, "...");
    } else {
      memcpy(short_out, trimmed, (size_t)MAX_STATUS_OUTPUT_CHARS);
      short_out[MAX_STATUS_OUTPUT_CHARS] = '\0';
    }
  } else {
    (void)snprintf(short_out, sizeof(short_out), "%s", trimmed);
  }

  if (strlen(m->status) + 3 + strlen(short_out) < sizeof(m->status)) {
    (void)strcat(m->status, " | ");
    (void)strcat(m->status, short_out);
  }
  free(trimmed);
}

const char *filter_label(FilterMode mode) {
  switch (mode) {
  case FILTER_RUNNING:
    return "running";
  case FILTER_STOPPED:
    return "stopped";
  default:
    return "all";
  }
}

const char *mode_label(UIMode mode) {
  switch (mode) {
  case MODE_STORAGE:
    return "storage";
  default:
    return "cells";
  }
}

static bool row_visible(const Model *m, const CellRow *row) {
  if (m->filter == FILTER_ALL) {
    return true;
  }
  if (m->filter == FILTER_RUNNING) {
    return row->running;
  }
  return !row->running;
}

static size_t collect_visible_indices(const Model *m, size_t **indices_out) {
  size_t *indices;
  size_t n = 0;

  indices = malloc((m->row_count == 0 ? 1 : m->row_count) * sizeof(*indices));
  if (indices == NULL) {
    *indices_out = NULL;
    return 0;
  }

  for (size_t i = 0; i < m->row_count; i++) {
    if (row_visible(m, &m->rows[i])) {
      indices[n++] = i;
    }
  }

  *indices_out = indices;
  return n;
}

void clamp_cursor(Model *m) {
  size_t *vis = NULL;
  size_t count = collect_visible_indices(m, &vis);

  if (count == 0) {
    m->cursor = 0;
    free(vis);
    return;
  }
  if (m->cursor < 0) {
    m->cursor = 0;
  }
  if ((size_t)m->cursor >= count) {
    m->cursor = (int)count - 1;
  }
  free(vis);
}

CellRow *selected_cell(Model *m) {
  size_t *vis = NULL;
  size_t count = collect_visible_indices(m, &vis);
  CellRow *row = NULL;

  if (count > 0 && m->cursor >= 0 && (size_t)m->cursor < count) {
    row = &m->rows[vis[m->cursor]];
  }
  free(vis);
  return row;
}

void clamp_volume_cursor(Model *m) {
  if (m->volume_row_count == 0) {
    m->volume_cursor = 0;
    return;
  }
  if (m->volume_cursor < 0) {
    m->volume_cursor = 0;
  }
  if ((size_t)m->volume_cursor >= m->volume_row_count) {
    m->volume_cursor = (int)m->volume_row_count - 1;
  }
}

VolumeRow *selected_volume(Model *m) {
  if (m->volume_row_count == 0 || m->volume_rows == NULL) {
    return NULL;
  }
  clamp_volume_cursor(m);
  return &m->volume_rows[m->volume_cursor];
}

void clamp_backup_cursor(Model *m) {
  if (m->backup_row_count == 0) {
    m->backup_cursor = 0;
    return;
  }
  if (m->backup_cursor < 0) {
    m->backup_cursor = 0;
  }
  if ((size_t)m->backup_cursor >= m->backup_row_count) {
    m->backup_cursor = (int)m->backup_row_count - 1;
  }
}

BackupRow *selected_backup(Model *m) {
  if (m->backup_row_count == 0 || m->backup_rows == NULL) {
    return NULL;
  }
  clamp_backup_cursor(m);
  return &m->backup_rows[m->backup_cursor];
}

int table_body_height(const Model *m, int term_h) {
  int fixed = 1 + DETAIL_PANEL_LINES + 1 + HELP_LINES_COUNT;
  int avail;
  int rows;

  avail = term_h - fixed;
  if (avail < 4) {
    avail = 4;
  }

  rows = avail - 2 - 1;
  if (rows < MIN_TABLE_BODY_HEIGHT) {
    rows = MIN_TABLE_BODY_HEIGHT;
  }
  return rows;
}

int running_count(const Model *m) {
  int count = 0;

  for (size_t i = 0; i < m->row_count; i++) {
    if (m->rows[i].running) {
      count++;
    }
  }
  return count;
}

int missing_manifest_count(const Model *m) {
  int count = 0;

  for (size_t i = 0; i < m->row_count; i++) {
    if (!m->rows[i].manifest_present) {
      count++;
    }
  }
  return count;
}

int runtime_volume_count(const Model *m) {
  int count = 0;

  for (size_t i = 0; i < m->volume_row_count; i++) {
    if (strcmp(blank_if(m->volume_rows[i].kind, ""), "volume") == 0 &&
        m->volume_rows[i].runtime_present) {
      count++;
    }
  }
  return count;
}

int mounted_volume_count(const Model *m) {
  int count = 0;

  for (size_t i = 0; i < m->volume_row_count; i++) {
    if (strcmp(blank_if(m->volume_rows[i].kind, ""), "volume") == 0 &&
        m->volume_rows[i].mounted) {
      count++;
    }
  }
  return count;
}

int storage_kind_count(const Model *m, const char *kind) {
  int count = 0;

  for (size_t i = 0; i < m->volume_row_count; i++) {
    if (strcmp(blank_if(m->volume_rows[i].kind, ""), blank_if(kind, "")) == 0) {
      count++;
    }
  }
  return count;
}

int storage_backup_eligible_count(const Model *m) {
  int count = 0;

  for (size_t i = 0; i < m->volume_row_count; i++) {
    if (!m->volume_rows[i].runtime_present || m->volume_rows[i].mounted) {
      continue;
    }
    count++;
  }
  return count;
}

static void model_set_rows(Model *m, CellRow *rows, size_t count) {
  clear_model_rows(m);
  m->rows = rows;
  m->row_count = count;
  clamp_cursor(m);
}

static void model_set_volume_rows(Model *m, VolumeRow *rows, size_t count) {
  clear_model_volume_rows(m);
  m->volume_rows = rows;
  m->volume_row_count = count;
  clamp_volume_cursor(m);
}

void clear_confirmation(Model *m) {
  m->confirm_open = false;
  m->confirm_action = CONFIRM_NONE;
  free(m->confirm_storage_kind);
  m->confirm_storage_kind = NULL;
  free(m->confirm_storage_name);
  m->confirm_storage_name = NULL;
  free(m->confirm_archive_path);
  m->confirm_archive_path = NULL;
}

void start_confirmation(Model *m, ConfirmAction action, const char *storage_kind,
                        const char *storage_name,
                        const char *archive_path) {
  clear_confirmation(m);
  m->confirm_open = true;
  m->confirm_action = action;
  m->confirm_storage_kind = xstrdup(blank_if(storage_kind, ""));
  m->confirm_storage_name = xstrdup(blank_if(storage_name, ""));
  m->confirm_archive_path = xstrdup(blank_if(archive_path, ""));
}

void sync_volume_backups(Model *m, bool force) {
  VolumeRow *row;
  char *target_key = NULL;
  char *err = NULL;
  BackupRow *rows = NULL;
  size_t count = 0;

  if (m->mode != MODE_STORAGE) {
    clear_confirmation(m);
    clear_model_backups(m);
    return;
  }

  row = selected_volume(m);
  if (row == NULL || is_blank(row->name)) {
    clear_confirmation(m);
    clear_model_backups(m);
    return;
  }

  target_key = xasprintf("%s:%s", blank_if(row->kind, ""),
                         blank_if(row->name, ""));
  if (!force && m->backup_target_key != NULL &&
      strcmp(m->backup_target_key, target_key) == 0) {
    free(target_key);
    return;
  }

  clear_confirmation(m);
  clear_model_backups(m);
  if (load_storage_backups(row->kind, row->name, &rows, &count, &err) != 0) {
    sync_bridge_disconnect_state(m);
    set_status(m, true, "%s", blank_if(err, "backup list failed"));
    free(err);
    m->backup_target_key = target_key;
    return;
  }
  sync_bridge_disconnect_state(m);
  free(err);

  m->backup_rows = rows;
  m->backup_row_count = count;
  m->backup_cursor = 0;
  m->backup_target_key = target_key;
  clamp_backup_cursor(m);
}

void model_refresh(Model *m) {
  CellRow *cell_rows = NULL;
  VolumeRow *volume_rows = NULL;
  size_t count = 0;
  char *err = NULL;
  time_t now = time(NULL);
  Model *prev_spinner_model = spinner_model;

  spinner_model = m;

  if (m->mode == MODE_CELLS) {
    if (load_rows(&cell_rows, &count, &err) != 0) {
      sync_bridge_disconnect_state(m);
      spinner_model = prev_spinner_model;
      set_status(m, true, "%s", blank_if(err, "refresh failed"));
      free(err);
      m->loading = false;
      m->last_refresh = now;
      m->next_refresh_due = now + REFRESH_EVERY_SEC;
      return;
    }
  } else {
    if (load_volume_rows(&volume_rows, &count, &err) != 0) {
      sync_bridge_disconnect_state(m);
      spinner_model = prev_spinner_model;
      set_status(m, true, "%s", blank_if(err, "refresh failed"));
      free(err);
      m->loading = false;
      m->last_refresh = now;
      m->next_refresh_due = now + REFRESH_EVERY_SEC;
      return;
    }
  }

  spinner_model = prev_spinner_model;
  sync_bridge_disconnect_state(m);

  if (m->mode == MODE_CELLS) {
    model_set_rows(m, cell_rows, count);
  } else {
    model_set_volume_rows(m, volume_rows, count);
    sync_volume_backups(m, true);
  }

  if (err != NULL) {
    set_status(m, true, "%s", err);
  } else {
    if (!status_error_sticky_active(m, now)) {
      struct tm *tmv = localtime(&now);
      if (tmv != NULL) {
        set_status(m, false, "updated %02d:%02d:%02d", tmv->tm_hour,
                   tmv->tm_min, tmv->tm_sec);
      } else {
        set_status(m, false, "updated --:--:--");
      }
    }
  }
  free(err);
  m->loading = false;
  m->last_refresh = now;
  m->next_refresh_due = now + REFRESH_EVERY_SEC;
}

void run_capture_action(Model *m, const char *title, bool refresh_after,
                        const char *const argv[]) {
  char *out = NULL;
  char *err = NULL;
  Model *prev_spinner_model = spinner_model;

  m->loading = true;
  draw_ui(m);
  spinner_model = m;

  if (run_capture_command(argv[0], argv, &out, &err) != 0) {
    sync_bridge_disconnect_state(m);
    set_status(m, true, "%s failed: %s", title,
               blank_if(err, "command failed"));
  } else {
    sync_bridge_disconnect_state(m);
    set_status(m, false, "%s done", title);
  }
  spinner_model = prev_spinner_model;
  free(out);
  free(err);

  m->loading = false;
  if (refresh_after) {
    m->loading = true;
    draw_ui(m);
    model_refresh(m);
  }
}

void run_interactive_action(Model *m, const char *title, bool refresh_after,
                            const char *const argv[], const char *env_key,
                            const char *env_val) {
  char *err = NULL;

  m->loading = true;
  draw_ui(m);

  if (run_interactive_command(argv[0], argv, env_key, env_val, &err) != 0) {
    sync_bridge_disconnect_state(m);
    set_status(m, true, "%s exited with error: %s", title,
               blank_if(err, "command failed"));
  } else {
    sync_bridge_disconnect_state(m);
    set_status(m, false, "%s exited", title);
  }
  free(err);

  m->loading = false;
  if (refresh_after) {
    m->loading = true;
    draw_ui(m);
    model_refresh(m);
  }
}

void init_model(Model *m) {
  memset(m, 0, sizeof(*m));
  m->filter = FILTER_ALL;
  m->mode = MODE_CELLS;
  m->cursor = 0;
  m->volume_cursor = 0;
  m->backup_cursor = 0;
  m->theme_index = 0;
  load_theme_preference(m);
  m->spinner_index = 0;
  m->next_refresh_due = time(NULL);
  m->disconnected = false;
  m->disconnect_reason[0] = '\0';
  set_status(m, false, "Loading cell status...");
}

void destroy_model(Model *m) {
  shutdown_command_bridge();
  clear_model_rows(m);
  clear_model_volume_rows(m);
  clear_model_backups(m);
  clear_confirmation(m);
}
