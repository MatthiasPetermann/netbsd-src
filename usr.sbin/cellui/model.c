#include "cellui.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

bool has_color = false;
Model *spinner_model = NULL;

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
  free(row->supervise_cmd);
  free(row->cpu1s);
  free(row->cpu10s);
  free(row->memory);
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

void set_status(Model *m, bool is_error, const char *fmt, ...) {
  va_list ap;

  m->status_is_error = is_error;
  va_start(ap, fmt);
  (void)vsnprintf(m->status, sizeof(m->status), fmt, ap);
  va_end(ap);
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

int table_body_height(const Model *m, int term_h) {
  int fixed = 1 + DETAIL_PANEL_LINES + 1 + HELP_LINES_COUNT;
  int avail;
  int rows;

  if (m->mode == MODE_COMMAND) {
    fixed += COMMAND_PANEL_LINES;
  }

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

static void model_set_rows(Model *m, CellRow *rows, size_t count) {
  clear_model_rows(m);
  m->rows = rows;
  m->row_count = count;
  clamp_cursor(m);
}

void model_refresh(Model *m) {
  CellRow *rows = NULL;
  size_t count = 0;
  char *err = NULL;
  time_t now = time(NULL);
  Model *prev_spinner_model = spinner_model;

  spinner_model = m;

  if (load_rows(&rows, &count, &err) != 0) {
    spinner_model = prev_spinner_model;
    set_status(m, true, "%s", blank_if(err, "refresh failed"));
    free(err);
    m->loading = false;
    m->last_refresh = now;
    m->next_refresh_due = now + REFRESH_EVERY_SEC;
    return;
  }
  spinner_model = prev_spinner_model;

  model_set_rows(m, rows, count);
  if (err != NULL) {
    set_status(m, true, "%s", err);
  } else {
    struct tm *tmv = localtime(&now);
    if (tmv != NULL) {
      set_status(m, false, "updated %02d:%02d:%02d", tmv->tm_hour, tmv->tm_min,
                 tmv->tm_sec);
    } else {
      set_status(m, false, "updated --:--:--");
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
    set_status(m, true, "%s failed: %s", title,
               blank_if(err, "command failed"));
  } else {
    set_status(m, false, "%s done", title);
  }
  spinner_model = prev_spinner_model;
  append_status_output(m, out);
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
    set_status(m, true, "%s exited with error: %s", title,
               blank_if(err, "command failed"));
  } else {
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
  m->mode = MODE_NORMAL;
  m->filter = FILTER_ALL;
  m->cursor = 0;
  m->theme_index = 0;
  m->spinner_index = 0;
  m->next_refresh_due = time(NULL);
  set_status(m, false, "Loading cell status...");
}
