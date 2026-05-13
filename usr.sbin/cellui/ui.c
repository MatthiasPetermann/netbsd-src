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

#include "cellui.h"

#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

typedef int (*UiActionFn)(void *ctx, char **err_out);

enum UiCellOp {
  UI_CELL_START = 0,
  UI_CELL_STOP,
  UI_CELL_RESTART,
};

enum UiBackupOp {
  UI_BACKUP_CREATE = 0,
  UI_BACKUP_RESTORE,
  UI_BACKUP_DELETE,
};

typedef struct {
  enum UiCellOp op;
  const char *name;
  bool all;
} UiCellActionCtx;

typedef struct {
  enum UiBackupOp op;
  const char *kind;
  const char *name;
  const char *archive;
} UiBackupActionCtx;

static int ui_cell_action(void *ctx, char **err_out) {
  UiCellActionCtx *c = ctx;

  switch (c->op) {
  case UI_CELL_START:
    return api_cell_start(c->name, c->all, err_out);
  case UI_CELL_STOP:
    return api_cell_stop(c->name, c->all, err_out);
  case UI_CELL_RESTART:
  default:
    return api_cell_restart(c->name, c->all, err_out);
  }
}

static int ui_apply_all_action(void *ctx, char **err_out) {
  (void)ctx;
  return api_apply_all(err_out);
}

static int ui_backup_action(void *ctx, char **err_out) {
  UiBackupActionCtx *c = ctx;

  switch (c->op) {
  case UI_BACKUP_CREATE:
    return api_backup_create(c->kind, c->name, err_out);
  case UI_BACKUP_RESTORE:
    return api_backup_restore(c->kind, c->name, c->archive, err_out);
  case UI_BACKUP_DELETE:
  default:
    return api_backup_delete(c->kind, c->name, c->archive, err_out);
  }
}

static void run_ui_action(Model *m, const char *title, bool refresh_after,
                          UiActionFn fn, void *ctx) {
  char *err = NULL;

  m->loading = true;
  draw_ui(m);

  if (fn(ctx, &err) != 0) {
    set_status(m, true, "%s failed: %s", title,
               blank_if(err, "command failed"));
  } else {
    set_status(m, false, "%s done", title);
  }
  free(err);

  m->loading = false;
  if (refresh_after) {
    m->loading = true;
    draw_ui(m);
    model_refresh(m);
  }
}

static void format_age_human(const char *src, char *out, size_t outsz) {
  unsigned long long s;
  unsigned long long m;
  unsigned long long h;
  unsigned long long d;
  unsigned long long w;
  char *endp;

  if (outsz == 0) {
    return;
  }
  if (src == NULL || *src == '\0') {
    (void)snprintf(out, outsz, "-");
    return;
  }

  s = strtoull(src, &endp, 10);
  if (endp == src || *endp != '\0') {
    (void)snprintf(out, outsz, "%s", src);
    return;
  }

  if (s < 60) {
    (void)snprintf(out, outsz, "%llus", s);
    return;
  }
  if (s < 3600) {
    m = s / 60;
    (void)snprintf(out, outsz, "%llum%llus", m, s % 60);
    return;
  }
  if (s < 86400) {
    h = s / 3600;
    m = (s % 3600) / 60;
    (void)snprintf(out, outsz, "%lluh%llum", h, m);
    return;
  }
  if (s < 604800) {
    d = s / 86400;
    h = (s % 86400) / 3600;
    (void)snprintf(out, outsz, "%llud%lluh", d, h);
    return;
  }

  w = s / 604800;
  d = (s % 604800) / 86400;
  (void)snprintf(out, outsz, "%lluw%llud", w, d);
}

static bool parse_u64_strict(const char *src, unsigned long long *out) {
  char *endp;
  unsigned long long v;

  if (src == NULL || *src == '\0') {
    return false;
  }
  v = strtoull(src, &endp, 10);
  if (endp == src || *endp != '\0') {
    return false;
  }
  *out = v;
  return true;
}

static void format_bytes_human(const char *src, char *out, size_t outsz) {
  static const char *units[] = {"KiB", "MiB", "GiB", "TiB"};
  unsigned long long bytes;
  double value;
  int unit_idx = 0;

  if (outsz == 0) {
    return;
  }
  if (is_blank(src) || strcmp(src, "-") == 0) {
    (void)snprintf(out, outsz, "-");
    return;
  }
  if (!parse_u64_strict(src, &bytes)) {
    (void)snprintf(out, outsz, "%s", src);
    return;
  }

  if (bytes < 1024ULL) {
    (void)snprintf(out, outsz, "%llu B", bytes);
    return;
  }

  value = (double)bytes / 1024.0;
  while (value >= 1024.0 && unit_idx < 3) {
    value /= 1024.0;
    unit_idx++;
  }
  (void)snprintf(out, outsz, "%.1f %s", value, units[unit_idx]);
}

static void format_backup_timestamp_iso(const char *src, char *out,
                                        size_t outsz) {
  const char *s;
  size_t i;

  if (outsz == 0) {
    return;
  }
  s = blank_if(src, "");
  if (*s == '\0' || strcmp(s, "-") == 0) {
    (void)snprintf(out, outsz, "-");
    return;
  }

  if (strlen(s) == 14) {
    for (i = 0; i < 14; i++) {
      if (s[i] < '0' || s[i] > '9') {
        (void)snprintf(out, outsz, "%s", s);
        return;
      }
    }
    (void)snprintf(out, outsz, "%.4s-%.2s-%.2sT%.2s:%.2s:%.2s", s, s + 4,
                   s + 6, s + 8, s + 10, s + 12);
    return;
  }

  (void)snprintf(out, outsz, "%s", s);
}

static void draw_box(int y, int x, int h, int w) {
  int i;

  if (h < 2 || w < 2) {
    return;
  }

  attrset(COLOR_PAIR(PAIR_PANEL));
  for (i = 1; i < h - 1; i++) {
    mvhline(y + i, x + 1, ' ', w - 2);
  }

  attrset(COLOR_PAIR(PAIR_PANEL_BORDER));
  mvhline(y, x + 1, ACS_HLINE, w - 2);
  mvhline(y + h - 1, x + 1, ACS_HLINE, w - 2);
  mvvline(y + 1, x, ACS_VLINE, h - 2);
  mvvline(y + 1, x + w - 1, ACS_VLINE, h - 2);
  mvaddch(y, x, ACS_ULCORNER);
  mvaddch(y, x + w - 1, ACS_URCORNER);
  mvaddch(y + h - 1, x, ACS_LLCORNER);
  mvaddch(y + h - 1, x + w - 1, ACS_LRCORNER);
}

static void pad_and_print(int y, int x, int width, const char *text, int pair) {
  int n;

  if (width <= 0) {
    return;
  }
  attrset(COLOR_PAIR(pair));
  mvhline(y, x, ' ', width);
  n = (int)strlen(text);
  if (n > width) {
    n = width;
  }
  mvaddnstr(y, x, text, n);
}

static void append_char_limited(char *dst, size_t dstsz, size_t *pos, char c) {
  if (*pos + 1 >= dstsz) {
    return;
  }
  dst[*pos] = c;
  (*pos)++;
  dst[*pos] = '\0';
}

static void append_field_padded(char *dst, size_t dstsz, size_t *pos,
                                const char *text, int width) {
  int i;
  int tlen = (int)strlen(text);

  if (tlen > width) {
    tlen = width;
  }
  for (i = 0; i < tlen; i++) {
    append_char_limited(dst, dstsz, pos, text[i]);
  }
  for (; i < width; i++) {
    append_char_limited(dst, dstsz, pos, ' ');
  }
}

static const char *bool_label(bool value);

static int table_name_width(int content_width) {
  int name_width = content_width - 58;

  if (name_width < 16) {
    name_width = 16;
  }
  return name_width;
}

static void table_row_string(const CellRow *row, int name_width, char *out,
                             size_t outsz) {
  char name[1024];
  char running[9];
  char cid[7];
  char procs[7];
  char cpu1s[9];
  char cpu10s[9];
  char age[32];
  char refs[8];
  size_t pos = 0;

  if (outsz == 0) {
    return;
  }
  out[0] = '\0';

  shorten_to(blank_if(row->name, ""), name_width, name, sizeof(name));
  shorten_to(bool_label(row->running), 8, running, sizeof(running));
  shorten_to(blank_if(row->cid, "-"), 6, cid, sizeof(cid));
  shorten_to(blank_if(row->procs, "0"), 6, procs, sizeof(procs));
  shorten_to(blank_if(row->cpu1s, "-"), 8, cpu1s, sizeof(cpu1s));
  shorten_to(blank_if(row->cpu10s, "-"), 8, cpu10s, sizeof(cpu10s));
  format_age_human(blank_if(row->age, ""), age, sizeof(age));
  shorten_to(blank_if(age, "-"), 8, age, sizeof(age));
  shorten_to(blank_if(row->refs, "-"), 7, refs, sizeof(refs));

  append_field_padded(out, outsz, &pos, name, name_width);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, running, 8);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, cid, 6);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, procs, 6);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, cpu1s, 8);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, cpu10s, 8);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, age, 8);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, refs, 7);
}

static bool starts_with_updated(const char *s) {
  if (s == NULL) {
    return false;
  }
  return strncasecmp(s, "updated ", 8) == 0;
}

static bool starts_with_refreshing(const char *s) {
  if (s == NULL) {
    return false;
  }
  return strncasecmp(s, "refresh", 7) == 0;
}

static char spinner_char(const Model *m) {
  static const char spinner[] = {'|', '/', '-', '\\'};
  return spinner[m->spinner_index % 4];
}

static void render_status_bar(const Model *m, char *out, size_t outsz) {
  char meta[768];
  char attention_line[4096];
  char left[4096];
  char right[96];
  int width = m->width;
  int right_w;
  int left_max;
  bool attention_status;

  if (m->mode == MODE_CELLS) {
    (void)snprintf(meta, sizeof(meta),
                   "cells: %zu  running: %d  orphaned: %d  filter: %s",
                   m->row_count, running_count(m), orphaned_count(m),
                   filter_label(m->filter));
  } else {
    int volume_total = storage_kind_count(m, "volume");
    int overlay_total = storage_kind_count(m, "overlay");
    (void)snprintf(meta, sizeof(meta),
                   "storage: %zu  volumes: %d  overlays: %d  backup-ready: %d  backups: %zu",
                   m->volume_row_count, volume_total, overlay_total,
                   storage_backup_eligible_count(m),
                   m->backup_row_count);
  }

  if (m->last_refresh == 0) {
    (void)snprintf(right, sizeof(right), "| updated --:--:--");
  } else {
    struct tm *tmv = localtime(&m->last_refresh);
    if (tmv != NULL) {
      (void)snprintf(right, sizeof(right), "| updated %02d:%02d:%02d",
                     tmv->tm_hour, tmv->tm_min, tmv->tm_sec);
    } else {
      (void)snprintf(right, sizeof(right), "| updated --:--:--");
    }
  }

  attention_status = (!is_blank(m->status) && !starts_with_updated(m->status));

  if (attention_status) {
    if (m->loading && !starts_with_refreshing(m->status)) {
      (void)snprintf(attention_line, sizeof(attention_line), "%c %s",
                     spinner_char(m), m->status);
    } else {
      (void)snprintf(attention_line, sizeof(attention_line), "%s", m->status);
    }
    (void)snprintf(left, sizeof(left), "%s", attention_line);
  } else {
    (void)snprintf(left, sizeof(left), "%s", meta);
  }

  right_w = (int)strlen(right);
  if (right_w >= width) {
    shorten_to(right, width, out, outsz);
    return;
  }

  left_max = width - right_w - 1;
  if (left_max < 0) {
    left_max = 0;
  }

  {
    char left_short[1024];
    int gap;
    shorten_to(left, left_max, left_short, sizeof(left_short));
    gap = width - (int)strlen(left_short) - right_w;
    if (gap < 1) {
      gap = 1;
    }
    (void)snprintf(out, outsz, "%s%*s%s", left_short, gap, "", right);
  }
}

typedef struct {
  const char *key;
  const char *desc;
} HelpBinding;

static int volume_table_name_width(int content_width) {
  int name_width = content_width - 31;

  if (name_width < 16) {
    name_width = 16;
  }
  return name_width;
}

static const char *bool_label(bool value) {
  return value ? "YES" : "NO";
}

static void volume_row_string(const VolumeRow *row, int name_width, char *out,
                              size_t outsz) {
  char name[1024];
  char kind[8];
  char mounted[8];
  char refs[6];
  char mode[9];
  size_t pos = 0;

  if (outsz == 0) {
    return;
  }
  out[0] = '\0';

  shorten_to(blank_if(row->name, ""), name_width, name, sizeof(name));
  shorten_to(blank_if(row->kind, "-"), 7, kind, sizeof(kind));
  shorten_to(bool_label(row->mounted), 7, mounted, sizeof(mounted));
  shorten_to(blank_if(row->refs, "0"), 5, refs, sizeof(refs));
  shorten_to(blank_if(row->mode, "-"), 8, mode, sizeof(mode));

  append_field_padded(out, outsz, &pos, name, name_width);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, kind, 7);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, mounted, 7);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, refs, 5);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, mode, 8);
}

static const char *archive_basename(const char *path) {
  const char *slash;

  if (is_blank(path)) {
    return "-";
  }
  slash = strrchr(path, '/');
  if (slash == NULL || slash[1] == '\0') {
    return path;
  }
  return slash + 1;
}

static void draw_help_line(int y, int width, const HelpBinding *bindings,
                           size_t count) {
  int x = 0;

  if (y < 0 || y >= LINES) {
    return;
  }
  attrset(COLOR_PAIR(PAIR_HELP));
  mvhline(y, 0, ' ', width);

  for (size_t i = 0; i < count; i++) {
    int n;
    if (x >= width) {
      break;
    }

    attrset(COLOR_PAIR(PAIR_KEY) | A_BOLD);
    n = (int)strlen(bindings[i].key);
    if (x + n > width) {
      n = width - x;
    }
    mvaddnstr(y, x, bindings[i].key, n);
    x += n;

    attrset(COLOR_PAIR(PAIR_HELP));
    n = (int)strlen(bindings[i].desc) + 1;
    if (x + n > width) {
      n = width - x;
    }
    mvaddnstr(y, x, " ", 1);
    if (n > 1) {
      mvaddnstr(y, x + 1, bindings[i].desc, n - 1);
    }
    x += n;

    if (i + 1 < count && x < width) {
      attrset(COLOR_PAIR(PAIR_HELP_SEP));
      n = 3;
      if (x + n > width) {
        n = width - x;
      }
      mvaddnstr(y, x, " | ", n);
      x += n;
    }
  }
}

static void draw_confirmation_dialog(const Model *m) {
  int dlg_w;
  int dlg_h = 10;
  int dlg_x;
  int dlg_y;
  int content_w;
  int title_x;
  int action_x;
  int action_w;
  int sep_x;
  int cancel_x;
  int sep_n;
  int cancel_n;
  int confirm_n;
  char line[1024];
  char value[768];
  char confirm_short[128];
  const char *cancel_label = "[other key] Cancel";
  const char *sep = " | ";
  const char *title;
  const char *warning;
  const char *confirm_label;
  const char *storage_kind;

  if (!m->confirm_open || m->width < 12 || m->height < dlg_h + 2) {
    return;
  }

  storage_kind = blank_if(m->confirm_storage_kind, "volume");

  switch (m->confirm_action) {
  case CONFIRM_DELETE_BACKUP:
    title = "Confirm Backup Delete";
    warning = "This will permanently delete this backup archive.";
    confirm_label = "[Enter] Delete backup";
    break;
  case CONFIRM_RESTORE_BACKUP:
  default:
    title = "Confirm Storage Restore";
    if (strcmp(storage_kind, "overlay") == 0) {
      warning = "This will replace current runtime overlay contents.";
    } else {
      warning = "This will replace current runtime volume contents.";
    }
    confirm_label = "[Enter] Restore now";
    break;
  }

  dlg_w = m->width - 10;
  if (dlg_w > 72) {
    dlg_w = 72;
  }
  if (dlg_w < 46) {
    dlg_w = 46;
  }

  dlg_x = (m->width - dlg_w) / 2;
  dlg_y = (m->height - dlg_h) / 2;
  if (dlg_x < 0) {
    dlg_x = 0;
  }
  if (dlg_y < 1) {
    dlg_y = 1;
  }

  draw_box(dlg_y, dlg_x, dlg_h, dlg_w);

  content_w = dlg_w - 4;
  if (content_w < 1) {
    return;
  }

  attrset(COLOR_PAIR(PAIR_PANEL));
  mvhline(dlg_y + 1, dlg_x + 1, ' ', dlg_w - 2);

  title_x = dlg_x + (dlg_w - (int)strlen(title)) / 2;
  if (title_x < dlg_x + 2) {
    title_x = dlg_x + 2;
  }
  attrset(COLOR_PAIR(PAIR_TABLE_HEADER) | A_BOLD);
  mvaddnstr(dlg_y + 1, title_x, title, content_w);
  attrset(COLOR_PAIR(PAIR_PANEL_BORDER));
  mvhline(dlg_y + 2, dlg_x + 2, ACS_HLINE, content_w);

  shorten_to(blank_if(m->confirm_storage_name, "-"), content_w - 10, value,
             sizeof(value));
  (void)snprintf(line, sizeof(line), "Storage: %s:%s", storage_kind, value);
  attrset(COLOR_PAIR(PAIR_PANEL));
  mvhline(dlg_y + 3, dlg_x + 2, ' ', content_w);
  mvaddnstr(dlg_y + 3, dlg_x + 2, line, content_w);

  shorten_to(blank_if(archive_basename(m->confirm_archive_path), "-"),
             content_w - 10, value, sizeof(value));
  (void)snprintf(line, sizeof(line), "Backup : %s", value);
  mvhline(dlg_y + 4, dlg_x + 2, ' ', content_w);
  mvaddnstr(dlg_y + 4, dlg_x + 2, line, content_w);

  shorten_to(warning, content_w, line, sizeof(line));
  mvhline(dlg_y + 5, dlg_x + 2, ' ', content_w);
  mvaddnstr(dlg_y + 5, dlg_x + 2, line, content_w);

  mvhline(dlg_y + 6, dlg_x + 2, ' ', content_w);

  action_x = dlg_x + 2;
  action_w = content_w;
  if (action_w < 1) {
    return;
  }
  confirm_n = action_w - ((int)strlen(sep) + (int)strlen(cancel_label));
  if (confirm_n < 1) {
    confirm_n = 1;
  }
  shorten_to(confirm_label, confirm_n, confirm_short, sizeof(confirm_short));

  attrset(COLOR_PAIR(PAIR_KEY) | A_BOLD);
  mvhline(dlg_y + 7, action_x, ' ', action_w);
  mvaddnstr(dlg_y + 7, action_x, confirm_short, action_w);

  sep_x = action_x + (int)strlen(confirm_short);
  sep_n = action_x + action_w - sep_x;
  if (sep_n > (int)strlen(sep)) {
    sep_n = (int)strlen(sep);
  }
  if (sep_n < 0) {
    sep_n = 0;
  }
  attrset(COLOR_PAIR(PAIR_HELP));
  if (sep_n > 0) {
    mvaddnstr(dlg_y + 7, sep_x, sep, sep_n);
  }

  cancel_x = sep_x + sep_n;
  cancel_n = action_x + action_w - cancel_x;
  if (cancel_n < 0) {
    cancel_n = 0;
  }
  attrset(COLOR_PAIR(PAIR_KEY) | A_BOLD);
  if (cancel_n > 0) {
    mvaddnstr(dlg_y + 7, cancel_x, cancel_label, cancel_n);
  }
}

void draw_ui(Model *m) {
  int h, w;
  int table_body;
  int table_name_w;
  int table_state_x;
  int table_h;
  int detail_h;
  int table_y;
  int detail_y;
  int status_y;
  int help_y;
  size_t *vis = NULL;
  size_t vis_count = 0;
  char header_line[1024];
  char header_left[512];
  char header_right[256];
  char header_left_short[512];

  getmaxyx(stdscr, h, w);
  m->height = h;
  m->width = w;

  if (m->loading) {
    m->spinner_index = (m->spinner_index + 1) % 4;
  }

  if (has_color) {
    bkgd(COLOR_PAIR(PAIR_PAGE));
  }
  erase();

  if (m->mode == MODE_CELLS) {
    (void)snprintf(header_left, sizeof(header_left), "cellui | Cell Management");
  } else {
    (void)snprintf(header_left, sizeof(header_left),
                   "cellui | Storage Management");
  }
  (void)snprintf(header_right, sizeof(header_right), " | %s",
                 current_theme(m)->name);

  if ((int)strlen(header_right) >= w) {
    shorten_to(header_right, w, header_line, sizeof(header_line));
  } else {
    int gap;
    int left_max = w - (int)strlen(header_right) - 1;
    if (left_max < 0) {
      left_max = 0;
    }
    shorten_to(header_left, left_max, header_left_short,
               sizeof(header_left_short));
    gap = w - (int)strlen(header_left_short) - (int)strlen(header_right);
    if (gap < 1) {
      gap = 1;
    }
    (void)snprintf(header_line, sizeof(header_line), "%s%*s%s",
                   header_left_short, gap, "", header_right);
  }
  pad_and_print(0, 0, w, header_line, PAIR_HEADER);

  table_body = table_body_height(m, h);
  if (m->mode == MODE_CELLS) {
    table_name_w = table_name_width(w - 2);
    table_state_x = 1 + table_name_w + 1;
  } else {
    table_name_w = volume_table_name_width(w - 2);
    table_state_x = 1 + table_name_w + 1 + 7 + 1;
  }
  table_h = table_body + 3;
  detail_h = ((m->mode == MODE_CELLS) ? CELL_DETAIL_CONTENT_LINES
                                       : STORAGE_DETAIL_CONTENT_LINES) +
             2;
  table_y = 1;
  detail_y = table_y + table_h;
  status_y = detail_y + detail_h;
  help_y = status_y + 1;

  if (table_y + table_h <= h) {
    draw_box(table_y, 0, table_h, w);
  }
  if (detail_y + detail_h <= h) {
    draw_box(detail_y, 0, detail_h, w);
  }

  if (table_y + 1 < h) {
    char header[512];
    if (m->mode == MODE_CELLS) {
      (void)snprintf(header, sizeof(header),
                     "%-*s %-8s %-6s %-6s %-8s %-8s %-8s %-7s",
                     table_name_w, "NAME", "RUNNING", "CID", "PROC", "CPU1S",
                     "CPU10S", "AGE", "REFS");
    } else {
      (void)snprintf(header, sizeof(header),
                     "%-*s %-7s %-7s %-5s %-8s", table_name_w, "NAME",
                     "TYPE", "MOUNTED", "REFS", "MODE");
    }
    attrset(COLOR_PAIR(PAIR_TABLE_HEADER) | A_BOLD);
    mvhline(table_y + 1, 1, ' ', w - 2);
    mvaddnstr(table_y + 1, 1, header, w - 2);
  }

  if (m->mode == MODE_CELLS) {
    size_t count = 0;
    vis = malloc((m->row_count == 0 ? 1 : m->row_count) * sizeof(*vis));
    if (vis != NULL) {
      for (size_t i = 0; i < m->row_count; i++) {
        if (m->filter == FILTER_ALL ||
            (m->filter == FILTER_RUNNING && m->rows[i].running) ||
            (m->filter == FILTER_STOPPED && !m->rows[i].running)) {
          vis[count++] = i;
        }
      }
    }
    vis_count = count;
  } else {
    vis_count = m->volume_row_count;
  }

  if (table_y + 2 < h) {
    if (vis_count == 0) {
      char msg[256];
      if (m->mode == MODE_CELLS) {
        shorten_to("No cells visible for current filter.", w - 2, msg,
                   sizeof(msg));
      } else {
        shorten_to("No storage entries found.", w - 2, msg, sizeof(msg));
      }
      attrset(COLOR_PAIR(PAIR_PANEL));
      mvhline(table_y + 2, 1, ' ', w - 2);
      mvaddnstr(table_y + 2, 1, msg, w - 2);
    } else {
      int start = 0;
      int active_cursor = (m->mode == MODE_CELLS) ? m->cursor : m->volume_cursor;
      if (active_cursor >= table_body) {
        start = active_cursor - table_body + 1;
      }
      if (start > (int)vis_count - table_body) {
        start = (int)vis_count - table_body;
      }
      if (start < 0) {
        start = 0;
      }

      for (int i = 0; i < table_body; i++) {
        int y = table_y + 2 + i;
        int idx = start + i;
        if (y >= h || y >= table_y + table_h - 1) {
          break;
        }

        attrset(COLOR_PAIR(PAIR_PANEL));
        mvhline(y, 1, ' ', w - 2);

        if (idx >= 0 && (size_t)idx < vis_count) {
          char line[2048];
          bool selected = false;

          if (m->mode == MODE_CELLS) {
            CellRow *row = &m->rows[vis[idx]];
            selected = (idx == m->cursor);
            table_row_string(row, table_name_w, line, sizeof(line));

            if (selected) {
              attrset(COLOR_PAIR(PAIR_SELECTED));
              mvhline(y, 1, ' ', w - 2);
              mvaddnstr(y, 1, line, w - 2);
            } else {
              attrset(COLOR_PAIR(PAIR_PANEL));
              mvaddnstr(y, 1, line, w - 2);
              if (w > table_state_x) {
                attrset(COLOR_PAIR(row->running ? PAIR_RUNNING : PAIR_STOPPED));
                mvaddnstr(y, table_state_x, row->running ? "YES" : "NO", 8);
              }
            }
          } else {
            VolumeRow *row = &m->volume_rows[idx];
            selected = (idx == m->volume_cursor);
            volume_row_string(row, table_name_w, line, sizeof(line));

            if (selected) {
              attrset(COLOR_PAIR(PAIR_SELECTED));
              mvhline(y, 1, ' ', w - 2);
              mvaddnstr(y, 1, line, w - 2);
            } else {
              attrset(COLOR_PAIR(PAIR_PANEL));
              mvaddnstr(y, 1, line, w - 2);
              if (w > table_state_x) {
                attrset(COLOR_PAIR(row->mounted ? PAIR_RUNNING : PAIR_STOPPED));
                mvaddnstr(y, table_state_x,
                          row->mounted ? "YES" : "NO", 7);
              }
            }
          }
        }
      }
    }
  }

  if (detail_y + 1 < h) {
    char lines[DETAIL_CONTENT_LINES][1024];
    bool selected_lines[DETAIL_CONTENT_LINES];
    int value_width = w - 18;

    for (int i = 0; i < DETAIL_CONTENT_LINES; i++) {
      selected_lines[i] = false;
    }

    if (value_width < 12) {
      value_width = 12;
    }

    if (m->mode == MODE_CELLS) {
      CellRow *row = selected_cell(m);
      char tmp[1024];
      char policy[1024];
      char as_human[64];
      char memory_human[64];

      if (row == NULL) {
        (void)snprintf(lines[0], sizeof(lines[0]), "No cell selected");
        for (int i = 1; i < DETAIL_CONTENT_LINES; i++) {
          lines[i][0] = '\0';
        }
      } else {
        shorten_to(blank_if(row->name, "-"), value_width, tmp, sizeof(tmp));
        format_prefixed(lines[0], sizeof(lines[0]), "Name        : ", tmp);
        (void)snprintf(lines[1], sizeof(lines[1]), "State       : %s",
                       blank_if(row->state, "-"));
        shorten_to(blank_if(row->root, "-"), value_width, tmp, sizeof(tmp));
        format_prefixed(lines[2], sizeof(lines[2]), "Root        : ", tmp);
        (void)snprintf(lines[3], sizeof(lines[3]), "Profile     : %s",
                       blank_if(row->create_profile, "-"));
        format_bytes_human(blank_if(row->create_rlimit_as, ""), as_human,
                           sizeof(as_human));
        (void)snprintf(policy, sizeof(policy), "ports=%s nofile=%s as=%s core=%s",
                       blank_if(row->create_reserved_ports, "-"),
                       blank_if(row->create_rlimit_nofile, "unlimited"),
                       blank_if(as_human, "unlimited"),
                       blank_if(row->create_rlimit_core, "unlimited"));
        shorten_to(policy, value_width, tmp, sizeof(tmp));
        format_prefixed(lines[4], sizeof(lines[4]), "Policy      : ", tmp);
        format_bytes_human(blank_if(row->memory, ""), memory_human,
                           sizeof(memory_human));
        (void)snprintf(lines[5], sizeof(lines[5]), "Memory      : %s",
                       blank_if(memory_human, "-"));
        shorten_to(blank_if(row->supervise_cmd, "-"), value_width, tmp,
                   sizeof(tmp));
        format_prefixed(lines[6], sizeof(lines[6]), "Supervise   : ", tmp);
        for (int i = 7; i < DETAIL_CONTENT_LINES; i++) {
          lines[i][0] = '\0';
        }
      }
    } else {
      VolumeRow *row = selected_volume(m);

      for (int i = 0; i < DETAIL_CONTENT_LINES; i++) {
        lines[i][0] = '\0';
      }

      if (row == NULL) {
        (void)snprintf(lines[0], sizeof(lines[0]), "No storage selected");
      } else {
        char tmp[1024];
        int backup_lines = DETAIL_CONTENT_LINES - 6;
        int backup_start = 6;
        int backup_scroll = 0;

        shorten_to(blank_if(row->name, "-"), value_width, tmp, sizeof(tmp));
        format_prefixed(lines[0], sizeof(lines[0]), "Name        : ", tmp);
        shorten_to(blank_if(row->path, "-"), value_width, tmp, sizeof(tmp));
        format_prefixed(lines[1], sizeof(lines[1]), "Path        : ", tmp);
        shorten_to(blank_if(row->used_by, "-"), value_width, tmp, sizeof(tmp));
        format_prefixed(lines[2], sizeof(lines[2]), "Used by     : ", tmp);
        (void)snprintf(lines[4], sizeof(lines[4]),
                       "State       : %s", blank_if(row->state, "-"));
        (void)snprintf(lines[5], sizeof(lines[5]), "Backups (newest first):");

        if (backup_lines < 1) {
          backup_lines = 1;
        }
        if (m->backup_row_count == 0) {
          (void)snprintf(lines[backup_start], sizeof(lines[backup_start]),
                         "  (none)");
        } else {
          if (m->backup_cursor >= backup_lines) {
            backup_scroll = m->backup_cursor - backup_lines + 1;
          }
          if (backup_scroll > (int)m->backup_row_count - backup_lines) {
            backup_scroll = (int)m->backup_row_count - backup_lines;
          }
          if (backup_scroll < 0) {
            backup_scroll = 0;
          }

          for (int i = 0; i < backup_lines; i++) {
            int idx = backup_scroll + i;
            const BackupRow *backup;
            const char *base;
            char backup_line[1024];
            char short_name[768];
            char ts_human[32];
            char size_human[64];
            int fixed_w;
            int name_w;

            if ((size_t)idx >= m->backup_row_count || backup_start + i >= DETAIL_CONTENT_LINES) {
              break;
            }
            backup = &m->backup_rows[idx];
            base = archive_basename(backup->archive);
            format_backup_timestamp_iso(blank_if(backup->timestamp, ""), ts_human,
                                        sizeof(ts_human));
            format_bytes_human(blank_if(backup->size, ""), size_human,
                               sizeof(size_human));
            fixed_w = (int)strlen(ts_human) + (int)strlen(size_human) + 6;
            name_w = value_width - fixed_w;
            if (name_w < 8) {
              name_w = 8;
            }
            shorten_to(base, name_w, short_name, sizeof(short_name));
            (void)snprintf(backup_line, sizeof(backup_line), "  %s  %s  %s",
                           ts_human, size_human, short_name);
            (void)snprintf(lines[backup_start + i], sizeof(lines[backup_start + i]),
                           "%s", backup_line);
            if (idx == m->backup_cursor) {
              selected_lines[backup_start + i] = true;
            }
          }
        }
      }
    }

    for (int i = 0; i < DETAIL_CONTENT_LINES; i++) {
      int y = detail_y + 1 + i;
      if (y >= h || y >= detail_y + detail_h - 1) {
        break;
      }
      if (selected_lines[i]) {
        attrset(COLOR_PAIR(PAIR_SELECTED));
      } else {
        attrset(COLOR_PAIR(PAIR_PANEL));
      }
      mvhline(y, 1, ' ', w - 2);
      mvaddnstr(y, 1, lines[i], w - 2);
    }
  }

  if (status_y < h) {
    char status_line[2048];
    render_status_bar(m, status_line, sizeof(status_line));
    pad_and_print(status_y, 0, w, status_line, PAIR_SUBHEADER);
  }

  if (help_y < h) {
    if (m->mode == MODE_CELLS) {
      const HelpBinding line1[] = {
          {"j/k", "move"},
          {"PgUp/PgDn", "page"},
          {"r", "refresh"},
          {"f", "filter"},
          {"enter", "shell"},
          {"TAB", "mode"},
      };
      draw_help_line(help_y, w, line1, sizeof(line1) / sizeof(line1[0]));
    } else {
      const HelpBinding line1[] = {
          {"j/k", "storage"},
          {"PgUp/PgDn", "page"},
          {"[/]", "backup"},
          {"R", "refresh"},
          {"TAB", "mode"},
          {"q", "quit"},
      };
      draw_help_line(help_y, w, line1, sizeof(line1) / sizeof(line1[0]));
    }
  }

  if (help_y + 1 < h) {
    if (m->mode == MODE_CELLS) {
      const HelpBinding line2[] = {
          {"s", "start"},
          {"x", "stop"},
          {"t", "restart"},
          {"a/z/y", "all"},
          {"A", "apply"},
          {"m", "theme"},
          {"q", "quit"},
      };
      draw_help_line(help_y + 1, w, line2, sizeof(line2) / sizeof(line2[0]));
    } else {
      const HelpBinding line2[] = {
          {"b", "backup"},
          {"r", "restore"},
          {"d", "delete"},
          {"m", "theme"},
      };
      draw_help_line(help_y + 1, w, line2, sizeof(line2) / sizeof(line2[0]));
    }
  }

  if (m->mode == MODE_STORAGE && m->confirm_open) {
    draw_confirmation_dialog(m);
  }

  (void)curs_set(0);

  free(vis);
  refresh();
}

static void handle_cell_mode_key(Model *m, int ch) {
  CellRow *row;
  char *name;

  switch (ch) {
  case KEY_UP:
  case 'k':
    m->cursor--;
    clamp_cursor(m);
    return;
  case KEY_DOWN:
  case 'j':
    m->cursor++;
    clamp_cursor(m);
    return;
  case KEY_PPAGE:
    m->cursor -= table_body_height(m, m->height);
    clamp_cursor(m);
    return;
  case KEY_NPAGE:
    m->cursor += table_body_height(m, m->height);
    clamp_cursor(m);
    return;
  case 'r':
    m->loading = true;
    set_status(m, false, "Refreshing...");
    draw_ui(m);
    model_refresh(m);
    return;
  case 'f':
    m->filter = (FilterMode)(((int)m->filter + 1) % 3);
    clamp_cursor(m);
    return;
  case 'm':
    rotate_theme(m);
    return;
  default:
    break;
  }

  row = selected_cell(m);
  if (ch == 'a') {
    UiCellActionCtx ctx = {
        .op = UI_CELL_START,
        .name = NULL,
        .all = true,
    };
    m->loading = true;
    set_status(m, false, "Starting all cells...");
    run_ui_action(m, "Start all", true, ui_cell_action, &ctx);
    return;
  }
  if (ch == 'z') {
    UiCellActionCtx ctx = {
        .op = UI_CELL_STOP,
        .name = NULL,
        .all = true,
    };
    m->loading = true;
    set_status(m, false, "Stopping all cells...");
    run_ui_action(m, "Stop all", true, ui_cell_action, &ctx);
    return;
  }
  if (ch == 'y') {
    UiCellActionCtx ctx = {
        .op = UI_CELL_RESTART,
        .name = NULL,
        .all = true,
    };
    m->loading = true;
    set_status(m, false, "Restarting all cells...");
    run_ui_action(m, "Restart all", true, ui_cell_action, &ctx);
    return;
  }
  if (ch == 'A') {
    m->loading = true;
    set_status(m, false, "Applying desired state...");
    run_ui_action(m, "Apply", true, ui_apply_all_action, NULL);
    return;
  }

  if (row == NULL) {
    return;
  }
  name = xstrdup(blank_if(row->name, ""));

  switch (ch) {
  case 's': {
    UiCellActionCtx ctx = {
        .op = UI_CELL_START,
        .name = name,
        .all = false,
    };
    m->loading = true;
    set_status(m, false, "Starting %s...", name);
    run_ui_action(m, "Start", true, ui_cell_action, &ctx);
    break;
  }
  case 'x': {
    UiCellActionCtx ctx = {
        .op = UI_CELL_STOP,
        .name = name,
        .all = false,
    };
    m->loading = true;
    set_status(m, false, "Stopping %s...", name);
    run_ui_action(m, "Stop", true, ui_cell_action, &ctx);
    break;
  }
  case 't': {
    UiCellActionCtx ctx = {
        .op = UI_CELL_RESTART,
        .name = name,
        .all = false,
    };
    m->loading = true;
    set_status(m, false, "Restarting %s...", name);
    run_ui_action(m, "Restart", true, ui_cell_action, &ctx);
    break;
  }
  case '\n':
  case '\r':
  case KEY_ENTER: {
    if (!row->running) {
      set_status(m, true, "Cannot open shell in %s: cell is not running", name);
      break;
    }

    m->loading = true;
    set_status(m, false, "Opening shell in %s", name);
    run_interactive_shell_action(m, "Shell", true, name);
    break;
  }
  default:
    break;
  }

  free(name);
}

static void handle_volume_mode_key(Model *m, int ch) {
  VolumeRow *row;

  if (m->confirm_open) {
    if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
      ConfirmAction action = m->confirm_action;
      char *storage_kind = xstrdup(blank_if(m->confirm_storage_kind, "volume"));
      char *storage_name = xstrdup(blank_if(m->confirm_storage_name, ""));
      char *archive_path = xstrdup(blank_if(m->confirm_archive_path, ""));

      clear_confirmation(m);

      switch (action) {
      case CONFIRM_DELETE_BACKUP: {
        UiBackupActionCtx ctx = {
            .op = UI_BACKUP_DELETE,
            .kind = storage_kind,
            .name = storage_name,
            .archive = archive_path,
        };
        m->loading = true;
        set_status(m, false, "Deleting backup for %s:%s...",
                   blank_if(storage_kind, "storage"),
                   blank_if(storage_name, "name"));
        run_ui_action(m, "Delete backup", true, ui_backup_action, &ctx);
        break;
      }
      case CONFIRM_RESTORE_BACKUP:
      default: {
        UiBackupActionCtx ctx = {
            .op = UI_BACKUP_RESTORE,
            .kind = storage_kind,
            .name = storage_name,
            .archive = archive_path,
        };
        m->loading = true;
        set_status(m, false, "Restoring %s:%s from backup...",
                   blank_if(storage_kind, "storage"),
                   blank_if(storage_name, "name"));
        run_ui_action(m, "Restore backup", true, ui_backup_action, &ctx);
        break;
      }
      }

      free(storage_kind);
      free(storage_name);
      free(archive_path);
      return;
    }

    clear_confirmation(m);
    set_status(m, false, "Action cancelled");
    return;
  }

  switch (ch) {
  case KEY_UP:
  case 'k':
    m->volume_cursor--;
    clamp_volume_cursor(m);
    sync_volume_backups(m, false);
    return;
  case KEY_DOWN:
  case 'j':
    m->volume_cursor++;
    clamp_volume_cursor(m);
    sync_volume_backups(m, false);
    return;
  case KEY_PPAGE:
    m->volume_cursor -= table_body_height(m, m->height);
    clamp_volume_cursor(m);
    sync_volume_backups(m, false);
    return;
  case KEY_NPAGE:
    m->volume_cursor += table_body_height(m, m->height);
    clamp_volume_cursor(m);
    sync_volume_backups(m, false);
    return;
  case '[':
  case KEY_LEFT:
    m->backup_cursor--;
    clamp_backup_cursor(m);
    return;
  case ']':
  case KEY_RIGHT:
    m->backup_cursor++;
    clamp_backup_cursor(m);
    return;
  case 'R':
    m->loading = true;
    set_status(m, false, "Refreshing storage...");
    draw_ui(m);
    model_refresh(m);
    return;
  case 'm':
    rotate_theme(m);
    return;
  default:
    break;
  }

  row = selected_volume(m);
  if (row == NULL || is_blank(row->name)) {
    return;
  }

  if (ch == 'b') {
    UiBackupActionCtx ctx = {
        .op = UI_BACKUP_CREATE,
        .kind = row->kind,
        .name = row->name,
        .archive = NULL,
    };
    m->loading = true;
    set_status(m, false, "Creating backup for %s:%s...",
               blank_if(row->kind, "storage"), row->name);
    run_ui_action(m, "Create backup", true, ui_backup_action, &ctx);
    return;
  }

  if (ch == 'r') {
    BackupRow *backup = selected_backup(m);
    const char *kind = blank_if(row->kind, "storage");

    if (row->mounted) {
      if (strcmp(kind, "overlay") == 0) {
        set_status(m, true,
                   "Cannot restore %s: cell is running or overlay is mounted",
                   row->name);
      } else {
        set_status(m, true, "Cannot restore %s: volume is mounted", row->name);
      }
      return;
    }
    if (backup == NULL || is_blank(backup->archive)) {
      set_status(m, true, "No backup selected for %s %s", kind, row->name);
      return;
    }
    start_confirmation(m, CONFIRM_RESTORE_BACKUP, kind, row->name,
                       backup->archive);
    set_status(m, false,
                "Selected restore: %s:%s from %s (Enter confirms, other key cancels)",
                kind, row->name,
                blank_if(archive_basename(backup->archive), "backup"));
    return;
  }

  if (ch == 'd') {
    BackupRow *backup = selected_backup(m);
    const char *kind = blank_if(row->kind, "storage");
    if (backup == NULL || is_blank(backup->archive)) {
      set_status(m, true, "No backup selected for %s %s", kind, row->name);
      return;
    }
    start_confirmation(m, CONFIRM_DELETE_BACKUP, kind, row->name,
                       backup->archive);
    set_status(m, false,
               "Selected delete: %s for %s:%s (Enter confirms, other key cancels)",
               blank_if(archive_basename(backup->archive), "backup"), kind,
               row->name);
    return;
  }

}

void handle_normal_key(Model *m, int ch, bool *quit) {
  if (ch == 3 || ch == 'q') {
    *quit = true;
    return;
  }

  if (ch == '\t') {
    clear_confirmation(m);
    if (m->mode == MODE_CELLS) {
      m->mode = MODE_STORAGE;
    } else {
      m->mode = MODE_CELLS;
    }
    set_status(m, false, "Refreshing...");
    m->loading = true;
    draw_ui(m);
    model_refresh(m);
    return;
  }

  if (m->mode == MODE_CELLS) {
    handle_cell_mode_key(m, ch);
  } else {
    handle_volume_mode_key(m, ch);
  }
}
