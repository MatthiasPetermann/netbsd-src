#include "cellui.h"

#include <curses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

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

static void table_row_string(const CellRow *row, char *out, size_t outsz) {
  char name[17];
  char state[9];
  char cid[7];
  char procs[7];
  char cpu1s[9];
  char cpu10s[9];
  char autostart[7];
  char refs[8];
  size_t pos = 0;

  if (outsz == 0) {
    return;
  }
  out[0] = '\0';

  shorten_to(blank_if(row->name, ""), 16, name, sizeof(name));
  shorten_to(row->running ? "running" : "stopped", 8, state, sizeof(state));
  shorten_to(blank_if(row->cid, "-"), 6, cid, sizeof(cid));
  shorten_to(blank_if(row->procs, "0"), 6, procs, sizeof(procs));
  shorten_to(blank_if(row->cpu1s, "-"), 8, cpu1s, sizeof(cpu1s));
  shorten_to(blank_if(row->cpu10s, "-"), 8, cpu10s, sizeof(cpu10s));
  shorten_to(blank_if(row->autostart, "NO"), 6, autostart, sizeof(autostart));
  shorten_to(blank_if(row->refs, "-"), 7, refs, sizeof(refs));

  append_field_padded(out, outsz, &pos, name, 16);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, state, 8);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, cid, 6);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, procs, 6);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, cpu1s, 8);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, cpu10s, 8);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, autostart, 6);
  append_char_limited(out, outsz, &pos, ' ');
  append_field_padded(out, outsz, &pos, refs, 7);
}

static bool starts_with_updated(const char *s) {
  if (s == NULL) {
    return false;
  }
  return strncasecmp(s, "updated ", 8) == 0;
}

static char spinner_char(const Model *m) {
  static const char spinner[] = {'|', '/', '-', '\\'};
  return spinner[m->spinner_index % 4];
}

static void render_status_bar(const Model *m, char *out, size_t outsz) {
  char meta[512];
  char left[4096];
  char status_view[4096];
  char right[64];
  int width = m->width;
  int right_w;
  int left_max;

  (void)snprintf(meta, sizeof(meta),
                 "cells: %zu  running: %d  filter: %s  theme: %s", m->row_count,
                 running_count(m), filter_label(m->filter),
                 current_theme(m)->name);

  status_view[0] = '\0';
  if (m->loading) {
    if (starts_with_updated(m->status)) {
      (void)snprintf(status_view, sizeof(status_view), "%c", spinner_char(m));
    } else {
      (void)snprintf(status_view, sizeof(status_view), "%c %s", spinner_char(m),
                     m->status);
    }
  } else if (!starts_with_updated(m->status)) {
    (void)snprintf(status_view, sizeof(status_view), "%s", m->status);
  }

  left[0] = '\0';
  concat_limited(left, sizeof(left), meta);
  if (status_view[0] != '\0') {
    concat_limited(left, sizeof(left), "  |  ");
    concat_limited(left, sizeof(left), status_view);
  }

  if (m->last_refresh == 0) {
    (void)snprintf(right, sizeof(right), "updated --:--:--");
  } else {
    struct tm *tmv = localtime(&m->last_refresh);
    if (tmv != NULL) {
      (void)snprintf(right, sizeof(right), "updated %02d:%02d:%02d",
                     tmv->tm_hour, tmv->tm_min, tmv->tm_sec);
    } else {
      (void)snprintf(right, sizeof(right), "updated --:--:--");
    }
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

void draw_ui(Model *m) {
  int h, w;
  int table_body;
  int table_h;
  int detail_h;
  int table_y;
  int detail_y;
  int status_y;
  int help_y;
  int cmd_y;
  size_t *vis = NULL;
  size_t vis_count = 0;

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

  pad_and_print(0, 0, w, "cellui | Manage NetBSD Cells with Style",
                PAIR_HEADER);

  table_body = table_body_height(m, h);
  table_h = table_body + 3;
  detail_h = DETAIL_CONTENT_LINES + 2;
  table_y = 1;
  detail_y = table_y + table_h;
  status_y = detail_y + detail_h;
  help_y = status_y + 1;
  cmd_y = help_y + 2;

  if (table_y + table_h <= h) {
    draw_box(table_y, 0, table_h, w);
  }
  if (detail_y + detail_h <= h) {
    draw_box(detail_y, 0, detail_h, w);
  }

  if (table_y + 1 < h) {
    char header[128];
    (void)snprintf(header, sizeof(header),
                   "%-16s %-8s %-6s %-6s %-8s %-8s %-6s %-7s", "NAME", "STATE",
                   "CID", "PROC", "CPU1S", "CPU10S", "AUTO", "REFS");
    attrset(COLOR_PAIR(PAIR_TABLE_HEADER) | A_BOLD);
    mvhline(table_y + 1, 1, ' ', w - 2);
    mvaddnstr(table_y + 1, 1, header, w - 2);
  }

  {
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
  }

  if (table_y + 2 < h) {
    if (vis_count == 0) {
      char msg[256];
      shorten_to("No cells visible. Use ':' to run cellmgr commands directly.",
                 w - 2, msg, sizeof(msg));
      attrset(COLOR_PAIR(PAIR_PANEL));
      mvhline(table_y + 2, 1, ' ', w - 2);
      mvaddnstr(table_y + 2, 1, msg, w - 2);
    } else {
      int start = 0;
      if (m->cursor >= table_body) {
        start = m->cursor - table_body + 1;
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
          CellRow *row = &m->rows[vis[idx]];
          bool selected = (idx == m->cursor);
          char line[256];

          table_row_string(row, line, sizeof(line));

          if (selected) {
            attrset(COLOR_PAIR(PAIR_SELECTED));
            mvhline(y, 1, ' ', w - 2);
            mvaddnstr(y, 1, line, w - 2);
          } else {
            attrset(COLOR_PAIR(PAIR_PANEL));
            mvaddnstr(y, 1, line, w - 2);
            if (w > 18) {
              attrset(COLOR_PAIR(row->running ? PAIR_RUNNING : PAIR_STOPPED));
              mvaddnstr(y, 1 + 17, row->running ? "running" : "stopped", 8);
            }
          }
        }
      }
    }
  }

  if (detail_y + 1 < h) {
    CellRow *row = selected_cell(m);
    char lines[DETAIL_CONTENT_LINES][1024];
    char tmp[1024];
    int value_width = w - 16;

    if (value_width < 12) {
      value_width = 12;
    }

    if (row == NULL) {
      (void)snprintf(lines[0], sizeof(lines[0]), "No cell selected");
      for (int i = 1; i < DETAIL_CONTENT_LINES; i++) {
        lines[i][0] = '\0';
      }
    } else {
      shorten_to(blank_if(row->name, "-"), value_width, tmp, sizeof(tmp));
      format_prefixed(lines[0], sizeof(lines[0]), "Name        : ", tmp);
      (void)snprintf(lines[1], sizeof(lines[1]), "State       : %s",
                     row->running ? "running" : "stopped");
      (void)snprintf(lines[2], sizeof(lines[2]), "CID         : %s",
                     blank_if(row->cid, "-"));
      shorten_to(blank_if(row->root, "-"), value_width, tmp, sizeof(tmp));
      format_prefixed(lines[3], sizeof(lines[3]), "Root        : ", tmp);
      (void)snprintf(lines[4], sizeof(lines[4]), "Autostart   : %s",
                     blank_if(row->autostart, "NO"));
      (void)snprintf(lines[5], sizeof(lines[5]), "Procs/Refs  : %s / %s",
                     blank_if(row->procs, "0"), blank_if(row->refs, "-"));
      (void)snprintf(lines[6], sizeof(lines[6]), "CPU1S/10S   : %s / %s",
                     blank_if(row->cpu1s, "-"), blank_if(row->cpu10s, "-"));
      (void)snprintf(lines[7], sizeof(lines[7]), "Memory      : %s",
                     blank_if(row->memory, "-"));
      shorten_to(blank_if(row->supervise_cmd, "-"), value_width, tmp,
                 sizeof(tmp));
      format_prefixed(lines[8], sizeof(lines[8]), "Supervise   : ", tmp);
    }

    for (int i = 0; i < DETAIL_CONTENT_LINES; i++) {
      int y = detail_y + 1 + i;
      if (y >= h || y >= detail_y + detail_h - 1) {
        break;
      }
      attrset(COLOR_PAIR(PAIR_PANEL));
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
    const HelpBinding line1[] = {
        {"j/k", "up/down"}, {"r", "refresh"}, {"f", "filter"},
        {"enter", "shell"}, {"s", "start"},   {"x", "stop"},
        {"t", "restart"},
    };
    draw_help_line(help_y, w, line1, sizeof(line1) / sizeof(line1[0]));
  }

  if (help_y + 1 < h) {
    const HelpBinding line2[] = {
        {"a", "start all"}, {"z", "stop all"}, {"y", "restart all"},
        {"m", "theme"},     {"e", "config"},   {":", "cellmgr cmd"},
        {"q", "quit"},
    };
    draw_help_line(help_y + 1, w, line2, sizeof(line2) / sizeof(line2[0]));
  }

  if (m->mode == MODE_COMMAND && cmd_y + 2 < h) {
    char prefix[] = "cellmgr ";
    int avail;
    int prefix_len = (int)strlen(prefix);
    int input_start = 0;
    int display_len;

    draw_box(cmd_y, 0, 3, w);
    attrset(COLOR_PAIR(PAIR_PANEL));
    mvhline(cmd_y + 1, 1, ' ', w - 2);
    mvaddnstr(cmd_y + 1, 1, prefix, w - 2);

    avail = w - 2 - prefix_len;
    if (avail < 0) {
      avail = 0;
    }
    if ((int)m->cmd_len > avail) {
      input_start = (int)m->cmd_len - avail;
    }
    display_len = (int)m->cmd_len - input_start;
    if (display_len > avail) {
      display_len = avail;
    }
    if (display_len > 0) {
      mvaddnstr(cmd_y + 1, 1 + prefix_len, m->cmd_input + input_start,
                display_len);
    }

    (void)curs_set(1);
    move(cmd_y + 1, 1 + prefix_len + display_len);
  } else {
    (void)curs_set(0);
  }

  free(vis);
  refresh();
}

static void handle_command_enter(Model *m) {
  char raw[MAX_CMD_INPUT + 1];
  char *trimmed;
  char **args = NULL;
  int argc = 0;
  char *parse_err = NULL;
  const char **argv = NULL;

  (void)snprintf(raw, sizeof(raw), "%s", m->cmd_input);
  m->cmd_input[0] = '\0';
  m->cmd_len = 0;
  m->mode = MODE_NORMAL;

  trimmed = trim_inplace(raw);
  if (*trimmed == '\0') {
    set_status(m, false, "No command executed");
    return;
  }

  if (split_shell_words(trimmed, &args, &argc, &parse_err) != 0) {
    set_status(m, true, "Invalid command: %s",
               blank_if(parse_err, "parse failed"));
    free(parse_err);
    return;
  }

  argv = calloc((size_t)argc + 2, sizeof(*argv));
  if (argv == NULL) {
    free_argv(args, argc);
    set_status(m, true, "Out of memory");
    return;
  }
  argv[0] = "cellmgr";
  for (int i = 0; i < argc; i++) {
    argv[i + 1] = args[i];
  }
  argv[argc + 1] = NULL;

  set_status(m, false, "Running: cellmgr %s", trimmed);
  run_interactive_action(m, "cellmgr", true, argv, NULL, NULL);

  free((void *)argv);
  free_argv(args, argc);
}

void handle_command_key(Model *m, int ch) {
  switch (ch) {
  case 27:
    m->mode = MODE_NORMAL;
    set_status(m, false, "Command cancelled");
    break;
  case '\n':
  case '\r':
  case KEY_ENTER:
    handle_command_enter(m);
    break;
  case KEY_BACKSPACE:
  case 127:
  case 8:
    if (m->cmd_len > 0) {
      m->cmd_len--;
      m->cmd_input[m->cmd_len] = '\0';
    }
    break;
  default:
    if (ch >= 32 && ch <= 126 && m->cmd_len < MAX_CMD_INPUT) {
      m->cmd_input[m->cmd_len++] = (char)ch;
      m->cmd_input[m->cmd_len] = '\0';
    }
    break;
  }
}

void handle_normal_key(Model *m, int ch, bool *quit) {
  CellRow *row;
  char *name;

  switch (ch) {
  case 3:
  case 'q':
    *quit = true;
    return;
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
  case ':':
    m->mode = MODE_COMMAND;
    set_status(m, false,
               "Enter cellmgr command (e.g. start web, create -a -x "
               "'/bin/sleep 60' web)");
    return;
  default:
    break;
  }

  row = selected_cell(m);
  if (ch == 'a') {
    const char *argv[] = {"cellmgr", "start", "--all", NULL};
    m->loading = true;
    set_status(m, false, "Starting all cells...");
    run_capture_action(m, "Start all", true, argv);
    return;
  }
  if (ch == 'z') {
    const char *argv[] = {"cellmgr", "stop", "--all", NULL};
    m->loading = true;
    set_status(m, false, "Stopping all cells...");
    run_capture_action(m, "Stop all", true, argv);
    return;
  }
  if (ch == 'y') {
    const char *argv[] = {"cellmgr", "restart", "--all", NULL};
    m->loading = true;
    set_status(m, false, "Restarting all cells...");
    run_capture_action(m, "Restart all", true, argv);
    return;
  }

  if (row == NULL) {
    return;
  }
  name = xstrdup(blank_if(row->name, ""));

  switch (ch) {
  case 's': {
    const char *argv[] = {"cellmgr", "start", name, NULL};
    m->loading = true;
    set_status(m, false, "Starting %s...", name);
    run_capture_action(m, "Start", true, argv);
    break;
  }
  case 'x': {
    const char *argv[] = {"cellmgr", "stop", name, NULL};
    m->loading = true;
    set_status(m, false, "Stopping %s...", name);
    run_capture_action(m, "Stop", true, argv);
    break;
  }
  case 't': {
    const char *argv[] = {"cellmgr", "restart", name, NULL};
    m->loading = true;
    set_status(m, false, "Restarting %s...", name);
    run_capture_action(m, "Restart", true, argv);
    break;
  }
  case '\n':
  case '\r':
  case KEY_ENTER: {
    char ps1[256];
    const char *argv[] = {"cellctl", "exec", name, NULL};
    (void)snprintf(ps1, sizeof(ps1), "[%s] # ", name);
    m->loading = true;
    set_status(m, false, "Opening shell in %s", name);
    run_interactive_action(m, "Shell", true, argv, "PS1", ps1);
    break;
  }
  case 'e': {
    const char *argv[] = {"cellmgr", "config", name, NULL};
    m->loading = true;
    set_status(m, false, "Opening cellmgr config for %s", name);
    run_interactive_action(m, "Config", true, argv, NULL, NULL);
    break;
  }
  default:
    break;
  }

  free(name);
}
