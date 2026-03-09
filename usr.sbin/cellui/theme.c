#include "cellui.h"

#include <ctype.h>
#include <curses.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const Theme themes[] = {
    {
        .name = "sysinst",
        .page_fg = "#D9D9D9",
        .page_bg = "#2A56A8",
        .header_fg = "#2A56A8",
        .header_bg = "#D9D9D9",
        .subheader_fg = "#D9D9D9",
        .subheader_bg = "#2A56A8",
        .help_fg = "#D9D9D9",
        .help_bg = "#2A56A8",
        .help_sep_fg = "#D9D9D9",
        .panel_fg = "#D9D9D9",
        .panel_bg = "#2A56A8",
        .panel_border_fg = "#D9D9D9",
        .table_header_fg = "#D9D9D9",
        .selected_fg = "#2A56A8",
        .selected_bg = "#D9D9D9",
        .key_fg = "#D9D9D9",
        .key_bg = "#2A56A8",
        .error_fg = "#D9D9D9",
        .running_fg = "#D9D9D9",
        .stopped_fg = "#D9D9D9",
        .state_default_fg = "#D9D9D9",
    },
    {
        .name = "mc",
        .page_fg = "#E7EEF9",
        .page_bg = "#1F3560",
        .header_fg = "#17303A",
        .header_bg = "#5FAFBF",
        .subheader_fg = "#DCE7F8",
        .subheader_bg = "#3B465E",
        .help_fg = "#DCE7F8",
        .help_bg = "#2B2B2B",
        .help_sep_fg = "#9EA7B3",
        .panel_fg = "#E7EEF9",
        .panel_bg = "#264274",
        .panel_border_fg = "#74B9CC",
        .table_header_fg = "#F3DF95",
        .selected_fg = "#1F3560",
        .selected_bg = "#5FAFBF",
        .key_fg = "#F3DF95",
        .key_bg = "#2B2B2B",
        .error_fg = "#F2ADAD",
        .running_fg = "#9FE3BC",
        .stopped_fg = "#F2ADAD",
        .state_default_fg = "#E7EEF9",
    },
    {
        .name = "amber-monitor",
        .page_fg = "#E2B56A",
        .page_bg = "#000000",
        .header_fg = "#1A1204",
        .header_bg = "#F2A65A",
        .subheader_fg = "#F0B46A",
        .subheader_bg = "#700000",
        .help_fg = "#E2B56A",
        .help_bg = "#000000",
        .help_sep_fg = "#D08A34",
        .panel_fg = "#E2B56A",
        .panel_bg = "#000000",
        .panel_border_fg = "#C78A2B",
        .table_header_fg = "#F3D7A5",
        .selected_fg = "#211200",
        .selected_bg = "#F2A65A",
        .key_fg = "#F3D7A5",
        .key_bg = "#000000",
        .error_fg = "#FF9070",
        .running_fg = "#E2B56A",
        .stopped_fg = "#C87555",
        .state_default_fg = "#E2B56A",
    },
    {
        .name = "green-monitor",
        .page_fg = "#6BEA74",
        .page_bg = "#000000",
        .header_fg = "#0F1A10",
        .header_bg = "#62D866",
        .subheader_fg = "#7AE77E",
        .subheader_bg = "#145A1A",
        .help_fg = "#6BEA74",
        .help_bg = "#000000",
        .help_sep_fg = "#49B954",
        .panel_fg = "#6BEA74",
        .panel_bg = "#000000",
        .panel_border_fg = "#2ECF3F",
        .table_header_fg = "#D6FCD9",
        .selected_fg = "#001807",
        .selected_bg = "#62D866",
        .key_fg = "#D6FCD9",
        .key_bg = "#000000",
        .error_fg = "#FF8B8B",
        .running_fg = "#6BEA74",
        .stopped_fg = "#4FAE57",
        .state_default_fg = "#6BEA74",
    },
    {
        .name = "mono-gray",
        .page_fg = "#F2F2F2",
        .page_bg = "#0F0F0F",
        .header_fg = "#080808",
        .header_bg = "#D9D9D9",
        .subheader_fg = "#E7E7E7",
        .subheader_bg = "#3D3D3D",
        .help_fg = "#DCDCDC",
        .help_bg = "#1F1F1F",
        .help_sep_fg = "#888888",
        .panel_fg = "#F2F2F2",
        .panel_bg = "#202020",
        .panel_border_fg = "#9B9B9B",
        .table_header_fg = "#F5F5F5",
        .selected_fg = "#0A0A0A",
        .selected_bg = "#BDBDBD",
        .key_fg = "#F0F0F0",
        .key_bg = "#1F1F1F",
        .error_fg = "#D0D0D0",
        .running_fg = "#F0F0F0",
        .stopped_fg = "#AAAAAA",
        .state_default_fg = "#F2F2F2",
    },
    {
        .name = "synthwave-80s",
        .page_fg = "#C9C8DC",
        .page_bg = "#07006A",
        .header_fg = "#211040",
        .header_bg = "#F25ACE",
        .subheader_fg = "#D4B1D4",
        .subheader_bg = "#7D2A76",
        .help_fg = "#D0CFDD",
        .help_bg = "#07006A",
        .help_sep_fg = "#18C6FF",
        .panel_fg = "#C9C8DC",
        .panel_bg = "#07006A",
        .panel_border_fg = "#04CCFF",
        .table_header_fg = "#FFF68F",
        .selected_fg = "#190027",
        .selected_bg = "#19C7F3",
        .key_fg = "#FFF68F",
        .key_bg = "#07006A",
        .error_fg = "#FF7CA8",
        .running_fg = "#53D5FF",
        .stopped_fg = "#FF7ACE",
        .state_default_fg = "#C9C8DC",
    },
};

static const size_t theme_count = sizeof(themes) / sizeof(themes[0]);

static bool theme_index_by_name(const char *name, int *index_out) {
  size_t i;

  if (name == NULL || *name == '\0') {
    return false;
  }
  for (i = 0; i < theme_count; i++) {
    if (strcmp(themes[i].name, name) == 0) {
      *index_out = (int)i;
      return true;
    }
  }
  return false;
}

static bool cellui_rc_path(char *dst, size_t dstsz) {
  const char *home;

  home = getenv("HOME");
  if (home == NULL || *home == '\0') {
    return false;
  }
  return path_join2(dst, dstsz, home, ".celluirc");
}

typedef struct {
  const char *hex;
  short id;
} ColorCacheEntry;

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static bool parse_hex_rgb(const char *hex, int *r, int *g, int *b) {
  int hi;
  int lo;

  if (hex == NULL || strlen(hex) != 7 || hex[0] != '#') {
    return false;
  }
  hi = hex_nibble(hex[1]);
  lo = hex_nibble(hex[2]);
  if (hi < 0 || lo < 0) {
    return false;
  }
  *r = hi * 16 + lo;

  hi = hex_nibble(hex[3]);
  lo = hex_nibble(hex[4]);
  if (hi < 0 || lo < 0) {
    return false;
  }
  *g = hi * 16 + lo;

  hi = hex_nibble(hex[5]);
  lo = hex_nibble(hex[6]);
  if (hi < 0 || lo < 0) {
    return false;
  }
  *b = hi * 16 + lo;

  return true;
}

static long color_distance_sq(int r1, int g1, int b1, int r2, int g2, int b2) {
  long dr = (long)r1 - (long)r2;
  long dg = (long)g1 - (long)g2;
  long db = (long)b1 - (long)b2;
  return dr * dr + dg * dg + db * db;
}

static void xterm_index_rgb(int idx, int *r, int *g, int *b) {
  static const int table16[16][3] = {
      {0, 0, 0},       {205, 0, 0},   {0, 205, 0},   {205, 205, 0},
      {0, 0, 238},     {205, 0, 205}, {0, 205, 205}, {229, 229, 229},
      {127, 127, 127}, {255, 0, 0},   {0, 255, 0},   {255, 255, 0},
      {92, 92, 255},   {255, 0, 255}, {0, 255, 255}, {255, 255, 255},
  };

  if (idx < 16) {
    *r = table16[idx][0];
    *g = table16[idx][1];
    *b = table16[idx][2];
    return;
  }
  if (idx >= 16 && idx <= 231) {
    static const int lvl[6] = {0, 95, 135, 175, 215, 255};
    int n = idx - 16;
    int ri = n / 36;
    int gi = (n / 6) % 6;
    int bi = n % 6;
    *r = lvl[ri];
    *g = lvl[gi];
    *b = lvl[bi];
    return;
  }
  if (idx >= 232 && idx <= 255) {
    int v = 8 + (idx - 232) * 10;
    *r = v;
    *g = v;
    *b = v;
    return;
  }
  *r = 0;
  *g = 0;
  *b = 0;
}

static short nearest_xterm_color(int r, int g, int b) {
  int best = 0;
  long best_dist = LONG_MAX;
  int max = (COLORS < 256) ? COLORS : 256;

  for (int i = 0; i < max; i++) {
    int cr, cg, cb;
    long dist;
    xterm_index_rgb(i, &cr, &cg, &cb);
    dist = color_distance_sq(r, g, b, cr, cg, cb);
    if (dist < best_dist) {
      best_dist = dist;
      best = i;
    }
  }
  return (short)best;
}

static short nearest_basic_color(int r, int g, int b) {
  static const short colors[8] = {
      COLOR_BLACK, COLOR_RED,     COLOR_GREEN, COLOR_YELLOW,
      COLOR_BLUE,  COLOR_MAGENTA, COLOR_CYAN,  COLOR_WHITE,
  };
  int best = 0;
  long best_dist = LONG_MAX;

  for (int i = 0; i < 8; i++) {
    int cr, cg, cb;
    long dist;
    xterm_index_rgb(i, &cr, &cg, &cb);
    dist = color_distance_sq(r, g, b, cr, cg, cb);
    if (dist < best_dist) {
      best_dist = dist;
      best = i;
    }
  }
  return colors[best];
}

static short resolve_theme_color(const char *hex, bool use_custom,
                                 short *next_custom, ColorCacheEntry *cache,
                                 size_t *cache_len) {
  int r, g, b;

  if (!parse_hex_rgb(hex, &r, &g, &b)) {
    return COLOR_WHITE;
  }

  if (use_custom) {
    for (size_t i = 0; i < *cache_len; i++) {
      if (strcmp(cache[i].hex, hex) == 0) {
        return cache[i].id;
      }
    }
    if (*next_custom < COLORS) {
      short id = *next_custom;
      int cr = (r * 1000 + 127) / 255;
      int cg = (g * 1000 + 127) / 255;
      int cb = (b * 1000 + 127) / 255;

      (void)init_color(id, cr, cg, cb);
      if (*cache_len < 48) {
        cache[*cache_len].hex = hex;
        cache[*cache_len].id = id;
        (*cache_len)++;
      }
      (*next_custom)++;
      return id;
    }
  }

  if (COLORS >= 256) {
    return nearest_xterm_color(r, g, b);
  }
  return nearest_basic_color(r, g, b);
}

static void apply_theme_colors(const Theme *t) {
  ColorCacheEntry cache[48];
  size_t cache_len = 0;
  bool use_custom = false;
  short next_custom = 16;
  short page_fg;
  short page_bg;
  short header_fg;
  short header_bg;
  short subheader_fg;
  short subheader_bg;
  short help_fg;
  short help_bg;
  short help_sep_fg;
  short panel_fg;
  short panel_bg;
  short panel_border_fg;
  short table_header_fg;
  short selected_fg;
  short selected_bg;
  short key_fg;
  short key_bg;
  short error_fg;
  short running_fg;
  short stopped_fg;
  short state_default_fg;

  if (!has_color) {
    return;
  }
  if (can_change_color() && COLORS >= 64) {
    int base = COLORS - 48;
    if (base < 16) {
      base = 16;
    }
    use_custom = true;
    next_custom = (short)base;
  }

  page_fg = resolve_theme_color(t->page_fg, use_custom, &next_custom, cache,
                                &cache_len);
  page_bg = resolve_theme_color(t->page_bg, use_custom, &next_custom, cache,
                                &cache_len);
  header_fg = resolve_theme_color(t->header_fg, use_custom, &next_custom, cache,
                                  &cache_len);
  header_bg = resolve_theme_color(t->header_bg, use_custom, &next_custom, cache,
                                  &cache_len);
  subheader_fg = resolve_theme_color(t->subheader_fg, use_custom, &next_custom,
                                     cache, &cache_len);
  subheader_bg = resolve_theme_color(t->subheader_bg, use_custom, &next_custom,
                                     cache, &cache_len);
  help_fg = resolve_theme_color(t->help_fg, use_custom, &next_custom, cache,
                                &cache_len);
  help_bg = resolve_theme_color(t->help_bg, use_custom, &next_custom, cache,
                                &cache_len);
  help_sep_fg = resolve_theme_color(t->help_sep_fg, use_custom, &next_custom,
                                    cache, &cache_len);
  panel_fg = resolve_theme_color(t->panel_fg, use_custom, &next_custom, cache,
                                 &cache_len);
  panel_bg = resolve_theme_color(t->panel_bg, use_custom, &next_custom, cache,
                                 &cache_len);
  panel_border_fg = resolve_theme_color(t->panel_border_fg, use_custom,
                                        &next_custom, cache, &cache_len);
  table_header_fg = resolve_theme_color(t->table_header_fg, use_custom,
                                        &next_custom, cache, &cache_len);
  selected_fg = resolve_theme_color(t->selected_fg, use_custom, &next_custom,
                                    cache, &cache_len);
  selected_bg = resolve_theme_color(t->selected_bg, use_custom, &next_custom,
                                    cache, &cache_len);
  key_fg = resolve_theme_color(t->key_fg, use_custom, &next_custom, cache,
                               &cache_len);
  key_bg = resolve_theme_color(t->key_bg, use_custom, &next_custom, cache,
                               &cache_len);
  error_fg = resolve_theme_color(t->error_fg, use_custom, &next_custom, cache,
                                 &cache_len);
  running_fg = resolve_theme_color(t->running_fg, use_custom, &next_custom,
                                   cache, &cache_len);
  stopped_fg = resolve_theme_color(t->stopped_fg, use_custom, &next_custom,
                                   cache, &cache_len);
  state_default_fg = resolve_theme_color(t->state_default_fg, use_custom,
                                         &next_custom, cache, &cache_len);

  (void)init_pair(PAIR_PAGE, page_fg, page_bg);
  (void)init_pair(PAIR_HEADER, header_fg, header_bg);
  (void)init_pair(PAIR_SUBHEADER, subheader_fg, subheader_bg);
  (void)init_pair(PAIR_HELP, help_fg, help_bg);
  (void)init_pair(PAIR_HELP_SEP, help_sep_fg, help_bg);
  (void)init_pair(PAIR_PANEL, panel_fg, panel_bg);
  (void)init_pair(PAIR_PANEL_BORDER, panel_border_fg, panel_bg);
  (void)init_pair(PAIR_TABLE_HEADER, table_header_fg, panel_bg);
  (void)init_pair(PAIR_SELECTED, selected_fg, selected_bg);
  (void)init_pair(PAIR_KEY, key_fg, key_bg);
  (void)init_pair(PAIR_ERROR, error_fg, subheader_bg);
  (void)init_pair(PAIR_RUNNING, running_fg, panel_bg);
  (void)init_pair(PAIR_STOPPED, stopped_fg, panel_bg);
  (void)init_pair(PAIR_STATE_DEFAULT, state_default_fg, panel_bg);
}

const Theme *current_theme(const Model *m) {
  if (m->theme_index < 0 || (size_t)m->theme_index >= theme_count) {
    return &themes[0];
  }
  return &themes[m->theme_index];
}

void apply_theme(Model *m, int index) {
  if ((size_t)index >= theme_count || index < 0) {
    index = 0;
  }
  m->theme_index = index;
  apply_theme_colors(current_theme(m));
}

void rotate_theme(Model *m) {
  int next = m->theme_index + 1;
  if ((size_t)next >= theme_count) {
    next = 0;
  }
  apply_theme(m, next);
  save_theme_preference(m);
  set_status(m, false, "Theme switched to %s", current_theme(m)->name);
}

void load_theme_preference(Model *m) {
  FILE *fp;
  char path[PATH_MAX];
  char line[256];
  int idx;

  if (!cellui_rc_path(path, sizeof(path))) {
    return;
  }

  fp = fopen(path, "r");
  if (fp == NULL) {
    return;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    char *s;

    s = trim_inplace(line);
    if (strncmp(s, "theme=", 6) != 0) {
      continue;
    }
    s += 6;
    while (*s != '\0' && isspace((unsigned char)*s)) {
      s++;
    }
    if (theme_index_by_name(s, &idx)) {
      m->theme_index = idx;
      break;
    }
  }

  (void)fclose(fp);
}

void save_theme_preference(const Model *m) {
  FILE *fp;
  char path[PATH_MAX];

  if (!cellui_rc_path(path, sizeof(path))) {
    return;
  }

  fp = fopen(path, "w");
  if (fp == NULL) {
    return;
  }
  (void)fprintf(fp, "theme=%s\n", current_theme(m)->name);
  (void)fclose(fp);
}
