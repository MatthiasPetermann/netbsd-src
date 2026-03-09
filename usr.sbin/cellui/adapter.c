#define _POSIX_C_SOURCE 200809L

#include "cellui.h"

#include <ctype.h>
#include <curses.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <dirent.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
  CellRow *items;
  size_t len;
  size_t cap;
} RowVec;

static void rowvec_init(RowVec *v) {
  v->items = NULL;
  v->len = 0;
  v->cap = 0;
}

static void rowvec_free(RowVec *v, bool free_items) {
  size_t i;

  if (free_items) {
    for (i = 0; i < v->len; i++) {
      free_cell_row(&v->items[i]);
    }
  }
  free(v->items);
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

static ssize_t rowvec_find_by_name(const RowVec *v, const char *name) {
  size_t i;

  for (i = 0; i < v->len; i++) {
    if (v->items[i].name != NULL && strcmp(v->items[i].name, name) == 0) {
      return (ssize_t)i;
    }
  }
  return -1;
}

static char *upper_copy(const char *src) {
  char *out;
  size_t i;

  out = xstrdup(src);
  for (i = 0; out[i] != '\0'; i++) {
    out[i] = (char)toupper((unsigned char)out[i]);
  }
  return out;
}

static int cmp_rows_by_name(const void *a, const void *b) {
  const CellRow *ra = a;
  const CellRow *rb = b;
  return strcmp(blank_if(ra->name, ""), blank_if(rb->name, ""));
}

static char *trimmed_copy(const char *s) {
  char *copy;
  char *trimmed;

  copy = xstrdup(s);
  trimmed = trim_inplace(copy);
  if (trimmed != copy) {
    memmove(copy, trimmed, strlen(trimmed) + 1);
  }
  return copy;
}

static int split_fields(const char *line, char ***fields_out, int *count_out) {
  char *copy;
  char *tok;
  char *saveptr;
  char **fields;
  int count;
  int cap;

  copy = xstrdup(line);
  fields = NULL;
  count = 0;
  cap = 0;

  for (tok = strtok_r(copy, " \t\r\n", &saveptr); tok != NULL;
       tok = strtok_r(NULL, " \t\r\n", &saveptr)) {
    if (count == cap) {
      int next_cap = (cap == 0) ? 8 : cap * 2;
      char **next = realloc(fields, (size_t)next_cap * sizeof(*next));
      if (next == NULL) {
        free(copy);
        for (int i = 0; i < count; i++) {
          free(fields[i]);
        }
        free(fields);
        return -1;
      }
      fields = next;
      cap = next_cap;
    }
    fields[count++] = xstrdup(tok);
  }

  free(copy);
  *fields_out = fields;
  *count_out = count;
  return 0;
}

static void free_fields(char **fields, int count) {
  for (int i = 0; i < count; i++) {
    free(fields[i]);
  }
  free(fields);
}

static char *join_fields(char **fields, int start, int count) {
  size_t len = 0;
  char *out;
  size_t pos = 0;

  if (start >= count) {
    return xstrdup("");
  }
  for (int i = start; i < count; i++) {
    len += strlen(fields[i]) + 1;
  }
  out = malloc(len + 1);
  if (out == NULL) {
    perror("malloc");
    exit(1);
  }
  out[0] = '\0';
  for (int i = start; i < count; i++) {
    size_t n = strlen(fields[i]);
    memcpy(out + pos, fields[i], n);
    pos += n;
    if (i < count - 1) {
      out[pos++] = ' ';
    }
  }
  out[pos] = '\0';
  return out;
}

static size_t argv_len(const char *const argv[]) {
  size_t n = 0;

  while (argv[n] != NULL) {
    n++;
  }
  return n;
}

static char **dup_exec_argv(const char *const argv[]) {
  size_t n = argv_len(argv);
  char **dup = calloc(n + 1, sizeof(*dup));

  if (dup == NULL) {
    perror("calloc");
    exit(1);
  }
  for (size_t i = 0; i < n; i++) {
    dup[i] = xstrdup(argv[i]);
  }
  dup[n] = NULL;
  return dup;
}

static void free_exec_argv(char **argv) {
  size_t i;

  if (argv == NULL) {
    return;
  }
  for (i = 0; argv[i] != NULL; i++) {
    free(argv[i]);
  }
  free(argv);
}

static void handle_loading_navigation_key(Model *m, int ch) {
  switch (ch) {
  case KEY_UP:
  case 'k':
    m->cursor--;
    clamp_cursor(m);
    break;
  case KEY_DOWN:
  case 'j':
    m->cursor++;
    clamp_cursor(m);
    break;
  case KEY_PPAGE:
    m->cursor -= table_body_height(m, m->height);
    clamp_cursor(m);
    break;
  case KEY_NPAGE:
    m->cursor += table_body_height(m, m->height);
    clamp_cursor(m);
    break;
  case 'f':
    m->filter = (FilterMode)(((int)m->filter + 1) % 3);
    clamp_cursor(m);
    break;
  case 'm':
    rotate_theme(m);
    break;
  default:
    break;
  }
}

int run_capture_command(const char *prog, const char *const argv[],
                        char **output_out, char **err_out) {
  int pipefd[2];
  pid_t pid;
  char **exec_argv;
  char *buf = NULL;
  size_t cap = 0;
  size_t len = 0;
  char tmp[4096];
  ssize_t nread;
  int status = 0;
  int flags;
  bool child_done = false;
  bool pipe_eof = false;
  char *trimmed;

  *output_out = NULL;
  *err_out = NULL;
  exec_argv = dup_exec_argv(argv);

  if (pipe(pipefd) != 0) {
    free_exec_argv(exec_argv);
    *err_out = xasprintf("pipe failed: %s", strerror(errno));
    return -1;
  }

  pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    free_exec_argv(exec_argv);
    *err_out = xasprintf("fork failed: %s", strerror(errno));
    return -1;
  }

  if (pid == 0) {
    (void)dup2(pipefd[1], STDOUT_FILENO);
    (void)dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);
    execvp(prog, exec_argv);
    fprintf(stderr, "%s: %s\n", prog, strerror(errno));
    _exit(127);
  }

  close(pipefd[1]);
  flags = fcntl(pipefd[0], F_GETFL, 0);
  if (flags >= 0) {
    (void)fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
  }

  while (!child_done || !pipe_eof) {
    for (;;) {
      nread = read(pipefd[0], tmp, sizeof(tmp));
      if (nread > 0) {
        size_t need = len + (size_t)nread + 1;
        if (need > cap) {
          size_t next_cap = (cap == 0) ? 4096 : cap;
          while (next_cap < need) {
            next_cap *= 2;
          }
          char *next = realloc(buf, next_cap);
          if (next == NULL) {
            free(buf);
            close(pipefd[0]);
            free_exec_argv(exec_argv);
            (void)waitpid(pid, NULL, 0);
            *err_out = xstrdup("out of memory");
            return -1;
          }
          buf = next;
          cap = next_cap;
        }
        memcpy(buf + len, tmp, (size_t)nread);
        len += (size_t)nread;
        continue;
      }
      if (nread == 0) {
        pipe_eof = true;
        break;
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      free(buf);
      close(pipefd[0]);
      free_exec_argv(exec_argv);
      (void)waitpid(pid, NULL, 0);
      *err_out = xasprintf("read failed: %s", strerror(errno));
      return -1;
    }

    if (!child_done) {
      pid_t wp = waitpid(pid, &status, WNOHANG);
      if (wp < 0) {
        free(buf);
        close(pipefd[0]);
        free_exec_argv(exec_argv);
        *err_out = xasprintf("waitpid failed: %s", strerror(errno));
        return -1;
      }
      if (wp == pid) {
        child_done = true;
      }
    }

    if (child_done && pipe_eof) {
      break;
    }

    if (spinner_model != NULL && spinner_model->loading) {
      int key = getch();
      if (key != ERR) {
        handle_loading_navigation_key(spinner_model, key);
      }
      draw_ui(spinner_model);
    }
    {
      struct timespec ts;
      ts.tv_sec = 0;
      ts.tv_nsec = 100000000L;
      (void)nanosleep(&ts, NULL);
    }
  }

  close(pipefd[0]);
  if (buf == NULL) {
    buf = xstrdup("");
  } else {
    buf[len] = '\0';
  }

  if (!child_done && waitpid(pid, &status, 0) < 0) {
    free(buf);
    free_exec_argv(exec_argv);
    *err_out = xasprintf("waitpid failed: %s", strerror(errno));
    return -1;
  }
  free_exec_argv(exec_argv);

  trimmed = trimmed_copy(buf);
  free(buf);
  *output_out = trimmed;

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    char *base;
    if (WIFEXITED(status)) {
      base = xasprintf("exit status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
      base = xasprintf("terminated by signal %d", WTERMSIG(status));
    } else {
      base = xstrdup("command failed");
    }
    if (!is_blank(*output_out)) {
      *err_out = xasprintf("%s: %s", base, *output_out);
    } else {
      *err_out = xstrdup(base);
    }
    free(base);
    return 1;
  }

  return 0;
}

int run_interactive_command(const char *prog, const char *const argv[],
                            const char *env_key, const char *env_val,
                            char **err_out) {
  pid_t pid;
  int status = 0;
  char **exec_argv;

  *err_out = NULL;
  exec_argv = dup_exec_argv(argv);

  (void)def_prog_mode();
  (void)endwin();
  fflush(stdout);
  fflush(stderr);

  pid = fork();
  if (pid < 0) {
    free_exec_argv(exec_argv);
    *err_out = xasprintf("fork failed: %s", strerror(errno));
    (void)reset_prog_mode();
    (void)refresh();
    return -1;
  }

  if (pid == 0) {
    if (env_key != NULL && env_val != NULL) {
      (void)setenv(env_key, env_val, 1);
    }
    execvp(prog, exec_argv);
    fprintf(stderr, "%s: %s\n", prog, strerror(errno));
    _exit(127);
  }

  if (waitpid(pid, &status, 0) < 0) {
    *err_out = xasprintf("waitpid failed: %s", strerror(errno));
  }
  free_exec_argv(exec_argv);

  (void)reset_prog_mode();
  (void)cbreak();
  (void)noecho();
  (void)keypad(stdscr, TRUE);
  (void)nodelay(stdscr, TRUE);
  (void)timeout(100);
  (void)clearok(stdscr, TRUE);
  (void)refresh();

  if (*err_out != NULL) {
    return -1;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    if (WIFEXITED(status)) {
      *err_out = xasprintf("exit status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
      *err_out = xasprintf("terminated by signal %d", WTERMSIG(status));
    } else {
      *err_out = xstrdup("command failed");
    }
    return 1;
  }

  return 0;
}

static char *unquote_double(const char *value) {
  size_t len = strlen(value);
  char *out;
  size_t j = 0;

  out = malloc(len + 1);
  if (out == NULL) {
    perror("malloc");
    exit(1);
  }

  for (size_t i = 0; i < len; i++) {
    if (value[i] == '\\' && i + 1 < len) {
      i++;
      switch (value[i]) {
      case 'n':
        out[j++] = '\n';
        break;
      case 't':
        out[j++] = '\t';
        break;
      case 'r':
        out[j++] = '\r';
        break;
      default:
        out[j++] = value[i];
        break;
      }
    } else {
      out[j++] = value[i];
    }
  }
  out[j] = '\0';
  return out;
}

static bool parse_assignment(const char *line, char **key_out,
                             char **value_out) {
  char *copy;
  char *eq;
  char *key;
  char *value;
  size_t vlen;

  *key_out = NULL;
  *value_out = NULL;

  copy = xstrdup(line);
  key = trim_inplace(copy);
  if (*key == '\0' || *key == '#') {
    free(copy);
    return false;
  }

  eq = strchr(key, '=');
  if (eq == NULL || eq == key) {
    free(copy);
    return false;
  }
  *eq = '\0';
  value = trim_inplace(eq + 1);
  key = trim_inplace(key);

  vlen = strlen(value);
  if (vlen >= 2 && value[0] == '"' && value[vlen - 1] == '"') {
    char saved = value[vlen - 1];
    char *tmp;
    value[vlen - 1] = '\0';
    tmp = unquote_double(value + 1);
    *value_out = tmp;
    value[vlen - 1] = saved;
  } else if (vlen >= 2 && value[0] == '\'' && value[vlen - 1] == '\'') {
    char saved = value[vlen - 1];
    value[vlen - 1] = '\0';
    *value_out = xstrdup(value + 1);
    value[vlen - 1] = saved;
  } else {
    *value_out = xstrdup(value);
  }

  *key_out = xstrdup(key);
  free(copy);
  return true;
}

static int read_manager_config(char *cell_data_dir, size_t sz, char **err_out) {
  const char *path;
  FILE *f;
  char *line = NULL;
  size_t linecap = 0;
  ssize_t nread;

  *err_out = NULL;
  (void)snprintf(cell_data_dir, sz, "%s", DEFAULT_CELL_DATA_DIR);

  path = getenv("CELLMGR_CONF");
  if (path == NULL || *path == '\0') {
    path = DEFAULT_CELLMGR_CONF;
  }

  f = fopen(path, "r");
  if (f == NULL) {
    if (errno == ENOENT) {
      return 0;
    }
    *err_out = xasprintf("cannot read %s: %s", path, strerror(errno));
    return -1;
  }

  while ((nread = getline(&line, &linecap, f)) >= 0) {
    char *key;
    char *value;
    (void)nread;
    if (!parse_assignment(line, &key, &value)) {
      continue;
    }
    if (strcmp(key, "CELL_DATA_DIR") == 0 && !is_blank(value)) {
      (void)snprintf(cell_data_dir, sz, "%s", trim_inplace(value));
    }
    free(key);
    free(value);
  }

  if (ferror(f)) {
    *err_out = xasprintf("error reading %s: %s", path, strerror(errno));
  }

  free(line);
  (void)fclose(f);
  return 0;
}

static int read_configured_cells(const char *data_dir, RowVec *out,
                                 char **err_out) {
  DIR *dir;
  struct dirent *de;

  *err_out = NULL;

  dir = opendir(data_dir);
  if (dir == NULL) {
    if (errno == ENOENT) {
      return 0;
    }
    *err_out = xasprintf("cannot read CELL_DATA_DIR (%s): %s", data_dir,
                         strerror(errno));
    return -1;
  }

  while ((de = readdir(dir)) != NULL) {
    char cell_dir[PATH_MAX];
    char cfg_path[PATH_MAX];
    char root_path[PATH_MAX];
    char *msg;
    struct stat st;
    FILE *f;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t nread;
    char *cell_name;
    char *autostart = NULL;
    char *supervise = NULL;
    ssize_t idx;
    CellRow *row;

    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
      continue;
    }

    if (!path_join2(cell_dir, sizeof(cell_dir), data_dir, de->d_name)) {
      msg = xasprintf("path too long: %s/%s", data_dir, de->d_name);
      append_error(err_out, msg);
      free(msg);
      continue;
    }
    if (stat(cell_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
      continue;
    }

    if (!path_join3(cfg_path, sizeof(cfg_path), data_dir, de->d_name,
                    "cell.conf")) {
      msg = xasprintf("path too long: %s/%s/cell.conf", data_dir, de->d_name);
      append_error(err_out, msg);
      free(msg);
      continue;
    }
    f = fopen(cfg_path, "r");
    if (f == NULL) {
      if (errno == ENOENT) {
        continue;
      }
      msg = xasprintf("cannot read %s: %s", cfg_path, strerror(errno));
      append_error(err_out, msg);
      free(msg);
      continue;
    }

    cell_name = xstrdup(de->d_name);
    if (!path_join3(root_path, sizeof(root_path), data_dir, de->d_name,
                    "root")) {
      msg = xasprintf("path too long: %s/%s/root", data_dir, de->d_name);
      append_error(err_out, msg);
      free(msg);
      free(cell_name);
      (void)fclose(f);
      continue;
    }

    while ((nread = getline(&line, &linecap, f)) >= 0) {
      char *key;
      char *value;
      (void)nread;
      if (!parse_assignment(line, &key, &value)) {
        continue;
      }
      if (strcmp(key, "CELL_NAME") == 0 && !is_blank(value)) {
        free(cell_name);
        cell_name = xstrdup(trim_inplace(value));
      } else if (strcmp(key, "CELL_AUTOSTART") == 0) {
        free(autostart);
        autostart = upper_copy(trim_inplace(value));
      } else if (strcmp(key, "CELL_SUPERVISE_CMD") == 0) {
        free(supervise);
        supervise = xstrdup(trim_inplace(value));
      }
      free(key);
      free(value);
    }

    if (ferror(f)) {
      msg = xasprintf("error reading %s: %s", cfg_path, strerror(errno));
      append_error(err_out, msg);
      free(msg);
    }

    free(line);
    line = NULL;
    linecap = 0;
    (void)fclose(f);

    idx = rowvec_find_by_name(out, cell_name);
    if (idx < 0) {
      row = rowvec_push(out);
    } else {
      row = &out->items[idx];
    }

    set_string(&row->name, cell_name);
    set_string(&row->root, root_path);
    if (autostart != NULL) {
      set_string(&row->autostart, autostart);
    }
    if (supervise != NULL) {
      set_string(&row->supervise_cmd, supervise);
    }

    free(cell_name);
    free(autostart);
    free(supervise);
  }

  (void)closedir(dir);
  return 0;
}

static int read_runtime_cells(RowVec *out, char **err_out) {
  char *list_output = NULL;
  char *list_err = NULL;
  char *stats_output = NULL;
  char *stats_err = NULL;
  char *line;
  char *saveptr;
  char *copy;

  *err_out = NULL;

  {
    const char *argv[] = {"cellctl", "list", NULL};
    if (run_capture_command("cellctl", argv, &list_output, &list_err) != 0) {
      *err_out = xasprintf("cellctl list failed: %s",
                           blank_if(list_err, "command failed"));
      free(list_output);
      free(list_err);
      return -1;
    }
  }

  copy = xstrdup(blank_if(list_output, ""));
  for (line = strtok_r(copy, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char **fields = NULL;
    int count = 0;
    char *trimmed = trim_inplace(line);
    ssize_t idx;
    CellRow *row;
    char *root;

    if (*trimmed == '\0' || strncmp(trimmed, "ID ", 3) == 0 ||
        strcmp(trimmed, "no cells") == 0) {
      continue;
    }
    if (split_fields(trimmed, &fields, &count) != 0) {
      continue;
    }
    if (count < 5) {
      free_fields(fields, count);
      continue;
    }

    idx = rowvec_find_by_name(out, fields[3]);
    if (idx < 0) {
      row = rowvec_push(out);
      set_string(&row->name, fields[3]);
    } else {
      row = &out->items[idx];
    }

    set_string(&row->cid, fields[0]);
    set_string(&row->refs, fields[1]);
    set_string(&row->procs, fields[2]);
    root = join_fields(fields, 4, count);
    set_string(&row->root, root);
    free(root);
    row->running = true;

    free_fields(fields, count);
  }
  free(copy);
  free(list_output);
  free(list_err);

  {
    const char *argv[] = {"cellctl", "stats", NULL};
    if (run_capture_command("cellctl", argv, &stats_output, &stats_err) != 0) {
      *err_out = xasprintf("cellctl stats failed: %s",
                           blank_if(stats_err, "command failed"));
      free(stats_output);
      free(stats_err);
      return 0;
    }
  }

  copy = xstrdup(blank_if(stats_output, ""));
  for (line = strtok_r(copy, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char **fields = NULL;
    int count = 0;
    char *trimmed = trim_inplace(line);
    ssize_t idx;
    CellRow *row;

    if (*trimmed == '\0' || strncmp(trimmed, "ID ", 3) == 0 ||
        strcmp(trimmed, "no cells") == 0) {
      continue;
    }
    if (split_fields(trimmed, &fields, &count) != 0) {
      continue;
    }
    if (count < 6) {
      free_fields(fields, count);
      continue;
    }

    idx = rowvec_find_by_name(out, fields[1]);
    if (idx < 0) {
      row = rowvec_push(out);
      set_string(&row->name, fields[1]);
    } else {
      row = &out->items[idx];
    }

    set_string(&row->cpu1s, fields[2]);
    set_string(&row->cpu10s, fields[3]);
    set_string(&row->procs, fields[4]);
    set_string(&row->memory, fields[5]);
    row->running = true;

    free_fields(fields, count);
  }

  free(copy);
  free(stats_output);
  free(stats_err);
  return 0;
}

int load_rows(CellRow **rows_out, size_t *count_out, char **err_out) {
  RowVec configured;
  RowVec runtime;
  RowVec final;
  char data_dir[PATH_MAX];
  char *cfg_err = NULL;
  char *conf_err = NULL;
  char *runtime_err = NULL;
  char *joined_err = NULL;

  *rows_out = NULL;
  *count_out = 0;
  *err_out = NULL;

  rowvec_init(&configured);
  rowvec_init(&runtime);
  rowvec_init(&final);

  (void)read_manager_config(data_dir, sizeof(data_dir), &cfg_err);
  (void)read_configured_cells(data_dir, &configured, &conf_err);
  (void)read_runtime_cells(&runtime, &runtime_err);

  for (size_t i = 0; i < runtime.len; i++) {
    CellRow *rt = &runtime.items[i];
    ssize_t idx;
    CellRow *dst;

    if (is_blank(rt->name)) {
      continue;
    }

    idx = rowvec_find_by_name(&configured, rt->name);
    if (idx < 0) {
      dst = rowvec_push(&configured);
      set_string(&dst->name, rt->name);
    } else {
      dst = &configured.items[idx];
      if (is_blank(dst->name)) {
        set_string(&dst->name, rt->name);
      }
    }

    set_string(&dst->cid, blank_if(rt->cid, ""));
    dst->running = true;
    set_string(&dst->refs, blank_if(rt->refs, ""));
    set_string(&dst->procs, blank_if(rt->procs, ""));
    if (!is_blank(rt->root)) {
      set_string(&dst->root, rt->root);
    }
    set_string(&dst->cpu1s, blank_if(rt->cpu1s, ""));
    set_string(&dst->cpu10s, blank_if(rt->cpu10s, ""));
    set_string(&dst->memory, blank_if(rt->memory, ""));
  }

  for (size_t i = 0; i < configured.len; i++) {
    CellRow *src = &configured.items[i];
    CellRow *dst;

    if (is_blank(src->name)) {
      continue;
    }
    dst = rowvec_push(&final);
    *dst = *src;
    memset(src, 0, sizeof(*src));
    if (is_blank(dst->autostart)) {
      set_string(&dst->autostart, "NO");
    }
  }

  qsort(final.items, final.len, sizeof(final.items[0]), cmp_rows_by_name);

  append_error(&joined_err, cfg_err);
  append_error(&joined_err, conf_err);
  append_error(&joined_err, runtime_err);

  free(cfg_err);
  free(conf_err);
  free(runtime_err);

  rowvec_free(&configured, true);
  rowvec_free(&runtime, true);

  *rows_out = final.items;
  *count_out = final.len;
  *err_out = joined_err;
  return 0;
}
