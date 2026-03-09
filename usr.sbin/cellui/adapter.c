#define _POSIX_C_SOURCE 200809L

#include "cellui.h"

#include <ctype.h>
#include <curses.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
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

#define IPC_PROTOCOL_VERSION 1
#define IPC_HEADER_MAX 256
#define IPC_TYPE_MAX 15
#define IPC_MAX_PAYLOAD (64U * 1024U * 1024U)

typedef struct {
  bool active;
  pid_t pid;
  int to_fd;
  int from_fd;
  unsigned long long next_id;
  bool disconnected;
  char *disconnect_reason;
} IpcBridge;

typedef struct {
  int version;
  char type[IPC_TYPE_MAX + 1];
  unsigned long long id;
  unsigned long long p1;
  unsigned long long p2;
  unsigned long long p3;
  unsigned long long len;
} IpcHeader;

static IpcBridge ipc_bridge = {
    .active = false,
    .pid = -1,
    .to_fd = -1,
    .from_fd = -1,
    .next_id = 1,
    .disconnected = false,
    .disconnect_reason = NULL,
};

static bool ipc_start(char **err_out);

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

static void ipc_set_disconnected(const char *reason) {
  ipc_bridge.disconnected = true;
  free(ipc_bridge.disconnect_reason);
  ipc_bridge.disconnect_reason =
      xstrdup(blank_if(reason, "cellmgr bridge disconnected"));
}

static void ipc_clear_disconnected(void) {
  ipc_bridge.disconnected = false;
  free(ipc_bridge.disconnect_reason);
  ipc_bridge.disconnect_reason = NULL;
}

static bool fd_write_all(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;

  while (len > 0) {
    ssize_t n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (n == 0) {
      return false;
    }
    p += (size_t)n;
    len -= (size_t)n;
  }
  return true;
}

static bool fd_wait_readable_with_spinner(int fd) {
  struct pollfd pfd;

  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  for (;;) {
    int rc = poll(&pfd, 1, 120);
    if (rc > 0) {
      if ((pfd.revents & (POLLIN | POLLHUP)) != 0) {
        return true;
      }
      if ((pfd.revents & POLLERR) != 0) {
        errno = EIO;
        return false;
      }
      continue;
    }
    if (rc == 0) {
      if (spinner_model != NULL && spinner_model->loading && !isendwin()) {
        draw_ui(spinner_model);
      }
      continue;
    }
    if (errno == EINTR) {
      continue;
    }
    return false;
  }
}

static bool fd_read_all(int fd, void *buf, size_t len) {
  unsigned char *p = buf;

  while (len > 0) {
    if (!fd_wait_readable_with_spinner(fd)) {
      return false;
    }
    ssize_t n = read(fd, p, len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (n == 0) {
      return false;
    }
    p += (size_t)n;
    len -= (size_t)n;
  }
  return true;
}

static bool fd_read_line(int fd, char *buf, size_t bufsz) {
  size_t pos = 0;

  if (bufsz == 0) {
    return false;
  }

  while (pos + 1 < bufsz) {
    char c;

    if (!fd_wait_readable_with_spinner(fd)) {
      return false;
    }
    ssize_t n = read(fd, &c, 1);

    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (n == 0) {
      return false;
    }
    if (c == '\n') {
      buf[pos] = '\0';
      return true;
    }
    buf[pos++] = c;
  }

  buf[bufsz - 1] = '\0';
  return false;
}

static bool parse_ipc_header(const char *line, IpcHeader *hdr) {
  int scanned;

  memset(hdr, 0, sizeof(*hdr));
  scanned = sscanf(line, "M %d %15s %llu %llu %llu %llu %llu", &hdr->version,
                   hdr->type, &hdr->id, &hdr->p1, &hdr->p2, &hdr->p3,
                   &hdr->len);
  if (scanned != 7) {
    return false;
  }
  if (hdr->version != IPC_PROTOCOL_VERSION) {
    return false;
  }
  if (hdr->len > IPC_MAX_PAYLOAD) {
    return false;
  }
  return true;
}

static void ipc_mark_down(void) {
  if (ipc_bridge.to_fd >= 0) {
    close(ipc_bridge.to_fd);
  }
  if (ipc_bridge.from_fd >= 0) {
    close(ipc_bridge.from_fd);
  }
  if (ipc_bridge.pid > 0) {
    (void)waitpid(ipc_bridge.pid, NULL, 0);
  }
  ipc_bridge.active = false;
  ipc_bridge.pid = -1;
  ipc_bridge.to_fd = -1;
  ipc_bridge.from_fd = -1;
}

void shutdown_command_bridge(void) {
  if (ipc_bridge.active) {
    const char *bye = "M 1 BYE 0 0 0 0 0\n";
    (void)fd_write_all(ipc_bridge.to_fd, bye, strlen(bye));
  }
  ipc_mark_down();
}

bool command_bridge_is_disconnected(void) {
  return ipc_bridge.disconnected;
}

const char *command_bridge_disconnect_reason(void) {
  return blank_if(ipc_bridge.disconnect_reason, "cellmgr bridge disconnected");
}

int command_bridge_reconnect(char **err_out) {
  char *ipc_err = NULL;

  *err_out = NULL;
  ipc_mark_down();
  if (!ipc_start(&ipc_err)) {
    ipc_set_disconnected(blank_if(ipc_err, "reconnect failed"));
    *err_out = xstrdup(blank_if(ipc_err, "reconnect failed"));
    free(ipc_err);
    return -1;
  }

  ipc_clear_disconnected();
  free(ipc_err);
  return 0;
}

static bool ipc_send_frame(const char *type, unsigned long long id,
                           unsigned long long p1, unsigned long long p2,
                           unsigned long long p3, const void *payload,
                           size_t payload_len, char **err_out) {
  char header[IPC_HEADER_MAX];
  int n;

  *err_out = NULL;
  n = snprintf(header, sizeof(header), "M %d %s %llu %llu %llu %llu %zu\n",
               IPC_PROTOCOL_VERSION, type, id, p1, p2, p3, payload_len);
  if (n <= 0 || (size_t)n >= sizeof(header)) {
    *err_out = xstrdup("failed to build IPC header");
    return false;
  }
  if (!fd_write_all(ipc_bridge.to_fd, header, (size_t)n)) {
    *err_out = xasprintf("ipc write failed: %s", strerror(errno));
    return false;
  }
  if (payload_len > 0 && payload != NULL &&
      !fd_write_all(ipc_bridge.to_fd, payload, payload_len)) {
    *err_out = xasprintf("ipc payload write failed: %s", strerror(errno));
    return false;
  }
  return true;
}

static bool ipc_read_frame(IpcHeader *hdr, unsigned char **payload_out,
                           size_t *payload_len_out, char **err_out) {
  char line[IPC_HEADER_MAX];
  unsigned char *payload = NULL;

  *payload_out = NULL;
  *payload_len_out = 0;
  *err_out = NULL;

  if (!fd_read_line(ipc_bridge.from_fd, line, sizeof(line))) {
    *err_out = xasprintf("ipc read header failed: %s", strerror(errno));
    return false;
  }
  if (!parse_ipc_header(line, hdr)) {
    *err_out = xasprintf("invalid ipc header: %s", line);
    return false;
  }

  if (hdr->len > 0) {
    size_t payload_len = (size_t)hdr->len;
    payload = malloc(payload_len + 1);
    if (payload == NULL) {
      *err_out = xstrdup("out of memory");
      return false;
    }
    if (!fd_read_all(ipc_bridge.from_fd, payload, payload_len)) {
      free(payload);
      *err_out = xasprintf("ipc read payload failed: %s", strerror(errno));
      return false;
    }
    payload[payload_len] = '\0';
    *payload_out = payload;
    *payload_len_out = payload_len;
  }

  return true;
}

static bool ipc_start(char **err_out) {
  int req_pipe[2] = {-1, -1};
  int res_pipe[2] = {-1, -1};
  pid_t pid;
  IpcHeader hdr;
  unsigned char *payload = NULL;
  size_t payload_len = 0;
  char *ipc_err = NULL;

  *err_out = NULL;
  if (ipc_bridge.active) {
    return true;
  }

  if (pipe(req_pipe) != 0 || pipe(res_pipe) != 0) {
    if (req_pipe[0] >= 0)
      close(req_pipe[0]);
    if (req_pipe[1] >= 0)
      close(req_pipe[1]);
    if (res_pipe[0] >= 0)
      close(res_pipe[0]);
    if (res_pipe[1] >= 0)
      close(res_pipe[1]);
    *err_out = xasprintf("pipe failed: %s", strerror(errno));
    return false;
  }

  pid = fork();
  if (pid < 0) {
    close(req_pipe[0]);
    close(req_pipe[1]);
    close(res_pipe[0]);
    close(res_pipe[1]);
    *err_out = xasprintf("fork failed: %s", strerror(errno));
    return false;
  }

  if (pid == 0) {
    int devnull;
    const char *srv_argv[] = {"cellmgr", "ipc", "serve", "--stdio", NULL};
    char **exec_argv = dup_exec_argv(srv_argv);

    (void)dup2(req_pipe[0], STDIN_FILENO);
    (void)dup2(res_pipe[1], STDOUT_FILENO);
    devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      (void)dup2(devnull, STDERR_FILENO);
      close(devnull);
    }

    close(req_pipe[0]);
    close(req_pipe[1]);
    close(res_pipe[0]);
    close(res_pipe[1]);

    execvp("cellmgr", exec_argv);
    free_exec_argv(exec_argv);
    _exit(127);
  }

  close(req_pipe[0]);
  close(res_pipe[1]);

  ipc_bridge.pid = pid;
  ipc_bridge.to_fd = req_pipe[1];
  ipc_bridge.from_fd = res_pipe[0];
  ipc_bridge.active = true;
  ipc_bridge.next_id = 1;

  if (!ipc_send_frame("HELLO", 0, 0, 0, 0, NULL, 0, &ipc_err)) {
    *err_out = xasprintf("ipc hello send failed: %s", blank_if(ipc_err, "error"));
    free(ipc_err);
    ipc_mark_down();
    return false;
  }
  if (!ipc_read_frame(&hdr, &payload, &payload_len, &ipc_err)) {
    *err_out = xasprintf("ipc hello read failed: %s", blank_if(ipc_err, "error"));
    free(ipc_err);
    free(payload);
    ipc_mark_down();
    return false;
  }
  free(payload);

  if (strcmp(hdr.type, "HELLO") != 0) {
    *err_out = xasprintf("unexpected ipc handshake response: %s", hdr.type);
    ipc_mark_down();
    return false;
  }

  ipc_clear_disconnected();

  return true;
}

static bool build_call_payload(const char *prog, const char *const argv[],
                               const char *env_key, const char *env_val,
                               char **payload_out, size_t *payload_len_out,
                               unsigned long long *argc_out,
                               unsigned long long *flags_out,
                               char **err_out) {
  size_t start = 0;
  size_t argc = 0;
  size_t payload_len = 0;
  char *payload;
  size_t off = 0;

  *payload_out = NULL;
  *payload_len_out = 0;
  *argc_out = 0;
  *flags_out = 0;
  *err_out = NULL;

  if (argv == NULL) {
    *err_out = xstrdup("missing argv");
    return false;
  }
  if (argv[0] != NULL && prog != NULL && strcmp(argv[0], prog) == 0) {
    start = 1;
  }

  if (env_key != NULL || env_val != NULL) {
    if (is_blank(env_key) || env_val == NULL) {
      *err_out = xstrdup("invalid env override");
      return false;
    }
    if (strchr(env_key, '\n') != NULL || strchr(env_val, '\n') != NULL) {
      *err_out = xstrdup("env override contains newline");
      return false;
    }
    payload_len += strlen(env_key) + 1;
    payload_len += strlen(env_val) + 1;
    *flags_out = 1;
  }

  for (size_t i = start; argv[i] != NULL; i++) {
    const char *arg = argv[i];
    if (strchr(arg, '\n') != NULL) {
      *err_out = xasprintf("argument contains newline and cannot be sent over ipc: %s", arg);
      return false;
    }
    payload_len += strlen(arg) + 1;
    argc++;
  }

  if (payload_len > IPC_MAX_PAYLOAD) {
    *err_out = xstrdup("ipc request payload too large");
    return false;
  }

  payload = malloc(payload_len == 0 ? 1 : payload_len);
  if (payload == NULL) {
    *err_out = xstrdup("out of memory");
    return false;
  }

  if (*flags_out == 1) {
    size_t n = strlen(env_key);
    memcpy(payload + off, env_key, n);
    off += n;
    payload[off++] = '\n';

    n = strlen(env_val);
    memcpy(payload + off, env_val, n);
    off += n;
    payload[off++] = '\n';
  }

  for (size_t i = start; argv[i] != NULL; i++) {
    size_t alen = strlen(argv[i]);
    memcpy(payload + off, argv[i], alen);
    off += alen;
    payload[off++] = '\n';
  }

  *payload_out = payload;
  *payload_len_out = payload_len;
  *argc_out = (unsigned long long)argc;
  return true;
}

static int ipc_call_command(int mode, const char *prog, const char *const argv[],
                            const char *env_key, const char *env_val,
                            int *cmd_rc_out, char **stdout_out,
                            char **stderr_out, char **transport_err_out) {
  IpcHeader hdr;
  char *payload = NULL;
  size_t payload_len = 0;
  unsigned long long argc = 0;
  unsigned long long flags = 0;
  unsigned long long id;
  unsigned char *resp_payload = NULL;
  size_t resp_len = 0;
  char *ipc_err = NULL;

  *cmd_rc_out = 0;
  *stdout_out = xstrdup("");
  *stderr_out = xstrdup("");
  *transport_err_out = NULL;

  if (!ipc_start(&ipc_err)) {
    *transport_err_out = xasprintf("ipc start failed: %s", blank_if(ipc_err, "error"));
    free(ipc_err);
    return -1;
  }

  if (!build_call_payload(prog, argv, env_key, env_val, &payload,
                          &payload_len, &argc, &flags, &ipc_err)) {
    free(*stderr_out);
    *stderr_out = xstrdup(blank_if(ipc_err, "invalid request"));
    *cmd_rc_out = 1;
    free(ipc_err);
    return 0;
  }

  id = ipc_bridge.next_id++;
  if (!ipc_send_frame("CALL", id, (unsigned long long)mode, argc, flags,
                      payload,
                      payload_len, &ipc_err)) {
    *transport_err_out = xasprintf("ipc call send failed: %s", blank_if(ipc_err, "error"));
    free(ipc_err);
    free(payload);
    return -1;
  }
  free(payload);

  if (!ipc_read_frame(&hdr, &resp_payload, &resp_len, &ipc_err)) {
    *transport_err_out = xasprintf("ipc call read failed: %s", blank_if(ipc_err, "error"));
    free(ipc_err);
    free(resp_payload);
    return -1;
  }

  if (strcmp(hdr.type, "ERR") == 0) {
    free(*stderr_out);
    *stderr_out = (resp_payload != NULL) ? trimmed_copy((const char *)resp_payload)
                                         : xstrdup("ipc error");
    *cmd_rc_out = (hdr.p1 == 0) ? 1 : (int)hdr.p1;
    free(resp_payload);
    return 0;
  }

  if (strcmp(hdr.type, "RET") != 0 || hdr.id != id) {
    *transport_err_out = xasprintf("unexpected ipc response: type=%s id=%llu", hdr.type,
                                   hdr.id);
    free(resp_payload);
    return -1;
  }

  {
    size_t out_len = (size_t)hdr.p2;
    size_t err_len = (size_t)hdr.p3;
    char *out_buf;
    char *err_buf;

    if (out_len + err_len != resp_len) {
      *transport_err_out = xstrdup("ipc response length mismatch");
      free(resp_payload);
      return -1;
    }

    out_buf = malloc(out_len + 1);
    err_buf = malloc(err_len + 1);
    if (out_buf == NULL || err_buf == NULL) {
      free(out_buf);
      free(err_buf);
      free(resp_payload);
      *transport_err_out = xstrdup("out of memory");
      return -1;
    }

    if (out_len > 0) {
      memcpy(out_buf, resp_payload, out_len);
    }
    out_buf[out_len] = '\0';

    if (err_len > 0) {
      memcpy(err_buf, resp_payload + out_len, err_len);
    }
    err_buf[err_len] = '\0';

    free(*stdout_out);
    free(*stderr_out);
    *stdout_out = out_buf;
    *stderr_out = err_buf;
    *cmd_rc_out = (int)hdr.p1;
  }

  free(resp_payload);
  return 0;
}

static char *concat_streams(const char *a, const char *b) {
  size_t alen = strlen(blank_if(a, ""));
  size_t blen = strlen(blank_if(b, ""));
  char *buf = malloc(alen + blen + 1);

  if (buf == NULL) {
    return xstrdup("");
  }
  if (alen > 0) {
    memcpy(buf, a, alen);
  }
  if (blen > 0) {
    memcpy(buf + alen, b, blen);
  }
  buf[alen + blen] = '\0';
  return buf;
}

int run_capture_command(const char *prog, const char *const argv[],
                        char **output_out, char **err_out) {
  int cmd_rc = 0;
  int ipc_rc;
  char *out = NULL;
  char *err = NULL;
  char *transport_err = NULL;
  char *combined = NULL;
  char *trimmed = NULL;

  *output_out = NULL;
  *err_out = NULL;

  ipc_rc = ipc_call_command(0, prog, argv, NULL, NULL, &cmd_rc, &out, &err,
                            &transport_err);
  if (ipc_rc != 0) {
    ipc_set_disconnected(blank_if(transport_err, "bridge unavailable"));
    shutdown_command_bridge();
    *err_out = xasprintf("ipc command failed: %s",
                         blank_if(transport_err, "bridge unavailable"));
    free(out);
    free(err);
    free(transport_err);
    return -1;
  }

  combined = concat_streams(blank_if(out, ""), blank_if(err, ""));
  trimmed = trimmed_copy(combined);
  *output_out = trimmed;

  if (cmd_rc != 0) {
    char *base = xasprintf("exit status %d", cmd_rc);
    if (!is_blank(*output_out)) {
      *err_out = xasprintf("%s: %s", base, *output_out);
    } else {
      *err_out = xstrdup(base);
    }
    free(base);
    free(out);
    free(err);
    free(combined);
    return 1;
  }

  free(out);
  free(err);
  free(combined);
  return 0;
}

int run_interactive_command(const char *prog, const char *const argv[],
                            const char *env_key, const char *env_val,
                            char **err_out) {
  int cmd_rc = 0;
  int ipc_rc;
  char *out = NULL;
  char *err = NULL;
  char *transport_err = NULL;

  *err_out = NULL;

  (void)def_prog_mode();
  (void)endwin();
  fflush(stdout);
  fflush(stderr);

  ipc_rc = ipc_call_command(1, prog, argv, env_key, env_val, &cmd_rc, &out,
                            &err, &transport_err);

  (void)reset_prog_mode();
  (void)cbreak();
  (void)noecho();
  (void)keypad(stdscr, TRUE);
  (void)nodelay(stdscr, TRUE);
  (void)timeout(100);
  (void)clearok(stdscr, TRUE);
  (void)refresh();

  if (ipc_rc != 0) {
    ipc_set_disconnected(blank_if(transport_err, "bridge unavailable"));
    shutdown_command_bridge();
    *err_out = xasprintf("ipc command failed: %s",
                         blank_if(transport_err, "bridge unavailable"));
    free(out);
    free(err);
    free(transport_err);
    return -1;
  }

  if (cmd_rc != 0) {
    if (!is_blank(err)) {
      *err_out = xasprintf("exit status %d: %s", cmd_rc, err);
    } else {
      *err_out = xasprintf("exit status %d", cmd_rc);
    }
    free(out);
    free(err);
    return 1;
  }

  free(out);
  free(err);
  return 0;
}

static int split_tsv_fixed(char *line, char **fields, int expected) {
  int count = 0;
  char *p = line;
  char *start = line;

  while (count < expected) {
    if (*p == '\t' || *p == '\0') {
      fields[count++] = start;
      if (*p == '\0') {
        break;
      }
      *p = '\0';
      start = p + 1;
    }
    p++;
  }

  if (count < expected) {
    return -1;
  }
  if (*p != '\0') {
    return -1;
  }
  return 0;
}

static bool parse_tsv_bool(const char *value, bool *ok_out) {
  const char *v = blank_if(value, "");

  if (strcmp(v, "1") == 0 || strcasecmp(v, "yes") == 0 ||
      strcasecmp(v, "true") == 0) {
    *ok_out = true;
    return true;
  }
  if (strcmp(v, "0") == 0 || strcasecmp(v, "no") == 0 ||
      strcasecmp(v, "false") == 0 || *v == '\0') {
    *ok_out = true;
    return false;
  }

  *ok_out = false;
  return false;
}

int load_rows(CellRow **rows_out, size_t *count_out, char **err_out) {
  RowVec out;
  char *output = NULL;
  char *cmd_err = NULL;
  char *copy;
  char *line;
  char *saveptr;
  size_t line_no;
  size_t malformed_lines;
  size_t first_bad_line;
  const char *argv[] = {
      "cellmgr",
      "cell",
      "list",
      "--view",
      "merged",
      "-T",
      "-H",
      "-o",
      "name,cid,refs,procs,root,autostart,create_profile,create_reserved_ports,"
      "create_rlimit_nofile,create_rlimit_as,create_rlimit_core,"
      "supervise_cmd,cpu1s,cpu10s,memory,age,running,manifest",
      NULL,
  };

  *rows_out = NULL;
  *count_out = 0;
  *err_out = NULL;
  rowvec_init(&out);

  if (run_capture_command("cellmgr", argv, &output, &cmd_err) != 0) {
    *err_out = xasprintf("cellmgr cell list failed: %s",
                         blank_if(cmd_err, "command failed"));
    free(output);
    free(cmd_err);
    return -1;
  }

  copy = xstrdup(blank_if(output, ""));
  line_no = 0;
  malformed_lines = 0;
  first_bad_line = 0;
  for (line = strtok_r(copy, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char *fields[18];
    CellRow *row;
    bool running_ok;
    bool manifest_ok;
    bool running;
    bool manifest_present;

    line_no++;

    if (*line == '\0') {
      continue;
    }
    if (strchr(line, '\t') == NULL) {
      continue;
    }
    if (split_tsv_fixed(line, fields, 18) != 0) {
      malformed_lines++;
      if (first_bad_line == 0)
        first_bad_line = line_no;
      continue;
    }
    running = parse_tsv_bool(fields[16], &running_ok);
    manifest_present = parse_tsv_bool(fields[17], &manifest_ok);
    if (!running_ok || !manifest_ok) {
      malformed_lines++;
      if (first_bad_line == 0)
        first_bad_line = line_no;
      continue;
    }

    row = rowvec_push(&out);
    set_string(&row->name, fields[0]);
    set_string(&row->cid, fields[1]);
    set_string(&row->refs, fields[2]);
    set_string(&row->procs, fields[3]);
    set_string(&row->root, fields[4]);
    set_string(&row->autostart, is_blank(fields[5]) ? "NO" : fields[5]);
    set_string(&row->create_profile, fields[6]);
    set_string(&row->create_reserved_ports, fields[7]);
    set_string(&row->create_rlimit_nofile, fields[8]);
    set_string(&row->create_rlimit_as, fields[9]);
    set_string(&row->create_rlimit_core, fields[10]);
    set_string(&row->supervise_cmd, fields[11]);
    set_string(&row->cpu1s, fields[12]);
    set_string(&row->cpu10s, fields[13]);
    set_string(&row->memory, fields[14]);
    set_string(&row->age, fields[15]);
    row->running = running;
    row->manifest_present = manifest_present;
  }

  if (malformed_lines > 0) {
    *err_out =
        xasprintf("ignored %zu malformed TSV line(s), first at line %zu",
                  malformed_lines, first_bad_line);
  }

  qsort(out.items, out.len, sizeof(out.items[0]), cmp_rows_by_name);

  *rows_out = out.items;
  *count_out = out.len;
  *err_out = NULL;

  free(copy);
  free(output);
  free(cmd_err);
  return 0;
}

static void set_overlay_path_from_root_field(VolumeRow *row,
                                             const char *root_path) {
  size_t len;
  char *overlay_path;

  if (is_blank(root_path) || strcmp(root_path, "-") == 0) {
    set_string(&row->path, "");
    return;
  }

  len = strlen(root_path);
  if (len >= 5 && strcmp(root_path + len - 5, "/root") == 0) {
    overlay_path = xasprintf("%.*s/.overlay", (int)(len - 5), root_path);
  } else {
    overlay_path = xasprintf("%s/.overlay", root_path);
  }
  set_string(&row->path, overlay_path);
  free(overlay_path);
}

int load_volume_rows(VolumeRow **rows_out, size_t *count_out, char **err_out) {
  VolumeVec out;
  char *output = NULL;
  char *cmd_err = NULL;
  char *copy = NULL;
  char *line;
  char *saveptr;
  const char *volume_argv[] = {
      "cellmgr", "volume", "list", "--view", "merged", "-T", "-H", "-o",
      "name,manifest,runtime,mounted,refs,mode,path,used_by", NULL,
  };
  const char *cell_argv[] = {
      "cellmgr", "cell", "list", "--view", "merged", "-T", "-H", "-o",
      "name,manifest,running,root", NULL,
  };

  *rows_out = NULL;
  *count_out = 0;
  *err_out = NULL;
  volumevec_init(&out);

  if (run_capture_command("cellmgr", volume_argv, &output, &cmd_err) != 0) {
    *err_out = xasprintf("cellmgr volume list failed: %s",
                         blank_if(cmd_err, "command failed"));
    free(output);
    free(cmd_err);
    return -1;
  }

  copy = xstrdup(blank_if(output, ""));
  for (line = strtok_r(copy, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char *fields[8];
    VolumeRow *row;
    bool manifest_ok;
    bool runtime_ok;
    bool mounted_ok;

    if (*line == '\0') {
      continue;
    }
    if (split_tsv_fixed(line, fields, 8) != 0) {
      continue;
    }
    row = volumevec_push(&out);
    set_string(&row->kind, "volume");
    set_string(&row->name, fields[0]);
    row->manifest_present = parse_tsv_bool(fields[1], &manifest_ok);
    row->runtime_present = parse_tsv_bool(fields[2], &runtime_ok);
    row->mounted = parse_tsv_bool(fields[3], &mounted_ok);
    if (!manifest_ok || !runtime_ok || !mounted_ok) {
      free_volume_row(row);
      memset(row, 0, sizeof(*row));
      out.len--;
      continue;
    }
    set_string(&row->refs, fields[4]);
    set_string(&row->mode, fields[5]);
    set_string(&row->path, fields[6]);
    set_string(&row->used_by, fields[7]);
  }
  free(copy);
  copy = NULL;
  free(output);
  output = NULL;
  free(cmd_err);
  cmd_err = NULL;

  if (run_capture_command("cellmgr", cell_argv, &output, &cmd_err) != 0) {
    *err_out = xasprintf("cellmgr cell list failed: %s",
                         blank_if(cmd_err, "command failed"));
    for (size_t i = 0; i < out.len; i++) {
      free_volume_row(&out.items[i]);
    }
    free(out.items);
    free(output);
    free(cmd_err);
    return -1;
  }

  copy = xstrdup(blank_if(output, ""));
  for (line = strtok_r(copy, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char *fields[4];
    VolumeRow *row;
    bool manifest_ok;
    bool mounted_ok;

    if (*line == '\0') {
      continue;
    }
    if (split_tsv_fixed(line, fields, 4) != 0) {
      continue;
    }

    row = volumevec_push(&out);
    set_string(&row->kind, "overlay");
    set_string(&row->name, fields[0]);
    row->manifest_present = parse_tsv_bool(fields[1], &manifest_ok);
    row->mounted = parse_tsv_bool(fields[2], &mounted_ok);
    if (!manifest_ok || !mounted_ok) {
      free_volume_row(row);
      memset(row, 0, sizeof(*row));
      out.len--;
      continue;
    }

    row->runtime_present = !is_blank(fields[3]) && strcmp(fields[3], "-") != 0;
    set_string(&row->refs, "-");
    set_string(&row->mode, "-");
    set_string(&row->used_by, fields[0]);
    set_overlay_path_from_root_field(row, fields[3]);
  }

  qsort(out.items, out.len, sizeof(out.items[0]), cmp_volume_rows_by_name);

  *rows_out = out.items;
  *count_out = out.len;
  *err_out = NULL;

  free(copy);
  free(output);
  free(cmd_err);
  return 0;
}

int load_storage_backups(const char *storage_kind, const char *storage_name,
                        BackupRow **rows_out, size_t *count_out,
                        char **err_out) {
  BackupVec out;
  char *output = NULL;
  char *cmd_err = NULL;
  char *copy;
  char *line;
  char *saveptr;
  const char *volume_argv[] = {
      "cellmgr", "volume", "backup", "list", storage_name, "-T", "-H", NULL,
  };
  const char *overlay_argv[] = {
      "cellmgr", "cell", "backup", "list", storage_name, "-T", "-H", NULL,
  };
  const char *const *argv = NULL;

  *rows_out = NULL;
  *count_out = 0;
  *err_out = NULL;
  backupvec_init(&out);

  if (strcmp(blank_if(storage_kind, ""), "overlay") == 0) {
    argv = overlay_argv;
  } else {
    argv = volume_argv;
  }

  if (run_capture_command("cellmgr", argv, &output, &cmd_err) != 0) {
    *err_out = xasprintf("cellmgr %s backup list failed: %s",
                         blank_if(storage_kind, "storage"),
                         blank_if(cmd_err, "command failed"));
    free(output);
    free(cmd_err);
    return -1;
  }

  copy = xstrdup(blank_if(output, ""));
  for (line = strtok_r(copy, "\n", &saveptr); line != NULL;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char *fields[4];
    BackupRow *row;

    if (*line == '\0') {
      continue;
    }
    if (split_tsv_fixed(line, fields, 4) != 0) {
      continue;
    }

    row = backupvec_push(&out);
    set_string(&row->volume, fields[0]);
    set_string(&row->timestamp, fields[1]);
    set_string(&row->size, fields[2]);
    set_string(&row->archive, fields[3]);
  }

  *rows_out = out.items;
  *count_out = out.len;
  *err_out = NULL;

  free(copy);
  free(output);
  free(cmd_err);
  return 0;
}
