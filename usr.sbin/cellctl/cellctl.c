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

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD$");
#endif /* not lint */

#include <sys/cell.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <paths.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define CELLCTL_LOG_MAX 511
#define CELLCTL_TAG_MAX 63

struct supervise_creds {
  bool enabled;
  uid_t uid;
  gid_t gid;
  gid_t *groups;
  size_t ngroups;
};

static void usage(void) __dead;

static void cell_exec(cellid_t, const char *, const char *, char *[],
                      const struct supervise_creds *);
static void cell_run_monitor_once(cellid_t, const char *, int, int, pid_t, int,
                                  int, int *);
static void cell_supervise_loop(const struct cell_info *, const char *,
                                char *[], int, int, int,
                                const struct supervise_creds *);
static void cell_spawn_detached(const struct cell_info *, const char *,
                                char *[], int, int, int,
                                const struct supervise_creds *);
static int parse_log_facility(const char *);
static int parse_log_level(const char *);
static int parse_log_level_arg(const char *);
static void validate_cell_name_or_die(const char *);
static uint32_t parse_profile(const char *);
static void parse_port_list(struct cell_create *, const char *);
static uid_t parse_uid_arg(const char *);
static gid_t parse_gid_arg(const char *, const char *);
static void parse_gid_list(const char *, gid_t **, size_t *);
static bool parse_rlimit_value(const char *, uint64_t *);
static void parse_create_rlimit(struct cell_create *, uint32_t, uint64_t *,
                                const char *, const char *);
static void sanitize_field(const char *, char *, size_t);
static void format_rlimit_field(const struct cell_info *, uint32_t, uint64_t,
                                char *, size_t);
static void cell_list(bool, bool);
static void cell_stats(bool, bool, bool, bool, bool);
static void apply_supervise_rlimits_or_die(const struct cell_info *);
static uint64_t monotonic_now_ns(void);
static uint64_t cell_age_seconds(const struct cell_info *, uint64_t);
static void prom_escape_label(const char *, char *, size_t);
static bool cell_lookup_by_name(const char *, struct cell_info *);
static bool cell_lookup_by_id(cellid_t, struct cell_info *);
static void log_stream_data(int, const char *, cellid_t, const char *, char *,
                            size_t *, const char *, size_t);
static cellid_t resolve_cell_target(const char *, struct cell_info *);

static volatile sig_atomic_t monitor_shutdown_requested;

/*
 * Signal handler used by supervise mode monitor process.
 *
 * We only set a flag here to keep the handler async-signal-safe; the actual
 * shutdown sequence (TERM/KILL and wait logic) is performed in the main loop.
 */
static void monitor_signal_handler(int signo) {
  (void)signo;
  monitor_shutdown_requested = 1;
}

static size_t cell_name_column_width(const struct cell_info *entries,
                                     size_t count) {
  size_t i;
  size_t width;

  width = strlen("NAME");
  for (i = 0; i < count; i++) {
    const char *name;
    size_t n;

    name = entries[i].ci_name[0] != '\0' ? entries[i].ci_name : "-";
    n = strlen(name);
    if (n > width)
      width = n;
  }

  return width;
}

static size_t cell_root_column_width(const struct cell_info *entries,
                                     size_t count) {
  size_t i;
  size_t width;

  width = strlen("ROOT");
  for (i = 0; i < count; i++) {
    const char *root;
    size_t n;

    root = entries[i].ci_root[0] != '\0' ? entries[i].ci_root : "-";
    n = strlen(root);
    if (n > width)
      width = n;
  }

  return width;
}

static void format_rlimit_field(const struct cell_info *entry, uint32_t flag,
                                uint64_t value, char *dst, size_t dsz) {
  if (entry == NULL || dst == NULL || dsz == 0)
    return;

  if ((entry->ci_create_flags & flag) == 0 || value == CELL_RLIMIT_INFINITY) {
    strlcpy(dst, "unlimited", dsz);
    return;
  }

  (void)snprintf(dst, dsz, "%" PRIu64, value);
}

static bool parse_rlimit_value(const char *arg, uint64_t *valuep) {
  unsigned long long v;
  char *endp;

  if (arg == NULL || valuep == NULL)
    return false;

  if (strcmp(arg, "unlimited") == 0) {
    *valuep = CELL_RLIMIT_INFINITY;
    return true;
  }

  errno = 0;
  v = strtoull(arg, &endp, 10);
  if (errno != 0 || *arg == '\0' || *endp != '\0')
    return false;

  *valuep = (uint64_t)v;
  return true;
}

static void parse_create_rlimit(struct cell_create *create, uint32_t flag,
                                uint64_t *fieldp, const char *arg,
                                const char *name) {
  uint64_t value;

  if (!parse_rlimit_value(arg, &value))
    errx(1, "invalid rlimit %s: %s", name, arg);

  *fieldp = value;
  create->cc_flags |= flag;
}

static rlim_t rlimit_value_to_native(uint64_t value, const char *name) {
  if (value == CELL_RLIMIT_INFINITY)
    return RLIM_INFINITY;

  if (value > (uint64_t)RLIM_INFINITY)
    errx(1, "rlimit %s out of range: %" PRIu64, name, value);

  return (rlim_t)value;
}

static void apply_supervise_rlimits_or_die(const struct cell_info *entry) {
  struct rlimit lim;

  if (entry == NULL)
    return;

  if ((entry->ci_create_flags & CELL_CREATE_RLIMIT_NOFILE) != 0) {
    lim.rlim_cur = lim.rlim_max =
        rlimit_value_to_native(entry->ci_rlimit_nofile, "nofile");
    if (setrlimit(RLIMIT_NOFILE, &lim) == -1)
      err(1, "setrlimit RLIMIT_NOFILE");
  }
  if ((entry->ci_create_flags & CELL_CREATE_RLIMIT_AS) != 0) {
    lim.rlim_cur = lim.rlim_max =
        rlimit_value_to_native(entry->ci_rlimit_as, "as");
    if (setrlimit(RLIMIT_AS, &lim) == -1)
      err(1, "setrlimit RLIMIT_AS");
  }
  if ((entry->ci_create_flags & CELL_CREATE_RLIMIT_CORE) != 0) {
    lim.rlim_cur = lim.rlim_max =
        rlimit_value_to_native(entry->ci_rlimit_core, "core");
    if (setrlimit(RLIMIT_CORE, &lim) == -1)
      err(1, "setrlimit RLIMIT_CORE");
  }
}

static uint64_t monotonic_now_ns(void) {
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1 || ts.tv_sec < 0)
    return 0;

  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t cell_age_seconds(const struct cell_info *entry,
                                 uint64_t now_ns) {
  if (entry == NULL || now_ns == 0 || entry->ci_created_ns == 0)
    return 0;
  if (now_ns <= entry->ci_created_ns)
    return 0;

  return (now_ns - entry->ci_created_ns) / 1000000000ULL;
}

static struct cell_info *cell_fetch_list(size_t *countp) {
  struct cell_info *entries;
  size_t len;

  /*
   * Two-pass sysctl pattern: first query required length, then allocate and
   * fetch the current cell table snapshot.
   */
  len = 0;
  if (sysctlbyname("security.models.cell.list", NULL, &len, NULL, 0) == -1)
    err(1, "list cells");

  if (len == 0) {
    *countp = 0;
    return NULL;
  }

  if (len % sizeof(*entries) != 0)
    errx(1, "unexpected cell list length");

  entries = calloc(1, len);
  if (entries == NULL)
    err(1, "calloc");

  if (sysctlbyname("security.models.cell.list", entries, &len, NULL, 0) == -1)
    err(1, "list cells");

  *countp = len / sizeof(*entries);
  return entries;
}

static cellid_t cell_create(const struct cell_create *create) {
  cellid_t id;
  struct cell_create req;
  size_t len;

  /* Structured create payload is mandatory in the cell-native ABI. */
  id = 0;
  if (create == NULL)
    errx(1, "internal error: create payload is required");

  req = *create;
  len = sizeof(req);
  if (sysctlbyname("security.models.cell.create", &req, &len, &req,
                   sizeof(req)) == -1)
    err(1, "create cell");
  id = req.cc_id;

  return id;
}

static void cell_destroy(cellid_t id) {
  if (sysctlbyname("security.models.cell.destroy", NULL, 0, &id, sizeof(id)) ==
      -1)
    err(1, "destroy cell %" PRIu32, id);
}

static void cell_enter(cellid_t id) {
  if (sysctlbyname("security.models.cell.id", NULL, 0, &id, sizeof(id)) == -1)
    err(1, "enter cell %" PRIu32, id);
}

static void cell_list(bool tsv, bool no_header) {
  struct cell_info *entries;
  uint64_t now_ns;
  size_t name_w;
  size_t count, i;

  entries = cell_fetch_list(&count);
  if (count == 0) {
    if (tsv) {
      if (!no_header)
        printf("CID\tNAME\tREFS\tPROCS\tAGE\tROOT\tNOFILE\tAS\tCORE\n");
    } else {
      printf("no cells\n");
    }
    return;
  }

  now_ns = monotonic_now_ns();

  if (tsv) {
    if (!no_header)
      printf("CID\tNAME\tREFS\tPROCS\tAGE\tROOT\tNOFILE\tAS\tCORE\n");
    for (i = 0; i < count; i++) {
      char name[(CELL_NAME_MAX + 1) * 2 + 1];
      char root[(CELL_ROOT_MAX + 1) * 2 + 1];
      char rlimit_nofile[32];
      char rlimit_as[32];
      char rlimit_core[32];
      uint64_t age_s;

      sanitize_field(entries[i].ci_name[0] != '\0' ? entries[i].ci_name : "-",
                     name, sizeof(name));
      sanitize_field(entries[i].ci_root[0] != '\0' ? entries[i].ci_root : "-",
                     root, sizeof(root));
      format_rlimit_field(&entries[i], CELL_CREATE_RLIMIT_NOFILE,
                          entries[i].ci_rlimit_nofile, rlimit_nofile,
                          sizeof(rlimit_nofile));
      format_rlimit_field(&entries[i], CELL_CREATE_RLIMIT_AS,
                          entries[i].ci_rlimit_as, rlimit_as,
                          sizeof(rlimit_as));
      format_rlimit_field(&entries[i], CELL_CREATE_RLIMIT_CORE,
                          entries[i].ci_rlimit_core, rlimit_core,
                          sizeof(rlimit_core));
      age_s = cell_age_seconds(&entries[i], now_ns);
      printf("%" PRIu32 "\t%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
             "\t%s\t%s\t%s\t%s\n",
             entries[i].ci_id, name, entries[i].ci_refcount,
             entries[i].ci_proc_current, age_s, root, rlimit_nofile, rlimit_as,
             rlimit_core);
    }
    free(entries);
    return;
  }

  name_w = cell_name_column_width(entries, count);

  printf("%-8s %-*s %-8s %-8s %-8s %-10s %-10s %-10s %s\n", "ID", (int)name_w,
         "NAME", "REFS", "PROCS", "AGE", "NOFILE", "AS", "CORE", "ROOT");
  for (i = 0; i < count; i++) {
    char rlimit_nofile[32];
    char rlimit_as[32];
    char rlimit_core[32];
    uint64_t age_s;

    format_rlimit_field(&entries[i], CELL_CREATE_RLIMIT_NOFILE,
                        entries[i].ci_rlimit_nofile, rlimit_nofile,
                        sizeof(rlimit_nofile));
    format_rlimit_field(&entries[i], CELL_CREATE_RLIMIT_AS,
                        entries[i].ci_rlimit_as, rlimit_as, sizeof(rlimit_as));
    format_rlimit_field(&entries[i], CELL_CREATE_RLIMIT_CORE,
                        entries[i].ci_rlimit_core, rlimit_core,
                        sizeof(rlimit_core));
    age_s = cell_age_seconds(&entries[i], now_ns);
    printf("%-8" PRIu32 " %-*s %-8" PRIu64 " %-8" PRIu64 " %-8" PRIu64
           " %-10s %-10s %-10s %s\n",
           entries[i].ci_id, (int)name_w,
           entries[i].ci_name[0] != '\0' ? entries[i].ci_name : "-",
           entries[i].ci_refcount, entries[i].ci_proc_current, age_s,
           rlimit_nofile, rlimit_as, rlimit_core,
           entries[i].ci_root[0] != '\0' ? entries[i].ci_root : "-");
  }

  free(entries);
}

static void cell_stats(bool prometheus, bool verbose, bool http_header,
                       bool tsv, bool no_header) {
  struct cell_info *entries;
  uint64_t now_ns;
  size_t name_w;
  size_t root_w;
  size_t count, i;

  entries = cell_fetch_list(&count);
  if (prometheus && http_header) {
    printf("HTTP/1.1 200 OK\r\n");
    printf("Content-Type: text/plain\r\n\r\n");
  }
  if (count == 0) {
    if (tsv) {
      if (!no_header)
        printf("CID\tNAME\tCPU1S\tCPU10S\tPROCS\tREFS\tMEMORY\tAGE\tROOT\n");
    } else if (!prometheus)
      printf("no cells\n");
    return;
  }

  now_ns = monotonic_now_ns();

  if (tsv) {
    if (!no_header)
      printf("CID\tNAME\tCPU1S\tCPU10S\tPROCS\tREFS\tMEMORY\tAGE\tROOT\n");
    for (i = 0; i < count; i++) {
      char name[(CELL_NAME_MAX + 1) * 2 + 1];
      char root[(CELL_ROOT_MAX + 1) * 2 + 1];
      uint64_t age_s;

      sanitize_field(entries[i].ci_name[0] != '\0' ? entries[i].ci_name : "-",
                     name, sizeof(name));
      sanitize_field(entries[i].ci_root[0] != '\0' ? entries[i].ci_root : "-",
                     root, sizeof(root));
      age_s = cell_age_seconds(&entries[i], now_ns);
      printf("%" PRIu32 "\t%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
             "\t%" PRIu64 "\t%" PRIu64 "\t%s\n",
             entries[i].ci_id, name, entries[i].ci_cpu_ticks_1s,
             entries[i].ci_cpu_ticks_10s, entries[i].ci_proc_current,
             entries[i].ci_refcount, entries[i].ci_memory_current, age_s, root);
    }
    free(entries);
    return;
  }

  if (!prometheus) {
    name_w = cell_name_column_width(entries, count);

    if (!verbose) {
      printf("%-8s %-*s %-10s %-10s %-8s %-8s %-12s\n", "ID", (int)name_w,
             "NAME", "CPU1S", "CPU10S", "PROC", "AGE", "MEMORY");
      for (i = 0; i < count; i++) {
        uint64_t age_s;

        age_s = cell_age_seconds(&entries[i], now_ns);
        printf("%-8" PRIu32 " %-*s %-10" PRIu64 " %-10" PRIu64 " %-8" PRIu64
               " %-8" PRIu64 " %-12" PRIu64 "\n",
               entries[i].ci_id, (int)name_w,
               entries[i].ci_name[0] != '\0' ? entries[i].ci_name : "-",
               entries[i].ci_cpu_ticks_1s, entries[i].ci_cpu_ticks_10s,
               entries[i].ci_proc_current, age_s, entries[i].ci_memory_current);
      }
    } else {
      root_w = cell_root_column_width(entries, count);
      printf("%-8s %-*s %-*s %-10s %-10s %-8s %-8s %-8s %-12s\n", "ID",
             (int)name_w, "NAME", (int)root_w, "ROOT", "CPU1S", "CPU10S",
             "PROC", "REFS", "AGE", "MEMORY");
      for (i = 0; i < count; i++) {
        uint64_t age_s;

        age_s = cell_age_seconds(&entries[i], now_ns);
        printf("%-8" PRIu32 " %-*s %-*s %-10" PRIu64 " %-10" PRIu64
               " %-8" PRIu64 " %-8" PRIu64 " %-8" PRIu64 " %-12" PRIu64 "\n",
               entries[i].ci_id, (int)name_w,
               entries[i].ci_name[0] != '\0' ? entries[i].ci_name : "-",
               (int)root_w,
               entries[i].ci_root[0] != '\0' ? entries[i].ci_root : "-",
               entries[i].ci_cpu_ticks_1s, entries[i].ci_cpu_ticks_10s,
               entries[i].ci_proc_current, entries[i].ci_refcount, age_s,
               entries[i].ci_memory_current);
      }
    }
    free(entries);
    return;
  }

  printf("# TYPE cell_cpu_ticks_1s gauge\n");
  printf("# TYPE cell_cpu_ticks_10s_avg gauge\n");
  printf("# TYPE cell_processes_current gauge\n");
  printf("# TYPE cell_references_current gauge\n");
  printf("# TYPE cell_memory_vmsize_bytes gauge\n");
  printf("# TYPE cell_age_seconds gauge\n");

  for (i = 0; i < count; i++) {
    char name[(CELL_NAME_MAX + 1) * 2 + 1];
    char root[(CELL_ROOT_MAX + 1) * 2 + 1];
    uint64_t age_s;

    prom_escape_label(entries[i].ci_name, name, sizeof(name));
    prom_escape_label(entries[i].ci_root, root, sizeof(root));
    age_s = cell_age_seconds(&entries[i], now_ns);

    printf("cell_cpu_ticks_1s{cid=\"%" PRIu32
           "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
           entries[i].ci_id, name, root, entries[i].ci_cpu_ticks_1s);
    printf("cell_cpu_ticks_10s_avg{cid=\"%" PRIu32
           "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
           entries[i].ci_id, name, root, entries[i].ci_cpu_ticks_10s);
    printf("cell_processes_current{cid=\"%" PRIu32
           "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
           entries[i].ci_id, name, root, entries[i].ci_proc_current);
    printf("cell_references_current{cid=\"%" PRIu32
           "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
           entries[i].ci_id, name, root, entries[i].ci_refcount);
    printf("cell_memory_vmsize_bytes{cid=\"%" PRIu32
           "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
           entries[i].ci_id, name, root, entries[i].ci_memory_current);
    printf("cell_age_seconds{cid=\"%" PRIu32
           "\",name=\"%s\",root=\"%s\"} %" PRIu64 "\n",
           entries[i].ci_id, name, root, age_s);
  }

  free(entries);
}

static void sanitize_field(const char *src, char *dst, size_t dsz) {
  size_t i, j;

  for (i = 0, j = 0; src[i] != '\0' && j + 1 < dsz; i++) {
    if (src[i] == '\n' || src[i] == '\r' || src[i] == '\t')
      dst[j++] = ' ';
    else
      dst[j++] = src[i];
  }
  dst[j] = '\0';
}

static void prom_escape_label(const char *src, char *dst, size_t dsz) {
  size_t i, j;

  for (i = 0, j = 0; src[i] != '\0' && j + 1 < dsz; i++) {
    if ((src[i] == '\\' || src[i] == '"') && j + 2 < dsz) {
      dst[j++] = '\\';
      dst[j++] = src[i];
    } else if (src[i] == '\n' && j + 2 < dsz) {
      dst[j++] = '\\';
      dst[j++] = 'n';
    } else if (src[i] == '\r' || src[i] == '\t') {
      dst[j++] = ' ';
    } else {
      dst[j++] = src[i];
    }
  }
  dst[j] = '\0';
}

static bool cell_lookup_by_id(cellid_t id, struct cell_info *jip) {
  struct cell_info *entries;
  size_t count, i;

  entries = cell_fetch_list(&count);
  for (i = 0; i < count; i++) {
    if (entries[i].ci_id == id) {
      *jip = entries[i];
      free(entries);
      return true;
    }
  }
  free(entries);
  return false;
}

static bool cell_lookup_by_name(const char *name, struct cell_info *jip) {
  struct cell_info *entries;
  size_t count, i;

  entries = cell_fetch_list(&count);
  for (i = 0; i < count; i++) {
    if (strcmp(entries[i].ci_name, name) == 0) {
      *jip = entries[i];
      free(entries);
      return true;
    }
  }
  free(entries);
  return false;
}

static void cell_exec(cellid_t id, const char *root, const char *name,
                      char *cmd[], const struct supervise_creds *creds) {
  const char *shell;
  const char *shell_name;
  char *login_argv0;
  char prompt[128];

  /*
   * Execution order matters:
   * 1) enter cell filesystem view via chroot
   * 2) switch cell membership in kernel via sysctl
   * 3) exec workload/shell with both constraints in effect
   */
  if (chdir(root) == -1 || chroot(".") == -1)
    err(1, "%s", root);

  if (chdir("/") == -1)
    err(1, "/");

  cell_enter(id);

  if (creds != NULL && creds->enabled) {
    if (creds->ngroups > (size_t)INT_MAX)
      errx(1, "too many supplementary gids");
    if (setgroups((int)creds->ngroups, creds->groups) == -1)
      err(1, "setgroups");
    if (setgid(creds->gid) == -1)
      err(1, "setgid");
    if (setuid(creds->uid) == -1)
      err(1, "setuid");
  }

  if (cmd != NULL) {
    execvp(cmd[0], cmd);
    err(1, "%s", cmd[0]);
  }

  (void)snprintf(prompt, sizeof(prompt), "[%s]# ",
                 (name != NULL && name[0] != '\0') ? name : "cell");
  if (setenv("PS1", prompt, 1) == -1)
    err(1, "setenv PS1");

  if ((shell = getenv("SHELL")) == NULL)
    shell = _PATH_BSHELL;

  shell_name = strrchr(shell, '/');
  if (shell_name != NULL)
    shell_name++;
  else
    shell_name = shell;

  login_argv0 = malloc(strlen(shell_name) + 2);
  if (login_argv0 == NULL)
    err(1, "malloc");

  login_argv0[0] = '-';
  (void)strcpy(login_argv0 + 1, shell_name);

  execlp(shell, login_argv0, "-i", NULL);
  err(1, "%s", shell);
}

static void log_stream_data(int priority, const char *stream, cellid_t id,
                            const char *name, char *linebuf, size_t *usedp,
                            const char *chunk, size_t chunklen) {
  size_t used;
  size_t i;

  /*
   * Convert an arbitrary byte stream into syslog lines while preserving
   * partial-line state across read(2) calls.
   */
  used = *usedp;
  for (i = 0; i < chunklen; i++) {
    if (chunk[i] == '\n') {
      syslog(priority, "cell=%s cid=%" PRIu32 " %s: %.*s", name, id, stream,
             (int)used, linebuf);
      used = 0;
      continue;
    }
    if (used + 1 >= CELLCTL_LOG_MAX) {
      syslog(priority, "cell=%s cid=%" PRIu32 " %s: %.*s", name, id, stream,
             (int)used, linebuf);
      used = 0;
    }
    linebuf[used++] = chunk[i];
  }

  *usedp = used;
}

static void cell_run_monitor_once(cellid_t id, const char *name, int outfd,
                                  int errfd, pid_t child, int stdout_priority,
                                  int stderr_priority, int *statusp) {
  const int kill_grace_ms = 5000;
  char outline[CELLCTL_LOG_MAX];
  char errline[CELLCTL_LOG_MAX];
  struct timespec now;
  struct timespec shutdown_deadline;
  size_t outused, errused;
  bool outopen, erropen;
  bool sent_sigterm, sent_sigkill;
  bool have_deadline;
  int flags;

  /*
   * Monitor one supervised child execution:
   * - forward stdout/stderr to syslog with cell context
   * - on shutdown request, terminate process group gracefully then forcefully
   */
  sent_sigterm = false;
  sent_sigkill = false;
  have_deadline = false;

  flags = fcntl(outfd, F_GETFL, 0);
  if (flags == -1)
    warn("fcntl outfd F_GETFL");
  else if (fcntl(outfd, F_SETFL, flags | O_NONBLOCK) == -1)
    warn("fcntl outfd O_NONBLOCK");
  flags = fcntl(errfd, F_GETFL, 0);
  if (flags == -1)
    warn("fcntl errfd F_GETFL");
  else if (fcntl(errfd, F_SETFL, flags | O_NONBLOCK) == -1)
    warn("fcntl errfd O_NONBLOCK");

  outused = 0;
  errused = 0;
  outopen = true;
  erropen = true;

  while (outopen || erropen) {
    struct pollfd pfd[2];
    int nfd, rv, i, timeout_ms;

    if (monitor_shutdown_requested && !sent_sigterm) {
      if (kill(-child, SIGTERM) == -1 && errno != ESRCH)
        warn("kill(SIGTERM, -%jd)", (intmax_t)child);
      sent_sigterm = true;
      if (clock_gettime(CLOCK_MONOTONIC, &shutdown_deadline) == -1)
        err(1, "clock_gettime");
      shutdown_deadline.tv_sec += kill_grace_ms / 1000;
      shutdown_deadline.tv_nsec += (kill_grace_ms % 1000) * 1000000L;
      if (shutdown_deadline.tv_nsec >= 1000000000L) {
        shutdown_deadline.tv_sec++;
        shutdown_deadline.tv_nsec -= 1000000000L;
      }
      have_deadline = true;
    }

    timeout_ms = 500;
    if (have_deadline && !sent_sigkill) {
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
        err(1, "clock_gettime");
      if (now.tv_sec > shutdown_deadline.tv_sec ||
          (now.tv_sec == shutdown_deadline.tv_sec &&
           now.tv_nsec >= shutdown_deadline.tv_nsec)) {
        if (kill(-child, SIGKILL) == -1 && errno != ESRCH)
          warn("kill(SIGKILL, -%jd)", (intmax_t)child);
        sent_sigkill = true;
        timeout_ms = 0;
      } else {
        long sec, nsec;

        sec = shutdown_deadline.tv_sec - now.tv_sec;
        nsec = shutdown_deadline.tv_nsec - now.tv_nsec;
        if (nsec < 0) {
          sec--;
          nsec += 1000000000L;
        }
        timeout_ms = (int)(sec * 1000 + nsec / 1000000L);
        if (timeout_ms < 0)
          timeout_ms = 0;
        if (timeout_ms > 500)
          timeout_ms = 500;
      }
    }

    nfd = 0;
    if (outopen) {
      pfd[nfd].fd = outfd;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    if (erropen) {
      pfd[nfd].fd = errfd;
      pfd[nfd].events = POLLIN;
      nfd++;
    }

    rv = poll(pfd, (nfds_t)nfd, timeout_ms);
    if (rv < 0) {
      if (errno == EINTR)
        continue;
      warn("poll");
      break;
    }
    if (rv == 0)
      continue;

    for (i = 0; i < nfd; i++) {
      bool *openp;

      openp = pfd[i].fd == outfd ? &outopen : &erropen;

      if (*openp == false)
        continue;
      if ((pfd[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0)
        continue;

      for (;;) {
        char buf[512];
        ssize_t n;

        n = read(pfd[i].fd, buf, sizeof(buf));
        if (n > 0) {
          if (pfd[i].fd == outfd)
            log_stream_data(stdout_priority, "stdout", id, name, outline,
                            &outused, buf, (size_t)n);
          else
            log_stream_data(stderr_priority, "stderr", id, name, errline,
                            &errused, buf, (size_t)n);
          continue;
        }

        if (n == 0) {
          *openp = false;
          close(pfd[i].fd);
          break;
        }

        if (errno == EINTR)
          continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          break;

        warn("read");
        *openp = false;
        close(pfd[i].fd);
        break;
      }
    }
  }

  if (outused > 0)
    syslog(stdout_priority, "cell=%s cid=%" PRIu32 " stdout: %.*s", name, id,
           (int)outused, outline);
  if (errused > 0)
    syslog(stderr_priority, "cell=%s cid=%" PRIu32 " stderr: %.*s", name, id,
           (int)errused, errline);

  if (waitpid(child, statusp, 0) == -1 && errno != ECHILD)
    warn("waitpid %jd", (intmax_t)child);
}

static void cell_supervise_loop(const struct cell_info *entry,
                                const char *logtag, char *cmd[], int facility,
                                int stdout_priority, int stderr_priority,
                                const struct supervise_creds *creds) {
  struct sigaction sa;
  int next_backoff_sec;
  cellid_t id;
  const char *name;
  const char *root;

  if (entry == NULL)
    errx(1, "internal error: missing cell entry");

  id = entry->ci_id;
  name = entry->ci_name;
  root = entry->ci_root;

  setproctitle("cellctl supervise cell=%s cid=%" PRIu32, name, id);
  openlog(logtag, LOG_PID | LOG_NDELAY, facility);

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = monitor_signal_handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGTERM, &sa, NULL) == -1 ||
      sigaction(SIGINT, &sa, NULL) == -1 || sigaction(SIGQUIT, &sa, NULL) == -1)
    err(1, "sigaction");

  /*
   * Keep supervise mode detached from caller terminal/session lifetime.
   * If started via rc(8), startup completion can trigger SIGHUP delivery
   * to background jobs; treating SIGHUP as shutdown would stop the cell.
   */
  sa.sa_handler = SIG_IGN;
  if (sigaction(SIGHUP, &sa, NULL) == -1)
    err(1, "sigaction");

  monitor_shutdown_requested = 0;
  next_backoff_sec = 1;

  for (;;) {
    int outpipe[2], errpipe[2], status;
    struct timespec started, elapsed;
    pid_t child;

    if (monitor_shutdown_requested)
      break;

    if (pipe(outpipe) == -1 || pipe(errpipe) == -1)
      err(1, "pipe");

    if (clock_gettime(CLOCK_MONOTONIC, &started) == -1)
      err(1, "clock_gettime");

    child = fork();
    if (child == -1)
      err(1, "fork");
    if (child == 0) {
      int devnull;

      close(outpipe[0]);
      close(errpipe[0]);
      if (setsid() == -1)
        err(1, "setsid");
      devnull = open(_PATH_DEVNULL, O_RDONLY);
      if (devnull == -1)
        err(1, "%s", _PATH_DEVNULL);
      if (dup2(devnull, STDIN_FILENO) == -1 ||
          dup2(outpipe[1], STDOUT_FILENO) == -1 ||
          dup2(errpipe[1], STDERR_FILENO) == -1)
        err(1, "dup2");
      if (devnull > STDERR_FILENO)
        close(devnull);
      close(outpipe[1]);
      close(errpipe[1]);
      apply_supervise_rlimits_or_die(entry);
      cell_exec(id, root, name, cmd, creds);
    }

    close(outpipe[1]);
    close(errpipe[1]);

    if (creds != NULL && creds->enabled) {
      syslog(LOG_INFO,
             "cell=%s cid=%" PRIu32
             " starting supervised command as uid=%ju gid=%ju",
             name, id, (uintmax_t)creds->uid, (uintmax_t)creds->gid);
    } else {
      syslog(LOG_INFO, "cell=%s cid=%" PRIu32 " starting supervised command",
             name, id);
    }
    status = 0;
    cell_run_monitor_once(id, name, outpipe[0], errpipe[0], child,
                          stdout_priority, stderr_priority, &status);

    if (monitor_shutdown_requested) {
      syslog(LOG_NOTICE, "cell=%s cid=%" PRIu32 " supervise shutdown requested",
             name, id);
      break;
    }

    if (WIFEXITED(status)) {
      syslog(LOG_WARNING,
             "cell=%s cid=%" PRIu32 " supervised command exited status=%d",
             name, id, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
      syslog(LOG_WARNING,
             "cell=%s cid=%" PRIu32 " supervised command killed by signal=%d",
             name, id, WTERMSIG(status));
    } else {
      syslog(LOG_WARNING,
             "cell=%s cid=%" PRIu32 " supervised command ended unexpectedly",
             name, id);
    }

    if (clock_gettime(CLOCK_MONOTONIC, &elapsed) == -1)
      err(1, "clock_gettime");
    elapsed.tv_sec -= started.tv_sec;
    elapsed.tv_nsec -= started.tv_nsec;
    if (elapsed.tv_nsec < 0) {
      elapsed.tv_sec--;
      elapsed.tv_nsec += 1000000000L;
    }

    if (elapsed.tv_sec >= 30)
      next_backoff_sec = 1;

    syslog(LOG_NOTICE,
           "cell=%s cid=%" PRIu32
           " restarting supervised command in %d seconds",
           name, id, next_backoff_sec);

    {
      int delay_sec;

      for (delay_sec = next_backoff_sec;
           delay_sec > 0 && !monitor_shutdown_requested; delay_sec--) {
        struct timespec delay = {.tv_sec = 1, .tv_nsec = 0};

        if (nanosleep(&delay, NULL) == -1 && errno != EINTR)
          warn("nanosleep");
      }
    }

    if (elapsed.tv_sec < 30) {
      next_backoff_sec *= 2;
      if (next_backoff_sec > 10)
        next_backoff_sec = 10;
    }
  }

  closelog();
  _exit(0);
}

static void cell_spawn_detached(const struct cell_info *entry,
                                const char *logtag, char *cmd[], int facility,
                                int stdout_priority, int stderr_priority,
                                const struct supervise_creds *creds) {
  struct cell_info entry_copy;
  struct supervise_creds creds_copy;
  int devnull;
  pid_t mgr;
  cellid_t id;

  if (entry == NULL)
    errx(1, "internal error: missing cell entry");
  entry_copy = *entry;
  memset(&creds_copy, 0, sizeof(creds_copy));
  if (creds != NULL)
    creds_copy = *creds;
  id = entry_copy.ci_id;

  /*
   * Supervise mode daemonizes itself so callers (for example rc(8) helpers)
   * do not need nohup/background wrappers.
   */
  mgr = fork();
  if (mgr == -1)
    err(1, "fork");
  if (mgr == 0) {
    mgr = fork();
    if (mgr == -1)
      err(1, "fork");
    if (mgr != 0)
      _exit(0);

    if (setsid() == -1)
      err(1, "setsid");
    devnull = open(_PATH_DEVNULL, O_RDWR);
    if (devnull == -1)
      err(1, "%s", _PATH_DEVNULL);
    if (dup2(devnull, STDIN_FILENO) == -1 ||
        dup2(devnull, STDOUT_FILENO) == -1 ||
        dup2(devnull, STDERR_FILENO) == -1)
      err(1, "dup2");
    if (devnull > STDERR_FILENO)
      close(devnull);
    cell_supervise_loop(&entry_copy, logtag, cmd, facility, stdout_priority,
                        stderr_priority, &creds_copy);
  }
  printf("cell %" PRIu32 "\n", id);
}

static int parse_log_facility(const char *name) {
  static const struct {
    const char *name;
    int facility;
  } facs[] = {
      {"auth", LOG_AUTH},     {"authpriv", LOG_AUTHPRIV},
      {"cron", LOG_CRON},     {"daemon", LOG_DAEMON},
      {"ftp", LOG_FTP},       {"kern", LOG_KERN},
      {"lpr", LOG_LPR},       {"mail", LOG_MAIL},
      {"news", LOG_NEWS},     {"syslog", LOG_SYSLOG},
      {"user", LOG_USER},     {"uucp", LOG_UUCP},
      {"local0", LOG_LOCAL0}, {"local1", LOG_LOCAL1},
      {"local2", LOG_LOCAL2}, {"local3", LOG_LOCAL3},
      {"local4", LOG_LOCAL4}, {"local5", LOG_LOCAL5},
      {"local6", LOG_LOCAL6}, {"local7", LOG_LOCAL7},
  };
  size_t i;

  for (i = 0; i < __arraycount(facs); i++) {
    if (strcmp(name, facs[i].name) == 0)
      return facs[i].facility;
  }

  errx(1, "invalid log facility: %s", name);
  /* NOTREACHED */
}

static int parse_log_level(const char *name) {
  static const struct {
    const char *name;
    int level;
  } levels[] = {
      {"emerg", LOG_EMERG}, {"alert", LOG_ALERT},     {"crit", LOG_CRIT},
      {"err", LOG_ERR},     {"warning", LOG_WARNING}, {"notice", LOG_NOTICE},
      {"info", LOG_INFO},   {"debug", LOG_DEBUG},
  };
  size_t i;

  for (i = 0; i < __arraycount(levels); i++) {
    if (strcmp(name, levels[i].name) == 0)
      return levels[i].level;
  }

  errx(1, "invalid log level: %s", name);
  /* NOTREACHED */
}

static int parse_log_level_arg(const char *arg) {
  long num;
  char *endp;

  errno = 0;
  num = strtol(arg, &endp, 0);
  if (errno == 0 && *arg != '\0' && *endp == '\0') {
    if (num < LOG_EMERG || num > LOG_DEBUG)
      errx(1, "log level out of range: %s", arg);
    return (int)num;
  }

  return parse_log_level(arg);
}

static uint32_t parse_profile(const char *arg) {
  if (strcmp(arg, "low") == 0)
    return CELL_PROFILE_LOW;
  if (strcmp(arg, "medium") == 0)
    return CELL_PROFILE_MEDIUM;
  if (strcmp(arg, "high") == 0)
    return CELL_PROFILE_HIGH;

  errx(1, "invalid profile '%s' (expected low|medium|high)", arg);
  return CELL_PROFILE_HIGH;
}

static void parse_port_list(struct cell_create *create, const char *arg) {
  char *list, *tok, *sp;
  unsigned long port;

  list = strdup(arg);
  if (list == NULL)
    err(1, "strdup");

  for (tok = strtok_r(list, ",", &sp); tok != NULL;
       tok = strtok_r(NULL, ",", &sp)) {
    char *endp;
    size_t i;

    errno = 0;
    port = strtoul(tok, &endp, 10);
    if (errno != 0 || *tok == '\0' || *endp != '\0' || port == 0 ||
        port > UINT16_MAX) {
      free(list);
      errx(1, "invalid reserved port: %s", tok);
    }
    for (i = 0; i < create->cc_nports; i++) {
      if (create->cc_ports[i] == (uint16_t)port) {
        free(list);
        errx(1, "duplicate reserved port: %lu", port);
      }
    }
    if (create->cc_nports >= CELL_PORTS_MAX) {
      free(list);
      errx(1, "too many reserved ports (max %u)", CELL_PORTS_MAX);
    }
    create->cc_ports[create->cc_nports++] = (uint16_t)port;
  }

  free(list);
  if (create->cc_nports > 0)
    create->cc_flags |= CELL_CREATE_PORTS;
}

static int getnum(const char *str, uintmax_t *num) {
  char *ep;

  errno = 0;
  *num = strtoumax(str, &ep, 0);
  if (str[0] == '\0' || *ep != '\0') {
    errno = EINVAL;
    return -1;
  }

  if (errno == ERANGE && *num == UINTMAX_MAX)
    return -1;

  return 0;
}

static uid_t parse_uid_arg(const char *arg) {
  uintmax_t num;

  if (getnum(arg, &num) == -1 || (uid_t)num != num)
    errx(1, "invalid uid: %s", arg);

  return (uid_t)num;
}

static gid_t parse_gid_arg(const char *arg, const char *what) {
  uintmax_t num;

  if (getnum(arg, &num) == -1 || (gid_t)num != num)
    errx(1, "invalid %s: %s", what, arg);

  return (gid_t)num;
}

static void parse_gid_list(const char *arg, gid_t **groups, size_t *ngroups) {
  char *list, *tok, *sp;
  gid_t *parsed;
  size_t n;

  if (arg == NULL || arg[0] == '\0')
    errx(1, "invalid supplementary gid list");

  list = strdup(arg);
  if (list == NULL)
    err(1, "strdup");

  parsed = *groups;
  n = *ngroups;
  for (tok = strtok_r(list, ",", &sp); tok != NULL;
       tok = strtok_r(NULL, ",", &sp)) {
    gid_t gid;
    gid_t *tmp;

    if (tok[0] == '\0') {
      free(list);
      errx(1, "invalid supplementary gid list: %s", arg);
    }

    gid = parse_gid_arg(tok, "supplementary gid");
    if (n >= (size_t)INT_MAX) {
      free(list);
      free(parsed);
      errx(1, "too many supplementary gids (max %d)", INT_MAX);
    }
    tmp = realloc(parsed, (n + 1) * sizeof(*tmp));
    if (tmp == NULL) {
      free(list);
      free(parsed);
      err(1, "realloc");
    }
    parsed = tmp;
    parsed[n++] = gid;
  }

  free(list);
  if (n == *ngroups)
    errx(1, "invalid supplementary gid list: %s", arg);

  *groups = parsed;
  *ngroups = n;
}

static void validate_cell_name_or_die(const char *name) {
  size_t i;

  if (name == NULL || name[0] == '\0')
    errx(1, "invalid cell name '%s' (allowed: A-Za-z0-9._-)",
         name == NULL ? "" : name);

  for (i = 0; name[i] != '\0'; i++) {
    unsigned char c;

    c = (unsigned char)name[i];
    if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
      errx(1, "invalid cell name '%s' (allowed: A-Za-z0-9._-)", name);
  }
}

static cellid_t resolve_cell_target(const char *arg, struct cell_info *ji) {
  uintmax_t num;

  /* Prefer numeric ID lookup, then fall back to exact-name lookup. */
  if (getnum(arg, &num) == 0 && num <= UINT32_MAX) {
    if (!cell_lookup_by_id((cellid_t)num, ji))
      errx(1, "cell %" PRIu32 " not found", (cellid_t)num);
    return (cellid_t)num;
  }

  validate_cell_name_or_die(arg);

  if (cell_lookup_by_name(arg, ji))
    return ji->ci_id;

  errx(1, "cell '%s' not found", arg);
}

int main(int argc, char *argv[]) {
  cellid_t id;
  const char *root;
  const char *name;
  struct cell_info ji;

  if (argc < 2)
    usage();

  if (strcmp(argv[1], "create") == 0) {
    struct cell_create create;
    int ch;

    memset(&create, 0, sizeof(create));
    name = NULL;
    create.cc_profile = CELL_PROFILE_HIGH;
    optind = 2;
    while ((ch = getopt(argc, argv, "n:l:r:N:A:C:")) != -1) {
      switch (ch) {
      case 'n':
        name = optarg;
        break;
      case 'l':
        create.cc_flags |= CELL_CREATE_PROFILE;
        create.cc_profile = parse_profile(optarg);
        break;
      case 'r':
        parse_port_list(&create, optarg);
        break;
      case 'N':
        parse_create_rlimit(&create, CELL_CREATE_RLIMIT_NOFILE,
                            &create.cc_rlimit_nofile, optarg, "nofile");
        break;
      case 'A':
        parse_create_rlimit(&create, CELL_CREATE_RLIMIT_AS,
                            &create.cc_rlimit_as, optarg, "as");
        break;
      case 'C':
        parse_create_rlimit(&create, CELL_CREATE_RLIMIT_CORE,
                            &create.cc_rlimit_core, optarg, "core");
        break;
      default:
        usage();
      }
    }

    if (optind >= argc || name == NULL || argc != optind + 1)
      usage();
    if (strlen(name) > CELL_NAME_MAX)
      errx(1, "name too long");
    validate_cell_name_or_die(name);

    if (cell_lookup_by_name(name, &ji))
      errx(1, "name already exists: %s", name);

    root = argv[optind];
    sanitize_field(name, create.cc_name, sizeof(create.cc_name));
    sanitize_field(root, create.cc_root, sizeof(create.cc_root));
    id = cell_create(&create);
    printf("cell %" PRIu32 "\n", id);
    return 0;
  }

  if (strcmp(argv[1], "supervise") == 0) {
    char **cmd;
    int ch;
    int facility, stdout_level, stderr_level;
    char logtag[CELLCTL_TAG_MAX + 1];
    struct supervise_creds creds;
    bool have_uid, have_gid;

    facility = LOG_DAEMON;
    stdout_level = LOG_NOTICE;
    stderr_level = LOG_ERR;
    strlcpy(logtag, "cellctl", sizeof(logtag));
    memset(&creds, 0, sizeof(creds));
    have_uid = false;
    have_gid = false;
    optind = 2;
    while ((ch = getopt(argc, argv, "f:t:o:e:U:G:g:")) != -1) {
      switch (ch) {
      case 'f':
        facility = parse_log_facility(optarg);
        break;
      case 'o':
        stdout_level = parse_log_level_arg(optarg);
        break;
      case 'e':
        stderr_level = parse_log_level_arg(optarg);
        break;
      case 't':
        sanitize_field(optarg, logtag, sizeof(logtag));
        if (logtag[0] == '\0')
          errx(1, "invalid log tag");
        break;
      case 'U':
        creds.uid = parse_uid_arg(optarg);
        have_uid = true;
        break;
      case 'G':
        creds.gid = parse_gid_arg(optarg, "gid");
        have_gid = true;
        break;
      case 'g':
        parse_gid_list(optarg, &creds.groups, &creds.ngroups);
        break;
      default:
        usage();
      }
    }

    if (have_uid != have_gid)
      errx(1, "-U and -G must be specified together");
    if (creds.ngroups > 0 && !have_uid)
      errx(1, "-g requires -U and -G");
    creds.enabled = have_uid;

    if (optind >= argc)
      usage();

    id = resolve_cell_target(argv[optind++], &ji);
    if (optind >= argc)
      errx(1, "supervise requires command [args...]");
    cmd = &argv[optind];

    cell_spawn_detached(&ji, logtag, cmd, facility, facility | stdout_level,
                        facility | stderr_level, creds.enabled ? &creds : NULL);
    free(creds.groups);
    return 0;
  }

  if (strcmp(argv[1], "destroy") == 0) {
    if (argc != 3)
      usage();

    id = resolve_cell_target(argv[2], &ji);
    cell_destroy(id);
    return 0;
  }

  if (strcmp(argv[1], "exec") == 0) {
    if (argc < 3)
      usage();

    id = resolve_cell_target(argv[2], &ji);

    cell_exec(id, ji.ci_root, ji.ci_name, argc > 3 ? &argv[3] : NULL, NULL);
    /* NOTREACHED */
  }

  if (strcmp(argv[1], "list") == 0) {
    bool tsv, no_header;
    int ch;

    tsv = false;
    no_header = false;
    optind = 2;
    while ((ch = getopt(argc, argv, "TH")) != -1) {
      switch (ch) {
      case 'T':
        tsv = true;
        break;
      case 'H':
        no_header = true;
        break;
      default:
        usage();
      }
    }
    if (optind != argc)
      usage();
    if (no_header && !tsv)
      errx(1, "-H requires -T");

    cell_list(tsv, no_header);
    return 0;
  }

  if (strcmp(argv[1], "stats") == 0) {
    bool prometheus, verbose, http_header, tsv, no_header;
    int ch;

    prometheus = false;
    verbose = false;
    http_header = false;
    tsv = false;
    no_header = false;
    optind = 2;
    while ((ch = getopt(argc, argv, "PvhTH")) != -1) {
      switch (ch) {
      case 'P':
        prometheus = true;
        break;
      case 'v':
        verbose = true;
        break;
      case 'h':
        http_header = true;
        break;
      case 'T':
        tsv = true;
        break;
      case 'H':
        no_header = true;
        break;
      default:
        usage();
      }
    }
    if (optind != argc)
      usage();
    if (http_header && !prometheus)
      errx(1, "-h requires -P");
    if (no_header && !tsv)
      errx(1, "-H requires -T");
    if (tsv && prometheus)
      errx(1, "-T is not valid with -P");
    if (tsv && verbose)
      errx(1, "-T is not valid with -v");
    if (tsv && http_header)
      errx(1, "-T is not valid with -h");

    cell_stats(prometheus, verbose, http_header, tsv, no_header);
    return 0;
  }

  usage();
  /* NOTREACHED */
}

static void usage(void) {
  fprintf(stderr,
          "usage: %s create [-l low|medium|high] [-r port[,port...]] "
          "[-N nofile|unlimited] [-A as|unlimited] "
          "[-C core|unlimited] -n name <root>\n"
          "       %s supervise [-f facility] [-o stdout-level] "
          "[-e stderr-level] [-t tag] [-U uid -G gid [-g gid[,gid...]]] "
          "<cell-id|name> <command [args...]>\n"
          "       %s exec <cell-id|name> [command [args...]]\n"
          "       %s destroy <cell-id|name>\n"
          "       %s list [-T] [-H]\n"
          "       %s stats [-P] [-v] [-h] [-T] [-H]\n",
          getprogname(), getprogname(), getprogname(), getprogname(),
          getprogname(), getprogname());
  exit(EXIT_FAILURE);
}
