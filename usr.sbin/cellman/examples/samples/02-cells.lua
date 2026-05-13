cell("web", {
  autostart = true,
  create = {
    profile = "high",
    reserved_ports = "8080",
    rlimit_nofile = "4096",
    rlimit_as = "1073741824",
    rlimit_core = "0",
  },
  supervise = {
    cmd = "/usr/libexec/httpd -I 8080 -X -s -f /var/www/web",
    log = {
      facility = "daemon",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-web",
    },
  },
  healthcheck = "test -f /var/www/web/index.html",
  mounts = {
    volume("webroot", { target = "/var/www/web", mode = "rw" }),
  },
})

cell("script", {
  autostart = true,
  create = {
    profile = "low",
  },
  supervise = {
    cmd = "/bin/sh -c 'while :; do sleep 300; done'",
    log = {
      facility = "daemon",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-script",
    },
  },
  healthcheck = "test -d /srv/shared",
  mounts = {
    volume("shared", { target = "/srv/shared", mode = "rw" }),
  },
})

cell("template", {
  autostart = true,
  create = {
    profile = "low",
  },
  supervise = {
    cmd = "/bin/sh -c 'while :; do sleep 300; done'",
    log = {
      facility = "daemon",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-template",
    },
  },
  healthcheck = "test -d /srv/shared",
  mounts = {
    volume("shared", { target = "/srv/shared", mode = "rw" }),
  },
})
