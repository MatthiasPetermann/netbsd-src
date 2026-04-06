cell("forgejo", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "3000",
    rlimit_nofile = "8192",
    rlimit_as = "2147483648",
    rlimit_core = "0",
  },
  supervise = {
    cmd = "env HOME=/var/lib/forgejo FORGEJO_WORK_DIR=/var/lib/forgejo /usr/pkg/bin/forgejo web --config /var/lib/forgejo/custom/conf/app.ini",
    log = {
      facility = "local4",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-forgejo",
    },
  },
  healthcheck = "test -f /var/lib/forgejo/custom/conf/app.ini",
  mounts = {
    volume("data", { target = "/var/lib/forgejo", mode = "rw" }),
  },
})
