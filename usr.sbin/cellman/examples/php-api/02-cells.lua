cell("phpfpm", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "9000",
  },
  supervise = {
    cmd = "/usr/pkg/sbin/php-fpm83 --nodaemonize --fpm-config /usr/pkg/etc/php-fpm.conf",
    log = {
      facility = "local3",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-phpfpm",
    },
  },
  healthcheck = "test -f /usr/pkg/etc/php-fpm.conf",
  mounts = {
    volume("webroot", { target = "/var/www/php-api", mode = "rw" }),
  },
})

cell("nginx", {
  autostart = true,
  create = {
    profile = "high",
    reserved_ports = "80",
  },
  supervise = {
    cmd = "/usr/pkg/sbin/nginx",
    run_as = "cell:nginx:nginx",
    log = {
      facility = "local4",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-nginx",
    },
  },
  depends_on = { "phpfpm" },
  healthcheck = "test -f /usr/pkg/etc/nginx/nginx.conf",
  mounts = {
    volume("webroot", { target = "/var/www/php-api", mode = "ro" }),
  },
})
