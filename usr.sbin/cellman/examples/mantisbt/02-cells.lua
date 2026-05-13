cell("postgresql", {
  autostart = true,
  create = {
    profile = "low",
    reserved_ports = "5432",
  },
  supervise = {
    cmd = "/usr/pkg/bin/postgres -D /var/postgresql/data",
    run_as = "cell:pgsql:pgsql",
    log = {
      facility = "local2",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-postgresql",
    },
  },
  healthcheck = "test -s /var/postgresql/data/PG_VERSION && /usr/pkg/bin/pg_isready -q -U pgsql -p 5432 -d postgres",
  mounts = {
    volume("secrets", { target = "/var/db/mantisbt-secrets", mode = "rw" }),
    volume("postgresql-data", { target = "/var/postgresql", mode = "rw" }),
  },
})

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
  depends_on = { "postgresql" },
  healthcheck = "test -f /usr/pkg/etc/php-fpm.conf && test -f /var/www/mantisbt/index.php",
  mounts = {
    volume("webroot", { target = "/var/www/mantisbt", mode = "rw" }),
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
  healthcheck = "test -f /usr/pkg/etc/nginx/nginx.conf && test -f /var/www/mantisbt/index.php",
  mounts = {
    volume("webroot", { target = "/var/www/mantisbt", mode = "ro" }),
  },
})
