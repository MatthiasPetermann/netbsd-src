cell("app-a", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "8080",
  },
  supervise = {
    cmd = "/usr/libexec/httpd -I 8080 -X -f -s /var/www/app-a",
    log = {
      facility = "local5",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-app-a",
    },
  },
  healthcheck = "test -f /var/www/app-a/index.html",
})

cell("app-b", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "8081",
  },
  supervise = {
    cmd = "/usr/libexec/httpd -I 8081 -X -f -s /var/www/app-b",
    log = {
      facility = "local5",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-app-b",
    },
  },
  healthcheck = "test -f /var/www/app-b/index.html",
})

cell("app-c", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "8082",
  },
  supervise = {
    cmd = "/usr/libexec/httpd -I 8082 -X -f -s /var/www/app-c",
    log = {
      facility = "local5",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-app-c",
    },
  },
  healthcheck = "test -f /var/www/app-c/index.html",
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
      facility = "local6",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-nginx",
    },
  },
  depends_on = { "app-a", "app-b", "app-c" },
  healthcheck = "test -f /usr/pkg/etc/nginx/nginx.conf",
})
