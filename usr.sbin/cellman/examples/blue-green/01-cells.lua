cell("blue", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "8080",
  },
  supervise = {
    cmd = "/usr/libexec/httpd -I 8080 -X -f -s /var/www/blue",
    log = {
      facility = "local5",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-blue",
    },
  },
  healthcheck = "test -f /var/www/blue/index.html",
})

cell("green", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "8081",
  },
  supervise = {
    cmd = "/usr/libexec/httpd -I 8081 -X -f -s /var/www/green",
    log = {
      facility = "local5",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-green",
    },
  },
  healthcheck = "test -f /var/www/green/index.html",
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
  depends_on = { "blue", "green" },
  healthcheck = "test -f /usr/pkg/etc/nginx/nginx.conf",
})
