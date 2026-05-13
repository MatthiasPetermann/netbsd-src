cell("httpd", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "8080",
  },
  supervise = {
    cmd = "/usr/libexec/httpd -I 8080 -X -f -s /var/www/httpd",
    log = {
      facility = "local1",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-httpd",
    },
  },
  healthcheck = "test -f /var/www/httpd/index.html",
})
