cell("ticketd", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "8080",
  },
  supervise = {
    cmd = "/opt/ticketd/ticketd -config /opt/ticketd/ticketd.conf",
    log = {
      facility = "local1",
      stdout_level = "info",
      stderr_level = "err",
      tag = "ticketd",
    },
  },
  healthcheck = "test -f /opt/ticketd/ticketd.conf",
  mounts = {
    volume("data", { target = "/var/ticketd", mode = "rw" }),
  },
})
