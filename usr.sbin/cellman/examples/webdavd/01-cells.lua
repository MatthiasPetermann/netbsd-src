cell("webdavd", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "8443",
  },
  supervise = {
    cmd = "/opt/webdavd/webdavd run -config /opt/webdavd/webdavd.conf",
    run_as = "host:nfsuser",
    log = {
      facility = "local1",
      stdout_level = "info",
      stderr_level = "err",
      tag = "webdavd",
    },
  },
  healthcheck = "test -f /opt/webdavd/webdavd.conf",
  mounts = {
    host("/data/sync", { target = "/var/webdavd", mode = "rw" }),
  },
})
