cell("luanti", {
  autostart = true,
  create = {
    profile = "medium",
    reserved_ports = "30000",
    rlimit_nofile = "8192",
    rlimit_as = "2147483648",
    rlimit_core = "0",
  },
  supervise = {
    cmd = "env MINETEST_USER_PATH=/var/lib/luanti LUANTI_USER_PATH=/var/lib/luanti /usr/pkg/bin/luantiserver --world /var/lib/luanti/world --gameid mineclonia --port 30000",
    log = {
      facility = "local4",
      stdout_level = "info",
      stderr_level = "err",
      tag = "cell-luanti",
    },
  },
  healthcheck = "test -f /var/lib/luanti/world/world.mt",
  mounts = {
    volume("worlddata", { target = "/var/lib/luanti", mode = "rw" }),
  },
})
