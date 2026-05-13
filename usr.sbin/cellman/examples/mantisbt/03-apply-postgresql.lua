apply("postgresql", {
  actions = {
    pkg("postgresql16-server"),
    dir("/var/postgresql", { mode = "0755", owner = "pgsql", group = "pgsql" }),
    dir("/var/postgresql/data", { mode = "0700", owner = "pgsql", group = "pgsql" }),
    dir("/var/db/mantisbt-secrets", { mode = "0700", owner = "root", group = "wheel" }),
    script("./assets/db-configure.sh"),
  },
})
