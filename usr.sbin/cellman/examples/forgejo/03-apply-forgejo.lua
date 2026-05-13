apply("forgejo", {
  actions = {
    pkg("forgejo"),
    dir("/var/lib/forgejo", { mode = "0755" }),
    dir("/var/lib/forgejo/custom", { mode = "0755" }),
    dir("/var/lib/forgejo/custom/conf", { mode = "0755" }),
    dir("/var/lib/forgejo/data", { mode = "0755" }),
    dir("/var/lib/forgejo/data/git", { mode = "0755" }),
    dir("/var/lib/forgejo/data/git/repositories", { mode = "0755" }),
    copy("./assets/app.ini", "/var/lib/forgejo/custom/conf/app.ini", {
      mode = "0644",
    }),
  },
})
