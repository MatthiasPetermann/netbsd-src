apply("app-a", {
  actions = {
    dir("/var/www/app-a", { mode = "0755", owner = "root", group = "wheel" }),
    copy("./assets/app-a-index.html", "/var/www/app-a/index.html", {
      mode = "0644",
    }),
  },
})
