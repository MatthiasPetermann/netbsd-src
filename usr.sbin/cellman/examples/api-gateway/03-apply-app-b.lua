apply("app-b", {
  actions = {
    dir("/var/www/app-b", { mode = "0755", owner = "root", group = "wheel" }),
    copy("./assets/app-b-index.html", "/var/www/app-b/index.html", {
      mode = "0644",
    }),
  },
})
