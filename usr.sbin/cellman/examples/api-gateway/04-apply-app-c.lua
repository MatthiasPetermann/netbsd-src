apply("app-c", {
  actions = {
    dir("/var/www/app-c", { mode = "0755", owner = "root", group = "wheel" }),
    copy("./assets/app-c-index.html", "/var/www/app-c/index.html", {
      mode = "0644",
    }),
  },
})
