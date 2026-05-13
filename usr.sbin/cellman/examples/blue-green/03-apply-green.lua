apply("green", {
  actions = {
    dir("/var/www/green", { mode = "0755", owner = "root", group = "wheel" }),
    copy("./assets/green-index.html", "/var/www/green/index.html", {
      mode = "0644",
    }),
  },
})
