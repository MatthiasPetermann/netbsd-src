apply("blue", {
  actions = {
    dir("/var/www/blue", { mode = "0755", owner = "root", group = "wheel" }),
    copy("./assets/blue-index.html", "/var/www/blue/index.html", {
      mode = "0644",
    }),
  },
})
