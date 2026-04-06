apply("web", {
  actions = {
    pkg("nginx"),
    dir("/var/www/web", { mode = "0755" }),
    script("./assets/ensure-bootstrapped.sh"),
    copy("./assets/index.html", "/var/www/web/index.html", {
      mode = "0644",
    }),
    symlink("/var/www/web", "/var/www/current"),
    template("./assets/runtime.txt.tmpl", "/var/www/web/runtime.txt", {
      mode = "0644",
    }),
  },
})
