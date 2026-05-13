apply("httpd", {
  actions = {
    dir("/var/www/httpd", { mode = "0755", owner = "root", group = "wheel" }),
    copy("./assets/index.html", "/var/www/httpd/index.html", {
      mode = "0644",
    }),
  },
})
