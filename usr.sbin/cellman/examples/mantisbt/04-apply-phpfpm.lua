apply("phpfpm", {
  actions = {
    pkg({ "php83", "php83-fpm", "php83-pgsql", "php83-mbstring", "curl" }),
    dir("/var/www/mantisbt", { mode = "0755", owner = "fpm", group = "www" }),
    dir("/var/db/mantisbt", { mode = "0750", owner = "fpm", group = "www" }),
    dir("/var/db/mantisbt/files", { mode = "0750", owner = "fpm", group = "www" }),
    script("./assets/app-configure.sh"),
    copy("./assets/php-fpm.conf", "/usr/pkg/etc/php-fpm.conf", {
      mode = "0644",
    }),
  },
})
