apply("phpfpm", {
  actions = {
    pkg({ "php83", "php83-fpm" }),
    dir("/var/www/php-api", { mode = "0755", owner = "fpm", group = "www" }),
    copy("./assets/index.php", "/var/www/php-api/index.php", {
      mode = "0644",
      owner = "fpm",
      group = "www",
    }),
    copy("./assets/php-fpm.conf", "/usr/pkg/etc/php-fpm.conf", {
      mode = "0644",
    }),
  },
})
