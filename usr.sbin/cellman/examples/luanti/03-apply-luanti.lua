apply("luanti", {
  actions = {
    pkg("unzip"),
    pkg("luanti"),
    dir("/var/lib/luanti", { mode = "0755" }),
    dir("/var/lib/luanti/games", { mode = "0755" }),
    dir("/var/lib/luanti/world", { mode = "0755" }),
    script("./assets/install-mineclonia.sh"),
    copy("./assets/world.mt", "/var/lib/luanti/world/world.mt", {
      mode = "0644",
    }),
    copy("./assets/minetest.conf", "/var/lib/luanti/minetest.conf", {
      mode = "0644",
    }),
  },
})
