apply("script", {
  actions = {
    dir("/srv/shared/script", { mode = "0755" }),
    script("./assets/bootstrap.sh", {
      args = { "--mode", "demo" },
      env = {
        CELL_NAME = "{{cell_name}}",
        MANIFEST_DIR = "{{manifest_dir}}",
        OUTPUT_FILE = "/srv/shared/script/bootstrap.log",
      },
    }),
    template("./assets/example.env.tmpl", "/srv/shared/script/tokens.txt", {
      mode = "0644",
      tokens = {
        site_name = "script-sample",
        site_role = "demo",
        host_path = from_env("PATH"),
      },
    }),
  },
})
