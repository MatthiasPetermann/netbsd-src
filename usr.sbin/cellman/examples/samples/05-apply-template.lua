apply("template", {
  actions = {
    dir("/srv/shared/template", {
      mode = "0755",
      owner = "{{run_uid}}",
      group = "{{run_gid}}",
    }),
    template("./assets/example.env.tmpl", "/srv/shared/template/tokens.txt", {
      mode = "0640",
      owner = "{{run_uid}}",
      group = "{{run_gid}}",
      tokens = {
        site_name = "template-sample",
        site_role = "demo",
        host_path = from_env("PATH"),
      },
    }),
    template("./assets/runtime.txt.tmpl", "/srv/shared/template/runtime.txt", {
      mode = "0644",
      owner = "{{run_uid}}",
      group = "{{run_gid}}",
    }),
  },
})
