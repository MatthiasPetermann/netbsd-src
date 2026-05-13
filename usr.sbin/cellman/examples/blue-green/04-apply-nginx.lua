apply("nginx", {
  actions = {
    pkg("nginx"),
    copy("./assets/nginx.conf", "/usr/pkg/etc/nginx/nginx.conf", {
      mode = "0644",
    }),
  },
})
