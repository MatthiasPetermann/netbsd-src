apply("webdavd", {
  actions = {
    dir("/opt/webdavd", {
      mode = "0755",
      owner = "{{run_uid}}",
      group = "{{run_gid}}",
    }),
    copy("./assets/webdavd", "/opt/webdavd/webdavd", {
      mode = "0555",
      owner = "{{run_uid}}",
      group = "{{run_gid}}",
    }),
    copy("./assets/webdavd.conf", "/opt/webdavd/webdavd.conf", {
      mode = "0555",
      owner = "{{run_uid}}",
      group = "{{run_gid}}",
    }),
  },
})
