volume("postgresql-data", {
  mode = "0755",
})

volume("secrets", {
  mode = "0700",
})

volume("webroot", {
  mode = "0755",
})
