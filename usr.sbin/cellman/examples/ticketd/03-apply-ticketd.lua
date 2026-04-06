apply("ticketd", {
  actions = {
    dir("/opt/ticketd", { mode = "0755" }),
    copy("./assets/ticketd", "/opt/ticketd/ticketd", {
      mode = "0555",
    }),
    copy("./assets/ticketadm", "/opt/ticketd/ticketadm", {
      mode = "0555",
    }),
    copy("./assets/ticketd-logo.svg", "/opt/ticketd/ticketd-logo.svg", {
      mode = "0555",
    }),
    copy("./assets/ticketd.conf", "/opt/ticketd/ticketd.conf", {
      mode = "0555",
    }),
  },
})
