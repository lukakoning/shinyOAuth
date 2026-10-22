# Rscript --vanilla tests/benchmarks/connection-enumeration.R [counts...]
# Synthetic grants, no HTTP. Compare explicit enumeration and unchanged polling.
Sys.setenv(TESTTHAT = "true")
pkgload::load_all(quiet = TRUE)
for (f in c(
  "helper-login.R",
  "helper-client-resources.R",
  "helper-connection-manager.R"
)) {
  source(file.path("tests/testthat", f))
}
args <- commandArgs(trailingOnly = TRUE)
counts <- if (length(args)) as.integer(args) else c(10L, 100L, 500L)
fixture <- manager_test_fixture()
shiny::testServer(
  oauth_connections_server,
  args = list(id = "health", manager = fixture[["manager"]]),
  session = manager_test_session(manager_test_cookie(fixture)),
  {
    hooks <- controller[["hooks"]]("a")
    prior <- 0L
    for (n in counts) {
      for (i in seq_len(n - prior)) {
        context <- hooks[["prepare"]]()
        hooks[["accept"]](
          manager_test_token(),
          context,
          as.numeric(Sys.time()) - 100
        )
      }
      controller[["poll"]]()
      for (operation in c("records", "poll")) {
        samples <- replicate(
          3L,
          unname(system.time(invisible(controller[[operation]]())))
        )
        print(c(
          count = n,
          operation = operation,
          stats::setNames(
            apply(samples, 1L, median),
            c("user.self", "sys.self", "elapsed", "user.child", "sys.child")
          )
        ))
      }
      prior <- n
    }
  }
)
