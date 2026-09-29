# Run from the repository root:
# Rscript --vanilla tests/benchmarks/connection-access.R [iterations]
# Exercises real module/manager reads with synthetic, unexpired credentials.
# No provider requests occur. Timings are diagnostic, not CI thresholds.
Sys.setenv(TESTTHAT = "true")
pkgload::load_all(".", quiet = TRUE)
for (helper in c(
  "helper-login.R",
  "helper-client-resources.R",
  "helper-connection-manager.R",
  "helper-connection-ordinary-oidc.R"
)) {
  source(file.path("tests/testthat", helper))
}
options(shinyOAuth.skip_browser_token = TRUE)
args <- commandArgs(trailingOnly = TRUE)
iterations <- if (length(args)) as.integer(args[[1]]) else 20L
stopifnot(length(iterations) == 1L, !is.na(iterations), iterations > 0L)

measure <- function(connection, scope) {
  # Warm up reactive dependencies before timing repeated credential reads.
  stopifnot(identical(connection[["access_token"]](), "synthetic-access"))
  stopifnot(connection[["has_scopes"]](scope))
  gc()
  access <- system.time(
    for (i in seq_len(iterations)) {
      stopifnot(identical(connection[["access_token"]](), "synthetic-access"))
    }
  )[["elapsed"]]
  gc()
  coverage <- system.time(
    for (i in seq_len(iterations)) {
      stopifnot(connection[["has_scopes"]](scope))
    }
  )[["elapsed"]]
  cat(sprintf(
    "access_token %.1f ms/call; has_scopes %.1f ms/call (%d iterations)\n",
    1000 * access / iterations,
    1000 * coverage / iterations,
    iterations
  ))
}

for (count in c(0L, 1L, 16L)) {
  scopes <- if (count == 16L) {
    # Maximum supported aggregate scope budget: 128 tokens / 8192 bytes.
    sprintf("%03d%s", seq_len(128), strrep("x", 61))
  } else {
    c("read", "write")
  }
  client <- make_test_client(use_nonce = FALSE, scopes = scopes)
  client@redirect_uri <- "https://app.example/callback"
  if (count) {
    provider <- client@provider
    provider@token_target_mode <- "rfc8707"
    S7::props(client) <- list(
      provider = provider,
      token_targets = stats::setNames(
        lapply(seq_len(count), function(i) {
          list(resource = paste0("urn:api:", i), scopes = scopes)
        }),
        paste0("api", seq_len(count))
      ),
      default_token_target = "api1"
    )
  }
  token <- manager_test_token()
  token@granted_scopes <- scopes
  cat(sprintf(
    "\n%d targets, %d scopes, %d scope bytes\n",
    count,
    length(scopes),
    sum(nchar(scopes, type = "bytes"))
  ))
  cat("Single module: ")
  shiny::testServer(
    oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      revoke_on_session_end = FALSE
    ),
    {
      session[["flushReact"]]()
      .accept_login_token(token, NULL)
      current <- values[["connection"]]()
      session[["flushReact"]]()
      measure(current, scopes[[1]])
    }
  )
  cat("Manager: ")
  fixture <- ordinary_manager_fixture(client)
  shiny::testServer(
    oauth_connections_server,
    args = list(id = "health", manager = fixture[["manager"]]),
    session = manager_test_session(manager_test_cookie(fixture)),
    {
      session[["flushReact"]]()
      id <- manager_test_accept(controller, token = token)
      current <- connection(id)
      session[["flushReact"]]()
      measure(current, scopes[[1]])
    }
  )
}
