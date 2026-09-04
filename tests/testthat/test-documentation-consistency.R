project_text <- function(...) {
  path <- testthat::test_path("..", "..", ...)
  testthat::skip_if_not(file.exists(path), "Source documentation unavailable")
  paste(readLines(path, warn = FALSE), collapse = "\n")
}

testthat::test_that("local HTTP Keycloak examples show the required opt-in", {
  paths <- list(
    c("vignettes", "usage.Rmd"),
    c("inst", "examples", "oauth_provider.R"),
    c("inst", "examples", "oauth_form_post_ui.R"),
    c("playground", "example-keycloak-docker.R"),
    c("playground", "example-keycloak.R"),
    c("playground", "example-keycloak-client-secret-jwt.R"),
    c("playground", "example-keycloak-private-key-jwt.R"),
    c("playground", "example-keycloak-form-post.R"),
    c("playground", "example-keycloak-form-post-root.R")
  )

  for (path in paths) {
    text <- do.call(project_text, as.list(path))
    testthat::expect_match(
      text,
      "options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)",
      fixed = TRUE,
      info = paste(path, collapse = "/")
    )
  }
})

testthat::test_that("OIDC docs separate host and loopback HTTP policy", {
  discovery_docs <- project_text("R", "providers__oidc_discovery.R")
  keycloak_docs <- project_text("integration", "keycloak", "README.md")
  usage_docs <- project_text("vignettes", "usage.Rmd")

  testthat::expect_match(
    discovery_docs,
    "Host allowlisting does not permit HTTP",
    fixed = TRUE
  )
  testthat::expect_match(
    keycloak_docs,
    "shinyOAuth.allow_insecure_oidc_loopback",
    fixed = TRUE
  )
  testthat::expect_match(
    keycloak_docs,
    "ordinary endpoint host allowlist\ndoes not permit HTTP",
    fixed = TRUE
  )
  testthat::expect_match(
    usage_docs,
    "it does not relax OIDC discovery",
    fixed = TRUE
  )
})

testthat::test_that("request_uri docs describe fail-closed HTTPS policy", {
  client_docs <- project_text("R", "classes__OAuthClient.R")

  testthat::expect_match(
    client_docs,
    "Caller-managed `request_uri` publication requires HTTPS",
    fixed = TRUE
  )
  testthat::expect_match(
    client_docs,
    "HTTP URLs are\n#'   rejected",
    fixed = TRUE
  )
  testthat::expect_false(grepl(
    "shinyOAuth still publishes it but warns",
    client_docs,
    fixed = TRUE
  ))
})
