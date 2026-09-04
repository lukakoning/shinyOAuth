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
