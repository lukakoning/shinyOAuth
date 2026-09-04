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

testthat::test_that("Ed448 at_hash docs describe fail-closed validation", {
  provider_docs <- project_text("R", "classes__OAuthProvider.R")

  testthat::expect_match(
    provider_docs,
    "any Ed448 ID\n#'   token containing an `at_hash` claim fails closed",
    fixed = TRUE
  )
  testthat::expect_false(grepl(
    "shinyOAuth skips\n#'   that optional check",
    provider_docs,
    fixed = TRUE
  ))
})

testthat::test_that("claims validation docs describe conditional defaults", {
  auth_docs <- project_text("vignettes", "authentication-flow.Rmd")

  testthat::expect_match(
    auth_docs,
    "it defaults\n  to `\"warn\"` if `claims` contains enforceable requirements",
    fixed = TRUE
  )
  testthat::expect_match(
    auth_docs,
    "and to `\"none\"`\n  otherwise",
    fixed = TRUE
  )
})

testthat::test_that("package overview distinguishes authentication from authorization", {
  description <- project_text("DESCRIPTION")
  readme <- project_text("README.md")

  testthat::expect_match(
    description,
    "OIDC Authentication and OAuth Authorization",
    fixed = TRUE
  )
  testthat::expect_match(
    readme,
    "an OAuth access token is an authorization\ncredential, not an identity assertion",
    fixed = TRUE
  )
  testthat::expect_match(
    readme,
    "a validated ID token authenticates\nthe user",
    fixed = TRUE
  )
  testthat::expect_false(grepl(
    "tokens\nwhich prove the user's identity",
    readme,
    fixed = TRUE
  ))
})

testthat::test_that("PKCE docs distinguish exchange and browser binding", {
  auth_docs <- project_text("vignettes", "authentication-flow.Rmd")

  testthat::expect_match(
    auth_docs,
    "bind the\n  authorization request to the later token exchange",
    fixed = TRUE
  )
  testthat::expect_match(
    auth_docs,
    "the state and browser\n  token provide the browser-session binding",
    fixed = TRUE
  )
  testthat::expect_false(grepl(
    "PKCE: a `code_verifier` and matching `code_challenge` that prove the same",
    auth_docs,
    fixed = TRUE
  ))
})

testthat::test_that("OTel catalog includes form-post state consumption", {
  otel_docs <- project_text("vignettes", "opentelemetry.Rmd")

  testthat::expect_match(
    otel_docs,
    "Span: `shinyOAuth.form_post.callback.consume_state`",
    fixed = TRUE
  )
  testthat::expect_match(
    otel_docs,
    "oauth.phase = \"form_post.callback_state_consume\"",
    fixed = TRUE
  )
})

testthat::test_that("OTel docs describe exception-message opt-in", {
  otel_docs <- project_text("vignettes", "opentelemetry.Rmd")

  testthat::expect_match(
    otel_docs,
    "Condition messages are\n  omitted by default",
    fixed = TRUE
  )
  testthat::expect_match(
    otel_docs,
    "options(shinyOAuth.expose_error_body = TRUE)",
    fixed = TRUE
  )
  testthat::expect_match(
    otel_docs,
    "should be handled as sensitive data",
    fixed = TRUE
  )
})

testthat::test_that("Spotify vignette defines its fallback operator", {
  spotify_docs <- project_text("vignettes", "example-spotify.Rmd")
  definition <- regexpr("`%||%` <- function", spotify_docs, fixed = TRUE)[[1L]]
  first_use <- regexpr("%||%", spotify_docs, fixed = TRUE)[[1L]]

  testthat::expect_gt(definition, 0L)
  testthat::expect_identical(first_use, definition + 1L)
})

testthat::test_that("Spotify vignette validates rendered provider URLs", {
  spotify_docs <- project_text("vignettes", "example-spotify.Rmd")
  spotify_lines <- strsplit(spotify_docs, "\n", fixed = TRUE)[[1L]]

  testthat::expect_match(
    spotify_docs,
    "spotify_safe_url <- function",
    fixed = TRUE
  )
  testthat::expect_match(spotify_docs, '"scdn.co"', fixed = TRUE)
  testthat::expect_match(spotify_docs, '"spotifycdn.com"', fixed = TRUE)
  testthat::expect_match(spotify_docs, '"open.spotify.com"', fixed = TRUE)
  testthat::expect_match(
    spotify_docs,
    'rel = "noopener noreferrer"',
    fixed = TRUE
  )
  testthat::expect_false(grepl(
    "href = user_info$external_urls$spotify",
    spotify_docs,
    fixed = TRUE
  ))

  helper_start <- grep("^`%\\|\\|%` <- function", spotify_lines)
  helper_end <- grep("^# Configure provider and client", spotify_lines) - 1L
  helper_env <- new.env(parent = baseenv())
  eval(parse(text = spotify_lines[helper_start:helper_end]), envir = helper_env)
  safe_url <- get("spotify_safe_url", envir = helper_env)
  safe_image_url <- get("spotify_safe_image_url", envir = helper_env)

  testthat::expect_identical(
    safe_url("https://open.spotify.com/artist/123", "open.spotify.com"),
    "https://open.spotify.com/artist/123"
  )
  testthat::expect_null(safe_url(
    "http://open.spotify.com/artist/123",
    "open.spotify.com"
  ))
  testthat::expect_null(safe_url(
    "https://open.spotify.com.evil.test/artist/123",
    "open.spotify.com"
  ))
  testthat::expect_null(safe_url(
    "https://user@open.spotify.com/artist/123",
    "open.spotify.com"
  ))
  testthat::expect_null(safe_url(
    "https://open.spotify.com:444/artist/123",
    "open.spotify.com"
  ))
  testthat::expect_identical(
    safe_image_url("https://i.scdn.co/image/abc"),
    "https://i.scdn.co/image/abc"
  )
})

testthat::test_that("GitHub OAuth help points to OAuth App settings", {
  provider_docs <- project_text("R", "providers.R")

  testthat::expect_match(
    provider_docs,
    "[OAuth App settings](https://github.com/settings/developers)",
    fixed = TRUE
  )
  testthat::expect_false(grepl(
    "https://github.com/settings/apps",
    provider_docs,
    fixed = TRUE
  ))
})

testthat::test_that("Apple provider help uses an Apple example", {
  provider_docs <- project_text("R", "providers__apple.R")
  example <- project_text("inst", "examples", "oauth_provider_apple.R")

  testthat::expect_match(
    provider_docs,
    "@example inst/examples/oauth_provider_apple.R",
    fixed = TRUE
  )
  testthat::expect_match(example, "oauth_provider_apple()", fixed = TRUE)
  testthat::expect_match(
    example,
    "oauth_client_secret_apple(",
    fixed = TRUE
  )
  testthat::expect_match(example, 'response_mode = "form_post"', fixed = TRUE)
})
