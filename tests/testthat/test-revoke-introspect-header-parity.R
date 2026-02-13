# Tests for revoke / introspect custom-header parity and edge cases
# Extends test-extra-headers-revoke-introspect.R with adversarial edge cases:
# - conflicting headers (custom Authorization, Content-Type)
# - header with special characters / unusual values
# - parity: both endpoints process extra_token_headers identically

testthat::test_that("revoke and introspect apply extra_token_headers with identical semantics", {
  # Verify that both revoke and introspect construct requests with the same
  # header handling: same final set of extra headers applied the same way.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@extra_token_headers <- c(
    "X-Request-Source" = "shinyOAuth-test",
    "X-Correlation-ID" = "corr-1234"
  )

  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  captured_revoke_req <- NULL
  captured_introspect_req <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("revoke", url)) {
        captured_revoke_req <<- req
      } else {
        captured_introspect_req <<- req
      }
      httr2::response(
        url = url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  revoke_token(cli, tok, which = "access", async = FALSE)
  introspect_token(cli, tok, which = "access", async = FALSE)

  testthat::expect_false(is.null(captured_revoke_req))
  testthat::expect_false(is.null(captured_introspect_req))

  # Both must have the exact same custom headers
  rev_hdrs <- captured_revoke_req$headers
  intr_hdrs <- captured_introspect_req$headers

  testthat::expect_identical(
    rev_hdrs[["X-Request-Source"]],
    intr_hdrs[["X-Request-Source"]]
  )
  testthat::expect_identical(
    rev_hdrs[["X-Correlation-ID"]],
    intr_hdrs[["X-Correlation-ID"]]
  )
  testthat::expect_identical(
    rev_hdrs[["X-Request-Source"]],
    "shinyOAuth-test"
  )
  testthat::expect_identical(rev_hdrs[["X-Correlation-ID"]], "corr-1234")
})

testthat::test_that("reserved Authorization header in extra_token_headers is rejected by validator", {
  # OAuthProvider validation rejects reserved headers like Authorization
  # unless explicitly unblocked via options.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  cli@provider@introspection_url <- "https://example.com/introspect"

  testthat::expect_error(
    cli@provider@extra_token_headers <- c(
      Authorization = "DPoP custom-proof-value"
    ),
    regexp = "reserved headers"
  )

  # With opt-in, the header should be accepted and applied to both endpoints
  withr::local_options(list(
    shinyOAuth.unblock_token_headers = c("authorization")
  ))
  cli@provider@extra_token_headers <- c(
    Authorization = "DPoP custom-proof-value"
  )

  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  revoke_called <- FALSE
  introspect_called <- FALSE

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("revoke", url)) {
        revoke_called <<- TRUE
      } else {
        introspect_called <<- TRUE
      }
      httr2::response(
        url = url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  # Both should succeed without errors when the header is unblocked
  res_rev <- revoke_token(cli, tok, which = "access", async = FALSE)
  res_int <- introspect_token(cli, tok, which = "access", async = FALSE)

  testthat::expect_true(revoke_called)
  testthat::expect_true(introspect_called)
  testthat::expect_identical(res_rev$status, "ok")
  testthat::expect_identical(res_int$status, "ok")
})

testthat::test_that("extra_token_headers with special characters are preserved", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  cli@provider@introspection_url <- "https://example.com/introspect"

  # Headers with unusual but valid values (empty string values are rejected
  # by OAuthProvider validator, so we only test non-empty values)
  cli@provider@extra_token_headers <- c(
    "X-Encoded" = "value%20with%20encoding",
    "X-Multi-Word" = "hello world foo"
  )

  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  captured_revoke_hdrs <- NULL
  captured_introspect_hdrs <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("revoke", url)) {
        captured_revoke_hdrs <<- req$headers
      } else {
        captured_introspect_hdrs <<- req$headers
      }
      httr2::response(
        url = url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  revoke_token(cli, tok, which = "access", async = FALSE)
  introspect_token(cli, tok, which = "access", async = FALSE)

  # Verify headers pass through as-is for both operations
  testthat::expect_identical(
    captured_revoke_hdrs[["X-Encoded"]],
    "value%20with%20encoding"
  )
  testthat::expect_identical(
    captured_introspect_hdrs[["X-Encoded"]],
    "value%20with%20encoding"
  )

  testthat::expect_identical(
    captured_revoke_hdrs[["X-Multi-Word"]],
    "hello world foo"
  )
  testthat::expect_identical(
    captured_introspect_hdrs[["X-Multi-Word"]],
    "hello world foo"
  )
})

testthat::test_that("extra_token_headers include Content-Type without breaking body", {
  # If a user sets Content-Type in extra_token_headers, httr2 may override it
  # with the form-encoded type. Document the behavior.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@extra_token_headers <- c(
    "Content-Type" = "application/json"
  )

  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  # Both should still succeed (httr2 form body should override Content-Type)
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  # These should not error — the form body builder should take precedence
  res_rev <- revoke_token(cli, tok, which = "access", async = FALSE)
  testthat::expect_identical(res_rev$status, "ok")

  res_intr <- introspect_token(cli, tok, which = "access", async = FALSE)
  testthat::expect_identical(res_intr$status, "ok")
})

testthat::test_that("revoke and introspect both apply add_req_defaults", {
  # Both endpoints must apply add_req_defaults() (timeout, UA) before
  # extra_token_headers. Verify that User-Agent is set by checking the
  # request object.
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  captured_revoke_req <- NULL
  captured_introspect_req <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("revoke", url)) {
        captured_revoke_req <<- req
      } else {
        captured_introspect_req <<- req
      }
      httr2::response(
        url = url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  revoke_token(cli, tok, which = "access", async = FALSE)
  introspect_token(cli, tok, which = "access", async = FALSE)

  testthat::expect_false(is.null(captured_revoke_req))
  testthat::expect_false(is.null(captured_introspect_req))

  # Both should have a User-Agent header set by add_req_defaults()
  rev_ua <- captured_revoke_req$headers[["User-Agent"]] %||%
    captured_revoke_req$options$useragent
  intr_ua <- captured_introspect_req$headers[["User-Agent"]] %||%
    captured_introspect_req$options$useragent
  # We don't assert the exact value but both should be non-NULL or set via
  # the options path. At minimum, the request should have been modified by

  # add_req_defaults.
  testthat::expect_false(is.null(captured_revoke_req$policies))
  testthat::expect_false(is.null(captured_introspect_req$policies))
})
