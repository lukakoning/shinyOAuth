testthat::test_that("extra_token_headers are sent on revoke requests", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  cli@provider@extra_token_headers <- c(
    "X-Custom" = "custom-value",
    Accept = "application/json"
  )

  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      captured_req <<- req
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw("{}")
      )
    },
    .package = "shinyOAuth"
  )

  res <- revoke_token(cli, tok, which = "access", async = FALSE)
  testthat::expect_identical(res$status, "ok")
  testthat::expect_true(isTRUE(res$revoked))

  # Verify custom headers were applied to the request
  testthat::expect_false(is.null(captured_req))
  hdrs <- captured_req$headers
  testthat::expect_identical(hdrs[["X-Custom"]], "custom-value")
  testthat::expect_identical(hdrs[["Accept"]], "application/json")
})

testthat::test_that("extra_token_headers are sent on introspect requests", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@extra_token_headers <- c(
    "X-Custom" = "custom-value",
    Accept = "application/json"
  )

  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  captured_req <- NULL
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      captured_req <<- req
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  res <- introspect_token(cli, tok, which = "access", async = FALSE)
  testthat::expect_identical(res$status, "ok")
  testthat::expect_true(isTRUE(res$active))

  # Verify custom headers were applied to the request
  testthat::expect_false(is.null(captured_req))
  hdrs <- captured_req$headers
  testthat::expect_identical(hdrs[["X-Custom"]], "custom-value")
  testthat::expect_identical(hdrs[["Accept"]], "application/json")
})

testthat::test_that("revoke and introspect work without extra_token_headers", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  cli@provider@introspection_url <- "https://example.com/introspect"
  # extra_token_headers defaults to character() in the test helper

  tok <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

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

  # Both should succeed without errors when no extra headers are set
  res_revoke <- revoke_token(cli, tok, which = "access", async = FALSE)
  testthat::expect_identical(res_revoke$status, "ok")

  res_intro <- introspect_token(cli, tok, which = "access", async = FALSE)
  testthat::expect_identical(res_intro$status, "ok")
})
