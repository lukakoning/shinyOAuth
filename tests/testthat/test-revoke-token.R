testthat::test_that("revoke_token handles unsupported and missing tokens", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # 1) Unsupported: no revocation_url -> supported = FALSE
  cli@provider@revocation_url <- NA_character_
  t <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )
  res <- revoke_token(cli, t, which = "access", async = FALSE)
  testthat::expect_type(res, "list")
  testthat::expect_false(isTRUE(res$supported))
  testthat::expect_true(is.na(res$revoked))
  testthat::expect_identical(res$status, "revocation_unsupported")

  # 2) Supported but missing token -> revoked = NA, status = "missing_token"
  cli@provider@revocation_url <- "https://example.com/revoke"
  t@access_token <- NA_character_
  res2 <- revoke_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(isTRUE(res2$supported))
  testthat::expect_true(is.na(res2$revoked))
  testthat::expect_identical(res2$status, "missing_token")

  t@access_token <- "at"
  t@refresh_token <- NA_character_
  res3 <- revoke_token(cli, t, which = "refresh", async = FALSE)
  testthat::expect_true(isTRUE(res3$supported))
  testthat::expect_true(is.na(res3$revoked))
  testthat::expect_identical(res3$status, "missing_token")
})

testthat::test_that("revoke_token returns ok on 2xx and status on http error", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  t <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  # HTTP error -> revoked = NA, status = "http_<code>"
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 400,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"error":"invalid_request"}')
      )
    },
    .package = "shinyOAuth"
  )
  res_err <- revoke_token(cli, t, which = "refresh", async = FALSE)
  testthat::expect_true(isTRUE(res_err$supported))
  testthat::expect_true(is.na(res_err$revoked))
  testthat::expect_identical(res_err$status, "http_400")

  # Success -> revoked = TRUE
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{}')
      )
    },
    .package = "shinyOAuth"
  )
  res_ok <- revoke_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(isTRUE(res_ok$supported))
  testthat::expect_true(isTRUE(res_ok$revoked))
  testthat::expect_identical(res_ok$status, "ok")
})

testthat::test_that("revoke_token async returns a resolved promise", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@revocation_url <- "https://example.com/revoke"
  t <- OAuthToken(
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
        body = charToRaw('{}')
      )
    },
    .package = "shinyOAuth"
  )

  # Use mirai synchronous mode to keep mocked bindings in-process
  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  p <- revoke_token(cli, t, which = "access", async = TRUE)
  # mirai objects implement as.promise() so convert explicitly
  p <- promises::as.promise(p)
  testthat::expect_s3_class(p, "promise")
  val <- NULL
  p$then(function(x) {
    val <<- x
  })
  deadline <- Sys.time() + 5
  while (is.null(val) && Sys.time() < deadline) {
    later::run_now(0.05)
    Sys.sleep(0.02)
  }
  testthat::expect_type(val, "list")
  testthat::expect_true(isTRUE(val$revoked))
})
