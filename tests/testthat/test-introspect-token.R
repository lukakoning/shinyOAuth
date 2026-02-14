testthat::test_that("introspect_token handles unsupported and missing tokens", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # 1) Unsupported: no introspection_url -> supported = FALSE
  cli@provider@introspection_url <- NA_character_
  t <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )
  res <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_type(res, "list")
  testthat::expect_false(isTRUE(res$supported))
  testthat::expect_true(is.na(res$active))
  testthat::expect_identical(res$status, "introspection_unsupported")

  # 2) Supported but missing token -> active = NA, status = "missing_token"
  cli@provider@introspection_url <- "https://example.com/introspect"
  # Missing access token
  t@access_token <- NA_character_
  res2 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(isTRUE(res2$supported))
  testthat::expect_true(is.na(res2$active))
  testthat::expect_identical(res2$status, "missing_token")
  # Missing refresh token
  t@access_token <- "at"
  t@refresh_token <- NA_character_
  res3 <- introspect_token(cli, t, which = "refresh", async = FALSE)
  testthat::expect_true(isTRUE(res3$supported))
  testthat::expect_true(is.na(res3$active))
  testthat::expect_identical(res3$status, "missing_token")
})

testthat::test_that("introspect_token parses active variants and http errors", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"
  t <- OAuthToken(
    access_token = "at",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 60,
    id_token = NA_character_
  )

  # HTTP error -> active = NA, supported = TRUE, status = "http_<code>"
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 404,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"error":"not_found"}')
      )
    },
    .package = "shinyOAuth"
  )
  res_err <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(isTRUE(res_err$supported))
  testthat::expect_true(is.na(res_err$active))
  testthat::expect_match(res_err$status, "^http_404$")

  # Swap mock to return different JSON bodies for each call
  bodies <- list(
    '{"active":true}',
    '{"active":false}',
    '{"active":"true"}',
    '{"active":"false"}',
    '{"active":1}',
    '{"active":0}',
    '{"note":"no active field"}',
    'not-json'
  )
  i <- 0
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      i <<- i + 1
      body <- bodies[[i]]
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(body)
      )
    },
    .package = "shinyOAuth"
  )
  # true
  r1 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(isTRUE(r1$active))
  # false
  r2 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_false(isTRUE(r2$active))
  # "true"
  r3 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(isTRUE(r3$active))
  # "false"
  r4 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_false(isTRUE(r4$active))
  # 1
  r5 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(isTRUE(r5$active))
  # 0
  r6 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_false(isTRUE(r6$active))
  # missing field -> NA
  r7 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(is.na(r7$active))
  testthat::expect_identical(r7$status, "missing_active")

  # invalid JSON -> NA + descriptive status
  r8 <- introspect_token(cli, t, which = "access", async = FALSE)
  testthat::expect_true(is.na(r8$active))
  testthat::expect_identical(r8$status, "invalid_json")
})

testthat::test_that("introspect_token async returns a resolved promise", {
  testthat::skip_on_cran()
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("mirai")
  testthat::skip_if_not_installed("later")

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"
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
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )

  # Use mirai synchronous mode to keep mocked bindings in-process
  mirai::daemons(sync = TRUE)
  withr::defer(mirai::daemons(0))

  p <- introspect_token(cli, t, which = "access", async = TRUE)
  # mirai objects implement as.promise() so convert explicitly
  p <- promises::as.promise(p)
  testthat::expect_s3_class(p, "promise")
  val <- NULL
  p$then(function(x) {
    val <<- shinyOAuth:::replay_async_warnings(x)
  })
  deadline <- Sys.time() + 5
  while (is.null(val) && Sys.time() < deadline) {
    later::run_now(0.05)
    Sys.sleep(0.02)
  }
  testthat::expect_type(val, "list")
  testthat::expect_true(isTRUE(val$active))
})
