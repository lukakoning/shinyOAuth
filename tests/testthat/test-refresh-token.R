testthat::test_that("refresh_token errors when missing refresh token", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  t <- OAuthToken(
    access_token = "at",
    refresh_token = NA_character_,
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )
  testthat::expect_error(
    refresh_token(cli, t, async = FALSE),
    class = "shinyOAuth_input_error"
  )
})

testthat::test_that("refresh_token success updates tokens and preserves when not rotated", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # Ensure provider expects body auth to exercise param paths
  cli@provider@token_auth_style <- "body"

  # Case A: rotation -> new refresh_token returned
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      # Verify body form has grant_type=refresh_token
      # We can't easily read it here; assume methods__token builds it correctly.
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new_at","refresh_token":"new_rt","expires_in":3600}'
        )
      )
    },
    .package = "shinyOAuth"
  )
  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "old_rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )
  t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "new_at")
  testthat::expect_identical(t2@refresh_token, "new_rt")
  testthat::expect_true(is.finite(t2@expires_at))

  # Case B: no rotation -> provider omits refresh_token or empty -> keep old
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"access_token":"newer_at","expires_in":"60"}')
      )
    },
    .package = "shinyOAuth"
  )
  kept_rt <- t2@refresh_token
  t3 <- refresh_token(cli, t2, async = FALSE, introspect = FALSE)
  testthat::expect_identical(t3@access_token, "newer_at")
  testthat::expect_identical(t3@refresh_token, kept_rt)
  # expires_in was a quoted string -> coerce_expires_in -> finite expires_at
  testthat::expect_true(is.finite(t3@expires_at))
})

testthat::test_that("refresh_token can fetch userinfo and optionally introspect", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # Set URLs first to satisfy provider validation when toggling userinfo_required
  cli@provider@userinfo_url <- "https://example.com/userinfo"
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@provider@userinfo_required <- TRUE

  # First, mock both token response and userinfo + introspection
  calls <- list(token = 0L, userinfo = 0L, introspection = 0L)
  testthat::local_mocked_bindings(
    req_with_retry = function(req) {
      url <- as.character(req$url)
      if (grepl("/token", url, fixed = TRUE)) {
        calls$token <<- calls$token + 1L
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"access_token":"at3","expires_in":120}')
        )
      } else if (grepl("/userinfo", url, fixed = TRUE)) {
        calls$userinfo <<- calls$userinfo + 1L
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"sub":"u-42"}')
        )
      } else if (grepl("/introspect", url, fixed = TRUE)) {
        calls$introspection <<- calls$introspection + 1L
        httr2::response(
          url = url,
          status = 200,
          headers = list("content-type" = "application/json"),
          body = charToRaw('{"active":true}')
        )
      } else {
        httr2::response(url = url, status = 200)
      }
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old",
    refresh_token = "rt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )
  t4 <- refresh_token(cli, t, async = FALSE, introspect = TRUE)
  testthat::expect_true(S7::S7_inherits(t4, OAuthToken))
  testthat::expect_true(is.list(t4@userinfo))
  testthat::expect_identical(t4@userinfo$sub, "u-42")
  # We expect at least one token call and one userinfo call
  testthat::expect_gte(calls$token, 1L)
  testthat::expect_gte(calls$userinfo, 1L)
  # Introspection is best-effort/optional, but with introspect=TRUE and URL set,
  # it should have been called once.
  testthat::expect_gte(calls$introspection, 1L)
})
