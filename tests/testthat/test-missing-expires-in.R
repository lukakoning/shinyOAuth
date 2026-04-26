# Tests for the warning emitted when `expires_in` is absent from a token
# response (RFC 6749 §5.1: expires_in is RECOMMENDED).
# When missing, `expires_at` falls back to a finite lifetime (default 3600
# seconds, or a configurable value via `options(shinyOAuth.default_expires_in)`).
# A warning is emitted so operators know the value was not server-provided.

# --- Login path (swap_code_for_token_set → OAuthToken construction) ----------

testthat::test_that("handle_callback warns when expires_in is absent (login)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  rlang::reset_warning_verbosity("expires_in_missing-exchange_code")
  withr::local_options(shinyOAuth.default_expires_in = NULL)

  # Mock token exchange to return a response WITHOUT expires_in
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"access_token":"tok_no_exp","token_type":"bearer"}')
      )
    },
    .package = "shinyOAuth"
  )

  bt <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = bt)
  enc <- parse_query_param(url, "state")
  before <- as.numeric(Sys.time())

  testthat::expect_warning(
    {
      tok <- handle_callback(
        cli,
        code = "auth_code_123",
        payload = enc,
        browser_token = bt
      )
    },
    class = "shinyOAuth_missing_expires_in"
  )
  after <- as.numeric(Sys.time())

  testthat::expect_true(S7::S7_inherits(tok, OAuthToken))
  testthat::expect_identical(tok@access_token, "tok_no_exp")
  testthat::expect_true(is.finite(tok@expires_at))
  testthat::expect_gte(tok@expires_at, before + 3600)
  testthat::expect_lte(tok@expires_at, after + 3600)
})

testthat::test_that("handle_callback does NOT warn when expires_in is present (login)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"tok_exp","token_type":"bearer","expires_in":3600}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  bt <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = bt)
  enc <- parse_query_param(url, "state")

  testthat::expect_no_warning({
    tok <- handle_callback(
      cli,
      code = "auth_code_456",
      payload = enc,
      browser_token = bt
    )
  })

  testthat::expect_true(S7::S7_inherits(tok, OAuthToken))
  testthat::expect_identical(tok@access_token, "tok_exp")
  testthat::expect_true(is.finite(tok@expires_at))
})

# --- Refresh path (refresh_token → expires_at assignment) --------------------

testthat::test_that("refresh_token warns when expires_in is absent (refresh)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  rlang::reset_warning_verbosity("expires_in_missing-refresh_token")
  withr::local_options(shinyOAuth.default_expires_in = NULL)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"refreshed_tok","token_type":"bearer"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt_123",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )
  before <- as.numeric(Sys.time())

  testthat::expect_warning(
    {
      t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
    },
    class = "shinyOAuth_missing_expires_in"
  )
  after <- as.numeric(Sys.time())

  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "refreshed_tok")
  testthat::expect_true(is.finite(t2@expires_at))
  testthat::expect_gte(t2@expires_at, before + 3600)
  testthat::expect_lte(t2@expires_at, after + 3600)
})

testthat::test_that("refresh_token does NOT warn when expires_in is present (refresh)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"refreshed_tok2","token_type":"bearer","expires_in":7200}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt_456",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )

  testthat::expect_no_warning({
    t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE)
  })

  testthat::expect_true(S7::S7_inherits(t2, OAuthToken))
  testthat::expect_identical(t2@access_token, "refreshed_tok2")
  testthat::expect_true(is.finite(t2@expires_at))
})

# --- Unit test for resolve_missing_expires_in itself -------------------------

testthat::test_that("resolve_missing_expires_in uses 3600-second fallback without option", {
  # Reset rlang once-per-session frequency guard for this warning
  rlang::reset_warning_verbosity("expires_in_missing-test_phase")
  withr::local_options(shinyOAuth.default_expires_in = NULL)

  before <- as.numeric(Sys.time())
  result <- NULL
  w <- testthat::expect_warning(
    result <- shinyOAuth:::resolve_missing_expires_in(phase = "test_phase"),
    class = "shinyOAuth_missing_expires_in"
  )
  after <- as.numeric(Sys.time())

  testthat::expect_true(is.finite(result))
  testthat::expect_gte(result, before + 3600)
  testthat::expect_lte(result, after + 3600)
  testthat::expect_match(
    conditionMessage(w),
    "expires_in",
    fixed = TRUE
  )
  testthat::expect_match(
    conditionMessage(w),
    "3600",
    fixed = TRUE
  )
})

testthat::test_that("resolve_missing_expires_in uses configurable default", {
  rlang::reset_warning_verbosity("expires_in_missing-opt_phase")
  withr::local_options(shinyOAuth.default_expires_in = 1800)

  before <- as.numeric(Sys.time())
  result <- NULL
  w <- testthat::expect_warning(
    result <- shinyOAuth:::resolve_missing_expires_in(phase = "opt_phase"),
    class = "shinyOAuth_missing_expires_in"
  )
  after <- as.numeric(Sys.time())

  # Should be now + 1800, NOT Inf
  testthat::expect_true(is.finite(result))
  testthat::expect_gte(result, before + 1800)
  testthat::expect_lte(result, after + 1800)
  # Warning should mention the option value
  testthat::expect_match(
    conditionMessage(w),
    "1800",
    fixed = TRUE
  )
})

testthat::test_that("resolve_missing_expires_in ignores invalid option values", {
  withr::local_options(shinyOAuth.default_expires_in = "not_a_number")
  rlang::reset_warning_verbosity("expires_in_missing-bad_opt1")

  before <- as.numeric(Sys.time())
  result <- NULL
  testthat::expect_warning(
    result <- shinyOAuth:::resolve_missing_expires_in(phase = "bad_opt1"),
    class = "shinyOAuth_missing_expires_in"
  )
  after <- as.numeric(Sys.time())
  testthat::expect_true(is.finite(result))
  testthat::expect_gte(result, before + 3600)
  testthat::expect_lte(result, after + 3600)

  # Negative value
  withr::local_options(shinyOAuth.default_expires_in = -100)
  rlang::reset_warning_verbosity("expires_in_missing-bad_opt2")

  before2 <- as.numeric(Sys.time())
  result2 <- NULL
  testthat::expect_warning(
    result2 <- shinyOAuth:::resolve_missing_expires_in(phase = "bad_opt2"),
    class = "shinyOAuth_missing_expires_in"
  )
  after2 <- as.numeric(Sys.time())
  testthat::expect_true(is.finite(result2))
  testthat::expect_gte(result2, before2 + 3600)
  testthat::expect_lte(result2, after2 + 3600)

  # Zero
  withr::local_options(shinyOAuth.default_expires_in = 0)
  rlang::reset_warning_verbosity("expires_in_missing-bad_opt3")

  before3 <- as.numeric(Sys.time())
  result3 <- NULL
  testthat::expect_warning(
    result3 <- shinyOAuth:::resolve_missing_expires_in(phase = "bad_opt3"),
    class = "shinyOAuth_missing_expires_in"
  )
  after3 <- as.numeric(Sys.time())
  testthat::expect_true(is.finite(result3))
  testthat::expect_gte(result3, before3 + 3600)
  testthat::expect_lte(result3, after3 + 3600)
})

testthat::test_that("resolve_missing_expires_in fires only once per phase", {
  rlang::reset_warning_verbosity("expires_in_missing-dedup_phase")
  withr::local_options(shinyOAuth.default_expires_in = NULL)

  # First call: should warn
  testthat::expect_warning(
    shinyOAuth:::resolve_missing_expires_in(phase = "dedup_phase"),
    class = "shinyOAuth_missing_expires_in"
  )

  # Second call with same phase: suppressed by .frequency = "once"
  testthat::expect_no_warning(
    shinyOAuth:::resolve_missing_expires_in(phase = "dedup_phase")
  )
})

# --- Integration: configurable default propagates through login/refresh ------

testthat::test_that("handle_callback uses default_expires_in option (login)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  rlang::reset_warning_verbosity("expires_in_missing-exchange_code")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"access_token":"tok_opt","token_type":"bearer"}')
      )
    },
    .package = "shinyOAuth"
  )

  withr::local_options(shinyOAuth.default_expires_in = 900)

  bt <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = bt)
  enc <- parse_query_param(url, "state")

  before <- as.numeric(Sys.time())
  testthat::expect_warning(
    tok <- handle_callback(
      cli,
      code = "auth_code_opt",
      payload = enc,
      browser_token = bt
    ),
    class = "shinyOAuth_missing_expires_in"
  )
  after <- as.numeric(Sys.time())

  testthat::expect_true(is.finite(tok@expires_at))
  testthat::expect_gte(tok@expires_at, before + 900)
  testthat::expect_lte(tok@expires_at, after + 900)
})

testthat::test_that("refresh_token uses default_expires_in option (refresh)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  rlang::reset_warning_verbosity("expires_in_missing-refresh_token")

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"refreshed_opt","token_type":"bearer"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  withr::local_options(shinyOAuth.default_expires_in = 600)

  t <- OAuthToken(
    access_token = "old_at",
    refresh_token = "rt_opt",
    expires_at = as.numeric(Sys.time()) + 10,
    id_token = NA_character_
  )

  before <- as.numeric(Sys.time())
  testthat::expect_warning(
    t2 <- refresh_token(cli, t, async = FALSE, introspect = FALSE),
    class = "shinyOAuth_missing_expires_in"
  )
  after <- as.numeric(Sys.time())

  testthat::expect_true(is.finite(t2@expires_at))
  testthat::expect_gte(t2@expires_at, before + 600)
  testthat::expect_lte(t2@expires_at, after + 600)
})
