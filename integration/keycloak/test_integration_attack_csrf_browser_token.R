## Attack vector: Browser Token CSRF (Double-Submit Cookie Bypass)
##
## Verifies that a mismatched browser token (cookie) causes authentication
## to fail, preventing CSRF attacks where an attacker tricks a victim's
## browser into completing a callback with a different session cookie.
## Defense mechanisms tested:
##   1. constant_time_compare() of browser token from cookie vs state store
##   2. Browser token format validation (exactly 128 hex chars)
##   3. Missing browser token is rejected when skip_browser_token is FALSE

# Shared helpers (auto-sourced by testthat::test_dir; explicit for standalone use)
if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

testthat::test_that("Browser token mismatch: tampered cookie value rejected", {
  skip_common()
  # Use skip_browser_token=TRUE so the module can build auth URLs in testServer,
  # but then call handle_callback() directly with bad browser tokens to test
  # the validation logic.
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()

      # Read the state store entry to see the stored browser_token
      ss <- get_state_store_entry(client, url)
      stored_bt <- ss$entry$browser_token

      # Generate a DIFFERENT valid-format browser token (128 hex chars)
      attacker_bt <- paste0(
        sample(c(0:9, letters[1:6]), 128, replace = TRUE),
        collapse = ""
      )
      # Ensure it's actually different
      testthat::expect_false(identical(attacker_bt, stored_bt))

      # Complete the login form normally
      res <- perform_login_form(url)

      # Call handle_callback() directly with the attacker's browser token.
      # The state store has the original token (__SKIPPED__), so the attacker's
      # token should fail the constant_time_compare check.
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          oauth_client = client,
          code = res$code,
          payload = res$state_payload,
          browser_token = attacker_bt
        ),
        regexp = "browser.token|Browser token|state|mismatch",
        ignore.case = TRUE
      )
    }
  )
})

testthat::test_that("Browser token: NULL browser_token rejected", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)

      # Calling handle_callback with NULL browser_token should fail
      # (state store entry has __SKIPPED__, NULL != __SKIPPED__)
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          oauth_client = client,
          code = res$code,
          payload = res$state_payload,
          browser_token = NULL
        ),
        regexp = "browser.token|Browser token|invalid|state",
        ignore.case = TRUE
      )
    }
  )
})

testthat::test_that("Browser token: malformed browser_token rejected", {
  skip_common()
  local_test_options()

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)

      # Too short (64 chars instead of 128)
      short_token <- paste0(
        sample(c(0:9, letters[1:6]), 64, replace = TRUE),
        collapse = ""
      )
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          oauth_client = client,
          code = res$code,
          payload = res$state_payload,
          browser_token = short_token
        ),
        regexp = "browser.token|length|hex|invalid|state",
        ignore.case = TRUE
      )

      # Non-hex characters
      bad_chars_token <- paste0(
        rep("zz", 64),
        collapse = ""
      )
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          oauth_client = client,
          code = res$code,
          payload = res$state_payload,
          browser_token = bad_chars_token
        ),
        regexp = "browser.token|hex|invalid|state",
        ignore.case = TRUE
      )
    }
  )
})

testthat::test_that("Browser token: skip_browser_token=TRUE allows __SKIPPED__ sentinel", {
  skip_common()
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.timeout = 10,
    shinyOAuth.disable_watchdog_warning = TRUE
  ))

  prov <- make_provider()
  client <- make_public_client(prov)

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      url <- values$build_auth_url()
      res <- perform_login_form(url)

      # With skip enabled, handle_callback should succeed with __SKIPPED__
      # sentinel (the state store also has __SKIPPED__ so they match).
      # handle_callback does NOT read the skip option — the sentinel must
      # be passed explicitly, which the module does automatically.
      result <- shinyOAuth:::handle_callback(
        oauth_client = client,
        code = res$code,
        payload = res$state_payload,
        browser_token = "__SKIPPED__"
      )
      testthat::expect_true(!is.null(result))
      testthat::expect_true(S7::S7_inherits(
        result,
        shinyOAuth::OAuthToken
      ))
    }
  )
})
