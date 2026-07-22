testthat::test_that("token refresh does not extend reauthentication lifetime", {
  testthat::skip_if_not_installed("promises")
  testthat::skip_if_not_installed("later")
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  for (async_mode in c(FALSE, TRUE)) {
    cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
    auth_started_at <- as.numeric(Sys.time()) - 5

    shiny::testServer(
      app = oauth_module_server,
      args = list(
        id = "auth",
        client = cli,
        auto_redirect = FALSE,
        async = async_mode,
        reauth_after_seconds = 60,
        refresh_proactively = TRUE,
        refresh_lead_seconds = 4000,
        refresh_check_interval = 100
      ),
      expr = {
        refreshed <- OAuthToken(
          access_token = "refreshed",
          refresh_token = "refresh-2",
          expires_at = as.numeric(Sys.time()) + 10000
        )

        testthat::with_mocked_bindings(
          refresh_token = function(...) {
            if (isTRUE(async_mode)) {
              promises::promise_resolve(refreshed)
            } else {
              refreshed
            }
          },
          .package = "shinyOAuth",
          {
            values$auth_started_at <- auth_started_at
            values$token <- OAuthToken(
              access_token = "initial",
              refresh_token = "refresh-1",
              expires_at = as.numeric(Sys.time()) + 3600
            )
            poll_for_async(
              function() values$refresh_success_generation == 1L,
              session
            )
          }
        )

        testthat::expect_identical(
          values$auth_started_at,
          auth_started_at,
          info = paste("async =", async_mode)
        )
        testthat::expect_identical(values$token@access_token, "refreshed")
      }
    )
  }
})

testthat::test_that("OIDC reauthentication sends and binds max_age zero", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = TRUE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      reauth_after_seconds = 1
    ),
    expr = {
      values$auth_started_at <- as.numeric(Sys.time()) - 10
      values$token <- OAuthToken(
        access_token = "old",
        expires_at = as.numeric(Sys.time()) + 3600
      )
      session$flushReact()

      testthat::expect_identical(values$error, "reauth_required")
      url <- values$build_auth_url()
      state <- parse_query_param(url, "state")
      payload <- shinyOAuth:::state_payload_decrypt_validate(cli, state)

      testthat::expect_identical(
        parse_query_param(url, "max_age", decode = TRUE),
        "0"
      )
      testthat::expect_equal(payload[["max_age"]], 0)
    }
  )
})

testthat::test_that("OAuth-only reauthentication remains a local lifetime", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      reauth_after_seconds = 1
    ),
    expr = {
      values$auth_started_at <- as.numeric(Sys.time()) - 10
      values$token <- OAuthToken(
        access_token = "old",
        expires_at = as.numeric(Sys.time()) + 3600
      )
      session$flushReact()

      testthat::expect_identical(values$error, "reauth_required")
      url <- values$build_auth_url()
      testthat::expect_true(is.na(parse_query_param(
        url,
        "max_age",
        decode = TRUE
      )))
    }
  )
})

testthat::test_that("validated auth_time starts the reauthentication lifetime", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  auth_time <- floor(as.numeric(Sys.time())) - 30
  token <- OAuthToken(
    access_token = "with-auth-time",
    id_token = build_dummy_jwt(list(sub = "user-1", auth_time = auth_time)),
    id_token_validated = TRUE,
    expires_at = as.numeric(Sys.time()) + 3600
  )

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE
    ),
    expr = {
      url <- values$build_auth_url()
      state <- parse_query_param(url, "state")

      testthat::with_mocked_bindings(
        handle_callback = function(...) token,
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", state))
        }
      )

      testthat::expect_identical(values$auth_started_at, auth_time)
      testthat::expect_identical(values$token@access_token, "with-auth-time")
    }
  )
})

testthat::test_that("transaction max_age requires a validated ID token", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  testthat::expect_error(
    shinyOAuth:::verify_token_set(
      cli,
      token_set = list(
        access_token = "access-only",
        token_type = "Bearer",
        scope = "openid"
      ),
      nonce = NULL,
      requested_max_age = 0
    ),
    "ID token required"
  )
})
