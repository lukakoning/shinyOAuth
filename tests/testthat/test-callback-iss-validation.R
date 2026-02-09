# Tests for RFC 9207: Authorization Server Issuer Identification
# Verifies that callback `iss` parameter is validated against the
# provider's configured issuer in oauth_module_server .process_query().

# Helper: build provider + client for callback iss tests
make_iss_test_client <- function(issuer = "https://issuer.example.com") {
  prov <- oauth_provider(
    name = "oidc-iss-test",
    auth_url = paste0(issuer, "/auth"),
    token_url = paste0(issuer, "/token"),
    issuer = issuer,
    id_token_validation = FALSE,
    id_token_required = FALSE,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = "body"
  )
  oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = c("openid"),
    scope_validation = "none",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

test_that("callback iss matching expected issuer is accepted", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  cli <- make_iss_test_client()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t", token_type = "Bearer", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0(
            "?code=ok&state=",
            enc,
            "&iss=",
            utils::URLencode("https://issuer.example.com", reserved = TRUE)
          ))
          session$flushReact()
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      testthat::expect_true(isTRUE(values$authenticated))
      testthat::expect_null(values$error)
    }
  )
})

test_that("callback iss mismatching expected issuer is rejected", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  cli <- make_iss_test_client()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t", token_type = "Bearer", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0(
            "?code=ok&state=",
            enc,
            "&iss=",
            utils::URLencode("https://evil.example.com", reserved = TRUE)
          ))
          session$flushReact()
        }
      )

      testthat::expect_null(values$token)
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "issuer_mismatch")
    }
  )
})

test_that("callback without iss parameter retains current behavior", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  cli <- make_iss_test_client()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      token <- testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t", token_type = "Bearer", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", enc))
          session$flushReact()
          values$token
        }
      )

      testthat::expect_false(is.null(token))
      testthat::expect_true(isTRUE(values$authenticated))
    }
  )
})

test_that("callback iss with trailing slash rejected under strict equality", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  cli <- make_iss_test_client()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      testthat::with_mocked_bindings(
        swap_code_for_token_set = function(client, code, code_verifier) {
          list(access_token = "t", token_type = "Bearer", expires_in = 3600)
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0(
            "?code=ok&state=",
            enc,
            "&iss=",
            utils::URLencode("https://issuer.example.com/", reserved = TRUE)
          ))
          session$flushReact()
          # Strict issuer matching: trailing slash difference is rejected (RFC 9207)
          testthat::expect_null(values$token)
          testthat::expect_false(isTRUE(values$authenticated))
        }
      )
    }
  )
})

test_that("callback iss rejected for error response too (RFC 9207)", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  cli <- make_iss_test_client()

  shiny::testServer(
    app = oauth_module_server,
    args = list(
      id = "auth",
      client = cli,
      auto_redirect = FALSE,
      indefinite_session = TRUE
    ),
    expr = {
      testthat::expect_true(values$has_browser_token())
      url <- values$build_auth_url()
      enc <- parse_query_param(url, "state")

      values$.process_query(paste0(
        "?error=access_denied&state=",
        enc,
        "&iss=",
        utils::URLencode("https://evil.example.com", reserved = TRUE)
      ))
      session$flushReact()

      testthat::expect_identical(values$error, "issuer_mismatch")
    }
  )
})
