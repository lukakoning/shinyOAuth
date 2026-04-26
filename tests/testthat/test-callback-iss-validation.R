# Tests for RFC 9207: Authorization Server Issuer Identification
# Verifies that callback `iss` parameter is validated against the
# provider's configured issuer in both oauth_module_server() and the
# exported low-level handle_callback() API.

# Helper: build provider + client for callback iss tests
make_iss_test_client <- function(
  issuer = "https://issuer.example.com",
  require_callback_issuer = FALSE
) {
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
    require_callback_issuer = require_callback_issuer,
    scopes = c("openid"),
    scope_validation = "none",
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

test_that("callback issuer strictness is configured on OAuthClient", {
  expect_true(
    "require_callback_issuer" %in% names(formals(shinyOAuth::oauth_client))
  )
  expect_false(
    "require_callback_issuer" %in%
      names(formals(shinyOAuth::oauth_module_server))
  )
  expect_false(
    "require_callback_issuer" %in% names(formals(shinyOAuth::handle_callback))
  )
})

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

test_that("callback iss matching expected issuer is accepted in strict mode", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  cli <- make_iss_test_client(require_callback_issuer = TRUE)

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

test_that("callback without iss parameter is rejected in strict mode", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))
  cli <- make_iss_test_client(require_callback_issuer = TRUE)

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
          testthat::fail("token exchange should not run when iss is required")
        },
        .package = "shinyOAuth",
        {
          values$.process_query(paste0("?code=ok&state=", enc))
          session$flushReact()
        }
      )

      testthat::expect_null(values$token)
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "issuer_missing")
    }
  )
})

test_that("strict callback issuer mode requires a configured provider issuer", {
  withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

  testthat::expect_error(
    oauth_client(
      provider = oauth_provider(
        name = "plain-oauth",
        auth_url = "https://example.com/auth",
        token_url = "https://example.com/token",
        id_token_validation = FALSE,
        id_token_required = FALSE,
        use_nonce = FALSE,
        use_pkce = TRUE,
        token_auth_style = "body"
      ),
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      require_callback_issuer = TRUE,
      scopes = character(0),
      scope_validation = "none",
      state_store = cachem::cache_mem(max_age = 600),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      )
    ),
    "require_callback_issuer"
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

test_that("callback with empty iss parameter is rejected as invalid query", {
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

      # Empty iss (e.g., ?iss=) should be rejected by validate_untrusted_query_param
      # as non-empty is required, rather than silently skipping RFC 9207 check
      values$.process_query(paste0("?code=ok&state=", enc, "&iss="))
      session$flushReact()

      testthat::expect_null(values$token)
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "invalid_callback_query")
    }
  )
})

test_that("callback with oversized iss parameter is rejected", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.callback_max_iss_bytes = 64
  ))
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

      # iss exceeding byte cap should be rejected
      long_iss <- paste0("https://issuer.example.com/", strrep("x", 100))
      values$.process_query(paste0(
        "?code=ok&state=",
        enc,
        "&iss=",
        utils::URLencode(long_iss, reserved = TRUE)
      ))
      session$flushReact()

      testthat::expect_null(values$token)
      testthat::expect_false(isTRUE(values$authenticated))
      testthat::expect_identical(values$error, "invalid_callback_query")
    }
  )
})

test_that("handle_callback accepts matching callback iss", {
  cli <- make_iss_test_client()
  browser_token <- valid_browser_token()
  url <- shinyOAuth::prepare_call(cli, browser_token = browser_token)
  enc <- parse_query_param(url, "state")

  token <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", token_type = "Bearer", expires_in = 3600)
    },
    .package = "shinyOAuth",
    {
      shinyOAuth::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = browser_token,
        iss = "https://issuer.example.com"
      )
    }
  )

  testthat::expect_true(
    is.character(token@access_token) && nzchar(token@access_token)
  )
})

test_that("handle_callback rejects mismatched callback iss before token exchange", {
  cli <- make_iss_test_client()
  browser_token <- valid_browser_token()
  url <- shinyOAuth::prepare_call(cli, browser_token = browser_token)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      testthat::fail(
        "token exchange should not run when callback iss mismatches"
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth::handle_callback(
          cli,
          code = "ok",
          payload = enc,
          browser_token = browser_token,
          iss = "https://evil.example.com"
        ),
        class = "shinyOAuth_state_error",
        regexp = "does not match expected issuer"
      )
    }
  )
})

test_that("handle_callback rejects missing iss in strict mode before token exchange", {
  cli <- make_iss_test_client(require_callback_issuer = TRUE)
  browser_token <- valid_browser_token()
  url <- shinyOAuth::prepare_call(cli, browser_token = browser_token)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      testthat::fail(
        "token exchange should not run when callback iss is required"
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth::handle_callback(
          cli,
          code = "ok",
          payload = enc,
          browser_token = browser_token
        ),
        class = "shinyOAuth_state_error",
        regexp = "missing required iss"
      )
    }
  )
})

test_that("handle_callback strict issuer mode requires a configured provider issuer", {
  testthat::expect_error(
    oauth_client(
      provider = oauth_provider(
        name = "plain-oauth",
        auth_url = "https://example.com/auth",
        token_url = "https://example.com/token",
        id_token_validation = FALSE,
        id_token_required = FALSE,
        use_nonce = FALSE,
        use_pkce = TRUE,
        token_auth_style = "body"
      ),
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      require_callback_issuer = TRUE,
      scopes = character(0),
      scope_validation = "none",
      state_store = cachem::cache_mem(max_age = 600),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      )
    ),
    class = "shinyOAuth_config_error",
    regexp = "require_callback_issuer"
  )
})
