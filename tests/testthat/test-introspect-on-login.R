test_that("handle_callback with introspect=TRUE fails when introspection unsupported", {
  # Provider without introspection_url

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- NA_character_

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer"
      )
    },
    .package = "shinyOAuth",
    {
      # Without introspect, should succeed
      tok_ok <- shinyOAuth:::handle_callback(
        cli,
        code = "abc",
        payload = enc,
        browser_token = tok,
        introspect = FALSE
      )
      testthat::expect_s3_class(tok_ok, "shinyOAuth::OAuthToken")

      # Re-prepare state for next call
      url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
      enc2 <- parse_query_param(url2, "state")

      # With introspect=TRUE and no introspection_url, should fail
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc2,
          browser_token = tok,
          introspect = TRUE
        ),
        class = "shinyOAuth_token_error",
        regexp = "introspection required but provider does not support"
      )
    }
  )
})

test_that("handle_callback fails fast for invalid introspection arguments", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)

  # Providing elements while introspect is FALSE is a config error
  testthat::expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = "state",
      browser_token = valid_browser_token(),
      introspect = FALSE,
      introspect_elements = "sub"
    ),
    class = "shinyOAuth_config_error",
    regexp = "introspect_elements.*introspect = FALSE"
  )

  # Invalid element values should be rejected as config errors
  testthat::expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = "state",
      browser_token = valid_browser_token(),
      introspect = TRUE,
      introspect_elements = c("sub", "nope")
    ),
    class = "shinyOAuth_config_error",
    regexp = "Invalid `introspect_elements`"
  )

  # NA / empty string should be rejected
  testthat::expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = "state",
      browser_token = valid_browser_token(),
      introspect = TRUE,
      introspect_elements = c(NA_character_)
    ),
    class = "shinyOAuth_config_error",
    regexp = "must not contain NA"
  )

  testthat::expect_error(
    shinyOAuth:::handle_callback(
      cli,
      code = "abc",
      payload = "state",
      browser_token = valid_browser_token(),
      introspect = TRUE,
      introspect_elements = c("")
    ),
    class = "shinyOAuth_config_error",
    regexp = "must not contain empty"
  )
})

.build_dummy_jwt <- function(payload) {
  # Minimal JWT string for parse_jwt_payload(): header.payload.signature
  hdr <- list(alg = "none", typ = "JWT")
  h <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    hdr,
    auto_unbox = TRUE
  )))
  p <- shinyOAuth:::b64url_encode(charToRaw(jsonlite::toJSON(
    payload,
    auto_unbox = TRUE
  )))
  paste0(h, ".", p, ".")
}

test_that("handle_callback with introspect=TRUE fails when token is inactive", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer"
      )
    },
    # Mock introspection to return inactive
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":false}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc,
          browser_token = tok,
          introspect = TRUE
        ),
        class = "shinyOAuth_token_error",
        regexp = "introspection indicates the access token is not active"
      )
    }
  )
})

test_that("handle_callback with introspect=TRUE succeeds when token is active", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer"
      )
    },
    # Mock introspection to return active
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth",
    {
      tok_obj <- shinyOAuth:::handle_callback(
        cli,
        code = "abc",
        payload = enc,
        browser_token = tok,
        introspect = TRUE
      )
      testthat::expect_s3_class(tok_obj, "shinyOAuth::OAuthToken")
      testthat::expect_equal(tok_obj@access_token, "at")
    }
  )
})

test_that("introspect_elements can require sub match (id_token)", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  idt <- .build_dummy_jwt(list(sub = "u1"))

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer",
        id_token = idt
      )
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true,"sub":"u1"}')
      )
    },
    .package = "shinyOAuth",
    {
      tok_obj <- shinyOAuth:::handle_callback(
        cli,
        code = "abc",
        payload = enc,
        browser_token = tok,
        introspect = TRUE,
        introspect_elements = "sub"
      )
      testthat::expect_equal(tok_obj@access_token, "at")
    }
  )

  # Mismatch should fail
  url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc2 <- parse_query_param(url2, "state")
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer",
        id_token = idt
      )
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true,"sub":"u2"}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc2,
          browser_token = tok,
          introspect = TRUE,
          introspect_elements = "sub"
        ),
        class = "shinyOAuth_token_error",
        regexp = "sub does not match"
      )
    }
  )
})

test_that("introspect_elements can require client_id match", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 3600, token_type = "Bearer")
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true,"client_id":"abc"}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_silent(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc,
          browser_token = tok,
          introspect = TRUE,
          introspect_elements = "client_id"
        )
      )
    }
  )

  url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc2 <- parse_query_param(url2, "state")
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 3600, token_type = "Bearer")
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true,"client_id":"wrong"}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc2,
          browser_token = tok,
          introspect = TRUE,
          introspect_elements = "client_id"
        ),
        class = "shinyOAuth_token_error",
        regexp = "client_id does not match"
      )
    }
  )
})

test_that("introspect_elements can require scopes", {
  cli <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = c("openid", "profile")
  )
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 3600, token_type = "Bearer")
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true,"scope":"openid profile"}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_silent(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc,
          browser_token = tok,
          introspect = TRUE,
          introspect_elements = "scope"
        )
      )
    }
  )

  # Reduced scopes should follow client@scope_validation
  cli_warn <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = c("openid", "profile")
  )
  cli_warn@scope_validation <- "warn"
  cli_warn@provider@introspection_url <- "https://example.com/introspect"
  urlw <- shinyOAuth:::prepare_call(cli_warn, browser_token = tok)
  encw <- parse_query_param(urlw, "state")
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 3600, token_type = "Bearer")
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true,"scope":"openid"}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_warning(
        shinyOAuth:::handle_callback(
          cli_warn,
          code = "abc",
          payload = encw,
          browser_token = tok,
          introspect = TRUE,
          introspect_elements = "scope"
        ),
        regexp = "Introspected scopes missing requested entries"
      )
    }
  )

  cli_none <- make_test_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = c("openid", "profile")
  )
  cli_none@scope_validation <- "none"
  cli_none@provider@introspection_url <- "https://example.com/introspect"
  urln <- shinyOAuth:::prepare_call(cli_none, browser_token = tok)
  encn <- parse_query_param(urln, "state")
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 3600, token_type = "Bearer")
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true,"scope":"openid"}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_silent(
        shinyOAuth:::handle_callback(
          cli_none,
          code = "abc",
          payload = encn,
          browser_token = tok,
          introspect = TRUE,
          introspect_elements = "scope"
        )
      )
    }
  )

  url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc2 <- parse_query_param(url2, "state")
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "at", expires_in = 3600, token_type = "Bearer")
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true,"scope":"openid"}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc2,
          browser_token = tok,
          introspect = TRUE,
          introspect_elements = "scope"
        ),
        class = "shinyOAuth_token_error",
        regexp = "Introspected scopes missing"
      )
    }
  )
})

test_that("introspect_elements errors when required fields are missing", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  idt <- .build_dummy_jwt(list(sub = "u1"))

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer",
        id_token = idt
      )
    },
    # Missing sub in introspection
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc,
          browser_token = tok,
          introspect = TRUE,
          introspect_elements = "sub"
        ),
        class = "shinyOAuth_token_error",
        regexp = "missing required sub"
      )
    }
  )
})

test_that("handle_callback with introspect=TRUE fails on introspection http error", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer"
      )
    },
    # Mock introspection to return HTTP error
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 500,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"error":"server_error"}')
      )
    },
    .package = "shinyOAuth",
    {
      # HTTP error results in active=NA which should fail the login
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc,
          browser_token = tok,
          introspect = TRUE
        ),
        class = "shinyOAuth_token_error",
        regexp = "introspection indicates the access token is not active"
      )
    }
  )
})

test_that("introspect_token emits audit events during login", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events <<- c(events, list(event))
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer"
      )
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth",
    {
      tok_obj <- shinyOAuth:::handle_callback(
        cli,
        code = "abc",
        payload = enc,
        browser_token = tok,
        introspect = TRUE
      )
    }
  )

  event_types <- vapply(events, function(e) e$type, character(1))
  testthat::expect_true("audit_token_introspection" %in% event_types)

  intro_evt <- events[[which(event_types == "audit_token_introspection")]]
  testthat::expect_true(isTRUE(intro_evt$supported))
  testthat::expect_true(isTRUE(intro_evt$active))
  testthat::expect_equal(intro_evt$status, "ok")
  testthat::expect_equal(intro_evt$which, "access")
})

test_that("introspect_token emits audit events even when login fails", {
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@provider@introspection_url <- "https://example.com/introspect"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  events <- list()
  old_hook <- getOption("shinyOAuth.audit_hook")
  options(shinyOAuth.audit_hook = function(event) {
    events <<- c(events, list(event))
  })
  on.exit(options(shinyOAuth.audit_hook = old_hook), add = TRUE)

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer"
      )
    },
    req_with_retry = function(req) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":false}')
      )
    },
    .package = "shinyOAuth",
    {
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc,
          browser_token = tok,
          introspect = TRUE
        ),
        class = "shinyOAuth_token_error",
        regexp = "introspection indicates the access token is not active"
      )
    }
  )

  event_types <- vapply(events, function(e) e$type, character(1))
  testthat::expect_true("audit_token_introspection" %in% event_types)

  intro_evt <- events[[which(event_types == "audit_token_introspection")[1]]]
  testthat::expect_true(isTRUE(intro_evt$supported))
  testthat::expect_false(isTRUE(intro_evt$active))
  testthat::expect_equal(intro_evt$status, "ok")
  testthat::expect_equal(intro_evt$which, "access")
})
