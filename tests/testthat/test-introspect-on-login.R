test_that("handle_callback with introspect=TRUE fails when introspection unsupported", {
  # To test that handle_callback fails when introspection is enabled but the
  # provider doesn't support it, we need to mock introspect_token to simulate
  # an unsupported scenario (since OAuthClient validation now catches missing
  # introspection_url at construction time).

  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # First, configure an introspection_url on the provider so the client can be created
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@introspect <- TRUE

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
    # Mock introspect_token to return unsupported (simulates provider not supporting it)
    introspect_token = function(oauth_client, oauth_token, which, async) {
      list(
        supported = FALSE,
        active = NA,
        status = "introspection_unsupported"
      )
    },
    .package = "shinyOAuth",
    {
      # With introspect=TRUE and mock returning unsupported, should fail
      testthat::expect_error(
        shinyOAuth:::handle_callback(
          cli,
          code = "abc",
          payload = enc,
          browser_token = tok
        ),
        class = "shinyOAuth_token_error",
        regexp = "introspection required but provider does not support"
      )
    }
  )
})

test_that("handle_callback respects client@introspect setting (no introspect by default)", {
  # Test that a client with introspect = FALSE doesn't do introspection
  cli <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  # introspect defaults to FALSE

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
        browser_token = tok
      )
      testthat::expect_s3_class(tok_ok, "shinyOAuth::OAuthToken")
    }
  )
})

test_that("OAuthClient validates introspect configuration at construction time", {
  # These checks are done when creating/modifying the OAuthClient

  # Providing elements while introspect is FALSE is an error
  # (S7 validation returns an S7_error, not shinyOAuth_config_error)
  testthat::expect_error(
    make_test_client(
      use_pkce = TRUE,
      use_nonce = FALSE,
      introspect = FALSE,
      introspect_elements = "sub"
    ),
    regexp = "introspect_elements.*introspect = FALSE"
  )

  # Invalid element values should be rejected
  # Need to first set up introspection_url for this to work
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@introspection_url <- "https://example.com/introspect"

  testthat::expect_error(
    shinyOAuth::oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      introspect = TRUE,
      introspect_elements = c("sub", "nope")
    ),
    regexp = "invalid introspect_elements"
  )

  # NA / empty string should be rejected
  testthat::expect_error(
    shinyOAuth::oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      introspect = TRUE,
      introspect_elements = c(NA_character_)
    ),
    regexp = "must not contain NA"
  )

  testthat::expect_error(
    shinyOAuth::oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      introspect = TRUE,
      introspect_elements = c("")
    ),
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

# Helper to create a test client with introspection configured
make_introspect_client <- function(...) {
  cli <- make_test_client(...)
  cli@provider@introspection_url <- "https://example.com/introspect"
  cli@introspect <- TRUE
  cli
}

test_that("handle_callback with introspect=TRUE fails when token is inactive", {
  cli <- make_introspect_client(use_pkce = TRUE, use_nonce = FALSE)

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
          browser_token = tok
        ),
        class = "shinyOAuth_token_error",
        regexp = "introspection indicates the access token is not active"
      )
    }
  )
})

test_that("handle_callback with introspect=TRUE succeeds when token is active", {
  cli <- make_introspect_client(use_pkce = TRUE, use_nonce = FALSE)

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
        browser_token = tok
      )
      testthat::expect_s3_class(tok_obj, "shinyOAuth::OAuthToken")
      testthat::expect_equal(tok_obj@access_token, "at")
    }
  )
})

test_that("introspect_elements can require sub match (id_token)", {
  cli <- make_introspect_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@introspect_elements <- "sub"

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
        browser_token = tok
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
          browser_token = tok
        ),
        class = "shinyOAuth_token_error",
        regexp = "sub does not match"
      )
    }
  )
})

test_that("introspect_elements can require client_id match", {
  cli <- make_introspect_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@introspect_elements <- "client_id"

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
          browser_token = tok
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
          browser_token = tok
        ),
        class = "shinyOAuth_token_error",
        regexp = "client_id does not match"
      )
    }
  )
})

test_that("introspect_elements can require scopes", {
  cli <- make_introspect_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = c("openid", "profile")
  )
  cli@introspect_elements <- "scope"

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer",
        scope = "openid profile"
      )
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
          browser_token = tok
        )
      )
    }
  )

  # Reduced scopes should follow client@scope_validation
  cli_warn <- make_introspect_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = c("openid", "profile")
  )
  cli_warn@scope_validation <- "warn"
  cli_warn@introspect_elements <- "scope"
  urlw <- shinyOAuth:::prepare_call(cli_warn, browser_token = tok)
  encw <- parse_query_param(urlw, "state")
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer",
        scope = "openid profile"
      )
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
          browser_token = tok
        ),
        regexp = "Introspected scopes missing requested entries"
      )
    }
  )

  cli_none <- make_introspect_client(
    use_pkce = TRUE,
    use_nonce = FALSE,
    scopes = c("openid", "profile")
  )
  cli_none@scope_validation <- "none"
  cli_none@introspect_elements <- "scope"
  urln <- shinyOAuth:::prepare_call(cli_none, browser_token = tok)
  encn <- parse_query_param(urln, "state")
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer",
        scope = "openid profile"
      )
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
          browser_token = tok
        )
      )
    }
  )

  url2 <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc2 <- parse_query_param(url2, "state")
  testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "at",
        expires_in = 3600,
        token_type = "Bearer",
        scope = "openid profile"
      )
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
          browser_token = tok
        ),
        class = "shinyOAuth_token_error",
        regexp = "Introspected scopes missing"
      )
    }
  )
})

test_that("introspect_elements errors when required fields are missing", {
  cli <- make_introspect_client(use_pkce = TRUE, use_nonce = FALSE)
  cli@introspect_elements <- "sub"

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
          browser_token = tok
        ),
        class = "shinyOAuth_token_error",
        regexp = "missing required sub"
      )
    }
  )
})

test_that("handle_callback with introspect=TRUE fails on introspection http error", {
  cli <- make_introspect_client(use_pkce = TRUE, use_nonce = FALSE)

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
          browser_token = tok
        ),
        class = "shinyOAuth_token_error",
        regexp = "introspection indicates the access token is not active"
      )
    }
  )
})

test_that("introspect_token emits audit events during login", {
  cli <- make_introspect_client(use_pkce = TRUE, use_nonce = FALSE)

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
        browser_token = tok
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
  cli <- make_introspect_client(use_pkce = TRUE, use_nonce = FALSE)

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
          browser_token = tok
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
