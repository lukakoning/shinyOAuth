test_that("when allowed_token_types is empty, missing token_type is allowed", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  # Explicitly clear allowed token types to change enforcement policy
  prov@allowed_token_types <- character(0)

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  token <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      # No token_type field returned
      list(access_token = "t", expires_in = 5)
    },
    .package = "shinyOAuth",
    shinyOAuth:::handle_callback(
      cli,
      code = "ok",
      payload = enc,
      browser_token = tok
    )
  )
  expect_s3_class(token, "S7_object")
  expect_true(is.character(token@access_token))
})

test_that("DPoP clients keep empty allowed_token_types as a callback opt-out", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@allowed_token_types <- character(0)

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    dpop_private_key = openssl::rsa_keygen(),
    dpop_require_access_token = FALSE
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  token <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(access_token = "t", expires_in = 5)
    },
    .package = "shinyOAuth",
    shinyOAuth:::handle_callback(
      cli,
      code = "ok",
      payload = enc,
      browser_token = tok
    )
  )

  expect_s3_class(token, "S7_object")
  expect_identical(token@access_token, "t")
})

test_that("callback carries forward effective DPoP token_type for userinfo when omitted", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@allowed_token_types <- character(0)
  prov@userinfo_url <- "https://example.com/userinfo"
  prov@userinfo_required <- TRUE

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    dpop_private_key = openssl::rsa_keygen(),
    dpop_require_access_token = FALSE
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")
  seen <- new.env(parent = emptyenv())
  seen$token_type <- NA_character_

  token <- testthat::with_mocked_bindings(
    swap_code_for_token_set = function(client, code, code_verifier) {
      list(
        access_token = "t",
        cnf = list(jkt = shinyOAuth:::client_dpop_jkt(cli)),
        expires_in = 5
      )
    },
    get_userinfo = function(
      oauth_client,
      token,
      token_type = NULL,
      shiny_session = NULL
    ) {
      seen$token_type <- token@token_type
      list(sub = "user-1")
    },
    .package = "shinyOAuth",
    shinyOAuth:::handle_callback(
      cli,
      code = "ok",
      payload = enc,
      browser_token = tok
    )
  )

  expect_identical(seen$token_type, "DPoP")
  expect_identical(token@token_type, "DPoP")
  expect_identical(token@userinfo$sub, "user-1")
})

test_that("DPoP clients keep empty allowed_token_types as a refresh opt-out", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@allowed_token_types <- character(0)

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    dpop_private_key = openssl::rsa_keygen(),
    dpop_require_access_token = FALSE
  )

  token <- OAuthToken(
    access_token = "old-at",
    token_type = "Bearer",
    refresh_token = "refresh-1",
    expires_at = as.numeric(Sys.time()) + 10,
    userinfo = list()
  )

  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(req, client, idempotent = FALSE) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new-at","refresh_token":"refresh-2","expires_in":60}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  refreshed <- refresh_token(cli, token, async = FALSE, introspect = FALSE)

  expect_identical(refreshed@access_token, "new-at")
  expect_identical(refreshed@refresh_token, "refresh-2")
})

test_that("refresh carries forward effective DPoP token_type for userinfo when omitted", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@allowed_token_types <- character(0)
  prov@userinfo_url <- "https://example.com/userinfo"
  prov@userinfo_required <- TRUE

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    dpop_private_key = openssl::rsa_keygen(),
    dpop_require_access_token = FALSE
  )

  token <- OAuthToken(
    access_token = "old-at",
    token_type = "DPoP",
    refresh_token = "refresh-1",
    expires_at = as.numeric(Sys.time()) + 10,
    userinfo = list()
  )
  seen <- new.env(parent = emptyenv())
  seen$token_type <- NA_character_

  testthat::local_mocked_bindings(
    req_with_dpop_retry = function(
      req,
      client,
      access_token = NULL,
      idempotent = TRUE
    ) {
      httr2::response(
        url = as.character(req[["url"]]),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"new-at","refresh_token":"refresh-2","expires_in":60}'
        )
      )
    },
    get_userinfo = function(
      oauth_client,
      token,
      token_type = NULL,
      shiny_session = NULL
    ) {
      seen$token_type <- token@token_type
      list(sub = "user-1")
    },
    .package = "shinyOAuth"
  )

  refreshed <- refresh_token(cli, token, async = FALSE, introspect = FALSE)

  expect_identical(seen$token_type, "DPoP")
  expect_identical(refreshed@token_type, "DPoP")
  expect_identical(refreshed@userinfo$sub, "user-1")
})

test_that("when allowed_token_types is non-empty, missing token_type errors", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  # Ensure default has a non-empty allow-list
  prov@allowed_token_types <- c("Bearer")

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        # Missing token_type should error
        list(access_token = "t", expires_in = 5)
      },
      .package = "shinyOAuth",
      shinyOAuth:::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = tok
      )
    ),
    regexp = "missing token_type|token_type",
    class = "shinyOAuth_token_error"
  )
})

test_that("handle_callback validates token_type before fetching userinfo", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  prov@allowed_token_types <- c("Bearer")

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(access_token = "t", token_type = "DPoP", expires_in = 5)
      },
      get_userinfo = function(oauth_client, token) {
        stop("userinfo should not be fetched")
      },
      .package = "shinyOAuth",
      shinyOAuth:::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = tok
      )
    ),
    regexp = "token_type|Unsupported token_type",
    class = "shinyOAuth_token_error"
  )
})

test_that("handle_callback rejects non-scalar token_type values", {
  prov <- oauth_provider(
    name = "fake",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  prov@allowed_token_types <- c("Bearer", "DPoP")

  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  tok <- valid_browser_token()
  url <- shinyOAuth:::prepare_call(cli, browser_token = tok)
  enc <- parse_query_param(url, "state")

  expect_error(
    testthat::with_mocked_bindings(
      swap_code_for_token_set = function(client, code, code_verifier) {
        list(
          access_token = "t",
          token_type = c("Bearer", "DPoP"),
          expires_in = 60
        )
      },
      .package = "shinyOAuth",
      shinyOAuth:::handle_callback(
        cli,
        code = "ok",
        payload = enc,
        browser_token = tok
      )
    ),
    regexp = "Invalid token_type",
    class = "shinyOAuth_token_error"
  )
})
