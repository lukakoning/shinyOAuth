request_body_text <- function(req) {
  body <- req$body %||% NULL
  if (is.null(body)) {
    return(NA_character_)
  }
  if (identical(body$type, "raw")) {
    return(rawToChar(body$data))
  }
  if (identical(body$type, "form")) {
    data <- body$data %||% list()
    if (!length(data)) {
      return("")
    }

    parts <- unlist(
      lapply(seq_along(data), function(i) {
        nm <- names(data)[[i]]
        paste0(
          nm,
          "=",
          utils::URLencode(as.character(data[[i]])[[1]], reserved = TRUE)
        )
      }),
      use.names = FALSE
    )
    return(paste(parts, collapse = "&"))
  }

  NA_character_
}

count_fixed_matches <- function(text, pattern) {
  matches <- gregexpr(pattern, text, fixed = TRUE)[[1]]
  sum(matches > 0L)
}

make_par_test_client <- function(
  token_auth_style = "body",
  client_id = "abc",
  client_secret = "",
  resource = character(0),
  extra_auth_params = list(),
  extra_token_headers = character(),
  client_assertion_audience = NULL,
  par_url = "https://example.com/par"
) {
  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    par_url = par_url,
    use_nonce = FALSE,
    use_pkce = TRUE,
    token_auth_style = token_auth_style,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    extra_auth_params = extra_auth_params,
    extra_token_headers = extra_token_headers,
    allowed_token_types = character()
  )

  oauth_client(
    provider = prov,
    client_id = client_id,
    client_secret = client_secret,
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    resource = resource,
    client_assertion_audience = client_assertion_audience,
    state_store = cachem::cache_mem(max_age = 60),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )
}

test_that("prepare_call pushes authorization params and redirects with request_uri", {
  cli <- make_par_test_client()
  body_text <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_text <<- request_body_text(req)
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())

  expect_match(
    auth_url,
    "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Atest"
  )
  expect_match(auth_url, "client_id=abc")
  expect_false(grepl("[?&]state=", auth_url))
  expect_false(grepl("[?&]redirect_uri=", auth_url))
  expect_false(grepl("[?&]code_challenge=", auth_url))

  expect_match(body_text, "response_type=code")
  expect_match(body_text, "client_id=abc")
  expect_match(body_text, "redirect_uri=http%3A%2F%2Flocalhost%3A8100")
  expect_match(body_text, "state=")
  expect_match(body_text, "code_challenge=")
  expect_match(body_text, "code_challenge_method=S256")
})

test_that("PAR HTTP failures surface as PAR-specific errors", {
  cli <- make_par_test_client()

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 400,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"error":"invalid_request","error_description":"PAR rejected"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "Pushed authorization request failed|PAR rejected|invalid_request"
  )
  expect_length(cli@state_store$keys(), 0L)
})

test_that("PAR rejects redirect responses", {
  cli <- make_par_test_client()

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 302,
        headers = list(location = "https://evil.example.com/par"),
        body = charToRaw("")
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "Unexpected redirect response during pushed_authorization_request"
  )
  expect_length(cli@state_store$keys(), 0L)
})

test_that("prepare_call preserves repeated resource indicators in PAR body", {
  cli <- make_par_test_client(
    resource = c(
      "https://api.example.com",
      "urn:example:ledger"
    )
  )
  body_text <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_text <<- request_body_text(req)
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())

  expect_match(auth_url, "request_uri=")
  expect_identical(count_fixed_matches(body_text, "resource="), 2L)
  expect_match(body_text, "resource=https%3A%2F%2Fapi\\.example\\.com")
  expect_match(body_text, "resource=urn%3Aexample%3Aledger")
})

test_that("PAR response requires request_uri and expires_in", {
  cli <- make_par_test_client()

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"expires_in":90}')
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "request_uri"
  )
  expect_length(cli@state_store$keys(), 0L)

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "expires_in"
  )
  expect_length(cli@state_store$keys(), 0L)
})

test_that("PAR response requires 201 JSON with integer expires_in", {
  cli <- make_par_test_client()

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "HTTP 201 Created|Status 200"
  )
  expect_length(cli@state_store$keys(), 0L)

  cli <- make_par_test_client()
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "text/plain"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "not JSON|Content-Type"
  )
  expect_length(cli@state_store$keys(), 0L)

  cli <- make_par_test_client()
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":"90"}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "expires_in"
  )
  expect_length(cli@state_store$keys(), 0L)

  cli <- make_par_test_client()
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90.5}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "positive integer"
  )
  expect_length(cli@state_store$keys(), 0L)
})

test_that("provider reserves request_uri and request object parameters", {
  expect_error(
    oauth_provider(
      name = "example",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      use_nonce = FALSE,
      use_pkce = TRUE,
      id_token_required = FALSE,
      id_token_validation = FALSE,
      extra_auth_params = list(request_uri = "urn:example:test")
    ),
    regexp = "request_uri"
  )

  expect_error(
    oauth_provider(
      name = "example",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      use_nonce = FALSE,
      use_pkce = TRUE,
      id_token_required = FALSE,
      id_token_validation = FALSE,
      extra_auth_params = list(request = "signed-request-object")
    ),
    regexp = "request"
  )

  cli <- make_par_test_client()
  expect_error(
    shinyOAuth:::push_authorization_request(
      cli,
      list(request_uri = "urn:attacker:request")
    ),
    regexp = "must not include request_uri"
  )
})

test_that("OIDC discovery rejects inconsistent required PAR metadata", {
  disc_body <- jsonlite::toJSON(
    list(
      issuer = "https://issuer.example.com",
      authorization_endpoint = "https://issuer.example.com/auth",
      token_endpoint = "https://issuer.example.com/token",
      jwks_uri = "https://issuer.example.com/jwks",
      response_types_supported = list("code"),
      subject_types_supported = list("public"),
      id_token_signing_alg_values_supported = list("RS256"),
      token_endpoint_auth_methods_supported = list(
        "client_secret_basic",
        "client_secret_post"
      ),
      require_pushed_authorization_requests = TRUE
    ),
    auto_unbox = TRUE
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(disc_body)
      )
    },
    .package = "shinyOAuth"
  )

  expect_error(
    oauth_provider_oidc_discover("https://issuer.example.com"),
    regexp = "pushed_authorization_request_endpoint"
  )
})

test_that("client_secret_jwt PAR request sends client assertion and omits secret", {
  cli <- make_par_test_client(
    token_auth_style = "client_secret_jwt",
    client_secret = paste(rep("s", 32), collapse = "")
  )
  captured <- NULL

  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())

  expect_match(auth_url, "request_uri=")
  expect_identical(
    captured$client_assertion_type,
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  )
  expect_true(
    is.character(captured$client_assertion) && nzchar(captured$client_assertion)
  )
  expect_false("client_secret" %in% names(captured))
})

test_that("PAR body auth omits client_secret for public clients and keeps extra headers", {
  cli <- make_par_test_client(
    token_auth_style = "body",
    client_secret = "",
    extra_token_headers = c(`X-Test-Par` = "ok")
  )
  body_text <- NULL
  seen_header <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_text <<- request_body_text(req)
      seen_header <<- req$headers$`X-Test-Par` %||% NULL
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())

  expect_match(auth_url, "request_uri=")
  expect_match(body_text, "client_id=abc")
  expect_false(grepl("client_secret=", body_text, fixed = TRUE))
  expect_identical(seen_header, "ok")
})

test_that("PAR header auth uses Basic auth and keeps client_secret out of body", {
  cli <- make_par_test_client(
    token_auth_style = "header",
    client_secret = "secret"
  )
  body_text <- NULL
  auth_header_names <- character()

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_text <<- request_body_text(req)
      auth_header_names <<- names(as.list(req[["headers"]]))
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())

  expect_match(auth_url, "request_uri=")
  expect_true("Authorization" %in% auth_header_names)
  expect_false(grepl("client_secret=", body_text, fixed = TRUE))
})

test_that("PAR JWT client assertions target par_url by default and allow audience override", {
  cli_default <- make_par_test_client(
    token_auth_style = "client_secret_jwt",
    client_secret = paste(rep("s", 32), collapse = "")
  )
  captured_default <- NULL

  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured_default <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  shinyOAuth:::prepare_call(cli_default, valid_browser_token())
  payload_default <- shinyOAuth:::parse_jwt_payload(
    captured_default$client_assertion
  )
  expect_identical(payload_default$aud, cli_default@provider@par_url)

  cli_override <- make_par_test_client(
    token_auth_style = "client_secret_jwt",
    client_secret = paste(rep("s", 32), collapse = ""),
    client_assertion_audience = "https://example.com/custom-par-aud"
  )
  captured_override <- NULL

  testthat::local_mocked_bindings(
    req_body_form = function(req, ...) {
      captured_override <<- list(...)
      req
    },
    .package = "httr2"
  )
  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"request_uri":"urn:ietf:params:oauth:request_uri:test","expires_in":90}'
        )
      )
    },
    .package = "shinyOAuth"
  )

  shinyOAuth:::prepare_call(cli_override, valid_browser_token())
  payload_override <- shinyOAuth:::parse_jwt_payload(
    captured_override$client_assertion
  )
  expect_identical(payload_override$aud, "https://example.com/custom-par-aud")
})

test_that("OIDC discovery wires PAR metadata into provider", {
  disc_body <- jsonlite::toJSON(
    list(
      issuer = "https://issuer.example.com",
      authorization_endpoint = "https://issuer.example.com/auth",
      token_endpoint = "https://issuer.example.com/token",
      jwks_uri = "https://issuer.example.com/jwks",
      response_types_supported = list("code"),
      subject_types_supported = list("public"),
      id_token_signing_alg_values_supported = list("RS256"),
      token_endpoint_auth_methods_supported = list(
        "client_secret_basic",
        "client_secret_post"
      ),
      pushed_authorization_request_endpoint = "https://issuer.example.com/par"
    ),
    auto_unbox = TRUE
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = as.character(req$url),
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(disc_body)
      )
    },
    .package = "shinyOAuth"
  )

  prov <- oauth_provider_oidc_discover("https://issuer.example.com")

  expect_identical(prov@par_url, "https://issuer.example.com/par")
})
