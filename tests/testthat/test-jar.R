query_param_names <- function(url) {
  q <- sub("^[^?]*\\?", "", url)
  if (identical(q, url) || !nzchar(q)) {
    return(character(0))
  }

  parts <- strsplit(q, "&", fixed = TRUE)[[1]]
  kv <- strsplit(parts, "=", fixed = TRUE)
  unique(vapply(kv, function(p) utils::URLdecode(p[1]), ""))
}

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

make_jar_test_provider <- function(
  issuer = "https://issuer.example.com",
  par_url = NA_character_,
  require_pushed_authorization_requests = FALSE,
  token_auth_style = "body",
  use_nonce = FALSE,
  extra_auth_params = list(),
  id_token_validation = FALSE,
  request_object_signing_alg_values_supported = character(0),
  request_object_encryption_alg_values_supported = character(0),
  request_object_encryption_enc_values_supported = character(0),
  request_object_encryption_jwk = NULL,
  request_uri_parameter_supported = NA,
  require_request_uri_registration = NA,
  require_signed_request_object = FALSE
) {
  do.call(
    shinyOAuth::oauth_provider,
    list(
      name = "example",
      auth_url = "https://example.com/auth",
      token_url = "https://example.com/token",
      issuer = issuer,
      par_url = par_url,
      require_pushed_authorization_requests = require_pushed_authorization_requests,
      request_object_signing_alg_values_supported = request_object_signing_alg_values_supported,
      request_object_encryption_alg_values_supported = request_object_encryption_alg_values_supported,
      request_object_encryption_enc_values_supported = request_object_encryption_enc_values_supported,
      request_object_encryption_jwk = request_object_encryption_jwk,
      request_uri_parameter_supported = request_uri_parameter_supported,
      require_request_uri_registration = require_request_uri_registration,
      require_signed_request_object = require_signed_request_object,
      use_nonce = use_nonce,
      use_pkce = TRUE,
      token_auth_style = token_auth_style,
      id_token_required = FALSE,
      id_token_validation = id_token_validation,
      extra_auth_params = extra_auth_params,
      allowed_token_types = character()
    )
  )
}

make_jar_test_client <- function(
  provider = make_jar_test_provider(),
  client_secret = paste(rep("s", 32), collapse = ""),
  client_private_key = NULL,
  client_private_key_kid = NULL,
  dpop_private_key = NULL,
  dpop_private_key_kid = NULL,
  dpop_signing_alg = NULL,
  authorization_request_mode = "request",
  authorization_request_signing_alg = NULL,
  authorization_request_audience = NULL,
  authorization_request_encryption_alg = NULL,
  authorization_request_encryption_enc = NULL,
  authorization_request_encryption_kid = NULL,
  authorization_request_ttl = 45,
  authorization_request_nbf_skew = NULL,
  scopes = c("openid", "profile"),
  resource = character(0),
  claims = NULL,
  claims_validation = "none",
  required_acr_values = character(0)
) {
  do.call(
    shinyOAuth::oauth_client,
    list(
      provider = provider,
      client_id = "abc",
      client_secret = client_secret,
      redirect_uri = "http://localhost:8100",
      scopes = scopes,
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      client_private_key = client_private_key,
      client_private_key_kid = client_private_key_kid,
      dpop_private_key = dpop_private_key,
      dpop_private_key_kid = dpop_private_key_kid,
      dpop_signing_alg = dpop_signing_alg,
      authorization_request_mode = authorization_request_mode,
      authorization_request_signing_alg = authorization_request_signing_alg,
      authorization_request_audience = authorization_request_audience,
      authorization_request_encryption_alg = authorization_request_encryption_alg,
      authorization_request_encryption_enc = authorization_request_encryption_enc,
      authorization_request_encryption_kid = authorization_request_encryption_kid,
      authorization_request_ttl = authorization_request_ttl,
      authorization_request_nbf_skew = authorization_request_nbf_skew,
      resource = resource,
      claims = claims,
      claims_validation = claims_validation,
      required_acr_values = required_acr_values
    )
  )
}

test_that("prepare_call emits a signed request object instead of raw auth params", {
  cli <- make_jar_test_client()

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)

  expect_setequal(query_param_names(auth_url), c("client_id", "request"))
  expect_identical(
    parse_query_param(auth_url, "client_id", decode = TRUE),
    "abc"
  )
  expect_true(is.character(request_jwt) && nzchar(request_jwt))

  hdr <- shinyOAuth:::parse_jwt_header(request_jwt)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(hdr$typ, "oauth-authz-req+jwt")
  expect_identical(hdr$alg, "HS256")
  expect_identical(pl$iss, "abc")
  expect_identical(pl$aud, "https://issuer.example.com")
  expect_false("sub" %in% names(pl))
  expect_identical(pl$response_type, "code")
  expect_identical(pl$client_id, "abc")
  expect_identical(pl$redirect_uri, "http://localhost:8100")
  expect_identical(pl$scope, "openid profile")
  expect_identical(pl$code_challenge_method, "S256")
  expect_true(is.character(pl$state) && nzchar(pl$state))
  expect_true(is.character(pl$code_challenge) && nzchar(pl$code_challenge))
  expect_true(is.numeric(pl$iat) && is.numeric(pl$exp) && pl$exp > pl$iat)
  expect_true(is.character(pl$jti) && nzchar(pl$jti))
})

test_that("request mode includes dpop_jkt inside the signed request object", {
  key <- openssl::rsa_keygen()
  cli <- make_jar_test_client(dpop_private_key = key)

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)
  expected_jkt <- shinyOAuth:::compute_jwk_thumbprint(
    shinyOAuth:::dpop_public_jwk(key)
  )

  expect_false("dpop_jkt" %in% query_param_names(auth_url))
  expect_identical(pl$dpop_jkt, expected_jkt)
})

test_that("request objects default to private-key signing and honor audience overrides", {
  key <- openssl::rsa_keygen()
  cli <- make_jar_test_client(
    client_secret = "",
    client_private_key = key,
    client_private_key_kid = "kid-123",
    authorization_request_audience = "https://example.com/custom-aud"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  hdr <- shinyOAuth:::parse_jwt_header(request_jwt)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(hdr$typ, "oauth-authz-req+jwt")
  expect_identical(hdr$alg, "RS256")
  expect_identical(hdr$kid, "kid-123")
  expect_identical(pl$aud, "https://example.com/custom-aud")
})

test_that("prepare_call encrypts signed request objects when configured", {
  encryption_key <- openssl::rsa_keygen()
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      request_object_encryption_alg_values_supported = "RSA-OAEP",
      request_object_encryption_enc_values_supported = "A256CBC-HS512",
      request_object_encryption_jwk = encryption_key$pubkey
    ),
    authorization_request_encryption_alg = "RSA-OAEP",
    authorization_request_encryption_enc = "A256CBC-HS512",
    authorization_request_encryption_kid = "enc-kid"
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwe <- parse_query_param(auth_url, "request", decode = TRUE)

  expect_setequal(query_param_names(auth_url), c("client_id", "request"))
  expect_length(strsplit(request_jwe, ".", fixed = TRUE)[[1]], 5L)

  outer <- shinyOAuth:::jwe_compact_decrypt(request_jwe, encryption_key)
  inner_hdr <- shinyOAuth:::parse_jwt_header(outer$plaintext)
  inner_pl <- shinyOAuth:::parse_jwt_payload(outer$plaintext)

  expect_identical(outer$header$alg, "RSA-OAEP")
  expect_identical(outer$header$enc, "A256CBC-HS512")
  expect_identical(outer$header$kid, "enc-kid")
  expect_identical(outer$header$typ, "oauth-authz-req+jwt")
  expect_identical(outer$header$cty, "JWT")
  expect_identical(inner_hdr$alg, "HS256")
  expect_identical(inner_hdr$typ, "oauth-authz-req+jwt")
  expect_identical(inner_pl$iss, "abc")
  expect_identical(inner_pl$aud, "https://issuer.example.com")
  expect_identical(inner_pl$client_id, "abc")
})

test_that("request objects omit aud when no provider issuer is configured", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(issuer = NA_character_)
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_null(shinyOAuth:::resolve_authorization_request_audience(cli))
  expect_false("aud" %in% names(pl))
})

test_that("request objects honor ttl and optional nbf skew controls", {
  cli <- make_jar_test_client(
    authorization_request_ttl = 300,
    authorization_request_nbf_skew = 15
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_equal(pl$exp - pl$iat, 300)
  expect_equal(pl$iat - pl$nbf, 15)
})

test_that("oauth_client validates request-object ttl and nbf skew", {
  prov <- make_jar_test_provider()

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = paste(rep("s", 32), collapse = ""),
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      authorization_request_mode = "request",
      authorization_request_ttl = 0
    ),
    regexp = "authorization_request_ttl must be greater than 0"
  )

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = paste(rep("s", 32), collapse = ""),
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      authorization_request_mode = "request",
      authorization_request_nbf_skew = -1
    ),
    regexp = "authorization_request_nbf_skew must be greater than or equal to 0"
  )
})

test_that("request mode requires signing material", {
  prov <- make_jar_test_provider()

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      ),
      authorization_request_mode = "request"
    ),
    regexp = paste(
      "authorization_request_mode = 'request' or 'request_uri' requires",
      "client_private_key or client_secret"
    )
  )
})

test_that("request_uri mode publishes signed request objects", {
  published <- NULL
  cli <- make_jar_test_client(
    authorization_request_mode = "request_uri"
  )

  auth_url <- shinyOAuth:::prepare_call(
    cli,
    valid_browser_token(),
    request_uri_publisher = function(
      request_object,
      request_handle_id,
      expires_at,
      oauth_client
    ) {
      published <<- list(
        request_object = request_object,
        request_handle_id = request_handle_id,
        expires_at = expires_at,
        client_id = oauth_client@client_id
      )
      "https://client.example.com/session/request-object"
    }
  )

  expect_setequal(query_param_names(auth_url), c("client_id", "request_uri"))
  expect_false(grepl("[?&]request=", auth_url))
  expect_identical(
    parse_query_param(auth_url, "request_uri", decode = TRUE),
    "https://client.example.com/session/request-object"
  )
  expect_true(is.list(published))
  expect_true(
    is.character(published$request_handle_id) &&
      length(published$request_handle_id) == 1L &&
      !is.na(published$request_handle_id) &&
      nzchar(published$request_handle_id)
  )
  expect_identical(published$client_id, "abc")

  request_payload <- shinyOAuth:::parse_jwt_payload(published$request_object)
  expect_identical(request_payload$client_id, "abc")
  expect_identical(request_payload$redirect_uri, "http://localhost:8100")
  expect_lt(
    as.numeric(difftime(published$expires_at, Sys.time(), units = "secs")),
    60
  )
})

test_that("request_uri mode requires a publisher", {
  cli <- make_jar_test_client(
    authorization_request_mode = "request_uri"
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = "request_uri_publisher"
  )
})

test_that("request_uri mode validates provider request_uri metadata", {
  expect_error(
    make_jar_test_client(
      provider = make_jar_test_provider(
        request_uri_parameter_supported = FALSE
      ),
      authorization_request_mode = "request_uri"
    ),
    regexp = paste(
      "request_uri parameter transport is not supported;",
      "authorization_request_mode = 'request_uri' cannot be used"
    )
  )

  registered_cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      require_request_uri_registration = TRUE
    ),
    authorization_request_mode = "request_uri"
  )

  expect_true(
    S7::S7_inherits(registered_cli, shinyOAuth::OAuthClient)
  )
})

test_that("request_uri mode bypasses optional PAR and publishes by reference", {
  published <- NULL
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(par_url = "https://example.com/par"),
    authorization_request_mode = "request_uri"
  )

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      stop("PAR should not be called for caller-managed request_uri mode")
    },
    .package = "shinyOAuth"
  )

  auth_url <- shinyOAuth:::prepare_call(
    cli,
    valid_browser_token(),
    request_uri_publisher = function(
      request_object,
      request_handle_id,
      expires_at,
      oauth_client
    ) {
      published <<- list(
        request_object = request_object,
        request_handle_id = request_handle_id,
        expires_at = expires_at,
        client_id = oauth_client@client_id
      )
      "https://client.example.com/published-request-object"
    }
  )

  expect_setequal(query_param_names(auth_url), c("client_id", "request_uri"))
  expect_false(grepl("[?&]request=", auth_url))
  expect_identical(
    parse_query_param(auth_url, "request_uri", decode = TRUE),
    "https://client.example.com/published-request-object"
  )
  expect_true(is.list(published))
  expect_identical(published$client_id, "abc")
})

test_that("request_uri mode rejects providers that require PAR", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      par_url = "https://example.com/par",
      require_pushed_authorization_requests = TRUE
    ),
    authorization_request_mode = "request_uri"
  )

  expect_error(
    shinyOAuth:::prepare_call(
      cli,
      valid_browser_token(),
      request_uri_publisher = function(...) {
        "https://client.example.com/request-object"
      }
    ),
    regexp = paste(
      "authorization_request_mode = 'request_uri' cannot",
      "be used when the provider requires PAR"
    )
  )
})

test_that("request_uri mode warns when request_uri exceeds RFC 9101 guidance", {
  cli <- make_jar_test_client(
    authorization_request_mode = "request_uri"
  )
  long_request_uri <- paste0(
    "https://client.example.com/",
    strrep("request-object/", 40)
  )
  auth_url <- NULL

  expect_warning(
    auth_url <- shinyOAuth:::prepare_call(
      cli,
      valid_browser_token(),
      request_uri_publisher = function(
        request_object,
        request_handle_id,
        expires_at,
        oauth_client
      ) {
        long_request_uri
      }
    ),
    regexp = "512 ASCII characters"
  )

  expect_identical(
    parse_query_param(auth_url, "request_uri", decode = TRUE),
    long_request_uri
  )
})

test_that("request mode pushes signed request objects through PAR when available", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(par_url = "https://example.com/par")
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

  request_param <- sub("^.*(?:^|[?&])request=([^&]+).*$", "\\1", body_text)
  request_param <- utils::URLdecode(request_param)
  pl <- shinyOAuth:::parse_jwt_payload(request_param)

  expect_setequal(query_param_names(auth_url), c("client_id", "request_uri"))
  expect_match(
    auth_url,
    "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Atest"
  )
  expect_false(grepl("[?&]request=", auth_url))
  expect_match(body_text, "client_id=abc")
  expect_match(body_text, "request=")
  expect_false(grepl("response_type=code", body_text, fixed = TRUE))
  expect_identical(pl$client_id, "abc")
  expect_identical(pl$redirect_uri, "http://localhost:8100")
  expect_true(is.character(pl$state) && nzchar(pl$state))
})

test_that("request mode through PAR keeps dpop_jkt inside the request object", {
  key <- openssl::rsa_keygen()
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(par_url = "https://example.com/par"),
    dpop_private_key = key
  )
  body_data <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_data <<- req$body$data %||% list()
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
  pl <- shinyOAuth:::parse_jwt_payload(body_data$request)
  expected_jkt <- shinyOAuth:::compute_jwk_thumbprint(
    shinyOAuth:::dpop_public_jwk(key)
  )

  expect_setequal(query_param_names(auth_url), c("client_id", "request_uri"))
  expect_false("dpop_jkt" %in% names(body_data))
  expect_identical(pl$dpop_jkt, expected_jkt)
})

test_that("request mode through PAR pushes encrypted request objects", {
  encryption_key <- openssl::rsa_keygen()
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      par_url = "https://example.com/par",
      request_object_encryption_alg_values_supported = "RSA-OAEP",
      request_object_encryption_enc_values_supported = "A256CBC-HS512",
      request_object_encryption_jwk = encryption_key$pubkey
    ),
    authorization_request_encryption_alg = "RSA-OAEP",
    authorization_request_encryption_enc = "A256CBC-HS512"
  )
  body_data <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_data <<- req$body$data %||% list()
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
  outer <- shinyOAuth:::jwe_compact_decrypt(body_data$request, encryption_key)
  inner_pl <- shinyOAuth:::parse_jwt_payload(outer$plaintext)

  expect_setequal(query_param_names(auth_url), c("client_id", "request_uri"))
  expect_false(grepl("[?&]request=", auth_url))
  expect_length(strsplit(body_data$request, ".", fixed = TRUE)[[1]], 5L)
  expect_identical(outer$header$alg, "RSA-OAEP")
  expect_identical(outer$header$enc, "A256CBC-HS512")
  expect_identical(outer$header$cty, "JWT")
  expect_identical(inner_pl$client_id, "abc")
  expect_identical(inner_pl$redirect_uri, "http://localhost:8100")
})


# 2. request object encryption validation -------------------------------------

test_that("oauth_client validates request-object encryption configuration", {
  encryption_key <- openssl::rsa_keygen()
  provider_with_key <- make_jar_test_provider(
    request_object_encryption_alg_values_supported = "RSA-OAEP",
    request_object_encryption_enc_values_supported = "A256CBC-HS512",
    request_object_encryption_jwk = encryption_key$pubkey
  )

  expect_error(
    make_jar_test_client(
      provider = provider_with_key,
      authorization_request_encryption_alg = "RSA-OAEP"
    ),
    regexp = paste(
      "authorization_request_encryption_alg and",
      "authorization_request_encryption_enc must both be provided"
    )
  )

  expect_error(
    make_jar_test_client(
      provider = make_jar_test_provider(issuer = NA_character_),
      authorization_request_encryption_alg = "RSA-OAEP",
      authorization_request_encryption_enc = "A256CBC-HS512"
    ),
    regexp = paste(
      "Request Object encryption requires provider issuer or",
      "provider request_object_encryption_jwk"
    )
  )

  expect_error(
    make_jar_test_client(
      provider = make_jar_test_provider(
        request_object_encryption_alg_values_supported = "RSA1_5",
        request_object_encryption_enc_values_supported = "A256CBC-HS512",
        request_object_encryption_jwk = encryption_key$pubkey
      ),
      authorization_request_encryption_alg = "RSA-OAEP",
      authorization_request_encryption_enc = "A256CBC-HS512"
    ),
    regexp = paste(
      "authorization_request_encryption_alg 'RSA-OAEP' is not supported by",
      "provider request_object_encryption_alg_values_supported"
    )
  )
})

test_that("request mode through PAR keeps client_id in the body for header auth", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      par_url = "https://example.com/par",
      token_auth_style = "header"
    )
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
  expect_match(body_text, "client_id=abc")
  expect_match(body_text, "request=")
  expect_false(grepl("client_secret=", body_text, fixed = TRUE))
})

test_that("request mode through PAR keeps extra auth params inside the request object", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      par_url = "https://example.com/par",
      extra_auth_params = list(
        prompt = "login",
        login_hint = "alice",
        custom_multi = c("alpha", "beta")
      )
    )
  )
  body_data <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_data <<- req$body$data %||% list()
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
  pl <- shinyOAuth:::parse_jwt_payload(body_data$request)

  expect_setequal(query_param_names(auth_url), c("client_id", "request_uri"))
  expect_false(grepl("[?&]prompt=", auth_url))
  expect_false(grepl("[?&]login_hint=", auth_url))
  expect_false("prompt" %in% names(body_data))
  expect_false("login_hint" %in% names(body_data))
  expect_false("response_type" %in% names(body_data))
  expect_false("redirect_uri" %in% names(body_data))
  expect_identical(pl$prompt, "login")
  expect_identical(pl$login_hint, "alice")
  expect_identical(unname(as.character(pl$custom_multi)), c("alpha", "beta"))
})

test_that("request mode through PAR supports client_secret_jwt client auth", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      par_url = "https://example.com/par",
      token_auth_style = "client_secret_jwt"
    )
  )
  body_data <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_data <<- req$body$data %||% list()
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
  request_value <- utils::URLdecode(as.character(body_data$request)[[1]])
  assertion_value <- utils::URLdecode(as.character(body_data$client_assertion)[[
    1
  ]])
  assertion_type <- utils::URLdecode(
    as.character(body_data$client_assertion_type)[[1]]
  )
  request_payload <- shinyOAuth:::parse_jwt_payload(request_value)
  assertion_payload <- shinyOAuth:::parse_jwt_payload(assertion_value)

  expect_setequal(query_param_names(auth_url), c("client_id", "request_uri"))
  expect_false(grepl("[?&]request=", auth_url))
  expect_true("request" %in% names(body_data))
  expect_identical(
    assertion_type,
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  )
  expect_true(
    is.character(assertion_value) && nzchar(assertion_value)
  )
  expect_false("client_secret" %in% names(body_data))
  expect_false("response_type" %in% names(body_data))
  expect_false("redirect_uri" %in% names(body_data))
  expect_identical(request_payload$client_id, "abc")
  expect_identical(assertion_payload$aud, cli@provider@par_url)
})

test_that("request mode through PAR supports private_key_jwt client auth", {
  key <- openssl::rsa_keygen()
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      par_url = "https://example.com/par",
      token_auth_style = "private_key_jwt"
    ),
    client_secret = "",
    client_private_key = key,
    client_private_key_kid = "kid-123"
  )
  body_data <- NULL

  testthat::local_mocked_bindings(
    req_with_retry = function(req, ...) {
      body_data <<- req$body$data %||% list()
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
  request_value <- utils::URLdecode(as.character(body_data$request)[[1]])
  assertion_value <- utils::URLdecode(as.character(body_data$client_assertion)[[
    1
  ]])
  assertion_type <- utils::URLdecode(
    as.character(body_data$client_assertion_type)[[1]]
  )
  request_header <- shinyOAuth:::parse_jwt_header(request_value)
  request_payload <- shinyOAuth:::parse_jwt_payload(request_value)
  assertion_header <- shinyOAuth:::parse_jwt_header(assertion_value)
  assertion_payload <- shinyOAuth:::parse_jwt_payload(assertion_value)

  expect_setequal(query_param_names(auth_url), c("client_id", "request_uri"))
  expect_false(grepl("[?&]request=", auth_url))
  expect_true("request" %in% names(body_data))
  expect_identical(
    assertion_type,
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  )
  expect_false("client_secret" %in% names(body_data))
  expect_false("response_type" %in% names(body_data))
  expect_false("redirect_uri" %in% names(body_data))
  expect_identical(request_header$typ, "oauth-authz-req+jwt")
  expect_identical(request_header$kid, "kid-123")
  expect_identical(request_payload$client_id, "abc")
  expect_identical(assertion_header$typ, "JWT")
  expect_identical(assertion_header$kid, "kid-123")
  expect_identical(assertion_payload$iss, "abc")
  expect_identical(assertion_payload$sub, "abc")
  expect_identical(assertion_payload$aud, cli@provider@par_url)
})

test_that("request object preserves repeated resource indicators", {
  cli <- make_jar_test_client(
    resource = c(
      "https://api.example.com",
      "urn:example:ledger"
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(
    unname(as.character(pl$resource)),
    c("https://api.example.com", "urn:example:ledger")
  )
})

test_that("request object preserves JSON-encoded claims requests", {
  cli <- make_jar_test_client(
    claims = list(
      userinfo = list(
        email = NULL,
        given_name = list(essential = TRUE)
      ),
      id_token = list(
        auth_time = list(essential = TRUE)
      )
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_type(pl$claims, "list")
  expect_true("userinfo" %in% names(pl$claims))
  expect_true("id_token" %in% names(pl$claims))
  expect_true("email" %in% names(pl$claims$userinfo))
  expect_true("given_name" %in% names(pl$claims$userinfo))
  expect_identical(pl$claims$userinfo$given_name$essential, TRUE)
  expect_identical(pl$claims$id_token$auth_time$essential, TRUE)
})

test_that("request object preserves acr_values hints", {
  prov <- make_jar_test_provider(
    use_nonce = TRUE,
    id_token_validation = TRUE
  )
  cli <- make_jar_test_client(
    provider = prov,
    required_acr_values = c(
      "urn:mace:incommon:iap:silver",
      "urn:mace:incommon:iap:bronze"
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(
    pl$acr_values,
    paste(
      c(
        "urn:mace:incommon:iap:silver",
        "urn:mace:incommon:iap:bronze"
      ),
      collapse = " "
    )
  )
  expect_true(is.character(pl$nonce) && nzchar(pl$nonce))
})

test_that("request object preserves safe provider extra auth params", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      extra_auth_params = list(
        prompt = "login",
        login_hint = "alice",
        custom_multi = c("alpha", "beta")
      )
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(pl$prompt, "login")
  expect_identical(pl$login_hint, "alice")
  expect_identical(unname(as.character(pl$custom_multi)), c("alpha", "beta"))
})

test_that("request mode preserves non-client-id sub while overriding managed JWT claims", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      extra_auth_params = list(
        iss = "user-supplied-iss",
        sub = "248289761001",
        aud = "user-supplied-aud",
        exp = 1,
        nbf = 2,
        iat = 3,
        jti = "user-supplied-jti"
      )
    )
  )

  auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(pl$sub, "248289761001")
  expect_null(pl$nbf)
  expect_identical(pl$iss, cli@client_id)
  expect_identical(
    pl$aud,
    shinyOAuth:::resolve_authorization_request_audience(cli)
  )
  expect_true(is.numeric(pl$iat) && pl$iat != 3)
  expect_true(is.numeric(pl$exp) && pl$exp != 1)
  expect_true(
    is.character(pl$jti) && nzchar(pl$jti) && pl$jti != "user-supplied-jti"
  )
})

test_that("request mode only emits nbf from authorization_request_nbf_skew", {
  fixed_now <- as.POSIXct("2026-05-13 12:00:00", tz = "UTC")
  cli <- make_jar_test_client(
    authorization_request_nbf_skew = 30,
    provider = make_jar_test_provider(
      extra_auth_params = list(nbf = 9999999999)
    )
  )

  auth_url <- testthat::with_mocked_bindings(
    Sys.time = function() fixed_now,
    .package = "base",
    shinyOAuth:::prepare_call(cli, valid_browser_token())
  )
  request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
  pl <- shinyOAuth:::parse_jwt_payload(request_jwt)

  expect_identical(pl$nbf, 1778673570L)
  expect_identical(pl$iat, 1778673600L)
})

test_that("request mode rejects client_id as request object sub", {
  cli <- make_jar_test_client(
    provider = make_jar_test_provider(
      extra_auth_params = list(sub = "abc")
    )
  )

  expect_error(
    shinyOAuth:::prepare_call(cli, valid_browser_token()),
    regexp = paste(
      "Authorization request object sub must not equal client_id;",
      "omit sub or use a distinct subject value"
    )
  )
})

test_that("HMAC request objects use the expected signature bytes", {
  hmac_signers <- list(
    HS256 = openssl::sha256,
    HS384 = openssl::sha384,
    HS512 = openssl::sha512
  )

  for (alg in names(hmac_signers)) {
    cli <- make_jar_test_client(
      client_secret = strrep("s", 64L),
      authorization_request_signing_alg = alg
    )

    auth_url <- shinyOAuth:::prepare_call(cli, valid_browser_token())
    request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
    parts <- strsplit(request_jwt, ".", fixed = TRUE)[[1]]
    signing_input <- paste(parts[1], parts[2], sep = ".")
    expected_signature <- shinyOAuth:::base64url_encode(
      hmac_signers[[alg]](
        charToRaw(signing_input),
        key = charToRaw(enc2utf8(cli@client_secret))
      )
    )

    expect_identical(length(parts), 3L, info = alg)
    expect_identical(
      shinyOAuth:::parse_jwt_header(request_jwt)$alg,
      alg,
      info = alg
    )
    expect_identical(parts[3], expected_signature, info = alg)
  }
})

test_that("HMAC request objects enforce RFC 7518 HMAC secret lengths", {
  cases <- c(HS384 = 48L, HS512 = 64L)

  for (alg in names(cases)) {
    expect_error(
      make_jar_test_client(
        client_secret = strrep("s", cases[[alg]] - 1L),
        authorization_request_signing_alg = alg
      ),
      regexp = paste0(
        "authorization_request_signing_alg '",
        alg,
        "'.*>= ",
        cases[[alg]],
        " bytes"
      ),
      info = alg
    )
  }

  expect_error(
    shinyOAuth:::encode_hmac_jwt_with_header(
      claims = list(iss = "abc"),
      secret = strrep("s", 63L),
      header = list(alg = "HS512", typ = "oauth-authz-req+jwt"),
      size = 512L,
      alg = "HS512"
    ),
    regexp = "HS512 requires client_secret >= 64 bytes"
  )
})

test_that("request mode rejects incompatible explicit signing alg combinations", {
  expect_error(
    make_jar_test_client(authorization_request_signing_alg = "RS256"),
    regexp = "asymmetric authorization_request_signing_alg requires client_private_key"
  )

  expect_error(
    make_jar_test_client(
      client_secret = "",
      authorization_request_signing_alg = "HS256"
    ),
    regexp = "HS[*] authorization_request_signing_alg requires client_secret"
  )

  expect_error(
    make_jar_test_client(authorization_request_signing_alg = "none"),
    regexp = "authorization_request_signing_alg = 'none' is not supported"
  )

  expect_error(
    make_jar_test_client(
      client_private_key = openssl::rsa_keygen(),
      authorization_request_signing_alg = "EdDSA"
    ),
    regexp = paste0(
      "authorization_request_signing_alg 'EdDSA' is incompatible with signed authorization requests"
    )
  )

  expect_error(
    make_jar_test_client(
      client_private_key = openssl::ec_keygen(curve = "P-256"),
      authorization_request_signing_alg = "ES512"
    ),
    regexp = paste(
      "authorization_request_signing_alg 'ES512' is incompatible",
      "with the provided private key"
    )
  )

  key_ed <- try(openssl::ed25519_keygen(), silent = TRUE)
  if (inherits(key_ed, "try-error")) {
    testthat::skip("Ed25519 key generation not supported on this platform")
  }

  expect_error(
    make_jar_test_client(
      client_secret = "",
      client_private_key = key_ed
    ),
    regexp = paste(
      "outbound signed authorization requests currently support RSA and ECDSA",
      "private keys only"
    )
  )
})

test_that("canonicalize_jws_alg preserves EdDSA casing", {
  expect_identical(shinyOAuth:::canonicalize_jws_alg("eddsa"), "EdDSA")
  expect_identical(shinyOAuth:::canonicalize_jws_alg("EDDSA"), "EdDSA")
})

test_that("request mode rejects provider-disallowed request object algs", {
  expect_error(
    make_jar_test_client(
      provider = make_jar_test_provider(
        request_object_signing_alg_values_supported = c("PS256")
      )
    ),
    regexp = paste(
      "authorization_request_signing_alg 'HS256' is not supported by",
      "provider request_object_signing_alg_values_supported"
    )
  )

  key <- openssl::rsa_keygen()
  expect_error(
    make_jar_test_client(
      provider = make_jar_test_provider(
        request_object_signing_alg_values_supported = c("PS256")
      ),
      client_secret = "",
      client_private_key = key
    ),
    regexp = paste(
      "authorization_request_signing_alg 'RS256' is not supported by",
      "provider request_object_signing_alg_values_supported"
    )
  )
})

test_that("providers requiring signed request objects reject parameters mode", {
  prov <- make_jar_test_provider(require_signed_request_object = TRUE)

  expect_error(
    oauth_client(
      provider = prov,
      client_id = "abc",
      client_secret = paste(rep("s", 32), collapse = ""),
      redirect_uri = "http://localhost:8100",
      scopes = c("openid"),
      state_store = cachem::cache_mem(max_age = 60),
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      )
    ),
    regexp = paste(
      "provider requires signed request objects;",
      "set authorization_request_mode = 'request' or 'request_uri'"
    )
  )
})
