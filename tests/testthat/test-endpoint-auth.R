test_that("async parent and PAR spans describe resolved endpoint authentication", {
  client <- make_test_client()
  client@provider@introspection_url <- "https://example.com/introspect"
  client@provider@revocation_url <- "https://example.com/revoke"
  client@provider@par_url <- "https://example.com/par"
  client@provider@extra_token_headers <- c("X-Token" = "token-only")
  client@endpoint_auth <- list(
    introspection = list(token_auth_style = "body"),
    revocation = list(token_auth_style = "body"),
    par = list(token_auth_style = "body")
  )
  captured <- NULL
  local_mocked_bindings(
    dispatch_token_async = function(parent_extra, ...) parent_extra,
    with_otel_span = function(name, code, attributes = list(), ...) {
      if (name == "shinyOAuth.login.par") {
        captured <<- attributes
      }
      force(code)
    },
    req_with_retry = function(req, ...) {
      expect_null(req$headers[["X-Token"]])
      httr2::response(
        status = 201,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"request_uri":"urn:example:par","expires_in":60}')
      )
    },
    .package = "shinyOAuth"
  )
  token <- OAuthToken(access_token = "access", refresh_token = "refresh")
  for (attrs in list(
    introspect_token(client, token, async = TRUE),
    revoke_token(client, token, async = TRUE)
  )) {
    expect_identical(attrs$oauth.client_auth_style, "body")
    expect_identical(attrs$oauth.extra_token_headers_count, 0L)
  }
  push_authorization_request(client, list(client_id = client@client_id))
  expect_identical(captured$oauth.client_auth_style, "body")
  expect_identical(captured$oauth.extra_token_headers_count, 0L)
})

test_that("endpoint metadata order cannot overwrite explicit assertion policy", {
  client <- make_test_client()
  client@client_secret <- strrep("s", 64)
  client@provider@token_auth_style <- "client_secret_jwt"
  client@client_assertion_alg <- "HS384"
  client@provider@introspection_url <- "https://example.com/introspect"
  client@provider@revocation_url <- "https://example.com/revoke"
  for (endpoint in c("introspection", "revocation")) {
    client@provider@endpoint_auth_metadata <- setNames(
      list(list(
        methods = "client_secret_jwt",
        signing_algs = c("HS256", "HS384")
      )),
      endpoint
    )
    auth <- endpoint_auth_client(client, endpoint)
    jwt <- build_client_assertion(auth, "https://example.com/audience")
    expect_identical(parse_jwt_header(jwt)$alg, "HS384")
    client@provider@endpoint_auth_metadata <- setNames(
      list(list(
        methods = "client_secret_jwt",
        signing_algs = "HS256"
      )),
      endpoint
    )
    expect_error(endpoint_auth_client(client, endpoint), "not supported")
  }
})

test_that("private-key endpoint policy checks the explicitly selected algorithm", {
  client <- make_test_client()
  client@client_assertion_private_key <- openssl::ec_keygen("P-384")
  client@provider@token_auth_style <- "private_key_jwt"
  client@client_assertion_alg <- "ES384"
  client@provider@introspection_url <- "https://example.com/introspect"
  client@provider@endpoint_auth_metadata <- list(
    introspection = list(
      methods = "private_key_jwt",
      signing_algs = c("RS256", "ES384")
    )
  )
  auth <- endpoint_auth_client(client, "introspection")
  expect_identical(
    parse_jwt_header(build_client_assertion(auth, "https://example.com"))$alg,
    "ES384"
  )
  client@provider@endpoint_auth_metadata <- list(
    introspection = list(
      methods = "private_key_jwt",
      signing_algs = "RS256"
    )
  )
  expect_error(endpoint_auth_client(client, "introspection"), "not supported")
})

test_that("discovery preserves independent authentication metadata and omission semantics", {
  issuer <- "https://example.com"
  doc <- list(
    issuer = issuer,
    authorization_endpoint = paste0(issuer, "/auth"),
    token_endpoint = paste0(issuer, "/token"),
    jwks_uri = paste0(issuer, "/jwks"),
    response_types_supported = list("code"),
    subject_types_supported = list("public"),
    id_token_signing_alg_values_supported = list("RS256")
  )
  doc$introspection_endpoint <- paste0(issuer, "/introspect")
  doc$revocation_endpoint <- paste0(issuer, "/revoke")
  doc$token_endpoint_auth_methods_supported <- list("private_key_jwt")
  doc$token_endpoint_auth_signing_alg_values_supported <- list("RS256")
  doc$introspection_endpoint_auth_methods_supported <- list("client_secret_jwt")
  doc$introspection_endpoint_auth_signing_alg_values_supported <- list("HS512")
  local_mocked_bindings(
    req_with_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(doc, auto_unbox = TRUE))
      )
    },
    .package = "shinyOAuth"
  )
  provider <- oauth_provider_oidc_discover(
    issuer,
    token_auth_style = "private_key_jwt"
  )
  expect_identical(
    provider@endpoint_auth_metadata$introspection,
    list(methods = "client_secret_jwt", signing_algs = "HS512")
  )
  expect_identical(
    provider@endpoint_auth_metadata$revocation$methods,
    "client_secret_basic"
  )
  omitted <- discover_endpoint_auth_metadata(list())
  expect_null(omitted$introspection$methods)
  expect_null(omitted$introspection$signing_algs)
  expect_error(
    discover_endpoint_auth_metadata(list(
      introspection_endpoint_auth_methods_supported = list("private_key_jwt")
    )),
    "requires signing algorithm"
  )
})

test_that("JWT token clients use independent Basic credentials and headers at other endpoints", {
  client <- make_test_client()
  client@client_assertion_private_key <- openssl::rsa_keygen()
  client@provider@token_auth_style <- "private_key_jwt"
  client@provider@revocation_url <- "https://revoke.example.com/revoke"
  client@provider@introspection_url <- "https://inspect.example.com/introspect"
  client@provider@extra_token_headers <- c("X-Token-Secret" = "token-only")
  client@provider@endpoint_auth_metadata <- list(
    introspection = list(methods = "client_secret_basic"),
    revocation = list(methods = "client_secret_basic")
  )
  client@endpoint_auth <- list(
    introspection = list(
      client_id = "inspector",
      client_secret = "inspect-secret",
      extra_headers = c("X-Inspect" = "inspect-only")
    ),
    revocation = list(client_secret = "revoke-secret")
  )
  requests <- list()
  spans <- list()
  local_mocked_bindings(
    with_otel_span = function(name, code, attributes = list(), ...) {
      spans[[name]] <<- attributes
      force(code)
    },
    req_with_retry = function(req, ...) {
      requests[[req$url]] <<- req
      httr2::response(
        url = req$url,
        status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw('{"active":true}')
      )
    },
    .package = "shinyOAuth"
  )
  token <- OAuthToken(
    access_token = "access",
    refresh_token = "refresh",
    expires_at = as.numeric(Sys.time()) + 60
  )
  expect_true(introspect_token(client, token)$active)
  expect_true(revoke_token(client, token)$revoked)
  expect_identical(
    spans[["shinyOAuth.token.introspect"]]$oauth.client_auth_style,
    "header"
  )
  expect_identical(
    spans[["shinyOAuth.token.introspect"]]$oauth.extra_token_headers_count,
    1L
  )
  expect_identical(
    spans[["shinyOAuth.token.revoke"]]$oauth.client_auth_style,
    "header"
  )
  expect_identical(
    spans[["shinyOAuth.token.revoke"]]$oauth.extra_token_headers_count,
    0L
  )
  inspect <- requests[[client@provider@introspection_url]]
  revoke <- requests[[client@provider@revocation_url]]
  expect_null(inspect$headers[["X-Token-Secret"]])
  expect_null(revoke$headers[["X-Token-Secret"]])
  expect_identical(inspect$headers[["X-Inspect"]], "inspect-only")
  expect_null(revoke$headers[["X-Inspect"]])
  authorization <- inspect$headers$Authorization
  if (typeof(authorization) == "weakref") {
    authorization <- rlang::wref_value(authorization)
  }
  expect_identical(
    authorization,
    paste0(
      "Basic ",
      openssl::base64_encode(charToRaw("inspector:inspect-secret"))
    )
  )
  expect_identical(client@provider@token_auth_style, "private_key_jwt")
  expect_identical(
    endpoint_auth_client(client, "token")@provider@extra_token_headers,
    c("X-Token-Secret" = "token-only")
  )
})

test_that("endpoint JWT algorithms, audiences and retry assertions are independently resolved", {
  client <- make_test_client()
  client@client_secret <- strrep("t", 32)
  client@provider@token_auth_style <- "client_secret_jwt"
  client@provider@token_endpoint_auth_signing_alg_values_supported <- "HS256"
  client@provider@introspection_url <- "https://example.com/introspect"
  client@provider@endpoint_auth_metadata <- list(
    introspection = list(
      methods = "client_secret_jwt",
      signing_algs = "HS512"
    )
  )
  client@endpoint_auth <- list(
    introspection = list(
      client_secret = strrep("i", 64),
      client_assertion_audience = "https://example.com/inspect-audience"
    )
  )
  auth <- endpoint_auth_client(client, "introspection")
  prepared <- apply_direct_client_auth(
    httr2::request(auth@provider@introspection_url),
    list(token = "access"),
    auth,
    "introspect_token"
  )
  jwt <- prepared$params$client_assertion
  expect_identical(parse_jwt_header(jwt)$alg, "HS512")
  expect_identical(
    parse_jwt_payload(jwt)$aud,
    "https://example.com/inspect-audience"
  )
  expect_silent(jose::jwt_decode_hmac(jwt, secret = strrep("i", 64)))
  req <- req_refresh_jwt_client_assertion_on_retry(
    prepared$req,
    prepared$params,
    auth,
    "introspect_token",
    body_mode = "form"
  )
  retried <- req$shinyOAuth_prepare_attempt(req, 2L)
  expect_false(identical(retried$body$data$client_assertion, jwt))
  expect_identical(
    parse_jwt_payload(retried$body$data$client_assertion)$aud,
    "https://example.com/inspect-audience"
  )
  expect_identical(
    client@provider@token_endpoint_auth_signing_alg_values_supported,
    "HS256"
  )
  expect_error(
    {
      client@endpoint_auth$introspection$client_assertion_alg <- "HS256"
      endpoint_auth_client(client, "introspection")
    },
    "not supported"
  )
})

test_that("endpoint authentication changes are bound to pending login policy", {
  client <- make_test_client()
  initial <- state_client_policy_fingerprint(client)
  client@endpoint_auth <- list(
    par = list(
      client_assertion_private_key = openssl::rsa_keygen(),
      extra_headers = c("X-App" = "registered-app")
    )
  )
  configured <- state_client_policy_fingerprint(client)
  expect_false(identical(initial, configured))
  expect_identical(configured, state_client_policy_fingerprint(client))
  expect_error(
    {
      client@endpoint_auth <- list(par = list(client_id = "different"))
    },
    "cannot change"
  )
  expect_error(
    {
      client@endpoint_auth <- list(
        revocation = list(extra_headers = c(Authorization = "credential"))
      )
    },
    "configure credentials separately"
  )
  expect_error(
    {
      client@endpoint_auth <- list(
        introspection = list(
          extra_headers = c("X-Injected" = "value\r\nOther: secret")
        )
      )
    },
    "safe headers"
  )
})
