# Arguments were read from the published CRAN 0.5.0 source, not a development
# signature. Renaming a formal is compatible only when its position keeps
# the same meaning and the released spelling remains accepted.
test_that("every CRAN positional argument retains its meaning", {
  baseline <- jsonlite::read_json(test_path(
    "fixtures",
    "cran-0.5.0-arguments.json"
  ))
  aliases <- c(
    client_private_key = "client_assertion_private_key",
    client_private_key_kid = "client_assertion_private_key_kid",
    userinfo_jwt_required_temporal_claims = "userinfo_jwt_required_time_claims",
    mtls_request_certificate_bound_access_tokens = "mtls_certificate_bound_access_tokens",
    tls_client_cert_file = "mtls_client_cert_file",
    tls_client_key_file = "mtls_client_key_file",
    tls_client_key_password = "mtls_client_key_password",
    tls_client_ca_file = "mtls_client_ca_file",
    authorization_request_mode = "request_object_mode",
    authorization_request_signing_alg = "request_object_signing_alg",
    authorization_request_audience = "request_object_audience",
    authorization_request_encryption_alg = "request_object_encryption_alg",
    authorization_request_encryption_enc = "request_object_encryption_enc",
    authorization_request_encryption_kid = "request_object_encryption_kid",
    authorization_request_ttl = "request_object_ttl",
    authorization_request_nbf_skew = "request_object_nbf_skew",
    introspect_elements = "introspection_checks",
    require_pushed_authorization_requests = "par_required",
    require_signed_request_object = "signed_request_object_required",
    require_request_uri_registration = "request_uri_registration_required",
    tls_client_certificate_bound_access_tokens = "mtls_client_certificate_bound_access_tokens",
    allowed_algs = "id_token_allowed_algs",
    oauth_client = "client",
    oauth_token = "token",
    payload = "state",
    which = "token_kind",
    refresh_check_interval = "refresh_check_interval_ms"
  )
  ns <- asNamespace("shinyOAuth")
  for (name in names(baseline[["arguments"]])) {
    released <- unlist(baseline[["arguments"]][[name]], use.names = FALSE)
    expected <- released
    renamed <- released %in% names(aliases)
    expected[renamed] <- unname(aliases[released[renamed]])
    current <- names(formals(get(name, envir = ns)))
    expect_identical(head(current, length(expected)), expected, info = name)
  }
})

test_that("released helper positions still configure the intended settings", {
  provider <- oauth_provider(
    "example",
    "https://auth.example/authorize",
    "https://auth.example/token",
    "https://auth.example/userinfo"
  )
  expect_identical(provider@userinfo_url, "https://auth.example/userinfo")
  expect_true(is.na(provider@issuer))
  client <- oauth_client(
    provider,
    "registered",
    "secret",
    "https://app.example/callback",
    FALSE,
    "read"
  )
  expect_identical(client@scopes, "read")
  expect_false(client@enforce_callback_issuer)
  oidc <- oauth_provider_oidc(
    "example",
    "https://auth.example",
    "/authorize",
    "/token",
    "/userinfo",
    "/introspect",
    TRUE,
    TRUE,
    FALSE
  )
  expect_false(oidc@jwks_host_issuer_match)
  expect_identical(oidc@token_auth_style, "header")
})

test_that("S7 constructors accept released names and properties bidirectionally", {
  provider <- OAuthProvider(
    name = "example",
    auth_url = "https://auth.example/authorize",
    token_url = "https://auth.example/token",
    par_url = "https://auth.example/par",
    require_pushed_authorization_requests = TRUE,
    allowed_algs = "RS256"
  )
  expect_true(provider@par_required)
  provider@require_pushed_authorization_requests <- FALSE
  expect_false(provider@par_required)
  provider@par_required <- TRUE
  expect_true(provider@require_pushed_authorization_requests)
  expect_identical(provider@id_token_allowed_algs, "RS256")
  provider@id_token_allowed_algs <- "RS384"
  expect_identical(provider@allowed_algs, "RS384")
  provider@allowed_algs <- "RS256"
  expect_identical(provider@id_token_allowed_algs, "RS256")

  client <- OAuthClient(
    provider = provider,
    client_id = "registered",
    client_secret = "secret",
    redirect_uri = "https://app.example/callback",
    authorization_request_ttl = 60
  )
  expect_identical(client@request_object_ttl, 60)
  client@authorization_request_ttl <- 90
  expect_identical(client@request_object_ttl, 90)
  client@request_object_ttl <- 120
  expect_identical(client@authorization_request_ttl, 120)
  expect_error(
    OAuthClient(request_object_ttl = 60, authorization_request_ttl = 90),
    "Cannot supply both"
  )
  expect_error(
    OAuthProvider(id_token_allowed_algs = "RS256", allowed_algs = "RS384"),
    "Cannot supply both"
  )
})

test_that("OAuthClient round-trips every released positional property", {
  provider <- oauth_provider(
    "example",
    "https://auth.example/authorize",
    "https://auth.example/token"
  )
  named <- oauth_client(
    provider,
    "registered",
    "secret",
    redirect_uri = "https://app.example/callback",
    scopes = "read",
    response_mode = "query"
  )
  baseline <- jsonlite::read_json(test_path(
    "fixtures",
    "cran-0.5.0-arguments.json"
  ))
  released <- unlist(
    baseline[["arguments"]][["OAuthClient"]],
    use.names = FALSE
  )
  values <- lapply(released, function(name) S7::prop(named, name))
  positional <- do.call(OAuthClient, values)
  expect_identical(S7::props(positional), S7::props(named))
})

test_that("S7 property lists reconstruct objects with matching aliases", {
  client <- make_test_client(use_pkce = TRUE, use_nonce = FALSE)
  rebuilt <- do.call(OAuthClient, S7::props(client))
  expect_identical(S7::props(rebuilt), S7::props(client))
  provider <- do.call(OAuthProvider, S7::props(client@provider))
  expect_identical(S7::props(provider), S7::props(client@provider))
})
