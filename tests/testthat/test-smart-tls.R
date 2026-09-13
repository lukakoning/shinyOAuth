test_that("SMART transport minima are request local and preserve stronger policy", {
  local_options(shinyOAuth.tls_min_version = NULL)
  smart <- smart_client(smart_client_fixture(), "app", "https://app.example/callback", "user/Patient.r")
  ordinary <- make_test_client()
  req <- httr2::request("https://ehr.example/token")
  expect_null(add_req_defaults(req, client = ordinary)$options$sslversion)
  secured <- add_req_defaults(req, client = smart)
  expect_identical(secured$options$sslversion, 6L)
  expect_identical(req_apply_tls_policy(secured)$options$sslversion, 6L)
  expect_null(getOption("shinyOAuth.tls_min_version"))
  local_options(shinyOAuth.tls_min_version = "1.3")
  expect_identical(add_req_defaults(req, client = smart)$options$sslversion, 7L)
})

test_that("SMART resource, discovery and signing-key requests select TLS 1.2", {
  local_options(shinyOAuth.tls_min_version = NULL)
  smart <- smart_client(smart_client_fixture(oidc = TRUE), "app", "https://app.example/callback", "user/Patient.r")
  token <- OAuthToken(access_token = "synthetic-access", token_type = "Bearer")
  expect_identical(resource_req(token, "https://ehr.example/fhir/R4/Patient/123",
    oauth_client = smart)$options$sslversion, 6L)
  seen <- list()
  metadata <- smart_client_fixture(oidc = TRUE)$metadata
  key <- openssl::rsa_keygen(2048)
  jwks <- list(keys = list(jsonlite::fromJSON(write_test_jwk(key$pubkey), simplifyVector = FALSE)))
  local_mocked_bindings(req_with_retry = function(req, ...) {
    seen[[length(seen) + 1L]] <<- req
    body <- if (endsWith(req$url, "smart-configuration")) metadata else jwks
    httr2::response(url = req$url, status = 200L, headers = list("content-type" = "application/json"),
      body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE)))
  })
  expect_no_error(smart_discover("https://ehr.example/fhir/R4"))
  identity_client <- smart_client(smart_client_fixture(oidc = TRUE), "app",
    "https://app.example/callback", character(), identity = "fhirUser")
  expect_no_error(fetch_client_jwks(identity_client, "https://ehr.example", cachem::cache_mem(),
    provider = identity_client@provider))
  expect_length(seen, 2L)
  expect_no_error(force_refresh_client_jwks(identity_client, "https://ehr.example",
    identity_client@provider@jwks_cache, provider = identity_client@provider,
    min_interval = 0))
  expect_length(seen, 3L)
  expect_true(all(vapply(seen, function(req) identical(req$options$sslversion, 6L), logical(1))))
})

test_that("SMART code exchange, refresh and revocation retain their TLS minimum", {
  local_options(shinyOAuth.tls_min_version = NULL)
  client <- smart_client(smart_client_fixture(), "app", "https://app.example/callback", "user/Patient.r")
  client@provider@revocation_url <- "https://ehr.example/revoke"
  seen <- list()
  local_mocked_bindings(req_with_retry = function(req, ...) {
    seen[[length(seen) + 1L]] <<- req
    httr2::response(url = req$url, status = 200L,
      headers = list("content-type" = "application/json"),
      body = charToRaw('{"access_token":"synthetic","token_type":"Bearer","expires_in":300,"scope":"user/Patient.r"}'))
  })
  swap_code_for_token_set(client, "synthetic-code", code_verifier = strrep("x", 64))
  token <- smart_update_token_context(client, OAuthToken(access_token = "synthetic",
    refresh_token = "synthetic-refresh", token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 300, granted_scopes = "user/Patient.r",
    granted_scopes_verified = TRUE))
  refresh_token(client, token)
  revoke_token(client, token)
  expect_gte(length(seen), 3L)
  expect_true(all(vapply(seen, function(req) identical(req$options$sslversion, 6L), logical(1))))
})
