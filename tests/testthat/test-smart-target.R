test_that("SMART target opts into an exact FHIR audience and S256", {
  site <- smart_target_fixture()
  target <- smart_target(site, "example", "https://app.example/callback",
    scopes = c("launch/patient", "patient/Patient.rs"),
    required_scopes = "patient/Patient.r")
  expect_s3_class(target, "OAuthTarget")
  expect_identical(target$smart$launch, "standalone")
  expect_identical(target$smart$fhir_base, site$fhir_base)
  expect_identical(target$resource_bases, c(fhir = site$fhir_base))
  expect_identical(target$required_scopes, "patient/Patient.r")
  expect_false(provider_uses_oidc(target$client@provider))
  params <- httr2::url_parse(prepare_call(target$client,
    browser_token = valid_browser_token()))$query
  expect_identical(params$aud, site$fhir_base)
  expect_identical(params$code_challenge_method, "S256")
  expect_true(nzchar(params$code_challenge))
  expect_null(params$launch)
  expect_identical(params$scope, "launch/patient patient/Patient.rs")
  expect_error(target$smart <- list(), "read-only")
  expect_identical(connection_current_target_fingerprint(target), target$fingerprint)
})

test_that("SMART capability and registration selection fails before network", {
  site <- smart_target_fixture()
  create <- function(site, ...) smart_target(site, "example", "https://app.example/callback",
    scopes = "user/Patient.rs", ...)
  local_mocked_bindings(req_with_retry = function(...) stop("Unexpected network call"),
    .package = "shinyOAuth")
  expect_no_error(create(site))
  for (capability in c("permission-v2", "client-public", "launch-standalone", "permission-user")) {
    bad <- site
    bad$metadata$capabilities <- as.list(setdiff(unlist(bad$metadata$capabilities), capability))
    expect_error(create(bad), "capability required")
  }
  bad <- site
  bad$metadata$token_endpoint_auth_methods_supported <- list("private_key_jwt")
  expect_no_error(create(bad))
  expect_error(create(bad, token_auth_style = "header", client_secret = "synthetic-secret"), "method is not advertised")
  bad <- site
  bad$metadata$token_endpoint <- "https://other.example/token"
  expect_error(create(bad), "endpoint_hosts")
  expect_error(create(site, client_secret = "unexpected"), "symmetric")
  expect_error(create(site, token_auth_style = "header"), "secret")
  expect_no_error(create(site, token_auth_style = "header", client_secret = "example-secret"))
  expect_error(create(site, identity = "fhirUser"), "sso-openid-connect")
  expect_error(create(site, response_mode = "query.jwt"), "currently supports")
  expect_error(create(site, request_object_mode = "request"), "unused argument")
})

test_that("SMART public registration needs capability but no none authentication advertisement", {
  site <- smart_target_fixture()
  site$metadata$capabilities <- as.list(setdiff(unlist(site$metadata$capabilities), "client-confidential-asymmetric"))
  for (methods in list(NULL, list("client_secret_basic"), list("private_key_jwt"))) {
    site$metadata$token_endpoint_auth_methods_supported <- methods
    target <- smart_target(site, "public-client", "https://app.example/callback",
      scopes = c("launch/patient", "patient/Patient.r"))
    expect_identical(target$client@provider@token_auth_style, "public")
    expect_length(target$client@client_secret, 0L)
  }
  site$metadata$capabilities <- as.list(setdiff(unlist(site$metadata$capabilities), "client-public"))
  expect_error(smart_target(site, "public-client", "https://app.example/callback",
    scopes = c("launch/patient", "patient/Patient.r")), "capability required")
})

test_that("SMART scope and identity policies cannot be inferred or weakened", {
  site <- smart_target_fixture(oidc = TRUE)
  none <- smart_target(site, "example", "https://app.example/callback",
    scopes = "user/Patient.rs")
  expect_false(provider_uses_oidc(none$client@provider))
  expect_false(none$client@provider@id_token_validation)
  expect_false("openid" %in% effective_client_scopes(none$client))
  identity <- smart_target(site, "example", "https://app.example/callback",
    scopes = "user/Patient.rs", identity = "fhirUser")
  expect_true(identity$client@provider@id_token_validation)
  expect_true(identity$client@provider@use_nonce)
  expect_true(all(c("openid", "fhirUser") %in% identity$required_scopes))
  expect_error(smart_target(site, "example", "https://app.example/callback",
    scopes = c("openid", "user/Patient.rs")), "Identity scopes require")
  expect_error(smart_target(site, "example", "https://app.example/callback",
    scopes = "patient/Patient.r"), "launch/patient")
  expect_error(smart_target(site, "example", "https://app.example/callback",
    scopes = "system/Patient.r"), "backend system")
  expect_error(smart_target(site, "example", "https://app.example/callback",
    scopes = "user/Patient.read"), "unsupported scope")
  expect_no_error(smart_target(site, "example", "https://app.example/callback",
    scopes = "user/Patient.read", allow_v1 = TRUE))
  changed <- none$client
  expect_error(changed@provider@use_pkce <- FALSE, "PKCE|SMART request composition")
  changed <- identity$client
  expect_error(changed@provider@id_token_validation <- FALSE, "identity validation|id_token_validation")
  expect_error(oauth_target(none$client, c(api = "https://other.example"),
    none$required_scopes), "configured FHIR base")
})

test_that("SMART asymmetric registration chooses explicit SHA-384 signing", {
  site <- smart_target_fixture()
  key <- openssl::rsa_keygen(2048)
  create <- function(...) smart_target(site, "example", "https://app.example/callback",
    scopes = "user/Patient.rs", token_auth_style = "private_key_jwt", ...)
  expect_error(create(), "requires a key")
  target <- create(client_assertion_private_key = key,
    client_assertion_private_key_kid = "registered-key")
  expect_identical(target$client@client_assertion_alg, "RS384")
  expect_error(create(client_assertion_private_key = key,
    client_assertion_private_key_kid = "registered-key", client_assertion_alg = "RS256"),
    "advertised RS384 or ES384")
  expect_error(create(client_assertion_private_key = key,
    client_assertion_private_key_kid = "registered-key", client_assertion_alg = "ES384"),
    "key|EC")
})

test_that("SMART lifetime and identity checks cannot use generic fallbacks", {
  target <- smart_target(smart_target_fixture(), "example", "https://app.example/callback",
    scopes = "user/Patient.r")
  base <- list(access_token = "example-access", token_type = "Bearer", scope = "user/Patient.r")
  local_options(shinyOAuth.default_expires_in = 3600)
  for (expiry in list(NULL, NA_real_, Inf, 0, -1, "60")) {
    expect_error(verify_token_set(target$client, c(base, list(expires_in = expiry)),
      nonce = NULL), "explicit positive expires_in")
  }
  expect_no_error(verify_token_set(target$client, c(base, list(expires_in = 60)), nonce = NULL))
  identity <- smart_target(smart_target_fixture(oidc = TRUE), "example",
    "https://app.example/callback", scopes = "user/Patient.r", identity = "fhirUser")
  expect_error(smart_verify_identity(identity$client, list(id_token = "opaque",
    .id_token_validated = FALSE), FALSE), "validated ID token")
  expect_no_error(smart_verify_identity(identity$client, list(), TRUE))
})

test_that("SMART fhirUser is taken only from a cryptographically validated ID token", {
  target <- smart_target(smart_target_fixture(oidc = TRUE), "example",
    "https://app.example/callback", scopes = "user/Patient.r", identity = "fhirUser")
  key <- openssl::rsa_keygen(2048)
  jwks <- list(keys = list(jsonlite::fromJSON(write_test_jwk(key$pubkey), simplifyVector = FALSE)))
  local_mocked_bindings(fetch_jwks = function(...) jwks, .package = "shinyOAuth")
  claims <- list(iss = "https://ehr.example", aud = "example", sub = "example-user",
    nonce = "expected-nonce", iat = as.numeric(Sys.time()), exp = as.numeric(Sys.time()) + 60,
    fhirUser = "https://ehr.example/fhir/R4/Practitioner/example")
  verify <- function(claims, signing_key = key) verify_token_set(target$client,
    list(access_token = "example-access", token_type = "Bearer", expires_in = 60,
      scope = "openid fhirUser user/Patient.r",
      id_token = jose::jwt_encode_sig(do.call(jose::jwt_claim, claims), signing_key)),
    nonce = "expected-nonce")
  expect_true(verify(claims)$.id_token_validated)
  for (kind in c("Patient", "Practitioner", "PractitionerRole", "RelatedPerson", "Person")) {
    relative <- claims
    relative$fhirUser <- paste0(kind, "/example")
    expect_true(verify(relative)$.id_token_validated)
  }
  for (value in list(NULL, 42, "javascript:example", "https://ehr.example/fhir/../secret",
      "Practitioner/..", "Practitioner/example?query=x", "../Practitioner/example", "Observation/example")) {
    bad <- claims
    bad$fhirUser <- value
    expect_error(verify(bad), "fhirUser")
  }
  bad <- claims
  bad$nonce <- "other"
  expect_error(verify(bad), class = "shinyOAuth_id_token_error")
  expect_error(verify(claims, openssl::rsa_keygen(2048)), class = "shinyOAuth_id_token_error")
})
