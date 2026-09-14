smart_client_fixture <- function(launch = "standalone", oidc = FALSE) {
  metadata <- list(
    authorization_endpoint = "https://ehr.example/authorize",
    token_endpoint = "https://ehr.example/token",
    capabilities = as.list(c("launch-standalone", "launch-ehr", "client-public",
      "client-confidential-symmetric", "client-confidential-asymmetric",
      "permission-patient", "permission-user", "permission-v2", "permission-v1",
      "context-standalone-patient", "context-ehr-patient",
      if (oidc) "sso-openid-connect")),
    grant_types_supported = list("authorization_code", "refresh_token"),
    code_challenge_methods_supported = list("S256"),
    scopes_supported = list("patient/*.cruds"),
    token_endpoint_auth_methods_supported = list("none", "client_secret_basic", "private_key_jwt"),
    token_endpoint_auth_signing_alg_values_supported = list("RS384", "ES384")
  )
  if (oidc) {
    metadata$issuer <- "https://ehr.example"
    metadata$jwks_uri <- "https://ehr.example/jwks"
  }
  list(fhir_base = "https://ehr.example/fhir/R4", smart_version = "2.2.0",
    discovery_url = "https://ehr.example/fhir/R4/.well-known/smart-configuration",
    metadata = metadata, endpoint_hosts = "ehr.example", allow_http_loopback = FALSE)
}
smart_identity_fixture <- function(reference = "Practitioner/example") {
  client <- smart_client(smart_client_fixture(oidc = TRUE), "example",
    "https://app.example/callback", scopes = character(), identity = "fhirUser")
  key <- openssl::rsa_keygen(2048)
  jwks <- list(keys = list(jsonlite::fromJSON(write_test_jwk(key$pubkey), simplifyVector = FALSE)))
  claims <- list(iss = "https://ehr.example", aud = "example", sub = "example-user",
    nonce = "expected-nonce", iat = as.numeric(Sys.time()), exp = as.numeric(Sys.time()) + 300,
    fhirUser = reference)
  signed <- jose::jwt_encode_sig(do.call(jose::jwt_claim, claims), key)
  testthat::local_mocked_bindings(fetch_jwks = function(...) jwks, .package = "shinyOAuth")
  verified <- verify_token_set(client,
    list(access_token = "example-access", token_type = "Bearer", expires_in = 300,
      scope = "openid fhirUser", id_token = signed), nonce = "expected-nonce")
  token <- OAuthToken(access_token = verified$access_token, refresh_token = "example-refresh",
    token_type = "Bearer", expires_at = as.numeric(Sys.time()) + 300,
    granted_scopes = verified$granted_scopes, granted_scopes_verified = TRUE,
    id_token = signed, id_token_validated = verified$.id_token_validated)
  list(client = client, token = smart_update_token_context(client, token),
    key = key, jwks = jwks, claims = claims)
}
