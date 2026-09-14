test_that("OAuthClient preserves every pre-SMART positional argument", {
  legacy <- c(
    "provider", "client_id", "client_secret", "endpoint_auth", "redirect_uri",
    "scopes", "response_mode", "resource", "claims", "enforce_callback_issuer",
    "authorization_server_mode", "authorization_server_redirect_uris",
    "scope_validation", "claims_validation", "required_acr_values",
    "userinfo_jwt_required_time_claims", "introspect", "introspect_elements",
    "state_store", "state_payload_max_age", "state_entropy", "state_key",
    "client_assertion_private_key", "client_assertion_private_key_kid",
    "client_assertion_alg", "client_assertion_audience", "mtls_client_cert_file",
    "mtls_client_key_file", "mtls_client_key_password", "mtls_client_ca_file",
    "mtls_certificate_bound_access_tokens", "dpop_private_key",
    "dpop_private_key_kid", "dpop_signing_alg", "dpop_require_access_token",
    "dpop_require_observed_cnf", "request_object_mode", "request_object_signing_alg",
    "request_object_audience", "request_object_encryption_alg",
    "request_object_encryption_enc", "request_object_encryption_kid",
    "request_object_ttl", "request_object_nbf_skew", "jarm_signed_response_alg",
    "jarm_encrypted_response_alg", "jarm_encrypted_response_enc",
    "jarm_decryption_private_key", "jarm_decryption_private_key_kid",
    "jarm_max_lifetime", "mtls_require_observed_cnf", "trusted_id_token_audiences",
    "compare_callback_issuer", "client_assertion_typ"
  )
  expect_identical(head(names(formals(OAuthClient)), length(legacy)), legacy)
  named <- oauth_client(make_test_provider(), "example",
    redirect_uri = "https://app.example/callback", scopes = "read",
    response_mode = "query", claims_validation = "strict")
  positional <- do.call(OAuthClient, unname(S7::props(named)[legacy]))
  expect_identical(S7::props(positional), S7::props(named))
  short <- OAuthClient(named@provider, "example", character(), list(),
    "https://app.example/callback", "read", "query")
  expect_identical(short@response_mode, "query")
  expect_identical(short@smart, list())
  expect_identical(short@resource_bases, character())
})
