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
