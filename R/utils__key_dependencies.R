# Pure key-source decisions shared by runtime selection and assessment. These
# helpers inspect policy only: no key normalization, signing, cache or network IO.
resolve_jwks_key_source <- function(provider, needed = TRUE) {
  if (!needed) {
    "none"
  } else if (is_valid_string(provider@jwks_uri)) {
    "configured_jwks"
  } else {
    "discovered_jwks"
  }
}

resolve_request_object_encryption_key_source <- function(provider) {
  if (!is.null(provider@request_object_encryption_jwk)) {
    "explicit_key"
  } else {
    resolve_jwks_key_source(provider)
  }
}

resolve_oauth_key_dependencies <- function(
  client,
  provider,
  operations,
  jarm,
  validates_id
) {
  encryption <- !is.null(client) &&
    client@request_object_mode %in% c("request", "request_uri") &&
    is_valid_string(client@request_object_encryption_alg) &&
    is_valid_string(client@request_object_encryption_enc)
  c(
    jarm = resolve_jwks_key_source(
      provider,
      jarm &&
        !resolve_authorization_response_signing_alg(client) %in%
          c("HS256", "HS384", "HS512")
    ),
    id_token = resolve_jwks_key_source(
      provider,
      validates_id && !all(grepl("^HS", provider@allowed_algs))
    ),
    userinfo = resolve_jwks_key_source(
      provider,
      "userinfo" %in%
        operations &&
        isTRUE(provider@userinfo_signed_jwt_required)
    ),
    request_object_encryption = if (encryption) {
      resolve_request_object_encryption_key_source(provider)
    } else {
      "none"
    }
  )
}
