#' Check a security policy flag
#'
#' Rejects missing and vector values before policy normalization.
#' @param value Candidate policy value.
#' @return Whether the value is one non-missing logical.
#' @keywords internal
#' @noRd
is_scalar_logical <- function(value) {
  is.logical(value) && length(value) == 1L && !is.na(value)
}

#' Provider boolean policy properties
#'
#' Shared by helper input validation and the S7 invariant. Discovery capability
#' flags with an explicit unknown (NA) state are validated separately.
#' @return Character vector of boolean property names.
#' @keywords internal
#' @noRd
oauth_provider_boolean_fields <- function() {
  c(
    "issuer_thus_oidc",
    "use_pkce",
    "use_nonce",
    "userinfo_required",
    "userinfo_id_token_match",
    "userinfo_signed_jwt_required",
    "id_token_required",
    "id_token_validation",
    "id_token_at_hash_required",
    "jwks_host_issuer_match",
    "par_required",
    "signed_request_object_required",
    "authorization_response_iss_parameter_supported",
    "mtls_client_certificate_bound_access_tokens",
    "jarm_tolerate_duplicate_top_level_iss"
  )
}
