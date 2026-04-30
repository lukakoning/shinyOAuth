# This file defines the OAuthToken object returned after login, refresh, or
# other token operations.
# Use it to keep the access token, optional refresh or ID tokens, expiry time,
# and fetched user info together in one validated result object.

# 1 OAuth token class ------------------------------------------------------

## 1.1 Class definition ----------------------------------------------------

#' OAuthToken S7 class
#'
#' @description
#' S7 class representing OAuth tokens and (optionally) user information.
#'
#' @param access_token Access token
#' @param token_type OAuth access token type (for example `Bearer` or `DPoP`)
#' @param refresh_token Refresh token (if provided by the provider)
#' @param id_token ID token (if provided by the provider; OpenID Connect)
#' @param expires_at Numeric timestamp (seconds since epoch) when the access
#'  token expires. `Inf` for non-expiring tokens
#' @param userinfo List containing user information fetched from the provider's
#'  userinfo endpoint (if fetched)
#' @param cnf Optional confirmation claim set returned alongside a
#'   sender-constrained access token. For RFC 8705 certificate-bound tokens,
#'   this may contain `x5t#S256` with the SHA-256 thumbprint of the client
#'   certificate that must accompany later requests.
#' @param id_token_validated Logical flag indicating whether the ID token was
#'  cryptographically validated (signature verified and standard claims checked)
#'  during the OAuth flow. Defaults to `FALSE`.
#'
#' @details
#' The `id_token_claims` property is a read-only computed property that returns
#' the decoded JWT payload of the ID token as a named list. This surfaces all
#' standard and optional OIDC claims (e.g., `sub`, `iss`, `aud`, `acr`, `amr`,
#' `auth_time`, `nonce`, `at_hash`, etc.) without requiring manual JWT
#' decoding. Returns an empty list when no ID token is present or if the token
#' cannot be decoded.
#'
#' Note: `id_token_claims` always decodes the JWT payload regardless
#' of whether the ID token's signature was verified.
#' Check the `id_token_validated` property to determine whether the claims
#' were cryptographically validated.
#'
#' @example inst/examples/token_methods.R
#'
#' @export
OAuthToken <- S7::new_class(
  "OAuthToken",
  package = "shinyOAuth",
  properties = list(
    access_token = S7::class_character,

    token_type = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),

    refresh_token = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),

    id_token = S7::new_property(S7::class_character, default = NA_character_),

    expires_at = S7::new_property(S7::class_numeric, default = Inf),

    userinfo = S7::class_list,

    cnf = S7::new_property(
      S7::class_list,
      default = list()
    ),

    id_token_validated = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),

    id_token_claims = S7::new_property(
      class = S7::class_list,
      getter = function(self) {
        raw <- S7::prop(self, "id_token")
        if (
          !is.character(raw) || length(raw) != 1L || is.na(raw) || !nzchar(raw)
        ) {
          return(list())
        }
        tryCatch(
          parse_jwt_payload(raw),
          error = function(e) list()
        )
      }
    )
  ),
  # Validate one token bundle before the rest of the package reads token
  # fields, expiry times, or decoded ID token claims.
  # Used every time an OAuthToken is created. Input: one token object.
  # Output: NULL on success or one error string describing the first problem.
  validator = function(self) {
    # Validate one optional token field that may be NA or a non-empty string.
    # Used only by the validator. Input: field value and field name. Output:
    # NULL or an error string.
    validate_optional_token_field <- function(value, field) {
      if (!is.character(value) || length(value) != 1L) {
        return(sprintf(
          "OAuthToken: %s must be a scalar character value",
          field
        ))
      }

      if (!is.na(value) && !nzchar(trimws(value))) {
        return(sprintf(
          "OAuthToken: %s must be NA or a non-empty string",
          field
        ))
      }

      NULL
    }

    if (!(is.character(self@access_token) && length(self@access_token) == 1L)) {
      return("OAuthToken: access_token must be a scalar character value")
    }
    if (is.na(self@access_token) || !nzchar(trimws(self@access_token))) {
      return("OAuthToken: access_token must be a non-empty string")
    }

    for (field in c("token_type", "refresh_token", "id_token")) {
      problem <- validate_optional_token_field(S7::prop(self, field), field)
      if (!is.null(problem)) {
        return(problem)
      }
    }

    expires_at <- self@expires_at
    if (!is.numeric(expires_at) || length(expires_at) != 1L) {
      return(
        "OAuthToken: expires_at must be a single numeric timestamp, NA, or Inf"
      )
    }
    if (is.nan(expires_at) || identical(expires_at, -Inf)) {
      return("OAuthToken: expires_at must be a finite timestamp, NA, or Inf")
    }

    thumbprint <- self@cnf[["x5t#S256"]] %||% NULL
    if (!is.null(thumbprint) && !is_valid_string(thumbprint)) {
      return(
        "OAuthToken: cnf$x5t#S256 must be a non-empty string when supplied"
      )
    }

    if (isTRUE(self@id_token_validated)) {
      if (!(is_valid_string(self@id_token) && nzchar(trimws(self@id_token)))) {
        return(
          "OAuthToken: id_token_validated = TRUE requires a non-empty id_token"
        )
      }

      parsed_claims <- try(parse_jwt_payload(self@id_token), silent = TRUE)
      if (inherits(parsed_claims, "try-error") || !is.list(parsed_claims)) {
        return(
          "OAuthToken: id_token_validated = TRUE requires id_token to be a parseable JWT"
        )
      }
    }

    NULL
  }
)
