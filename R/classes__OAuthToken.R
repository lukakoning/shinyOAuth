#' OAuthToken S7 class
#'
#' @description
#' S7 class representing OAuth tokens and (optionally) user information.
#'
#' @param access_token Access token
#' @param refresh_token Refresh token (if provided by the provider)
#' @param id_token ID token (if provided by the provider; OpenID Connect)
#' @param expires_at Numeric timestamp (seconds since epoch) when the access
#'  token expires. `Inf` for non-expiring tokens
#' @param userinfo List containing user information fetched from the provider's
#'  userinfo endpoint (if fetched)
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

    refresh_token = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),

    id_token = S7::new_property(S7::class_character, default = NA_character_),

    expires_at = S7::new_property(S7::class_numeric, default = Inf),

    userinfo = S7::class_list,

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
  )
)
