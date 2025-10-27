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
#'
#' @example inst/examples/token_methods.R
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

    userinfo = S7::class_list
  )
)
