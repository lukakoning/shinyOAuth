# This file contains Apple-specific helpers for Sign in with Apple
# Used for configuring Apple's discovery-backed OIDC provider and generating
# the ES256 client-secret JWT that Apple expects on token requests

# 1 Apple helpers -------------------------------------------------------------

## 1.1 Provider constructor ---------------------------------------------------

#' Create an Apple [OAuthProvider]
#'
#' @description
#' Ready-to-use [OAuthProvider] settings for Sign in with Apple.
#'
#' @details
#' This helper resolves Sign in with Apple's current metadata from Apple's OIDC
#' discovery document at `https://appleid.apple.com/.well-known/openid-configuration`.
#'
#' Apple does not publish a userinfo endpoint, so this helper relies on the
#' validated ID token for subject and claim data and leaves
#' `userinfo_required = FALSE`.
#'
#' When configuring your [OAuthClient]:
#' - use your Services ID or App ID as `client_id`
#' - supply `client_secret` as an Apple-signed ES256 JWT, for example via
#'   `oauth_client_secret_apple()`
#' - use an HTTPS redirect URI with a domain name; Apple does not allow IP
#'   literals or `localhost`
#' - if you request `email` or `name`, configure
#'   `oauth_client(..., response_mode = "form_post")` and wrap your UI with
#'   [oauth_form_post_ui()]
#'
#' Apple can return a one-time `user` JSON payload on the front-channel
#' form_post callback when `email` or `name` are requested. shinyOAuth does not
#' currently map that transient payload into the returned [OAuthToken]
#' `userinfo` field, so this helper leaves `userinfo_required = FALSE` and
#' relies on ID token claims.
#'
#' Because this helper delegates to [oauth_provider_oidc_discover()], any
#' discovery-backed metadata Apple publishes in the future is picked up
#' automatically. When a particular discovery field is omitted, shinyOAuth keeps
#' the same defaults documented for [oauth_provider_oidc_discover()].
#'
#' @param name Optional provider name (default "apple")
#'
#' @return [OAuthProvider] object configured for Sign in with Apple
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_apple <- function(name = "apple") {
  oauth_provider_oidc_discover(
    issuer = "https://appleid.apple.com",
    name = name
  )
}

## 1.2 Client secret helper ---------------------------------------------------

#' Create an Apple client secret JWT
#'
#' @description
#' Builds the ES256-signed JWT that Apple expects in the token-request
#' `client_secret` form field for Sign in with Apple.
#'
#' @details
#' Apple currently requires the following JWT shape for Sign in with Apple
#' token requests:
#' - JOSE header `alg = ES256` and `kid = <Apple key id>`
#' - `iss = <Apple Developer Team ID>`
#' - `sub = <client_id>`
#' - `aud = "https://appleid.apple.com"`
#' - `exp` no more than `15777000` seconds (six months) after `iat`
#'
#' The resulting string can be supplied directly to [oauth_client()] as the
#' `client_secret` for `oauth_provider_apple()`.
#'
#' @param client_id Apple Services ID or App ID used as the OAuth client id
#' @param team_id Apple Developer Team ID. Apple documents this as a
#'   10-character identifier
#' @param key_id Apple Sign in with Apple private-key identifier (`kid`). Apple
#'   documents this as a 10-character identifier
#' @param private_key Apple private key as an `openssl::key` or PEM string. The
#'   key must be compatible with `ES256` (P-256 ECDSA)
#' @param expires_in Positive lifetime in seconds. Must be no more than
#'   `15777000` seconds (six months). Defaults to `15776700` seconds, leaving a
#'   five-minute margin below Apple's documented maximum
#' @param issued_at Issue time for the JWT. Defaults to `Sys.time()`
#' @param audience Audience claim. Defaults to `"https://appleid.apple.com"`
#'
#' @return A compact signed JWT string suitable for `oauth_client(...,
#'   client_secret = ...)`
#'
#' @examples
#' \dontrun{
#' key <- openssl::ec_keygen(curve = "P-256")
#'
#' oauth_client_secret_apple(
#'   client_id = "com.example.web",
#'   team_id = "ABCDEFGHIJ",
#'   key_id = "ABC123DEFG",
#'   private_key = key
#' )
#' }
#'
#' @export
oauth_client_secret_apple <- function(
  client_id,
  team_id,
  key_id,
  private_key,
  expires_in = 15776700,
  issued_at = Sys.time(),
  audience = "https://appleid.apple.com"
) {
  if (!is_valid_string(client_id)) {
    err_input("client_id must be a non-empty string")
  }
  if (!is_valid_string(team_id) || nchar(team_id) != 10L) {
    err_input("team_id must be a 10-character string")
  }
  if (!is_valid_string(key_id) || nchar(key_id) != 10L) {
    err_input("key_id must be a 10-character string")
  }
  if (!is_valid_string(audience)) {
    err_input("audience must be a non-empty string")
  }

  expires_in <- suppressWarnings(as.numeric(expires_in))
  if (
    !is.numeric(expires_in) ||
      length(expires_in) != 1L ||
      is.na(expires_in) ||
      !is.finite(expires_in) ||
      expires_in <= 0
  ) {
    err_input("expires_in must be a single positive number of seconds")
  }
  if (expires_in > 15777000) {
    err_input(
      "expires_in must be less than or equal to 15777000 seconds (six months)"
    )
  }

  issued_at <- suppressWarnings(as.numeric(issued_at))
  if (
    !is.numeric(issued_at) ||
      length(issued_at) != 1L ||
      is.na(issued_at) ||
      !is.finite(issued_at)
  ) {
    err_input("issued_at must be a single finite time value")
  }

  key <- normalize_private_key_input(private_key, arg_name = "private_key")
  if (!private_key_can_sign_jws_alg(key, "ES256", typ = "JWT")) {
    err_config(
      "private_key must be an ES256-compatible P-256 EC private key"
    )
  }

  iat <- floor(issued_at)
  claims <- list(
    iss = team_id,
    iat = iat,
    exp = iat + as.integer(expires_in),
    aud = audience,
    sub = client_id
  )
  header <- list(
    alg = "ES256",
    kid = key_id
  )

  jwt <- try(
    jose::jwt_encode_sig(
      do.call(jose::jwt_claim, claims),
      key = key,
      header = header
    ),
    silent = TRUE
  )
  if (inherits(jwt, "try-error")) {
    err_config("Failed to sign Apple client secret")
  }

  jwt
}
