#' Discover an OAuth authorization server
#'
#' Fetch RFC 8414 metadata for an OAuth authorization-code provider. The metadata
#' location inserts `/.well-known/oauth-authorization-server` before the issuer's
#' path. A terminal slash is removed for that request; the returned issuer must
#' still match the caller's issuer exactly, including its terminal slash.
#'
#' This helper requires support for the code flow and configures OAuth-only
#' behavior: no automatic `openid` scope, OIDC nonce, ID-token validation or
#' UserInfo request. It retains the discovery transport, endpoint, host, PKCE,
#' client authentication, PAR, DPoP and mTLS checks. JWKS is optional; an
#' advertised JWKS URL still undergoes the normal URL and host checks.
#'
#' Supply an issuer identifier, rather than a metadata-document URL. This helper
#' does not fall back to another discovery location and does not verify signed
#' metadata. Use [oauth_provider_oidc_discover()] for OpenID Connect.
#'
#' @inheritParams oauth_provider_oidc_discover
#' @param issuer Exact OAuth authorization-server issuer URL, including its
#'   scheme, path and any terminal slash. Supply the issuer identifier rather
#'   than a metadata-document URL.
#' @param ... Additional [oauth_provider()] settings. OIDC settings and relaxed
#'   issuer matching are not accepted by this OAuth-only helper.
#' @return An [OAuthProvider] configured from the authorization-server metadata.
#' @seealso [oauth_provider()], [oauth_provider_oidc_discover()]
#' @examples
#' \dontrun{
#' # Requires your service's issuer URL and a registered public OAuth client.
#' provider <- oauth_provider_oauth_discover(
#'   issuer = "https://auth.example.com",
#'   token_auth_style = "public"
#' )
#' client <- oauth_client(
#'   provider = provider,
#'   client_id = "your-client-id",
#'   redirect_uri = "http://127.0.0.1:8100/callback"
#' )
#' }
#' @export
oauth_provider_oauth_discover <- function(
  issuer,
  name = NULL,
  use_pkce = TRUE,
  token_auth_style = NULL,
  allowed_token_types = "Bearer",
  ...
) {
  dots <- list(...)
  reserved <- c(
    "use_nonce",
    "id_token_validation",
    "id_token_required",
    "id_token_profile",
    "infer_oidc_from_issuer",
    "issuer_match",
    "userinfo_required",
    "userinfo_id_token_match",
    ".oauth_only"
  )
  if (any(reserved %in% names(dots))) {
    err_input(
      "OAuth discovery does not accept OIDC settings or relaxed issuer matching"
    )
  }
  do.call(
    .discover_provider,
    c(
      list(
        issuer = issuer,
        name = name,
        use_pkce = use_pkce,
        token_auth_style = token_auth_style,
        allowed_token_types = allowed_token_types,
        use_nonce = FALSE,
        id_token_validation = FALSE,
        issuer_match = "url",
        id_token_required = FALSE,
        userinfo_required = FALSE,
        userinfo_id_token_match = FALSE,
        .oauth_only = TRUE
      ),
      dots
    )
  )
}

.discover_build_oauth_request <- function(issuer) {
  parsed <- httr2::url_parse(issuer)
  if (
    nzchar(parsed[["username"]] %||% "") || nzchar(parsed[["password"]] %||% "")
  ) {
    err_input("OAuth issuer must not contain user information")
  }
  host <- parsed[["hostname"]]
  if (grepl(":", host, fixed = TRUE) && !startsWith(host, "[")) {
    host <- paste0("[", host, "]")
  }
  authority <- paste0(parsed[["scheme"]], "://", host)
  port <- parsed[["port"]] %||% ""
  if (nzchar(port)) {
    authority <- paste0(authority, ":", port)
  }
  path <- sub("/+$", "", url_raw_path(issuer))
  httr2::request(paste0(
    authority,
    "/.well-known/oauth-authorization-server",
    path
  )) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    add_req_defaults() |>
    req_no_redirect()
}
