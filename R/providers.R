# OIDC generic + discovery -----------------------------------------------------

#' @title
#' Create a generic OpenID Connect (OIDC) [OAuthProvider]
#'
#' @description
#' Preconfigured [OAuthProvider] for OpenID Connect (OIDC) compliant providers.
#'
#' @param name Friendly name for the provider
#' @param base_url Base URL for OIDC endpoints
#' @param auth_path Authorization endpoint path (default: "/authorize")
#' @param token_path Token endpoint path (default: "/token")
#' @param userinfo_path User info endpoint path (default: "/userinfo")
#' @param introspection_path Token introspection endpoint path (default: "/introspect")
#' @param use_nonce Logical, whether to use OIDC nonce. Defaults to TRUE
#' @param id_token_validation Logical, whether to validate ID tokens automatically
#'   for this provider. Defaults to TRUE
#' @param jwks_host_issuer_match When TRUE (default), enforce that the JWKS host
#'   discovered from the provider matches the issuer host (or a subdomain). For
#'   providers that serve JWKS from a different host (e.g., Google), set
#'   `jwks_host_allow_only` to the exact hostname instead of disabling this.
#'   Disabling (`FALSE`) is not recommended unless you also pin JWKS via
#'   `jwks_host_allow_only` or `jwks_pins`
#' @param allowed_token_types Character vector of allowed token types for
#'  access tokens issued by this provider. Defaults to 'Bearer'
#' @param ... Additional arguments passed to [oauth_provider()]
#'
#' @return [OAuthProvider] object
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_oidc <- function(
  name,
  base_url,
  auth_path = "/authorize",
  token_path = "/token",
  userinfo_path = "/userinfo",
  introspection_path = "/introspect",
  use_nonce = TRUE,
  id_token_validation = TRUE,
  jwks_host_issuer_match = TRUE,
  allowed_token_types = c('Bearer'),
  ...
) {
  auth_url <- paste0(base_url, auth_path)
  token_url <- paste0(base_url, token_path)
  userinfo_url <- paste0(base_url, userinfo_path)
  introspection_url <- paste0(base_url, introspection_path)

  oauth_provider(
    name = name,
    auth_url = auth_url,
    token_url = token_url,
    userinfo_url = userinfo_url,
    introspection_url = introspection_url,
    issuer = base_url,
    use_nonce = use_nonce,
    id_token_validation = id_token_validation,
    token_auth_style = "header",
    allowed_token_types = allowed_token_types,
    jwks_host_issuer_match = jwks_host_issuer_match,
    ...
  )
}

# Preconfigured providers ------------------------------------------------------

#' Create a GitHub [OAuthProvider]
#'
#' @description
#' Pre-configured OAuth 2.0 provider for GitHub.
#'
#' @details
#' You can register a new GitHub OAuth 2.0 app in your
#' ['Developer Settings'](https://github.com/settings/apps).
#'
#' @param name Optional provider name (default "github")
#'
#' @return [OAuthProvider] object for use with a GitHub OAuth 2.0 app
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_github <- function(name = "github") {
  oauth_provider(
    name = name,

    auth_url = "https://github.com/login/oauth/authorize",
    token_url = "https://github.com/login/oauth/access_token",
    userinfo_url = "https://api.github.com/user",
    introspection_url = NA_character_,
    issuer = NA_character_,

    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",

    token_auth_style = "body",
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = c(Accept = "application/json"),

    userinfo_required = TRUE,
    userinfo_id_token_match = FALSE,
    userinfo_id_selector = function(userinfo) as.character(userinfo$id)
  )
}

#' Create a Google [OAuthProvider]
#'
#' @description
#' Pre-configured [OAuthProvider] for Google.
#'
#' @param name Optional provider name (default "google")
#'
#' @return [OAuthProvider] object for use with a Google OAuth 2.0 app
#'
#' @details
#' You can register a new Google OAuth 2.0 app in the
#' [Google Cloud Console](https://console.cloud.google.com/apis/credentials).
#' Configure the client ID & secret in your [OAuthClient].
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_google <- function(name = "google") {
  # Route through oauth_provider() so a reusable JWKS cache is initialized
  oauth_provider(
    name = name,

    auth_url = "https://accounts.google.com/o/oauth2/v2/auth",
    token_url = "https://oauth2.googleapis.com/token",
    revocation_url = "https://oauth2.googleapis.com/revoke",
    userinfo_url = "https://openidconnect.googleapis.com/v1/userinfo",
    issuer = "https://accounts.google.com",

    use_nonce = TRUE,

    token_auth_style = "header",
    extra_auth_params = list(access_type = "offline"),

    userinfo_required = TRUE,
    userinfo_id_token_match = TRUE,

    id_token_required = TRUE,
    id_token_validation = TRUE,

    # Pin JWKS to Google's host; allow-only normalized to host
    jwks_host_allow_only = "www.googleapis.com"
  )
}

#' Create a Microsoft (Entra ID) [OAuthProvider]
#'
#' @description
#' Pre-configured [OAuthProvider] for Microsoft Entra ID (formerly Azure AD)
#' using the v2.0 endpoints. Accepts a tenant identifier and configures the
#' authorization, token, and userinfo endpoints directly (no discovery).
#'
#' @details
#' The `tenant` can be one of the special values "common", "organizations",
#' or "consumers", or a specific directory (tenant) ID GUID
#' (e.g., "00000000-0000-0000-0000-000000000000").
#'
#' When `tenant` is a specific GUID, the provider will enable strict ID token
#' validation (issuer match). When using the multi-tenant aliases ("common",
#' "organizations", "consumers"), the exact issuer depends on the account that
#' signs in and therefore ID token validation is disabled by default to avoid
#' false negatives. You can override this via `id_token_validation` if you know
#' the environment guarantees a fixed issuer.
#'
#' Note: ID token validation requires a stable issuer. For multi-tenant aliases,
#' this provider sets `issuer = NA` and therefore also disables `use_nonce` by
#' default (nonce validation relies on validating the ID token).
#'
#' Microsoft issues RS256 ID tokens; `allowed_algs` is restricted accordingly.
#' The userinfo endpoint is provided by Microsoft Graph
#' (https://graph.microsoft.com/oidc/userinfo).
#'
#' When configuring your [OAuthClient], if you do not have the option to
#' register an app or simply wish to test during development, you may be able
#' to use the default Azure CLI public app, with `client_id`
#' '9391afd1-7129-4938-9e4d-633c688f93c0' (uses `redirect_uri`
#' 'http://localhost:8100').
#'
#' @param name Optional friendly name for the provider. Defaults to "microsoft"
#' @param tenant Tenant identifier ("common", "organizations", "consumers",
#'   or directory GUID). Defaults to "common"
#' @param id_token_validation Optional override (logical). If `NULL` (default),
#'   it's enabled automatically when `tenant` looks like a GUID, otherwise
#'   disabled
#'
#' @return [OAuthProvider] object configured for Microsoft identity platform
#'
#' @example inst/examples/oauth_provider_microsoft.R
#'
#' @export
oauth_provider_microsoft <- function(
  name = "microsoft",
  tenant = c("common", "organizations", "consumers"),
  id_token_validation = NULL
) {
  tenant <- tenant[1]
  stopifnot(is.character(tenant), length(tenant) == 1, nzchar(tenant))
  # Detect GUID-like tenant IDs
  is_guid <- grepl(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    tenant
  )
  if (is.null(id_token_validation)) {
    id_token_validation <- is_guid
  }

  base <- sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0", tenant)
  auth_url <- paste0(base, "/authorize")
  token_url <- paste0(base, "/token")
  userinfo_url <- "https://graph.microsoft.com/oidc/userinfo"
  # Only set issuer when it's stable (GUID tenant); otherwise leave NA
  issuer <- if (is_guid) {
    sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)
  } else {
    NA_character_
  }

  oauth_provider(
    name = name,

    auth_url = auth_url,
    token_url = token_url,
    userinfo_url = userinfo_url,
    introspection_url = NA_character_,

    issuer = issuer,

    use_nonce = isTRUE(id_token_validation),
    use_pkce = TRUE,
    pkce_method = "S256",

    token_auth_style = "body",
    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),

    allowed_algs = c("RS256"),

    userinfo_required = TRUE,
    userinfo_id_token_match = isTRUE(id_token_validation),
    userinfo_id_selector = function(userinfo) userinfo$sub,

    id_token_required = isTRUE(id_token_validation),
    id_token_validation = isTRUE(id_token_validation)
  )
}

#' Create a Spotify [OAuthProvider]
#'
#' @description
#' Pre-configured OAuth 2.0 provider for Spotify.
#' Uses /v1/me as "userinfo". No ID token (not OIDC).
#'
#' @param name Optional provider name (default "spotify")
#' @details
#' Spotify requires scopes to be included in the authorization request.
#' Set requested scopes on the client with `oauth_client(..., scopes = ...)`.
#'
#' @return [OAuthProvider] object for use with a Spotify OAuth 2.0 app
#'
#' @example inst/examples/oauth_provider.R
#' @seealso
#' For an example application which using Spotify OAuth 2.0 login to
#' display the user's listening data, see `vignette("example-spotify")`.
#'
#' @export
oauth_provider_spotify <- function(
  name = "spotify"
) {
  oauth_provider(
    name = name,

    auth_url = "https://accounts.spotify.com/authorize",
    token_url = "https://accounts.spotify.com/api/token",
    userinfo_url = "https://api.spotify.com/v1/me",
    introspection_url = NA_character_,
    issuer = NA_character_,

    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",

    extra_auth_params = list(),
    extra_token_params = list(),
    extra_token_headers = character(),
    token_auth_style = "header",

    userinfo_id_selector = function(userinfo) as.character(userinfo$id),
    userinfo_required = TRUE,
    userinfo_id_token_match = FALSE,

    id_token_required = FALSE,
    id_token_validation = FALSE
  )
}

#' Create a Slack [OAuthProvider] (via OIDC discovery)
#'
#' @param name Optional provider name (default "slack")
#'
#' @return [OAuthProvider] object configured for Slack
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_slack <- function(name = "slack") {
  oauth_provider_oidc_discover(issuer = "https://slack.com", name = name)
}

#' Create a Keycloak [OAuthProvider] (via OIDC discovery)
#'
#' @param base_url Base URL of the Keycloak server, e.g.,
#'  "http://localhost:8080"
#' @param realm Keycloak realm name, e.g., "myrealm"
#' @param name Optional provider name. Defaults to `paste0('keycloak-', realm)`
#' @param token_auth_style Optional override for token endpoint authentication
#'  method. One of "header" (client_secret_basic), "body"
#'  (client_secret_post), "private_key_jwt", or "client_secret_jwt". Defaults
#'  to "body" for Keycloak, which works for both confidential clients and
#'  public PKCE clients (secretless). If you pass `NULL`, discovery will infer
#'  the method from the provider's
#'  `token_endpoint_auth_methods_supported` metadata.
#'
#' @return [OAuthProvider] object configured for the specified Keycloak realm
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_keycloak <- function(
  base_url,
  realm,
  name = paste0("keycloak-", realm),
  token_auth_style = "body"
) {
  stopifnot(nzchar(base_url), nzchar(realm))

  issuer <- paste0(rtrim_slash(base_url), "/realms/", realm)

  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name,
    token_auth_style = token_auth_style
  )
}

#' Create an Okta [OAuthProvider] (via OIDC discovery)
#'
#' @param domain Your Okta domain, e.g., "dev-123456.okta.com"
#' @param auth_server Authorization server ID (default "default")
#' @param name Optional provider name (default "okta")
#'
#' @return [OAuthProvider] object configured for the specified Okta domain
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_okta <- function(
  domain,
  auth_server = "default",
  name = "okta"
) {
  stopifnot(nzchar(domain))

  base <- if (grepl("^https?://", domain)) {
    domain
  } else {
    paste0("https://", domain)
  }

  issuer <- paste0(rtrim_slash(base), "/oauth2/", auth_server)

  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name
  )
}

#' Create an Auth0 [OAuthProvider] (via OIDC discovery)
#'
#' @param domain Your Auth0 domain, e.g., "your-domain.auth0.com"
#' @param name Optional provider name (default "auth0")
#' @param audience Optional audience to request in auth flows
#'
#' @return [OAuthProvider] object configured for the specified Auth0 domain
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_auth0 <- function(domain, name = "auth0", audience = NULL) {
  stopifnot(nzchar(domain))

  base <- if (grepl("^https?://", domain)) {
    domain
  } else {
    paste0("https://", domain)
  }

  issuer <- rtrim_slash(base)

  extra_auth <- if (!is.null(audience)) list(audience = audience) else list()

  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name,
    extra_auth_params = extra_auth
  )
}
