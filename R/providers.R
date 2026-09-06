# This file contains ready-to-use provider constructors
# Used for creating common provider configurations with endpoints and defaults
# already filled in

# 1 Provider constructors ------------------------------------------------------

## 1.1 Generic OIDC construction -----------------------------------------------

#' @title
#' Create a generic OpenID Connect (OIDC) [OAuthProvider]
#'
#' @description
#' Build OIDC provider URLs from a base address and known endpoint paths.
#' Use this when configuring an OIDC service without discovery, with its
#' endpoint paths available from the service configuration or documentation.
#' Use [oauth_provider_oidc_discover()] if your provider offers discovery, which
#' looks up its actual URLs. This helper is for manual configuration; its
#' default paths must match the service you are using.
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
#' @param token_auth_style Token endpoint client authentication style passed to
#'   [oauth_provider()]. Defaults to `"header"`.
#' @param jwks_host_issuer_match When TRUE (default), enforce that the JWKS host
#'   discovered from the provider matches the issuer host exactly. For
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
  token_auth_style = "header",
  jwks_host_issuer_match = TRUE,
  allowed_token_types = c("Bearer"),
  ...
) {
  base_url <- sub("/+$", "", base_url)

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
    issuer_thus_oidc = TRUE,
    use_nonce = use_nonce,
    id_token_validation = id_token_validation,
    token_auth_style = token_auth_style,
    allowed_token_types = allowed_token_types,
    jwks_host_issuer_match = jwks_host_issuer_match,
    ...
  )
}

## 1.2 Direct-configured provider presets --------------------------------------

#' Create a GitHub [OAuthProvider]
#'
#' @description
#' Create the provider configuration for a GitHub OAuth App, then pass it with
#' your app credentials to [oauth_client()]. This configures profile retrieval
#' from GitHub's API; GitHub does not return an OIDC ID token.
#'
#' @details
#' You can register a new GitHub OAuth 2.0 app in your
#' [OAuth App settings](https://github.com/settings/developers).
#'
#' @param name Optional provider name (default "github")
#'
#' @return [OAuthProvider] object for use with a GitHub OAuth 2.0 app
#'
#' @examples
#' oauth_provider_github()
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
    userinfo_id_selector = function(userinfo) {
      as.character(userinfo[["id"]])
    }
  )
}

#' Create a Google [OAuthProvider]
#'
#' @description
#' Use your Google app registration with [oauth_client()] to add Google
#' sign-in. The helper configures OIDC validation and profile retrieval.
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
#' @examples
#' oauth_provider_google()
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
    issuer_thus_oidc = TRUE,

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
#' Create provider settings for Microsoft Entra ID. Choose which accounts may
#' sign in with `tenant`, then pass the provider and your own registered app's
#' credentials to [oauth_client()].
#'
#' @details
#' Use a directory (tenant) ID to target one organization. `"organizations"`
#' allows work or school accounts, `"consumers"` allows personal Microsoft
#' accounts, and `"common"` allows both. Your app registration and app access
#' rules must also permit the intended accounts.
#'
#' ID token validation is enabled for these tenant choices. For a directory ID,
#' the issuer must match that directory. `"common"` and `"organizations"` use
#' Microsoft's tenant-independent issuer template and signing-key issuer rules.
#' `"consumers"` uses the consumer tenant issuer. The helper restricts ID token
#' algorithms to RS256 and fetches userinfo from Microsoft Graph.
#'
#' Setting `id_token_validation = FALSE` disables ID token and nonce checks and
#' leaves OAuth plus profile retrieval. Keep the default for OIDC sign-in.
#'
#' @param name Optional friendly name for the provider. Defaults to "microsoft"
#' @param tenant Tenant identifier ("common", "organizations", "consumers",
#'   or directory GUID). Defaults to "common"
#' @param id_token_validation Optional override (logical). If `NULL` (default),
#'   it's enabled automatically when `tenant` looks like a GUID or one of the
#'   Microsoft alias tenants (`common`, `organizations`, `consumers`).
#'   `common` and `organizations` use Microsoft's tenant-independent issuer and
#'   signing-key validation rules; `consumers` uses the stable consumer tenant
#'   issuer
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
  if (!is_valid_string(tenant)) {
    err_input("tenant must be a non-empty string")
  }
  consumer_tenant_guid <- "9188040d-6c67-4c5b-b112-36a304b66dad"
  tenant_independent_alias <- tenant %in% c("common", "organizations")
  consumer_alias <- identical(tenant, "consumers")
  is_guid <- is_guid_like(tenant)
  if (is.null(id_token_validation)) {
    id_token_validation <- is_guid || tenant_independent_alias || consumer_alias
  }

  base <- sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0", tenant)
  auth_url <- paste0(base, "/authorize")
  token_url <- paste0(base, "/token")
  userinfo_url <- "https://graph.microsoft.com/oidc/userinfo"
  issuer <- if (is_guid) {
    sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)
  } else if (!isTRUE(id_token_validation)) {
    NA_character_
  } else if (tenant_independent_alias) {
    sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)
  } else if (consumer_alias) {
    sprintf("https://login.microsoftonline.com/%s/v2.0", consumer_tenant_guid)
  } else {
    NA_character_
  }
  issuer_match <- if (tenant_independent_alias && isTRUE(id_token_validation)) {
    "host"
  } else {
    "url"
  }

  oauth_provider(
    name = name,

    auth_url = auth_url,
    token_url = token_url,
    userinfo_url = userinfo_url,
    introspection_url = NA_character_,

    issuer = issuer,
    issuer_thus_oidc = TRUE,
    issuer_match = issuer_match,

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
    userinfo_id_selector = function(userinfo) {
      userinfo[["sub"]]
    },

    id_token_required = isTRUE(id_token_validation),
    id_token_validation = isTRUE(id_token_validation)
  )
}

#' Create a Spotify [OAuthProvider]
#'
#' @description
#' Connect your app to a user's Spotify account. Pass this provider to
#' [oauth_client()] and request the scopes needed by the Spotify API calls you
#' plan to make. The helper configures profile retrieval through Spotify's API
#' and does not expect an ID token.
#'
#' @param name Optional provider name (default "spotify")
#' @param allow_legacy_id Whether to fall back to Spotify's mutable `id` when
#'   `account_id` is absent. Default `FALSE`; enable only during migration.
#' @details
#' Spotify requires scopes to be included in the authorization request.
#' Set requested scopes on the client with `oauth_client(..., scopes = ...)`.
#' Identity uses Spotify's immutable `account_id`. Existing installations must
#' migrate stored account mappings and audit digests from `id` before upgrading.
#' Link the old and new identifiers only from a successfully authenticated
#' profile; do not use display names or email to merge accounts. To temporarily
#' preserve old mappings, explicitly replace `provider@userinfo_id_selector`
#' with `function(userinfo) userinfo[["id"]]` while completing the migration.
#'
#' @return [OAuthProvider] object for use with a Spotify OAuth 2.0 app
#'
#' @examples
#' oauth_provider_spotify()
#' @seealso
#' For a Shiny app that connects to Spotify to
#' display the user's listening data, see the [Spotify example](https://lukakoning.github.io/shinyOAuth/articles/example-spotify.html).
#'
#' @export
oauth_provider_spotify <- function(
  name = "spotify",
  allow_legacy_id = FALSE
) {
  if (
    !is.logical(allow_legacy_id) ||
      length(allow_legacy_id) != 1L ||
      is.na(allow_legacy_id)
  ) {
    err_input("allow_legacy_id must be a single non-NA logical")
  }
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

    userinfo_id_selector = function(userinfo) {
      account_id <- userinfo[["account_id"]]
      if (is_valid_string(account_id)) {
        return(account_id)
      }
      if (
        isTRUE(allow_legacy_id) &&
          is.null(account_id) &&
          is_valid_string(userinfo[["id"]])
      ) {
        return(userinfo[["id"]])
      }
      NA_character_
    },
    userinfo_required = TRUE,
    userinfo_id_token_match = FALSE,

    id_token_required = FALSE,
    id_token_validation = FALSE
  )
}


## 1.3 Discovery-backed provider presets ---------------------------------------

#' Create a Slack [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Look up Slack's OpenID Connect settings for Sign in with Slack. This
#' helper contacts the discovery service during setup; pass its result to
#' [oauth_client()] with your Slack app credentials.
#'
#' @param name Optional provider name (default "slack")
#' @param profile Slack app registration profile: `"confidential"` (default)
#'   uses HTTP Basic and OIDC nonce validation without PKCE; `"public_pkce"`
#'   uses S256 PKCE and sends no client secret. Select the public profile only
#'   after enabling PKCE for that Slack app. Slack marks the app public, and
#'   reversing that registration setting requires contacting Slack support.
#'   See <https://docs.slack.dev/authentication/using-pkce/>.
#'
#' @return [OAuthProvider] object configured for Slack
#'
#' @examples
#' \dontrun{
#' oauth_provider_slack()
#' }
#'
#' @export
oauth_provider_slack <- function(
  name = "slack",
  profile = c("confidential", "public_pkce")
) {
  profile <- match.arg(profile)
  provider <- oauth_provider_oidc_discover(
    issuer = "https://slack.com",
    name = name,
    token_auth_style = "header",
    use_pkce = identical(profile, "public_pkce")
  )
  if (identical(profile, "public_pkce")) {
    # Slack's global discovery omits `none`; the explicit app registration
    # profile is the authority for this app-specific public-client setting.
    provider@token_auth_style <- "public"
  }
  provider
}

#' Create a Keycloak [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Look up login settings for a Keycloak realm. Supply your server URL
#' and realm name, then pass the result to [oauth_client()]. This helper
#' contacts the Keycloak server during setup.
#'
#' @param base_url Base URL of the Keycloak server, e.g.,
#'  "http://localhost:8080". Local HTTP development also requires
#'  `options(shinyOAuth.allow_insecure_oidc_loopback = TRUE)`.
#' @param realm Keycloak realm name, e.g., "myrealm"
#' @param name Optional provider name. Defaults to `paste0('keycloak-', realm)`
#' @param token_auth_style Optional override for token endpoint authentication
#'  method. One of "header" (client_secret_basic), "body"
#'  (client_secret_post), "public" (send `client_id` only; `"none"` alias also
#'  accepted), "private_key_jwt", or "client_secret_jwt". Defaults
#'  to "body" for Keycloak, which works for many common setups. Use `"public"`
#'  if you need to suppress `client_secret` even when it is set in the
#'  environment. If you pass `NULL`, discovery will infer the method from the
#'  provider's `token_endpoint_auth_methods_supported` metadata.
#' @param jarm_tolerate_duplicate_top_level_iss Logical. Defaults to `TRUE`
#'  for Keycloak because current Keycloak JARM responses may repeat an
#'  identical top-level `iss` claim. Set `FALSE` to fail closed on duplicate
#'  top-level `iss` members instead of applying this interoperability
#'  workaround.
#'
#' @return [OAuthProvider] object configured for the specified Keycloak realm
#'
#' @examples
#' \dontrun{
#' oauth_provider_keycloak("https://login.example.com", realm = "myrealm")
#' }
#'
#' @export
oauth_provider_keycloak <- function(
  base_url,
  realm,
  name = paste0("keycloak-", realm),
  token_auth_style = "body",
  jarm_tolerate_duplicate_top_level_iss = TRUE
) {
  if (!is_valid_string(base_url)) {
    err_input("base_url must be a non-empty string")
  }
  if (!is_valid_string(realm)) {
    err_input("realm must be a non-empty string")
  }

  issuer <- paste0(rtrim_slash(base_url), "/realms/", realm)

  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name,
    token_auth_style = token_auth_style,
    jarm_tolerate_duplicate_top_level_iss = jarm_tolerate_duplicate_top_level_iss
  )
}

#' Create an Okta [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Look up login settings for your Okta domain and authorization server.
#' Pass the result to [oauth_client()] with your registered app credentials.
#' This helper makes a discovery request during setup.
#'
#' @param domain Your Okta domain, e.g., "dev-123456.okta.com"
#' @param auth_server Authorization server ID for a custom authorization
#'   server (default "default"). Use `NULL` to target the org authorization
#'   server at `https://{yourOktaDomain}`.
#' @param name Optional provider name (default "okta")
#'
#' @return [OAuthProvider] object configured for the specified Okta domain
#'
#' @examples
#' \dontrun{
#' oauth_provider_okta("dev-123456.okta.com")
#' }
#'
#' @export
oauth_provider_okta <- function(
  domain,
  auth_server = "default",
  name = "okta"
) {
  if (!is_valid_string(domain)) {
    err_input("domain must be a non-empty string")
  }

  if (!(is.null(auth_server) || is_valid_string(auth_server))) {
    err_input("auth_server must be NULL or a non-empty string")
  }

  base <- if (grepl("^https?://", domain)) {
    domain
  } else {
    paste0("https://", domain)
  }

  issuer <- if (is.null(auth_server)) {
    rtrim_slash(base)
  } else {
    paste0(rtrim_slash(base), "/oauth2/", auth_server)
  }

  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name
  )
}

#' Create an Auth0 [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Look up login settings for your Auth0 domain. Pass the result to
#' [oauth_client()] with your registered app credentials. This helper makes
#' a discovery request during setup.
#'
#' @param domain Your Auth0 domain, e.g., "your-domain.auth0.com"
#' @param name Optional provider name (default "auth0")
#' @param audience Optional audience value to send in authorization requests.
#'
#' @return [OAuthProvider] object configured for the specified Auth0 domain
#'
#' @examples
#' \dontrun{
#' oauth_provider_auth0("your-domain.auth0.com")
#' }
#'
#' @export
oauth_provider_auth0 <- function(domain, name = "auth0", audience = NULL) {
  if (!is_valid_string(domain)) {
    err_input("domain must be a non-empty string")
  }

  base <- if (grepl("^https?://", domain)) {
    domain
  } else {
    paste0("https://", domain)
  }

  # Auth0's issuer identifier includes a trailing slash. Preserve it for the
  # exact Discovery and ID-token issuer comparisons required by OIDC.
  issuer <- paste0(rtrim_slash(base), "/")

  extra_auth <- if (!is.null(audience)) list(audience = audience) else list()

  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name,
    extra_auth_params = extra_auth
  )
}

# 2 Helpers --------------------------------------------------------------------

## 2.1 Microsoft-specific helpers ----------------------------------------------

#' Check whether a value looks like a GUID
#'
#' Used by [oauth_provider_microsoft()] and tenant-independent ID token
#' validation helpers.
#'
#' @param value Candidate tenant identifier.
#' @return `TRUE` when `value` is a single GUID-like string; otherwise `FALSE`.
#' @keywords internal
#' @noRd
is_guid_like <- function(value) {
  is.character(value) &&
    length(value) == 1L &&
    !is.na(value) &&
    grepl(
      "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
      value
    )
}

#' Detect a tenant-independent Microsoft issuer
#'
#' Used by Microsoft-specific issuer handling when tenant-independent
#' authorities are configured.
#'
#' @param issuer Issuer URL to inspect.
#' @return A normalized tenant-independent issuer path, or `NULL` when `issuer`
#'   is not one of the supported Microsoft tenant-independent authorities.
#' @keywords internal
#' @noRd
microsoft_tenant_independent_issuer <- function(issuer) {
  if (!is_valid_string(issuer)) {
    return(NULL)
  }

  parsed <- try(httr2::url_parse(issuer), silent = TRUE)
  if (inherits(parsed, "try-error")) {
    return(NULL)
  }

  host <- tolower(parsed[["hostname"]] %||% "")
  path <- tolower(gsub(
    "^/+|/+$",
    "",
    parsed[["path"]] %||% ""
  ))

  if (!identical(host, "login.microsoftonline.com")) {
    return(NULL)
  }

  if (path %in% c("common/v2.0", "organizations/v2.0")) {
    return(path)
  }

  NULL
}

#' Resolve the expected ID token issuer
#'
#' Used before issuer comparison during Microsoft tenant-independent token
#' validation.
#'
#' @param provider_issuer Configured provider issuer.
#' @param token_payload Parsed ID token payload.
#' @return A list containing `expected_issuer`, `enforce_key_issuer`, and
#'   `token_tid`.
#' @keywords internal
#' @noRd
resolve_expected_id_token_issuer <- function(provider_issuer, token_payload) {
  if (is.null(microsoft_tenant_independent_issuer(provider_issuer))) {
    return(list(
      expected_issuer = provider_issuer,
      enforce_key_issuer = FALSE,
      token_tid = NULL
    ))
  }

  token_tid <- token_payload[["tid"]] %||% NULL
  if (!is_guid_like(token_tid)) {
    err_id_token(c(
      "x" = "Microsoft ID token missing or invalid tid claim",
      "i" = paste(
        "Tenant-independent Microsoft authorities require a GUID tid claim"
      )
    ))
  }

  list(
    expected_issuer = sprintf(
      "https://login.microsoftonline.com/%s/v2.0",
      token_tid
    ),
    enforce_key_issuer = TRUE,
    token_tid = token_tid
  )
}

#' Filter Microsoft JWKS keys by token issuer
#'
#' Used only for tenant-independent Microsoft authorities after candidate keys
#' have been selected.
#'
#' @param keys Candidate JWKS keys.
#' @param provider_issuer Configured provider issuer.
#' @param token_issuer Issuer claim from the token being validated.
#' @param token_tid Tenant id claim from the token being validated.
#' @return The subset of `keys` that matches the token issuer context.
#' @keywords internal
#' @noRd
filter_microsoft_jwks_for_token_issuer <- function(
  keys,
  provider_issuer,
  token_issuer,
  token_tid
) {
  if (
    is.null(microsoft_tenant_independent_issuer(provider_issuer)) ||
      length(keys) == 0L ||
      !is_valid_string(token_issuer) ||
      !is_guid_like(token_tid)
  ) {
    return(keys)
  }

  keep <- vapply(
    keys,
    function(key) {
      key_issuer <- key[["issuer"]] %||% NULL
      if (!is_valid_string(key_issuer)) {
        return(FALSE)
      }

      if (grepl("\\{tenantid\\}", key_issuer, ignore.case = TRUE)) {
        key_issuer <- gsub(
          "\\{tenantid\\}",
          token_tid,
          key_issuer,
          ignore.case = TRUE
        )
      }

      identical(key_issuer, token_issuer)
    },
    logical(1)
  )

  keys[keep]
}
