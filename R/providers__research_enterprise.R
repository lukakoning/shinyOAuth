# Provider presets for research services and institutional deployments.
# Discovery-backed helpers make a network request during app setup.

#' Create an ORCID [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Configure researcher sign-in with ORCID. Discovery selects ORCID's
#' `client_secret_post` authentication; pass a client secret to [oauth_client()].
#'
#' @details
#' Request `scopes = "openid"` on the client. ORCID uses this instead of
#' `/authenticate` for OIDC login; do not request both. Its OIDC metadata does
#' not advertise `profile` or `email` scopes. Additional record permissions
#' depend on whether you registered a Public or Member API client.
#'
#' Sandbox and production require separate credentials and user accounts.
#' Production redirect URIs must use HTTPS. ORCID does not advertise PKCE in
#' its discovery metadata, so this confidential-client preset uses client
#' authentication and validated OIDC nonce without claiming PKCE protection.
#' See the [ORCID authentication guide](https://info.orcid.org/documentation/api-tutorials/api-tutorial-get-and-authenticated-orcid-id/).
#'
#' @param name Optional provider name (default `"orcid"`).
#' @param sandbox Logical; use ORCID's sandbox instead of production.
#'
#' @return [OAuthProvider] object configured for ORCID.
#' @examples
#' \dontrun{
#' oauth_provider_orcid()
#' oauth_provider_orcid(sandbox = TRUE)
#' }
#' @export
oauth_provider_orcid <- function(name = "orcid", sandbox = FALSE) {
  if (!is_scalar_logical(sandbox)) {
    err_input("sandbox must be a single non-NA logical")
  }
  issuer <- if (sandbox) "https://sandbox.orcid.org" else "https://orcid.org"
  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name,
    token_auth_style = "body",
    use_pkce = FALSE
  )
}

#' Create a GitLab [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Configure OIDC sign-in with GitLab.com or a self-managed GitLab instance.
#' Register an OAuth application on that instance, then pass its credentials
#' to [oauth_client()] with `scopes = c("openid", "profile", "email")`.
#'
#' @details
#' Supply only the scopes your app needs; `"openid"` is enough to request an
#' ID token. API and repository access require separate GitLab scopes.
#' See [GitLab's OIDC guide](https://docs.gitlab.com/integration/openid_connect_provider/).
#'
#' @param base_url GitLab instance URL, including HTTPS and any deployment
#'   subpath. Defaults to `"https://gitlab.com"`.
#' @param name Optional provider name (default `"gitlab"`).
#' @inheritParams oauth_provider_oidc_discover
#' @return [OAuthProvider] object configured for GitLab.
#' @examples
#' \dontrun{
#' oauth_provider_gitlab()
#' oauth_provider_gitlab("https://gitlab.example.edu")
#' }
#' @export
oauth_provider_gitlab <- function(
  base_url = "https://gitlab.com",
  name = "gitlab",
  token_auth_style = NULL
) {
  if (!is_valid_string(base_url)) {
    err_input("base_url must be a non-empty string")
  }
  oauth_provider_oidc_discover(
    issuer = rtrim_slash(base_url),
    name = name,
    token_auth_style = token_auth_style
  )
}

#' Create an Amazon Cognito [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Configure OIDC login for an Amazon Cognito user pool. Register an app client
#' with the authorization code grant, configure a user pool login domain, and
#' pass the app credentials to [oauth_client()] with the enabled OIDC scopes.
#'
#' @details
#' Use the exact user pool issuer, not the managed-login or custom domain.
#' Discovery obtains authorization, token, and UserInfo URLs on that login
#' domain while retaining the pool issuer for ID token validation. Both the
#' original `cognito-idp` and updated `issuer-cognito-idp` issuer forms are
#' supported, as are AWS partition-specific hostnames. No AWS credentials
#' are needed for discovery.
#'
#' See [Cognito endpoints](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html).
#'
#' @param issuer Exact user pool issuer URL from AWS, for example
#'   `"https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Example"`.
#' @param name Optional provider name (default `"cognito"`).
#' @inheritParams oauth_provider_oidc_discover
#' @return [OAuthProvider] object configured for a Cognito user pool.
#' @examples
#' \dontrun{
#' oauth_provider_cognito(
#'   "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Example"
#' )
#' }
#' @export
oauth_provider_cognito <- function(
  issuer,
  name = "cognito",
  token_auth_style = NULL
) {
  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name,
    token_auth_style = token_auth_style
  )
}

#' Create a Globus Auth [OAuthProvider]
#'
#' @description
#' Configure OIDC sign-in with Globus Auth using its published endpoints and
#' RS512 ID token signatures. Register a confidential web application at
#' <https://app.globus.org/settings/developers> and request
#' `scopes = c("openid", "profile", "email")` on [oauth_client()].
#'
#' @details
#' This preset does not make a discovery request. Globus currently advertises
#' RS512 only, whereas generic OIDC discovery requires advertised RS256 support.
#' The preset pins RS512 and the Globus JWKS URL, retaining signature, issuer,
#' audience, nonce, UserInfo subject, and S256 PKCE validation.
#'
#' This helper supports OIDC login. Globus API grants can return separate
#' credentials for several resource servers in `other_tokens`. Those fields
#' are preserved in `token@extra_fields`, but shinyOAuth does not automatically
#' select, refresh, or revoke the nested tokens. Keep this login client's
#' scopes limited to `openid`, `profile`, `email`, and optionally
#' `offline_access`; use a separate Globus-aware integration for multi-resource
#' API authorization. Never send the login access token to another resource
#' server merely because a nested token granted access to it.
#'
#' See the [Globus Auth guide](https://docs.globus.org/api/auth/developer-guide/).
#'
#' @param name Optional provider name (default `"globus"`).
#' @return [OAuthProvider] object configured for Globus Auth login.
#' @examples
#' oauth_provider_globus()
#' @export
oauth_provider_globus <- function(name = "globus") {
  oauth_provider(
    name = name,
    issuer = "https://auth.globus.org",
    auth_url = "https://auth.globus.org/v2/oauth2/authorize",
    token_url = "https://auth.globus.org/v2/oauth2/token",
    userinfo_url = "https://auth.globus.org/v2/oauth2/userinfo",
    revocation_url = "https://auth.globus.org/v2/oauth2/token/revoke",
    jwks_uri = "https://auth.globus.org/jwk.json",
    id_token_allowed_algs = "RS512",
    token_auth_style = "header",
    use_pkce = TRUE,
    pkce_method = "S256"
  )
}

#' Create a Hugging Face [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Configure Sign in with Hugging Face. Register an OAuth application in your
#' Hugging Face settings, then pass its credentials to [oauth_client()].
#'
#' @details
#' For login, request `scopes = c("openid", "profile")`, adding `"email"`
#' only if needed. Repository access and inference require their own scopes,
#' such as `"read-repos"` or `"inference-api"`, and user consent.
#' This preset targets confidential applications with a client secret.
#' See [Sign in with Hugging Face](https://huggingface.co/docs/hub/oauth).
#'
#' @param name Optional provider name (default `"huggingface"`).
#' @return [OAuthProvider] object configured for Hugging Face.
#' @examples
#' \dontrun{
#' oauth_provider_huggingface()
#' }
#' @export
oauth_provider_huggingface <- function(name = "huggingface") {
  oauth_provider_oidc_discover(
    issuer = "https://huggingface.co",
    name = name,
    token_auth_style = "header"
  )
}

#' Create a SURFconext [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Configure institutional OIDC login through SURFconext. Register your service
#' with SURFconext before using its client credentials with [oauth_client()].
#'
#' @details
#' Request the `"openid"` scope. Additional claims depend on your service's
#' agreed attribute release policy; requesting `"email"` or `"profile"` does
#' not guarantee those attributes will be released. Use the validated issuer
#' and `sub` to identify a user, rather than assuming email is present.
#' Test and production environments require their own service configuration.
#' See [SURFconext for service providers](https://servicedesk.surf.nl/wiki/spaces/IAM/pages/128909810/SURFconext+for+Service+Providers).
#'
#' @param environment SURFconext environment: `"production"` (default) or `"test"`.
#' @param name Optional provider name (default `"surfconext"`).
#' @inheritParams oauth_provider_oidc_discover
#' @return [OAuthProvider] object configured for SURFconext.
#' @examples
#' \dontrun{
#' oauth_provider_surfconext()
#' oauth_provider_surfconext(environment = "test")
#' }
#' @export
oauth_provider_surfconext <- function(
  environment = c("production", "test"),
  name = "surfconext",
  token_auth_style = NULL
) {
  environment <- match.arg(environment)
  issuer <- if (identical(environment, "test")) {
    "https://connect.test.surfconext.nl"
  } else {
    "https://connect.surfconext.nl"
  }
  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name,
    token_auth_style = token_auth_style
  )
}

#' Create an authentik [OAuthProvider] (via OIDC discovery)
#'
#' @description
#' Configure login for an authentik OAuth2/OIDC application. Supply the
#' instance URL and application slug, then pass the registered credentials
#' to [oauth_client()] with the scopes configured in authentik.
#'
#' @details
#' Uses authentik's default per-application issuer mode and preserves its
#' trailing slash. Global issuer mode is not supported by this preset;
#' configure the endpoints explicitly with [oauth_provider()] for that mode.
#' For refresh tokens, both request `"offline_access"` and enable the
#' corresponding scope mapping in authentik. Configure a signing key that
#' supports RS256 for OIDC discovery.
#' See [authentik's provider guide](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/).
#'
#' @param base_url authentik instance URL, for example `"https://auth.example.com"`.
#' @param application_slug Application slug configured in authentik (not the
#'   display name or client ID).
#' @param name Optional provider name (default `"authentik"`).
#' @inheritParams oauth_provider_oidc_discover
#' @return [OAuthProvider] object configured for the authentik application.
#' @examples
#' \dontrun{
#' oauth_provider_authentik("https://auth.example.com", "shiny-app")
#' }
#' @export
oauth_provider_authentik <- function(
  base_url,
  application_slug,
  name = "authentik",
  token_auth_style = NULL
) {
  if (!is_valid_string(base_url)) {
    err_input("base_url must be a non-empty string")
  }
  if (
    !is_valid_string(application_slug) ||
      !grepl("^[A-Za-z0-9_-]+$", application_slug)
  ) {
    err_input("application_slug must contain only letters, digits, '_' or '-'")
  }
  issuer <- paste0(
    rtrim_slash(base_url), "/application/o/", application_slug, "/"
  )
  oauth_provider_oidc_discover(
    issuer = issuer,
    name = name,
    token_auth_style = token_auth_style
  )
}
