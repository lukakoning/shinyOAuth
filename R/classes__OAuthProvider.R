# This file defines the OAuthProvider object that describes the remote OAuth or
# OpenID Connect server
# Used for keeping endpoint URLs, protocol rules, and security checks in one
# validated object

# 1 OAuth provider class -------------------------------------------------------

## 1.1 Class definition --------------------------------------------------------

#' OAuthProvider S7 class
#'
#' @description
#' S7 class describing an OAuth 2.0 or OpenID Connect provider.
#' It stores the provider's endpoints and the rules shinyOAuth should follow
#' during login, callback handling, token exchange, and optional OIDC checks.
#'
#' This is a low-level constructor intended for advanced use. Most users should
#' prefer the helper constructors [oauth_provider()] for generic OAuth 2.0
#' providers or [oauth_provider_oidc()] / [oauth_provider_oidc_discover()] for
#' OpenID Connect providers. Those helpers enable secure defaults based on the
#' presence of an issuer and available endpoints.
#'
#' @param name Provider name (e.g., "github", "google"). Cosmetic
#' only; used in logging and audit events
#'
#' @param auth_url Authorization endpoint URL
#' @param token_url Token endpoint URL
#' @param userinfo_url User info endpoint URL (optional)
#' @param introspection_url Token introspection endpoint URL (optional; RFC 7662)
#' @param revocation_url Token revocation endpoint URL (optional; RFC 7009)
#' @param par_url Optional Pushed Authorization Request (PAR) URL (RFC 9126).
#'   When set, shinyOAuth first sends the authorization request from server to
#'   provider and then redirects the browser with the returned `request_uri`
#'   handle instead of the full request payload. Most users only need this when
#'   their provider specifically supports or requires PAR.
#' @param require_pushed_authorization_requests Logical. Whether the provider
#'   requires authorization requests to be sent via PAR. When `TRUE`,
#'   `par_url` must also be configured.
#' @param authorization_request_front_channel_mode Character scalar controlling
#'   which browser-visible outer parameters shinyOAuth keeps when the actual
#'   authorization request is carried by JAR or PAR. Use `"compat"`
#'   (default) to keep the current OIDC-compatible shape with outer
#'   `client_id`, `response_type`, and `scope` when an issuer is configured.
#'   Use `"minimal"` for plain OAuth browser redirects and for PAR
#'   deployments whose authorization endpoint accepts only `client_id`
#'   plus the provider-issued `request_uri` handle. OpenID Connect
#'   by-value `request` and caller-managed `request_uri` transports reject
#'   `"minimal"` because OIDC still requires outer `response_type` and an
#'   outer `scope` containing `openid`.
#' @param request_object_signing_alg_values_supported Optional vector of JWS
#'   algorithms that the provider advertises for signed Request Objects (RFC
#'   9101). This is mainly used for early validation when an [OAuthClient]
#'   sends `authorization_request_mode = "request"` or
#'   `authorization_request_mode = "request_uri"`.
#' @param request_object_encryption_alg_values_supported Optional vector of JWE
#'   key-management algorithms that the provider advertises for encrypted
#'   Request Objects. This metadata is used for early validation when an
#'   [OAuthClient] enables Request Object encryption.
#' @param request_object_encryption_enc_values_supported Optional vector of JWE
#'   content-encryption algorithms that the provider advertises for encrypted
#'   Request Objects. This metadata is used for early validation when an
#'   [OAuthClient] enables Request Object encryption.
#' @param request_object_encryption_jwk Optional explicit recipient public key
#'   used to encrypt Request Objects when discovery-backed JWKS selection is not
#'   available or when you need to pin one specific encryption key. Accepts an
#'   OpenSSL public key, a PEM public-key string, a parsed JWK object, or a JWK
#'   JSON string.
#' @param require_signed_request_object Logical. Whether the provider requires
#'   signed Request Objects for authorization requests. When `TRUE`, clients
#'   should use `authorization_request_mode = "request"` or
#'   `authorization_request_mode = "request_uri"`.
#' @param request_parameter_supported Logical or `NA`. Whether discovery
#'   metadata explicitly advertises support for the authorization-request
#'   `request` parameter. `NA` means the provider did not say. Discovery-derived
#'   providers apply the OpenID Connect default (`FALSE`) when this metadata is
#'   omitted.
#' @param request_uri_parameter_supported Logical or `NA`. Whether discovery
#'   metadata explicitly advertises support for the authorization-request
#'   `request_uri` parameter for caller-managed request URIs. `NA` means the
#'   provider did not say. Discovery-derived providers apply the OpenID Connect
#'   default (`TRUE`) when this metadata is omitted. PAR-issued `request_uri`
#'   handles remain valid even when this metadata is `FALSE`.
#' @param require_request_uri_registration Logical or `NA`. Whether discovery
#'   metadata says caller-managed `request_uri` values must be pre-registered.
#'   `NA` means the provider did not say. Discovery-derived providers apply the
#'   OpenID Connect default (`FALSE`) when this metadata is omitted.
#'   shinyOAuth can publish caller-managed `request_uri` values through
#'   `oauth_module_server()`. When this is `TRUE`, make sure the provider has a
#'   matching public request URI or wildcard prefix registered for the client.
#'   shinyOAuth stores this metadata for caller awareness, but it cannot verify
#'   provider-side registration state automatically.
#' @param token_endpoint_auth_signing_alg_values_supported Optional vector of
#'   JWS algorithms that the provider advertises for JWT-based client
#'   authentication (`client_secret_jwt` / `private_key_jwt`) at the token
#'   endpoint. This metadata is used for early validation of
#'   `OAuthClient@client_assertion_alg` and inferred JWT client-assertion
#'   defaults.
#' @param dpop_signing_alg_values_supported Optional vector of JWS algorithms
#'   that the provider advertises for DPoP proof JWTs (RFC 9449). This
#'   metadata is used for early validation of `OAuthClient@dpop_signing_alg`
#'   and inferred outbound DPoP signing defaults.
#' @param authorization_response_iss_parameter_supported Logical. Whether the
#'   provider advertises RFC 9207 support for returning an `iss` parameter on
#'   the authorization response. When `TRUE`, the [oauth_client()] helper can
#'   auto-enable callback issuer enforcement when the caller leaves
#'   `enforce_callback_issuer` unset and the provider also has a configured
#'   `issuer`.
#' @param response_modes_supported Optional character vector of OAuth/OIDC
#'   `response_mode` values advertised by the provider. Discovery-backed
#'   providers use the discovery metadata value, defaulting to `c("query",
#'   "fragment")` when omitted per OIDC Discovery/RFC 8414. Generic providers
#'   may leave this empty when capabilities are not known. Provider metadata may
#'   include response modes that shinyOAuth does not implement, such as JARM
#'   values ending in `.jwt`; clients still fail fast if they request one of
#'   those unsupported modes.
#' @param mtls_endpoint_aliases Optional named list of RFC 8705 mTLS endpoint
#'   aliases. Names should follow the metadata keys such as `token_endpoint`,
#'   `userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`,
#'   `par_endpoint`, or `pushed_authorization_request_endpoint`, and values
#'   must be absolute URLs. This is an advanced setting used when a provider
#'   publishes separate mTLS-specific endpoints.
#' @param tls_client_certificate_bound_access_tokens Logical. Whether the
#'   authorization server advertises RFC 8705 capability to issue
#'   certificate-bound access tokens. This describes server capability; the
#'   client still has to opt into mTLS separately. When `TRUE`, token responses
#'   may include a `cnf` claim with an `x5t#S256` thumbprint that downstream
#'   requests must match with the same certificate.
#'
#' @param issuer Optional OIDC issuer URL. You need this when you want ID token
#'   validation. shinyOAuth uses it to verify the ID token `iss` claim and to
#'   locate the provider's signing keys (JWKS), typically through the OIDC
#'   discovery document at `/.well-known/openid-configuration`.
#' @param issuer_match Character scalar controlling how strictly the discovery
#' document's `issuer` is validated against `issuer` when it later
#' performs runtime discovery to locate the JWKS URI.
#'
#' - `"url"` (default): require the issuer used for discovery to match
#'   exactly, after removing one trailing slash for discovery URL construction.
#' - `"host"`: compare only scheme + host.
#' - `"none"`: do not validate discovery issuer consistency.
#'
#' In most cases, keep the default `"url"`. Use `"host"` only for providers
#' that publish tenant-independent metadata with a templated issuer, such as
#' some Microsoft aliases.
#'
#' @param use_nonce Whether to use OIDC nonce. This adds a `nonce` parameter to
#' the authorization request and validates the `nonce` claim in the ID token.
#' For OIDC providers, leaving this enabled is usually the right choice.
#' @param use_pkce Whether to use PKCE. This adds a `code_challenge` parameter to
#' the authorization request and requires a `code_verifier` when exchanging
#' the authorization code for tokens. This helps protect against authorization
#' code interception attacks.
#' @param pkce_method PKCE code challenge method ("S256" or "plain"). "S256" is
#' recommended. Use "plain" only if you are working with a provider that does
#' not support "S256".
#'
#' @param userinfo_required Whether to fetch userinfo after token exchange.
#' User information will be stored in the `userinfo` field of the returned
#' `OAuthToken` object. This requires a valid `userinfo_url` to be set.
#' If fetching userinfo fails, login fails.
#'
#' For the low-level constructor [oauth_provider()], when not explicitly
#' supplied, this is inferred from the presence of a non-empty `userinfo_url`:
#' if a `userinfo_url` is provided, `userinfo_required` defaults to `TRUE`,
#' otherwise it defaults to `FALSE`. This avoids unexpected validation errors
#' when `userinfo_url` is omitted (since it is optional).
#'
#' @param userinfo_id_token_match Whether to fail closed if UserInfo cannot be
#' bound to a validated ID token subject. Whenever both UserInfo and a
#' validated ID token are available, shinyOAuth compares the validated ID token
#' `sub` to the value returned by `userinfo_id_selector(userinfo)`. Setting
#' this field to `TRUE` additionally requires a validated ID token baseline
#' whenever UserInfo is fetched. This requires `userinfo_required`, a
#' configured `userinfo_id_selector`, plus either `id_token_validation` or
#' `use_nonce` to be `TRUE`.
#'
#' For [oauth_provider()], when not explicitly supplied, this is inferred as
#' `TRUE` when `userinfo_required` is `TRUE` and either
#' `id_token_validation` or `use_nonce` is `TRUE`; otherwise it defaults to
#' `FALSE`.
#'
#' @param userinfo_signed_jwt_required Whether to require that the userinfo
#' endpoint returns a signed JWT (`Content-Type: application/jwt`) whose
#' signature can be verified against the provider's JWKS. This is an advanced
#' hardening option. When `TRUE`:
#' \itemize{
#'   \item If the userinfo response is not `application/jwt`, authentication fails.
#'   \item If the JWT uses `alg=none` or an algorithm not in the asymmetric
#'     subset of `allowed_algs` (`RS*`, `ES*`, or `EdDSA`), authentication
#'     fails. `HS*` algorithms are not accepted for UserInfo JWTs on this
#'     surface even if they appear in `allowed_algs`.
#'   \item If signature verification fails (JWKS fetch error, no compatible keys,
#'     or invalid signature), authentication fails.
#' }
#' This prevents unsigned or weakly signed userinfo payloads from being treated
#' as trusted identity data. Requires `userinfo_required = TRUE` and a valid
#' `issuer` (for JWKS).
#' Defaults to `FALSE`.
#'
#' Note: `oauth_provider_oidc_discover()` does not auto-enable this flag.
#' Discovery's `userinfo_signing_alg_values_supported` indicates provider
#' capability, not that every client actually receives signed JWTs. Pass
#' `userinfo_signed_jwt_required = TRUE` explicitly if you need this behavior.
#'
#' @param userinfo_id_selector A function that extracts the user ID from the userinfo response.
#' Should take a single argument (the userinfo list) and return the user ID
#' as a string.
#'
#' This is used for helpers that need a provider-specific user identifier, such
#' as audit fields and UserInfo-to-ID-token subject matching. If you configure a
#' selector other than `function(x) x$sub`, that selector also defines which
#' UserInfo value is compared against the validated ID token `sub`. Helper
#' constructors like [oauth_provider()] and [oauth_provider_oidc()] provide a
#' default selector that extracts the `sub` field.
#'
#' @param id_token_required Whether to require an ID token to be returned
#' during token exchange. If no ID token is returned, the token exchange
#' will fail. This only makes sense for OpenID Connect providers and may
#' require the client's scope to include `openid`.
#'
#' Note: At the S7 class level, this defaults to FALSE so that pure OAuth 2.0
#' providers can be configured without OIDC. Helper constructors like
#' [oauth_provider()] and [oauth_provider_oidc()] will enable this when an
#' issuer is supplied or OIDC is explicitly requested.
#'
#' @param id_token_validation Whether to perform ID token validation after token exchange.
#' This requires the provider to be a valid OpenID Connect provider with a configured
#' `issuer` and the token response to include an ID token (may require setting
#' the client's scope to include `openid`).
#'
#' Note: At the S7 class level, this defaults to FALSE. Helper constructors like
#' [oauth_provider()] and [oauth_provider_oidc()] turn this on when an issuer
#' is provided or when OIDC is used.
#'
#' @param id_token_at_hash_required Whether to require the `at_hash` (Access Token hash)
#' claim in the ID token. When `TRUE`, login fails if the ID token does not
#' contain an `at_hash` claim or if the claim does not match the access token.
#' When `FALSE` (default), `at_hash` is validated only when present.
#' Requires `id_token_validation = TRUE`.
#'
#' @param extra_auth_params Extra parameters for authorization URL
#' @param extra_token_params Extra parameters for token exchange
#' @param extra_token_headers Extra headers for back-channel token-style
#'   requests (named character vector). shinyOAuth applies these headers to
#'   token exchange, refresh, introspection, revocation, and PAR requests.
#'   Use this only for headers you intentionally want on that full set of
#'   authorization-server calls.
#'
#' @param token_auth_style How the client authenticates at the token endpoint.
#'   One of:
#'   - "header": HTTP Basic (client_secret_basic)
#'   - "body": Form body (client_secret_post)
#'   - "public": Public-client form body (`none` in discovery metadata);
#'     sends `client_id` but never `client_secret`, even if one is configured.
#'     The alias `"none"` is also accepted.
#'   - "tls_client_auth": RFC 8705 mutual TLS client authentication using a
#'     client certificate chained to a trusted CA
#'   - "self_signed_tls_client_auth": RFC 8705 mutual TLS client
#'     authentication using a self-signed client certificate registered out of
#'     band with the provider
#'   - "client_secret_jwt": JWT client assertion signed with HMAC using client_secret
#'     (RFC 7523)
#'   - "private_key_jwt": JWT client assertion signed with an asymmetric key
#'     (RFC 7523)
#'
#' @param jwks_cache Cache used for the provider's signing keys (JWKS). If not
#'   provided, shinyOAuth creates an in-memory cache for 1 hour with
#'   `cachem::cache_mem(max_age = 3600)`. You can also use another
#'   cachem-compatible backend, including a shared cache created with
#'   [custom_cache()].
#'
#'   In most cases, a TTL between 15 minutes and 2 hours is reasonable. Shorter
#'   TTLs pick up new keys faster but do more network work; longer TTLs reduce
#'   traffic but may take longer to notice key rotation. If a new `kid` appears,
#'   shinyOAuth will also do a one-time refresh automatically.
#' @param jwks_pins Optional character vector of RFC 7638 JWK thumbprints
#'   (base64url) to pin against. If non-empty, fetched JWKS must contain keys
#'   whose thumbprints match these values depending on `jwks_pin_mode`.
#'   This is an advanced hardening option that lets you pre-authorize expected
#'   keys.
#' @param jwks_pin_mode Pinning policy when `jwks_pins` is provided. Either
#'   "any" (default; at least one key in JWKS must match) or "all" (every
#'   RSA/EC/OKP public key in JWKS must match one of the configured pins)
#' @param jwks_host_issuer_match When TRUE, enforce that the discovery `jwks_uri` host
#'   matches the issuer host exactly. Defaults to FALSE at the class
#'   level, but helper constructors for OIDC (e.g., [oauth_provider_oidc()] and
#'   [oauth_provider_oidc_discover()]) enable this by default for safer config.
#'   The generic helper [oauth_provider()] will also automatically set this to
#'   TRUE when an `issuer` is provided and either `id_token_validation` or
#'   `id_token_required` is TRUE (OIDC-like configuration). Set explicitly to
#'   FALSE to opt out. For providers that legitimately publish JWKS on a
#'   different host (for example Google), prefer setting
#'   `jwks_host_allow_only` to the exact hostname rather than disabling this
#'   check.
#' @param jwks_host_allow_only Optional explicit hostname that the jwks_uri must match.
#'   When provided, jwks_uri host must equal this value (exact match). You can
#'   pass either just the host (e.g., "www.googleapis.com") or a full URL; only
#'   the host component will be used. If you need to include a port or an IPv6
#'   literal, pass a full URL (e.g., \verb{https://[::1]:8443}) - the port is ignored
#'   and only the hostname part is used for matching. Takes precedence over
#'   `jwks_host_issuer_match`.
#'
#' @param allowed_algs Optional vector of allowed JWT algorithms for ID tokens.
#'   Use to restrict acceptable `alg` values on a per-provider basis. Supported
#'   asymmetric algorithms include `RS256`, `RS384`, `RS512`, `ES256`,
#'   `ES384`, `ES512`, and `EdDSA` for OKP-backed signatures. When ID token
#'   `at_hash` validation is in play, Ed25519 is supported. Ed448 `at_hash`
#'   cannot be validated with the current crypto bindings, so shinyOAuth skips
#'   that optional check unless `id_token_at_hash_required = TRUE`, in which
#'   case Ed448 ID tokens fail fast.
#'   Symmetric HMAC algorithms `HS256`, `HS384`, `HS512` are also supported but
#'   require that you supply a `client_secret` and explicitly enable HMAC
#'   verification via the option `options(shinyOAuth.allow_hs = TRUE)`.
#'   Defaults to `c("RS256","RS384","RS512","ES256","ES384","ES512","EdDSA")`,
#'   which intentionally excludes HS*.
#'   Only include `HS*` if you are certain the `client_secret` is stored strictly
#'   server-side and is never shipped to, or derivable by, the browser or other
#'   untrusted environments.
#' @param allowed_token_types Character vector of acceptable OAuth token types
#'   returned by the token endpoint (case-insensitive). Successful token
#'   responses must always include `token_type`; when `allowed_token_types` is
#'   non-empty, its value must also be one of the allowed values or the flow
#'   fails fast with a `shinyOAuth_token_error`. The [oauth_provider()] helper
#'   defaults to `c("Bearer")`. When the [OAuthClient] is configured with
#'   `dpop_private_key`, shinyOAuth also accepts `token_type = "DPoP"` and uses
#'   DPoP proofs on supported token and downstream requests. Other non-Bearer
#'   token types (for example `MAC`) still fail fast rather than being misused.
#'   Set `allowed_token_types = character()` explicitly only to disable the
#'   value allowlist while still requiring `token_type` itself.
#'
#' @param leeway Clock skew leeway (seconds) applied to ID token `exp`/`iat`/`nbf` checks
#'   and state payload `issued_at` future check. Default 30. Can be globally
#'   overridden via option `shinyOAuth.leeway`.
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
OAuthProvider <- S7::new_class(
  "OAuthProvider",
  package = "shinyOAuth",
  properties = list(
    name = S7::class_character,
    auth_url = S7::class_character,
    token_url = S7::class_character,
    userinfo_url = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    introspection_url = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    revocation_url = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    par_url = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    require_pushed_authorization_requests = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    authorization_request_front_channel_mode = S7::new_property(
      S7::class_character,
      default = "compat"
    ),
    request_object_signing_alg_values_supported = S7::new_property(
      S7::class_character,
      default = character()
    ),
    request_object_encryption_alg_values_supported = S7::new_property(
      S7::class_character,
      default = character()
    ),
    request_object_encryption_enc_values_supported = S7::new_property(
      S7::class_character,
      default = character()
    ),
    request_object_encryption_jwk = S7::new_property(
      S7::class_any,
      default = NULL
    ),
    require_signed_request_object = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    request_parameter_supported = S7::new_property(
      S7::class_logical,
      default = NA
    ),
    request_uri_parameter_supported = S7::new_property(
      S7::class_logical,
      default = NA
    ),
    require_request_uri_registration = S7::new_property(
      S7::class_logical,
      default = NA
    ),
    token_endpoint_auth_signing_alg_values_supported = S7::new_property(
      S7::class_character,
      default = character()
    ),
    dpop_signing_alg_values_supported = S7::new_property(
      S7::class_character,
      default = character()
    ),
    authorization_response_iss_parameter_supported = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    response_modes_supported = S7::new_property(
      S7::class_character,
      default = character()
    ),
    issuer = S7::new_property(S7::class_character, default = NA_character_),
    issuer_match = S7::new_property(
      S7::class_character,
      default = "url"
    ),
    use_nonce = S7::new_property(S7::class_logical, default = FALSE),
    use_pkce = S7::new_property(S7::class_logical, default = TRUE),
    pkce_method = S7::new_property(S7::class_character, default = "S256"),
    userinfo_required = S7::new_property(S7::class_logical, default = FALSE),
    userinfo_id_selector = S7::new_property(
      S7::class_any,
      default = quote(function(userinfo) userinfo$sub)
    ),
    userinfo_id_token_match = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    userinfo_signed_jwt_required = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    id_token_required = S7::new_property(S7::class_logical, default = FALSE),
    id_token_validation = S7::new_property(S7::class_logical, default = FALSE),
    id_token_at_hash_required = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    extra_auth_params = S7::class_list,
    extra_token_params = S7::class_list,
    extra_token_headers = S7::new_property(
      S7::class_character,
      default = character()
    ),
    mtls_endpoint_aliases = S7::new_property(
      S7::class_list,
      default = list()
    ),
    tls_client_certificate_bound_access_tokens = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    token_auth_style = S7::new_property(
      S7::class_character,
      default = "header"
    ),
    jwks_cache = S7::new_property(
      S7::class_any,
      default = quote(cachem::cache_mem(max_age = 3600))
    ),
    jwks_pins = S7::new_property(S7::class_character, default = character()),
    jwks_pin_mode = S7::new_property(S7::class_character, default = "any"),
    jwks_host_issuer_match = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    # Use NA_character_ instead of NULL so the property always respects
    # the declared character type; constructors normalize to a hostname or NA
    jwks_host_allow_only = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    allowed_algs = S7::new_property(
      S7::class_character,
      default = c(
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA"
      )
    ),
    allowed_token_types = S7::new_property(
      S7::class_character,
      default = c("Bearer")
    ),
    leeway = S7::new_property(
      S7::class_numeric,
      default = quote(getOption(
        "shinyOAuth.leeway",
        30
      ))
    )
  ),
  validator = function(self) oauth_provider_validate(self)
)

# 2 Generic provider constructor -----------------------------------------------

#' Normalize optional provider boolean metadata
#'
#' Used by [oauth_provider()] when callers or discovery wire through provider
#' capability flags where omitted metadata must remain distinguishable from
#' explicit `FALSE`.
#'
#' @param value Candidate logical value.
#' @param field Field name used in validation errors.
#' @return Scalar logical or `NA` when the metadata is unspecified.
#' @keywords internal
#' @noRd
normalize_optional_provider_boolean <- function(value, field) {
  if (is.null(value)) {
    return(NA)
  }
  if (!is.logical(value) || length(value) != 1L) {
    err_input(paste0(
      "OAuthProvider: ",
      field,
      " must be a scalar logical or NA"
    ))
  }
  if (is.na(value)) {
    return(NA)
  }

  value
}

#' Create generic [OAuthProvider]
#'
#' Helper to create an [OAuthProvider] object with sensible defaults.
#' It is the main user-facing constructor for generic providers and is also
#' used by the built-in provider helpers.
#'
#' @inheritParams OAuthProvider
#'
#' @return [OAuthProvider] object
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider <- function(
  name,
  auth_url,
  token_url,
  userinfo_url = NA_character_,
  introspection_url = NA_character_,
  revocation_url = NA_character_,
  par_url = NA_character_,
  require_pushed_authorization_requests = FALSE,
  authorization_request_front_channel_mode = "compat",
  request_object_signing_alg_values_supported = character(),
  request_object_encryption_alg_values_supported = character(),
  request_object_encryption_enc_values_supported = character(),
  request_object_encryption_jwk = NULL,
  require_signed_request_object = FALSE,
  request_parameter_supported = NA,
  request_uri_parameter_supported = NA,
  require_request_uri_registration = NA,
  token_endpoint_auth_signing_alg_values_supported = character(),
  dpop_signing_alg_values_supported = character(),
  authorization_response_iss_parameter_supported = FALSE,
  response_modes_supported = character(),
  mtls_endpoint_aliases = list(),
  tls_client_certificate_bound_access_tokens = FALSE,
  issuer = NA_character_,
  issuer_match = "url",
  use_nonce = NULL,
  use_pkce = TRUE,
  pkce_method = "S256",
  userinfo_required = NULL,
  userinfo_id_token_match = NULL,
  userinfo_signed_jwt_required = FALSE,
  userinfo_id_selector = function(userinfo) userinfo$sub,
  id_token_required = NULL,
  id_token_validation = NULL,
  extra_auth_params = list(),
  extra_token_params = list(),
  extra_token_headers = character(),
  token_auth_style = "header",
  jwks_cache = NULL,
  jwks_pins = character(),
  jwks_pin_mode = "any",
  jwks_host_issuer_match = NULL,
  jwks_host_allow_only = NULL,
  allowed_algs = c(
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA"
  ),
  allowed_token_types = c("Bearer"),
  leeway = getOption("shinyOAuth.leeway", 30),
  id_token_at_hash_required = FALSE
) {
  # Validate scalar URL inputs before normalization to prevent cryptic
  # coercion errors from normalize_url() when callers pass vectors.
  for (url_arg in list(
    list("auth_url", auth_url),
    list("token_url", token_url),
    list("userinfo_url", userinfo_url),
    list("introspection_url", introspection_url),
    list("revocation_url", revocation_url),
    list("par_url", par_url)
  )) {
    u_val <- url_arg[[2]]
    if (!is.null(u_val) && (!is.character(u_val) || length(u_val) != 1L)) {
      err_input(paste0(
        "OAuthProvider: ",
        url_arg[[1]],
        " must be a scalar character string (length 1), not length ",
        length(u_val)
      ))
    }
  }

  # Use shared internal helper to normalize only the path component
  auth_url <- normalize_url(auth_url)
  token_url <- normalize_url(token_url)
  userinfo_url <- normalize_url(userinfo_url)
  introspection_url <- normalize_url(introspection_url)
  revocation_url <- normalize_url(revocation_url)
  par_url <- normalize_url(par_url)

  if (is.null(request_object_signing_alg_values_supported)) {
    request_object_signing_alg_values_supported <- character()
  }
  request_object_signing_alg_values_supported <- toupper(as.character(
    unlist(request_object_signing_alg_values_supported, use.names = FALSE)
  ))
  if (is.null(request_object_encryption_alg_values_supported)) {
    request_object_encryption_alg_values_supported <- character()
  }
  request_object_encryption_alg_values_supported <- toupper(as.character(
    unlist(
      request_object_encryption_alg_values_supported,
      use.names = FALSE
    )
  ))
  if (is.null(request_object_encryption_enc_values_supported)) {
    request_object_encryption_enc_values_supported <- character()
  }
  request_object_encryption_enc_values_supported <- toupper(as.character(
    unlist(
      request_object_encryption_enc_values_supported,
      use.names = FALSE
    )
  ))
  if (is.null(response_modes_supported)) {
    response_modes_supported <- character()
  }
  response_modes_supported <- tolower(trimws(as.character(
    unlist(response_modes_supported, use.names = FALSE)
  )))
  request_parameter_supported <- normalize_optional_provider_boolean(
    request_parameter_supported,
    "request_parameter_supported"
  )
  request_uri_parameter_supported <- normalize_optional_provider_boolean(
    request_uri_parameter_supported,
    "request_uri_parameter_supported"
  )
  require_request_uri_registration <- normalize_optional_provider_boolean(
    require_request_uri_registration,
    "require_request_uri_registration"
  )
  if (is.null(token_endpoint_auth_signing_alg_values_supported)) {
    token_endpoint_auth_signing_alg_values_supported <- character()
  }
  token_endpoint_auth_signing_alg_values_supported <- toupper(as.character(
    unlist(
      token_endpoint_auth_signing_alg_values_supported,
      use.names = FALSE
    )
  ))
  if (is.null(dpop_signing_alg_values_supported)) {
    dpop_signing_alg_values_supported <- character()
  }
  dpop_signing_alg_values_supported <- toupper(as.character(
    unlist(
      dpop_signing_alg_values_supported,
      use.names = FALSE
    )
  ))
  if (is.null(mtls_endpoint_aliases)) {
    mtls_endpoint_aliases <- list()
  }
  if (!is.list(mtls_endpoint_aliases)) {
    mtls_endpoint_aliases <- as.list(mtls_endpoint_aliases)
  }
  if (length(mtls_endpoint_aliases) > 0) {
    mtls_endpoint_aliases <- lapply(mtls_endpoint_aliases, function(value) {
      if (
        is.character(value) &&
          length(value) == 1L &&
          !is.na(value) &&
          nzchar(value)
      ) {
        return(normalize_url(value))
      }
      value
    })
  }

  if (is.null(jwks_cache)) {
    jwks_cache <- cachem::cache_mem(max_age = 3600)
  }

  # Normalize pkce_method (be tolerant of NULL/NA and case)
  if (
    !is.null(pkce_method) &&
      (!is.character(pkce_method) || length(pkce_method) != 1L)
  ) {
    err_input(paste0(
      "OAuthProvider: pkce_method must be a scalar character string (length 1), not length ",
      length(pkce_method)
    ))
  }
  if (is.null(pkce_method) || is.na(pkce_method)) {
    pkce_method <- "S256"
  }
  pkce_method <- normalize_pkce_method(pkce_method, default = "S256")
  issuer_match <- match.arg(
    issuer_match,
    choices = c("url", "host", "none")
  )
  authorization_request_front_channel_mode <- match.arg(
    authorization_request_front_channel_mode,
    choices = c("compat", "minimal")
  )
  token_auth_style <- normalize_token_auth_style(token_auth_style)

  # Normalize and validate allowed_algs
  if (is.null(allowed_algs)) {
    allowed_algs <- c(
      "RS256",
      "RS384",
      "RS512",
      "ES256",
      "ES384",
      "ES512",
      "EdDSA"
    )
  }
  allowed_algs <- toupper(allowed_algs)

  # Normalize jwks_host_allow_only: allow either hostname or full URL; store hostname only
  if (is_valid_string(jwks_host_allow_only)) {
    jh <- trimws(jwks_host_allow_only)
    if (grepl("^https?://", tolower(jh))) {
      jh <- parse_url_host(jh, "jwks_host_allow_only")
    } else {
      jh <- tolower(sub("\\.$", "", jh))
    }
    jwks_host_allow_only <- jh
  } else {
    jwks_host_allow_only <- NA_character_
  }

  # If issuer is present, then set sensible defaults for nonce/id_token flags
  has_issuer <- is_valid_string(issuer)
  if (is.null(use_nonce)) {
    use_nonce <- if (has_issuer) TRUE else FALSE
  }
  if (is.null(id_token_required)) {
    id_token_required <- if (has_issuer) TRUE else FALSE
  }
  if (is.null(id_token_validation)) {
    id_token_validation <- if (has_issuer) TRUE else FALSE
  }

  # Auto-enable JWKS issuer-host match for OIDC-like configurations unless explicitly set
  if (is.null(jwks_host_issuer_match)) {
    jwks_host_issuer_match <- has_issuer &&
      (isTRUE(id_token_validation) || isTRUE(id_token_required))
  }

  # Default to Bearer for all providers. If an OAuthClient later enables DPoP
  # via dpop_private_key, shinyOAuth also accepts token_type = DPoP
  # automatically; other non-Bearer token types still fail fast rather than
  # being misused. Set allowed_token_types = character() to disable the value
  # allowlist while still requiring token_type.
  if (is.null(allowed_token_types)) {
    allowed_token_types <- c("Bearer")
  }

  # Gentle host configuration reminder:
  # In non-interactive (server) sessions, if no global host allowlist is set
  # and the provider is configured with OIDC features (issuer present or
  # ID token validation/requirement enabled), emit a once-per-session warning
  # pointing operators to host hardening guidance. Suppressed during tests.
  if (
    !.is_interactive() &&
      !.is_test() &&
      (has_issuer || isTRUE(id_token_required) || isTRUE(id_token_validation))
  ) {
    allowed_hosts_opt <- getOption("shinyOAuth.allowed_hosts", NULL)
    if (is.null(allowed_hosts_opt) || length(allowed_hosts_opt) == 0) {
      warn_pkg(
        "Configure allowed hosts for production",
        c(
          "!" = paste0(
            "No host allowlist configured via ",
            "{.code options(shinyOAuth.allowed_hosts = c(\".example.com\", \"api.example.com\"))}."
          ),
          "i" = "Restricting hosts hardens redirect and API endpoint validation.",
          "i" = "See {.code ?is_ok_host} for policy details and review the 'authentication-flow' vignette"
        ),
        .frequency = "once",
        .frequency_id = "allowed_hosts_config_reminder"
      )
    }
  }

  # Infer sensible defaults for userinfo-related flags when not provided
  has_ui <- is_valid_string(userinfo_url) && is_ok_host(userinfo_url)
  if (is.null(userinfo_required)) {
    userinfo_required <- isTRUE(has_ui)
  }
  if (is.null(userinfo_id_token_match)) {
    userinfo_id_token_match <- isTRUE(userinfo_required) &&
      (isTRUE(id_token_validation) || isTRUE(use_nonce))
  }

  OAuthProvider(
    name = name,
    auth_url = auth_url,
    token_url = token_url,
    userinfo_url = userinfo_url,
    introspection_url = introspection_url,
    revocation_url = revocation_url,
    par_url = par_url,
    require_pushed_authorization_requests = isTRUE(
      require_pushed_authorization_requests
    ),
    authorization_request_front_channel_mode = authorization_request_front_channel_mode,
    request_object_signing_alg_values_supported = request_object_signing_alg_values_supported,
    request_object_encryption_alg_values_supported = request_object_encryption_alg_values_supported,
    request_object_encryption_enc_values_supported = request_object_encryption_enc_values_supported,
    request_object_encryption_jwk = request_object_encryption_jwk,
    require_signed_request_object = isTRUE(require_signed_request_object),
    request_parameter_supported = request_parameter_supported,
    request_uri_parameter_supported = request_uri_parameter_supported,
    require_request_uri_registration = require_request_uri_registration,
    token_endpoint_auth_signing_alg_values_supported = token_endpoint_auth_signing_alg_values_supported,
    dpop_signing_alg_values_supported = dpop_signing_alg_values_supported,
    authorization_response_iss_parameter_supported = isTRUE(
      authorization_response_iss_parameter_supported
    ),
    response_modes_supported = response_modes_supported,
    issuer = issuer,
    issuer_match = issuer_match,
    use_nonce = use_nonce,
    use_pkce = use_pkce,
    pkce_method = pkce_method,
    userinfo_required = userinfo_required,
    id_token_required = id_token_required,
    id_token_validation = id_token_validation,
    userinfo_id_token_match = userinfo_id_token_match,
    userinfo_signed_jwt_required = isTRUE(userinfo_signed_jwt_required),
    userinfo_id_selector = userinfo_id_selector,
    extra_auth_params = extra_auth_params,
    extra_token_params = extra_token_params,
    extra_token_headers = extra_token_headers,
    mtls_endpoint_aliases = mtls_endpoint_aliases,
    tls_client_certificate_bound_access_tokens = isTRUE(
      tls_client_certificate_bound_access_tokens
    ),
    token_auth_style = token_auth_style,
    jwks_cache = jwks_cache,
    jwks_pins = jwks_pins,
    jwks_pin_mode = jwks_pin_mode,
    jwks_host_issuer_match = isTRUE(jwks_host_issuer_match),
    jwks_host_allow_only = jwks_host_allow_only,
    allowed_algs = allowed_algs,
    allowed_token_types = allowed_token_types,
    leeway = leeway,
    id_token_at_hash_required = id_token_at_hash_required
  )
}
# 3 Provider helpers -----------------------------------------------------------

## 3.1 Provider validation -----------------------------------------------------

#' Internal: validate one OAuthProvider configuration
#'
#' Used by the [OAuthProvider] S7 class before the rest of the package builds
#' authorization URLs, performs discovery, fetches JWKS, or exchanges tokens.
#'
#' @param self [OAuthProvider] instance under validation.
#' @return `NULL` for a valid provider, otherwise a length-1 validation error
#'   string.
#' @keywords internal
#' @noRd
oauth_provider_validate <- function(self) {
  # Reuse for all properties (required vs optional mirrors your S7 defs)
  fields <- list(
    auth_url = list(val = self@auth_url, required = TRUE),
    token_url = list(val = self@token_url, required = TRUE),
    userinfo_url = list(val = self@userinfo_url, required = FALSE),
    introspection_url = list(val = self@introspection_url, required = FALSE),
    revocation_url = list(val = self@revocation_url, required = FALSE),
    par_url = list(
      val = self@par_url,
      required = FALSE
    ),
    issuer = list(val = self@issuer, required = FALSE)
  )
  for (nm in names(fields)) {
    f <- fields[[nm]]
    msg <- oauth_provider_check_host_field(f$val, nm, f$required)
    if (!is.null(msg)) {
      return(msg)
    }
  }

  # OIDC issuer identifiers must not contain query or fragment components
  if (is_valid_string(self@issuer)) {
    parsed_issuer <- try(httr2::url_parse(self@issuer), silent = TRUE)
    if (
      !inherits(parsed_issuer, "try-error") &&
        (length(parsed_issuer$query) > 0L ||
          nzchar(parsed_issuer$fragment %||% ""))
    ) {
      return(
        "OAuthProvider: issuer must not contain query or fragment components"
      )
    }
  }

  if (!isTRUE(self@issuer_match %in% c("url", "host", "none"))) {
    return("OAuthProvider: issuer_match must be 'url', 'host', or 'none'")
  }

  # Validate extra_token_headers: must be named character vector of length n
  # with all non-empty names and scalar (length-1) character values.
  if (length(self@extra_token_headers) > 0) {
    eth <- self@extra_token_headers
    if (!is.character(eth)) {
      return(
        "OAuthProvider: extra_token_headers must be a named character vector"
      )
    }
    nms <- names(eth)
    if (is.null(nms) || !all(nzchar(nms))) {
      return(
        "OAuthProvider: extra_token_headers must have non-empty names for all headers"
      )
    }

    default_reserved_headers <- c("authorization", "cookie")
    unblocked <- tolower(getOption(
      "shinyOAuth.unblock_token_headers",
      character()
    ))
    reserved_header_names <- setdiff(default_reserved_headers, unblocked)
    bad_headers <- intersect(tolower(trimws(nms)), reserved_header_names)
    if (length(bad_headers) > 0) {
      return(sprintf(
        paste0(
          "OAuthProvider: extra_token_headers must not contain reserved headers: %s. ",
          "To unblock, set `options(shinyOAuth.unblock_token_headers = c(...))`"
        ),
        paste(sQuote(bad_headers), collapse = ", ")
      ))
    }

    bad_len <- lengths(eth) != 1L
    if (any(bad_len)) {
      return("OAuthProvider: each extra_token_headers value must be length 1")
    }
    if (any(is.na(eth) | !nzchar(eth))) {
      return(
        "OAuthProvider: extra_token_headers values must be non-empty strings"
      )
    }
  }

  if (length(self@mtls_endpoint_aliases) > 0) {
    aliases <- self@mtls_endpoint_aliases
    if (!is.list(aliases)) {
      return("OAuthProvider: mtls_endpoint_aliases must be a named list")
    }
    alias_names <- names(aliases)
    if (is.null(alias_names) || !all(nzchar(alias_names))) {
      return(
        "OAuthProvider: mtls_endpoint_aliases must have non-empty names for all aliases"
      )
    }

    for (alias_name in alias_names) {
      alias_value <- aliases[[alias_name]]
      if (!is_valid_string(alias_value)) {
        return(sprintf(
          "OAuthProvider: mtls_endpoint_aliases$%s must be a non-empty string",
          alias_name
        ))
      }

      msg <- oauth_provider_check_host_field(
        alias_value,
        paste0("mtls_endpoint_aliases$", alias_name),
        required = TRUE
      )
      if (!is.null(msg)) {
        return(msg)
      }
    }
  }

  if (
    !(is.logical(self@tls_client_certificate_bound_access_tokens) &&
      length(self@tls_client_certificate_bound_access_tokens) == 1L &&
      !is.na(self@tls_client_certificate_bound_access_tokens))
  ) {
    return(
      paste(
        "OAuthProvider: tls_client_certificate_bound_access_tokens",
        "must be a single non-NA logical"
      )
    )
  }

  if (length(self@extra_auth_params) > 0) {
    nms <- names(self@extra_auth_params)
    if (is.null(nms) || !all(nzchar(nms))) {
      return(
        "OAuthProvider: extra_auth_params must be a named list (all elements must have names)"
      )
    }
  }

  response_mode_info <- inspect_auth_response_mode(self@extra_auth_params)
  if (!is.null(response_mode_info$error)) {
    return(response_mode_info$error)
  }
  if (!is.character(self@response_modes_supported)) {
    return("OAuthProvider: response_modes_supported must be a character vector")
  }
  if (
    length(self@response_modes_supported) > 0 &&
      any(
        !nzchar(self@response_modes_supported) |
          is.na(self@response_modes_supported)
      )
  ) {
    return(
      "OAuthProvider: response_modes_supported must contain only non-empty strings"
    )
  }
  if (
    !is.null(response_mode_info$mode) &&
      length(self@response_modes_supported) > 0 &&
      !response_mode_info$mode %in% self@response_modes_supported
  ) {
    return(paste0(
      "OAuthProvider: extra_auth_params$response_mode = ",
      sQuote(response_mode_info$mode),
      " is not advertised in response_modes_supported"
    ))
  }

  max_age_info <- inspect_auth_max_age(self@extra_auth_params)
  if (!is.null(max_age_info$error)) {
    return(max_age_info$error)
  }

  default_reserved_auth_keys <- c(
    "response_type",
    "client_id",
    "redirect_uri",
    "request_uri",
    "request",
    "state",
    "scope",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims"
  )
  unblocked_auth <- tolower(trimws(getOption(
    "shinyOAuth.unblock_auth_params",
    character()
  )))
  reserved_auth_keys <- setdiff(default_reserved_auth_keys, unblocked_auth)
  if (length(self@extra_auth_params) > 0) {
    nms <- tolower(trimws(names(self@extra_auth_params)))
    bad <- intersect(nms, reserved_auth_keys)
    if (length(bad) > 0) {
      return(sprintf(
        paste0(
          "OAuthProvider: extra_auth_params must not contain reserved keys managed by shinyOAuth: %s. ",
          "To unblock, set options(shinyOAuth.unblock_auth_params = c(...))"
        ),
        paste(sQuote(bad), collapse = ", ")
      ))
    }
  }

  if (length(self@extra_token_params) > 0) {
    nms <- names(self@extra_token_params)
    if (is.null(nms) || !all(nzchar(nms))) {
      return(
        "OAuthProvider: extra_token_params must be a named list (all elements must have names)"
      )
    }
  }

  default_reserved_token_keys <- c(
    "grant_type",
    "code",
    "refresh_token",
    "redirect_uri",
    "code_verifier",
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type"
  )
  unblocked_token <- tolower(trimws(getOption(
    "shinyOAuth.unblock_token_params",
    character()
  )))
  reserved_token_keys <- setdiff(default_reserved_token_keys, unblocked_token)
  if (length(self@extra_token_params) > 0) {
    nms <- tolower(trimws(names(self@extra_token_params)))
    bad <- intersect(nms, reserved_token_keys)
    if (length(bad) > 0) {
      return(sprintf(
        paste0(
          "OAuthProvider: extra_token_params must not contain reserved keys managed by shinyOAuth: %s. ",
          "To unblock, set options(shinyOAuth.unblock_token_params = c(...))"
        ),
        paste(sQuote(bad), collapse = ", ")
      ))
    }
  }

  tok_style <- normalize_token_auth_style(self@token_auth_style)
  if (
    !isTRUE(
      tok_style %in%
        c(
          "header",
          "body",
          "public",
          "tls_client_auth",
          "self_signed_tls_client_auth",
          "client_secret_jwt",
          "private_key_jwt"
        )
    )
  ) {
    return(paste0(
      "OAuthProvider: token_auth_style must be one of 'header', 'body', 'public', ",
      "'tls_client_auth', 'self_signed_tls_client_auth', 'client_secret_jwt', or 'private_key_jwt' ('none' is accepted as an alias for 'public')"
    ))
  }

  if (!is.null(self@pkce_method)) {
    if (!isTRUE(self@pkce_method %in% c("S256", "plain"))) {
      return("OAuthProvider: pkce_method must be 'S256' or 'plain'")
    }
  }

  has_get <- !is.null(self@jwks_cache$get) &&
    is.function(self@jwks_cache$get)
  has_set <- !is.null(self@jwks_cache$set) &&
    is.function(self@jwks_cache$set)
  if (!isTRUE(has_get && has_set)) {
    return(
      paste(
        "OAuthProvider: jwks_cache must provide $get(key, missing=NULL) and",
        "$set(key, value) methods"
      )
    )
  }
  jget_formals <- try(formals(self@jwks_cache$get), silent = TRUE)
  jget_args <- if (!inherits(jget_formals, "try-error")) {
    names(jget_formals)
  } else {
    character()
  }
  if (!("..." %in% jget_args || "missing" %in% jget_args)) {
    return(
      "OAuthProvider: jwks_cache$get must accept argument 'missing' (expected signature get(key, missing = NULL))"
    )
  }
  jset_formals <- try(formals(self@jwks_cache$set), silent = TRUE)
  jset_args <- if (!inherits(jset_formals, "try-error")) {
    names(jset_formals)
  } else {
    character()
  }
  if (
    !("..." %in% jset_args || ("key" %in% jset_args && "value" %in% jset_args))
  ) {
    return("OAuthProvider: jwks_cache$set must accept (key, value)")
  }
  if (!is.null(self@jwks_cache$remove) && is.function(self@jwks_cache$remove)) {
    jrm_formals <- try(formals(self@jwks_cache$remove), silent = TRUE)
    jrm_args <- if (!inherits(jrm_formals, "try-error")) {
      names(jrm_formals)
    } else {
      character()
    }
    if (!("..." %in% jrm_args || length(jrm_args) >= 1L)) {
      return(
        "OAuthProvider: jwks_cache$remove must accept (key) when provided"
      )
    }
  }

  if (!isTRUE(self@jwks_pin_mode %in% c("any", "all"))) {
    return("OAuthProvider: jwks_pin_mode must be 'any' or 'all'")
  }
  if (length(self@jwks_pins) > 0) {
    ok <- vapply(
      self@jwks_pins,
      function(x) {
        is.character(x) && length(x) == 1 && grepl("^[A-Za-z0-9_-]+$", x)
      },
      logical(1)
    )
    if (!all(ok)) {
      return("OAuthProvider: jwks_pins must be base64url strings")
    }
  }

  if (length(self@allowed_algs) > 0) {
    supported <- c(
      "RS256",
      "RS384",
      "RS512",
      "ES256",
      "ES384",
      "ES512",
      "EDDSA",
      "HS256",
      "HS384",
      "HS512"
    )
    aa <- toupper(self@allowed_algs)
    bad <- setdiff(aa, supported)
    if (length(bad) > 0) {
      return(paste0(
        "OAuthProvider: allowed_algs contains unsupported entries: ",
        paste(bad, collapse = ", ")
      ))
    }

    if (any(aa %in% c("HS256", "HS384", "HS512"))) {
      allow_hs <- isTRUE(getOption("shinyOAuth.allow_hs", FALSE))
      if (!allow_hs) {
        return(
          "OAuthProvider: allowed_algs includes HS* but `options(shinyOAuth.allow_hs = TRUE)` is not enabled"
        )
      }
    }
  }

  if (
    !(is.logical(self@require_pushed_authorization_requests) &&
      length(self@require_pushed_authorization_requests) == 1L &&
      !is.na(self@require_pushed_authorization_requests))
  ) {
    return(
      paste(
        "OAuthProvider: require_pushed_authorization_requests",
        "must be a single non-NA logical"
      )
    )
  }
  if (
    isTRUE(self@require_pushed_authorization_requests) &&
      !is_valid_string(self@par_url %||% NA_character_)
  ) {
    return(
      paste(
        "OAuthProvider: require_pushed_authorization_requests = TRUE",
        "requires par_url"
      )
    )
  }
  if (
    !(is.character(self@authorization_request_front_channel_mode) &&
      length(self@authorization_request_front_channel_mode) == 1L &&
      !is.na(self@authorization_request_front_channel_mode) &&
      self@authorization_request_front_channel_mode %in% c("compat", "minimal"))
  ) {
    return(
      paste(
        "OAuthProvider: authorization_request_front_channel_mode",
        "must be one of 'compat' or 'minimal'"
      )
    )
  }

  for (field in c(
    "request_parameter_supported",
    "request_uri_parameter_supported",
    "require_request_uri_registration"
  )) {
    value <- S7::prop(self, field)
    if (!(is.logical(value) && length(value) == 1L)) {
      return(paste0(
        "OAuthProvider: ",
        field,
        " must be a scalar logical or NA"
      ))
    }
  }

  if (
    identical(self@request_uri_parameter_supported, FALSE) &&
      isTRUE(self@require_request_uri_registration)
  ) {
    return(
      paste(
        "OAuthProvider: request_uri_parameter_supported = FALSE",
        "is inconsistent with require_request_uri_registration = TRUE"
      )
    )
  }

  request_object_algs <- self@request_object_signing_alg_values_supported
  if (length(request_object_algs) > 0) {
    if (!is.character(request_object_algs)) {
      return(
        paste(
          "OAuthProvider: request_object_signing_alg_values_supported",
          "must be a character vector"
        )
      )
    }
    if (anyNA(request_object_algs) || !all(nzchar(request_object_algs))) {
      return(
        paste(
          "OAuthProvider: request_object_signing_alg_values_supported",
          "must contain only non-empty strings"
        )
      )
    }
  }

  request_object_encryption_algs <-
    self@request_object_encryption_alg_values_supported
  if (length(request_object_encryption_algs) > 0) {
    if (!is.character(request_object_encryption_algs)) {
      return(
        paste(
          "OAuthProvider: request_object_encryption_alg_values_supported",
          "must be a character vector"
        )
      )
    }
    if (
      anyNA(request_object_encryption_algs) ||
        !all(nzchar(request_object_encryption_algs))
    ) {
      return(
        paste(
          "OAuthProvider: request_object_encryption_alg_values_supported",
          "must contain only non-empty strings"
        )
      )
    }
  }

  request_object_encryption_encs <-
    self@request_object_encryption_enc_values_supported
  if (length(request_object_encryption_encs) > 0) {
    if (!is.character(request_object_encryption_encs)) {
      return(
        paste(
          "OAuthProvider: request_object_encryption_enc_values_supported",
          "must be a character vector"
        )
      )
    }
    if (
      anyNA(request_object_encryption_encs) ||
        !all(nzchar(request_object_encryption_encs))
    ) {
      return(
        paste(
          "OAuthProvider: request_object_encryption_enc_values_supported",
          "must contain only non-empty strings"
        )
      )
    }
  }

  if (!is.null(self@request_object_encryption_jwk)) {
    parsed_request_object_encryption_key <- try(
      normalize_jwe_recipient_public_key(
        self@request_object_encryption_jwk,
        arg_name = "request_object_encryption_jwk"
      ),
      silent = TRUE
    )
    if (inherits(parsed_request_object_encryption_key, "try-error")) {
      return(
        paste(
          "OAuthProvider: request_object_encryption_jwk must be a parseable",
          "JWK object, JWK JSON string, openssl::key, or PEM public key"
        )
      )
    }
  }

  if (
    !(is.logical(self@require_signed_request_object) &&
      length(self@require_signed_request_object) == 1L &&
      !is.na(self@require_signed_request_object))
  ) {
    return(
      "OAuthProvider: require_signed_request_object must be a single non-NA logical"
    )
  }
  if (
    isTRUE(self@require_signed_request_object) &&
      length(self@request_object_signing_alg_values_supported) > 0 &&
      !any(
        toupper(self@request_object_signing_alg_values_supported) != "NONE"
      )
  ) {
    return(
      paste(
        "OAuthProvider: require_signed_request_object = TRUE is inconsistent",
        "with request_object_signing_alg_values_supported = 'none' only"
      )
    )
  }

  if (isTRUE(self@use_nonce)) {
    if (!is_valid_string(self@issuer)) {
      return(
        "OAuthProvider: use_nonce = TRUE requires a non-empty provider issuer"
      )
    }
  }

  token_endpoint_auth_signing_algs <-
    self@token_endpoint_auth_signing_alg_values_supported
  if (length(token_endpoint_auth_signing_algs) > 0) {
    if (!is.character(token_endpoint_auth_signing_algs)) {
      return(
        paste(
          "OAuthProvider: token_endpoint_auth_signing_alg_values_supported",
          "must be a character vector"
        )
      )
    }
    if (
      anyNA(token_endpoint_auth_signing_algs) ||
        !all(nzchar(token_endpoint_auth_signing_algs))
    ) {
      return(
        paste(
          "OAuthProvider: token_endpoint_auth_signing_alg_values_supported",
          "must contain only non-empty strings"
        )
      )
    }
  }

  dpop_signing_algs <- self@dpop_signing_alg_values_supported
  if (length(dpop_signing_algs) > 0) {
    if (!is.character(dpop_signing_algs)) {
      return(
        paste(
          "OAuthProvider: dpop_signing_alg_values_supported",
          "must be a character vector"
        )
      )
    }
    if (anyNA(dpop_signing_algs) || !all(nzchar(dpop_signing_algs))) {
      return(
        paste(
          "OAuthProvider: dpop_signing_alg_values_supported",
          "must contain only non-empty strings"
        )
      )
    }
  }

  if (length(self@allowed_token_types) > 0) {
    att <- self@allowed_token_types
    if (!is.character(att)) {
      return("OAuthProvider: allowed_token_types must be a character vector")
    }
    if (any(is.na(att) | !nzchar(att))) {
      return(
        "OAuthProvider: allowed_token_types must contain only non-empty strings"
      )
    }
  }

  if (isTRUE(self@id_token_validation)) {
    if (!is_valid_string(self@issuer)) {
      return(
        "OAuthProvider: id_token_validation = TRUE requires a non-empty provider issuer"
      )
    }
  }

  if (isTRUE(self@id_token_at_hash_required)) {
    if (!isTRUE(self@id_token_validation)) {
      return(
        "OAuthProvider: id_token_at_hash_required = TRUE requires id_token_validation = TRUE"
      )
    }
  }

  if (isTRUE(self@userinfo_required)) {
    if (!is_valid_string(self@userinfo_url)) {
      return(
        "OAuthProvider: userinfo_required = TRUE requires a non-empty userinfo_url"
      )
    }
    if (!is_ok_host(self@userinfo_url)) {
      return(
        "OAuthProvider: userinfo_url provided but not accepted as a host (see `?is_ok_host`)"
      )
    }
  }

  if (isTRUE(self@userinfo_signed_jwt_required)) {
    if (!isTRUE(self@userinfo_required)) {
      return(
        "OAuthProvider: userinfo_signed_jwt_required = TRUE requires userinfo_required = TRUE"
      )
    }
    if (!is_valid_string(self@issuer)) {
      return(
        "OAuthProvider: userinfo_signed_jwt_required = TRUE requires a non-empty issuer (for JWKS verification)"
      )
    }
  }

  if (isTRUE(self@userinfo_id_token_match)) {
    if (!isTRUE(self@userinfo_required)) {
      return(
        "OAuthProvider: userinfo_id_token_match = TRUE requires userinfo_required = TRUE"
      )
    }
    if (!(isTRUE(self@id_token_validation) || isTRUE(self@use_nonce))) {
      return(
        "OAuthProvider: userinfo_id_token_match = TRUE requires id_token_validation = TRUE or use_nonce = TRUE"
      )
    }
    if (!is_valid_string(self@userinfo_url) || !is_ok_host(self@userinfo_url)) {
      return(
        "OAuthProvider: userinfo_id_token_match = TRUE requires a valid userinfo_url"
      )
    }
    if (
      is.null(self@userinfo_id_selector) ||
        !is.function(self@userinfo_id_selector)
    ) {
      return(
        "OAuthProvider: userinfo_id_token_match = TRUE requires userinfo_id_selector to be a function"
      )
    }
  }

  if (
    !is.numeric(self@leeway) ||
      length(self@leeway) != 1 ||
      !is.finite(self@leeway) ||
      self@leeway < 0
  ) {
    return(
      "OAuthProvider: leeway must be a single finite non-negative numeric value"
    )
  }

  if (is_valid_string(self@jwks_host_allow_only)) {
    val <- trimws(self@jwks_host_allow_only)
    host_only <- val
    if (grepl("^https?://", tolower(val))) {
      host_only <- try(
        parse_url_host(val, "jwks_host_allow_only"),
        silent = TRUE
      )
      if (inherits(host_only, "try-error")) {
        return("OAuthProvider: jwks_host_allow_only URL could not be parsed")
      }
    } else {
      if (!grepl("^[A-Za-z0-9.-]+$", host_only)) {
        return(
          "OAuthProvider: jwks_host_allow_only must be a hostname or a URL containing a hostname"
        )
      }
      host_only <- sub("\\.$", "", tolower(host_only))
    }
  }

  NULL
}

## 3.2 Endpoint validation -----------------------------------------------------

#' Internal: validate one provider endpoint-like field
#'
#' Used by the [OAuthProvider] validator for required and optional endpoint
#' fields before the provider object is accepted.
#'
#' @param value Endpoint string to validate.
#' @param name Field label used in validation errors.
#' @param required Whether the field must be present.
#' @return `NULL` on success, otherwise the first validation error string.
#' @keywords internal
#' @noRd
oauth_provider_check_host_field <- function(value, name, required = FALSE) {
  if (required && !is_valid_string(value)) {
    return(sprintf(
      "OAuthProvider: %s is required and must be a non-empty string",
      name
    ))
  }
  if (!is_valid_string(value)) {
    return(NULL)
  }

  parsed <- try(httr2::url_parse(value), silent = TRUE)
  if (
    inherits(parsed, "try-error") ||
      !nzchar((parsed$scheme %||% "")) ||
      !nzchar((parsed$hostname %||% ""))
  ) {
    return(sprintf(
      "OAuthProvider: %s must be an absolute URL (including scheme and hostname)",
      name
    ))
  }

  if (!identical(name, "issuer") && isTRUE(has_uri_fragment(value))) {
    return(sprintf(
      "OAuthProvider: %s must not include a fragment component",
      name
    ))
  }

  if (!is_ok_host(value)) {
    return(sprintf(
      "OAuthProvider: %s provided but not accepted as a host (see `?is_ok_host` for details)",
      name
    ))
  }
  NULL
}

## 3.3 Provider fingerprint ----------------------------------------------------

#' Build a provider fingerprint
#'
#' Computes a stable digest over the provider endpoints and callback-relevant
#' security policy so the callback can confirm it is finishing under the same
#' provider configuration that initiated the flow. Used when a login request is
#' created and again when callback handling resumes.
#'
#' @param provider [OAuthProvider] instance to fingerprint.
#' @return A length-1 character string in `sha256:<digest>` format.
#' @keywords internal
#' @noRd
provider_fingerprint <- function(provider) {
  components <- list(
    issuer = provider@issuer,
    auth_url = provider@auth_url,
    token_url = provider@token_url,
    userinfo_url = provider@userinfo_url,
    introspection_url = provider@introspection_url,
    issuer_match = provider@issuer_match,
    use_nonce = isTRUE(provider@use_nonce),
    use_pkce = isTRUE(provider@use_pkce),
    pkce_method = provider@pkce_method,
    userinfo_required = isTRUE(provider@userinfo_required),
    userinfo_id_selector = provider@userinfo_id_selector,
    userinfo_id_token_match = isTRUE(provider@userinfo_id_token_match),
    userinfo_signed_jwt_required = isTRUE(
      provider@userinfo_signed_jwt_required
    ),
    id_token_required = isTRUE(provider@id_token_required),
    id_token_validation = isTRUE(provider@id_token_validation),
    id_token_at_hash_required = isTRUE(provider@id_token_at_hash_required),
    token_auth_style = provider@token_auth_style,
    tls_client_certificate_bound_access_tokens = isTRUE(
      provider@tls_client_certificate_bound_access_tokens
    ),
    jwks_pins = state_policy_string_set(provider@jwks_pins),
    jwks_pin_mode = provider@jwks_pin_mode,
    jwks_host_issuer_match = isTRUE(provider@jwks_host_issuer_match),
    jwks_host_allow_only = provider@jwks_host_allow_only,
    allowed_algs = state_policy_string_set(
      provider@allowed_algs,
      transform = toupper
    ),
    allowed_token_types = state_policy_string_set(provider@allowed_token_types),
    leeway = provider@leeway,
    mtls_endpoint_aliases = provider@mtls_endpoint_aliases
  )

  state_policy_digest(components)
}
