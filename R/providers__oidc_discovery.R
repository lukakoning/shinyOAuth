# This file contains helpers for OpenID Connect discovery
# OpenID Connect discovery is the standard metadata document that tells a
# client which endpoints and settings a provider supports
# Used for building provider objects from that metadata and checking it for
# safety

# 1 OIDC discovery -------------------------------------------------------------

## 1.1 Provider construction ---------------------------------------------------

#' @title
#' Discover and create an OpenID Connect (OIDC) [OAuthProvider]
#'
#' @description
#' Builds an [OAuthProvider] from the provider's OpenID Connect discovery
#' document at `/.well-known/openid-configuration`. When present,
#' `introspection_endpoint` is also wired into the resulting provider.
#'
#' @details
#' Most users can accept the defaults here. The points below are mainly
#' reference for advanced provider setups or for understanding why discovery
#' might fail early.
#'
#' - ID token algorithms: by default this helper accepts common asymmetric
#'   algorithms RSA (RS*), ECDSA (ES*), and EdDSA. When the
#'   provider advertises its supported ID token signing algorithms via
#'   `id_token_signing_alg_values_supported`, the helper uses the intersection
#'   with the caller-provided `allowed_algs`. If there is no overlap, discovery
#'   fails with a configuration error. There is no automatic fallback to the
#'   discovery-advertised set.
#'
#' - Token endpoint authentication methods: supports `client_secret_basic`
#'   (header), `client_secret_post` (body), public clients using `none`
#'   (mapped to `token_auth_style = "public"` when PKCE is enabled), as well as
#'   JWT-based methods `private_key_jwt` and
#'   `client_secret_jwt` per RFC 7523. Discovery also preserves RFC 8705 mTLS
#'   metadata (`mtls_endpoint_aliases` and
#'   `tls_client_certificate_bound_access_tokens`) and supports explicit
#'   `tls_client_auth` / `self_signed_tls_client_auth` selection.
#'
#' - PAR metadata: when the discovery document advertises
#'   `pushed_authorization_request_endpoint` or
#'   `require_pushed_authorization_requests`, the resulting provider stores that
#'   PAR capability and policy metadata so authorization requests can use RFC
#'   9126 PAR and fail fast on PAR-only provider policies.
#'
#' - Request Object metadata: when the discovery document advertises
#'   `request_object_signing_alg_values_supported` or
#'   `require_signed_request_object`, the resulting provider stores that
#'   metadata so `OAuthClient` can fail fast when a request-object algorithm is
#'   unsupported or when the provider requires signed Request Objects. When the
#'   discovery document also advertises
#'   `request_object_encryption_alg_values_supported` or
#'   `request_object_encryption_enc_values_supported`, the resulting provider
#'   stores that encryption metadata so Request Object JWE configuration can be
#'   validated early as well.
#'
#' - Authorization request transport metadata: when the discovery document
#'   advertises `request_parameter_supported`,
#'   `request_uri_parameter_supported`, or
#'   `require_request_uri_registration`, the resulting provider stores that
#'   metadata so shinyOAuth can fail fast when a provider explicitly disallows
#'   the front-channel `request` transport used by JAR or caller-managed
#'   `request_uri` values. The registration requirement itself remains
#'   deployment-specific: shinyOAuth stores
#'   `require_request_uri_registration` for caller awareness, but it cannot
#'   independently verify whether the provider has already registered a
#'   matching public `request_uri` or wildcard prefix for the client. When PAR
#'   is configured, shinyOAuth sends signed Request Objects to the PAR endpoint
#'   and the browser redirect only carries the PAR-issued `request_uri`
#'   handle, regardless of `request_uri_parameter_supported` or
#'   `require_request_uri_registration`. When discovery omits these booleans,
#'   this helper applies the OpenID Connect defaults instead of storing `NA`.
#'
#' - Response mode metadata: when the discovery document advertises
#'   `response_modes_supported`, the resulting provider stores it so explicit
#'   `response_mode` requests can fail fast when unsupported. When the metadata
#'   is omitted, this helper applies the OAuth/OIDC metadata default of
#'   `c("query", "fragment")`.
#'
#' - Token endpoint JWT auth metadata: when the discovery document advertises
#'   `token_endpoint_auth_signing_alg_values_supported`, the resulting provider
#'   stores that metadata so `OAuthClient` can fail fast when a JWT client
#'   assertion algorithm is unsupported.
#'
#' - DPoP metadata: when the discovery document advertises
#'   `dpop_signing_alg_values_supported`, the resulting provider stores that
#'   metadata so `OAuthClient` can fail fast when an explicit or inferred DPoP
#'   proof signing algorithm is unsupported.
#'
#' - RFC 9207 callback issuer metadata: when the discovery document advertises
#'   `authorization_response_iss_parameter_supported = true`, the resulting
#'   provider stores that metadata so [oauth_client()] can auto-enable callback
#'   issuer enforcement unless you explicitly opt out.
#'
#' - PKCE method discovery: this helper keeps `S256` as the default and does not
#'   silently downgrade to `plain`. If discovery metadata explicitly omits
#'   `S256`, discovery fails with a configuration error unless you explicitly
#'   opt into `pkce_method = "plain"`.
#'
#'   Important: discovery metadata lists methods supported across the provider,
#'   not per-client provisioning. This helper does not automatically select
#'   JWT-based methods just because they are advertised. By default it prefers
#'   `client_secret_basic` (header) when available, otherwise
#'   `client_secret_post` (body), and maps public `none` to
#'   `token_auth_style = "public"` only for PKCE clients.
#'   If a provider advertises only JWT methods, you must explicitly set
#'   `token_auth_style` and configure the corresponding credentials on your
#'   [OAuthClient] (a private key for `private_key_jwt`, or a sufficiently
#'   strong `client_secret` for `client_secret_jwt`).
#'
#' - Host policy: by default, discovered standard endpoints must be absolute
#'   URLs whose host matches the issuer host exactly. Subdomains are NOT
#'   implicitly allowed. If you want to allow subdomains, add a leading-dot or
#'   glob in `options(shinyOAuth.allowed_hosts)`, e.g., `.example.com` or
#'   `*.example.com`. If a global whitelist is supplied via
#'   `options(shinyOAuth.allowed_hosts)`, discovery will restrict endpoints to
#'   that whitelist. RFC 8705 `mtls_endpoint_aliases` are validated separately:
#'   they may use a different host or port by default, but an explicit
#'   `shinyOAuth.allowed_hosts` whitelist still constrains them. Scheme policy
#'   (https/http for loopback) is delegated to `is_ok_host()`, so you may allow
#'   non-HTTPS hosts with `options(shinyOAuth.allowed_non_https_hosts)` (see
#'   `?is_ok_host`).
#'
#' @param issuer The OIDC issuer base URL (including scheme), e.g.,
#'   "https://login.example.com"
#' @param name Optional friendly provider name. Defaults to the issuer hostname
#' @param use_pkce Logical, whether to use PKCE for this provider. Defaults to
#'   TRUE. If the discovery document indicates `token_endpoint_auth_methods_supported`
#'   includes "none", PKCE is required unless `use_pkce` is explicitly set to FALSE
#'   (not recommended)
#' @param use_nonce Logical, whether to use OIDC nonce. Defaults to TRUE
#' @param id_token_validation Logical, whether to validate ID tokens automatically
#'   for this provider. Defaults to TRUE
#' @param token_auth_style Authentication style for token requests: "header"
#'   (client_secret_basic), "body" (client_secret_post), or "public"
#'   (public client; send `client_id` only). The alias `"none"` is also
#'   accepted for `"public"`. If NULL (default), it is inferred conservatively
#'   from discovery. When PKCE is enabled and the provider advertises support
#'   for public clients via `none`, discovery selects `"public"`. Otherwise,
#'   the helper prefers `"header"` (client_secret_basic) when available, then
#'   `"body"` (client_secret_post). JWT-based methods are not auto-selected
#'   unless explicitly requested.
#' @param allowed_algs Character vector of allowed ID token signing algorithms.
#'  Defaults to a broad set of common algorithms, including RSA (RS*), ECDSA
#'  (ES*), and EdDSA. If the discovery document advertises
#'  supported algorithms, the intersection of advertised and caller-provided
#'  algorithms is used to avoid runtime mismatches. If there's no overlap,
#'  discovery fails with a configuration error (no fallback).
#' @param allowed_token_types Character vector of allowed token types for
#'  access tokens issued by this provider. Defaults to 'Bearer'
#' @param jwks_host_issuer_match When TRUE (default), enforce that the JWKS host
#'  discovered from the provider matches the issuer host exactly. For
#'  providers that serve JWKS from a different host, set
#'  `jwks_host_allow_only` to the exact hostname instead of disabling this.
#'  Disabling (`FALSE`) is not recommended unless you also pin JWKS via
#'  `jwks_host_allow_only` or `jwks_pins`.
#' @param issuer_match Character scalar controlling how strictly to validate the
#'  discovery document's `issuer` against the input `issuer`.
#'
#'  - `"url"` (default): require the issuer used for discovery to match
#'    exactly, after removing one trailing slash for discovery URL construction
#'    (recommended).
#'  - `"host"`: compare only scheme + host (explicit opt-out; not recommended).
#'  - `"none"`: do not validate issuer consistency.
#'
#'  Prefer `"url"` and tighten hosts via `options(shinyOAuth.allowed_hosts)`
#'  when feasible.
#' @param ... Additional fields passed to [oauth_provider()] (for example,
#'   `pkce_method = "plain"` when a provider explicitly advertises only plain
#'   PKCE support and you intentionally want to allow that downgrade).
#'
#' @return [OAuthProvider] object configured from discovery
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider_oidc_discover <- function(
  issuer,
  name = NULL,
  use_pkce = TRUE,
  use_nonce = TRUE,
  id_token_validation = TRUE,
  token_auth_style = NULL,
  allowed_algs = c(
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA"
  ),
  allowed_token_types = c('Bearer'),
  jwks_host_issuer_match = TRUE,
  issuer_match = c("url", "host", "none"),
  ...
) {
  issuer_match <- match.arg(issuer_match)

  # If callers explicitly turn off ID
  # token validation and do not explicitly opt back into nonce handling,
  # discovery should not require JWKS just because use_nonce's formal default
  # is TRUE
  if (
    missing(use_nonce) &&
      !missing(id_token_validation) &&
      isFALSE(id_token_validation)
  ) {
    use_nonce <- FALSE
  }

  # 1) Validate issuer input
  .discover_assert_valid_issuer(issuer)

  # 2) Build and fetch discovery document
  req <- .discover_build_request(issuer)
  resp <- .discover_fetch_response(req, issuer)

  # 3) Parse JSON and normalize to list
  disc <- .discover_parse_json(resp)

  # 4) Extract key endpoints
  endpoints <- .discover_extract_endpoints(disc)

  # 5) Resolve issuer (prefer discovery) and normalize host
  iss <- validate_discovery_issuer(
    issuer_input = issuer,
    issuer_discovered = disc[["issuer"]],
    issuer_match = issuer_match
  )
  iss_host <- .discover_normalize_host(
    httr2::url_parse(iss)$hostname %||% err_parse("Invalid issuer host")
  )

  # 6) Determine allowed hosts and validate endpoints
  allowed_hosts_vec <- .discover_allowed_hosts(iss_host)
  .discover_validate_endpoints(endpoints, allowed_hosts_vec)

  # 6a) Read caller overrides before any JWKS-dependent policy checks so
  # both presence requirements and host pinning see the same values.
  dots <- list(...)
  jwks_host_allow_only <- dots$jwks_host_allow_only %||% NULL

  # 6b) Any mode that verifies ID-token or UserInfo JWT signatures needs JWKS.
  .discover_require_jwks_uri(
    disc = disc,
    iss = iss,
    id_token_validation = id_token_validation,
    use_nonce = use_nonce,
    userinfo_signed_jwt_required = isTRUE(dots$userinfo_signed_jwt_required)
  )

  # 8) Enforce JWKS host pinning if enabled or explicitly configured.
  if (isTRUE(jwks_host_issuer_match) || is_valid_string(jwks_host_allow_only)) {
    .discover_enforce_jwks_pinning(
      disc = disc,
      iss = iss,
      iss_host = iss_host,
      allowed_hosts_vec = allowed_hosts_vec,
      jwks_host_allow_only = jwks_host_allow_only,
      jwks_host_issuer_match = jwks_host_issuer_match
    )
  }

  # 9) Infer token auth style when not set
  token_auth_style <- .discover_infer_token_auth_style(
    token_auth_style,
    disc,
    use_pkce,
    iss,
    endpoints$token_url
  )

  # 10) Resolve PKCE method against discovery metadata
  pkce_method <- .discover_resolve_pkce_method(
    disc = disc,
    use_pkce = use_pkce,
    iss = iss,
    iss_host = iss_host,
    pkce_method = dots$pkce_method %||% NULL
  )

  # 11) Negotiate allowed ID token algs
  allowed_algs <- .discover_negotiate_algs(allowed_algs, disc, iss)
  require_pushed_authorization_requests <- .discover_parse_optional_boolean(
    disc,
    "require_pushed_authorization_requests"
  )
  request_object_signing_alg_values_supported <- toupper(as.character(
    unlist(
      disc[["request_object_signing_alg_values_supported"]] %||% character(0),
      use.names = FALSE
    )
  ))
  request_object_encryption_alg_values_supported <- toupper(as.character(
    unlist(
      disc[["request_object_encryption_alg_values_supported"]] %||%
        character(0),
      use.names = FALSE
    )
  ))
  request_object_encryption_enc_values_supported <- toupper(as.character(
    unlist(
      disc[["request_object_encryption_enc_values_supported"]] %||%
        character(0),
      use.names = FALSE
    )
  ))
  require_signed_request_object <- .discover_parse_optional_boolean(
    disc,
    "require_signed_request_object"
  )
  request_parameter_supported <- .discover_parse_nullable_boolean(
    disc,
    "request_parameter_supported",
    default = FALSE
  )
  request_uri_parameter_supported <- .discover_parse_nullable_boolean(
    disc,
    "request_uri_parameter_supported",
    default = TRUE
  )
  require_request_uri_registration <- .discover_parse_nullable_boolean(
    disc,
    "require_request_uri_registration",
    default = FALSE
  )
  response_modes_supported <- tolower(trimws(as.character(unlist(
    disc[["response_modes_supported"]] %||% c("query", "fragment"),
    use.names = FALSE
  ))))
  token_endpoint_auth_signing_alg_values_supported <- toupper(as.character(
    unlist(
      disc[["token_endpoint_auth_signing_alg_values_supported"]] %||%
        character(0),
      use.names = FALSE
    )
  ))
  dpop_signing_alg_values_supported <- toupper(as.character(
    unlist(
      disc[["dpop_signing_alg_values_supported"]] %||% character(0),
      use.names = FALSE
    )
  ))
  authorization_response_iss_parameter_supported <-
    .discover_parse_optional_boolean(
      disc,
      "authorization_response_iss_parameter_supported"
    )
  mtls_endpoint_aliases <- .discover_extract_mtls_endpoint_aliases(disc)
  .discover_validate_endpoint_aliases(
    mtls_endpoint_aliases,
    .discover_allowed_alias_hosts()
  )
  tls_client_certificate_bound_access_tokens <-
    .discover_parse_optional_boolean(
      disc,
      "tls_client_certificate_bound_access_tokens"
    )

  # 11b) Forward caller ... args (e.g. userinfo_signed_jwt_required)
  #      Note: userinfo_signing_alg_values_supported in discovery indicates
  #      provider *capability*, not that every client receives signed JWTs.
  #      Whether the userinfo response is application/jwt depends on per-client
  #      configuration at the provider. Therefore we do NOT auto-enable
  #      userinfo_signed_jwt_required from discovery; callers must opt in.
  dots$pkce_method <- pkce_method

  # 12) Default provider name from issuer when needed
  name <- .discover_default_name(name, iss)

  # 13) Construct provider. Allow explicit caller overrides in ... to replace
  # discovered defaults without passing duplicate named formals through do.call().
  provider_args <- list(
    name = name,
    auth_url = endpoints$auth_url,
    token_url = endpoints$token_url,
    userinfo_url = endpoints$userinfo_url,
    introspection_url = endpoints$introspection_url,
    revocation_url = endpoints$revocation_url,
    par_url = endpoints$par_url,
    require_pushed_authorization_requests = require_pushed_authorization_requests,
    request_object_signing_alg_values_supported = request_object_signing_alg_values_supported,
    request_object_encryption_alg_values_supported = request_object_encryption_alg_values_supported,
    request_object_encryption_enc_values_supported = request_object_encryption_enc_values_supported,
    require_signed_request_object = require_signed_request_object,
    request_parameter_supported = request_parameter_supported,
    request_uri_parameter_supported = request_uri_parameter_supported,
    require_request_uri_registration = require_request_uri_registration,
    response_modes_supported = response_modes_supported,
    token_endpoint_auth_signing_alg_values_supported = token_endpoint_auth_signing_alg_values_supported,
    dpop_signing_alg_values_supported = dpop_signing_alg_values_supported,
    authorization_response_iss_parameter_supported = authorization_response_iss_parameter_supported,
    mtls_endpoint_aliases = mtls_endpoint_aliases,
    tls_client_certificate_bound_access_tokens = tls_client_certificate_bound_access_tokens,
    issuer = iss,
    issuer_match = issuer_match,
    use_nonce = use_nonce,
    id_token_validation = id_token_validation,
    use_pkce = use_pkce,
    token_auth_style = token_auth_style,
    allowed_algs = allowed_algs,
    allowed_token_types = allowed_token_types,
    jwks_host_issuer_match = jwks_host_issuer_match
  )
  duplicate_dot_names <- intersect(
    names(provider_args),
    names(dots) %||% character(0)
  )
  if (length(duplicate_dot_names) > 0) {
    provider_args[duplicate_dot_names] <- NULL
  }

  do.call(oauth_provider, c(provider_args, dots))
}

# 2 Discovery helpers ----------------------------------------------------------

## 2.1 Input validation --------------------------------------------------------

#' Internal: validate issuer input
#'
#' Used by [oauth_provider_oidc_discover()] before any network call is made.
#'
#' @param issuer Issuer URL string.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   typed input or configuration error.
#'
#' @keywords internal
#' @noRd
.discover_assert_valid_issuer <- function(issuer) {
  if (!is_valid_string(issuer)) {
    err_input("issuer must be a non-empty URL")
  }

  parsed <- try(httr2::url_parse(issuer), silent = TRUE)
  if (
    inherits(parsed, "try-error") ||
      !nzchar((parsed$scheme %||% "")) ||
      !nzchar((parsed$hostname %||% ""))
  ) {
    err_input(
      c(
        "x" = "issuer must be an absolute URL (including scheme and hostname)",
        "i" = paste0("Got issuer: ", as.character(issuer))
      )
    )
  }

  if (!is_ok_host(issuer)) {
    err_input(
      c(
        "x" = "issuer is not an allowed host",
        "i" = paste0("Got issuer: ", as.character(issuer)),
        "i" = "See `?is_ok_host` for help"
      )
    )
  }

  if (length(parsed$query) > 0L || nzchar(parsed$fragment %||% "")) {
    err_input(
      c(
        "x" = "issuer must not contain query or fragment components",
        "i" = paste0("Got issuer: ", as.character(issuer))
      )
    )
  }

  invisible(TRUE)
}

#' Internal: build httr2 request for discovery
#'
#' Used by [oauth_provider_oidc_discover()] after the issuer has been validated.
#'
#' @param issuer Issuer URL string.
#' @return httr2 request object for the discovery document.
#'
#' @keywords internal
#' @noRd
.discover_build_request <- function(issuer) {
  disco_url <- paste0(rtrim_slash(issuer), "/.well-known/openid-configuration")

  req <- httr2::request(disco_url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "application/json") |>
    add_req_defaults() |>
    req_no_redirect()

  req
}


## 2.2 Transport and parsing ---------------------------------------------------

#' Internal: fetch discovery response with retry and structured errors
#'
#' Used by [oauth_provider_oidc_discover()] to execute the discovery HTTP request.
#'
#' @param req httr2 request object.
#' @param issuer Issuer string used for error context.
#' @return Successful httr2 response. Otherwise this function raises a typed
#'   HTTP error.
#'
#' @keywords internal
#' @noRd
.discover_fetch_response <- function(req, issuer) {
  resp <- try(req_with_retry(req), silent = TRUE)

  if (inherits(resp, "try-error")) {
    msg <- try(conditionMessage(attr(resp, "condition")), silent = TRUE)
    err_http(
      c("x" = "Failed to fetch OIDC discovery document"),
      resp = NULL,
      context = list(
        issuer = issuer,
        transport_error = if (!inherits(msg, "try-error")) {
          as.character(msg)
        } else {
          NULL
        }
      )
    )
  }

  # Security: reject redirect responses to prevent bypassing host validation
  reject_redirect_response(resp, context = "oidc_discovery")

  if (httr2::resp_is_error(resp)) {
    err_http(
      c("x" = "Failed to fetch OIDC discovery document"),
      resp,
      context = list(issuer = issuer)
    )
  }

  resp
}

#' Internal: parse discovery JSON and normalize to list
#'
#' Used by [oauth_provider_oidc_discover()] after a successful discovery fetch.
#'
#' @param resp Discovery HTTP response.
#' @return Parsed discovery document as a named list.
#'
#' @keywords internal
#' @noRd
.discover_parse_json <- function(resp) {
  check_resp_body_size(resp, context = "oidc_discovery")
  ct <- tolower(httr2::resp_header(resp, "content-type") %||% "")

  if (!grepl("^application/json", ct)) {
    err_parse(
      "Discovery response was not JSON",
      context = list(content_type = ct)
    )
  }

  body <- httr2::resp_body_string(resp)
  reject_duplicate_json_object_members(body, "Discovery JSON")
  disc <- try(jsonlite::fromJSON(body, simplifyVector = FALSE), silent = TRUE)

  if (inherits(disc, "try-error")) {
    err_parse(c("x" = "Failed to parse discovery JSON"))
  }

  if (is.data.frame(disc)) {
    disc <- as.list(disc)
  }
  if (!is.list(disc)) {
    err_parse(c("x" = "Discovery JSON did not parse to an object"))
  }

  disc
}

#' Internal: extract endpoints from discovery doc
#'
#' Used by [oauth_provider_oidc_discover()] to pull the provider URLs it needs later.
#'
#' @param disc Parsed discovery document.
#' @return Named list of endpoint URLs and PAR metadata.
#'
#' @keywords internal
#' @noRd
.discover_extract_endpoints <- function(disc) {
  auth_url <- disc[["authorization_endpoint"]] %||%
    err_parse("Discovery missing authorization_endpoint")

  token_url <- disc[["token_endpoint"]] %||%
    err_parse(c("x" = "Discovery missing token_endpoint"))

  userinfo_url <- disc[["userinfo_endpoint"]] %||% NA_character_

  introspection_url <- disc[["introspection_endpoint"]] %||% NA_character_

  revocation_url <- disc[["revocation_endpoint"]] %||% NA_character_

  par_url <- disc[["pushed_authorization_request_endpoint"]] %||% NA_character_

  require_pushed_authorization_requests <- .discover_parse_optional_boolean(
    disc,
    "require_pushed_authorization_requests"
  )

  if (require_pushed_authorization_requests && !is_valid_string(par_url)) {
    err_parse(
      "Discovery requires PAR but is missing pushed_authorization_request_endpoint"
    )
  }

  list(
    auth_url = auth_url,
    token_url = token_url,
    userinfo_url = userinfo_url,
    introspection_url = introspection_url,
    revocation_url = revocation_url,
    par_url = par_url
  )
}


## 2.3 Endpoint and host policy ------------------------------------------------

#' Internal: normalize and sanitize hostname
#'
#' Used by the host-policy helpers in this file so host comparisons are consistent.
#'
#' @param host Host string to normalize.
#' @return Normalized lowercase host string.
#'
#' @keywords internal
#' @noRd
.discover_normalize_host <- function(host) {
  h <- tolower(trimws(as.character(host %||% "")))
  sub("\\.$", "", h)
}

#' Internal: compute the host allowlist used during OIDC discovery
#'
#' Used by [oauth_provider_oidc_discover()] before validating discovered endpoints.
#'
#' Takes the normalized issuer host and returns the host vector that discovery
#' should trust for both normal endpoints and RFC 8705 mTLS endpoint aliases.
#' If the package-level `shinyOAuth.allowed_hosts` option is set, that wins;
#' otherwise discovery falls back to trusting the issuer host only.
#'
#' @param iss_host Normalized issuer host.
#' @return Host vector that discovery is allowed to trust.
#' @keywords internal
#' @noRd
.discover_allowed_hosts <- function(iss_host) {
  opt_allowed <- getOption("shinyOAuth.allowed_hosts", default = NULL)

  if (!is.null(opt_allowed) && length(opt_allowed) > 0) {
    return(opt_allowed)
  }

  c(iss_host)
}

#' Internal: compute the host allowlist used for discovered mTLS aliases
#'
#' RFC 8705 allows `mtls_endpoint_aliases` to live on a different host or port
#' than the issuer. Discovery therefore applies the explicit
#' `shinyOAuth.allowed_hosts` allowlist when present, but otherwise falls back
#' to the general `is_ok_host()` policy instead of implicitly pinning aliases to
#' the issuer host.
#'
#' @return Host vector that discovered mTLS aliases are allowed to trust, or
#'   `NULL` when the general host policy should apply.
#' @keywords internal
#' @noRd
.discover_allowed_alias_hosts <- function() {
  opt_allowed <- getOption("shinyOAuth.allowed_hosts", default = NULL)

  if (!is.null(opt_allowed) && length(opt_allowed) > 0) {
    return(opt_allowed)
  }

  NULL
}

#' Internal: validate all endpoints against host policy
#'
#' Used by [oauth_provider_oidc_discover()] after endpoint extraction.
#'
#' @param endpoints Endpoint list.
#' @param allowed_hosts_vec Allowed host vector.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   host-policy error.
#'
#' @keywords internal
#' @noRd
.discover_validate_endpoints <- function(endpoints, allowed_hosts_vec) {
  validate_endpoint(endpoints$auth_url, allowed_hosts_vec)
  validate_endpoint(endpoints$token_url, allowed_hosts_vec)
  validate_endpoint(endpoints$userinfo_url, allowed_hosts_vec)
  validate_endpoint(endpoints$introspection_url, allowed_hosts_vec)
  validate_endpoint(endpoints$revocation_url, allowed_hosts_vec)
  validate_endpoint(endpoints$par_url, allowed_hosts_vec)

  invisible(TRUE)
}


## 2.4 Capability negotiation --------------------------------------------------

#' Internal: require jwks_uri when runtime verification depends on JWKS
#'
#' Used by [oauth_provider_oidc_discover()] when the resulting provider will
#' verify ID tokens or signed UserInfo JWTs via the provider's JWKS.
#'
#' @param disc Discovery document.
#' @param iss Issuer string.
#' @param id_token_validation Whether ID token validation is enabled.
#' @param use_nonce Whether nonce-based ID token validation is enabled.
#' @param userinfo_signed_jwt_required Whether signed UserInfo JWT verification
#'   is required.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   configuration error.
#'
#' @keywords internal
#' @noRd
.discover_require_jwks_uri <- function(
  disc,
  iss,
  id_token_validation,
  use_nonce,
  userinfo_signed_jwt_required
) {
  needs_jwks <- isTRUE(id_token_validation) ||
    isTRUE(use_nonce) ||
    isTRUE(userinfo_signed_jwt_required)

  if (!needs_jwks) {
    return(invisible(TRUE))
  }

  jwks_uri <- disc[["jwks_uri"]] %||% ""
  if (
    is_valid_string(jwks_uri) &&
      nzchar(trimws(jwks_uri))
  ) {
    return(invisible(TRUE))
  }

  err_config(
    c(
      "x" = "Discovery document missing jwks_uri",
      "i" = paste0(
        "Issuer: ",
        iss
      ),
      "i" = paste0(
        paste(
          "jwks_uri is required when discovery enables id_token_validation,",
          "use_nonce, or userinfo_signed_jwt_required because those modes",
          "verify signatures against the provider's JWKS"
        )
      )
    ),
    context = list(
      issuer = iss,
      id_token_validation = id_token_validation,
      use_nonce = use_nonce,
      userinfo_signed_jwt_required = userinfo_signed_jwt_required
    )
  )
}

#' Internal: enforce JWKS pinning per issuer/allowed hosts
#'
#' Used by [oauth_provider_oidc_discover()] to make sure signing keys come from an allowed host.
#'
#' @param disc Discovery document.
#' @param iss Issuer string.
#' @param iss_host Normalized issuer host.
#' @param allowed_hosts_vec Allowed host vector used for endpoint validation.
#' @param jwks_host_allow_only Optional exact JWKS host override.
#' @param jwks_host_issuer_match Whether JWKS host must match the issuer host.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   configuration error.
#'
#' @keywords internal
#' @noRd
.discover_enforce_jwks_pinning <- function(
  disc,
  iss,
  iss_host,
  allowed_hosts_vec,
  jwks_host_allow_only = NULL,
  jwks_host_issuer_match = TRUE
) {
  jwks_uri <- disc[["jwks_uri"]] %||% ""
  if (!nzchar(jwks_uri)) {
    return(invisible(TRUE))
  }

  jwks_host <- parse_url_host(jwks_uri, "jwks_uri")

  if (is_valid_string(jwks_host_allow_only)) {
    pinned_host <- tolower(trimws(jwks_host_allow_only))
    if (grepl("://", pinned_host, fixed = TRUE)) {
      normalized_host <- try(
        parse_url_host(pinned_host, label = "jwks_host_allow_only"),
        silent = TRUE
      )
      if (!inherits(normalized_host, "try-error")) {
        pinned_host <- normalized_host
      }
    }
    pinned_host <- sub("\\.$", "", pinned_host)

    if (!identical(jwks_host, pinned_host)) {
      err_config(
        c(
          "x" = "jwks_uri host must equal configured jwks_host_allow_only",
          "!" = sprintf("Got '%s' but expected '%s'", jwks_host, pinned_host),
          "i" = "Set `jwks_host_allow_only` to the exact host, or clear it to use issuer-based checks"
        ),
        context = list(
          issuer = iss,
          jwks_uri = jwks_uri,
          issuer_host = iss_host,
          jwks_host = jwks_host,
          jwks_host_allow_only = pinned_host
        )
      )
    }

    return(invisible(TRUE))
  }

  opt_allowed <- getOption("shinyOAuth.allowed_hosts", default = NULL)
  jwks_ok <- if (!is.null(opt_allowed) && length(opt_allowed) > 0) {
    is_ok_host(paste0("https://", jwks_host, "/"), allowed_hosts = opt_allowed)
  } else if (isTRUE(jwks_host_issuer_match)) {
    identical(jwks_host, iss_host)
  } else {
    TRUE
  }

  if (!jwks_ok) {
    err_config(
      c(
        "x" = "JWKS host must match issuer host exactly (or allowed host)",
        "i" = paste0("Issuer host: ", iss_host),
        "i" = paste0("JWKS host: ", jwks_host),
        "i" = paste0(
          "Allowed hosts: ",
          paste(allowed_hosts_vec, collapse = ", ")
        )
      ),
      context = list(
        issuer = iss,
        jwks_uri = jwks_uri,
        issuer_host = iss_host,
        jwks_host = jwks_host,
        allowed_hosts = opt_allowed
      )
    )
  }

  invisible(TRUE)
}

#' Internal: infer token auth style from discovery
#'
#' Used by [oauth_provider_oidc_discover()] when the caller did not choose a token auth style explicitly.
#'
#' @param token_auth_style Requested token auth style, or `NULL`.
#' @param disc Discovery document.
#' @param use_pkce Whether PKCE is enabled for the client.
#' @param iss Discovery issuer.
#' @param token_url Token endpoint URL from discovery.
#' @return Normalized token auth style. Otherwise this function raises a
#'   configuration error.
#'
#' @keywords internal
#' @noRd
.discover_infer_token_auth_style <- function(
  token_auth_style,
  disc,
  use_pkce,
  iss,
  token_url
) {
  methods <- disc[["token_endpoint_auth_methods_supported"]] %||% character(0)
  methods <- tolower(as.character(methods))

  if (!is.null(token_auth_style)) {
    return(.discover_validate_requested_token_auth_style(
      token_auth_style = token_auth_style,
      methods = methods,
      use_pkce = use_pkce,
      iss = iss,
      token_url = token_url
    ))
  }

  # Conservative default: prefer confidential auth methods first so that

  # mixed metadata (e.g. 'none' + 'client_secret_basic') does not silently
  # drift a confidential client to public-client-like behaviour.
  if ("client_secret_basic" %in% methods) {
    return("header")
  }

  if ("client_secret_post" %in% methods) {
    return("body")
  }

  # Public clients: if discovery only advertises 'none' (no confidential
  # methods matched above) and PKCE is enabled, use secretless token requests.
  # Map this to the dedicated public-client auth style.
  if ("none" %in% methods && isTRUE(use_pkce)) {
    return("public")
  }

  # Public clients: if 'none' is advertised but PKCE is disabled, surface a
  # configuration error to encourage enabling PKCE instead of falling back.
  if ("none" %in% methods) {
    err_config(
      c(
        "x" = "OIDC discovery indicates `token_endpoint_auth_methods_supported = ['none']` for public clients",
        "i" = "Enable PKCE to use this provider (set `use_pkce = TRUE`)"
      ),
      context = list(issuer = iss, token_endpoint = token_url)
    )
  }

  # If only mTLS methods are advertised, do not auto-select them because the
  # client certificate is provisioned per app registration. Require explicit
  # opt-in just like JWT-based methods.
  if (any(MTLS_TOKEN_AUTH_STYLES %in% methods)) {
    err_config(
      c(
        "x" = "OIDC discovery advertises only mutual TLS client authentication methods",
        "i" = paste(
          "Set `token_auth_style = 'tls_client_auth'` or",
          "`token_auth_style = 'self_signed_tls_client_auth'` explicitly"
        ),
        "i" = "Configure tls_client_cert_file and tls_client_key_file on your OAuthClient"
      ),
      context = list(
        issuer = iss,
        token_endpoint = token_url,
        methods = methods
      )
    )
  }

  # If only JWT-based methods are advertised, do not auto-select them because
  # per-client credentials may not be provisioned. Require explicit opt-in.
  if (any(c("private_key_jwt", "client_secret_jwt") %in% methods)) {
    err_config(
      c(
        "x" = "OIDC discovery advertises only JWT client authentication methods",
        "i" = "Set `token_auth_style = 'private_key_jwt'` (with a private key) or `token_auth_style = 'client_secret_jwt'` (with a strong client_secret) explicitly",
        "i" = "Discovery metadata is provider-wide and may not reflect your app's registered auth method"
      ),
      context = list(
        issuer = iss,
        token_endpoint = token_url,
        methods = methods
      )
    )
  }

  # When methods are not advertised, fall back to historic default: header.
  "header"
}

#' Validate an explicitly requested token auth style
#'
#' Confirms that the caller-requested token auth style is compatible with the
#' client authentication methods advertised by OIDC discovery.
#' Used by `.discover_infer_token_auth_style()` when the caller sets
#' `token_auth_style` explicitly.
#'
#' @param token_auth_style Requested token auth style.
#' @param methods Advertised token endpoint auth methods.
#' @param use_pkce Whether PKCE is enabled for the client.
#' @param iss Discovery issuer.
#' @param token_url Token endpoint URL from discovery.
#' @return The normalized token auth style. Otherwise this function raises a
#'   configuration error.
#' @keywords internal
#' @noRd
.discover_validate_requested_token_auth_style <- function(
  token_auth_style,
  methods,
  use_pkce,
  iss,
  token_url
) {
  token_auth_style <- normalize_token_auth_style(token_auth_style)

  if (length(methods) == 0L) {
    return(token_auth_style)
  }

  is_supported <- switch(
    token_auth_style,
    header = "client_secret_basic" %in% methods,
    body = "client_secret_post" %in% methods,
    public = ("none" %in% methods && isTRUE(use_pkce)),
    client_secret_jwt = "client_secret_jwt" %in% methods,
    private_key_jwt = "private_key_jwt" %in% methods,
    tls_client_auth = "tls_client_auth" %in% methods,
    self_signed_tls_client_auth = "self_signed_tls_client_auth" %in% methods,
    FALSE
  )

  if (isTRUE(is_supported)) {
    return(token_auth_style)
  }

  err_config(
    c(
      "x" = "Requested token_auth_style is not advertised by OIDC discovery",
      "i" = paste0("Requested: ", token_auth_style),
      "i" = paste0("Advertised methods: ", paste(methods, collapse = ", "))
    ),
    context = list(
      issuer = iss,
      token_endpoint = token_url,
      requested_token_auth_style = token_auth_style,
      methods = methods
    )
  )
}


## 2.5 mTLS discovery metadata -------------------------------------------------

#' Extract discovered mTLS endpoint aliases
#'
#' Reads the optional `mtls_endpoint_aliases` object from the discovery
#' document and maps supported alias names onto shinyOAuth's internal endpoint
#' names.
#' Used by [oauth_provider_oidc_discover()] before mTLS alias host validation.
#'
#' @param disc Parsed discovery document.
#' @return A named list of mTLS alias URLs.
#' @keywords internal
#' @noRd
.discover_extract_mtls_endpoint_aliases <- function(disc) {
  aliases <- disc[["mtls_endpoint_aliases"]] %||% list()
  if (is.null(aliases)) {
    return(list())
  }
  if (is.data.frame(aliases)) {
    aliases <- as.list(aliases)
  }
  if (!is.list(aliases)) {
    err_parse("Discovery mtls_endpoint_aliases must be a JSON object")
  }

  alias_name_map <- c(
    token_endpoint = "token_endpoint",
    userinfo_endpoint = "userinfo_endpoint",
    introspection_endpoint = "introspection_endpoint",
    revocation_endpoint = "revocation_endpoint",
    pushed_authorization_request_endpoint = "par_endpoint",
    device_authorization_endpoint = "device_authorization_endpoint"
  )
  alias_names <- intersect(
    names(aliases) %||% character(0),
    names(alias_name_map)
  )
  if (length(alias_names) == 0L) {
    return(list())
  }

  out <- list()
  for (name in alias_names) {
    value <- aliases[[name]]
    target_name <- alias_name_map[[name]]
    if (is.null(value)) {
      out[[target_name]] <- NULL
      next
    }

    if (!is.character(value) || length(value) != 1L || is.na(value)) {
      err_parse(
        paste0("Discovery mtls_endpoint_aliases$", name, " must be a string")
      )
    }
    out[[target_name]] <- as.character(value)
  }

  out[!vapply(out, is.null, logical(1))]
}

#' Parse an optional discovery boolean field
#'
#' Used by [oauth_provider_oidc_discover()] and its helper functions when
#' discovery metadata contains optional boolean feature flags.
#'
#' @param disc Parsed discovery document.
#' @param field Field name to read.
#' @return `TRUE` or `FALSE`.
#' @keywords internal
#' @noRd
.discover_parse_optional_boolean <- function(disc, field) {
  value <- disc[[field]]
  if (is.null(value)) {
    return(FALSE)
  }
  if (!is.logical(value) || length(value) != 1L || is.na(value)) {
    err_parse(sprintf("Discovery %s must be a JSON boolean", field))
  }

  value
}

#' Parse discovery boolean metadata with an explicit default
#'
#' Used by [oauth_provider_oidc_discover()] for optional booleans whose
#' omission has a defined OpenID Connect default.
#'
#' @param disc Parsed discovery document.
#' @param field Field name to read.
#' @param default Logical scalar returned when the metadata is omitted.
#' @return `TRUE` or `FALSE`.
#' @keywords internal
#' @noRd
.discover_parse_nullable_boolean <- function(disc, field, default) {
  if (!is.logical(default) || length(default) != 1L || is.na(default)) {
    err_input("default must be a single non-NA logical")
  }

  value <- disc[[field]]
  if (is.null(value)) {
    return(default)
  }
  if (!is.logical(value) || length(value) != 1L || is.na(value)) {
    err_parse(sprintf("Discovery %s must be a JSON boolean", field))
  }

  value
}

#' Validate discovered mTLS endpoint aliases
#'
#' Applies host validation to discovered mTLS aliases.
#'
#' By default this uses the package's general `is_ok_host()` policy so RFC 8705
#' aliases may live on a different host or port than the issuer. When callers
#' configure an explicit host allowlist, aliases must satisfy that allowlist.
#'
#' @param mtls_endpoint_aliases Named list of discovered mTLS alias URLs.
#' @param allowed_hosts_vec Optional host vector used for endpoint validation.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   validation error.
#' @keywords internal
#' @noRd
.discover_validate_endpoint_aliases <- function(
  mtls_endpoint_aliases,
  allowed_hosts_vec
) {
  if (!length(mtls_endpoint_aliases)) {
    return(invisible(TRUE))
  }

  for (alias_url in unname(mtls_endpoint_aliases)) {
    validate_endpoint(alias_url, allowed_hosts_vec)
  }

  invisible(TRUE)
}


## 2.6 PKCE and algorithm negotiation ------------------------------------------

#' Internal: resolve PKCE method against discovery metadata
#'
#' Used by [oauth_provider_oidc_discover()] to keep PKCE choices aligned with provider metadata.
#'
#' @param disc Discovery document.
#' @param use_pkce Whether PKCE is enabled.
#' @param iss Discovery issuer.
#' @param iss_host Normalized issuer host.
#' @param pkce_method Optional requested PKCE method.
#' @return Chosen PKCE method. Otherwise this function raises a configuration
#'   error.
#'
#' @keywords internal
#' @noRd
.discover_resolve_pkce_method <- function(
  disc,
  use_pkce,
  iss,
  iss_host,
  pkce_method = NULL
) {
  if (!isTRUE(use_pkce)) {
    return(pkce_method)
  }

  cc_methods <- disc[["code_challenge_methods_supported"]] %||% character(0)
  cc_methods <- toupper(as.character(cc_methods))
  pkce_method <- normalize_pkce_method(pkce_method %||% NULL, default = NULL)
  if (
    !is.null(pkce_method) &&
      !identical(pkce_method, "S256") &&
      !identical(pkce_method, "plain")
  ) {
    err_config(
      c(
        "x" = "pkce_method must be 'S256' or 'plain'",
        "i" = paste0("Received: ", as.character(pkce_method))
      ),
      context = list(
        issuer = iss,
        issuer_host = iss_host,
        pkce_method = pkce_method
      )
    )
  }

  # When the provider does not advertise methods, preserve the historical
  # default and let oauth_provider() choose S256 unless the caller explicitly
  # requests plain.
  if (length(cc_methods) == 0L) {
    return(pkce_method)
  }

  requested_method <- toupper(pkce_method %||% "S256")

  if (!(requested_method %in% cc_methods)) {
    remediation <- if ("PLAIN" %in% cc_methods) {
      "Discovery will not silently downgrade; pass `pkce_method = 'plain'` explicitly only if you intend to allow plain PKCE"
    } else {
      "Adjust the provider or discovery configuration so it supports PKCE S256"
    }

    err_config(
      c(
        "x" = paste0(
          "OIDC discovery does not advertise PKCE ",
          requested_method,
          " support"
        ),
        "!" = paste0(
          "Advertised methods: ",
          paste(cc_methods, collapse = ", ")
        ),
        "i" = remediation
      ),
      context = list(
        issuer = iss,
        issuer_host = iss_host,
        code_challenge_methods_supported = cc_methods,
        requested_pkce_method = requested_method
      )
    )
  }

  pkce_method
}

#' Internal: intersect allowed ID token algs with discovery
#'
#' Used by [oauth_provider_oidc_discover()] to keep ID token verification settings compatible with the provider.
#'
#' @param allowed_algs Caller allowlist of supported algorithms.
#' @param disc Discovery document.
#' @param iss Discovery issuer.
#' @return Negotiated algorithm vector.
#'
#' @keywords internal
#' @noRd
.discover_negotiate_algs <- function(allowed_algs, disc, iss) {
  disc_algs <- disc[["id_token_signing_alg_values_supported"]] %||% character(0)

  if (length(disc_algs) == 0) {
    return(allowed_algs)
  }

  aa <- toupper(as.character(allowed_algs %||% character(0)))
  da <- toupper(as.character(disc_algs))

  overlap <- intersect(aa, da)

  if (length(overlap) == 0) {
    err_config(
      c(
        "x" = "No supported ID token signing algorithms found via OIDC discovery",
        "!" = paste0("Provider advertises: ", paste(da, collapse = ", ")),
        "!" = paste0("Allowed algorithms: ", paste(aa, collapse = ", ")),
        "i" = paste0(
          "You may adjust `allowed_algs` to accommodate the provider's supported algorithms"
        )
      ),
      context = list(issuer = iss, discovery_alg_values = da)
    )
  }

  overlap
}


## 2.7 Naming ------------------------------------------------------------------

#' Internal: derive default name from issuer
#'
#' Used by [oauth_provider_oidc_discover()] when the caller did not supply a friendly provider name.
#'
#' @param name Optional provider name.
#' @param iss Issuer URL.
#' @return Chosen provider name string.
#'
#' @keywords internal
#' @noRd
.discover_default_name <- function(name, iss) {
  if (!is.null(name)) {
    return(name)
  }

  parsed <- try(httr2::url_parse(iss), silent = TRUE)
  host <- if (!inherits(parsed, "try-error")) parsed$hostname else NA_character_

  if (is_valid_string(host)) {
    return(host)
  }

  "oidc"
}
