# OIDC discovery ----------------------------------------------------------

#' @title
#' Discover and create an OpenID Connect (OIDC) [OAuthProvider]
#'
#' @description
#' Uses the OpenID Connect discovery document at
#' `/.well-known/openid-configuration` to auto-configure an [OAuthProvider].
#' When present, `introspection_endpoint` is wired into the resulting provider
#' for RFC 7662 support.
#'
#' @details
#' - ID token algorithms: by default this helper accepts common asymmetric
#'   algorithms RSA (RS*), RSA-PSS (PS*), ECDSA (ES*), and EdDSA. When the
#'   provider advertises its supported ID token signing algorithms via
#'   `id_token_signing_alg_values_supported`, the helper uses the intersection
#'   with the caller-provided `allowed_algs`. If there is no overlap, discovery
#'   fails with a configuration error. There is no automatic fallback to the
#'   discovery-advertised set.
#'
#' - Token endpoint authentication methods: supports `client_secret_basic`
#'   (header), `client_secret_post` (body), public clients using `none`
#'   (with PKCE), as well as JWT-based methods `private_key_jwt` and
#'   `client_secret_jwt` per RFC 7523.
#'
#'   Important: discovery metadata lists methods supported across the provider,
#'   not per-client provisioning. This helper does not automatically select
#'   JWT-based methods just because they are advertised. By default it prefers
#'   `client_secret_basic` (header) when available, otherwise
#'   `client_secret_post` (body), and only uses public `none` for PKCE clients.
#'   If a provider advertises only JWT methods, you must explicitly set
#'   `token_auth_style` and configure the corresponding credentials on your
#'   [OAuthClient] (a private key for `private_key_jwt`, or a sufficiently
#'   strong `client_secret` for `client_secret_jwt`).
#'
#' - Host policy: by default, discovered endpoints must be absolute URLs whose
#'   host matches the issuer host exactly. Subdomains are NOT implicitly allowed.
#'   If you want to allow subdomains, add a leading-dot or glob in
#'   `options(shinyOAuth.allowed_hosts)`, e.g., `.example.com` or `*.example.com`.
#'   If a global whitelist is supplied via `options(shinyOAuth.allowed_hosts)`,
#'   discovery will restrict endpoints to that whitelist. Scheme policy (https/http for
#'   loopback) is delegated to `is_ok_host()`, so you may allow non-HTTPS hosts
#'   with `options(shinyOAuth.allowed_non_https_hosts)` (see `?is_ok_host`).
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
#'   (client_secret_basic) or "body" (client_secret_post). If NULL (default),
#'   it is inferred conservatively from discovery. When PKCE is enabled and the
#'   provider advertises support for public clients via `none`, a secretless
#'   flow is preferred (modeled as `"body"` without credentials). Otherwise,
#'   the helper prefers `"header"` (client_secret_basic) when available, then
#'   `"body"` (client_secret_post). JWT-based methods are not auto-selected
#'   unless explicitly requested
#' @param allowed_algs Character vector of allowed ID token signing algorithms.
#'  Defaults to a broad set of common algorithms, including RSA (RS*), RSA-PSS
#'  (PS*), ECDSA (ES*), and EdDSA. If the discovery document advertises
#'  supported algorithms, the intersection of advertised and caller-provided
#'  algorithms is used to avoid runtime mismatches. If there's no overlap,
#'  discovery fails with a configuration error (no fallback)
#' @param allowed_token_types Character vector of allowed token types for
#'  access tokens issued by this provider. Defaults to 'Bearer'
#' @param jwks_host_issuer_match When TRUE (default), enforce that the JWKS host
#'  discovered from the provider matches the issuer host (or a subdomain). For
#'  providers that serve JWKS from a different host, set
#'  `jwks_host_allow_only` to the exact hostname instead of disabling this.
#'  Disabling (`FALSE`) is not recommended unless you also pin JWKS via
#'  `jwks_host_allow_only` or `jwks_pins`
#' @param issuer_match Character scalar controlling how strictly to validate the
#'  discovery document's `issuer` against the input `issuer`.
#'
#'  - `"url"` (default): require the full issuer URL to match after
#'    trailing-slash normalization (recommended).
#'  - `"host"`: compare only scheme + host (explicit opt-out; not recommended).
#'  - `"none"`: do not validate issuer consistency.
#'
#'  Prefer `"url"` and tighten hosts via `options(shinyOAuth.allowed_hosts)`
#'  when feasible.
#' @param ... Additional fields passed to [oauth_provider()]
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
    "PS256",
    "PS384",
    "PS512",
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
  allowed_hosts_vec <- .discover_compute_allowed_hosts(iss_host)
  .discover_validate_endpoints(endpoints, allowed_hosts_vec)

  # 7) Enforce JWKS host pinning if enabled
  if (isTRUE(jwks_host_issuer_match)) {
    .discover_enforce_jwks_pinning(disc, iss, iss_host, allowed_hosts_vec)
  }

  # 8) Infer token auth style when not set
  token_auth_style <- .discover_infer_token_auth_style(
    token_auth_style,
    disc,
    use_pkce,
    iss,
    endpoints$token_url
  )

  # 9) Optional PKCE S256 warning
  .discover_warn_pkce_s256(disc, use_pkce, iss_host)

  # 10) Negotiate allowed ID token algs
  allowed_algs <- .discover_negotiate_algs(allowed_algs, disc, iss)

  # 10b) Forward caller ... args (e.g. userinfo_signed_jwt_required)
  #      Note: userinfo_signing_alg_values_supported in discovery indicates
  #      provider *capability*, not that every client receives signed JWTs.
  #      Whether the userinfo response is application/jwt depends on per-client
  #      configuration at the provider. Therefore we do NOT auto-enable
  #      userinfo_signed_jwt_required from discovery; callers must opt in.
  dots <- list(...)

  # 11) Default provider name from issuer when needed
  name <- .discover_default_name(name, iss)

  # 12) Construct provider
  do.call(
    oauth_provider,
    c(
      list(
        name = name,
        auth_url = endpoints$auth_url,
        token_url = endpoints$token_url,
        userinfo_url = endpoints$userinfo_url,
        introspection_url = endpoints$introspection_url,
        revocation_url = endpoints$revocation_url,
        issuer = iss,
        use_nonce = use_nonce,
        id_token_validation = id_token_validation,
        use_pkce = use_pkce,
        token_auth_style = token_auth_style,
        allowed_algs = allowed_algs,
        allowed_token_types = allowed_token_types,
        jwks_host_issuer_match = jwks_host_issuer_match
      ),
      dots
    )
  )
}

# Helpers -----------------------------------------------------------------

#' Internal: validate issuer input
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

  invisible(TRUE)
}

#' Internal: build httr2 request for discovery
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

#' Internal: fetch discovery response with retry and structured errors
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
#' @keywords internal
#' @noRd
.discover_parse_json <- function(resp) {
  ct <- tolower(httr2::resp_header(resp, "content-type") %||% "")

  if (!grepl("^application/json", ct)) {
    err_parse(
      "Discovery response was not JSON",
      context = list(content_type = ct)
    )
  }

  body <- httr2::resp_body_string(resp)
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

  list(
    auth_url = auth_url,
    token_url = token_url,
    userinfo_url = userinfo_url,
    introspection_url = introspection_url,
    revocation_url = revocation_url
  )
}

#' Internal: normalize and sanitize hostname
#'
#' @keywords internal
#' @noRd
.discover_normalize_host <- function(host) {
  h <- tolower(trimws(as.character(host %||% "")))
  sub("\\.$", "", h)
}

#' Internal: compute allowed hosts vector for endpoint validation
#'
#' @keywords internal
#' @noRd
.discover_compute_allowed_hosts <- function(iss_host) {
  opt_allowed <- getOption("shinyOAuth.allowed_hosts", default = NULL)

  if (!is.null(opt_allowed) && length(opt_allowed) > 0) {
    return(opt_allowed)
  }

  c(iss_host)
}

#' Internal: validate all endpoints against host policy
#'
#' @keywords internal
#' @noRd
.discover_validate_endpoints <- function(endpoints, allowed_hosts_vec) {
  validate_endpoint(endpoints$auth_url, allowed_hosts_vec)
  validate_endpoint(endpoints$token_url, allowed_hosts_vec)
  validate_endpoint(endpoints$userinfo_url, allowed_hosts_vec)
  validate_endpoint(endpoints$introspection_url, allowed_hosts_vec)
  validate_endpoint(endpoints$revocation_url, allowed_hosts_vec)

  invisible(TRUE)
}

#' Internal: enforce JWKS pinning per issuer/allowed hosts
#'
#' @keywords internal
#' @noRd
.discover_enforce_jwks_pinning <- function(
  disc,
  iss,
  iss_host,
  allowed_hosts_vec
) {
  jwks_uri <- disc[["jwks_uri"]] %||% ""
  if (!nzchar(jwks_uri)) {
    return(invisible(TRUE))
  }

  jwks_host <- .discover_normalize_host(
    httr2::url_parse(jwks_uri)[["hostname"]] %||% ""
  )
  if (!nzchar(jwks_host)) {
    err_config(
      c(
        "x" = "Discovery jwks_host must be an absolute URL",
        "i" = paste0("Got invalid jwks_uri: ", as.character(jwks_uri))
      ),
      context = list(jwks_uri = jwks_uri)
    )
  }

  opt_allowed <- getOption("shinyOAuth.allowed_hosts", default = NULL)
  jwks_ok <- if (!is.null(opt_allowed) && length(opt_allowed) > 0) {
    is_ok_host(paste0("https://", jwks_host, "/"), allowed_hosts = opt_allowed)
  } else {
    # Allow exact match or subdomain of issuer host
    identical(jwks_host, iss_host) ||
      (nzchar(iss_host) && endsWith(jwks_host, paste0(".", iss_host)))
  }

  if (!jwks_ok) {
    err_config(
      c(
        "x" = "JWKS host must match issuer host or subdomain (or allowed host)",
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
#' @keywords internal
#' @noRd
.discover_infer_token_auth_style <- function(
  token_auth_style,
  disc,
  use_pkce,
  iss,
  token_url
) {
  if (!is.null(token_auth_style)) {
    return(token_auth_style)
  }

  methods <- disc[["token_endpoint_auth_methods_supported"]] %||% character(0)
  methods <- tolower(as.character(methods))

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
  # We model this as 'body' style without credentials (code_verifier only).
  if ("none" %in% methods && isTRUE(use_pkce)) {
    return("body")
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

#' Internal: warn if PKCE S256 not advertised
#'
#' @keywords internal
#' @noRd
.discover_warn_pkce_s256 <- function(disc, use_pkce, iss_host) {
  if (!isTRUE(use_pkce)) {
    return(invisible(FALSE))
  }

  cc_methods <- disc[["code_challenge_methods_supported"]] %||% character(0)
  cc_methods <- toupper(as.character(cc_methods))

  if (length(cc_methods) > 0 && !("S256" %in% cc_methods)) {
    if (!.is_test()) {
      rlang::warn(
        c(
          "!" = "Discovery does not advertise PKCE S256 support",
          "i" = "Provider may accept only 'plain' code challenge; explore if enabling it is possible with the provider"
        ),
        .frequency = "once",
        .frequency_id = paste0("pkce-s256-", iss_host)
      )
    }
    return(invisible(TRUE))
  }

  invisible(FALSE)
}

#' Internal: intersect allowed ID token algs with discovery
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


#' Internal: derive default name from issuer
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
