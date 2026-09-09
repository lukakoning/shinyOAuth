# Pure configuration helpers. In particular, do not construct a temporary S7
# client here: its validator can probe private-key signing and consume randomness.
oauth21_requirement_source <- function(reference) {
  if (grepl("openid-connect-core", reference, fixed = TRUE)) {
    "oidc"
  } else if (grepl("oauth-rfc7523bis", reference, fixed = TRUE)) {
    "jwt_client_authentication"
  } else if (grepl("rfc9207", reference, fixed = TRUE)) {
    "issuer_identification"
  } else if (grepl("rfc9700", reference, fixed = TRUE)) {
    "oauth_security_bcp"
  } else if (grepl("rfc9325", reference, fixed = TRUE)) {
    "tls_security_bcp"
  } else {
    "oauth21"
  }
}

oauth21_validate_context <- function(context) {
  if (
    !is.list(context) ||
      (length(context) &&
        (is.null(names(context)) ||
          anyDuplicated(names(context)) ||
          !all(names(context) %in% c("operations", "nonce_exception"))))
  ) {
    stop(
      "context must be a named list containing operations and/or nonce_exception",
      call. = FALSE
    )
  }
  operations <- context$operations
  if (
    !is.null(operations) &&
      (!is.character(operations) ||
        anyNA(operations) ||
        !all(operations %in% c("userinfo", "introspection", "revocation")))
  ) {
    stop(
      "context$operations must select userinfo, introspection and/or revocation",
      call. = FALSE
    )
  }
  if (
    !is.null(context$nonce_exception) &&
      !is_scalar_logical(context$nonce_exception)
  ) {
    stop(
      "context$nonce_exception must be a single non-NA logical",
      call. = FALSE
    )
  }
  invisible(NULL)
}

oauth21_verdict <- function(checks) {
  mandatory <- checks$status[
    checks$affects_verdict & checks$status != "not_applicable"
  ]
  if ("fail" %in% mandatory) {
    return(FALSE)
  }
  if (!length(mandatory) || "unknown" %in% mandatory) {
    return(NA)
  }
  all(mandatory == "pass")
}

oauth21_url_parts <- function(url) {
  if (!is_valid_string(url)) {
    return(NULL)
  }
  tryCatch(httr2::url_parse(url), error = function(e) NULL)
}

# The legacy skip helpers use R's condition coercion, including numeric flags.
# Preserve their effective meaning; malformed flags are unresolved, not passes.
oauth21_test_bypass_active <- function(option, development) {
  tryCatch(
    if (!getOption(option, FALSE)) FALSE else development,
    error = function(e) NA
  )
}

oauth21_https <- function(url) {
  parts <- oauth21_url_parts(url)
  !is.null(parts) &&
    identical(tolower(parts$scheme %||% ""), "https") &&
    is_valid_string(parts$hostname) &&
    !nzchar(parts$username %||% "") &&
    !nzchar(parts$password %||% "") &&
    !nzchar(parts$fragment %||% "")
}

oauth21_redirect_ok <- function(url) {
  if (oauth21_https(url)) {
    return(TRUE)
  }
  parts <- oauth21_url_parts(url)
  !is.null(parts) &&
    identical(tolower(parts$scheme %||% ""), "http") &&
    tolower(parts$hostname %||% "") %in%
      c("localhost", "127.0.0.1", "::1", "[::1]") &&
    !nzchar(parts$username %||% "") &&
    !nzchar(parts$password %||% "") &&
    !nzchar(parts$fragment %||% "")
}

oauth21_endpoint_settings <- function(client, provider, endpoint) {
  override <- if (is.null(client) || endpoint %in% c("token", "userinfo")) {
    list()
  } else {
    client@endpoint_auth[[endpoint]] %||% list()
  }
  effective <- function(name) {
    override[[name]] %||%
      if (!is.null(client)) S7::prop(client, name) else NULL
  }
  method <- resolve_endpoint_auth_method(provider, endpoint, override)
  style <- method$style
  cert <- is_valid_string(effective("mtls_client_cert_file")) &&
    is_valid_string(effective("mtls_client_key_file"))
  bound <- !is.null(client) &&
    isTRUE(client@mtls_certificate_bound_access_tokens) &&
    isTRUE(provider@mtls_client_certificate_bound_access_tokens) &&
    cert
  mtls <- style %in% MTLS_TOKEN_AUTH_STYLES || bound
  url <- resolve_provider_endpoint_url(
    provider,
    paste0(endpoint, "_endpoint"),
    mtls
  )
  secret <- effective("client_secret")
  has_secret <- is_valid_string(secret)
  credentials <- switch(
    style,
    header = has_secret,
    body = has_secret || isTRUE(provider@use_pkce),
    public = TRUE,
    client_secret_jwt = has_secret && nchar(secret, type = "bytes") >= 32,
    private_key_jwt = !is.null(effective("client_assertion_private_key")),
    tls_client_auth = cert,
    self_signed_tls_client_auth = cert,
    FALSE
  )
  # Share algorithm normalization and key inspection with runtime construction.
  # Unparsed keys and unknown capabilities remain unresolved without signing.
  if (style %in% c("client_secret_jwt", "private_key_jwt")) {
    alg <- canonicalize_jws_alg(effective("client_assertion_alg"))
    advertised <- if (endpoint %in% c("token", "par")) {
      provider@token_endpoint_auth_signing_alg_values_supported
    } else {
      provider@endpoint_auth_metadata[[endpoint]]$signing_algs
    }
    candidates <- if (nzchar(alg)) {
      alg
    } else if (length(advertised) && endpoint %in% c("introspection", "revocation")) {
      advertised
    } else if (style == "client_secret_jwt") {
      "HS256"
    } else {
      # These are the runtime defaults for RSA, EC and Ed25519 respectively.
      c("RS256", "ES256", "ES384", "ES512", "EdDSA")
    }
    compatible <- vapply(candidates, function(candidate) {
      if (style == "client_secret_jwt") {
        has_secret && candidate %in% c("HS256", "HS384", "HS512") &&
          nchar(secret, type = "bytes") >= min_hmac_key_bytes(candidate)
      } else {
        private_key_jws_alg_compatibility(
          effective("client_assertion_private_key"), candidate
        )
      }
    }, logical(1))
    if (length(advertised)) {
      compatible <- compatible & candidates %in% advertised
    }
    credentials <- credentials && any(compatible)
  }
  mtls_backend <- !mtls || mtls_pem_backend_supported()
  credentials <- credentials && mtls_backend
  headers <- if (endpoint == "token") {
    provider@extra_token_headers
  } else {
    override$extra_headers
  }
  if (
    any(
      tolower(trimws(names(headers))) %in%
        c("authorization", "proxy-authorization")
    )
  ) {
    method$problem <- "Configured headers conflict with managed client authentication"
  }
  fixed <- tryCatch(decode_form_pairs(url_raw_query(url)), error = function(e) {
    NULL
  })
  if (
    is.null(fixed) ||
      any(
        names(fixed) %in% c("client_secret", "client_assertion", "access_token")
      )
  ) {
    method$problem <- "Endpoint query contains malformed or conflicting credential parameters"
  }
  list(
    style = style,
    url = url,
    credentials = credentials,
    mtls = mtls,
    mtls_backend = mtls_backend,
    problem = method$problem,
    confidential = !style %in% c("public") &&
      !(style == "body" && !has_secret) &&
      !identical(credentials, FALSE),
    audience = effective("client_assertion_audience"),
    typ = effective("client_assertion_typ")
  )
}

# Inspect only deterministic authorization fields. No state, nonce, DPoP key
# thumbprint, request object or request_uri is generated during assessment.
oauth21_authorization_settings <- function(client) {
  provider <- client@provider
  mode <- resolve_oauth_client_response_mode(client)
  extra <- mode$extra_auth_params
  scopes <- as_scope_tokens(client@scopes)
  if (provider_uses_oidc(provider) && !"openid" %in% scopes) {
    scopes <- c("openid", scopes)
  }
  params <- compact_list(list(
    response_type = "code",
    client_id = client@client_id,
    redirect_uri = client@redirect_uri,
    scope = if (length(scopes)) paste(scopes, collapse = " "),
    code_challenge_method = if (isTRUE(provider@use_pkce)) {
      normalize_pkce_method(provider@pkce_method)
    },
    response_mode = mode$explicit_mode,
    resource = if (length(client@resource)) client@resource,
    claims = if (is.list(client@claims)) {
      jsonlite::toJSON(client@claims, auto_unbox = TRUE, null = "null")
    } else {
      client@claims
    },
    acr_values = if (length(client@required_acr_values)) {
      paste(client@required_acr_values, collapse = " ")
    }
  ))
  max_age <- inspect_auth_max_age(extra)
  if (length(max_age$index) == 1L) {
    extra[[max_age$index]] <- max_age$value
  }
  merged <- oauth_extra_params_resolution(params, extra)
  blocked <- c("redirect_uri", "scope", "claims")
  if (client_has_dpop(client)) {
    blocked <- c(blocked, "dpop_jkt")
  }
  if (length(client@required_acr_values)) {
    blocked <- c(blocked, "acr_values")
  }
  unblocked <- tolower(trimws(getOption(
    "shinyOAuth.unblock_auth_params",
    character()
  )))
  conflicts <- intersect(
    tolower(trimws(names(extra))),
    setdiff(blocked, unblocked)
  )
  if (
    !is.null(mode$error) ||
      !is.null(max_age$error) ||
      !is.null(merged$problem) ||
      length(conflicts)
  ) {
    return(list(status = "fail", redirect_uri = client@redirect_uri))
  }
  resolved <- authorization_query_resolution(provider@auth_url, merged$params)
  fixed <- tryCatch(
    decode_form_pairs(url_raw_query(provider@auth_url)),
    error = function(e) list()
  )
  dynamic <- c(
    "state",
    "nonce",
    "code_challenge",
    "request",
    "request_uri",
    "dpop_jkt"
  )
  unresolved <- any(names(fixed) %in% dynamic) ||
    any(
      setdiff(names(fixed), names(merged$params)) %in%
        c(
          "response_mode",
          "max_age",
          "claims",
          "acr_values",
          "code_challenge_method"
        )
    )
  # A selected redirect override must still agree with the callback transaction.
  redirect <- merged$params$redirect_uri
  conflict <- !identical(redirect, client@redirect_uri) ||
    (provider_uses_oidc(provider) &&
      !"openid" %in% as_scope_tokens(merged$params$scope))
  list(
    status = if (!is.null(resolved$problem) || conflict) {
      "fail"
    } else if (unresolved) {
      "unknown"
    } else {
      "pass"
    },
    redirect_uri = redirect
  )
}
