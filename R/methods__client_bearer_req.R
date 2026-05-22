# This file contains the helper that builds outbound API requests with the
# current access token already attached
# Used for creating an httr2 request that already includes authentication and
# the package's normal HTTP defaults

# 1 Authenticated request helper -----------------------------------------------

#' Build an authenticated httr2 request for a protected resource
#'
#' @description
#' This is a helper for calling downstream APIs with an access token. It creates an
#' [httr2::request()] for the given URL, attaches the right authorization header
#' for the token type, and applies shinyOAuth's standard HTTP defaults.
#'
#' Use [perform_resource_req()] when you want shinyOAuth to also perform the request
#' and handle DPoP nonce challenges for you (which [httr2::req_perform()]
#' would not do on its own).
#'
#' @param token Either an [OAuthToken] object or a raw access token string.
#' @param url The absolute URL to call.
#' @param method Optional HTTP method (character). Defaults to "GET". When
#'   the effective token type is `DPoP`, this must be the final request method
#'   because the proof is signed against it.
#' @param headers Optional named list or named character vector of extra
#'   headers to set on the request. Header names are case-insensitive.
#'   Any user-supplied `Authorization` or `DPoP` header is ignored to ensure
#'   the token authentication set by this function is not overridden.
#' @param query Optional named list of query parameters to append to the URL.
#' @param follow_redirect Logical. If `FALSE` (the default), HTTP redirects
#'   are disabled to prevent leaking the access token to unexpected hosts.
#'   Set to `TRUE` only if you trust all possible redirect targets and
#'   understand the security implications.
#' @param check_url Logical. If `TRUE` (the default), validates `url` against
#'   [is_ok_host()] before attaching the access token. This rejects relative
#'   URLs, plain HTTP to non-loopback hosts, and when
#'   `options(shinyOAuth.allowed_hosts)` is set, hosts outside the allowlist.
#'   Set to `FALSE` only if you have already validated the URL and understand
#'   the security implications.
#' @param oauth_client Optional [OAuthClient]. Required when the effective
#'   token type is `DPoP`, because the client carries the configured DPoP proof
#'   key, and also when using sender-constrained mTLS / certificate-bound
#'   tokens so shinyOAuth can attach the configured client certificate and
#'   validate any `cnf` thumbprint from an [OAuthToken] and observe any `cnf`
#'   thumbprint carried on a raw JWT access-token string.
#' @param token_type Optional override for the access token type when `token`
#'   is supplied as a raw string. Supported values are `Bearer` and `DPoP`.
#'   Invalid or multi-valued inputs are rejected. When omitted, shinyOAuth
#'   preserves `OAuthToken@token_type`, and may infer `DPoP` from explicit
#'   `OAuthToken@cnf$jkt` metadata. Raw access-token strings default to
#'   `Bearer` unless you pass `token_type = "DPoP"` explicitly.
#' @param dpop_nonce Optional DPoP nonce to embed in the proof for this
#'   request. This is primarily useful after a resource server challenges with
#'   `DPoP-Nonce`.
#'
#' @return An [httr2] request object, ready to be performed with
#'   [httr2::req_perform()]. Callers may still add headers or query
#'   parameters, but when the effective token type is `DPoP` they must not
#'   change the request method or base URL after calling
#'   [resource_req()] because the proof is already bound to those values.
#'
#' @section DPoP note:
#' DPoP proofs bind the current HTTP method and target URI (without query or
#' fragment). Adding query parameters after [resource_req()] is fine, but
#' changing the method, scheme, host, or path invalidates the proof.
#'
#' @example inst/examples/client_bearer_req.R
#'
#' @export
resource_req <- function(
  token,
  url,
  method = "GET",
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE,
  check_url = TRUE,
  oauth_client = NULL,
  token_type = NULL,
  dpop_nonce = NULL
) {
  prepare_client_bearer_request(
    token = token,
    url = url,
    method = method,
    headers = headers,
    query = query,
    follow_redirect = follow_redirect,
    check_url = check_url,
    oauth_client = oauth_client,
    token_type = token_type,
    dpop_nonce = dpop_nonce
  )$req
}

#' @title
#' Alias for `resource_req()`
#'
#' @description
#' `r lifecycle::badge("deprecated")`
#'
#' Deprecated alias for `resource_req()` to avoid a breaking change in the public API.
#' Use `resource_req()` for Bearer, DPoP, and mTLS-protected resource requests instead.
#'
#' @inheritParams resource_req
#' @return Same value as [resource_req()].
#' @export
client_bearer_req <- function(
  token,
  url,
  method = "GET",
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE,
  check_url = TRUE,
  oauth_client = NULL,
  token_type = NULL,
  dpop_nonce = NULL
) {
  deprecate_warn_pkg(
    when = "0.4.0.9000",
    what = "client_bearer_req()",
    with = "resource_req()",
    details = paste(
      "Use resource_req() for Bearer, DPoP, and mTLS-protected resource requests"
    )
  )

  resource_req(
    token = token,
    url = url,
    method = method,
    headers = headers,
    query = query,
    follow_redirect = follow_redirect,
    check_url = check_url,
    oauth_client = oauth_client,
    token_type = token_type,
    dpop_nonce = dpop_nonce
  )
}

#' Build and perform an authenticated httr2 request for a protected resource
#'
#' @description
#' This is a helper for calling downstream APIs with an access token. It creates
#' an [httr2::request()] for the given URL, attaches the right authorization
#' header for the token type, applies shinyOAuth's standard HTTP defaults, and
#' performs the request. You can also provide a prebuilt [httr2::request()] object
#' as the `url` argument, in which case this helper will layer token authentication
#' and any explicit overrides on top of the provided request before performing it.
#'
#' Use [resource_req()] if you want to only build the request (and perform it later).
#'
#' Compared to [httr2::req_perform()], this helper adds shinyOAuth-specific
#' handling for DPoP-bound tokens, including retrying once with a fresh proof when
#' a `DPoP-Nonce` challenge is encountered. For non-DPoP tokens, this helper behaves
#' similarly to [httr2::req_perform()] but with the package's standard defaults
#' for retries and redirects.
#'
#' @inheritParams resource_req
#' @param url Either the absolute URL to call or an [httr2::request()] object
#'   to authorize and perform. When you pass a request object, shinyOAuth uses
#'   it as the base request, still applies token authentication and request
#'   defaults, and then layers any explicit `method`, `headers`, `query`, and
#'   `follow_redirect` overrides on top.
#' @param idempotent Optional logical controlling generic transport and
#'   transient-HTTP retries in `req_with_retry()`. When `NULL` (the default),
#'   shinyOAuth infers this from the final request method using standard HTTP
#'   idempotency semantics (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`,
#'   `DELETE`). DPoP nonce challenges are replayed once regardless, as required
#'   by RFC 9449.
#'
#' @return An [httr2] response object.
#'
#' @example inst/examples/client_bearer_req.R
#'
#' @export
perform_resource_req <- function(
  token,
  url,
  method = "GET",
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE,
  check_url = TRUE,
  oauth_client = NULL,
  token_type = NULL,
  dpop_nonce = NULL,
  idempotent = NULL
) {
  request_input <- inherits(url, "httr2_request")
  method_override <- if (request_input && missing(method)) NULL else method

  prepared <- prepare_client_bearer_request(
    token = token,
    url = if (request_input) NULL else url,
    req = if (request_input) url else NULL,
    method = method_override,
    headers = headers,
    query = query,
    follow_redirect = follow_redirect,
    check_url = check_url,
    oauth_client = oauth_client,
    token_type = token_type,
    dpop_nonce = dpop_nonce
  )

  req <- prepared$req
  token_info <- prepared$token_info

  if (is.null(idempotent)) {
    request_method <- tryCatch(
      toupper(as.character(req$method %||% method)[[1]]),
      error = function(...) "GET"
    )
    idempotent <- request_method %in%
      c(
        "GET",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "PUT",
        "DELETE"
      )
  } else if (
    !(is.logical(idempotent) && length(idempotent) == 1L && !is.na(idempotent))
  ) {
    err_input("idempotent must be NULL or a single non-NA logical")
  }

  if (is_dpop_token_type(token_info$token_type)) {
    return(req_with_dpop_retry(
      req,
      oauth_client,
      access_token = token_info$access_token,
      idempotent = isTRUE(idempotent),
      nonce = dpop_nonce
    ))
  }

  req_with_retry(req, idempotent = isTRUE(idempotent))
}

#' @title
#' Alias for `perform_resource_req()`
#'
#' @description
#' `r lifecycle::badge("deprecated")`
#'
#' Deprecated alias for `perform_resource_req()` to avoid a breaking change in the public API.
#' Use `perform_resource_req()` for Bearer, DPoP, and mTLS-protected resource requests instead.
#'
#' @inheritParams perform_resource_req
#' @return Same value as [perform_resource_req()].
#' @export
perform_client_bearer_req <- function(
  token,
  url,
  method = "GET",
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE,
  check_url = TRUE,
  oauth_client = NULL,
  token_type = NULL,
  dpop_nonce = NULL,
  idempotent = NULL
) {
  deprecate_warn_pkg(
    when = "0.4.0.9000",
    what = "perform_client_bearer_req()",
    with = "perform_resource_req()",
    details = paste(
      "Use perform_resource_req() for Bearer, DPoP, and mTLS-protected resource requests"
    )
  )

  perform_resource_req(
    token = token,
    url = url,
    method = method,
    headers = headers,
    query = query,
    follow_redirect = follow_redirect,
    check_url = check_url,
    oauth_client = oauth_client,
    token_type = token_type,
    dpop_nonce = dpop_nonce,
    idempotent = idempotent
  )
}


# 2 Request validation and shaping ---------------------------------------------

#' Build the authenticated request state for a protected resource
#'
#' Used by [resource_req()] and [perform_resource_req()] to resolve the token
#' context, validate the target URL, attach authentication, and apply the
#' package's standard request defaults before the request is performed.
#'
#' @param token Either an [OAuthToken] object or a raw access-token string.
#' @param url Optional absolute URL supplied by the caller.
#' @param req Optional httr2 request object to use as the base request.
#' @param method Optional HTTP method override.
#' @param headers Optional named list or named character vector of headers.
#' @param query Optional named list of query parameters.
#' @param follow_redirect Whether redirects should remain enabled.
#' @param check_url Whether URL validation should run.
#' @param oauth_client Optional [OAuthClient].
#' @param token_type Optional token-type override.
#' @param dpop_nonce Optional DPoP nonce to include in the proof.
#' @return A named list with `req` and `token_info` entries.
#' @keywords internal
#' @noRd
prepare_client_bearer_request <- function(
  token,
  url = NULL,
  req = NULL,
  method = "GET",
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE,
  check_url = TRUE,
  oauth_client = NULL,
  token_type = NULL,
  dpop_nonce = NULL
) {
  token_info <- resolve_client_bearer_token(
    token = token,
    token_type = token_type
  )

  validate_client_bearer_token_context(
    token_type = token_info$token_type,
    oauth_client = oauth_client
  )

  validate_client_bearer_sender_constraints(
    token = token,
    access_token = token_info$access_token,
    token_type = token_info$token_type,
    oauth_client = oauth_client
  )

  target_url <- resolve_client_bearer_target_url(url = url, req = req)
  validate_client_bearer_url(target_url, check_url = check_url)

  req <- build_client_bearer_authorized_request(
    url = target_url,
    req = req,
    method = method,
    token = token,
    access_token = token_info$access_token,
    token_type = token_info$token_type,
    oauth_client = oauth_client,
    dpop_nonce = dpop_nonce
  )

  req <- finalize_client_bearer_request(
    req = req,
    headers = headers,
    query = query,
    follow_redirect = follow_redirect
  )

  list(req = req, token_info = token_info)
}

# 2.1 Token handling -----------------------------------------------------------

#' Resolve the target URL for an authorized API request
#'
#' Used by `prepare_client_bearer_request()` to support either a URL string or
#' a prebuilt httr2 request object as the request source.
#'
#' @param url Optional target URL string.
#' @param req Optional httr2 request object.
#' @return Scalar character URL extracted from `url` or `req`.
#' @keywords internal
#' @noRd
resolve_client_bearer_target_url <- function(url = NULL, req = NULL) {
  if (!inherits(req, "httr2_request")) {
    return(url)
  }

  req_url <- req[["url"]] %||% NULL
  if (!is_valid_string(req_url)) {
    err_input("httr2 request must have a non-empty URL")
  }

  as.character(req_url)
}

#' Resolve the access token and token type for an authorized API request
#'
#' Used by [resource_req()] before request construction. It accepts either
#' a raw access-token string or an [OAuthToken] object and applies the default
#' token type when the caller did not provide one.
#'
#' @param token Either an [OAuthToken] object or a raw access-token string.
#' @param token_type Optional token-type override for raw token strings.
#' @return A named list with `access_token` and `token_type` scalar string
#'   entries.
#' @keywords internal
#' @noRd
resolve_client_bearer_token <- function(
  token,
  token_type = NULL
) {
  access_token <- token
  effective_token_type <- NULL
  explicit_cnf_jkt <- NA_character_
  explicit_token_type <- !(is.null(token_type) ||
    (is.character(token_type) && length(token_type) == 1L && is.na(token_type)))

  if (S7::S7_inherits(token, class = OAuthToken)) {
    access_token <- token@access_token
    effective_token_type <- token@token_type
    explicit_cnf_jkt <- normalize_token_cnf(token@cnf %||% NULL)[["jkt"]] %||%
      NA_character_
  }

  if (isTRUE(explicit_token_type)) {
    effective_token_type <- token_type
  }

  if (!is_valid_string(access_token)) {
    err_input("access_token must be a non-empty string")
  }

  effective_token_type <- if (isTRUE(explicit_token_type)) {
    if (!is_valid_string(effective_token_type)) {
      err_input("token_type must be a single non-empty string")
    }
    as.character(effective_token_type)
  } else if (is_valid_string(effective_token_type)) {
    as.character(effective_token_type)
  } else if (is_valid_string(explicit_cnf_jkt)) {
    "DPoP"
  } else {
    "Bearer"
  }

  if (!(tolower(effective_token_type) %in% c("bearer", "dpop"))) {
    err_input("token_type must be either 'Bearer' or 'DPoP'")
  }

  list(
    access_token = access_token,
    token_type = effective_token_type
  )
}

#' Used by [resource_req()] after the effective token type is known. DPoP
#' requests need an [OAuthClient] because the client carries the private key
#' used to sign the DPoP proof.
#'
#' @param token_type Effective access-token type.
#' @param oauth_client Optional [OAuthClient] supplied to [resource_req()].
#' @return Invisibly returns `TRUE` when the token context is valid. Otherwise
#'   this function raises an input error.
#' @keywords internal
#' @noRd
validate_client_bearer_token_context <- function(token_type, oauth_client) {
  if (!is_dpop_token_type(token_type)) {
    return(invisible(TRUE))
  }

  if (
    is.null(oauth_client) ||
      !S7::S7_inherits(oauth_client, class = OAuthClient)
  ) {
    err_input("oauth_client must be an OAuthClient when token_type = 'DPoP'")
  }
  if (!client_has_dpop(oauth_client)) {
    err_input(
      "oauth_client with dpop_private_key is required for token_type = 'DPoP'"
    )
  }

  invisible(TRUE)
}

#' Validate sender-constraint bindings for an authorized API request
#'
#' Used by [resource_req()] before an outbound request is built. This
#' keeps locally configured DPoP keys aligned with any DPoP token `cnf$jkt`
#' binding before a proof is signed.
#'
#' @param token Original token input supplied to [resource_req()].
#' @param access_token Scalar access-token string.
#' @param token_type Effective access-token type.
#' @param oauth_client Optional [OAuthClient] supplied to [resource_req()].
#' @return Invisibly returns `TRUE` when sender constraints are locally valid.
#' @keywords internal
#' @noRd
validate_client_bearer_sender_constraints <- function(
  token,
  access_token,
  token_type,
  oauth_client
) {
  if (!is_dpop_token_type(token_type)) {
    return(invisible(TRUE))
  }

  validate_token_dpop_binding(
    oauth_client = oauth_client,
    token = token,
    access_token = access_token,
    error_context = "input"
  )
  validate_observed_dpop_cnf_required(
    oauth_client = oauth_client,
    token = token,
    access_token = access_token,
    error_context = "input"
  )

  invisible(TRUE)
}


# 2.2 Target URL validation ----------------------------------------------------

#' Validate the target URL for an authorized API request
#'
#' Used by [resource_req()] before credentials are attached to the request.
#' The helper enforces the public contract that resource URLs must be explicit
#' HTTP(S) URLs and then delegates host/scheme policy to [is_ok_host()].
#'
#' @param url Target resource URL.
#' @param check_url Whether URL validation should run.
#' @return Invisibly returns `TRUE` when the URL is accepted. Otherwise this
#'   function raises an input error.
#'
#' @keywords internal
#' @noRd
validate_client_bearer_url <- function(url, check_url = TRUE) {
  if (!isTRUE(check_url)) {
    return(invisible(TRUE))
  }

  if (!is_valid_string(url)) {
    err_input("url must be a non-empty string")
  }

  # Require an explicit scheme before delegating to is_ok_host(). is_ok_host()
  # intentionally normalizes schemeless inputs for convenience in other
  # contexts, but resource_req() documents that `url` must be absolute.
  if (!grepl("^[Hh][Tt][Tt][Pp][Ss]?://", url)) {
    err_input(c(
      "url must be an absolute URL with an explicit scheme (https:// or http://)",
      "i" = "Received a schemeless or non-HTTP(S) URL.",
      "i" = "Provide the full URL including the scheme, e.g. 'https://api.example.com/resource'."
    ))
  }

  if (!is_ok_host(url)) {
    err_input(c(
      "url is not allowed by host/scheme policy",
      "i" = "The URL must be absolute, use HTTPS (or target an allowed non-HTTPS host),",
      "i" = "and pass the `is_ok_host()` check. See `?is_ok_host` for details.",
      "i" = "Set `check_url = FALSE` to bypass this validation (not recommended)."
    ))
  }

  invisible(TRUE)
}


# 2.3 Request authentication ---------------------------------------------------

#' Build the authenticated resource request
#'
#' Used by [resource_req()] after token and URL validation. It applies the
#' requested HTTP method, sender-constrained mTLS settings, Bearer or DPoP
#' authentication, and the package's standard request defaults.
#'
#' @param url Target resource URL.
#' @param req Optional httr2 request object to use as the base request.
#' @param method HTTP method to set when it is a non-empty string.
#' @param token Original token input supplied to [resource_req()].
#' @param access_token Scalar access-token string.
#' @param token_type Effective token type, either `Bearer` or `DPoP`.
#' @param oauth_client Optional [OAuthClient] used for DPoP and mTLS behavior.
#' @param dpop_nonce Optional DPoP nonce to include in the proof.
#' @return An httr2 request object with access-token authentication attached.
#'
#' @keywords internal
#' @noRd
build_client_bearer_authorized_request <- function(
  url,
  req = NULL,
  method,
  token,
  access_token,
  token_type,
  oauth_client = NULL,
  dpop_nonce = NULL
) {
  if (is.null(req)) {
    req <- httr2::request(url)
  }

  if (is_valid_string(method)) {
    req <- httr2::req_method(req, toupper(method))
  }

  req <- req_apply_sender_constrained_mtls(
    req,
    token = token,
    oauth_client = oauth_client
  )

  if (is_dpop_token_type(token_type)) {
    return(
      req |>
        httr2::req_headers(Authorization = paste("DPoP", access_token)) |>
        req_add_dpop_proof(
          oauth_client,
          access_token = access_token,
          nonce = dpop_nonce
        ) |>
        add_req_defaults()
    )
  }

  req |>
    httr2::req_auth_bearer_token(access_token) |>
    add_req_defaults()
}


# 2.4 Optional headers ---------------------------------------------------------

#' Apply post-auth request shaping for an authorized API request
#'
#' Used after authentication has been attached so redirect policy, optional
#' headers, and optional query parameters are handled consistently for both URL
#' inputs and prebuilt httr2 request objects.
#'
#' @param req httr2 request object.
#' @param headers Optional named list or named character vector of headers.
#' @param query Optional named list of query parameters.
#' @param follow_redirect Whether redirects should remain enabled.
#' @return Updated httr2 request object.
#' @keywords internal
#' @noRd
finalize_client_bearer_request <- function(
  req,
  headers = NULL,
  query = NULL,
  follow_redirect = FALSE
) {
  # Security: disable redirects by default to prevent leaking the access token.
  if (!isTRUE(follow_redirect)) {
    req <- req_no_redirect(req)
  }

  req <- apply_client_bearer_headers(req, headers)

  if (is.list(query) && length(query) > 0L) {
    query <- compact_list(query)
    req <- do.call(httr2::req_url_query, c(list(req), query))
  }

  req
}

#' Apply caller-supplied headers to an authorized API request
#'
#' Used by [resource_req()] after access-token authentication has been
#' attached. The helper accepts the package's supported header input shapes and
#' drops auth-related headers so callers cannot override the token credentials.
#'
#' @param req httr2 request object.
#' @param headers Optional named list or named character vector of headers.
#' @return Updated httr2 request object.
#'
#' @keywords internal
#' @noRd
apply_client_bearer_headers <- function(req, headers = NULL) {
  headers <- normalize_client_bearer_headers(headers)
  if (is.null(headers) || length(headers) == 0L) {
    return(req)
  }

  headers <- drop_client_bearer_auth_headers(headers)
  if (length(headers) == 0L) {
    return(req)
  }

  do.call(httr2::req_headers, c(list(req), headers))
}

#' Normalize caller-supplied headers for an authorized API request
#'
#' Used by `apply_client_bearer_headers()` to accept both named lists and named
#' character vectors while rejecting ambiguous inputs.
#'
#' @param headers Optional header input supplied by the caller.
#' @return A named list of headers, or `NULL` when no usable headers were
#'   supplied.
#'
#' @keywords internal
#' @noRd
normalize_client_bearer_headers <- function(headers = NULL) {
  if (is.null(headers) || length(headers) == 0L) {
    return(NULL)
  }

  if (is.list(headers)) {
    return(headers)
  }

  if (is.character(headers) && !is.null(names(headers))) {
    return(as.list(headers))
  }

  warn_pkg(
    "Ignoring invalid client bearer headers",
    c(
      "!" = "The {.arg headers} argument must be a named list or named character vector."
    )
  )
  NULL
}

#' Drop custom Authorization and DPoP headers
#'
#' Used by `apply_client_bearer_headers()` to keep caller-supplied headers from
#' replacing the authentication scheme and proof that [resource_req()] just
#' attached.
#'
#' @param headers Named list of normalized headers.
#' @return `headers` with custom `Authorization` and `DPoP` entries removed.
#'
#' @keywords internal
#' @noRd
drop_client_bearer_auth_headers <- function(headers) {
  header_names <- names(headers)
  if (is.null(header_names)) {
    return(headers)
  }

  lowered <- tolower(header_names)
  is_auth <- lowered == "authorization"
  is_dpop <- lowered == "dpop"
  drop_header <- is_auth | is_dpop

  if (!any(drop_header, na.rm = TRUE)) {
    return(headers)
  }

  if (any(is_dpop, na.rm = TRUE)) {
    warn_pkg(
      "Ignoring custom authentication headers",
      c(
        "!" = "Custom {.code Authorization} or {.code DPoP} headers were ignored because token authentication is already set."
      )
    )
  } else {
    warn_pkg(
      "Ignoring custom authentication headers",
      c(
        "!" = "Custom {.code Authorization} header was ignored because the bearer token is already set."
      )
    )
  }

  headers[!drop_header]
}
