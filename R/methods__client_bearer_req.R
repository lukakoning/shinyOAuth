# This file contains the helper that builds outbound API requests with the
# current access token already attached
# Used for creating an httr2 request that already includes authentication and
# the package's normal HTTP defaults

# 1 Authenticated request helper -----------------------------------------------

#' Build an authenticated httr2 request for a protected resource
#'
#' @description
#' Small helper for calling downstream APIs with an access token.
#' It creates an [httr2::request()] for the given URL, attaches the right
#' authorization header for the token type, and applies shinyOAuth's standard
#' HTTP defaults. Use [perform_resource_req()] when you want
#' shinyOAuth to also perform the request and handle DPoP nonce challenges for
#' you.
#'
#' Accepts either a raw access token string or an [OAuthToken] object.
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
#'   validate any `cnf` thumbprint from an [OAuthToken] or raw JWT access
#'   token string.
#' @param token_type Optional override for the access token type when `token`
#'   is supplied as a raw string. Supported values are `Bearer` and `DPoP`.
#'   Invalid or multi-valued inputs are rejected. When omitted, shinyOAuth
#'   preserves `OAuthToken@token_type` and also infers `DPoP` from a raw JWT
#'   access token's `cnf.jkt` binding when `oauth_client` carries a DPoP key.
#' @param dpop_nonce Optional DPoP nonce to embed in the proof for this
#'   request. This is primarily useful after a resource server challenges with
#'   `DPoP-Nonce`.
#'
#' @return An httr2 request object, ready to be performed with
#'   [httr2::req_perform()]. Callers may still add headers or query
#'   parameters, but when the effective token type is `DPoP` they must not
#'   change the request method or base URL after calling
#'   [resource_req()] because the proof is already bound to those values.
#'
#' @section Side effects:
#' This function does not perform network I/O. It reads shinyOAuth package
#' options through [is_ok_host()] and HTTP-default helpers, may emit warnings
#' when unsafe custom auth headers are ignored, and may read configured mTLS
#' certificate files when validating certificate-bound access tokens.
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
  token_info <- resolve_client_bearer_token(
    token = token,
    token_type = token_type,
    oauth_client = oauth_client
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
  validate_client_bearer_url(url, check_url = check_url)

  req <- build_client_bearer_authorized_request(
    url = url,
    method = method,
    token = token,
    access_token = token_info$access_token,
    token_type = token_info$token_type,
    oauth_client = oauth_client,
    dpop_nonce = dpop_nonce
  )

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

#' `r lifecycle::badge("deprecated")`
#'
#' Deprecated alias for [resource_req()].
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
  lifecycle::deprecate_warn(
    when = "0.4.0.9000",
    what = "client_bearer_req()",
    with = "resource_req()",
    details = paste(
      "Use resource_req() for Bearer, DPoP, and mTLS-protected resource requests."
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

#' Perform an authenticated httr2 request for a protected resource
#'
#' @description
#' Companion to [resource_req()] for callers who want shinyOAuth to both
#' build and perform the request. For DPoP-bound access tokens, this helper
#' reuses shinyOAuth's existing nonce-challenge handling and retries one
#' `use_dpop_nonce` response with a fresh proof that includes the supplied
#' `DPoP-Nonce`, as described by RFC 9449.
#'
#' @inheritParams resource_req
#' @param idempotent Optional logical controlling generic transport and
#'   transient-HTTP retries in `req_with_retry()`. When `NULL` (the default),
#'   shinyOAuth infers this from the final request method using standard HTTP
#'   idempotency semantics (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`,
#'   `DELETE`). DPoP nonce challenges are replayed once regardless, as required
#'   by RFC 9449.
#'
#' @return An httr2 response object.
#'
#' @section Side effects:
#' Performs network I/O, may retry idempotent requests through shinyOAuth's
#' HTTP retry helpers, and when the effective token type is `DPoP` may mint a
#' second proof and replay the request once after a server-provided nonce
#' challenge.
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
  req <- resource_req(
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

  token_info <- resolve_client_bearer_token(
    token = token,
    token_type = token_type,
    oauth_client = oauth_client
  )

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

#' `r lifecycle::badge("deprecated")`
#'
#' Deprecated alias for [perform_resource_req()].
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
  lifecycle::deprecate_warn(
    when = "0.4.0.9000",
    what = "perform_client_bearer_req()",
    with = "perform_resource_req()",
    details = paste(
      "Use perform_resource_req() for Bearer, DPoP, and mTLS-protected resource requests."
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

# 2.1 Token handling -----------------------------------------------------------

#' Resolve the access token and token type for an authorized API request
#'
#' Used by [resource_req()] before request construction. It accepts either
#' a raw access-token string or an [OAuthToken] object and applies the default
#' token type when the caller did not provide one.
#'
#' @param token Either an [OAuthToken] object or a raw access-token string.
#' @param token_type Optional token-type override for raw token strings.
#' @param oauth_client Optional [OAuthClient] whose configured DPoP key may
#'   imply an effective `DPoP` token type for raw JWT access tokens carrying a
#'   `cnf.jkt` binding.
#' @return A named list with `access_token` and `token_type` scalar string
#'   entries.
#' @keywords internal
#' @noRd
resolve_client_bearer_token <- function(
  token,
  token_type = NULL,
  oauth_client = NULL
) {
  access_token <- token
  effective_token_type <- NULL
  explicit_token_type <- !(is.null(token_type) ||
    (is.character(token_type) && length(token_type) == 1L && is.na(token_type)))

  if (S7::S7_inherits(token, class = OAuthToken)) {
    access_token <- token@access_token
    effective_token_type <- token@token_type
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
  } else if (
    S7::S7_inherits(oauth_client, class = OAuthClient) &&
      client_has_dpop(oauth_client) &&
      is_valid_string(token_cnf_jkt(token = token, access_token = access_token))
  ) {
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

#' Validate token-type requirements for an authorized API request
#'
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
#' @section Side effects:
#' Reads `shinyOAuth.allowed_hosts` and related host-policy options indirectly
#' through [is_ok_host()].
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
#' @param method HTTP method to set when it is a non-empty string.
#' @param token Original token input supplied to [resource_req()].
#' @param access_token Scalar access-token string.
#' @param token_type Effective token type, either `Bearer` or `DPoP`.
#' @param oauth_client Optional [OAuthClient] used for DPoP and mTLS behavior.
#' @param dpop_nonce Optional DPoP nonce to include in the proof.
#' @return An httr2 request object with access-token authentication attached.
#'
#' @section Side effects:
#' Reads shinyOAuth HTTP-default options through `add_req_defaults()`. When the
#' token requires mTLS sender constraints, this may read configured certificate
#' files through mTLS helpers.
#'
#' @keywords internal
#' @noRd
build_client_bearer_authorized_request <- function(
  url,
  method,
  token,
  access_token,
  token_type,
  oauth_client = NULL,
  dpop_nonce = NULL
) {
  req <- httr2::request(url)
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
#' @section Side effects:
#' Emits warnings when `headers` has an unsupported shape or includes
#' auth-related headers that must be ignored.
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
#' @section Side effects:
#' Emits a warning when unsupported header input is ignored.
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

  cli::cli_warn(
    "Ignoring 'headers' because it must be a named list or named character vector"
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
#' @section Side effects:
#' Emits a warning when auth-related headers are ignored.
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
    cli::cli_warn(
      "Ignoring custom 'Authorization' or 'DPoP' header; token authentication is already set"
    )
  } else {
    cli::cli_warn(
      "Ignoring custom 'Authorization' header; bearer token is already set"
    )
  }

  headers[!drop_header]
}
