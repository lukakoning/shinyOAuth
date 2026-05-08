# This file contains the helper that builds outbound API requests with the
# current access token already attached.
# Use it after login when you want an httr2 request that already carries the
# right Bearer or DPoP authentication and the package's normal HTTP defaults.

# 1 Authenticated request helper -----------------------------------------------

#' Build an authorized httr2 request with an OAuth access token
#'
#' @description
#' Convenience helper to reduce boilerplate when calling downstream APIs.
#' It creates an [httr2::request()] for the given URL, attaches the
#' appropriate `Authorization` header for the supplied token type, and applies
#' the package's standard HTTP defaults (timeout and User-Agent).
#'
#' Accepts either a raw access token string or an [OAuthToken] object.
#'
#' @param token Either an [OAuthToken] object or a raw access token string.
#' @param url The absolute URL to call.
#' @param method Optional HTTP method (character). Defaults to "GET".
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
#' @param dpop_nonce Optional DPoP nonce to embed in the proof for this
#'   request. This is primarily useful after a resource server challenges with
#'   `DPoP-Nonce`.
#'
#' @return An httr2 request object, ready to be further customized or
#'   performed with [httr2::req_perform()].
#'
#' @section Side effects:
#' This function does not perform network I/O. It reads shinyOAuth package
#' options through [is_ok_host()] and HTTP-default helpers, may emit warnings
#' when unsafe custom auth headers are ignored, and may read configured mTLS
#' certificate files when validating certificate-bound access tokens.
#'
#' @example inst/examples/client_bearer_req.R
#'
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
  token_info <- resolve_client_bearer_token(token, token_type)

  validate_client_bearer_token_context(
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


# 2 Request validation and shaping ---------------------------------------------

# 2.1 Token handling -----------------------------------------------------------

#' Resolve the access token and token type for an authorized API request
#'
#' Used by [client_bearer_req()] before request construction. It accepts either
#' a raw access-token string or an [OAuthToken] object and applies the default
#' token type when the caller did not provide one.
#'
#' @param token Either an [OAuthToken] object or a raw access-token string.
#' @param token_type Optional token-type override for raw token strings.
#' @return A named list with `access_token` and `token_type` scalar string
#'   entries.
#' @keywords internal
#' @noRd
resolve_client_bearer_token <- function(token, token_type = NULL) {
  access_token <- token
  effective_token_type <- token_type %||% NA_character_

  if (S7::S7_inherits(token, class = OAuthToken)) {
    access_token <- token@access_token
    effective_token_type <- token@token_type %||% effective_token_type
  }

  if (!is_valid_string(access_token)) {
    err_input("access_token must be a non-empty string")
  }

  if (
    !is.character(effective_token_type) ||
      length(effective_token_type) != 1L
  ) {
    effective_token_type <- NA_character_
  }

  effective_token_type <- if (
    !is.na(effective_token_type) && nzchar(effective_token_type)
  ) {
    as.character(effective_token_type)[[1]]
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
#' Used by [client_bearer_req()] after the effective token type is known. DPoP
#' requests need an [OAuthClient] because the client carries the private key
#' used to sign the DPoP proof.
#'
#' @param token_type Effective access-token type.
#' @param oauth_client Optional [OAuthClient] supplied to [client_bearer_req()].
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


# 2.2 Target URL validation ----------------------------------------------------

#' Validate the target URL for an authorized API request
#'
#' Used by [client_bearer_req()] before credentials are attached to the request.
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
  # contexts, but client_bearer_req() documents that `url` must be absolute.
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
#' Used by [client_bearer_req()] after token and URL validation. It applies the
#' requested HTTP method, sender-constrained mTLS settings, Bearer or DPoP
#' authentication, and the package's standard request defaults.
#'
#' @param url Target resource URL.
#' @param method HTTP method to set when it is a non-empty string.
#' @param token Original token input supplied to [client_bearer_req()].
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
#' Used by [client_bearer_req()] after access-token authentication has been
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
#' replacing the authentication scheme and proof that [client_bearer_req()] just
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
