# This file contains the helper that builds outbound API requests with the
# current access token already attached.
# Use it after login when you want an httr2 request that already carries the
# right Bearer or DPoP authentication and the package's normal HTTP defaults.

# 1 Authenticated request helper ------------------------------------------

## 1.1 Build request with access token ------------------------------------

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
#'   URLs, plain HTTP to non-loopback hosts, and – when
#'   `options(shinyOAuth.allowed_hosts)` is set – hosts outside the allowlist.
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
  original_token <- token

  # Resolve token to string ----------------------------------------------------
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
    !is.character(effective_token_type) || length(effective_token_type) != 1L
  ) {
    effective_token_type <- NA_character_
  }
  effective_token_type <- if (
    !is.na(effective_token_type) && nzchar(effective_token_type)
  ) {
    as.character(effective_token_type)[1]
  } else {
    "Bearer"
  }
  if (!(tolower(effective_token_type) %in% c("bearer", "dpop"))) {
    err_input("token_type must be either 'Bearer' or 'DPoP'")
  }
  if (is_dpop_token_type(effective_token_type)) {
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
  }

  # Validate URL ----------------------------------------------------------------
  if (isTRUE(check_url)) {
    if (!is_valid_string(url)) {
      err_input("url must be a non-empty string")
    }

    # Require an explicit scheme (https:// or http://) before delegating to
    # is_ok_host(). is_ok_host() intentionally normalises schemeless inputs
    # for convenience in other contexts, but client_bearer_req() documents
    # that `url` must be an absolute URL. Accepting schemeless strings here
    # would silently weaken that contract.
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
  }

  # Build base request ---------------------------------------------------------
  req <- httr2::request(url)
  if (is_valid_string(method)) {
    req <- httr2::req_method(req, toupper(method))
  }

  req <- req_apply_sender_constrained_mtls(
    req,
    token = original_token,
    oauth_client = oauth_client
  )

  if (is_dpop_token_type(effective_token_type)) {
    req <- req |>
      httr2::req_headers(Authorization = paste("DPoP", access_token)) |>
      req_add_dpop_proof(
        oauth_client,
        access_token = access_token,
        nonce = dpop_nonce
      ) |>
      add_req_defaults()
  } else {
    req <- req |>
      httr2::req_auth_bearer_token(access_token) |>
      add_req_defaults()
  }

  # Security: disable redirects by default to prevent leaking the access token
  if (!isTRUE(follow_redirect)) {
    req <- req_no_redirect(req)
  }

  # Extra headers
  if (!is.null(headers) && length(headers) > 0) {
    # Accept both named lists (preferred) and named character vectors (common)
    if (!is.list(headers)) {
      if (is.character(headers) && !is.null(names(headers))) {
        headers <- as.list(headers)
      } else {
        cli::cli_warn(
          "Ignoring 'headers' because it must be a named list or named character vector"
        )
        headers <- NULL
      }
    }

    if (!is.null(headers) && length(headers) > 0) {
      # Drop any user-supplied Authorization/DPoP header to avoid overriding
      # the auth scheme and proof we just attached above. Header names are
      # case-insensitive.
      hdr_names <- names(headers)
      if (!is.null(hdr_names)) {
        lowered <- tolower(hdr_names)
        is_auth <- lowered == "authorization"
        is_dpop <- lowered == "dpop"
        drop_header <- is_auth | is_dpop
        if (any(drop_header, na.rm = TRUE)) {
          if (any(is_dpop, na.rm = TRUE)) {
            cli::cli_warn(
              "Ignoring custom 'Authorization' or 'DPoP' header; token authentication is already set"
            )
          } else {
            cli::cli_warn(
              "Ignoring custom 'Authorization' header; bearer token is already set"
            )
          }
          headers <- headers[!drop_header]
        }
      }

      if (length(headers) > 0) {
        req <- do.call(httr2::req_headers, c(list(req), headers))
      }
    }
  }

  # Query params
  if (is.list(query) && length(query) > 0) {
    # Drop NULL/NA
    q <- compact_list(query)
    req <- do.call(httr2::req_url_query, c(list(req), q))
  }

  req
}
