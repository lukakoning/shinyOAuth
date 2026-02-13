#' Build an authorized httr2 request with Bearer token
#'
#' @description
#' Convenience helper to reduce boilerplate when calling downstream APIs.
#' It creates an [httr2::request()] for the given URL, attaches the
#' `Authorization: Bearer <token>` header, and applies the package's standard
#' HTTP defaults (timeout and User-Agent).
#'
#' Accepts either a raw access token string or an [OAuthToken] object.
#'
#' @param token Either an [OAuthToken] object or a raw access token string.
#' @param url The absolute URL to call.
#' @param method Optional HTTP method (character). Defaults to "GET".
#' @param headers Optional named list or named character vector of extra
#'   headers to set on the request. Header names are case-insensitive.
#'   Any user-supplied `Authorization`
#'   header is ignored to ensure the Bearer token set by this function is not
#'   overridden.
#' @param query Optional named list of query parameters to append to the URL.
#' @param follow_redirect Logical. If `FALSE` (the default), HTTP redirects
#'   are disabled to prevent leaking the Bearer token to unexpected hosts.
#'   Set to `TRUE` only if you trust all possible redirect targets and
#'   understand the security implications.
#' @param check_url Logical. If `TRUE` (the default), validates `url` against
#'   [is_ok_host()] before attaching the Bearer token. This rejects relative
#'   URLs, plain HTTP to non-loopback hosts, and – when
#'   `options(shinyOAuth.allowed_hosts)` is set – hosts outside the allowlist.
#'   Set to `FALSE` only if you have already validated the URL and understand
#'   the security implications.
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
  check_url = TRUE
) {
  # Resolve token to string ----------------------------------------------------
  access_token <- token
  if (S7::S7_inherits(token, class = OAuthToken)) {
    access_token <- token@access_token
  }

  if (!is_valid_string(access_token)) {
    err_input("access_token must be a non-empty string")
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
  req <- httr2::request(url) |>
    httr2::req_auth_bearer_token(access_token) |>
    add_req_defaults()

  # Security: disable redirects by default to prevent leaking Bearer token
  if (!isTRUE(follow_redirect)) {
    req <- req_no_redirect(req)
  }

  # Apply method if supplied
  if (is_valid_string(method)) {
    req <- httr2::req_method(req, toupper(method))
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
      # Drop any user-supplied Authorization header to avoid overriding the
      # bearer token that we just attached above. Header names are case-insensitive.
      hdr_names <- names(headers)
      if (!is.null(hdr_names)) {
        is_auth <- tolower(hdr_names) == "authorization"
        if (any(is_auth, na.rm = TRUE)) {
          # Warn and remove those entries
          cli::cli_warn(
            "Ignoring custom 'Authorization' header; bearer token is already set"
          )
          headers <- headers[!is_auth]
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
