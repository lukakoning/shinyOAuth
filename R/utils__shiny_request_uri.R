# This file contains the helpers that publish Request Objects through a live
# Shiny session
# Used for caller-managed request_uri support on the app's existing Shiny URL

# 1 Shiny request_uri helpers -------------------------------------------------

## 1.1 Session URL helpers ----------------------------------------------------

#' Normalize a public request_uri base URL override
#'
#' Used when deployments need the authorization server to fetch published
#' Request Objects through a public host or proxy URL instead of the current
#' browser-visible Shiny origin.
#'
#' @param base_url Optional absolute base URL override.
#' @param arg Human-readable argument label used in validation errors.
#' @return Normalized absolute base URL string, or `NULL` when unset.
#' @keywords internal
#' @noRd
normalize_request_uri_base_url <- function(
  base_url,
  arg = "base_url"
) {
  if (is.null(base_url)) {
    return(NULL)
  }

  if (!is_valid_string(base_url)) {
    err_input(
      sprintf(
        "{.arg %s} must be NULL or a single non-empty absolute URL.",
        arg
      )
    )
  }

  validate_endpoint(
    base_url,
    getOption("shinyOAuth.allowed_hosts", default = NULL)
  )

  parsed <- httr2::url_parse(base_url)
  query <- as.character(parsed$query %||% "")
  fragment <- as.character(parsed$fragment %||% "")

  if (nzchar(query) || nzchar(fragment)) {
    err_input(
      sprintf(
        "{.arg %s} must not include a query string or fragment.",
        arg
      )
    )
  }

  port <- as.character(parsed$port %||% "")
  port <- if (!is.na(port) && nzchar(port)) paste0(":", port) else ""

  path <- as.character(parsed$path %||% "")
  path <- if (!nzchar(path) || identical(path, "/")) {
    ""
  } else {
    path <- sub("/+$", "", path)
    if (!startsWith(path, "/")) paste0("/", path) else path
  }

  paste0(
    tolower(as.character(parsed$scheme %||% "")),
    "://",
    tolower(as.character(parsed$hostname %||% "")),
    port,
    path
  )
}

#' Build the base URL for Shiny session data-object endpoints
#'
#' Mirrors Shiny's client-side path handling so relative `session/.../dataobj`
#' paths returned by `session$registerDataObj()` become absolute URLs on the
#' current app origin.
#'
#' @param session Active Shiny session.
#' @param base_url Optional absolute base URL override used instead of the
#'   browser-visible session origin.
#' @return Absolute base URL string.
#' @keywords internal
#' @noRd
shiny_request_uri_base_url <- function(session, base_url = NULL) {
  base_url <- normalize_request_uri_base_url(base_url)
  if (is_valid_string(base_url)) {
    return(base_url)
  }

  if (is.null(session)) {
    err_config("A live Shiny session is required to publish request_uri values")
  }

  protocol <- tryCatch(
    as.character(session$clientData$url_protocol %||% NA_character_),
    error = function(...) NA_character_
  )
  hostname <- tryCatch(
    as.character(session$clientData$url_hostname %||% NA_character_),
    error = function(...) NA_character_
  )
  port <- tryCatch(
    as.character(session$clientData$url_port %||% NA_character_),
    error = function(...) NA_character_
  )
  pathname <- tryCatch(
    as.character(session$clientData$url_pathname %||% NA_character_),
    error = function(...) NA_character_
  )

  if (!is_valid_string(protocol) || !grepl("^[A-Za-z][A-Za-z0-9+.-]*:$", protocol)) {
    err_config("Could not determine the Shiny app URL protocol for request_uri publishing")
  }
  if (!is_valid_string(hostname)) {
    err_config("Could not determine the Shiny app hostname for request_uri publishing")
  }
  if (!is_valid_string(pathname) || !startsWith(pathname, "/")) {
    err_config("Could not determine the Shiny app path for request_uri publishing")
  }

  base_path <- sub("/[^/]*$", "", pathname)
  port_suffix <- if (is_valid_string(port)) paste0(":", port) else ""

  paste0(protocol, "//", hostname, port_suffix, base_path)
}

## 1.2 Response builders ------------------------------------------------------

#' Serve one published Request Object through a Shiny data-object endpoint
#'
#' Used as the `filterFunc` passed to `session$registerDataObj()` for
#' caller-managed `request_uri` values.
#'
#' @param data Registered Request Object data.
#' @param req Rook request environment.
#' @return Rook response list.
#' @keywords internal
#' @noRd
serve_shiny_request_object <- function(data, req) {
  method <- toupper(
    as.character(
      req$REQUEST_METHOD %||% req$request_method %||% req$method %||% "GET"
    )[[1]]
  )
  headers <- c(
    "Content-Type" = "application/oauth-authz-req+jwt",
    "Cache-Control" = "no-store",
    "Pragma" = "no-cache",
    "X-Content-Type-Options" = "nosniff"
  )

  if (!(method %in% c("GET", "HEAD"))) {
    return(list(
      status = 405L,
      headers = c(headers, Allow = "GET, HEAD"),
      body = "Method not allowed"
    ))
  }

  expires_at <- data$expires_at %||% NULL
  if (!is.null(expires_at) && isTRUE(Sys.time() > expires_at)) {
    return(list(
      status = 410L,
      headers = c(
        headers[names(headers) != "Content-Type"],
        "Content-Type" = "text/plain; charset=utf-8"
      ),
      body = if (identical(method, "HEAD")) "" else "Request Object expired"
    ))
  }

  list(
    status = 200L,
    headers = headers,
    body = if (identical(method, "HEAD")) "" else data$request_object
  )
}

## 1.3 Publisher --------------------------------------------------------------

#' Publish a Request Object on the current Shiny app origin
#'
#' Registers a session data-object endpoint, then returns the absolute URL that
#' an authorization server can fetch via `request_uri`.
#'
#' @param session Active Shiny session.
#' @param request_object Compact Request Object JWT or JWE.
#' @param request_handle_id Optional stable handle identifier.
#' @param expires_at Optional expiry timestamp for the published object.
#' @param base_url Optional absolute base URL override used instead of the
#'   browser-visible session origin.
#' @return Absolute request-object URL.
#' @keywords internal
#' @noRd
publish_shiny_request_object <- function(
  session,
  request_object,
  request_handle_id = NULL,
  expires_at = NULL,
  base_url = NULL
) {
  if (!is_valid_string(request_object)) {
    err_config("request_object must be a single non-empty string")
  }

  object_name <- if (is_valid_string(request_handle_id)) {
    paste0("oauth-request-", request_handle_id)
  } else {
    paste0("oauth-request-", random_urlsafe(32))
  }

  relative_url <- tryCatch(
    {
      session$registerDataObj(
        object_name,
        list(
          request_object = request_object,
          expires_at = expires_at
        ),
        serve_shiny_request_object
      )
    },
    error = function(e) {
      err_config(c(
        "x" = "Failed to register a Shiny request_uri endpoint",
        "i" = conditionMessage(e)
      ))
    }
  )

  if (!is_valid_string(relative_url)) {
    err_config("Shiny request_uri registration did not return a usable URL")
  }

  absolute_url <- paste0(
    shiny_request_uri_base_url(session, base_url = base_url),
    if (startsWith(relative_url, "/")) "" else "/",
    relative_url
  )
  validate_endpoint(
    absolute_url,
    getOption("shinyOAuth.allowed_hosts", default = NULL)
  )

  absolute_url
}
