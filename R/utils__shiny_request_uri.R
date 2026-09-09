# This file contains the helpers that publish Request Objects through a live
# Shiny app
# Used for caller-managed request_uri support on the app's existing Shiny URL

# 1 Shiny request_uri helpers -------------------------------------------------

## 1.1 Session URL helpers ----------------------------------------------------

#' Require HTTPS for a caller-managed request_uri
#'
#' Used for caller-managed Request Object publication flows. RFC 9101 Section
#' 5.2 requires client-provided `request_uri` values to use HTTPS.
#'
#' @param request_uri Absolute request URI string.
#' @param subject Human-readable label used in the warning body.
#' @return Invisibly returns `TRUE` for an HTTPS URI; otherwise raises a
#'   configuration error.
#' @keywords internal
#' @noRd
require_https_request_uri <- function(
  request_uri,
  subject = "The published `request_uri`"
) {
  if (!is_valid_string(request_uri)) {
    return(invisible(TRUE))
  }

  parsed <- try(httr2::url_parse(request_uri), silent = TRUE)
  if (inherits(parsed, "try-error")) {
    return(invisible(TRUE))
  }

  scheme <- tolower(as.character(parsed[["scheme"]] %||% ""))
  host <- as.character(parsed[["hostname"]] %||% "")

  if (!nzchar(host) || identical(scheme, "https")) {
    return(invisible(TRUE))
  }

  err_config(
    c(
      "x" = paste(subject, "must use HTTPS."),
      "i" = paste0("Got scheme: ", toupper(scheme)),
      "i" = paste(
        "RFC 9101 Section 5.2 requires client-provided request_uri values",
        "to use HTTPS."
      )
    )
  )
}

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
        "`%s` must be NULL or a single non-empty absolute URL.",
        arg
      )
    )
  }

  if (has_uri_fragment(base_url)) {
    err_input(sprintf(
      "`%s` must not include a query string or fragment.",
      arg
    ))
  }

  validate_endpoint(
    base_url,
    getOption("shinyOAuth.allowed_hosts", default = NULL)
  )

  parsed <- httr2::url_parse(base_url)
  query <- as.character(parsed[["query"]] %||% "")
  fragment <- as.character(parsed[["fragment"]] %||% "")

  if (nzchar(query) || nzchar(fragment)) {
    err_input(
      sprintf(
        "`%s` must not include a query string or fragment.",
        arg
      )
    )
  }

  port <- as.character(parsed[["port"]] %||% "")
  port <- if (!is.na(port) && nzchar(port)) paste0(":", port) else ""

  path <- as.character(parsed[["path"]] %||% "")
  path <- if (!nzchar(path) || identical(path, "/")) {
    ""
  } else {
    path <- sub("/+$", "", path)
    if (!startsWith(path, "/")) paste0("/", path) else path
  }

  paste0(
    tolower(as.character(parsed[["scheme"]] %||% "")),
    "://",
    tolower(as.character(parsed[["hostname"]] %||% "")),
    port,
    path
  )
}

#' Build the public base URL for the Shiny app
#'
#' Mirrors Shiny client-side path handling to locate the current app root.
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

  if (
    !is_valid_string(protocol) || !grepl("^[A-Za-z][A-Za-z0-9+.-]*:$", protocol)
  ) {
    err_config(
      "Could not determine the Shiny app URL protocol for request_uri publishing"
    )
  }
  if (!is_valid_string(hostname)) {
    err_config(
      "Could not determine the Shiny app hostname for request_uri publishing"
    )
  }
  if (!is_valid_string(pathname) || !startsWith(pathname, "/")) {
    err_config(
      "Could not determine the Shiny app path for request_uri publishing"
    )
  }

  base_path <- sub("/[^/]*$", "", pathname)
  port_suffix <- if (is_valid_string(port)) paste0(":", port) else ""

  paste0(protocol, "//", hostname, port_suffix, base_path)
}

## 1.2 Response builders ------------------------------------------------------

#' Build the response for a published Request Object
#'
#' Used by the app-level request-object HTTP handler.
#'
#' @param data Registered Request Object data.
#' @param req Rook request environment.
#' @return Rook response list.
#' @keywords internal
#' @noRd
serve_shiny_request_object <- function(data, req) {
  method <- toupper(
    as.character(
      req[["REQUEST_METHOD"]] %||%
        req[["request_method"]] %||%
        req[["method"]] %||%
        "GET"
    )[[1]]
  )
  headers <- c(
    "Content-Type" = "application/oauth-authz-req+jwt",
    "Cache-Control" = "no-store",
    "Pragma" = "no-cache",
    "X-Content-Type-Options" = "nosniff"
  )
  gone_headers <- c(
    headers[names(headers) != "Content-Type"],
    "Content-Type" = "text/plain; charset=utf-8"
  )

  if (!(method %in% c("GET", "HEAD"))) {
    return(list(
      status = 405L,
      headers = c(headers, Allow = "GET, HEAD"),
      body = "Method not allowed"
    ))
  }

  usage_state <- data[["usage_state"]] %||% NULL
  if (is.environment(usage_state) && isTRUE(usage_state$consumed)) {
    return(list(
      status = 410L,
      headers = gone_headers,
      body = if (identical(method, "HEAD")) {
        ""
      } else {
        "Request Object already used"
      }
    ))
  }

  expires_at <- data[["expires_at"]] %||% NULL
  if (!is.null(expires_at) && isTRUE(Sys.time() > expires_at)) {
    return(list(
      status = 410L,
      headers = gone_headers,
      body = if (identical(method, "HEAD")) "" else "Request Object expired"
    ))
  }

  if (identical(method, "GET") && is.environment(usage_state)) {
    usage_state$consumed <- TRUE
  }

  list(
    status = 200L,
    headers = headers,
    body = if (identical(method, "HEAD")) {
      ""
    } else {
      data[["request_object"]]
    }
  )
}

## 1.3 Publisher --------------------------------------------------------------

#' Publish a Request Object on the current Shiny app origin
#'
#' Uses an independent random handle and the client's state store. The app UI
#' wrapper serves the object without exposing a Shiny session-routing token.
#'
#' @param session Active Shiny session.
#' @param request_object Compact Request Object JWT or JWE.
#' @param request_handle_id Legacy argument; handles are independently random.
#' @param expires_at Optional expiry timestamp, capped at 120 seconds.
#' @param base_url Optional absolute base URL override used instead of the
#'   browser-visible session origin.
#' @param oauth_client OAuth client whose state store backs the app route.
#' @return Absolute request-object URL.
#' @keywords internal
#' @noRd
publish_shiny_request_object <- function(
  session,
  request_object,
  request_handle_id = NULL,
  expires_at = NULL,
  base_url = NULL,
  oauth_client
) {
  S7::check_is_S7(oauth_client, class = OAuthClient)
  if (!is_valid_string(request_object)) {
    err_config("request_object must be a single non-empty string")
  }

  public_base_url <- shiny_request_uri_base_url(session, base_url = base_url)
  require_https_request_uri(public_base_url)

  store <- oauth_client@state_store
  require_request_object_atomic_store(store)
  now <- as.numeric(Sys.time())
  expiry <- if (is.null(expires_at)) now + 120 else as.numeric(expires_at)
  if (length(expiry) != 1L || !is.finite(expiry)) {
    err_config("Request Object expiry must be a single finite timestamp")
  }
  expiry <- as.POSIXct(min(expiry, now + 120), origin = "1970-01-01")
  handle <- random_urlsafe(43)
  absolute_url <- paste0(
    public_base_url,
    "/?",
    shiny_request_object_param,
    "=",
    handle
  )
  validate_endpoint(
    absolute_url,
    getOption("shinyOAuth.allowed_hosts", default = NULL)
  )
  require_https_request_uri(absolute_url)
  store$set(
    shiny_request_object_key(oauth_client, handle),
    list(
      request_object = request_object,
      expires_at = expiry
    )
  )
  absolute_url
}

shiny_request_object_param <- "shinyOAuth_request_object"

shiny_request_object_key <- function(client, handle) {
  paste0(
    "request_object_",
    string_digest(
      paste(
        client@client_id,
        client@provider@name,
        client@redirect_uri,
        handle,
        sep = "\n"
      ),
      key = NULL
    )
  )
}

require_request_object_atomic_store <- function(store) {
  if (!is.function(store$take) && !inherits(store, "cache_mem")) {
    err_config(paste(
      "Request Object publication requires atomic `$take(key, missing)`",
      "or cachem::cache_mem() for a single-process app"
    ))
  }
  invisible(TRUE)
}

# Return NULL for ordinary app requests; all handle requests terminate here.
shiny_request_object_http_handler <- function(req, client) {
  query_error <- oauth_http_query_guard(req)
  if (!is.null(query_error)) {
    return(query_error)
  }
  query <- req[["QUERY_STRING"]] %||% ""
  handles <- oauth_module_query_raw_values(query, shiny_request_object_param)
  if (!length(handles)) {
    return(NULL)
  }
  method <- toupper(req[["REQUEST_METHOD"]] %||% "GET")
  response <- function(
    status,
    content = "Request Object unavailable",
    allow = FALSE
  ) {
    shiny::httpResponse(
      status,
      content_type = "text/plain; charset=utf-8",
      content = if (identical(method, "HEAD")) "" else content,
      headers = c(
        list(
          "Cache-Control" = "no-store",
          "Pragma" = "no-cache",
          "Referrer-Policy" = "no-referrer",
          "X-Content-Type-Options" = "nosniff"
        ),
        if (allow) list(Allow = "GET, HEAD")
      )
    )
  }
  if (!method %in% c("GET", "HEAD")) {
    return(response(405L, "Method not allowed", allow = TRUE))
  }
  if (length(handles) != 1L || !grepl("^[A-Za-z0-9_-]{43}$", handles[[1L]])) {
    return(response(400L))
  }
  if (is.null(client)) {
    return(response(410L))
  }
  tryCatch(
    {
      store <- client@state_store
      require_request_object_atomic_store(store)
      key <- shiny_request_object_key(client, handles[[1L]])
      data <- if (identical(method, "GET") && is.function(store$take)) {
        store$take(key, missing = NULL)
      } else {
        value <- store$get(key, missing = NULL)
        if (identical(method, "GET")) {
          # No event-loop yield occurs between read and removal in cache_mem.
          store$remove(key)
          if (!is.null(store$get(key, missing = NULL))) {
            stop("Request Object removal failed")
          }
        }
        value
      }
      if (
        !is.list(data) ||
          !is_valid_string(data$request_object) ||
          length(data$expires_at) != 1L ||
          !is.finite(as.numeric(data$expires_at)) ||
          Sys.time() >= data$expires_at
      ) {
        return(response(410L))
      }
      result <- serve_shiny_request_object(data, req)
      shiny::httpResponse(
        result$status,
        content_type = result$headers[["Content-Type"]],
        content = result$body,
        headers = c(
          as.list(result$headers[names(result$headers) != "Content-Type"]),
          list("Referrer-Policy" = "no-referrer")
        )
      )
    },
    error = function(...) response(503L)
  )
}
