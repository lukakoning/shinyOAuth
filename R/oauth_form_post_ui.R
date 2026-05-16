# This file contains the Shiny UI wrapper needed for OAuth/OIDC form_post
# callbacks. The POST request arrives before a Shiny session exists, so the
# wrapper stores the callback body under a one-time handle and redirects the
# browser back to the normal Shiny app page.

# 1 Public UI wrapper -----------------------------------------------------------

#' Wrap a Shiny UI to accept OAuth/OIDC form_post callbacks
#'
#' `oauth_form_post_ui()` enables the OpenID Foundation OAuth 2.0 Form Post
#' Response Mode for apps that use [oauth_module_server()]. It wraps your
#' existing Shiny UI so a provider can POST an authorization response to the
#' app's redirect URI. The POST body is stored server-side under a short-lived
#' one-time handle, and the browser is redirected back to the app with only
#' that opaque handle in the query string.
#'
#' This helper is only for authorization-code callbacks (`response_type=code`),
#' which is the flow implemented by shinyOAuth.
#'
#' @param base_ui Existing Shiny UI object, or a UI function accepting `req`.
#' @param id Shiny module id used by [oauth_module_server()]. This must match
#'   the `id` argument passed to the server module.
#' @param client [OAuthClient] object used by [oauth_module_server()].
#' @param callback_path Optional URL path to accept POST callbacks on. Defaults
#'   to the path component of `client@redirect_uri`.
#'
#' @return A Shiny UI function. Pass it to `shinyApp()` and, for non-root
#'   callback paths, use `uiPattern = ".*"` so Shiny routes the callback path to
#'   this UI function.
#'
#' @export
#'
#' @examples
#' \dontrun{
#' ui <- oauth_form_post_ui(
#'   shiny::fluidPage(
#'     use_shinyOAuth()
#'   ),
#'   id = "auth",
#'   client = client
#' )
#'
#' server <- function(input, output, session) {
#'   auth <- oauth_module_server("auth", client)
#' }
#'
#' shiny::shinyApp(ui, server, uiPattern = ".*")
#' }
oauth_form_post_ui <- function(
  base_ui,
  id,
  client,
  callback_path = NULL
) {
  S7::check_is_S7(client, class = OAuthClient)

  if (!is_valid_string(id)) {
    err_input("{.arg id} must be a single non-empty string.")
  }

  callback_path <- normalize_oauth_form_post_callback_path(
    callback_path %||% oauth_form_post_redirect_path(client)
  )

  force(base_ui)
  force(id)
  force(client)
  force(callback_path)

  request_matches <- oauth_form_post_request_matches
  handle_request <- oauth_form_post_handle_request

  ui <- function(req) {
    if (request_matches(req, callback_path)) {
      return(handle_request(req, id = id, client = client))
    }

    if (is.function(base_ui)) {
      return(base_ui(req))
    }

    if (identical(req$REQUEST_METHOD, "GET")) {
      return(base_ui)
    }

    NULL
  }

  supported <- attr(base_ui, "http_methods_supported", exact = TRUE)
  supported <- unique(c(supported %||% "GET", "GET", "POST"))
  attr(ui, "http_methods_supported") <- supported

  ui
}

# 2 Shared callback limits ------------------------------------------------------

oauth_form_post_handle_param <- "shinyOAuth_form_post"
oauth_form_post_id_param <- "shinyOAuth_form_post_id"

#' Internal: callback size limits
#'
#' Centralizes callback limits used by URL query callbacks and form_post
#' callbacks so both transports enforce the same field caps.
#'
#' @return Named list of byte limits.
#' @keywords internal
#' @noRd
oauth_callback_limits <- function() {
  max_code_bytes <- get_option_positive_number(
    "shinyOAuth.callback_max_code_bytes",
    4096
  )
  max_state_bytes <- get_option_positive_number(
    "shinyOAuth.callback_max_state_bytes",
    8192
  )
  max_error_bytes <- get_option_positive_number(
    "shinyOAuth.callback_max_error_bytes",
    256
  )
  max_error_desc_bytes <- get_option_positive_number(
    "shinyOAuth.callback_max_error_description_bytes",
    4096
  )
  max_error_uri_bytes <- get_option_positive_number(
    "shinyOAuth.callback_max_error_uri_bytes",
    2048
  )
  max_iss_bytes <- get_option_positive_number(
    "shinyOAuth.callback_max_iss_bytes",
    2048
  )
  max_form_post_handle_bytes <- get_option_positive_number(
    "shinyOAuth.callback_max_form_post_handle_bytes",
    128
  )
  max_form_post_id_bytes <- get_option_positive_number(
    "shinyOAuth.callback_max_form_post_id_bytes",
    256
  )

  max_query_overhead_bytes <- 2048
  derived_query_bytes <-
    max_code_bytes +
    max_state_bytes +
    max_error_bytes +
    max_error_desc_bytes +
    max_error_uri_bytes +
    max_iss_bytes +
    max_form_post_handle_bytes +
    max_form_post_id_bytes +
    max_query_overhead_bytes

  list(
    code = max_code_bytes,
    state = max_state_bytes,
    error = max_error_bytes,
    error_description = max_error_desc_bytes,
    error_uri = max_error_uri_bytes,
    iss = max_iss_bytes,
    form_post_handle = max_form_post_handle_bytes,
    form_post_id = max_form_post_id_bytes,
    query = get_option_positive_number(
      "shinyOAuth.callback_max_query_bytes",
      derived_query_bytes
    ),
    form_post_body = get_option_positive_number(
      "shinyOAuth.callback_max_form_post_body_bytes",
      derived_query_bytes
    )
  )
}

# 3 Request handling ------------------------------------------------------------

oauth_form_post_redirect_path <- function(client) {
  parsed <- httr2::url_parse(client@redirect_uri)
  normalize_oauth_form_post_callback_path(parsed$path %||% "/")
}

normalize_oauth_form_post_callback_path <- function(path) {
  if (!is.character(path) || length(path) != 1L || is.na(path)) {
    err_input(
      "{.arg callback_path} must be NULL or a single non-empty path string."
    )
  }

  path <- trimws(path)
  if (!nzchar(path)) {
    path <- "/"
  }
  if (grepl("[?#]", path)) {
    err_input("{.arg callback_path} must not contain query or fragment parts.")
  }
  if (grepl("[[:cntrl:]]", path)) {
    err_input("{.arg callback_path} must not contain control characters.")
  }
  if (!startsWith(path, "/")) {
    path <- paste0("/", path)
  }

  path
}

oauth_form_post_request_path <- function(req) {
  path <- tryCatch(req$PATH_INFO %||% "/", error = function(...) "/")
  normalize_oauth_form_post_callback_path(path)
}

oauth_form_post_request_matches <- function(req, callback_path) {
  identical(req$REQUEST_METHOD, "POST") &&
    identical(oauth_form_post_request_path(req), callback_path)
}

oauth_form_post_handle_request <- function(req, id, client) {
  tryCatch(
    {
      oauth_form_post_validate_content_type(req)
      limits <- oauth_callback_limits()
      body <- oauth_form_post_read_body(req, limits$form_post_body)
      payload <- oauth_form_post_parse_body(body, limits)
      handle <- oauth_form_post_store_set(client, id, payload)
      location <- oauth_form_post_redirect_location(req, id, handle)

      shiny::httpResponse(
        status = 303L,
        content_type = "text/html; charset=UTF-8",
        content = paste0(
          "<!doctype html><html><head><meta name=\"referrer\" ",
          "content=\"no-referrer\"></head><body>",
          "<a href=\"",
          htmltools::htmlEscape(location, attribute = TRUE),
          "\">Continue</a>",
          "</body></html>"
        ),
        headers = stats::setNames(
          as.list(c(
            location,
            "no-store",
            "no-cache",
            "no-referrer"
          )),
          c("Location", "Cache-Control", "Pragma", "Referrer-Policy")
        )
      )
    },
    shinyOAuth_form_post_http_error = function(e) {
      oauth_form_post_error_response(e)
    },
    shinyOAuth_state_error = function(e) {
      oauth_form_post_error_response(e, fallback_status = 400L)
    },
    error = function(e) {
      oauth_form_post_error_response(e, fallback_status = 500L)
    }
  )
}

oauth_form_post_validate_content_type <- function(req) {
  content_type <- req$CONTENT_TYPE %||% req$HTTP_CONTENT_TYPE %||% ""
  content_type <- tolower(trimws(strsplit(
    content_type,
    ";",
    fixed = TRUE
  )[[1]][1]))

  if (!identical(content_type, "application/x-www-form-urlencoded")) {
    err_form_post_http(
      "OAuth form_post callback must use application/x-www-form-urlencoded.",
      status = 415L
    )
  }

  invisible(NULL)
}

oauth_form_post_read_body <- function(req, max_bytes) {
  content_length <- suppressWarnings(as.numeric(
    req$CONTENT_LENGTH %||% req$HTTP_CONTENT_LENGTH %||% NA_real_
  ))
  if (
    length(content_length) == 1L &&
      is.finite(content_length) &&
      !is.na(content_length) &&
      content_length > max_bytes
  ) {
    err_form_post_http(
      "OAuth form_post callback body exceeded maximum length.",
      status = 413L
    )
  }

  input <- req$rook.input
  if (is.null(input) || !is.function(input$read)) {
    err_form_post_http("OAuth form_post callback body is unavailable.")
  }

  body_raw <- input$read(as.integer(max_bytes + 1L))
  if (!is.raw(body_raw)) {
    err_form_post_http("OAuth form_post callback body was not raw bytes.")
  }
  if (length(body_raw) > max_bytes) {
    err_form_post_http(
      "OAuth form_post callback body exceeded maximum length.",
      status = 413L
    )
  }

  tryCatch(
    rawToChar(body_raw),
    error = function(e) {
      err_form_post_http("OAuth form_post callback body could not be decoded.")
    }
  )
}

oauth_form_post_parse_body <- function(body, limits = oauth_callback_limits()) {
  if (!is.character(body) || length(body) != 1L || is.na(body)) {
    err_form_post_http("OAuth form_post callback body must be a single string.")
  }

  actual_bytes <- nchar(body, type = "bytes")
  if (!is.finite(actual_bytes) || is.na(actual_bytes)) {
    err_form_post_http("OAuth form_post callback body had invalid length.")
  }
  if (actual_bytes > limits$form_post_body) {
    err_form_post_http(
      "OAuth form_post callback body exceeded maximum length.",
      status = 413L
    )
  }

  tryCatch(
    reject_duplicate_form_encoded_members(
      body,
      "OAuth form_post callback body"
    ),
    shinyOAuth_parse_error = function(e) {
      err_form_post_http(conditionMessage(e))
    }
  )

  parsed <- tryCatch(
    shiny::parseQueryString(paste0("?", body)),
    error = function(e) {
      err_form_post_http("OAuth form_post callback body could not be parsed.")
    }
  )

  payload <- compact_list(list(
    code = parsed$code,
    state = parsed$state,
    error = parsed$error,
    error_description = parsed$error_description,
    error_uri = parsed$error_uri,
    iss = parsed$iss
  ))

  oauth_form_post_validate_payload(payload, limits)
}

oauth_form_post_validate_payload <- function(
  payload,
  limits = oauth_callback_limits()
) {
  if (!is.list(payload)) {
    err_form_post_http("OAuth form_post callback payload must be a list.")
  }

  validate_untrusted_query_param("code", payload$code, limits$code)
  validate_untrusted_query_param("state", payload$state, limits$state)
  validate_untrusted_query_param("error", payload$error, limits$error)
  validate_untrusted_query_param(
    "error_description",
    payload$error_description,
    max_bytes = limits$error_description,
    allow_empty = TRUE
  )
  validate_untrusted_query_param(
    "error_uri",
    payload$error_uri,
    max_bytes = limits$error_uri,
    allow_empty = TRUE
  )
  validate_untrusted_query_param("iss", payload$iss, limits$iss)

  if (is.null(payload$state)) {
    err_form_post_http("OAuth form_post callback missing state.")
  }
  if (!is.null(payload$code) && !is.null(payload$error)) {
    err_form_post_http(
      "OAuth form_post callback must not contain both code and error."
    )
  }
  if (is.null(payload$code) && is.null(payload$error)) {
    err_form_post_http("OAuth form_post callback missing code or error.")
  }

  payload$type <- if (!is.null(payload$error)) "error" else "code"
  payload
}

oauth_form_post_redirect_location <- function(req, id, handle) {
  path <- oauth_form_post_request_path(req)
  clean_query <- strip_oauth_module_callback_query(req$QUERY_STRING %||% "")
  clean_query <- sub("^\\?", "", clean_query)
  handle_query <- httr2::url_query_build(stats::setNames(
    list(handle, id),
    c(oauth_form_post_handle_param, oauth_form_post_id_param)
  ))
  query <- paste(
    c(clean_query, handle_query)[nzchar(c(
      clean_query,
      handle_query
    ))],
    collapse = "&"
  )

  paste0(path, if (nzchar(query)) paste0("?", query) else "")
}

# 4 One-time form_post callback storage ----------------------------------------

oauth_form_post_cache_key <- function(id, handle) {
  if (!is_valid_string(id) || !is_valid_string(handle)) {
    err_invalid_state("Invalid form_post callback handle")
  }

  paste0(
    "formpost",
    raw_to_hex_lower(openssl::sha256(charToRaw(paste(id, handle, sep = "\n"))))
  )
}

oauth_form_post_store_set <- function(client, id, payload) {
  S7::check_is_S7(client, class = OAuthClient)
  if (!is_valid_string(id)) {
    err_invalid_state("Invalid form_post module id")
  }

  payload <- oauth_form_post_validate_payload(payload)
  handle <- random_urlsafe(32)
  key <- oauth_form_post_cache_key(id, handle)
  payload$module_id <- id
  payload$stored_at <- as.numeric(Sys.time())

  tryCatch(
    client@state_store$set(key, payload),
    error = function(e) {
      err_invalid_state(
        sprintf(
          "Failed to persist form_post callback payload: %s",
          conditionMessage(e)
        ),
        context = list(phase = "form_post_store_set")
      )
    }
  )

  handle
}

oauth_form_post_store_take <- function(client, id, handle) {
  S7::check_is_S7(client, class = OAuthClient)
  if (!is_valid_string(id)) {
    err_invalid_state("Invalid form_post module id")
  }

  limits <- oauth_callback_limits()
  validate_untrusted_query_param(
    oauth_form_post_handle_param,
    handle,
    max_bytes = limits$form_post_handle
  )

  key <- oauth_form_post_cache_key(id, handle)
  store <- client@state_store

  has_take <- !is.null(store$take) && is.function(store$take)
  payload <- NULL
  if (has_take) {
    payload <- tryCatch(
      store$take(key, missing = NULL),
      error = function(e) {
        err_invalid_state(
          sprintf(
            "Failed to consume form_post callback handle: %s",
            conditionMessage(e)
          ),
          context = list(phase = "form_post_store_take")
        )
      }
    )
  } else {
    if (!inherits(store, "cache_mem")) {
      if (!isTRUE(getOption("shinyOAuth.allow_non_atomic_state_store"))) {
        err_config(c(
          "form_post callback store requires atomic `$take(key, missing)` method",
          "i" = paste0(
            "The POST callback handle is single-use. Provide an atomic ",
            "`$take()` via `custom_cache(take = ...)` or use ",
            "`cachem::cache_mem()` for single-process deployments."
          )
        ))
      }
    }

    payload <- tryCatch(
      store$get(key, missing = NULL),
      error = function(e) {
        err_invalid_state(
          sprintf(
            "Failed to read form_post callback handle: %s",
            conditionMessage(e)
          ),
          context = list(phase = "form_post_store_get")
        )
      }
    )
    try(store$remove(key), silent = TRUE)
  }

  if (is.null(payload)) {
    err_invalid_state(
      "form_post callback handle is missing or already consumed",
      context = list(phase = "form_post_store_take")
    )
  }
  if (!identical(payload$module_id %||% NULL, id)) {
    err_invalid_state(
      "form_post callback handle module mismatch",
      context = list(phase = "form_post_store_take")
    )
  }

  oauth_form_post_validate_payload(payload)
}

# 5 HTTP errors ----------------------------------------------------------------

err_form_post_http <- function(message, status = 400L) {
  rlang::abort(
    message,
    class = "shinyOAuth_form_post_http_error",
    status = as.integer(status)
  )
}

oauth_form_post_error_response <- function(e, fallback_status = 400L) {
  status <- tryCatch(e$status, error = function(...) NULL)
  if (
    !is.numeric(status) ||
      length(status) != 1L ||
      is.na(status) ||
      status < 400L
  ) {
    status <- fallback_status
  }

  shiny::httpResponse(
    status = as.integer(status),
    content_type = "text/plain; charset=UTF-8",
    content = conditionMessage(e),
    headers = stats::setNames(
      as.list(c("no-store", "no-cache", "no-referrer")),
      c("Cache-Control", "Pragma", "Referrer-Policy")
    )
  )
}
